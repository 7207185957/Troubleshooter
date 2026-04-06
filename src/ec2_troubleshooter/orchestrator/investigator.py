"""
Investigation Orchestrator.

Full investigation workflow for an inbound Alert:

  1. Resolve Name-tag hostnames → EC2 instance IDs (when alert gives names).
  2. For each instance:
     a. EC2 describe → get private IP, state, metadata.
     b. Query Prometheus/Mimir node metrics using the INFRA org ID.
     c. Determine the primary alert category from contributors
        (cpu / memory / disk / network / app / baseline).
     d. Run the targeted SSM diagnostic profile for that category.
     e. For APP_METRIC contributors: query Mimir using the APP org ID
        for that archetype (X-Scope-OrgID per app tenant).
     f. For LOG_SIGNAL contributors: read the count from the alert payload.
     g. Analyse all evidence → structured Findings.
  3. Derive likely causes across all instances.
  4. Return InvestigationReport.

Multi-tenant Mimir routing
──────────────────────────
- Infra metrics (node_exporter) → PROMETHEUS_INFRA_ORG_ID
- App metrics                   → PROMETHEUS_APP_ORG_IDS[archetype] or _default

No remediation is ever performed.
"""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime

import structlog

from ec2_troubleshooter.config.settings import Settings
from ec2_troubleshooter.models.alert import Alert, AnomalyContributor, ContributorKind
from ec2_troubleshooter.models.findings import (
    DiagnosticResult,
    DiagnosticStatus,
    FindingSeverity,
    InstanceInvestigation,
    InvestigationReport,
)
from ec2_troubleshooter.tools import EC2ToolServer

from .analyzer import EvidenceAnalyzer

log = structlog.get_logger(__name__)

# Maps ContributorKind / metric category to SSM profile key
_INFRA_METRIC_TO_PROFILE: dict[str, str] = {
    "cpu": "cpu",
    "mem": "memory",
    "memory": "memory",
    "disk": "disk",
    "network": "network",
    "net": "network",
    "load": "cpu",
    "swap": "memory",
}


class InvestigationOrchestrator:
    """
    Coordinates the full investigation workflow for an inbound alert.

    Usage::

        orchestrator = InvestigationOrchestrator(tool_server, settings)
        report = orchestrator.investigate(alert)
    """

    def __init__(self, tool_server: EC2ToolServer, settings: Settings) -> None:
        self._server = tool_server
        self._settings = settings
        self._analyzer = EvidenceAnalyzer()

    def investigate(self, alert: Alert) -> InvestigationReport:
        """Run diagnostics on all instances in *alert* and return a report."""
        log.info(
            "investigation.start",
            alert_id=alert.alert_id,
            source=alert.source,
            archetype=alert.archetype,
            instances=alert.instance_ids or alert.instance_names,
        )

        aiops = alert.aiops
        report = InvestigationReport(
            alert_id=alert.alert_id,
            alert_title=alert.title,
            alert_source=alert.source,
            severity=alert.severity.value,
            archetype=alert.archetype,
            aiops_health=aiops.health if aiops else None,
            aiops_failure=aiops.failure if aiops else None,
            aiops_risk=aiops.risk if aiops else None,
            aiops_state=aiops.state if aiops else None,
            aiops_policy_reason=aiops.policy_reason if aiops else None,
            aiops_app_log_errors=aiops.app_log_errors if aiops else 0,
            started_at=datetime.now(tz=UTC),
        )

        # Resolve Name-tag hostnames → instance IDs when the alert gives names
        effective_ids = list(alert.instance_ids)
        if alert.instance_names and not effective_ids:
            effective_ids = self._resolve_names(alert)

        if not effective_ids:
            report.error = (
                "Alert contains no resolvable instance identifiers – nothing to investigate. "
                f"instance_ids={alert.instance_ids}, instance_names={alert.instance_names}"
            )
            report.completed_at = datetime.now(tz=UTC)
            log.warning("investigation.no_instances", alert_id=alert.alert_id)
            return report

        for instance_id in effective_ids:
            inv = self._investigate_instance(instance_id, alert)
            report.instances.append(inv)

        report.likely_causes = self._derive_likely_causes(report)
        report.summary = self._build_report_summary(report)
        report.completed_at = datetime.now(tz=UTC)

        log.info(
            "investigation.complete",
            alert_id=alert.alert_id,
            instances=len(report.instances),
            likely_causes=len(report.likely_causes),
        )
        return report

    # ── Name resolution ────────────────────────────────────────────────────

    def _resolve_names(self, alert: Alert) -> list[str]:
        names = alert.instance_names
        log.info("resolving instance names", alert_id=alert.alert_id, count=len(names))
        name_to_id = self._server.resolve_instance_names(names)
        resolved = list(name_to_id.values())
        unresolved = [n for n in names if n not in name_to_id]
        if unresolved:
            log.warning(
                "instance names could not be resolved",
                alert_id=alert.alert_id,
                unresolved=unresolved,
            )
        log.info(
            "name resolution complete",
            alert_id=alert.alert_id,
            resolved=len(resolved),
            unresolved=len(unresolved),
        )
        return resolved

    # ── Instance-level investigation ───────────────────────────────────────

    def _investigate_instance(self, instance_id: str, alert: Alert) -> InstanceInvestigation:
        log.info("instance.investigate.start", instance_id=instance_id)
        inv = InstanceInvestigation(
            instance_id=instance_id,
            started_at=datetime.now(tz=UTC),
        )
        try:
            all_results: list[DiagnosticResult] = []

            # ── Step 1: EC2 metadata ──────────────────────────────────────
            describe_result = self._server.call(instance_id, "ec2:describe_instance")
            instance_ip = describe_result.metrics.get("private_ip") if describe_result.metrics else None
            all_results.append(describe_result)
            all_results.append(self._server.call(instance_id, "ec2:get_instance_status"))
            all_results.append(self._server.call(instance_id, "ec2:describe_volumes"))
            all_results.append(self._server.call(instance_id, "ec2:get_console_output"))

            # ── Step 2: Infra metrics from Mimir (infra tenant) ───────────
            infra_org = self._settings.infra_org_id()
            if self._server._prom_tools.is_available() and instance_ip:
                log.info("querying infra metrics", instance_id=instance_id,
                         org_id=infra_org)
                all_results.append(
                    self._server.call(
                        instance_id, "prometheus:node_metrics",
                        instance_ip=instance_ip, org_id=infra_org,
                    )
                )
            else:
                all_results.append(DiagnosticResult(
                    tool_name="prometheus:node_metrics",
                    status=DiagnosticStatus.SKIPPED,
                    summary="Prometheus unavailable or instance IP unknown",
                ))

            # ── Step 3: Targeted SSM profile based on contributors ─────────
            ssm_profile = self._select_ssm_profile(alert.contributors)
            if self._server._ssm_tools.is_managed(instance_id):
                log.info("running targeted SSM profile",
                         instance_id=instance_id, profile=ssm_profile)
                all_results.append(
                    self._server.call(instance_id, f"ssm:profile:{ssm_profile}")
                )
                inv.ssm_managed = True
            else:
                log.info("instance not SSM-managed, skipping host diagnostics",
                         instance_id=instance_id)
                all_results.append(DiagnosticResult(
                    tool_name="ssm:availability",
                    status=DiagnosticStatus.SKIPPED,
                    summary="Instance is not SSM-managed; host diagnostics unavailable",
                ))

            # ── Step 4: Contributor-specific evidence ─────────────────────
            if instance_ip and alert.contributors:
                app_org = self._settings.app_org_id_for(alert.archetype)
                contributor_results = self._query_contributor_metrics(
                    instance_id, instance_ip, alert.contributors, app_org
                )
                all_results.extend(contributor_results)

            inv.diagnostics = all_results
            self._enrich_metadata(inv, all_results)
            self._analyzer.analyze(inv)

        except Exception as exc:
            log.error(
                "instance.investigate.error",
                instance_id=instance_id,
                error=str(exc),
                exc_info=True,
            )
            inv.overall_status = DiagnosticStatus.ERROR
            inv.summary = f"Investigation failed: {exc}"

        inv.completed_at = datetime.now(tz=UTC)
        log.info(
            "instance.investigate.complete",
            instance_id=instance_id,
            status=inv.overall_status,
            findings=len(inv.findings),
        )
        return inv

    # ── SSM profile selection ──────────────────────────────────────────────

    @staticmethod
    def _select_ssm_profile(contributors: list[AnomalyContributor]) -> str:
        """
        Choose the most appropriate SSM diagnostic profile based on the
        primary contributor kind/name.

        Priority:
          1. If any contributor is an INFRA_METRIC, match by name prefix
             (cpu → cpu profile, memory → memory profile, etc.)
          2. If any contributor is an APP_METRIC → app profile
          3. If any contributor is a LOG_SIGNAL → app profile (log errors
             indicate application-level issues)
          4. Default: baseline profile
        """
        for c in contributors:
            if c.kind == ContributorKind.INFRA_METRIC:
                name = c.metric_name.lower()
                for prefix, profile in _INFRA_METRIC_TO_PROFILE.items():
                    if name == prefix or name.startswith(f"{prefix}_") or name.startswith(f"{prefix} "):
                        return profile
        for c in contributors:
            if c.kind in (ContributorKind.APP_METRIC, ContributorKind.LOG_SIGNAL):
                return "app"
        return "baseline"

    # ── Contributor metric queries ─────────────────────────────────────────

    def _query_contributor_metrics(
        self,
        instance_id: str,
        instance_ip: str,
        contributors: list[AnomalyContributor],
        app_org: str | None,
    ) -> list[DiagnosticResult]:
        """
        Route each contributor to the correct evidence source.

        LOG_SIGNAL   → synthesise result from alert payload count (no Mimir)
        INFRA_METRIC → skip (already covered by node_metrics with infra org)
        APP_METRIC   → query Mimir with the APP org ID for this archetype
        """
        results: list[DiagnosticResult] = []
        seen: set[str] = set()

        for contributor in contributors:
            name = contributor.metric_name
            if name in seen:
                continue
            seen.add(name)

            if contributor.kind == ContributorKind.LOG_SIGNAL:
                results.append(self._make_log_signal_result(contributor))

            elif contributor.kind == ContributorKind.INFRA_METRIC:
                log.debug("contributor covered by node_metrics, skipping",
                          metric=name, instance_id=instance_id)
                results.append(DiagnosticResult(
                    tool_name=f"prometheus:contributor:{name}",
                    status=DiagnosticStatus.SKIPPED,
                    summary=f"Infra metric '{name}' already covered by node_metrics (infra tenant)",
                    metrics={"metric": name, "kind": contributor.kind},
                ))

            elif contributor.kind == ContributorKind.APP_METRIC:
                log.debug("querying app metric from Mimir",
                          metric=name, instance_id=instance_id, org_id=app_org)
                results.append(
                    self._server.call(
                        instance_id,
                        "prometheus:contributor_metric",
                        instance_ip=instance_ip,
                        metric_name=name,
                        org_id=app_org,
                    )
                )
        return results

    @staticmethod
    def _make_log_signal_result(contributor: AnomalyContributor) -> DiagnosticResult:
        name = contributor.metric_name
        count = contributor.value
        is_dag = "dag" in name.lower()
        signal_label = "Airflow DAG log errors" if is_dag else "App log errors"
        status = DiagnosticStatus.DEGRADED if (count and count > 0) else DiagnosticStatus.OK
        summary = (
            f"{signal_label}: {int(count)} error(s) reported in alert"
            if count is not None
            else f"{signal_label}: count not available in alert payload"
        )
        return DiagnosticResult(
            tool_name=f"log_signal:{name}",
            status=status,
            summary=summary,
            metrics={"metric": name, "kind": contributor.kind, "count": count},
        )

    # ── Metadata enrichment ────────────────────────────────────────────────

    def _enrich_metadata(
        self, inv: InstanceInvestigation, results: list[DiagnosticResult]
    ) -> None:
        for r in results:
            if r.tool_name == "ec2:describe_instance" and r.metrics:
                m = r.metrics
                inv.instance_state = m.get("state")
                inv.instance_type = m.get("instance_type")
                inv.private_ip = m.get("private_ip")
                inv.public_ip = m.get("public_ip")
                inv.availability_zone = m.get("availability_zone")
                inv.tags = m.get("tags", {})
                launch_str = m.get("launch_time", "")
                if launch_str:
                    with contextlib.suppress(ValueError, AttributeError):
                        inv.launch_time = datetime.fromisoformat(
                            launch_str.replace("Z", "+00:00")
                        )
                break

        for r in results:
            if r.tool_name == "ssm:availability" and r.status == DiagnosticStatus.SKIPPED:
                inv.ssm_managed = False
            elif r.tool_name.startswith("ssm:") and r.status not in (
                DiagnosticStatus.ERROR,
                DiagnosticStatus.SKIPPED,
            ):
                inv.ssm_managed = True

    # ── Report-level synthesis ─────────────────────────────────────────────

    def _derive_likely_causes(self, report: InvestigationReport) -> list[str]:
        seen: set[str] = set()
        causes: list[tuple[int, str]] = []
        _sev = {
            FindingSeverity.CRITICAL: 0,
            FindingSeverity.HIGH: 1,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 3,
            FindingSeverity.INFO: 4,
        }
        for inst in report.instances:
            for finding in inst.findings:
                key = f"{finding.category}:{finding.message}"
                if key not in seen:
                    seen.add(key)
                    causes.append((_sev.get(finding.severity, 99), finding.message))
        causes.sort(key=lambda x: x[0])
        return [c[1] for c in causes[:10]]

    @staticmethod
    def _build_report_summary(report: InvestigationReport) -> str:
        total = len(report.instances)
        degraded = sum(
            1 for i in report.instances
            if i.overall_status in (DiagnosticStatus.DEGRADED, DiagnosticStatus.FAILED)
        )
        if total == 0:
            return "No instances investigated."
        if degraded == 0:
            return f"Investigated {total} instance(s). No significant issues detected."
        likely = "; ".join(report.likely_causes[:3])
        return (
            f"Investigated {total} instance(s), {degraded} degraded/failed. "
            f"Top findings: {likely}"
        )
