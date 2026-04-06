"""
Investigation Orchestrator.

Drives the full investigation lifecycle for an Alert:

  1. For each affected instance in the alert, run the standard diagnostic suite
     via the EC2ToolServer (EC2 APIs + Prometheus/Mimir node metrics + SSM).
  2. Extract instance metadata from the describe_instance result so the private
     IP is available for Prometheus label matching.
  3. Query contributor metrics from the alert against Prometheus so that the
     exact metric values that triggered the alert are included in evidence.
  4. Run the EvidenceAnalyzer to turn raw results into structured findings.
  5. Derive top-level likely causes across all instances.
  6. Return an InvestigationReport ready to be sent to the reporting layer.

The orchestrator contains no app-specific logic.  It only orchestrates generic
EC2 / OS / infrastructure diagnostics.
"""

from __future__ import annotations

from datetime import UTC, datetime

import structlog

from ec2_troubleshooter.models.alert import Alert, AnomalyContributor
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


class InvestigationOrchestrator:
    """
    Coordinates the full investigation workflow for an inbound alert.

    Usage::

        orchestrator = InvestigationOrchestrator(tool_server)
        report = orchestrator.investigate(alert)
    """

    def __init__(self, tool_server: EC2ToolServer) -> None:
        self._server = tool_server
        self._analyzer = EvidenceAnalyzer()

    def investigate(self, alert: Alert) -> InvestigationReport:
        """
        Run diagnostics on all instances referenced in *alert* and return a
        complete InvestigationReport.
        """
        log.info(
            "investigation.start",
            alert_id=alert.alert_id,
            source=alert.source,
            instances=alert.instance_ids,
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
        """
        Resolve ``alert.instance_names`` (EC2 Name tags) to instance IDs via
        the EC2 describe_instances API.  Logs a warning for any names that
        could not be resolved.
        """
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
            # Step 1: EC2 describe to get private IP before querying Prometheus
            describe_result = self._server.call(instance_id, "ec2:describe_instance")
            instance_ip = describe_result.metrics.get("private_ip") if describe_result.metrics else None

            # Step 2: Run the full standard suite, passing the IP for Prometheus
            results = self._server.run_standard_suite(instance_id, instance_ip=instance_ip)

            # Avoid duplicate describe_instance in the diagnostics list
            results = [r for r in results if r.tool_name != "ec2:describe_instance"]
            results.insert(0, describe_result)

            # Step 3: Query alert contributor metrics from Prometheus
            if instance_ip and alert.contributors:
                contributor_results = self._query_contributor_metrics(
                    instance_id, instance_ip, alert.contributors
                )
                results.extend(contributor_results)

            inv.diagnostics = results
            self._enrich_metadata(inv, results)
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

    def _query_contributor_metrics(
        self,
        instance_id: str,
        instance_ip: str,
        contributors: list[AnomalyContributor],
    ) -> list[DiagnosticResult]:
        """
        For each alert contributor whose metric_name looks like a Prometheus
        metric (no spaces, no special chars), query its current value and
        recent trend from Mimir.

        This surfaces the exact signals that triggered the alert alongside the
        OS-level evidence.
        """
        results: list[DiagnosticResult] = []
        seen: set[str] = set()
        for contributor in contributors:
            name = contributor.metric_name
            # Skip generic descriptions like "CloudWatch alarm reason"
            if not _looks_like_prom_metric(name) or name in seen:
                continue
            seen.add(name)
            log.debug(
                "querying contributor metric",
                instance_id=instance_id,
                metric=name,
            )
            results.append(
                self._server.call(
                    instance_id,
                    "prometheus:contributor_metric",
                    instance_ip=instance_ip,
                    metric_name=name,
                )
            )
        return results

    def _enrich_metadata(
        self, inv: InstanceInvestigation, results: list[DiagnosticResult]
    ) -> None:
        """Populate InstanceInvestigation metadata from describe_instance result."""
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
                    try:
                        norm = launch_str.replace("Z", "+00:00")
                        inv.launch_time = datetime.fromisoformat(norm)
                    except (ValueError, AttributeError):
                        pass
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
        """
        Aggregate findings across all instances into a de-duplicated list of
        likely cause statements, ordered by severity.
        """
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
            1
            for i in report.instances
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


def _looks_like_prom_metric(name: str) -> bool:
    """
    Return True if *name* resembles a valid Prometheus metric name.
    Prometheus metric names match [a-zA-Z_:][a-zA-Z0-9_:]*.
    """
    import re
    return bool(re.match(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$", name))
