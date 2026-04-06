"""
Investigation Orchestrator.

Drives the full investigation lifecycle for an Alert:

  1. For each affected instance in the alert, run the standard diagnostic suite
     via the EC2ToolServer.
  2. Extract instance metadata from the describe_instance result.
  3. Run the EvidenceAnalyzer to turn raw results into structured findings.
  4. Derive top-level likely causes across all instances.
  5. Return an InvestigationReport ready to be sent to the reporting layer.

The orchestrator contains no app-specific logic.  It only orchestrates generic
EC2 / OS diagnostics.
"""

from __future__ import annotations

from datetime import UTC, datetime

import structlog

from ec2_troubleshooter.models.alert import Alert
from ec2_troubleshooter.models.findings import (
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

        report = InvestigationReport(
            alert_id=alert.alert_id,
            alert_title=alert.title,
            alert_source=alert.source,
            severity=alert.severity.value,
            started_at=datetime.now(tz=UTC),
        )

        if not alert.instance_ids:
            report.error = "Alert contains no instance_ids – nothing to investigate"
            report.completed_at = datetime.now(tz=UTC)
            log.warning("investigation.no_instances", alert_id=alert.alert_id)
            return report

        for instance_id in alert.instance_ids:
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

    # ── Instance-level investigation ───────────────────────────────────────

    def _investigate_instance(self, instance_id: str, alert: Alert) -> InstanceInvestigation:
        log.info("instance.investigate.start", instance_id=instance_id)
        inv = InstanceInvestigation(
            instance_id=instance_id,
            started_at=datetime.now(tz=UTC),
        )
        try:
            results = self._server.run_standard_suite(instance_id)
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

    def _enrich_metadata(
        self, inv: InstanceInvestigation, results: list
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
                        # Normalise the ISO string – boto3 may include +00:00 suffix
                        norm = launch_str.replace("Z", "+00:00")
                        inv.launch_time = datetime.fromisoformat(norm)
                    except (ValueError, AttributeError):
                        pass
                break
            if r.tool_name == "ssm:availability" and r.status == DiagnosticStatus.SKIPPED:
                inv.ssm_managed = False
            elif r.tool_name.startswith("ssm:") and r.status != DiagnosticStatus.ERROR:
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
        return [c[1] for c in causes[:10]]  # top 10 causes

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
            return (
                f"Investigated {total} instance(s). No significant issues detected."
            )
        likely = "; ".join(report.likely_causes[:3])
        return (
            f"Investigated {total} instance(s), {degraded} degraded/failed. "
            f"Top findings: {likely}"
        )
