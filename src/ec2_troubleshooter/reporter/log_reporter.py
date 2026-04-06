"""Log reporter – writes findings to stdout/structlog (default for air-gapped use)."""

from __future__ import annotations

import structlog

from ec2_troubleshooter.models.findings import InvestigationReport

from .base import BaseReporter
from .formatter import format_text

log = structlog.get_logger(__name__)


class LogReporter(BaseReporter):
    """Writes the formatted investigation report to the application log."""

    def send(self, report: InvestigationReport) -> None:
        text = format_text(report)
        log.info(
            "investigation_report",
            alert_id=report.alert_id,
            severity=report.severity,
            summary=report.summary,
            likely_causes=report.likely_causes,
            report_text=text,
        )
