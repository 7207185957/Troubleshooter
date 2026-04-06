"""Tests for Alert and Findings models."""

from __future__ import annotations

from datetime import datetime, timezone

from ec2_troubleshooter.models.alert import Alert, AlertSeverity, AnomalyContributor
from ec2_troubleshooter.models.findings import (
    DiagnosticResult,
    DiagnosticStatus,
    InvestigationReport,
)


class TestAlert:
    def test_minimal_alert(self):
        a = Alert(alert_id="a1", source="test", title="Test alert")
        assert a.severity == AlertSeverity.UNKNOWN
        assert a.instance_ids == []
        assert a.contributors == []

    def test_alert_with_contributors(self):
        c = AnomalyContributor(metric_name="CPUUtilization", value=95.0, threshold=80.0)
        a = Alert(
            alert_id="a2",
            source="anomaly-platform",
            title="High CPU",
            severity=AlertSeverity.HIGH,
            instance_ids=["i-abc123"],
            contributors=[c],
        )
        assert a.severity == AlertSeverity.HIGH
        assert len(a.contributors) == 1
        assert a.contributors[0].value == 95.0


class TestDiagnosticResult:
    def test_ok_result(self):
        r = DiagnosticResult(tool_name="ec2:describe_instance", status=DiagnosticStatus.OK, summary="ok")
        assert r.status == DiagnosticStatus.OK
        assert r.error is None

    def test_error_result(self):
        r = DiagnosticResult(
            tool_name="ec2:describe_instance",
            status=DiagnosticStatus.ERROR,
            error="NoCredentials",
        )
        assert r.status == DiagnosticStatus.ERROR


class TestInvestigationReport:
    def test_report_serialisation(self):
        report = InvestigationReport(
            alert_id="r1",
            alert_title="Test",
            alert_source="test",
            severity="HIGH",
            summary="All clear",
            started_at=datetime.now(tz=timezone.utc),
        )
        d = report.model_dump(mode="json")
        assert d["alert_id"] == "r1"
        assert "started_at" in d
