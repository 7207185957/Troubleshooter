"""Tests for reporter formatter and log reporter."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ec2_troubleshooter.models.findings import (
    DiagnosticStatus,
    Finding,
    FindingSeverity,
    InstanceInvestigation,
    InvestigationReport,
)
from ec2_troubleshooter.reporter.formatter import (
    format_gchat_card,
    format_json_payload,
    format_text,
)
from ec2_troubleshooter.reporter.log_reporter import LogReporter


@pytest.fixture
def sample_report():
    inv = InstanceInvestigation(
        instance_id="i-abc001",
        instance_type="t3.large",
        instance_state="running",
        availability_zone="us-east-1a",
        private_ip="10.0.1.5",
        ssm_managed=True,
        overall_status=DiagnosticStatus.DEGRADED,
        findings=[
            Finding(
                severity=FindingSeverity.HIGH,
                category="cpu",
                message="High CPU: max=92%",
                evidence=["CPUUtilization: 92.3"],
                recommendation="Check process_list",
            ),
            Finding(
                severity=FindingSeverity.MEDIUM,
                category="memory",
                message="Memory usage at 78%",
            ),
        ],
    )
    return InvestigationReport(
        alert_id="alert-001",
        alert_title="High CPU Anomaly",
        alert_source="test-platform",
        severity="HIGH",
        summary="1 instance degraded",
        likely_causes=["High CPU: max=92%", "Memory usage at 78%"],
        instances=[inv],
        started_at=datetime.now(tz=UTC),
    )


class TestTextFormatter:
    def test_format_includes_instance_id(self, sample_report):
        text = format_text(sample_report)
        assert "i-abc001" in text

    def test_format_includes_findings(self, sample_report):
        text = format_text(sample_report)
        assert "High CPU" in text

    def test_format_includes_likely_causes(self, sample_report):
        text = format_text(sample_report)
        assert "LIKELY CAUSES" in text

    def test_empty_report_no_crash(self):
        report = InvestigationReport(
            alert_id="x",
            alert_title="t",
            alert_source="s",
            severity="LOW",
        )
        text = format_text(report)
        assert "INVESTIGATION REPORT" in text


class TestGChatFormatter:
    def test_gchat_card_structure(self, sample_report):
        card = format_gchat_card(sample_report)
        assert "cardsV2" in card
        assert len(card["cardsV2"]) == 1
        c = card["cardsV2"][0]["card"]
        assert "header" in c
        assert "sections" in c

    def test_gchat_card_has_instance_section(self, sample_report):
        card = format_gchat_card(sample_report)
        sections = card["cardsV2"][0]["card"]["sections"]
        headers = [s.get("header", "") for s in sections]
        assert any("i-abc001" in h for h in headers)


class TestJsonFormatter:
    def test_json_payload_is_dict(self, sample_report):
        d = format_json_payload(sample_report)
        assert isinstance(d, dict)
        assert d["alert_id"] == "alert-001"

    def test_json_payload_serialisable(self, sample_report):
        import json
        d = format_json_payload(sample_report)
        text = json.dumps(d)
        assert "i-abc001" in text


class TestLogReporter:
    def test_log_reporter_sends_without_error(self, sample_report):
        reporter = LogReporter()
        reporter.send(sample_report)  # Should not raise
