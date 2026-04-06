"""Tests for the InvestigationOrchestrator."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from ec2_troubleshooter.config.settings import Settings
from ec2_troubleshooter.models.alert import Alert, AlertSeverity
from ec2_troubleshooter.models.findings import (
    DiagnosticResult,
    DiagnosticStatus,
)
from ec2_troubleshooter.orchestrator.investigator import InvestigationOrchestrator


def _make_mock_server(private_ip: str = "10.0.0.1") -> MagicMock:
    server = MagicMock()
    ok = DiagnosticResult(
        tool_name="ec2:describe_instance",
        status=DiagnosticStatus.OK,
        summary="ok",
        metrics={
            "state": "running",
            "instance_type": "t3.medium",
            "availability_zone": "us-east-1a",
            "private_ip": private_ip,
            "tags": {"Name": "worker-1"},
        },
    )
    server.call.return_value = ok
    server._prom_tools.is_available.return_value = False
    server._ssm_tools.is_managed.return_value = False
    return server


@pytest.fixture
def mock_tool_server():
    return _make_mock_server()


@pytest.fixture
def orchestrator(mock_tool_server):
    return InvestigationOrchestrator(mock_tool_server, Settings(AWS_REGION="us-east-1"))


class TestInvestigate:
    def test_empty_instance_ids_returns_error(self, orchestrator):
        alert = Alert(alert_id="a1", source="test", title="Alert", instance_ids=[])
        report = orchestrator.investigate(alert)
        assert report.error is not None
        assert len(report.instances) == 0

    def test_single_instance_investigation(self, orchestrator, mock_tool_server):
        alert = Alert(
            alert_id="a2",
            source="test",
            title="CPU Alert",
            severity=AlertSeverity.HIGH,
            instance_ids=["i-abc"],
        )
        report = orchestrator.investigate(alert)
        assert len(report.instances) == 1
        assert report.instances[0].instance_id == "i-abc"
        assert report.alert_id == "a2"
        assert report.completed_at is not None

    def test_multiple_instances(self, orchestrator):
        alert = Alert(
            alert_id="a3",
            source="test",
            title="Multi-instance alert",
            instance_ids=["i-001", "i-002", "i-003"],
        )
        report = orchestrator.investigate(alert)
        assert len(report.instances) == 3

    def test_metadata_enriched(self, orchestrator):
        alert = Alert(alert_id="a4", source="test", title="t", instance_ids=["i-abc"])
        report = orchestrator.investigate(alert)
        inv = report.instances[0]
        assert inv.instance_type == "t3.medium"
        assert inv.availability_zone == "us-east-1a"
        assert inv.private_ip == "10.0.0.1"

    def test_tool_server_failure_does_not_crash(self, orchestrator, mock_tool_server):
        mock_tool_server.call.side_effect = RuntimeError("boom")
        alert = Alert(alert_id="a5", source="test", title="t", instance_ids=["i-fail"])
        report = orchestrator.investigate(alert)
        assert len(report.instances) == 1
        assert report.instances[0].overall_status == DiagnosticStatus.ERROR
