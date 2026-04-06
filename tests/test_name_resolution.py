"""Tests for EC2 instance Name → ID resolution."""

from __future__ import annotations

import boto3
import pytest

from ec2_troubleshooter.config.settings import Settings

try:
    from moto import mock_aws
except ImportError:
    from moto import mock_ec2 as mock_aws  # type: ignore[no-reattr]

from ec2_troubleshooter.tools.aws_client import AWSClientFactory
from ec2_troubleshooter.tools.ec2_tools import EC2Tools


@pytest.fixture
def settings():
    return Settings(AWS_REGION="us-east-1")


@pytest.fixture
def factory(settings):
    return AWSClientFactory(settings)


@mock_aws
def test_resolve_empty_list(factory):
    tools = EC2Tools(factory)
    result = tools.resolve_instance_names([])
    assert result == {}


@mock_aws
def test_resolve_known_names(factory):
    ec2 = boto3.resource("ec2", region_name="us-east-1")
    inst = ec2.create_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)[0]
    inst.create_tags(Tags=[{"Key": "Name", "Value": "ec2-dw-platform-use1-mimirread-102p"}])

    tools = EC2Tools(factory)
    mapping = tools.resolve_instance_names(["ec2-dw-platform-use1-mimirread-102p"])
    assert "ec2-dw-platform-use1-mimirread-102p" in mapping
    assert mapping["ec2-dw-platform-use1-mimirread-102p"] == inst.id


@mock_aws
def test_resolve_unknown_names_returns_empty(factory):
    tools = EC2Tools(factory)
    mapping = tools.resolve_instance_names(["nonexistent-host"])
    assert mapping == {}


@mock_aws
def test_resolve_partial_match(factory):
    ec2 = boto3.resource("ec2", region_name="us-east-1")
    inst = ec2.create_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)[0]
    inst.create_tags(Tags=[{"Key": "Name", "Value": "known-host"}])

    tools = EC2Tools(factory)
    mapping = tools.resolve_instance_names(["known-host", "unknown-host"])
    assert "known-host" in mapping
    assert "unknown-host" not in mapping


@mock_aws
def test_resolve_multiple_instances(factory):
    ec2 = boto3.resource("ec2", region_name="us-east-1")
    names = [f"ec2-dw-platform-use1-mimirread-10{i}p" for i in range(3)]
    instances = ec2.create_instances(ImageId="ami-12345678", MinCount=3, MaxCount=3)
    for inst, name in zip(instances, names, strict=False):
        inst.create_tags(Tags=[{"Key": "Name", "Value": name}])

    tools = EC2Tools(factory)
    mapping = tools.resolve_instance_names(names)
    assert len(mapping) == 3
    for name in names:
        assert name in mapping


@mock_aws
def test_tool_server_resolve_integration(factory):
    """Test resolution through the tool server call interface."""
    from unittest.mock import patch

    from ec2_troubleshooter.models.findings import DiagnosticStatus
    from ec2_troubleshooter.tools.tool_server import EC2ToolServer

    ec2 = boto3.resource("ec2", region_name="us-east-1")
    inst = ec2.create_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)[0]
    inst.create_tags(Tags=[{"Key": "Name", "Value": "mimir-read-01"}])

    settings = Settings(AWS_REGION="us-east-1")
    with patch("ec2_troubleshooter.tools.tool_server.PrometheusTools"):
        server = EC2ToolServer(settings)

    result = server.call("dummy", "ec2:resolve_instance_names", names=["mimir-read-01"])
    assert result.status == DiagnosticStatus.OK
    assert result.metrics["name_to_id"]["mimir-read-01"] == inst.id


class TestOrchestratorNameResolution:
    """Test that the orchestrator correctly resolves names before investigating."""

    def test_names_resolved_before_investigation(self):
        from unittest.mock import MagicMock

        from ec2_troubleshooter.models.alert import Alert, AlertSeverity
        from ec2_troubleshooter.models.findings import DiagnosticResult, DiagnosticStatus
        from ec2_troubleshooter.orchestrator.investigator import InvestigationOrchestrator


        mock_server = MagicMock()
        ok = DiagnosticResult(
            tool_name="ec2:describe_instance",
            status=DiagnosticStatus.OK,
            summary="ok",
            metrics={"state": "running", "instance_type": "r6g.xlarge",
                     "private_ip": "10.0.1.5", "availability_zone": "us-east-1a",
                     "tags": {}},
        )
        mock_server.call.return_value = ok
        mock_server._prom_tools.is_available.return_value = False
        mock_server._ssm_tools.is_managed.return_value = False
        mock_server.resolve_instance_names.return_value = {
            "ec2-dw-platform-use1-mimirread-102p": "i-0abc123",
        }

        alert = Alert(
            alert_id="a1",
            source="aiops_archetype",
            title="AIOps ALERT: platform-mimir (use1)",
            severity=AlertSeverity.HIGH,
            instance_names=["ec2-dw-platform-use1-mimirread-102p"],
        )

        orch = InvestigationOrchestrator(mock_server, Settings(AWS_REGION="us-east-1"))
        report = orch.investigate(alert)

        # resolve_instance_names should have been called with the name list
        mock_server.resolve_instance_names.assert_called_once_with(
            ["ec2-dw-platform-use1-mimirread-102p"]
        )
        # One instance investigated
        assert len(report.instances) == 1

    def test_no_ids_and_no_names_returns_error(self):
        from unittest.mock import MagicMock

        from ec2_troubleshooter.models.alert import Alert
        from ec2_troubleshooter.orchestrator.investigator import InvestigationOrchestrator

        mock_server = MagicMock()
        mock_server._prom_tools.is_available.return_value = False
        mock_server._ssm_tools.is_managed.return_value = False
        alert = Alert(alert_id="a2", source="test", title="Empty alert")
        orch = InvestigationOrchestrator(mock_server, Settings(AWS_REGION="us-east-1"))
        report = orch.investigate(alert)
        assert report.error is not None
        assert len(report.instances) == 0

    def test_aiops_scores_propagated_to_report(self):
        from unittest.mock import MagicMock

        from ec2_troubleshooter.models.alert import AIOpsScores, Alert, AlertSeverity
        from ec2_troubleshooter.models.findings import DiagnosticResult, DiagnosticStatus
        from ec2_troubleshooter.orchestrator.investigator import InvestigationOrchestrator


        mock_server = MagicMock()
        ok = DiagnosticResult(
            tool_name="ec2:describe_instance", status=DiagnosticStatus.OK, summary="ok",
            metrics={"state": "running", "private_ip": "10.0.1.5"}
        )
        mock_server.call.return_value = ok
        mock_server._prom_tools.is_available.return_value = False
        mock_server._ssm_tools.is_managed.return_value = False

        alert = Alert(
            alert_id="a3",
            source="aiops_archetype",
            title="t",
            severity=AlertSeverity.HIGH,
            instance_ids=["i-abc"],
            aiops=AIOpsScores(
                health=70.0, failure=86.1, risk=57.4,
                app_log_errors=574, state="UNHEALTHY_STABLE",
                policy_reason="first_unhealthy_bucket",
            ),
        )
        orch = InvestigationOrchestrator(mock_server, Settings(AWS_REGION="us-east-1"))
        report = orch.investigate(alert)

        assert report.aiops_health == 70.0
        assert report.aiops_failure == 86.1
        assert report.aiops_state == "UNHEALTHY_STABLE"
        assert report.aiops_app_log_errors == 574
        assert report.aiops_policy_reason == "first_unhealthy_bucket"
