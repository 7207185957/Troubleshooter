"""Tests for EC2ToolServer dispatch and allowlist enforcement."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from ec2_troubleshooter.config.settings import Settings
from ec2_troubleshooter.models.findings import DiagnosticResult, DiagnosticStatus
from ec2_troubleshooter.tools.tool_server import EC2ToolServer


@pytest.fixture
def settings():
    return Settings(AWS_REGION="us-east-1")


@pytest.fixture
def mock_server(settings):
    """Create an EC2ToolServer with all AWS calls mocked out."""
    with (
        patch("ec2_troubleshooter.tools.tool_server.AWSClientFactory"),
        patch("ec2_troubleshooter.tools.tool_server.EC2Tools") as mock_ec2,
        patch("ec2_troubleshooter.tools.tool_server.SSMTools") as mock_ssm,
        patch("ec2_troubleshooter.tools.tool_server.CloudWatchTools") as mock_cw,
    ):
        server = EC2ToolServer(settings)
        server._ec2_tools = mock_ec2.return_value
        server._ssm_tools = mock_ssm.return_value
        server._cw_tools = mock_cw.return_value
        yield server


class TestToolListing:
    def test_list_tools_returns_known_tools(self, mock_server):
        tools = mock_server.list_tools()
        assert "ec2:describe_instance" in tools
        assert "ec2:get_instance_status" in tools
        assert "cloudwatch:cpu_utilization" in tools
        assert "ssm:disk_usage" in tools
        assert "ssm:memory_free" in tools

    def test_list_tools_sorted(self, mock_server):
        tools = mock_server.list_tools()
        assert tools == sorted(tools)


class TestDispatch:
    def test_unknown_tool_returns_error(self, mock_server):
        result = mock_server.call("i-test", "notreal:tool")
        assert result.status == DiagnosticStatus.ERROR
        assert "Unknown tool" in result.summary

    def test_ssm_non_allowlisted_returns_error(self, mock_server):
        result = mock_server.call("i-test", "ssm:rm_rf_slash")
        assert result.status == DiagnosticStatus.ERROR

    def test_ec2_describe_dispatched(self, mock_server):
        expected = DiagnosticResult(
            tool_name="ec2:describe_instance",
            status=DiagnosticStatus.OK,
            summary="ok",
        )
        mock_server._ec2_tools.describe_instance.return_value = expected
        result = mock_server.call("i-abc", "ec2:describe_instance")
        assert result.status == DiagnosticStatus.OK
        mock_server._ec2_tools.describe_instance.assert_called_once_with("i-abc")

    def test_cw_cpu_dispatched(self, mock_server):
        expected = DiagnosticResult(
            tool_name="cloudwatch:cpu_utilization",
            status=DiagnosticStatus.OK,
            summary="ok",
        )
        mock_server._cw_tools.get_cpu_utilization.return_value = expected
        result = mock_server.call("i-abc", "cloudwatch:cpu_utilization")
        assert result.status == DiagnosticStatus.OK

    def test_ebs_metrics_requires_volume_id(self, mock_server):
        result = mock_server.call("i-abc", "cloudwatch:ebs_metrics")
        assert result.status == DiagnosticStatus.ERROR
        assert "volume_id" in result.summary


class TestStandardSuite:
    def test_standard_suite_skips_ssm_when_not_managed(self, mock_server):
        ok = DiagnosticResult(tool_name="x", status=DiagnosticStatus.OK, summary="ok")
        mock_server._ec2_tools.describe_instance.return_value = ok
        mock_server._ec2_tools.get_instance_status.return_value = ok
        mock_server._ec2_tools.describe_volumes.return_value = ok
        mock_server._ec2_tools.get_console_output.return_value = ok
        mock_server._cw_tools.get_cpu_utilization.return_value = ok
        mock_server._cw_tools.get_disk_io.return_value = ok
        mock_server._cw_tools.get_network_io.return_value = ok
        mock_server._cw_tools.get_status_check_metrics.return_value = ok
        mock_server._ssm_tools.is_managed.return_value = False

        results = mock_server.run_standard_suite("i-notmanaged")
        ssm_results = [r for r in results if r.tool_name.startswith("ssm:")]
        # Should only have the skipped availability marker
        assert len(ssm_results) == 1
        assert ssm_results[0].status == DiagnosticStatus.SKIPPED
