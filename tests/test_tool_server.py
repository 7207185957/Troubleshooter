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
    """Create an EC2ToolServer with all AWS/Prometheus calls mocked out."""
    with (
        patch("ec2_troubleshooter.tools.tool_server.AWSClientFactory"),
        patch("ec2_troubleshooter.tools.tool_server.EC2Tools") as mock_ec2,
        patch("ec2_troubleshooter.tools.tool_server.SSMTools") as mock_ssm,
        patch("ec2_troubleshooter.tools.tool_server.PrometheusTools") as mock_prom,
    ):
        server = EC2ToolServer(settings)
        server._ec2_tools = mock_ec2.return_value
        server._ssm_tools = mock_ssm.return_value
        server._prom_tools = mock_prom.return_value
        yield server


class TestToolListing:
    def test_list_tools_returns_known_tools(self, mock_server):
        tools = mock_server.list_tools()
        assert "ec2:describe_instance" in tools
        assert "ec2:get_instance_status" in tools
        assert "prometheus:node_metrics" in tools
        assert "prometheus:query" in tools
        assert "prometheus:query_range" in tools
        assert "prometheus:contributor_metric" in tools
        assert "ssm:disk_usage" in tools
        assert "ssm:memory_free" in tools

    def test_list_tools_no_cloudwatch(self, mock_server):
        tools = mock_server.list_tools()
        assert not any(t.startswith("cloudwatch:") for t in tools)

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

    def test_prometheus_node_metrics_requires_ip(self, mock_server):
        result = mock_server.call("i-abc", "prometheus:node_metrics")
        assert result.status == DiagnosticStatus.ERROR
        assert "instance_ip" in result.summary

    def test_prometheus_node_metrics_dispatched(self, mock_server):
        expected = DiagnosticResult(
            tool_name="prometheus:node_metrics",
            status=DiagnosticStatus.OK,
            summary="ok",
        )
        mock_server._prom_tools.get_node_metrics.return_value = expected
        result = mock_server.call("i-abc", "prometheus:node_metrics",
                                  instance_ip="10.0.0.1", org_id="infra")
        assert result.status == DiagnosticStatus.OK
        mock_server._prom_tools.get_node_metrics.assert_called_once_with(
            "10.0.0.1", org_id="infra"
        )

    def test_prometheus_query_requires_promql(self, mock_server):
        result = mock_server.call("i-abc", "prometheus:query")
        assert result.status == DiagnosticStatus.ERROR
        assert "promql" in result.summary

    def test_prometheus_query_dispatched(self, mock_server):
        expected = DiagnosticResult(
            tool_name="prometheus:query",
            status=DiagnosticStatus.OK,
            summary="ok",
        )
        mock_server._prom_tools.query.return_value = expected
        result = mock_server.call(
            "i-abc", "prometheus:query", promql="up", instance_ip="10.0.0.1"
        )
        assert result.status == DiagnosticStatus.OK

    def test_prometheus_contributor_metric_requires_ip_and_name(self, mock_server):
        result = mock_server.call("i-abc", "prometheus:contributor_metric", metric_name="my_m")
        assert result.status == DiagnosticStatus.ERROR


class TestStandardSuite:
    def test_standard_suite_skips_ssm_when_not_managed(self, mock_server):
        ok = DiagnosticResult(tool_name="x", status=DiagnosticStatus.OK, summary="ok",
                              metrics={"private_ip": "10.0.0.1", "state": "running"})
        mock_server._ec2_tools.describe_instance.return_value = ok
        mock_server._ec2_tools.get_instance_status.return_value = ok
        mock_server._ec2_tools.describe_volumes.return_value = ok
        mock_server._ec2_tools.get_console_output.return_value = ok
        mock_server._prom_tools.is_available.return_value = False
        mock_server._ssm_tools.is_managed.return_value = False

        results = mock_server.run_standard_suite("i-notmanaged", instance_ip="10.0.0.1")
        ssm_results = [r for r in results if r.tool_name.startswith("ssm:")]
        assert len(ssm_results) == 1
        assert ssm_results[0].status == DiagnosticStatus.SKIPPED

    def test_standard_suite_calls_prometheus_when_available(self, mock_server):
        ok = DiagnosticResult(tool_name="x", status=DiagnosticStatus.OK, summary="ok",
                              metrics={"private_ip": "10.0.0.1"})
        prom_ok = DiagnosticResult(
            tool_name="prometheus:node_metrics", status=DiagnosticStatus.OK, summary="ok"
        )
        mock_server._ec2_tools.describe_instance.return_value = ok
        mock_server._ec2_tools.get_instance_status.return_value = ok
        mock_server._ec2_tools.describe_volumes.return_value = ok
        mock_server._ec2_tools.get_console_output.return_value = ok
        mock_server._prom_tools.is_available.return_value = True
        mock_server._prom_tools.get_node_metrics.return_value = prom_ok
        mock_server._ssm_tools.is_managed.return_value = False

        results = mock_server.run_standard_suite("i-test", instance_ip="10.0.0.1")
        prom_results = [r for r in results if r.tool_name == "prometheus:node_metrics"]
        assert len(prom_results) == 1
        assert prom_results[0].status == DiagnosticStatus.OK
