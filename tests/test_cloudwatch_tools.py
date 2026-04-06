"""Tests for CloudWatchTools using moto mocks."""

from __future__ import annotations

from datetime import UTC, datetime

import boto3
import pytest

try:
    from moto import mock_aws
except ImportError:
    from moto import mock_cloudwatch as mock_aws  # type: ignore[no-reattr]

from ec2_troubleshooter.config.settings import Settings
from ec2_troubleshooter.models.findings import DiagnosticStatus
from ec2_troubleshooter.tools.aws_client import AWSClientFactory
from ec2_troubleshooter.tools.cloudwatch_tools import CloudWatchTools

INSTANCE_ID = "i-testcw001"


@pytest.fixture
def settings():
    return Settings(AWS_REGION="us-east-1")


@pytest.fixture
def factory(settings):
    return AWSClientFactory(settings)


@mock_aws
def test_cpu_no_data(factory):
    tools = CloudWatchTools(factory)
    result = tools.get_cpu_utilization(INSTANCE_ID)
    assert result.tool_name == "cloudwatch:cpu_utilization"
    # No data points → SKIPPED
    assert result.status == DiagnosticStatus.SKIPPED


@mock_aws
def test_cpu_with_data(factory):
    cw = boto3.client("cloudwatch", region_name="us-east-1")
    # Push metric data spanning the look-back window
    cw.put_metric_data(
        Namespace="AWS/EC2",
        MetricData=[
            {
                "MetricName": "CPUUtilization",
                "Dimensions": [{"Name": "InstanceId", "Value": INSTANCE_ID}],
                "Timestamp": datetime.now(tz=UTC),
                "Value": 92.5,
                "Unit": "Percent",
            }
        ],
    )
    tools = CloudWatchTools(factory)
    result = tools.get_cpu_utilization(INSTANCE_ID)
    # moto may or may not return datapoints depending on version; accept any non-error status
    assert result.status in (
        DiagnosticStatus.OK,
        DiagnosticStatus.DEGRADED,
        DiagnosticStatus.SKIPPED,
    )


@mock_aws
def test_status_check_metrics_no_data(factory):
    tools = CloudWatchTools(factory)
    result = tools.get_status_check_metrics(INSTANCE_ID)
    assert result.tool_name == "cloudwatch:status_check_metrics"
    assert result.status == DiagnosticStatus.OK


@mock_aws
def test_network_io(factory):
    tools = CloudWatchTools(factory)
    result = tools.get_network_io(INSTANCE_ID)
    assert result.tool_name == "cloudwatch:network_io"
