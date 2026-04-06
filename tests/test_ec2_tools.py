"""Tests for EC2Tools using moto mocks."""

from __future__ import annotations

import boto3
import pytest

try:
    from moto import mock_aws
except ImportError:
    from moto import mock_ec2 as mock_aws  # type: ignore[no-reattr]

from ec2_troubleshooter.config.settings import Settings
from ec2_troubleshooter.models.findings import DiagnosticStatus
from ec2_troubleshooter.tools.aws_client import AWSClientFactory
from ec2_troubleshooter.tools.ec2_tools import EC2Tools


@pytest.fixture
def settings():
    return Settings(AWS_REGION="us-east-1")


@pytest.fixture
def factory(settings):
    return AWSClientFactory(settings)


@mock_aws
def test_describe_instance_not_found(factory):
    tools = EC2Tools(factory)
    result = tools.describe_instance("i-nonexistent")
    assert result.status == DiagnosticStatus.ERROR
    assert "not found" in result.summary or "error" in result.summary.lower()


@mock_aws
def test_describe_instance_running(factory):
    # Create a real EC2 instance via moto
    ec2 = boto3.resource("ec2", region_name="us-east-1")
    instance = ec2.create_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.medium",
    )[0]
    instance_id = instance.id

    tools = EC2Tools(factory)
    result = tools.describe_instance(instance_id)
    assert result.status == DiagnosticStatus.OK
    assert result.metrics["instance_id"] == instance_id
    assert result.metrics["state"] == "running"
    assert result.metrics["instance_type"] == "t3.medium"


@mock_aws
def test_get_instance_status(factory):
    ec2 = boto3.resource("ec2", region_name="us-east-1")
    instance = ec2.create_instances(
        ImageId="ami-12345678", MinCount=1, MaxCount=1
    )[0]
    tools = EC2Tools(factory)
    result = tools.get_instance_status(instance.id)
    # moto may return empty status; just check no crash
    assert result.tool_name == "ec2:get_instance_status"


@mock_aws
def test_describe_volumes(factory):
    boto3.client("ec2", region_name="us-east-1")
    ec2_resource = boto3.resource("ec2", region_name="us-east-1")
    instance = ec2_resource.create_instances(
        ImageId="ami-12345678", MinCount=1, MaxCount=1
    )[0]
    tools = EC2Tools(factory)
    result = tools.describe_volumes(instance.id)
    assert result.tool_name == "ec2:describe_volumes"
    assert "volumes" in result.metrics


@mock_aws
def test_get_console_output(factory):
    ec2_resource = boto3.resource("ec2", region_name="us-east-1")
    instance = ec2_resource.create_instances(
        ImageId="ami-12345678", MinCount=1, MaxCount=1
    )[0]
    tools = EC2Tools(factory)
    result = tools.get_console_output(instance.id)
    assert result.tool_name == "ec2:get_console_output"
