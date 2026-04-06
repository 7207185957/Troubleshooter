"""Tests for the AlertNormalizer."""

from __future__ import annotations

import pytest

from ec2_troubleshooter.alert.normalizer import AlertNormalizer
from ec2_troubleshooter.models.alert import AlertSeverity


@pytest.fixture
def normalizer():
    return AlertNormalizer()


class TestGenericNormalizer:
    def test_canonical_passthrough(self, normalizer):
        payload = {
            "alert_id": "alert-001",
            "source": "my-platform",
            "title": "High CPU",
            "severity": "HIGH",
            "instance_ids": ["i-abc123", "i-def456"],
        }
        alert = normalizer.normalize(payload)
        assert alert.alert_id == "alert-001"
        assert alert.severity == AlertSeverity.HIGH
        assert len(alert.instance_ids) == 2

    def test_generic_fallback(self, normalizer):
        payload = {"title": "mystery alert", "instances": ["i-xyz"]}
        alert = normalizer.normalize(payload, source_hint="generic")
        assert alert.title == "mystery alert"
        assert alert.instance_ids == ["i-xyz"]
        assert alert.alert_id.startswith("auto-")

    def test_unknown_severity_defaults(self, normalizer):
        payload = {"alert_id": "x", "source": "s", "title": "t", "severity": "UNKNOWN"}
        alert = normalizer.normalize(payload)
        assert alert.severity == AlertSeverity.UNKNOWN


class TestDatadogNormalizer:
    def test_datadog_parse(self, normalizer):
        payload = {
            "id": 12345,
            "title": "CPU high on worker",
            "alert_type": "alert",
            "tags": "instance_id:i-aaa111,archetype:airflow-worker,env:prod",
            "metric": "system.cpu.user",
        }
        alert = normalizer.normalize(payload, source_hint="datadog")
        assert alert.source == "datadog"
        assert alert.alert_id == "12345"
        assert alert.instance_ids == ["i-aaa111"]
        assert alert.archetype == "airflow-worker"
        assert alert.severity == AlertSeverity.HIGH
        assert len(alert.contributors) == 1
        assert alert.contributors[0].metric_name == "system.cpu.user"


class TestCloudWatchNormalizer:
    def test_cloudwatch_alarm_parse(self, normalizer):
        payload = {
            "detail": {
                "alarmName": "HighCPU-i-test123",
                "alarmArn": "arn:aws:cloudwatch:us-east-1:123:alarm:HighCPU",
                "state": {"value": "ALARM", "reason": "Threshold Crossed"},
                "configuration": {
                    "description": "CPU alarm",
                    "metrics": [],
                },
                "Trigger": {
                    "Dimensions": [{"name": "InstanceId", "value": "i-test123"}]
                },
            }
        }
        alert = normalizer.normalize(payload, source_hint="cloudwatch_alarm")
        assert alert.source == "cloudwatch_alarm"
        assert alert.severity == AlertSeverity.HIGH
        assert "i-test123" in alert.instance_ids
