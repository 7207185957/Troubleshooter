"""Tests for the AIOps Archetype Notifications normalizer."""

from __future__ import annotations

import pytest

from ec2_troubleshooter.alert.normalizer import AlertNormalizer, _looks_like_aiops
from ec2_troubleshooter.models.alert import AlertSeverity


@pytest.fixture
def normalizer():
    return AlertNormalizer()


# ── Payload matching the screenshot ───────────────────────────────────────

SCREENSHOT_PAYLOAD = {
    "title": "AIOps ALERT: platform-mimir (use1)",
    "state": "UNHEALTHY_STABLE",
    "timestamp": "2026-04-06T15:55:00+00:00",
    "health": 70.0,
    "failure": 86.1,
    "risk": 57.4000000000000006,
    "contributors": "App logs",
    "metric_contributors": "app_log_errors",
    "affected_instances": [
        "ec2-dw-platform-use1-mimirread-102p",
        "ec2-dw-platform-use1-mimirread-103p",
        "ec2-dw-platform-use1-mimirread-106p",
        "ec2-dw-platform-use1-mimirread-110p",
        "ec2-dw-platform-use1-mimirwrite-101p",
        "ec2-dw-platform-use1-mimirwrite-102p",
        "ec2-dw-platform-use1-mimirwrite-103p",
        "ec2-dw-platform-use1-mimirwrite-104p",
        "ec2-dw-platform-use1-mimirwrite-105p",
        "ec2-dw-platform-use1-mimirwrite-107p",
    ],
    "infra_anomalies": 0,
    "app_anomalies": 0,
    "app_log_errors": 574,
    "dag_log_errors": 0,
    "policy_reason": "first_unhealthy_bucket",
}


class TestAIOpsNormalizerScreenshot:
    def test_parse_with_source_hint(self, normalizer):
        alert = normalizer.normalize(SCREENSHOT_PAYLOAD, source_hint="aiops_archetype")
        assert alert.source == "aiops_archetype"

    def test_auto_detection_without_hint(self, normalizer):
        alert = normalizer.normalize(SCREENSHOT_PAYLOAD)
        assert alert.source == "aiops_archetype"

    def test_title_preserved(self, normalizer):
        alert = normalizer.normalize(SCREENSHOT_PAYLOAD)
        assert "platform-mimir" in alert.title

    def test_archetype_extracted_from_title(self, normalizer):
        alert = normalizer.normalize(SCREENSHOT_PAYLOAD)
        assert alert.archetype == "platform-mimir (use1)"

    def test_instance_names_populated(self, normalizer):
        alert = normalizer.normalize(SCREENSHOT_PAYLOAD)
        assert len(alert.instance_names) == 10
        assert "ec2-dw-platform-use1-mimirread-102p" in alert.instance_names
        assert "ec2-dw-platform-use1-mimirwrite-107p" in alert.instance_names

    def test_instance_ids_empty_before_resolution(self, normalizer):
        """instance_ids should be empty – populated later by name resolution."""
        alert = normalizer.normalize(SCREENSHOT_PAYLOAD)
        assert alert.instance_ids == []

    def test_severity_from_unhealthy_stable(self, normalizer):
        alert = normalizer.normalize(SCREENSHOT_PAYLOAD)
        assert alert.severity == AlertSeverity.HIGH

    def test_aiops_scores(self, normalizer):
        alert = normalizer.normalize(SCREENSHOT_PAYLOAD)
        assert alert.aiops is not None
        assert alert.aiops.health == 70.0
        assert alert.aiops.failure == 86.1
        assert abs(alert.aiops.risk - 57.4) < 0.01
        assert alert.aiops.app_log_errors == 574
        assert alert.aiops.dag_log_errors == 0
        assert alert.aiops.infra_anomalies == 0
        assert alert.aiops.state == "UNHEALTHY_STABLE"
        assert alert.aiops.policy_reason == "first_unhealthy_bucket"

    def test_metric_contributor_parsed(self, normalizer):
        alert = normalizer.normalize(SCREENSHOT_PAYLOAD)
        assert len(alert.contributors) >= 1
        assert any(c.metric_name == "app_log_errors" for c in alert.contributors)

    def test_fired_at_parsed(self, normalizer):
        alert = normalizer.normalize(SCREENSHOT_PAYLOAD)
        assert alert.fired_at.year == 2026
        assert alert.fired_at.month == 4


class TestAIOpsNormalizerEdgeCases:
    def test_comma_separated_instances(self, normalizer):
        payload = {
            **SCREENSHOT_PAYLOAD,
            "affected_instances": "host-1, host-2, host-3",
        }
        alert = normalizer.normalize(payload, source_hint="aiops_archetype")
        assert len(alert.instance_names) == 3

    def test_comma_separated_metric_contributors(self, normalizer):
        payload = {
            **SCREENSHOT_PAYLOAD,
            "metric_contributors": "app_log_errors, cpu_usage",
        }
        alert = normalizer.normalize(payload, source_hint="aiops_archetype")
        names = [c.metric_name for c in alert.contributors]
        assert "app_log_errors" in names
        assert "cpu_usage" in names

    def test_degrading_state_maps_to_high(self, normalizer):
        payload = {**SCREENSHOT_PAYLOAD, "state": "DEGRADING"}
        alert = normalizer.normalize(payload, source_hint="aiops_archetype")
        assert alert.severity == AlertSeverity.HIGH

    def test_healthy_state_maps_to_low(self, normalizer):
        payload = {**SCREENSHOT_PAYLOAD, "state": "HEALTHY"}
        alert = normalizer.normalize(payload, source_hint="aiops_archetype")
        assert alert.severity == AlertSeverity.LOW

    def test_explicit_archetype_field_takes_precedence(self, normalizer):
        payload = {**SCREENSHOT_PAYLOAD, "archetype": "my-explicit-archetype"}
        alert = normalizer.normalize(payload, source_hint="aiops_archetype")
        assert alert.archetype == "my-explicit-archetype"

    def test_missing_optional_fields_no_crash(self, normalizer):
        minimal = {
            "health": 50.0,
            "failure": 90.0,
            "affected_instances": ["host-a"],
        }
        alert = normalizer.normalize(minimal, source_hint="aiops_archetype")
        assert len(alert.instance_names) == 1
        assert alert.aiops is not None
        assert alert.aiops.health == 50.0


class TestAutoDetection:
    def test_looks_like_aiops_true(self):
        assert _looks_like_aiops(SCREENSHOT_PAYLOAD) is True

    def test_looks_like_aiops_false_for_generic(self):
        assert _looks_like_aiops({"title": "some alert", "severity": "HIGH"}) is False

    def test_auto_detect_routes_correctly(self, normalizer):
        # No source_hint supplied – should detect aiops_archetype automatically
        alert = normalizer.normalize(SCREENSHOT_PAYLOAD)
        assert alert.source == "aiops_archetype"
