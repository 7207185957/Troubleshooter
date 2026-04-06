"""Tests for Settings / config module."""

from __future__ import annotations

import pytest

from ec2_troubleshooter.config.settings import Settings


class TestSettings:
    def test_defaults(self):
        s = Settings()
        assert s.aws_region == "us-east-1"
        assert s.use_vpc_endpoints is False
        assert s.reporter_type == "log"
        assert s.api_port == 8080

    def test_vpc_endpoint_routing(self, monkeypatch):
        monkeypatch.setenv("USE_VPC_ENDPOINTS", "true")
        monkeypatch.setenv("VPC_ENDPOINT_EC2", "https://vpce-abc.ec2.vpce.amazonaws.com")
        monkeypatch.setenv("VPC_ENDPOINT_SSM", "https://vpce-def.ssm.vpce.amazonaws.com")
        s = Settings()
        assert s.use_vpc_endpoints is True
        assert s.endpoint_for("ec2") == "https://vpce-abc.ec2.vpce.amazonaws.com"
        assert s.endpoint_for("ssm") == "https://vpce-def.ssm.vpce.amazonaws.com"
        assert s.endpoint_for("sts") is None

    def test_prometheus_settings(self, monkeypatch):
        monkeypatch.setenv("PROMETHEUS_URL", "http://mimir.internal:8080/prometheus")
        monkeypatch.setenv("PROMETHEUS_ORG_ID", "tenant-1")
        monkeypatch.setenv("PROMETHEUS_INSTANCE_LABEL", "instance")
        monkeypatch.setenv("PROMETHEUS_LOOKBACK_MINUTES", "90")
        s = Settings()
        assert s.prometheus_url == "http://mimir.internal:8080/prometheus"
        assert s.prometheus_org_id == "tenant-1"
        assert s.prometheus_lookback_minutes == 90

    def test_prometheus_defaults(self):
        s = Settings()
        assert s.prometheus_url is None
        assert s.prometheus_instance_label == "instance"
        assert s.prometheus_lookback_minutes == 60
        assert s.prometheus_step_seconds == 60
        assert s.prometheus_verify_ssl is True

    def test_no_vpc_endpoints_returns_none(self):
        s = Settings()
        assert s.endpoint_for("ec2") is None
        assert s.endpoint_for("ssm") is None

    def test_gchat_reporter_requires_url(self, monkeypatch):
        monkeypatch.setenv("REPORTER_TYPE", "gchat")
        with pytest.raises((ValueError, Exception)):
            Settings()

    def test_gchat_reporter_with_url(self, monkeypatch):
        monkeypatch.setenv("REPORTER_TYPE", "gchat")
        monkeypatch.setenv("REPORTER_GCHAT_WEBHOOK_URL", "https://chat.example.com/hook")
        s = Settings()
        assert s.reporter_type == "gchat"
        assert s.reporter_gchat_webhook_url == "https://chat.example.com/hook"

    def test_webhook_headers_from_json_string(self, monkeypatch):
        monkeypatch.setenv("REPORTER_TYPE", "webhook")
        monkeypatch.setenv("REPORTER_WEBHOOK_URL", "https://example.com/ingest")
        monkeypatch.setenv("REPORTER_WEBHOOK_HEADERS", '{"X-Api-Key": "secret"}')
        s = Settings()
        assert s.reporter_webhook_headers == {"X-Api-Key": "secret"}
