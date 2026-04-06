"""Tests for the FastAPI alert receiver."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from ec2_troubleshooter.alert.receiver import create_app
from ec2_troubleshooter.config.settings import Settings
from ec2_troubleshooter.models.findings import InvestigationReport


@pytest.fixture
def settings():
    return Settings(AWS_REGION="us-east-1", LOG_FORMAT="console", REPORTER_TYPE="log")


@pytest.fixture
def app(settings):
    with (
        patch("ec2_troubleshooter.alert.receiver.EC2ToolServer"),
        patch("ec2_troubleshooter.alert.receiver.InvestigationOrchestrator") as mock_orch,
        patch("ec2_troubleshooter.alert.receiver.build_reporter"),
        patch("ec2_troubleshooter.alert.receiver.AlertQueueManager") as mock_queue,
    ):
        mock_orch.return_value.investigate.return_value = InvestigationReport(
            alert_id="test-001",
            alert_title="Test",
            alert_source="test",
            severity="HIGH",
            summary="No issues found",
        )
        mock_queue.return_value.enqueue.return_value = True
        mock_queue.return_value.stats.return_value = MagicMock(depth=0)
        mock_queue.return_value.start = MagicMock(return_value=None)
        mock_queue.return_value.stop = MagicMock(return_value=None)
        return create_app(settings)


@pytest.fixture
def client(app):
    return TestClient(app)


class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


class TestAlertEndpoint:
    def test_alert_accepted(self, client):
        payload = {
            "alert_id": "a001",
            "source": "test",
            "title": "High CPU",
            "severity": "HIGH",
            "instance_ids": ["i-abc123"],
        }
        resp = client.post("/alert", json=payload)
        assert resp.status_code == 202
        assert resp.json()["alert_id"] == "a001"
        assert resp.json()["status"] == "accepted"

    def test_invalid_json_returns_400(self, client):
        resp = client.post("/alert", content=b"not-json", headers={"content-type": "application/json"})
        assert resp.status_code == 400

    def test_sync_alert_returns_report(self, client):
        payload = {
            "alert_id": "sync-001",
            "source": "test",
            "title": "Test",
            "instance_ids": ["i-xxx"],
        }
        resp = client.post("/alert/sync", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert "alert_id" in data


class TestAuthEndpoint:
    def test_token_required_when_configured(self):
        settings = Settings(
            AWS_REGION="us-east-1",
            REPORTER_TYPE="log",
            API_SECRET_TOKEN="mysecret",
        )
        with (
            patch("ec2_troubleshooter.alert.receiver.EC2ToolServer"),
            patch("ec2_troubleshooter.alert.receiver.InvestigationOrchestrator"),
            patch("ec2_troubleshooter.alert.receiver.build_reporter"),
        ):
            app = create_app(settings)
        c = TestClient(app)
        resp = c.get("/tools")
        assert resp.status_code == 401

    def test_valid_token_accepted(self):
        settings = Settings(
            AWS_REGION="us-east-1",
            REPORTER_TYPE="log",
            API_SECRET_TOKEN="mysecret",
        )
        with (
            patch("ec2_troubleshooter.alert.receiver.EC2ToolServer"),
            patch("ec2_troubleshooter.alert.receiver.InvestigationOrchestrator"),
            patch("ec2_troubleshooter.alert.receiver.build_reporter"),
        ):
            app = create_app(settings)
        c = TestClient(app)
        resp = c.get("/tools", headers={"Authorization": "Bearer mysecret"})
        assert resp.status_code == 200
