"""Tests for PrometheusTools (Mimir/Prometheus query layer)."""

from __future__ import annotations

import httpx
import pytest
import respx

from ec2_troubleshooter.config.settings import Settings
from ec2_troubleshooter.models.findings import DiagnosticStatus
from ec2_troubleshooter.tools.prometheus_tools import PrometheusTools

INSTANCE_IP = "10.0.1.5"
MIMIR_URL = "http://mimir.internal:8080/prometheus"


@pytest.fixture
def settings_no_prom():
    return Settings(AWS_REGION="us-east-1")


@pytest.fixture
def settings_with_prom():
    return Settings(
        AWS_REGION="us-east-1",
        PROMETHEUS_URL=MIMIR_URL,
        PROMETHEUS_ORG_ID="my-org",
        PROMETHEUS_INSTANCE_LABEL="instance",
        PROMETHEUS_LOOKBACK_MINUTES=60,
        PROMETHEUS_STEP_SECONDS=60,
    )


# ── is_available ──────────────────────────────────────────────────────────

class TestAvailability:
    def test_not_available_when_url_missing(self, settings_no_prom):
        tools = PrometheusTools(settings_no_prom)
        assert tools.is_available() is False

    def test_available_when_url_set(self, settings_with_prom):
        tools = PrometheusTools(settings_with_prom)
        assert tools.is_available() is True


# ── get_node_metrics ──────────────────────────────────────────────────────

class TestGetNodeMetrics:
    def test_skipped_when_no_url(self, settings_no_prom):
        tools = PrometheusTools(settings_no_prom)
        result = tools.get_node_metrics(INSTANCE_IP)
        assert result.status == DiagnosticStatus.SKIPPED

    @respx.mock
    def test_returns_ok_with_data(self, settings_with_prom):
        # Mock every POST to /api/v1/query with a generic scalar response
        respx.post(f"{MIMIR_URL}/api/v1/query").mock(
            return_value=httpx.Response(
                200,
                json={
                    "status": "success",
                    "data": {
                        "resultType": "vector",
                        "result": [
                            {
                                "metric": {"instance": f"{INSTANCE_IP}:9100"},
                                "value": [1700000000, "45.2"],
                            }
                        ],
                    },
                },
            )
        )
        tools = PrometheusTools(settings_with_prom)
        result = tools.get_node_metrics(INSTANCE_IP)
        assert result.tool_name == "prometheus:node_metrics"
        # Mock returns 45.2 for every metric including oom_kills_rate → FAILED is valid
        assert result.status in (DiagnosticStatus.OK, DiagnosticStatus.DEGRADED, DiagnosticStatus.FAILED)
        assert result.metrics  # should have at least some entries

    @respx.mock
    def test_returns_skipped_on_empty_response(self, settings_with_prom):
        respx.post(f"{MIMIR_URL}/api/v1/query").mock(
            return_value=httpx.Response(
                200,
                json={"status": "success", "data": {"resultType": "vector", "result": []}},
            )
        )
        tools = PrometheusTools(settings_with_prom)
        result = tools.get_node_metrics(INSTANCE_IP)
        # All metrics unavailable → SKIPPED
        assert result.status == DiagnosticStatus.SKIPPED

    @respx.mock
    def test_handles_http_error_gracefully(self, settings_with_prom):
        respx.post(f"{MIMIR_URL}/api/v1/query").mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )
        tools = PrometheusTools(settings_with_prom)
        # Should not raise – errors are captured
        result = tools.get_node_metrics(INSTANCE_IP)
        assert result.tool_name == "prometheus:node_metrics"


# ── query ─────────────────────────────────────────────────────────────────

class TestQuery:
    def test_skipped_when_no_url(self, settings_no_prom):
        tools = PrometheusTools(settings_no_prom)
        result = tools.query("up")
        assert result.status == DiagnosticStatus.SKIPPED

    @respx.mock
    def test_returns_result(self, settings_with_prom):
        respx.post(f"{MIMIR_URL}/api/v1/query").mock(
            return_value=httpx.Response(
                200,
                json={
                    "status": "success",
                    "data": {
                        "resultType": "vector",
                        "result": [
                            {"metric": {}, "value": [1700000000, "1"]},
                        ],
                    },
                },
            )
        )
        tools = PrometheusTools(settings_with_prom)
        result = tools.query("up")
        assert result.status == DiagnosticStatus.OK

    def test_error_missing_promql(self, settings_no_prom):
        """Callers that pass empty PromQL should get SKIPPED (URL not set)."""
        tools = PrometheusTools(settings_no_prom)
        result = tools.query("")
        assert result.status == DiagnosticStatus.SKIPPED


# ── instance selector ─────────────────────────────────────────────────────

class TestInstanceSelector:
    def test_selector_contains_ip(self, settings_with_prom):
        tools = PrometheusTools(settings_with_prom)
        sel = tools._instance_selector("10.0.1.5")
        assert "10.0.1.5" in sel
        assert "=~" in sel  # regex match

    def test_selector_uses_configured_label(self, settings_with_prom):
        tools = PrometheusTools(settings_with_prom)
        sel = tools._instance_selector("10.0.0.1")
        assert sel.startswith("instance=~")


# ── X-Scope-OrgID header ──────────────────────────────────────────────────

class TestOrgIDHeader:
    @respx.mock
    def test_org_id_sent_in_header(self, settings_with_prom):
        route = respx.post(f"{MIMIR_URL}/api/v1/query").mock(
            return_value=httpx.Response(
                200,
                json={"status": "success", "data": {"resultType": "vector", "result": []}},
            )
        )
        tools = PrometheusTools(settings_with_prom)
        # org_id must be explicitly passed per-request (per-tenant routing)
        tools.query("up", org_id="my-org")
        assert route.called
        request = route.calls[0].request
        assert request.headers.get("x-scope-orgid") == "my-org"

    @respx.mock
    def test_different_org_ids_per_call(self, settings_with_prom):
        route = respx.post(f"{MIMIR_URL}/api/v1/query").mock(
            return_value=httpx.Response(
                200,
                json={"status": "success", "data": {"resultType": "vector", "result": []}},
            )
        )
        tools = PrometheusTools(settings_with_prom)
        tools.query("up", org_id="infra-tenant")
        tools.query("app_metric", org_id="app-tenant")
        assert route.call_count == 2
        assert route.calls[0].request.headers.get("x-scope-orgid") == "infra-tenant"
        assert route.calls[1].request.headers.get("x-scope-orgid") == "app-tenant"


# ── get_contributor_metrics ───────────────────────────────────────────────

class TestContributorMetrics:
    def test_skipped_when_no_url(self, settings_no_prom):
        tools = PrometheusTools(settings_no_prom)
        result = tools.get_contributor_metrics("my_metric", INSTANCE_IP)
        assert result.status == DiagnosticStatus.SKIPPED

    @respx.mock
    def test_returns_metric_value(self, settings_with_prom):
        respx.post(f"{MIMIR_URL}/api/v1/query").mock(
            return_value=httpx.Response(
                200,
                json={
                    "status": "success",
                    "data": {
                        "resultType": "vector",
                        "result": [{"metric": {}, "value": [1700000000, "88.5"]}],
                    },
                },
            )
        )
        tools = PrometheusTools(settings_with_prom)
        result = tools.get_contributor_metrics("my_app_metric", INSTANCE_IP)
        assert result.status == DiagnosticStatus.OK
        assert result.metrics.get("metric") == "my_app_metric"


# ── Status assessment ─────────────────────────────────────────────────────

class TestStatusAssessment:
    def test_ok_when_all_normal(self):
        metrics = {"cpu_usage_pct": 30.0, "memory_used_pct": 50.0}
        status = PrometheusTools._assess_node_status(metrics)
        assert status == DiagnosticStatus.OK

    def test_failed_on_high_cpu(self):
        metrics = {"cpu_usage_pct": 97.0}
        status = PrometheusTools._assess_node_status(metrics)
        assert status == DiagnosticStatus.FAILED

    def test_degraded_on_elevated_memory(self):
        metrics = {"memory_used_pct": 88.0}
        status = PrometheusTools._assess_node_status(metrics)
        assert status == DiagnosticStatus.DEGRADED

    def test_failed_on_oom_kills(self):
        metrics = {"oom_kills_rate": 0.01}
        status = PrometheusTools._assess_node_status(metrics)
        assert status == DiagnosticStatus.FAILED

    def test_skipped_on_empty(self):
        status = PrometheusTools._assess_node_status({})
        assert status == DiagnosticStatus.SKIPPED
