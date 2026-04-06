"""
Prometheus / Grafana Mimir query tools — multi-tenant aware.

Multi-tenancy
─────────────
Mimir uses the ``X-Scope-OrgID`` header to isolate tenants.  In this system
infra metrics (node_exporter) and app metrics live in **different tenants**:

    Infra tenant   – PROMETHEUS_INFRA_ORG_ID
                     Contains node_exporter series: cpu, memory, disk, net, …

    App tenants    – PROMETHEUS_APP_ORG_IDS (JSON mapping: archetype → org ID)
                     Contains application-specific metrics per archetype/team.

Every public method accepts an optional ``org_id`` override so the
orchestrator can route infra queries to the infra tenant and app queries to
the correct app tenant without creating separate PrometheusTools instances.

Air-gapped compatibility
────────────────────────
PROMETHEUS_URL is an internal URL.  TLS verification can be disabled or
customised via PROMETHEUS_VERIFY_SSL / PROMETHEUS_CA_CERT.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import structlog

from ec2_troubleshooter.config.settings import Settings
from ec2_troubleshooter.models.findings import DiagnosticResult, DiagnosticStatus

log = structlog.get_logger(__name__)


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


# ── Pre-built node_exporter PromQL expressions ─────────────────────────────
# Placeholder {INSTANCE_SELECTOR} is replaced at query time.

_NODE_QUERIES: dict[str, str] = {
    "cpu_usage_pct": (
        "100 - (avg by (instance) "
        "(rate(node_cpu_seconds_total{{mode='idle',{INSTANCE_SELECTOR}}}[5m])) * 100)"
    ),
    "cpu_by_mode": (
        "avg by (instance, mode) "
        "(rate(node_cpu_seconds_total{{{INSTANCE_SELECTOR}}}[5m])) * 100"
    ),
    "load_1m":  "node_load1{{{INSTANCE_SELECTOR}}}",
    "load_5m":  "node_load5{{{INSTANCE_SELECTOR}}}",
    "load_15m": "node_load15{{{INSTANCE_SELECTOR}}}",
    "memory_used_pct": (
        "100 - ((node_memory_MemAvailable_bytes{{{INSTANCE_SELECTOR}}} "
        "/ node_memory_MemTotal_bytes{{{INSTANCE_SELECTOR}}}) * 100)"
    ),
    "memory_total_bytes":     "node_memory_MemTotal_bytes{{{INSTANCE_SELECTOR}}}",
    "memory_available_bytes": "node_memory_MemAvailable_bytes{{{INSTANCE_SELECTOR}}}",
    "swap_used_pct": (
        "((node_memory_SwapTotal_bytes{{{INSTANCE_SELECTOR}}} "
        "- node_memory_SwapFree_bytes{{{INSTANCE_SELECTOR}}}) "
        "/ clamp_min(node_memory_SwapTotal_bytes{{{INSTANCE_SELECTOR}}}, 1)) * 100"
    ),
    "disk_used_pct": (
        "100 - ((node_filesystem_avail_bytes{{{INSTANCE_SELECTOR},"
        "fstype!~'tmpfs|devtmpfs|overlay|squashfs'}} "
        "/ node_filesystem_size_bytes{{{INSTANCE_SELECTOR},"
        "fstype!~'tmpfs|devtmpfs|overlay|squashfs'}}) * 100)"
    ),
    "disk_read_bytes_rate": (
        "sum by (instance) "
        "(rate(node_disk_read_bytes_total{{{INSTANCE_SELECTOR}}}[5m]))"
    ),
    "disk_write_bytes_rate": (
        "sum by (instance) "
        "(rate(node_disk_written_bytes_total{{{INSTANCE_SELECTOR}}}[5m]))"
    ),
    "disk_io_util_pct": (
        "rate(node_disk_io_time_seconds_total{{{INSTANCE_SELECTOR}}}[5m]) * 100"
    ),
    "network_receive_bytes_rate": (
        "sum by (instance) "
        "(rate(node_network_receive_bytes_total{{{INSTANCE_SELECTOR},"
        "device!~'lo|docker.*|veth.*'}}[5m]))"
    ),
    "network_transmit_bytes_rate": (
        "sum by (instance) "
        "(rate(node_network_transmit_bytes_total{{{INSTANCE_SELECTOR},"
        "device!~'lo|docker.*|veth.*'}}[5m]))"
    ),
    "network_errors_rate": (
        "sum by (instance) ("
        "rate(node_network_receive_errs_total{{{INSTANCE_SELECTOR}}}[5m]) + "
        "rate(node_network_transmit_errs_total{{{INSTANCE_SELECTOR}}}[5m]))"
    ),
    "fd_used_pct": (
        "(node_filefd_allocated{{{INSTANCE_SELECTOR}}} "
        "/ node_filefd_maximum{{{INSTANCE_SELECTOR}}}) * 100"
    ),
    "context_switches_rate": (
        "rate(node_context_switches_total{{{INSTANCE_SELECTOR}}}[5m])"
    ),
    "oom_kills_rate": (
        "rate(node_vmstat_oom_kill{{{INSTANCE_SELECTOR}}}[5m])"
    ),
}


class PrometheusTools:
    """
    Query Grafana Mimir (or any Prometheus-compatible backend).

    All public methods accept an optional ``org_id`` parameter that overrides
    the default X-Scope-OrgID for that specific call.  The orchestrator uses
    this to route infra queries to the infra tenant and app queries to the
    correct app tenant.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        # Shared base client (no org ID set — injected per request)
        self._base_client = self._build_base_client(settings)

    # ── Public API ─────────────────────────────────────────────────────────

    def is_available(self) -> bool:
        return bool(self._settings.prometheus_url)

    def get_node_metrics(self, instance_ip: str, org_id: str | None = None) -> DiagnosticResult:
        """
        Run the full node_exporter query suite for *instance_ip*.
        Use the infra org ID (PROMETHEUS_INFRA_ORG_ID) unless overridden.
        """
        tool = "prometheus:node_metrics"
        effective_org = org_id or self._settings.infra_org_id()
        if not self.is_available():
            return DiagnosticResult(
                tool_name=tool,
                status=DiagnosticStatus.SKIPPED,
                summary="PROMETHEUS_URL not configured – node metrics unavailable",
            )

        selector = self._instance_selector(instance_ip)
        results: dict[str, Any] = {}
        errors: list[str] = []

        for metric_key, expr_template in _NODE_QUERIES.items():
            expr = expr_template.replace("{INSTANCE_SELECTOR}", selector)
            value = self._query_instant(expr, org_id=effective_org)
            if value is None:
                errors.append(metric_key)
            else:
                results[metric_key] = value

        results["_org_id"] = effective_org  # store for report transparency
        status = self._assess_node_status(results)
        summary = self._node_summary(results, instance_ip)
        if errors:
            summary += f" ({len(errors)} metric(s) unavailable)"

        return DiagnosticResult(
            tool_name=tool,
            status=status,
            summary=summary,
            metrics=results,
        )

    def query(
        self,
        promql: str,
        instance_ip: str | None = None,
        org_id: str | None = None,
    ) -> DiagnosticResult:
        """Execute an arbitrary PromQL instant query."""
        tool = "prometheus:query"
        if not self.is_available():
            return DiagnosticResult(
                tool_name=tool, status=DiagnosticStatus.SKIPPED,
                summary="PROMETHEUS_URL not configured",
            )
        if instance_ip and "{INSTANCE_SELECTOR}" in promql:
            promql = promql.replace("{INSTANCE_SELECTOR}", self._instance_selector(instance_ip))

        value = self._query_instant(promql, org_id=org_id)
        if value is None:
            return DiagnosticResult(
                tool_name=tool, status=DiagnosticStatus.SKIPPED,
                summary=f"No data for query: {promql[:120]}",
                metrics={"query": promql, "org_id": org_id},
            )
        return DiagnosticResult(
            tool_name=tool, status=DiagnosticStatus.OK,
            summary=f"Query returned {len(value) if isinstance(value, list) else 1} series",
            metrics={"query": promql, "result": value, "org_id": org_id},
        )

    def query_range(
        self,
        promql: str,
        instance_ip: str | None = None,
        lookback_minutes: int | None = None,
        org_id: str | None = None,
    ) -> DiagnosticResult:
        """Execute a PromQL range query and return trend data."""
        tool = "prometheus:query_range"
        if not self.is_available():
            return DiagnosticResult(
                tool_name=tool, status=DiagnosticStatus.SKIPPED,
                summary="PROMETHEUS_URL not configured",
            )
        if instance_ip and "{INSTANCE_SELECTOR}" in promql:
            promql = promql.replace("{INSTANCE_SELECTOR}", self._instance_selector(instance_ip))

        lookback = lookback_minutes or self._settings.prometheus_lookback_minutes
        end = _utcnow()
        start = end - timedelta(minutes=lookback)
        data = self._query_range_raw(promql, start, end, org_id=org_id)
        if not data:
            return DiagnosticResult(
                tool_name=tool, status=DiagnosticStatus.SKIPPED,
                summary=f"No data for range query: {promql[:120]}",
                metrics={"query": promql, "org_id": org_id},
            )
        return DiagnosticResult(
            tool_name=tool, status=DiagnosticStatus.OK,
            summary=f"Range query returned {len(data)} series over last {lookback}m",
            metrics={"query": promql, "series": data, "org_id": org_id},
        )

    def get_contributor_metrics(
        self,
        metric_name: str,
        instance_ip: str,
        org_id: str | None = None,
        extra_labels: dict[str, str] | None = None,
    ) -> DiagnosticResult:
        """
        Query an app-specific metric from Mimir using the provided org ID.
        The caller is responsible for passing the correct app tenant org ID.
        """
        tool = f"prometheus:contributor:{metric_name}"
        if not self.is_available():
            return DiagnosticResult(
                tool_name=tool, status=DiagnosticStatus.SKIPPED,
                summary="PROMETHEUS_URL not configured",
            )

        selector_parts = [self._instance_selector(instance_ip)]
        if extra_labels:
            for k, v in extra_labels.items():
                selector_parts.append(f'{k}="{v}"')
        selector = ",".join(selector_parts)
        expr = f"{metric_name}{{{selector}}}"

        value = self._query_instant(expr, org_id=org_id)
        if value is None:
            return DiagnosticResult(
                tool_name=tool, status=DiagnosticStatus.SKIPPED,
                summary=f"No data for '{metric_name}' on {instance_ip} (org: {org_id})",
                metrics={"metric": metric_name, "instance": instance_ip, "org_id": org_id},
            )
        return DiagnosticResult(
            tool_name=tool, status=DiagnosticStatus.OK,
            summary=f"'{metric_name}': {value}  (org: {org_id})",
            metrics={"metric": metric_name, "instance": instance_ip,
                     "result": value, "org_id": org_id},
        )

    # ── Internal HTTP helpers ──────────────────────────────────────────────

    def _get_headers(self, org_id: str | None) -> dict[str, str]:
        """Build per-request headers, injecting the correct X-Scope-OrgID."""
        headers: dict[str, str] = {}
        if org_id:
            headers["X-Scope-OrgID"] = org_id
        if self._settings.prometheus_token:
            headers["Authorization"] = f"Bearer {self._settings.prometheus_token}"
        return headers

    def _query_instant(self, expr: str, org_id: str | None = None) -> Any:
        url = self._settings.prometheus_url.rstrip("/") + "/api/v1/query"  # type: ignore[union-attr]
        try:
            resp = self._base_client.post(
                url,
                data={"query": expr, "time": _utcnow().timestamp()},
                headers=self._get_headers(org_id),
            )
            resp.raise_for_status()
            return self._parse_instant(resp.json())
        except Exception as exc:
            log.warning("prometheus.query_instant failed",
                        expr=expr[:120], org_id=org_id, error=str(exc))
            return None

    def _query_range_raw(
        self, expr: str, start: datetime, end: datetime, org_id: str | None = None
    ) -> list[dict[str, Any]]:
        url = self._settings.prometheus_url.rstrip("/") + "/api/v1/query_range"  # type: ignore[union-attr]
        try:
            resp = self._base_client.post(
                url,
                data={
                    "query": expr,
                    "start": start.timestamp(),
                    "end": end.timestamp(),
                    "step": self._settings.prometheus_step_seconds,
                },
                headers=self._get_headers(org_id),
            )
            resp.raise_for_status()
            return resp.json().get("data", {}).get("result", [])
        except Exception as exc:
            log.warning("prometheus.query_range failed",
                        expr=expr[:120], org_id=org_id, error=str(exc))
            return []

    @staticmethod
    def _parse_instant(body: dict[str, Any]) -> Any:
        result_type = body.get("data", {}).get("resultType")
        results = body.get("data", {}).get("result", [])
        if not results:
            return None
        if result_type == "scalar":
            return float(results[1])
        if result_type == "vector":
            parsed = []
            for r in results:
                try:
                    val = float(r["value"][1])
                except (KeyError, IndexError, ValueError):
                    val = None
                parsed.append({"labels": r.get("metric", {}), "value": val})
            return parsed[0]["value"] if len(parsed) == 1 else parsed
        return results

    def _instance_selector(self, instance_ip: str) -> str:
        label = self._settings.prometheus_instance_label
        return f'{label}=~"{instance_ip}(:[0-9]+)?"'

    @staticmethod
    def _build_base_client(settings: Settings) -> httpx.Client:
        """Build a base httpx client with auth and TLS but WITHOUT org ID headers."""
        headers: dict[str, str] = {}
        # Token auth is added per-request via _get_headers; avoid double injection
        auth: httpx.Auth | None = None
        if settings.prometheus_username and settings.prometheus_password:
            auth = httpx.BasicAuth(settings.prometheus_username, settings.prometheus_password)

        verify: bool | str = settings.prometheus_verify_ssl
        if settings.prometheus_ca_cert:
            verify = settings.prometheus_ca_cert

        return httpx.Client(
            headers=headers,
            auth=auth,
            verify=verify,
            timeout=settings.prometheus_timeout_sec,
            follow_redirects=True,
        )

    # ── Status assessment ──────────────────────────────────────────────────

    @staticmethod
    def _assess_node_status(metrics: dict[str, Any]) -> DiagnosticStatus:
        cpu  = _safe_float(metrics.get("cpu_usage_pct"))
        mem  = _safe_float(metrics.get("memory_used_pct"))
        swap = _safe_float(metrics.get("swap_used_pct"))
        fd   = _safe_float(metrics.get("fd_used_pct"))
        oom  = _safe_float(metrics.get("oom_kills_rate"))

        if oom and oom > 0:
            return DiagnosticStatus.FAILED
        if (cpu and cpu > 95) or (mem and mem > 95):
            return DiagnosticStatus.FAILED
        if (cpu and cpu > 80) or (mem and mem > 85):
            return DiagnosticStatus.DEGRADED
        if (swap and swap > 50) or (fd and fd > 85):
            return DiagnosticStatus.DEGRADED
        if not any(v is not None for k, v in metrics.items() if not k.startswith("_")):
            return DiagnosticStatus.SKIPPED
        return DiagnosticStatus.OK

    @staticmethod
    def _node_summary(metrics: dict[str, Any], instance_ip: str) -> str:
        parts: list[str] = []
        if (v := _safe_float(metrics.get("cpu_usage_pct"))) is not None:
            parts.append(f"CPU={v:.1f}%")
        if (v := _safe_float(metrics.get("memory_used_pct"))) is not None:
            parts.append(f"Mem={v:.1f}%")
        if (v := _safe_float(metrics.get("load_1m"))) is not None:
            parts.append(f"Load1m={v:.2f}")
        return (f"{instance_ip} – " + ", ".join(parts)) if parts else f"No node metrics for {instance_ip}"


def _safe_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
