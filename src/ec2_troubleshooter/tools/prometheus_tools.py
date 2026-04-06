"""
Prometheus / Grafana Mimir query tools.

All metrics — node-level (node_exporter) and application-specific — are
queried through the Prometheus-compatible HTTP API that Mimir exposes.

Air-gapped compatibility
────────────────────────
The Mimir endpoint is an internal URL (e.g. http://mimir.internal:8080).
No public internet access is required.  TLS verification can be disabled
or a custom CA bundle can be supplied for internal PKI.

Multi-tenancy
─────────────
Mimir requires the ``X-Scope-OrgID`` header to identify the tenant.  Set
``PROMETHEUS_ORG_ID`` and it will be injected on every request automatically.

Instance matching
─────────────────
node_exporter exposes metrics with an ``instance`` label that is typically
``<private_ip>:<port>`` (default port 9100).  The ``instance_label`` setting
controls which label name to use; the value is matched with a regex so both
``10.0.1.5:9100`` and ``10.0.1.5`` will match a query for IP ``10.0.1.5``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
import structlog

from ec2_troubleshooter.config.settings import Settings
from ec2_troubleshooter.models.findings import DiagnosticResult, DiagnosticStatus

log = structlog.get_logger(__name__)


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


# ── Pre-built node_exporter PromQL expressions ─────────────────────────────
#
# All use a placeholder ``{INSTANCE_SELECTOR}`` which is replaced at query
# time with the real label selector, e.g. instance=~"10.0.1.5.*"
#
# The expressions are intentionally simple so they work across all common
# node_exporter versions without relying on recording rules.

_NODE_QUERIES: dict[str, str] = {
    # CPU – 5-minute average utilisation across all non-idle modes
    "cpu_usage_pct": (
        "100 - (avg by (instance) "
        "(rate(node_cpu_seconds_total{{mode='idle',{INSTANCE_SELECTOR}}}[5m])) * 100)"
    ),
    # Per-mode CPU breakdown (user, system, iowait, steal)
    "cpu_by_mode": (
        "avg by (instance, mode) "
        "(rate(node_cpu_seconds_total{{{INSTANCE_SELECTOR}}}[5m])) * 100"
    ),
    # System load averages
    "load_1m": "node_load1{{{INSTANCE_SELECTOR}}}",
    "load_5m": "node_load5{{{INSTANCE_SELECTOR}}}",
    "load_15m": "node_load15{{{INSTANCE_SELECTOR}}}",
    # Memory
    "memory_used_pct": (
        "100 - ((node_memory_MemAvailable_bytes{{{INSTANCE_SELECTOR}}} "
        "/ node_memory_MemTotal_bytes{{{INSTANCE_SELECTOR}}}) * 100)"
    ),
    "memory_total_bytes": "node_memory_MemTotal_bytes{{{INSTANCE_SELECTOR}}}",
    "memory_available_bytes": "node_memory_MemAvailable_bytes{{{INSTANCE_SELECTOR}}}",
    # Swap
    "swap_used_pct": (
        "((node_memory_SwapTotal_bytes{{{INSTANCE_SELECTOR}}} "
        "- node_memory_SwapFree_bytes{{{INSTANCE_SELECTOR}}}) "
        "/ clamp_min(node_memory_SwapTotal_bytes{{{INSTANCE_SELECTOR}}}, 1)) * 100"
    ),
    # Disk usage per filesystem (excludes tmpfs/devtmpfs)
    "disk_used_pct": (
        "100 - ((node_filesystem_avail_bytes{{{INSTANCE_SELECTOR},"
        "fstype!~'tmpfs|devtmpfs|overlay|squashfs'}} "
        "/ node_filesystem_size_bytes{{{INSTANCE_SELECTOR},"
        "fstype!~'tmpfs|devtmpfs|overlay|squashfs'}}) * 100)"
    ),
    # Disk I/O throughput (bytes/sec averaged over 5m)
    "disk_read_bytes_rate": (
        "sum by (instance) "
        "(rate(node_disk_read_bytes_total{{{INSTANCE_SELECTOR}}}[5m]))"
    ),
    "disk_write_bytes_rate": (
        "sum by (instance) "
        "(rate(node_disk_written_bytes_total{{{INSTANCE_SELECTOR}}}[5m]))"
    ),
    # Disk I/O utilisation (% of time device was busy)
    "disk_io_util_pct": (
        "rate(node_disk_io_time_seconds_total{{{INSTANCE_SELECTOR}}}[5m]) * 100"
    ),
    # Network throughput (bytes/sec)
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
    # Network errors + drops
    "network_errors_rate": (
        "sum by (instance) ("
        "rate(node_network_receive_errs_total{{{INSTANCE_SELECTOR}}}[5m]) + "
        "rate(node_network_transmit_errs_total{{{INSTANCE_SELECTOR}}}[5m]))"
    ),
    # File descriptors
    "fd_used_pct": (
        "(node_filefd_allocated{{{INSTANCE_SELECTOR}}} "
        "/ node_filefd_maximum{{{INSTANCE_SELECTOR}}}) * 100"
    ),
    # Context switches / interrupts (indicators of CPU thrashing)
    "context_switches_rate": (
        "rate(node_context_switches_total{{{INSTANCE_SELECTOR}}}[5m])"
    ),
    # OOM kill counter (increments each time the kernel OOM-kills a process)
    "oom_kills_rate": (
        "rate(node_vmstat_oom_kill{{{INSTANCE_SELECTOR}}}[5m])"
    ),
}


class PrometheusTools:
    """
    Query Grafana Mimir (or any Prometheus-compatible backend) for both
    node-level and application-specific metrics.

    All requests include ``X-Scope-OrgID`` when ``prometheus_org_id`` is set.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client = self._build_client(settings)

    # ── Public API ─────────────────────────────────────────────────────────

    def is_available(self) -> bool:
        """Return True if the Prometheus/Mimir URL is configured."""
        return bool(self._settings.prometheus_url)

    def get_node_metrics(self, instance_ip: str) -> DiagnosticResult:
        """
        Run the full set of pre-built node_exporter queries for *instance_ip*
        and return a single DiagnosticResult with all metric summaries.
        """
        tool = "prometheus:node_metrics"
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
            value = self._query_instant(expr)
            if value is None:
                errors.append(metric_key)
            else:
                results[metric_key] = value

        status = self._assess_node_status(results)
        summary = self._node_summary(results, instance_ip)
        if errors:
            summary += f" ({len(errors)} metric(s) unavailable: {', '.join(errors[:5])})"

        return DiagnosticResult(
            tool_name=tool,
            status=status,
            summary=summary,
            metrics=results,
        )

    def query(self, promql: str, instance_ip: str | None = None) -> DiagnosticResult:
        """
        Execute an arbitrary PromQL instant query against Mimir.

        This is the **app-specific metrics** tool.  The orchestrator can call
        this with contributor metrics from the alert (e.g. a custom JVM heap
        metric, a Kafka consumer lag metric, etc.).

        If *instance_ip* is provided the instance selector is automatically
        injected as an additional label filter when the expression contains
        the placeholder ``{INSTANCE_SELECTOR}``.  Otherwise the expression is
        used verbatim.
        """
        tool = "prometheus:query"
        if not self.is_available():
            return DiagnosticResult(
                tool_name=tool,
                status=DiagnosticStatus.SKIPPED,
                summary="PROMETHEUS_URL not configured",
            )

        if instance_ip and "{INSTANCE_SELECTOR}" in promql:
            promql = promql.replace("{INSTANCE_SELECTOR}", self._instance_selector(instance_ip))

        value = self._query_instant(promql)
        if value is None:
            return DiagnosticResult(
                tool_name=tool,
                status=DiagnosticStatus.SKIPPED,
                summary=f"No data returned for query: {promql[:120]}",
                metrics={"query": promql},
            )
        return DiagnosticResult(
            tool_name=tool,
            status=DiagnosticStatus.OK,
            summary=f"Query returned {len(value) if isinstance(value, list) else 1} series",
            metrics={"query": promql, "result": value},
        )

    def query_range(
        self,
        promql: str,
        instance_ip: str | None = None,
        lookback_minutes: int | None = None,
    ) -> DiagnosticResult:
        """
        Execute a PromQL range query.  Returns one value per step over the
        lookback window.  Useful for trend analysis (e.g. did CPU spike 10
        minutes ago and recover?).
        """
        tool = "prometheus:query_range"
        if not self.is_available():
            return DiagnosticResult(
                tool_name=tool,
                status=DiagnosticStatus.SKIPPED,
                summary="PROMETHEUS_URL not configured",
            )

        if instance_ip and "{INSTANCE_SELECTOR}" in promql:
            promql = promql.replace("{INSTANCE_SELECTOR}", self._instance_selector(instance_ip))

        lookback = lookback_minutes or self._settings.prometheus_lookback_minutes
        end = _utcnow()
        from datetime import timedelta
        start = end - timedelta(minutes=lookback)

        data = self._query_range_raw(promql, start, end)
        if not data:
            return DiagnosticResult(
                tool_name=tool,
                status=DiagnosticStatus.SKIPPED,
                summary=f"No data returned for range query: {promql[:120]}",
                metrics={"query": promql},
            )
        return DiagnosticResult(
            tool_name=tool,
            status=DiagnosticStatus.OK,
            summary=f"Range query returned {len(data)} series over last {lookback}m",
            metrics={"query": promql, "series": data},
        )

    def get_contributor_metrics(
        self,
        metric_name: str,
        instance_ip: str,
        extra_labels: dict[str, str] | None = None,
    ) -> DiagnosticResult:
        """
        Query a specific metric by name, scoped to the instance.

        Intended to be called with the contributor metric_names extracted from
        an incoming alert so the agent can surface the actual current value
        alongside its historical trend.
        """
        tool = f"prometheus:contributor:{metric_name}"
        if not self.is_available():
            return DiagnosticResult(
                tool_name=tool,
                status=DiagnosticStatus.SKIPPED,
                summary="PROMETHEUS_URL not configured",
            )

        selector_parts = [self._instance_selector(instance_ip)]
        if extra_labels:
            for k, v in extra_labels.items():
                selector_parts.append(f'{k}="{v}"')

        selector = ",".join(selector_parts)
        expr = f"{metric_name}{{{selector}}}"

        value = self._query_instant(expr)
        if value is None:
            return DiagnosticResult(
                tool_name=tool,
                status=DiagnosticStatus.SKIPPED,
                summary=f"No data for contributor metric '{metric_name}' on {instance_ip}",
                metrics={"metric": metric_name, "instance": instance_ip},
            )
        return DiagnosticResult(
            tool_name=tool,
            status=DiagnosticStatus.OK,
            summary=f"Contributor metric '{metric_name}': {value}",
            metrics={"metric": metric_name, "instance": instance_ip, "result": value},
        )

    # ── Internal HTTP helpers ──────────────────────────────────────────────

    def _query_instant(self, expr: str) -> Any:
        """
        POST to /api/v1/query (instant) and return the parsed result values.

        Returns a scalar float, a list of {metric, value} dicts, or None on
        error / no data.
        """
        url = self._settings.prometheus_url.rstrip("/") + "/api/v1/query"  # type: ignore[union-attr]
        try:
            resp = self._client.post(url, data={"query": expr, "time": _utcnow().timestamp()})
            resp.raise_for_status()
            body = resp.json()
            return self._parse_instant(body)
        except Exception as exc:
            log.warning("prometheus.query_instant failed", expr=expr[:120], error=str(exc))
            return None

    def _query_range_raw(
        self, expr: str, start: datetime, end: datetime
    ) -> list[dict[str, Any]]:
        """POST to /api/v1/query_range and return the raw result list."""
        url = self._settings.prometheus_url.rstrip("/") + "/api/v1/query_range"  # type: ignore[union-attr]
        try:
            resp = self._client.post(
                url,
                data={
                    "query": expr,
                    "start": start.timestamp(),
                    "end": end.timestamp(),
                    "step": self._settings.prometheus_step_seconds,
                },
            )
            resp.raise_for_status()
            body = resp.json()
            return body.get("data", {}).get("result", [])
        except Exception as exc:
            log.warning("prometheus.query_range failed", expr=expr[:120], error=str(exc))
            return []

    @staticmethod
    def _parse_instant(body: dict[str, Any]) -> Any:
        """
        Parse the Prometheus /api/v1/query response.

        - vector  → list of {labels, value} dicts (most common)
        - scalar  → single float
        - matrix  → list of {labels, values} (shouldn't happen for instant)
        """
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
            if len(parsed) == 1:
                return parsed[0]["value"]
            return parsed
        return results

    def _instance_selector(self, instance_ip: str) -> str:
        """
        Build a Prometheus label selector that matches the instance by IP.

        Uses a regex match (=~) so that both ``10.0.1.5:9100`` and
        ``10.0.1.5`` will be matched regardless of the port suffix.
        """
        label = self._settings.prometheus_instance_label
        return f'{label}=~"{instance_ip}(:[0-9]+)?"'

    @staticmethod
    def _build_client(settings: Settings) -> httpx.Client:
        """Build a pre-configured httpx.Client with auth and TLS settings."""
        headers: dict[str, str] = {}

        if settings.prometheus_org_id:
            headers["X-Scope-OrgID"] = settings.prometheus_org_id

        auth: httpx.Auth | None = None
        if settings.prometheus_token:
            headers["Authorization"] = f"Bearer {settings.prometheus_token}"
        elif settings.prometheus_username and settings.prometheus_password:
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
        cpu = metrics.get("cpu_usage_pct")
        mem = metrics.get("memory_used_pct")
        swap = metrics.get("swap_used_pct")
        fd = metrics.get("fd_used_pct")
        oom = metrics.get("oom_kills_rate")

        if oom and float(oom) > 0:
            return DiagnosticStatus.FAILED
        if cpu and float(cpu) > 95:
            return DiagnosticStatus.FAILED
        if mem and float(mem) > 95:
            return DiagnosticStatus.FAILED

        if cpu and float(cpu) > 80:
            return DiagnosticStatus.DEGRADED
        if mem and float(mem) > 85:
            return DiagnosticStatus.DEGRADED
        if swap and float(swap) > 50:
            return DiagnosticStatus.DEGRADED
        if fd and float(fd) > 85:
            return DiagnosticStatus.DEGRADED

        if not metrics:
            return DiagnosticStatus.SKIPPED
        return DiagnosticStatus.OK

    @staticmethod
    def _node_summary(metrics: dict[str, Any], instance_ip: str) -> str:
        parts: list[str] = []
        if (v := metrics.get("cpu_usage_pct")) is not None:
            parts.append(f"CPU={float(v):.1f}%")
        if (v := metrics.get("memory_used_pct")) is not None:
            parts.append(f"Mem={float(v):.1f}%")
        if (v := metrics.get("load_1m")) is not None:
            parts.append(f"Load1m={float(v):.2f}")
        if not parts:
            return f"No node metrics returned for {instance_ip}"
        return f"{instance_ip} – " + ", ".join(parts)
