"""
EC2 Tool Server – MCP-style bounded tool interface.

This class is the single point of entry for all diagnostic tool calls.  The
orchestrator never talks to AWS or Prometheus directly; it always goes through
this server.  The server enforces:

  1. Read-only contract  – no mutating API is ever called.
  2. Allowlist contract  – only SSM commands in ALLOWLISTED_COMMANDS can run.
  3. Error containment   – every tool call returns a DiagnosticResult; errors
                           are captured and returned rather than propagated.

Metric backend
──────────────
Node-level and application metrics are queried from Grafana Mimir (or any
Prometheus-compatible backend) via PrometheusTools.  CloudWatch is not used.
"""

from __future__ import annotations

import structlog

from ec2_troubleshooter.config import Settings
from ec2_troubleshooter.models.findings import DiagnosticResult, DiagnosticStatus

from .aws_client import AWSClientFactory
from .ec2_tools import EC2Tools
from .prometheus_tools import PrometheusTools
from .ssm_tools import ALLOWLISTED_COMMANDS, DIAGNOSTIC_PROFILES, SSMTools

log = structlog.get_logger(__name__)


class EC2ToolServer:
    """
    Bounded, read-only EC2 diagnostic tool server.

    Exposes a flat catalogue of named tools; the orchestrator selects which
    tools to call based on alert context.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        factory = AWSClientFactory(settings)
        self._ec2_tools = EC2Tools(factory)
        self._ssm_tools = SSMTools(factory, settings)
        self._prom_tools = PrometheusTools(settings)

    # ── Tool catalogue ─────────────────────────────────────────────────────

    def list_tools(self) -> list[str]:
        """Return a sorted list of all available tool names."""
        ec2_tools = [
            "ec2:describe_instance",
            "ec2:get_instance_status",
            "ec2:describe_volumes",
            "ec2:get_console_output",
            "ec2:resolve_instance_names",
        ]
        prom_tools = [
            "prometheus:node_metrics",
            "prometheus:query",
            "prometheus:query_range",
            "prometheus:contributor_metric",
        ]
        ssm_tools = [f"ssm:{k}" for k in ALLOWLISTED_COMMANDS]
        ssm_profiles = [f"ssm:profile:{k}" for k in DIAGNOSTIC_PROFILES]
        return sorted(ec2_tools + prom_tools + ssm_tools + ssm_profiles)

    # ── Dispatch ───────────────────────────────────────────────────────────

    def call(self, instance_id: str, tool_name: str, **kwargs: object) -> DiagnosticResult:
        """
        Invoke a named tool for *instance_id*.

        Extra *kwargs* are forwarded to tools that need them:
          - ``instance_ip``   – private IP for Prometheus label matching
          - ``promql``        – PromQL expression for prometheus:query / query_range
          - ``metric_name``   – metric name for prometheus:contributor_metric
          - ``extra_labels``  – dict of additional label filters
        """
        log.debug("tool_server.call", instance_id=instance_id, tool=tool_name)
        try:
            return self._dispatch(instance_id, tool_name, **kwargs)
        except Exception as exc:
            log.error(
                "tool_server.call unhandled error",
                instance_id=instance_id,
                tool=tool_name,
                error=str(exc),
            )
            return DiagnosticResult(
                tool_name=tool_name,
                status=DiagnosticStatus.ERROR,
                summary=f"Unhandled tool error: {exc}",
                error=str(exc),
            )

    def _dispatch(
        self, instance_id: str, tool_name: str, **kwargs: object
    ) -> DiagnosticResult:
        instance_ip = str(kwargs.get("instance_ip", ""))
        org_id = kwargs.get("org_id")  # optional X-Scope-OrgID override

        # ── EC2 tools ─────────────────────────────────────────────────────
        if tool_name == "ec2:describe_instance":
            return self._ec2_tools.describe_instance(instance_id)
        if tool_name == "ec2:get_instance_status":
            return self._ec2_tools.get_instance_status(instance_id)
        if tool_name == "ec2:describe_volumes":
            return self._ec2_tools.describe_volumes(instance_id)
        if tool_name == "ec2:get_console_output":
            return self._ec2_tools.get_console_output(instance_id)
        if tool_name == "ec2:resolve_instance_names":
            names = kwargs.get("names", [])
            if not isinstance(names, list):
                return DiagnosticResult(
                    tool_name=tool_name,
                    status=DiagnosticStatus.ERROR,
                    summary="names kwarg must be a list of strings",
                )
            mapping = self._ec2_tools.resolve_instance_names(names)
            resolved = len(mapping)
            unresolved = len(names) - resolved
            status = DiagnosticStatus.OK if unresolved == 0 else DiagnosticStatus.DEGRADED
            return DiagnosticResult(
                tool_name=tool_name,
                status=status,
                summary=f"Resolved {resolved}/{len(names)} instance names to IDs",
                metrics={"name_to_id": mapping, "unresolved_count": unresolved},
            )

        # ── Prometheus / Mimir tools ───────────────────────────────────────
        if tool_name == "prometheus:node_metrics":
            if not instance_ip:
                return DiagnosticResult(
                    tool_name=tool_name,
                    status=DiagnosticStatus.ERROR,
                    summary="instance_ip kwarg required for prometheus:node_metrics",
                )
            return self._prom_tools.get_node_metrics(
                instance_ip, org_id=str(org_id) if org_id else None
            )

        if tool_name == "prometheus:query":
            promql = str(kwargs.get("promql", ""))
            if not promql:
                return DiagnosticResult(
                    tool_name=tool_name,
                    status=DiagnosticStatus.ERROR,
                    summary="promql kwarg required for prometheus:query",
                )
            return self._prom_tools.query(
                promql,
                instance_ip=instance_ip or None,
                org_id=str(org_id) if org_id else None,
            )

        if tool_name == "prometheus:query_range":
            promql = str(kwargs.get("promql", ""))
            if not promql:
                return DiagnosticResult(
                    tool_name=tool_name,
                    status=DiagnosticStatus.ERROR,
                    summary="promql kwarg required for prometheus:query_range",
                )
            lookback = kwargs.get("lookback_minutes")
            return self._prom_tools.query_range(
                promql,
                instance_ip=instance_ip or None,
                lookback_minutes=int(lookback) if lookback else None,
                org_id=str(org_id) if org_id else None,
            )

        if tool_name == "prometheus:contributor_metric":
            metric_name = str(kwargs.get("metric_name", ""))
            if not metric_name or not instance_ip:
                return DiagnosticResult(
                    tool_name=tool_name,
                    status=DiagnosticStatus.ERROR,
                    summary="metric_name and instance_ip kwargs required",
                )
            extra_labels = kwargs.get("extra_labels")
            return self._prom_tools.get_contributor_metrics(
                metric_name,
                instance_ip,
                org_id=str(org_id) if org_id else None,
                extra_labels=extra_labels if isinstance(extra_labels, dict) else None,
            )

        # ── SSM individual command ─────────────────────────────────────────
        if tool_name.startswith("ssm:profile:"):
            profile_key = tool_name[12:]
            if profile_key not in DIAGNOSTIC_PROFILES:
                return DiagnosticResult(
                    tool_name=tool_name,
                    status=DiagnosticStatus.ERROR,
                    summary=f"Unknown SSM diagnostic profile '{profile_key}'",
                )
            return self._run_ssm_profile(instance_id, profile_key)

        if tool_name.startswith("ssm:"):
            command_key = tool_name[4:]
            if command_key not in ALLOWLISTED_COMMANDS:
                return DiagnosticResult(
                    tool_name=tool_name,
                    status=DiagnosticStatus.ERROR,
                    summary=f"SSM command '{command_key}' is not in the allowlist",
                )
            return self._ssm_tools.run_diagnostic(instance_id, command_key)

        # ── Unknown tool ──────────────────────────────────────────────────
        return DiagnosticResult(
            tool_name=tool_name,
            status=DiagnosticStatus.ERROR,
            summary=f"Unknown tool: '{tool_name}'",
        )

    def _run_ssm_profile(self, instance_id: str, profile_key: str) -> DiagnosticResult:
        """Run all commands in a named diagnostic profile sequentially."""
        keys = DIAGNOSTIC_PROFILES[profile_key]
        results = self._ssm_tools.run_diagnostics(instance_id, keys)
        failed = [r for r in results if r.status == DiagnosticStatus.ERROR]
        status = DiagnosticStatus.OK if not failed else DiagnosticStatus.DEGRADED
        return DiagnosticResult(
            tool_name=f"ssm:profile:{profile_key}",
            status=status,
            summary=f"Profile '{profile_key}': ran {len(results)} commands, {len(failed)} errors",
            metrics={
                "profile": profile_key,
                "commands_run": [r.tool_name for r in results],
                "results": {r.tool_name: r.model_dump(exclude={"raw_output"}) for r in results},
            },
            raw_output="\n\n".join(
                f"=== {r.tool_name} ===\n{r.raw_output or r.summary}" for r in results
            ),
        )

    def resolve_instance_names(self, names: list[str]) -> dict[str, str]:
        """Resolve a list of EC2 Name-tag values to instance IDs (read-only)."""
        return self._ec2_tools.resolve_instance_names(names)

    # ── Convenience: run a standard diagnostic suite ───────────────────────

    def run_standard_suite(
        self, instance_id: str, instance_ip: str | None = None
    ) -> list[DiagnosticResult]:
        """
        Run the default suite of diagnostics for an instance.

        1. Always runs EC2 describe/status/volumes/console.
        2. Queries Prometheus/Mimir for node metrics when the URL is configured
           and ``instance_ip`` is known.
        3. Falls back to SSM host diagnostics when the instance is SSM-managed.
        """
        results: list[DiagnosticResult] = []

        # EC2 API tools – always run
        for tool in [
            "ec2:describe_instance",
            "ec2:get_instance_status",
            "ec2:describe_volumes",
            "ec2:get_console_output",
        ]:
            results.append(self.call(instance_id, tool))

        # Prometheus / Mimir node metrics
        if self._prom_tools.is_available() and instance_ip:
            log.info("prometheus_available, querying node metrics", instance_id=instance_id)
            results.append(
                self.call(instance_id, "prometheus:node_metrics", instance_ip=instance_ip)
            )
        elif not self._prom_tools.is_available():
            results.append(
                DiagnosticResult(
                    tool_name="prometheus:node_metrics",
                    status=DiagnosticStatus.SKIPPED,
                    summary="PROMETHEUS_URL not configured – node metrics skipped",
                )
            )
        else:
            results.append(
                DiagnosticResult(
                    tool_name="prometheus:node_metrics",
                    status=DiagnosticStatus.SKIPPED,
                    summary="Instance private IP unknown – cannot query Prometheus",
                )
            )

        # SSM host-level diagnostics
        if self._ssm_tools.is_managed(instance_id):
            log.info("ssm_managed, running host-level diagnostics", instance_id=instance_id)
            for cmd_key in [
                "load_average",
                "cpu_top",
                "memory_free",
                "disk_usage",
                "disk_inodes",
                "process_list",
                "zombie_processes",
                "systemd_failed",
                "dmesg_errors",
                "journal_errors",
                "journal_kernel_oom",
                "network_connections",
                "fd_usage",
                "ntp_status",
            ]:
                results.append(self.call(instance_id, f"ssm:{cmd_key}"))
        else:
            log.info(
                "instance not SSM-managed, skipping host diagnostics",
                instance_id=instance_id,
            )
            results.append(
                DiagnosticResult(
                    tool_name="ssm:availability",
                    status=DiagnosticStatus.SKIPPED,
                    summary="Instance is not SSM-managed; host-level diagnostics unavailable",
                )
            )

        return results
