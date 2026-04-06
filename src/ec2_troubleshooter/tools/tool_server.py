"""
EC2 Tool Server – MCP-style bounded tool interface.

This class is the single point of entry for all diagnostic tool calls.  The
orchestrator never talks to AWS directly; it always goes through this server.
The server enforces:

  1. Read-only contract  – no mutating API is ever called.
  2. Allowlist contract  – only SSM commands in ALLOWLISTED_COMMANDS can run.
  3. Error containment   – every tool call returns a DiagnosticResult; errors
                           are captured and returned rather than propagated.

Think of this as the MCP server side of the agent boundary.
"""

from __future__ import annotations

import structlog

from ec2_troubleshooter.config import Settings
from ec2_troubleshooter.models.findings import DiagnosticResult, DiagnosticStatus

from .aws_client import AWSClientFactory
from .cloudwatch_tools import CloudWatchTools
from .ec2_tools import EC2Tools
from .ssm_tools import ALLOWLISTED_COMMANDS, SSMTools

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
        self._cw_tools = CloudWatchTools(factory)

    # ── Tool catalogue ─────────────────────────────────────────────────────

    def list_tools(self) -> list[str]:
        """Return a sorted list of all available tool names."""
        ec2_tools = [
            "ec2:describe_instance",
            "ec2:get_instance_status",
            "ec2:describe_volumes",
            "ec2:get_console_output",
        ]
        cw_tools = [
            "cloudwatch:cpu_utilization",
            "cloudwatch:disk_io",
            "cloudwatch:network_io",
            "cloudwatch:status_check_metrics",
        ]
        ssm_tools = [f"ssm:{k}" for k in ALLOWLISTED_COMMANDS]
        return sorted(ec2_tools + cw_tools + ssm_tools)

    # ── Dispatch ───────────────────────────────────────────────────────────

    def call(self, instance_id: str, tool_name: str, **kwargs: object) -> DiagnosticResult:
        """
        Invoke a named tool for *instance_id*.

        Extra *kwargs* are passed to tools that need them (e.g. volume_id for
        the EBS metrics tool).  Unknown tool names return an ERROR result
        rather than raising an exception so the orchestrator can continue.
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
        # ── EC2 tools ─────────────────────────────────────────────────────
        if tool_name == "ec2:describe_instance":
            return self._ec2_tools.describe_instance(instance_id)
        if tool_name == "ec2:get_instance_status":
            return self._ec2_tools.get_instance_status(instance_id)
        if tool_name == "ec2:describe_volumes":
            return self._ec2_tools.describe_volumes(instance_id)
        if tool_name == "ec2:get_console_output":
            return self._ec2_tools.get_console_output(instance_id)

        # ── CloudWatch tools ──────────────────────────────────────────────
        if tool_name == "cloudwatch:cpu_utilization":
            return self._cw_tools.get_cpu_utilization(instance_id)
        if tool_name == "cloudwatch:disk_io":
            return self._cw_tools.get_disk_io(instance_id)
        if tool_name == "cloudwatch:network_io":
            return self._cw_tools.get_network_io(instance_id)
        if tool_name == "cloudwatch:status_check_metrics":
            return self._cw_tools.get_status_check_metrics(instance_id)
        if tool_name == "cloudwatch:ebs_metrics":
            volume_id = str(kwargs.get("volume_id", ""))
            if not volume_id:
                return DiagnosticResult(
                    tool_name=tool_name,
                    status=DiagnosticStatus.ERROR,
                    summary="volume_id kwarg required for cloudwatch:ebs_metrics",
                )
            return self._cw_tools.get_ebs_metrics(instance_id, volume_id)

        # ── SSM tools ─────────────────────────────────────────────────────
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

    # ── Convenience: run a standard diagnostic suite ───────────────────────

    def run_standard_suite(self, instance_id: str) -> list[DiagnosticResult]:
        """
        Run the default suite of diagnostics for an instance.

        Checks whether SSM is available first; if not, skips SSM tools and
        falls back to the EC2/CloudWatch-only subset.
        """
        results: list[DiagnosticResult] = []

        # Always run EC2 and CloudWatch tools
        for tool in [
            "ec2:describe_instance",
            "ec2:get_instance_status",
            "ec2:describe_volumes",
            "ec2:get_console_output",
            "cloudwatch:cpu_utilization",
            "cloudwatch:disk_io",
            "cloudwatch:network_io",
            "cloudwatch:status_check_metrics",
        ]:
            results.append(self.call(instance_id, tool))

        # Run SSM tools only if the instance is SSM-managed
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
            log.info("instance not SSM-managed, skipping host diagnostics", instance_id=instance_id)
            results.append(
                DiagnosticResult(
                    tool_name="ssm:availability",
                    status=DiagnosticStatus.SKIPPED,
                    summary="Instance is not SSM-managed; host-level diagnostics unavailable",
                )
            )

        return results
