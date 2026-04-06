"""
SSM Run Command read-only diagnostic tools.

All commands are drawn from an ALLOWLIST – the agent never constructs or
executes arbitrary shell commands.  Each command is a fixed diagnostic profile
with a known, auditable purpose.  This is the foundational air-gapped safety
mechanism: no SSH, no freeform shell, only pre-approved read-only commands
via SSM.

Commands run as root by default via SSM but only perform read operations
(top, df, free, ps, journalctl, dmesg, etc.).
"""

from __future__ import annotations

import time

import structlog

from ec2_troubleshooter.config import Settings
from ec2_troubleshooter.models.findings import DiagnosticResult, DiagnosticStatus

from .aws_client import AWSClientFactory

log = structlog.get_logger(__name__)


# ── Allowlisted SSM diagnostic commands ──────────────────────────────────────
#
# Key  : short tool identifier used throughout the codebase
# Value: the exact shell string sent to SSM Run Command
#
# IMPORTANT: This dict is the sole source of truth for allowed commands.
#            Adding a new command requires a code review.
#
ALLOWLISTED_COMMANDS: dict[str, str] = {
    # CPU / load
    "cpu_top": (
        "top -b -n 1 -o -%CPU | head -30"
    ),
    "load_average": (
        "cat /proc/loadavg && uptime"
    ),
    # Memory
    "memory_free": (
        "free -m"
    ),
    "memory_vmstat": (
        "vmstat -s | head -20"
    ),
    # Disk
    "disk_usage": (
        "df -hT --exclude-type=tmpfs --exclude-type=devtmpfs"
    ),
    "disk_inodes": (
        "df -i --exclude-type=tmpfs --exclude-type=devtmpfs"
    ),
    "disk_io_stats": (
        "iostat -x 1 3 2>/dev/null || cat /proc/diskstats | head -30"
    ),
    # Network
    "network_connections": (
        "ss -tunap 2>/dev/null | head -60"
    ),
    "network_stats": (
        "cat /proc/net/dev && ip -s link show 2>/dev/null | head -60"
    ),
    # Processes and services
    "process_list": (
        "ps aux --sort=-%cpu | head -30"
    ),
    "zombie_processes": (
        "ps aux | awk '$8==\"Z\" {print}'"
    ),
    "systemd_failed": (
        "systemctl --failed --no-legend 2>/dev/null || echo 'systemctl not available'"
    ),
    "systemd_status": (
        "systemctl status --no-pager 2>/dev/null | head -40 "
        "|| echo 'systemctl not available'"
    ),
    # OS / kernel logs
    "dmesg_errors": (
        "dmesg --level=err,crit,alert,emerg --time-format=reltime 2>/dev/null "
        "| tail -50 || dmesg | grep -iE '(error|panic|oom|killed|segfault)' | tail -50"
    ),
    "journal_errors": (
        "journalctl -p err --since '1 hour ago' --no-pager 2>/dev/null "
        "| tail -80 || echo 'journalctl not available'"
    ),
    "journal_kernel_oom": (
        "journalctl -k --since '1 hour ago' --no-pager 2>/dev/null "
        "| grep -iE '(oom|killed|out of memory)' | tail -30 "
        "|| echo 'journalctl not available'"
    ),
    # OS version / identity
    "os_release": (
        "cat /etc/os-release 2>/dev/null || cat /etc/system-release 2>/dev/null"
    ),
    "kernel_version": (
        "uname -r && uname -a"
    ),
    # Entropy / time
    "ntp_status": (
        "timedatectl status 2>/dev/null || chronyc tracking 2>/dev/null "
        "|| ntpq -p 2>/dev/null || echo 'time sync tool not available'"
    ),
    # File descriptor pressure
    "fd_usage": (
        "cat /proc/sys/fs/file-nr && lsof 2>/dev/null | wc -l || echo 'lsof not available'"
    ),
    # Top memory consumers (RSS sorted)
    "memory_top_processes": (
        "ps aux --sort=-%mem | head -20"
    ),
    # Detailed memory breakdown per process
    "memory_smaps": (
        "for pid in $(ps aux --sort=-%mem | awk 'NR>1{print $2}' | head -5); do "
        "echo \"=== PID $pid ===\"; "
        "cat /proc/$pid/status 2>/dev/null | grep -E '(Name|VmRSS|VmSwap|VmPeak)'; "
        "done"
    ),
    # Open files per top process (FD leak detection)
    "fd_top_processes": (
        "for pid in $(ps aux --sort=-%mem | awk 'NR>1{print $2}' | head -5); do "
        "echo \"=== PID $pid ($(cat /proc/$pid/comm 2>/dev/null)) ===\"; "
        "ls /proc/$pid/fd 2>/dev/null | wc -l; "
        "done"
    ),
    # Disk space details – largest directories
    "disk_large_dirs": (
        "du -xh --max-depth=3 / 2>/dev/null | sort -rh | head -20 "
        "|| du -h --max-depth=3 / 2>/dev/null | sort -rh | head -20"
    ),
    # Recently modified large files
    "disk_recent_large_files": (
        "find / -xdev -type f -size +100M -printf '%T@ %s %p\\n' 2>/dev/null "
        "| sort -rn | head -10 | awk '{printf \"%.0f MB  %s\\n\", $2/1048576, $3}'"
    ),
    # I/O wait and block device pressure
    "disk_io_wait": (
        "iostat -xz 1 5 2>/dev/null | tail -30 "
        "|| cat /proc/diskstats | awk '{print $3, $6, $10}' | head -20"
    ),
    # CPU-intensive process details
    "cpu_intensive_processes": (
        "ps aux --sort=-%cpu | head -20 && echo '---' && "
        "top -b -n 3 -d 2 -o -%CPU | grep -v '^$' | tail -20"
    ),
    # Per-CPU utilisation
    "cpu_per_core": (
        "mpstat -P ALL 1 3 2>/dev/null || "
        "cat /proc/stat | head -20"
    ),
    # Services that have restarted recently (crash loops)
    "systemd_recent_restarts": (
        "systemctl list-units --state=failed --no-legend 2>/dev/null; "
        "journalctl --since '1 hour ago' --no-pager 2>/dev/null "
        "| grep -iE '(started|stopped|failed|restarting).*\\.service' | tail -30 "
        "|| echo 'journalctl not available'"
    ),
    # Network connection counts by state (detect connection exhaustion)
    "network_connection_counts": (
        "ss -s 2>/dev/null || netstat -s 2>/dev/null | head -30"
    ),
    # Kernel ring buffer – last 100 lines (for any anomaly context)
    "dmesg_recent": (
        "dmesg --time-format=reltime 2>/dev/null | tail -50 || dmesg | tail -50"
    ),
    # App log tail – last 200 lines of common log locations
    "app_log_tail": (
        "for logdir in /var/log/app /var/log/application /opt/app/logs "
        "/var/log/airflow /home/airflow/logs; do "
        "if [ -d \"$logdir\" ]; then "
        "echo \"=== $logdir ===\"; "
        "find \"$logdir\" -name '*.log' -newer /proc/1 -type f 2>/dev/null "
        "| head -3 | xargs tail -n 50 2>/dev/null; "
        "fi; done"
    ),
}


# ── Targeted diagnostic profiles ──────────────────────────────────────────
#
# Each profile is an ordered list of command keys to run when a specific
# contributor kind is the primary alert signal.  The orchestrator picks
# the profile that best matches the alert contributors.
#
# All keys must be present in ALLOWLISTED_COMMANDS above.

DIAGNOSTIC_PROFILES: dict[str, list[str]] = {
    # Triggered when cpu / load_average is the alert contributor
    "cpu": [
        "load_average",
        "cpu_intensive_processes",
        "cpu_per_core",
        "systemd_failed",
        "systemd_recent_restarts",
        "dmesg_errors",
        "zombie_processes",
        "fd_usage",
    ],
    # Triggered when memory is the alert contributor
    "memory": [
        "memory_free",
        "memory_vmstat",
        "memory_top_processes",
        "memory_smaps",
        "journal_kernel_oom",
        "systemd_failed",
        "systemd_recent_restarts",
        "dmesg_errors",
        "swap_status" if "swap_status" in ALLOWLISTED_COMMANDS else "memory_vmstat",
    ],
    # Triggered when disk usage or disk I/O is the alert contributor
    "disk": [
        "disk_usage",
        "disk_inodes",
        "disk_io_wait",
        "disk_large_dirs",
        "disk_recent_large_files",
        "systemd_failed",
        "dmesg_errors",
        "process_list",
    ],
    # Triggered when network metrics are the alert contributor
    "network": [
        "network_connections",
        "network_connection_counts",
        "network_stats",
        "dmesg_errors",
        "systemd_failed",
        "process_list",
    ],
    # Triggered when an app metric is the alert contributor — lightweight OS baseline
    "app": [
        "load_average",
        "memory_free",
        "disk_usage",
        "process_list",
        "systemd_failed",
        "systemd_recent_restarts",
        "app_log_tail",
        "journal_errors",
        "dmesg_errors",
    ],
    # Full baseline — used when contributor is unknown or for initial triage
    "baseline": [
        "load_average",
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
    ],
}

# Fix: remove any keys that slipped in that aren't in ALLOWLISTED_COMMANDS
for _profile_name, _keys in DIAGNOSTIC_PROFILES.items():
    DIAGNOSTIC_PROFILES[_profile_name] = [k for k in _keys if k in ALLOWLISTED_COMMANDS]


class SSMTools:
    """
    Execute allowlisted read-only diagnostic commands on an EC2 instance via
    SSM Run Command (aws:runShellScript document).
    """

    def __init__(self, factory: AWSClientFactory, settings: Settings) -> None:
        self._ssm = factory.ssm
        self._poll_interval = settings.ssm_poll_interval_sec
        self._max_wait = settings.ssm_max_wait_sec

    # ── Public methods ─────────────────────────────────────────────────────

    def is_managed(self, instance_id: str) -> bool:
        """Return True if the instance has an active SSM agent registered."""
        try:
            resp = self._ssm.describe_instance_information(
                Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
            )
            infos = resp.get("InstanceInformationList", [])
            if not infos:
                return False
            status = infos[0].get("PingStatus", "")
            return status == "Online"
        except Exception as exc:
            log.warning("ssm.is_managed check failed", instance_id=instance_id, error=str(exc))
            return False

    def run_diagnostic(self, instance_id: str, command_key: str) -> DiagnosticResult:
        """
        Run a single allowlisted diagnostic command on the instance.

        Raises KeyError if *command_key* is not in ALLOWLISTED_COMMANDS.
        """
        if command_key not in ALLOWLISTED_COMMANDS:
            raise KeyError(
                f"Command '{command_key}' is not in the allowlist. "
                f"Available: {sorted(ALLOWLISTED_COMMANDS)}"
            )
        command = ALLOWLISTED_COMMANDS[command_key]
        tool_name = f"ssm:{command_key}"
        start = time.monotonic()
        try:
            send_resp = self._ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": [command]},
                Comment=f"ec2-troubleshooter read-only diagnostic: {command_key}",
                TimeoutSeconds=int(self._max_wait),
            )
            command_id: str = send_resp["Command"]["CommandId"]
            output, status = self._wait_for_result(instance_id, command_id)
            duration_ms = (time.monotonic() - start) * 1000
            return DiagnosticResult(
                tool_name=tool_name,
                status=status,
                summary=self._make_summary(command_key, output),
                raw_output=output,
                duration_ms=duration_ms,
            )
        except KeyError:
            raise
        except Exception as exc:
            log.warning(
                "ssm.run_diagnostic failed",
                instance_id=instance_id,
                command_key=command_key,
                error=str(exc),
            )
            return DiagnosticResult(
                tool_name=tool_name,
                status=DiagnosticStatus.ERROR,
                summary=f"SSM error: {exc}",
                error=str(exc),
                duration_ms=(time.monotonic() - start) * 1000,
            )

    def run_diagnostics(
        self, instance_id: str, command_keys: list[str]
    ) -> list[DiagnosticResult]:
        """Run multiple allowlisted commands sequentially and return all results."""
        return [self.run_diagnostic(instance_id, key) for key in command_keys]

    # ── Internal helpers ───────────────────────────────────────────────────

    def _wait_for_result(
        self, instance_id: str, command_id: str
    ) -> tuple[str, DiagnosticStatus]:
        """Poll SSM until the command completes or the timeout is reached."""
        deadline = time.monotonic() + self._max_wait
        while time.monotonic() < deadline:
            try:
                resp = self._ssm.get_command_invocation(
                    CommandId=command_id, InstanceId=instance_id
                )
                invocation_status = resp.get("Status", "")
                if invocation_status in ("Success", "Failed", "Cancelled", "TimedOut"):
                    stdout = resp.get("StandardOutputContent", "") or ""
                    stderr = resp.get("StandardErrorContent", "") or ""
                    output = stdout
                    if stderr.strip():
                        output += f"\n[stderr]\n{stderr}"
                    if invocation_status == "Success":
                        return output, DiagnosticStatus.OK
                    else:
                        return output, DiagnosticStatus.FAILED
            except self._ssm.exceptions.InvocationDoesNotExist:
                pass
            except Exception as exc:
                log.debug("SSM poll error", command_id=command_id, error=str(exc))
            time.sleep(self._poll_interval)
        return "", DiagnosticStatus.ERROR

    @staticmethod
    def _make_summary(command_key: str, output: str) -> str:
        """Extract a short summary from command output."""
        if not output:
            return f"{command_key}: no output"
        first_line = output.splitlines()[0][:200]
        return f"{command_key}: {first_line}"
