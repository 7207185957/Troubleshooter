"""
Evidence analyzer.

Transforms raw DiagnosticResult objects into structured Finding objects and
derives a list of likely causes.  This layer is intentionally generic – it
reasons about OS-level symptoms only (CPU, memory, disk, network, processes,
kernel errors) and does not contain app-specific logic.
"""

from __future__ import annotations

import re
from typing import Any

from ec2_troubleshooter.models.findings import (
    DiagnosticResult,
    DiagnosticStatus,
    Finding,
    FindingSeverity,
    InstanceInvestigation,
)


class EvidenceAnalyzer:
    """Convert diagnostic results into human-readable findings."""

    def analyze(self, investigation: InstanceInvestigation) -> None:
        """
        Populate *investigation.findings* and *investigation.summary* in-place
        based on the diagnostics already collected in *investigation.diagnostics*.
        """
        findings: list[Finding] = []

        for result in investigation.diagnostics:
            findings.extend(self._analyze_result(result))

        # Deduplicate and sort by severity
        findings = _deduplicate(findings)
        findings.sort(key=lambda f: _SEV_ORDER.get(f.severity, 99))
        investigation.findings = findings
        investigation.summary = self._build_summary(investigation)
        investigation.overall_status = self._overall_status(investigation)

    # ── Per-tool analyzers ─────────────────────────────────────────────────

    def _analyze_result(self, result: DiagnosticResult) -> list[Finding]:
        if result.status == DiagnosticStatus.ERROR:
            return self._error_finding(result)

        tool = result.tool_name
        findings: list[Finding] = []

        if tool == "ec2:describe_instance":
            findings.extend(self._analyze_instance_state(result))
        elif tool == "ec2:get_instance_status":
            findings.extend(self._analyze_instance_status_checks(result))
        elif tool == "ec2:describe_volumes":
            findings.extend(self._analyze_volumes(result))
        elif tool == "ec2:get_console_output":
            findings.extend(self._analyze_console_output(result))
        elif tool == "cloudwatch:cpu_utilization":
            findings.extend(self._analyze_cpu(result))
        elif tool == "cloudwatch:status_check_metrics":
            findings.extend(self._analyze_cw_status_checks(result))
        elif tool.startswith("ssm:"):
            findings.extend(self._analyze_ssm(result))

        return findings

    # ── EC2 ────────────────────────────────────────────────────────────────

    def _analyze_instance_state(self, result: DiagnosticResult) -> list[Finding]:
        state = result.metrics.get("state", "unknown")
        if state != "running":
            return [
                Finding(
                    severity=FindingSeverity.CRITICAL,
                    category="os",
                    message=f"Instance is in state '{state}' (not running)",
                    evidence=[result.summary],
                    recommendation=(
                        "Investigate why the instance is not running. "
                        "Check the EC2 event history for this instance."
                    ),
                )
            ]
        return []

    def _analyze_instance_status_checks(self, result: DiagnosticResult) -> list[Finding]:
        sys_status = result.metrics.get("system_status", "ok")
        inst_status = result.metrics.get("instance_status", "ok")
        findings = []
        if sys_status != "ok":
            findings.append(
                Finding(
                    severity=FindingSeverity.CRITICAL,
                    category="os",
                    message=f"EC2 system status check failing: {sys_status}",
                    evidence=result.metrics.get("system_details", []),
                    recommendation=(
                        "System status failures usually indicate underlying hardware issues. "
                        "Consider stopping and restarting the instance to migrate to new hardware."
                    ),
                )
            )
        if inst_status != "ok":
            findings.append(
                Finding(
                    severity=FindingSeverity.HIGH,
                    category="os",
                    message=f"EC2 instance status check failing: {inst_status}",
                    evidence=result.metrics.get("instance_details", []),
                    recommendation=(
                        "Instance status failures indicate OS or application issues. "
                        "Inspect kernel logs and system services."
                    ),
                )
            )
        return findings

    def _analyze_volumes(self, result: DiagnosticResult) -> list[Finding]:
        findings = []
        for vol in result.metrics.get("volumes", []):
            if vol.get("state") != "in-use":
                findings.append(
                    Finding(
                        severity=FindingSeverity.HIGH,
                        category="disk",
                        message=(
                            f"EBS volume {vol.get('volume_id')} is in state "
                            f"'{vol.get('state')}' (expected 'in-use')"
                        ),
                        evidence=[str(vol)],
                    )
                )
        return findings

    def _analyze_console_output(self, result: DiagnosticResult) -> list[Finding]:
        output = (result.raw_output or "").lower()
        findings = []
        patterns = [
            (r"kernel panic", FindingSeverity.CRITICAL, "kernel", "Kernel panic detected in console output"),
            (r"out of memory|oom.?killer|killed process", FindingSeverity.CRITICAL, "memory", "OOM Killer activity detected in console output"),
            (r"i/o error|blk_update_request|end_request.*error", FindingSeverity.HIGH, "disk", "Disk I/O errors in console output"),
            (r"segfault|segmentation fault", FindingSeverity.HIGH, "process", "Segmentation fault in console output"),
            (r"nfs: server .* not responding", FindingSeverity.HIGH, "network", "NFS server not responding in console output"),
            (r"call trace|rip |stack trace", FindingSeverity.HIGH, "os", "Kernel call trace in console output"),
        ]
        for pattern, sev, cat, msg in patterns:
            if re.search(pattern, output):
                snippet_lines = [
                    line for line in (result.raw_output or "").splitlines()
                    if re.search(pattern, line.lower())
                ][:5]
                findings.append(
                    Finding(
                        severity=sev,
                        category=cat,
                        message=msg,
                        evidence=snippet_lines,
                    )
                )
        return findings

    # ── CloudWatch ─────────────────────────────────────────────────────────

    def _analyze_cpu(self, result: DiagnosticResult) -> list[Finding]:
        cpu_stats: dict[str, Any] = result.metrics.get("cpu_utilization_pct", {})
        latest = cpu_stats.get("latest")
        max_val = cpu_stats.get("max")
        if latest is None:
            return []
        findings = []
        if max_val is not None and max_val > 95:
            findings.append(
                Finding(
                    severity=FindingSeverity.CRITICAL,
                    category="cpu",
                    message=f"Sustained CPU saturation: max={max_val:.1f}%, latest={latest:.1f}%",
                    evidence=[result.summary],
                    recommendation=(
                        "Identify the top CPU-consuming process. "
                        "Check process_list and cpu_top diagnostic outputs."
                    ),
                )
            )
        elif max_val is not None and max_val > 80:
            findings.append(
                Finding(
                    severity=FindingSeverity.HIGH,
                    category="cpu",
                    message=f"Elevated CPU utilization: max={max_val:.1f}%, latest={latest:.1f}%",
                    evidence=[result.summary],
                )
            )
        return findings

    def _analyze_cw_status_checks(self, result: DiagnosticResult) -> list[Finding]:
        findings = []
        for check_name, stats in result.metrics.items():
            if isinstance(stats, dict) and stats.get("max", 0) and stats["max"] > 0:
                findings.append(
                    Finding(
                        severity=FindingSeverity.HIGH,
                        category="os",
                        message=f"CloudWatch metric {check_name} shows failures",
                        evidence=[f"max={stats['max']}, latest={stats.get('latest')}"],
                    )
                )
        return findings

    # ── SSM ────────────────────────────────────────────────────────────────

    def _analyze_ssm(self, result: DiagnosticResult) -> list[Finding]:
        output = (result.raw_output or "").lower()
        tool = result.tool_name
        findings: list[Finding] = []

        if tool == "ssm:memory_free":
            findings.extend(self._analyze_memory_output(result.raw_output or ""))
        elif tool == "ssm:disk_usage":
            findings.extend(self._analyze_disk_usage_output(result.raw_output or ""))
        elif tool == "ssm:disk_inodes":
            findings.extend(self._analyze_disk_inodes_output(result.raw_output or ""))
        elif tool == "ssm:dmesg_errors":
            if output.strip():
                findings.extend(self._analyze_dmesg(result.raw_output or ""))
        elif tool == "ssm:journal_errors":
            if output.strip() and "not available" not in output:
                findings.extend(self._analyze_journal_errors(result.raw_output or ""))
        elif tool == "ssm:journal_kernel_oom":
            if output.strip() and "not available" not in output:
                lines = [ln for ln in (result.raw_output or "").splitlines() if ln.strip()]
                if lines:
                    findings.append(
                        Finding(
                            severity=FindingSeverity.CRITICAL,
                            category="memory",
                            message="OOM Killer events found in kernel journal",
                            evidence=lines[:10],
                            recommendation=(
                                "The OOM killer has been terminating processes. "
                                "Inspect memory usage and consider increasing instance memory."
                            ),
                        )
                    )
        elif tool == "ssm:zombie_processes":
            lines = [ln for ln in (result.raw_output or "").splitlines() if ln.strip()]
            if lines:
                findings.append(
                    Finding(
                        severity=FindingSeverity.MEDIUM,
                        category="process",
                        message=f"{len(lines)} zombie process(es) detected",
                        evidence=lines[:5],
                    )
                )
        elif tool == "ssm:systemd_failed":
            lines = [
                ln for ln in (result.raw_output or "").splitlines()
                if ln.strip() and "not available" not in ln.lower()
            ]
            if lines:
                findings.append(
                    Finding(
                        severity=FindingSeverity.HIGH,
                        category="process",
                        message=f"{len(lines)} failed systemd unit(s)",
                        evidence=lines[:10],
                        recommendation=(
                            "One or more systemd services have failed. "
                            "Check 'journalctl -xe' on the instance for details."
                        ),
                    )
                )
        elif tool == "ssm:fd_usage":
            findings.extend(self._analyze_fd_usage(result.raw_output or ""))
        elif tool == "ssm:load_average":
            findings.extend(self._analyze_load_average(result.raw_output or ""))

        return findings

    # ── Output parsers ─────────────────────────────────────────────────────

    def _analyze_memory_output(self, output: str) -> list[Finding]:
        """Parse 'free -m' output."""
        findings = []
        for line in output.splitlines():
            if line.lower().startswith("mem:"):
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        total = int(parts[1])
                        used = int(parts[2])
                        if total > 0:
                            pct = used / total * 100
                            if pct > 95:
                                findings.append(
                                    Finding(
                                        severity=FindingSeverity.CRITICAL,
                                        category="memory",
                                        message=f"Memory nearly exhausted: {used} MB / {total} MB ({pct:.0f}%)",
                                        evidence=[line],
                                        recommendation=(
                                            "Check for memory leaks or oversized processes. "
                                            "Inspect process_list for top memory consumers."
                                        ),
                                    )
                                )
                            elif pct > 85:
                                findings.append(
                                    Finding(
                                        severity=FindingSeverity.HIGH,
                                        category="memory",
                                        message=f"High memory usage: {used} MB / {total} MB ({pct:.0f}%)",
                                        evidence=[line],
                                    )
                                )
                    except (ValueError, IndexError):
                        pass
        return findings

    def _analyze_disk_usage_output(self, output: str) -> list[Finding]:
        """Parse 'df -hT' output and flag filesystems over 85% / 95%."""
        findings = []
        for line in output.splitlines():
            # df columns: Filesystem, Type, Size, Used, Avail, Use%, Mounted on
            m = re.search(r"(\d+)%\s+(\S+)$", line)
            if m:
                pct = int(m.group(1))
                mount = m.group(2)
                if pct >= 95:
                    findings.append(
                        Finding(
                            severity=FindingSeverity.CRITICAL,
                            category="disk",
                            message=f"Disk almost full: {mount} at {pct}%",
                            evidence=[line],
                            recommendation=(
                                f"Filesystem {mount} is critically full. "
                                "Identify and remove large files or expand the volume."
                            ),
                        )
                    )
                elif pct >= 85:
                    findings.append(
                        Finding(
                            severity=FindingSeverity.HIGH,
                            category="disk",
                            message=f"Disk usage high: {mount} at {pct}%",
                            evidence=[line],
                        )
                    )
        return findings

    def _analyze_disk_inodes_output(self, output: str) -> list[Finding]:
        """Parse 'df -i' and flag filesystems with inode exhaustion."""
        findings = []
        for line in output.splitlines():
            m = re.search(r"(\d+)%\s+(\S+)$", line)
            if m:
                pct = int(m.group(1))
                mount = m.group(2)
                if pct >= 90:
                    findings.append(
                        Finding(
                            severity=FindingSeverity.HIGH,
                            category="disk",
                            message=f"Inode exhaustion: {mount} at {pct}% inodes used",
                            evidence=[line],
                            recommendation=(
                                f"Filesystem {mount} is running out of inodes. "
                                "Find and clean up large numbers of small files."
                            ),
                        )
                    )
        return findings

    def _analyze_dmesg(self, output: str) -> list[Finding]:
        findings = []
        patterns = [
            (r"Out of memory|OOM killer", FindingSeverity.CRITICAL, "memory"),
            (r"I/O error|blk_update_request", FindingSeverity.HIGH, "disk"),
            (r"SCSI error|Medium Error", FindingSeverity.HIGH, "disk"),
            (r"Kernel panic|BUG:|Oops:", FindingSeverity.CRITICAL, "os"),
            (r"segfault at", FindingSeverity.HIGH, "process"),
            (r"NFS: server .* not responding", FindingSeverity.HIGH, "network"),
            (r"soft lockup|hard lockup|RCU stall", FindingSeverity.CRITICAL, "os"),
            (r"TCP: out of memory", FindingSeverity.HIGH, "network"),
            (r"EXT4-fs error|XFS.*corruption|EXT3-fs error", FindingSeverity.HIGH, "disk"),
        ]
        for pattern, sev, cat in patterns:
            matching = [
                line for line in output.splitlines()
                if re.search(pattern, line, re.IGNORECASE)
            ]
            if matching:
                findings.append(
                    Finding(
                        severity=sev,
                        category=cat,
                        message=f"dmesg pattern '{pattern}' found",
                        evidence=matching[:5],
                    )
                )
        return findings

    def _analyze_journal_errors(self, output: str) -> list[Finding]:
        lines = [ln for ln in output.splitlines() if ln.strip()]
        if not lines:
            return []
        return [
            Finding(
                severity=FindingSeverity.MEDIUM,
                category="os",
                message=f"{len(lines)} ERROR-level journal entries in the last hour",
                evidence=lines[:10],
                recommendation="Review journalctl output to identify failing services.",
            )
        ]

    def _analyze_fd_usage(self, output: str) -> list[Finding]:
        """Parse /proc/sys/fs/file-nr and warn on high FD usage."""
        findings = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) == 3:
                try:
                    allocated = int(parts[0])
                    maximum = int(parts[2])
                    if maximum > 0:
                        pct = allocated / maximum * 100
                        if pct > 90:
                            findings.append(
                                Finding(
                                    severity=FindingSeverity.HIGH,
                                    category="os",
                                    message=f"File descriptor limit nearly reached: {allocated}/{maximum} ({pct:.0f}%)",
                                    evidence=[line],
                                    recommendation=(
                                        "The system is close to the open file descriptor limit. "
                                        "Increase fs.file-max or investigate FD leaks."
                                    ),
                                )
                            )
                except (ValueError, IndexError):
                    pass
        return findings

    def _analyze_load_average(self, output: str) -> list[Finding]:
        """Parse uptime output and report high load average."""
        findings = []
        m = re.search(r"load average:\s*([\d.]+),\s*([\d.]+),\s*([\d.]+)", output)
        if m:
            load1 = float(m.group(1))
            load15 = float(m.group(3))
            if load15 > 10:
                findings.append(
                    Finding(
                        severity=FindingSeverity.HIGH,
                        category="cpu",
                        message=f"Sustained high load average: 1m={load1}, 15m={load15}",
                        evidence=[output.strip()],
                        recommendation=(
                            "The 15-minute load average is elevated. "
                            "Check cpu_top and process_list for CPU-bound tasks."
                        ),
                    )
                )
        return findings

    # ── Summary / overall status ───────────────────────────────────────────

    @staticmethod
    def _build_summary(investigation: InstanceInvestigation) -> str:
        if not investigation.findings:
            return (
                f"No significant issues found on {investigation.instance_id}. "
                "Instance appears healthy based on available diagnostics."
            )
        criticals = [f for f in investigation.findings if f.severity == FindingSeverity.CRITICAL]
        highs = [f for f in investigation.findings if f.severity == FindingSeverity.HIGH]
        parts = []
        if criticals:
            parts.append(f"{len(criticals)} CRITICAL finding(s): " + "; ".join(f.message for f in criticals[:3]))
        if highs:
            parts.append(f"{len(highs)} HIGH finding(s): " + "; ".join(f.message for f in highs[:3]))
        if not parts:
            return f"Minor issues found on {investigation.instance_id}."
        return f"Issues on {investigation.instance_id}: " + " | ".join(parts)

    @staticmethod
    def _overall_status(investigation: InstanceInvestigation) -> DiagnosticStatus:
        if any(f.severity == FindingSeverity.CRITICAL for f in investigation.findings):
            return DiagnosticStatus.FAILED
        if any(f.severity == FindingSeverity.HIGH for f in investigation.findings):
            return DiagnosticStatus.DEGRADED
        return DiagnosticStatus.OK

    # ── Error finding ──────────────────────────────────────────────────────

    @staticmethod
    def _error_finding(result: DiagnosticResult) -> list[Finding]:
        return [
            Finding(
                severity=FindingSeverity.INFO,
                category="other",
                message=f"Diagnostic tool {result.tool_name} failed: {result.summary}",
            )
        ]


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    out = []
    for f in findings:
        key = f"{f.category}:{f.message}"
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


_SEV_ORDER = {
    FindingSeverity.CRITICAL: 0,
    FindingSeverity.HIGH: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 3,
    FindingSeverity.INFO: 4,
}
