"""Tests for the EvidenceAnalyzer."""

from __future__ import annotations

import pytest

from ec2_troubleshooter.models.findings import (
    DiagnosticResult,
    DiagnosticStatus,
    FindingSeverity,
    InstanceInvestigation,
)
from ec2_troubleshooter.orchestrator.analyzer import EvidenceAnalyzer


@pytest.fixture
def analyzer():
    return EvidenceAnalyzer()


class TestInstanceStateAnalysis:
    def test_running_instance_no_findings(self, analyzer):
        result = DiagnosticResult(
            tool_name="ec2:describe_instance",
            status=DiagnosticStatus.OK,
            summary="running",
            metrics={"state": "running"},
        )
        inv = InstanceInvestigation(instance_id="i-001", diagnostics=[result])
        analyzer.analyze(inv)
        state_findings = [f for f in inv.findings if "state" in f.message.lower()]
        assert len(state_findings) == 0

    def test_stopped_instance_critical_finding(self, analyzer):
        result = DiagnosticResult(
            tool_name="ec2:describe_instance",
            status=DiagnosticStatus.DEGRADED,
            summary="stopped",
            metrics={"state": "stopped"},
        )
        inv = InstanceInvestigation(instance_id="i-002", diagnostics=[result])
        analyzer.analyze(inv)
        assert any(f.severity == FindingSeverity.CRITICAL for f in inv.findings)


class TestCPUAnalysis:
    def test_high_cpu_degraded(self, analyzer):
        result = DiagnosticResult(
            tool_name="cloudwatch:cpu_utilization",
            status=DiagnosticStatus.DEGRADED,
            summary="High CPU",
            metrics={"cpu_utilization_pct": {"latest": 85.0, "max": 96.0, "avg": 82.0, "min": 50.0}},
        )
        inv = InstanceInvestigation(instance_id="i-003", diagnostics=[result])
        analyzer.analyze(inv)
        cpu_findings = [f for f in inv.findings if f.category == "cpu"]
        assert len(cpu_findings) >= 1
        assert cpu_findings[0].severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH)

    def test_normal_cpu_no_findings(self, analyzer):
        result = DiagnosticResult(
            tool_name="cloudwatch:cpu_utilization",
            status=DiagnosticStatus.OK,
            summary="Normal CPU",
            metrics={"cpu_utilization_pct": {"latest": 20.0, "max": 35.0, "avg": 22.0, "min": 10.0}},
        )
        inv = InstanceInvestigation(instance_id="i-004", diagnostics=[result])
        analyzer.analyze(inv)
        cpu_findings = [f for f in inv.findings if f.category == "cpu"]
        assert len(cpu_findings) == 0


class TestDiskAnalysis:
    def test_full_disk_critical(self, analyzer):
        output = "ext4  /dev/xvda1  20G  19G  100M  96% /"
        result = DiagnosticResult(
            tool_name="ssm:disk_usage",
            status=DiagnosticStatus.OK,
            raw_output=output,
        )
        inv = InstanceInvestigation(instance_id="i-005", diagnostics=[result])
        analyzer.analyze(inv)
        disk_findings = [f for f in inv.findings if f.category == "disk"]
        assert any(f.severity == FindingSeverity.CRITICAL for f in disk_findings)

    def test_normal_disk_no_findings(self, analyzer):
        output = "ext4  /dev/xvda1  20G  5G  15G  25% /"
        result = DiagnosticResult(
            tool_name="ssm:disk_usage",
            status=DiagnosticStatus.OK,
            raw_output=output,
        )
        inv = InstanceInvestigation(instance_id="i-006", diagnostics=[result])
        analyzer.analyze(inv)
        disk_findings = [f for f in inv.findings if f.category == "disk"]
        assert len(disk_findings) == 0


class TestMemoryAnalysis:
    def test_critical_memory(self, analyzer):
        # free -m format
        output = "              total        used        free      shared  buff/cache   available\nMem:           8192        8000         192\nSwap:             0           0           0"
        result = DiagnosticResult(
            tool_name="ssm:memory_free",
            status=DiagnosticStatus.OK,
            raw_output=output,
        )
        inv = InstanceInvestigation(instance_id="i-007", diagnostics=[result])
        analyzer.analyze(inv)
        mem_findings = [f for f in inv.findings if f.category == "memory"]
        assert len(mem_findings) >= 1


class TestOOMAnalysis:
    def test_oom_in_console_output(self, analyzer):
        output = "kernel: Out of memory: Kill process 1234 (python) score 900\nkilled process 1234"
        result = DiagnosticResult(
            tool_name="ec2:get_console_output",
            status=DiagnosticStatus.DEGRADED,
            raw_output=output,
        )
        inv = InstanceInvestigation(instance_id="i-008", diagnostics=[result])
        analyzer.analyze(inv)
        mem_findings = [f for f in inv.findings if f.category == "memory"]
        assert len(mem_findings) >= 1

    def test_kernel_panic_in_console(self, analyzer):
        output = "Kernel panic - not syncing: VFS: Unable to mount root fs"
        result = DiagnosticResult(
            tool_name="ec2:get_console_output",
            status=DiagnosticStatus.DEGRADED,
            raw_output=output,
        )
        inv = InstanceInvestigation(instance_id="i-009", diagnostics=[result])
        analyzer.analyze(inv)
        os_findings = [f for f in inv.findings if f.category in ("os", "kernel")]
        assert len(os_findings) >= 1


class TestOverallStatus:
    def test_overall_status_reflects_worst_finding(self, analyzer):
        result = DiagnosticResult(
            tool_name="cloudwatch:cpu_utilization",
            status=DiagnosticStatus.DEGRADED,
            metrics={"cpu_utilization_pct": {"latest": 98.0, "max": 99.0, "avg": 97.0, "min": 90.0}},
        )
        inv = InstanceInvestigation(instance_id="i-010", diagnostics=[result])
        analyzer.analyze(inv)
        assert inv.overall_status in (DiagnosticStatus.FAILED, DiagnosticStatus.DEGRADED)
