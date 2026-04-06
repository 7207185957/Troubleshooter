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
    def test_high_cpu_critical_from_prometheus(self, analyzer):
        result = DiagnosticResult(
            tool_name="prometheus:node_metrics",
            status=DiagnosticStatus.FAILED,
            summary="CPU=97.0%, Mem=50.0%, Load1m=12.00",
            metrics={"cpu_usage_pct": 97.0, "memory_used_pct": 50.0, "load_1m": 12.0},
        )
        inv = InstanceInvestigation(instance_id="i-003", diagnostics=[result])
        analyzer.analyze(inv)
        cpu_findings = [f for f in inv.findings if f.category == "cpu"]
        assert len(cpu_findings) >= 1
        assert cpu_findings[0].severity == FindingSeverity.CRITICAL

    def test_elevated_cpu_high_from_prometheus(self, analyzer):
        result = DiagnosticResult(
            tool_name="prometheus:node_metrics",
            status=DiagnosticStatus.DEGRADED,
            summary="CPU=83.0%",
            metrics={"cpu_usage_pct": 83.0},
        )
        inv = InstanceInvestigation(instance_id="i-003b", diagnostics=[result])
        analyzer.analyze(inv)
        cpu_findings = [f for f in inv.findings if f.category == "cpu"]
        assert len(cpu_findings) >= 1
        assert cpu_findings[0].severity == FindingSeverity.HIGH

    def test_normal_cpu_no_findings(self, analyzer):
        result = DiagnosticResult(
            tool_name="prometheus:node_metrics",
            status=DiagnosticStatus.OK,
            summary="CPU=20.0%, Mem=40.0%",
            metrics={"cpu_usage_pct": 20.0, "memory_used_pct": 40.0},
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
    def test_critical_memory_from_prometheus(self, analyzer):
        result = DiagnosticResult(
            tool_name="prometheus:node_metrics",
            status=DiagnosticStatus.FAILED,
            summary="Mem=97.0%",
            metrics={
                "memory_used_pct": 97.0,
                "memory_available_bytes": 100 * 1024 * 1024,
                "memory_total_bytes": 8 * 1024 * 1024 * 1024,
            },
        )
        inv = InstanceInvestigation(instance_id="i-007a", diagnostics=[result])
        analyzer.analyze(inv)
        mem_findings = [f for f in inv.findings if f.category == "memory"]
        assert len(mem_findings) >= 1
        assert mem_findings[0].severity == FindingSeverity.CRITICAL

    def test_critical_memory_from_ssm(self, analyzer):
        # free -m format
        output = "              total        used        free      shared  buff/cache   available\nMem:           8192        8000         192\nSwap:             0           0           0"
        result = DiagnosticResult(
            tool_name="ssm:memory_free",
            status=DiagnosticStatus.OK,
            raw_output=output,
        )
        inv = InstanceInvestigation(instance_id="i-007b", diagnostics=[result])
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


class TestPrometheusFindings:
    def test_oom_kill_critical(self, analyzer):
        result = DiagnosticResult(
            tool_name="prometheus:node_metrics",
            status=DiagnosticStatus.FAILED,
            summary="OOM kills active",
            metrics={"oom_kills_rate": 0.05},
        )
        inv = InstanceInvestigation(instance_id="i-011", diagnostics=[result])
        analyzer.analyze(inv)
        oom_findings = [f for f in inv.findings if "OOM" in f.message]
        assert len(oom_findings) >= 1
        assert oom_findings[0].severity == FindingSeverity.CRITICAL

    def test_disk_full_critical_from_vector(self, analyzer):
        result = DiagnosticResult(
            tool_name="prometheus:node_metrics",
            status=DiagnosticStatus.DEGRADED,
            summary="disk full",
            metrics={
                "disk_used_pct": [
                    {"labels": {"mountpoint": "/", "device": "/dev/xvda1"}, "value": 97.0}
                ]
            },
        )
        inv = InstanceInvestigation(instance_id="i-012", diagnostics=[result])
        analyzer.analyze(inv)
        disk_findings = [f for f in inv.findings if f.category == "disk"]
        assert any(f.severity == FindingSeverity.CRITICAL for f in disk_findings)

    def test_contributor_metric_info_finding(self, analyzer):
        result = DiagnosticResult(
            tool_name="prometheus:contributor:kafka_consumer_lag",
            status=DiagnosticStatus.OK,
            summary="kafka_consumer_lag current value: 5000",
            metrics={"metric": "kafka_consumer_lag", "result": 5000.0},
        )
        inv = InstanceInvestigation(instance_id="i-013", diagnostics=[result])
        analyzer.analyze(inv)
        other_findings = [f for f in inv.findings if f.category == "other"]
        assert len(other_findings) >= 1
        assert other_findings[0].severity == FindingSeverity.INFO


class TestOverallStatus:
    def test_overall_status_reflects_worst_finding(self, analyzer):
        result = DiagnosticResult(
            tool_name="prometheus:node_metrics",
            status=DiagnosticStatus.FAILED,
            summary="CPU=98.0%",
            metrics={"cpu_usage_pct": 98.0},
        )
        inv = InstanceInvestigation(instance_id="i-010", diagnostics=[result])
        analyzer.analyze(inv)
        assert inv.overall_status in (DiagnosticStatus.FAILED, DiagnosticStatus.DEGRADED)
