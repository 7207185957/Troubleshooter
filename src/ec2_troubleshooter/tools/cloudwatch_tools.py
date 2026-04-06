"""
CloudWatch read-only metrics tools.

Fetches recent metric statistics for a given EC2 instance.  All queries go
through the CloudWatch VPC endpoint when running in an air-gapped environment.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

from ec2_troubleshooter.models.findings import DiagnosticResult, DiagnosticStatus

from .aws_client import AWSClientFactory

log = structlog.get_logger(__name__)

# Default look-back window and resolution
_DEFAULT_PERIOD_SEC = 300          # 5-minute granularity
_DEFAULT_LOOKBACK_MIN = 60         # last 60 minutes


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


class CloudWatchTools:
    """Retrieves CloudWatch metrics for EC2 instances (read-only)."""

    def __init__(self, factory: AWSClientFactory) -> None:
        self._cw = factory.cloudwatch

    # ── Internal helpers ───────────────────────────────────────────────────

    def _get_metric_stats(
        self,
        namespace: str,
        metric_name: str,
        dimensions: list[dict[str, str]],
        stat: str = "Average",
        period: int = _DEFAULT_PERIOD_SEC,
        lookback_minutes: int = _DEFAULT_LOOKBACK_MIN,
    ) -> list[dict[str, Any]]:
        end_time = _utcnow()
        start_time = end_time - timedelta(minutes=lookback_minutes)
        try:
            resp = self._cw.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                Dimensions=dimensions,
                StartTime=start_time,
                EndTime=end_time,
                Period=period,
                Statistics=[stat],
            )
            return sorted(resp.get("Datapoints", []), key=lambda dp: dp["Timestamp"])
        except Exception as exc:
            log.warning(
                "cloudwatch.get_metric_statistics failed",
                metric=metric_name,
                error=str(exc),
            )
            return []

    def _summarise_datapoints(
        self, datapoints: list[dict[str, Any]], stat: str = "Average"
    ) -> dict[str, float | None]:
        values = [dp.get(stat) for dp in datapoints if dp.get(stat) is not None]
        if not values:
            return {"latest": None, "max": None, "avg": None, "min": None}
        return {
            "latest": values[-1],
            "max": max(values),
            "avg": sum(values) / len(values),
            "min": min(values),
        }

    # ── Public diagnostic methods ─────────────────────────────────────────

    def get_cpu_utilization(self, instance_id: str) -> DiagnosticResult:
        """Fetch CPUUtilization (%) for the last hour."""
        tool = "cloudwatch:cpu_utilization"
        dims = [{"Name": "InstanceId", "Value": instance_id}]
        dps = self._get_metric_stats("AWS/EC2", "CPUUtilization", dims)
        stats = self._summarise_datapoints(dps)
        latest = stats.get("latest")
        max_val = stats.get("max")
        status = DiagnosticStatus.OK
        if latest is None:
            status = DiagnosticStatus.SKIPPED
            summary = "No CPU utilization data available"
        elif max_val is not None and max_val > 90:
            status = DiagnosticStatus.DEGRADED
            summary = f"High CPU: latest={latest:.1f}%, max={max_val:.1f}%"
        else:
            summary = f"CPU OK: latest={latest:.1f}%, max={max_val:.1f}%"
        return DiagnosticResult(
            tool_name=tool,
            status=status,
            summary=summary,
            metrics={"cpu_utilization_pct": stats},
        )

    def get_disk_io(self, instance_id: str) -> DiagnosticResult:
        """Fetch DiskReadOps and DiskWriteOps for the last hour."""
        tool = "cloudwatch:disk_io"
        dims = [{"Name": "InstanceId", "Value": instance_id}]
        read_dps = self._get_metric_stats("AWS/EC2", "DiskReadOps", dims, stat="Sum")
        write_dps = self._get_metric_stats("AWS/EC2", "DiskWriteOps", dims, stat="Sum")
        read_stats = self._summarise_datapoints(read_dps, stat="Sum")
        write_stats = self._summarise_datapoints(write_dps, stat="Sum")
        metrics = {"disk_read_ops": read_stats, "disk_write_ops": write_stats}
        summary = (
            f"Disk IO – reads: latest={read_stats['latest']}, "
            f"writes: latest={write_stats['latest']}"
        )
        return DiagnosticResult(
            tool_name=tool, status=DiagnosticStatus.OK, summary=summary, metrics=metrics
        )

    def get_network_io(self, instance_id: str) -> DiagnosticResult:
        """Fetch NetworkIn and NetworkOut bytes for the last hour."""
        tool = "cloudwatch:network_io"
        dims = [{"Name": "InstanceId", "Value": instance_id}]
        in_dps = self._get_metric_stats("AWS/EC2", "NetworkIn", dims, stat="Sum")
        out_dps = self._get_metric_stats("AWS/EC2", "NetworkOut", dims, stat="Sum")
        in_stats = self._summarise_datapoints(in_dps, stat="Sum")
        out_stats = self._summarise_datapoints(out_dps, stat="Sum")
        metrics = {"network_in_bytes": in_stats, "network_out_bytes": out_stats}
        summary = (
            f"Network IO – in: latest={in_stats['latest']}, "
            f"out: latest={out_stats['latest']}"
        )
        return DiagnosticResult(
            tool_name=tool, status=DiagnosticStatus.OK, summary=summary, metrics=metrics
        )

    def get_status_check_metrics(self, instance_id: str) -> DiagnosticResult:
        """Fetch StatusCheckFailed_* metrics which fire when EC2 health checks fail."""
        tool = "cloudwatch:status_check_metrics"
        dims = [{"Name": "InstanceId", "Value": instance_id}]
        checks = {
            "StatusCheckFailed": self._get_metric_stats(
                "AWS/EC2", "StatusCheckFailed", dims, stat="Maximum"
            ),
            "StatusCheckFailed_System": self._get_metric_stats(
                "AWS/EC2", "StatusCheckFailed_System", dims, stat="Maximum"
            ),
            "StatusCheckFailed_Instance": self._get_metric_stats(
                "AWS/EC2", "StatusCheckFailed_Instance", dims, stat="Maximum"
            ),
        }
        failed_checks: list[str] = []
        metrics: dict[str, Any] = {}
        for name, dps in checks.items():
            stats = self._summarise_datapoints(dps, stat="Maximum")
            metrics[name] = stats
            if stats.get("max") and stats["max"] > 0:
                failed_checks.append(name)

        status = DiagnosticStatus.DEGRADED if failed_checks else DiagnosticStatus.OK
        summary = (
            f"Status check failures detected: {', '.join(failed_checks)}"
            if failed_checks
            else "All status check metrics are 0"
        )
        return DiagnosticResult(
            tool_name=tool, status=status, summary=summary, metrics=metrics
        )

    def get_ebs_metrics(self, instance_id: str, volume_id: str) -> DiagnosticResult:
        """Fetch EBS-level queue length and throughput for a specific volume."""
        tool = "cloudwatch:ebs_metrics"
        dims = [{"Name": "VolumeId", "Value": volume_id}]
        queue_dps = self._get_metric_stats(
            "AWS/EBS", "VolumeQueueLength", dims, stat="Average"
        )
        read_lat_dps = self._get_metric_stats(
            "AWS/EBS", "VolumeTotalReadTime", dims, stat="Average"
        )
        write_lat_dps = self._get_metric_stats(
            "AWS/EBS", "VolumeTotalWriteTime", dims, stat="Average"
        )
        queue_stats = self._summarise_datapoints(queue_dps)
        read_lat_stats = self._summarise_datapoints(read_lat_dps)
        write_lat_stats = self._summarise_datapoints(write_lat_dps)

        degraded = queue_stats.get("max") is not None and queue_stats["max"] > 1.0
        status = DiagnosticStatus.DEGRADED if degraded else DiagnosticStatus.OK
        summary = (
            f"EBS {volume_id}: queue_length max={queue_stats['max']}"
        )
        metrics = {
            "volume_id": volume_id,
            "queue_length": queue_stats,
            "read_latency": read_lat_stats,
            "write_latency": write_lat_stats,
        }
        return DiagnosticResult(
            tool_name=tool, status=status, summary=summary, metrics=metrics
        )
