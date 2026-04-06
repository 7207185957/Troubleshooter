"""
EC2 read-only diagnostic tools.

All methods call describe-* or get-* EC2 APIs.  No mutating API is called.
"""

from __future__ import annotations

from typing import Any

import structlog

from ec2_troubleshooter.models.findings import DiagnosticResult, DiagnosticStatus

from .aws_client import AWSClientFactory

log = structlog.get_logger(__name__)


class EC2Tools:
    """Read-only EC2 instance diagnostics via the EC2 and STS APIs."""

    def __init__(self, factory: AWSClientFactory) -> None:
        self._ec2 = factory.ec2
        self._sts = factory.sts

    # ── Instance metadata ──────────────────────────────────────────────────

    def describe_instance(self, instance_id: str) -> DiagnosticResult:
        """Return core instance metadata (type, state, AZ, tags, etc.)."""
        tool = "ec2:describe_instance"
        try:
            resp = self._ec2.describe_instances(InstanceIds=[instance_id])
            reservations = resp.get("Reservations", [])
            if not reservations:
                return DiagnosticResult(
                    tool_name=tool,
                    status=DiagnosticStatus.ERROR,
                    summary=f"Instance {instance_id} not found",
                )
            inst = reservations[0]["Instances"][0]
            state = inst.get("State", {}).get("Name", "unknown")
            status = DiagnosticStatus.OK if state == "running" else DiagnosticStatus.DEGRADED
            tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
            metrics = {
                "instance_id": instance_id,
                "instance_type": inst.get("InstanceType"),
                "state": state,
                "availability_zone": inst.get("Placement", {}).get("AvailabilityZone"),
                "private_ip": inst.get("PrivateIpAddress"),
                "public_ip": inst.get("PublicIpAddress"),
                "launch_time": str(inst.get("LaunchTime", "")),
                "image_id": inst.get("ImageId"),
                "platform": inst.get("Platform", "linux"),
                "tags": tags,
                "iam_instance_profile": inst.get("IamInstanceProfile", {}).get("Arn"),
                "vpc_id": inst.get("VpcId"),
                "subnet_id": inst.get("SubnetId"),
                "security_groups": [
                    sg.get("GroupId") for sg in inst.get("SecurityGroups", [])
                ],
            }
            summary = (
                f"Instance {instance_id} is {state} "
                f"({inst.get('InstanceType')}, {inst.get('Placement', {}).get('AvailabilityZone')})"
            )
            return DiagnosticResult(
                tool_name=tool, status=status, summary=summary, metrics=metrics
            )
        except Exception as exc:
            log.warning("ec2.describe_instance failed", instance_id=instance_id, error=str(exc))
            return DiagnosticResult(
                tool_name=tool,
                status=DiagnosticStatus.ERROR,
                summary=f"API error: {exc}",
                error=str(exc),
            )

    def get_instance_status(self, instance_id: str) -> DiagnosticResult:
        """Return EC2 instance status checks (system + instance checks)."""
        tool = "ec2:get_instance_status"
        try:
            resp = self._ec2.describe_instance_status(
                InstanceIds=[instance_id], IncludeAllInstances=True
            )
            statuses = resp.get("InstanceStatuses", [])
            if not statuses:
                return DiagnosticResult(
                    tool_name=tool,
                    status=DiagnosticStatus.SKIPPED,
                    summary="No status data available",
                )
            s = statuses[0]
            sys_check = s.get("SystemStatus", {}).get("Status", "unknown")
            inst_check = s.get("InstanceStatus", {}).get("Status", "unknown")
            overall = (
                DiagnosticStatus.OK
                if sys_check == "ok" and inst_check == "ok"
                else DiagnosticStatus.DEGRADED
            )
            sys_details = [
                f"{d['Name']}: {d['Status']}"
                for d in s.get("SystemStatus", {}).get("Details", [])
            ]
            inst_details = [
                f"{d['Name']}: {d['Status']}"
                for d in s.get("InstanceStatus", {}).get("Details", [])
            ]
            metrics = {
                "system_status": sys_check,
                "instance_status": inst_check,
                "system_details": sys_details,
                "instance_details": inst_details,
            }
            summary = f"System check: {sys_check}; Instance check: {inst_check}"
            return DiagnosticResult(
                tool_name=tool, status=overall, summary=summary, metrics=metrics
            )
        except Exception as exc:
            log.warning("ec2.get_instance_status failed", instance_id=instance_id, error=str(exc))
            return DiagnosticResult(
                tool_name=tool,
                status=DiagnosticStatus.ERROR,
                summary=f"API error: {exc}",
                error=str(exc),
            )

    def describe_volumes(self, instance_id: str) -> DiagnosticResult:
        """Return EBS volumes attached to the instance."""
        tool = "ec2:describe_volumes"
        try:
            resp = self._ec2.describe_volumes(
                Filters=[{"Name": "attachment.instance-id", "Values": [instance_id]}]
            )
            volumes: list[dict[str, Any]] = resp.get("Volumes", [])
            volume_info = []
            degraded = False
            for vol in volumes:
                state = vol.get("State", "unknown")
                if state != "in-use":
                    degraded = True
                volume_info.append(
                    {
                        "volume_id": vol.get("VolumeId"),
                        "size_gb": vol.get("Size"),
                        "volume_type": vol.get("VolumeType"),
                        "state": state,
                        "iops": vol.get("Iops"),
                        "throughput": vol.get("Throughput"),
                        "encrypted": vol.get("Encrypted"),
                        "device": next(
                            (
                                a.get("Device")
                                for a in vol.get("Attachments", [])
                                if a.get("InstanceId") == instance_id
                            ),
                            None,
                        ),
                    }
                )
            status = DiagnosticStatus.DEGRADED if degraded else DiagnosticStatus.OK
            summary = f"{len(volumes)} volume(s) attached"
            return DiagnosticResult(
                tool_name=tool,
                status=status,
                summary=summary,
                metrics={"volumes": volume_info},
            )
        except Exception as exc:
            log.warning("ec2.describe_volumes failed", instance_id=instance_id, error=str(exc))
            return DiagnosticResult(
                tool_name=tool,
                status=DiagnosticStatus.ERROR,
                summary=f"API error: {exc}",
                error=str(exc),
            )

    def get_console_output(self, instance_id: str) -> DiagnosticResult:
        """Retrieve the most recent EC2 serial console output (read-only)."""
        tool = "ec2:get_console_output"
        try:
            resp = self._ec2.get_console_output(InstanceId=instance_id, Latest=True)
            output: str = resp.get("Output", "") or ""
            # Truncate to last 8 KB so we don't blow up the report
            if len(output) > 8192:
                output = "...[truncated]...\n" + output[-8192:]
            has_errors = any(
                kw in output.lower()
                for kw in ("error", "panic", "oops", "oom", "killed", "segfault", "kernel bug")
            )
            status = DiagnosticStatus.DEGRADED if has_errors else DiagnosticStatus.OK
            summary = (
                "Console output contains error indicators"
                if has_errors
                else "No critical error keywords in console output"
            )
            return DiagnosticResult(
                tool_name=tool,
                status=status,
                summary=summary,
                raw_output=output if output else None,
            )
        except Exception as exc:
            log.warning(
                "ec2.get_console_output failed", instance_id=instance_id, error=str(exc)
            )
            return DiagnosticResult(
                tool_name=tool,
                status=DiagnosticStatus.ERROR,
                summary=f"API error: {exc}",
                error=str(exc),
            )

    def get_caller_identity(self) -> dict[str, str]:
        """Return the AWS caller identity – useful for confirming air-gapped connectivity."""
        try:
            return self._sts.get_caller_identity()
        except Exception as exc:
            log.warning("sts.get_caller_identity failed", error=str(exc))
            return {"error": str(exc)}
