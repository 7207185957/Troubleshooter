"""Investigation findings model.

Represents the structured output produced by the orchestrator after running
all applicable diagnostic tools against an EC2 instance.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from ec2_troubleshooter.compat import StrEnum


class FindingSeverity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class DiagnosticStatus(StrEnum):
    OK = "OK"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


class DiagnosticResult(BaseModel):
    """Result from a single diagnostic tool call."""

    tool_name: str
    status: DiagnosticStatus = DiagnosticStatus.OK
    summary: str = ""
    raw_output: str | None = None
    metrics: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    duration_ms: float | None = None


class Finding(BaseModel):
    """A single observed symptom or conclusion extracted from diagnostic results."""

    severity: FindingSeverity = FindingSeverity.INFO
    category: str
    """Broad category: cpu | memory | disk | network | process | os | config | other"""

    message: str
    """Human-readable description of the finding."""

    evidence: list[str] = Field(default_factory=list)
    """Supporting evidence snippets (log lines, metric values, command output)."""

    recommendation: str = ""
    """Read-only observation / next step for a human responder – NOT a remediation action."""


class InstanceInvestigation(BaseModel):
    """Diagnostic results and findings for a single EC2 instance."""

    instance_id: str
    instance_state: str | None = None
    instance_type: str | None = None
    private_ip: str | None = None
    public_ip: str | None = None
    availability_zone: str | None = None
    launch_time: datetime | None = None
    tags: dict[str, str] = Field(default_factory=dict)
    ssm_managed: bool = False

    diagnostics: list[DiagnosticResult] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)

    overall_status: DiagnosticStatus = DiagnosticStatus.OK
    summary: str = ""

    started_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    completed_at: datetime | None = None


class InvestigationReport(BaseModel):
    """Top-level report for an entire alert investigation."""

    alert_id: str
    alert_title: str
    alert_source: str
    severity: str
    archetype: str | None = None

    # AIOps scores carried from the original alert for context in the report
    aiops_health: float | None = None
    aiops_failure: float | None = None
    aiops_risk: float | None = None
    aiops_state: str | None = None
    aiops_policy_reason: str | None = None
    aiops_app_log_errors: int = 0

    instances: list[InstanceInvestigation] = Field(default_factory=list)
    likely_causes: list[str] = Field(default_factory=list)
    summary: str = ""

    started_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    completed_at: datetime | None = None

    error: str | None = None
    """Set if the investigation itself encountered a fatal error."""
