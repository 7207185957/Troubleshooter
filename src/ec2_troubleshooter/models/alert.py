"""Inbound alert model.

Represents a normalised anomaly alert produced by any upstream platform
(custom anomaly detector, Datadog, CloudWatch Anomaly Detection, etc.).
The receiver layer is responsible for translating platform-specific payloads
into this canonical shape before passing them to the orchestrator.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AlertSeverity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class AnomalyContributor(BaseModel):
    """A single metric or dimension that contributed to the anomaly score."""

    metric_name: str
    """Human-readable metric or signal name, e.g. 'CPUUtilization'."""

    value: float | None = None
    """Observed value at alert time."""

    threshold: float | None = None
    """Threshold / expected value that was breached, if known."""

    score: float | None = None
    """Anomaly score or weight assigned by the upstream platform."""

    unit: str | None = None
    """Metric unit, e.g. 'Percent', 'Bytes/Second'."""

    extra: dict[str, Any] = Field(default_factory=dict)
    """Arbitrary additional context from the upstream platform."""


class Alert(BaseModel):
    """Normalised inbound alert."""

    alert_id: str = Field(..., description="Unique identifier assigned by the source platform")
    source: str = Field(..., description="Name / identifier of the alerting platform")
    title: str = Field(..., description="Short human-readable title")
    description: str = Field(default="", description="Optional longer description")
    severity: AlertSeverity = AlertSeverity.UNKNOWN
    fired_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))

    # ── Affected resources ────────────────────────────────────────────────
    instance_ids: list[str] = Field(
        default_factory=list,
        description="EC2 instance IDs affected by this alert",
    )
    archetype: str | None = Field(
        default=None,
        description="Logical group / archetype label, e.g. 'kafka-broker', 'airflow-worker'",
    )
    aws_region: str | None = Field(
        default=None,
        description="AWS region override; falls back to the global setting if absent",
    )
    aws_account_id: str | None = None

    # ── Anomaly context ───────────────────────────────────────────────────
    contributors: list[AnomalyContributor] = Field(
        default_factory=list,
        description="Metrics / dimensions that contributed to the anomaly",
    )

    # ── Raw payload passthrough ───────────────────────────────────────────
    raw_payload: dict[str, Any] = Field(
        default_factory=dict,
        description="Original unmodified payload from the source platform",
    )
