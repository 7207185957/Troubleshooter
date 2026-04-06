"""Inbound alert model.

Represents a normalised anomaly alert produced by any upstream platform
(AIOps archetype notifier, Datadog, CloudWatch Alarm, etc.).
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


class ContributorKind(StrEnum):
    """
    Classification of what kind of signal a contributor represents.

    log_signal  – A pre-aggregated log error count already present in the
                  alert payload (app_log_errors, dag_log_errors).
                  These are NOT Prometheus metrics and must not be queried
                  from Mimir.  The count is read directly from the alert.

    infra_metric – A standard infrastructure metric (cpu, memory, disk,
                   network).  These are already covered by the
                   prometheus:node_metrics tool (node_exporter queries).
                   No additional Mimir query is needed.

    app_metric   – An application-specific Prometheus metric
                   (e.g. kafka_consumer_lag, jvm_heap_used, http_error_rate).
                   These should be queried from Mimir by metric name.

    unknown      – Classification could not be determined; treated as
                   informational only, no query attempted.
    """

    LOG_SIGNAL = "log_signal"
    INFRA_METRIC = "infra_metric"
    APP_METRIC = "app_metric"
    UNKNOWN = "unknown"


# Metric names that are log-based signals (count already in the alert payload)
_LOG_SIGNAL_NAMES: frozenset[str] = frozenset({
    "app_log_errors",
    "dag_log_errors",
})

# Metric names that map to node_exporter / infra categories already queried
_INFRA_METRIC_PREFIXES: tuple[str, ...] = (
    "cpu",
    "memory",
    "mem",
    "disk",
    "network",
    "net",
    "load",
    "swap",
)


def classify_contributor(metric_name: str) -> ContributorKind:
    """
    Determine the ContributorKind for a metric name.

    Rules (applied in order):
      1. If the name is in the log signal set → LOG_SIGNAL
      2. If the name starts with an infra prefix → INFRA_METRIC
      3. If the name looks like a valid Prometheus metric name → APP_METRIC
      4. Otherwise → UNKNOWN
    """
    name = metric_name.strip().lower()
    if name in _LOG_SIGNAL_NAMES:
        return ContributorKind.LOG_SIGNAL
    if any(name == p or name.startswith(f"{p}_") or name.startswith(f"{p} ")
           for p in _INFRA_METRIC_PREFIXES):
        return ContributorKind.INFRA_METRIC
    import re
    if re.match(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$", metric_name):
        return ContributorKind.APP_METRIC
    return ContributorKind.UNKNOWN


class AnomalyContributor(BaseModel):
    """A single metric or dimension that contributed to the anomaly score."""

    metric_name: str
    """Metric or signal name as it appears in the alert, e.g. 'app_log_errors'."""

    kind: ContributorKind = ContributorKind.UNKNOWN
    """Classification of this contributor — set by the normalizer."""

    value: float | None = None
    """Observed value at alert time (for log signals this is the error count)."""

    threshold: float | None = None
    """Threshold / expected value that was breached, if known."""

    score: float | None = None
    """Anomaly score or weight assigned by the upstream platform."""

    unit: str | None = None
    """Metric unit, e.g. 'Percent', 'Bytes/Second'."""

    extra: dict[str, Any] = Field(default_factory=dict)
    """Arbitrary additional context from the upstream platform."""


class AIOpsScores(BaseModel):
    """Health / failure / risk scores from the AIOps archetype platform."""

    health: float | None = None
    failure: float | None = None
    risk: float | None = None

    # Anomaly counts
    infra_anomalies: int = 0
    app_anomalies: int = 0
    app_log_errors: int = 0
    dag_log_errors: int = 0

    # State classification from the AIOps policy engine
    state: str | None = None
    """e.g. 'UNHEALTHY_STABLE', 'DEGRADING', 'HEALTHY'"""

    policy_reason: str | None = None
    """e.g. 'first_unhealthy_bucket'"""


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
        description="EC2 instance IDs (i-xxx). Populated after name resolution.",
    )
    instance_names: list[str] = Field(
        default_factory=list,
        description=(
            "EC2 instance Name-tag values as they appear in the alert "
            "(e.g. 'ec2-dw-platform-use1-mimirread-102p'). "
            "The orchestrator resolves these to instance IDs before investigating."
        ),
    )
    archetype: str | None = Field(
        default=None,
        description="Logical group / archetype label, e.g. 'platform-mimir (use1)'",
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

    # ── AIOps-specific scores and state ───────────────────────────────────
    aiops: AIOpsScores | None = Field(
        default=None,
        description="Health, failure, risk scores and anomaly counts from the AIOps platform",
    )

    # ── Raw payload passthrough ───────────────────────────────────────────
    raw_payload: dict[str, Any] = Field(
        default_factory=dict,
        description="Original unmodified payload from the source platform",
    )
