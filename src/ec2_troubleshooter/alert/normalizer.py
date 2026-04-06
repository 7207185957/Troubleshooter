"""
Alert normalizer.

Translates arbitrary inbound payloads into the canonical Alert model.

Supported source formats
────────────────────────
  aiops_archetype  – AIOps / Archetype Notifications GChat webhook payload
                     (the format shown in the screenshot: health/failure/risk,
                      affected instances as Name tags, metric contributors)
  generic          – already in canonical format (default fallback)
  cloudwatch_alarm – AWS CloudWatch alarm state change notification
  datadog          – Datadog monitor webhook payload

The ``source_hint`` query parameter on the /alert endpoint selects the parser.
Auto-detection is attempted when source_hint is "generic" and the payload
does not contain an ``alert_id`` field.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

from ec2_troubleshooter.models.alert import (
    AIOpsScores,
    Alert,
    AlertSeverity,
    AnomalyContributor,
    classify_contributor,
)


def _make_id(payload: dict[str, Any]) -> str:
    """Generate a stable alert_id from the payload hash if one is not supplied."""
    blob = json.dumps(payload, sort_keys=True, default=str)
    return "auto-" + hashlib.sha256(blob.encode()).hexdigest()[:12]


class AlertNormalizer:
    """Converts raw webhook payloads into canonical Alert objects."""

    def normalize(self, payload: dict[str, Any], source_hint: str = "generic") -> Alert:
        """
        Convert *payload* to an Alert.

        *source_hint* controls which parser is applied.  If the payload already
        has a top-level ``alert_id`` field it is assumed to be canonical.
        Auto-detection is attempted for ``aiops_archetype`` payloads.
        """
        if "alert_id" in payload:
            return self._parse_canonical(payload)
        if source_hint == "aiops_archetype" or _looks_like_aiops(payload):
            return self._parse_aiops_archetype(payload)
        if source_hint == "cloudwatch_alarm":
            return self._parse_cloudwatch_alarm(payload)
        if source_hint == "datadog":
            return self._parse_datadog(payload)
        return self._parse_generic(payload)

    # ── AIOps / Archetype Notifications ───────────────────────────────────

    def _parse_aiops_archetype(self, p: dict[str, Any]) -> Alert:
        """
        Parse the AIOps Archetype Notifications payload.

        Expected fields (all optional except the ones used to build the title):
          title / alert_title      – e.g. "AIOps ALERT: platform-mimir (use1)"
          state                    – e.g. "UNHEALTHY_STABLE"
          timestamp / fired_at     – ISO-8601 string
          health                   – float, e.g. 70.0
          failure                  – float, e.g. 86.1
          risk                     – float, e.g. 57.4
          contributors             – string or list of contributor names
          metric_contributors      – string or list of metric signal names
          affected_instances       – list of EC2 Name-tag strings
          infra_anomalies          – int
          app_anomalies            – int
          app_log_errors           – int
          dag_log_errors           – int
          policy_reason            – string, e.g. "first_unhealthy_bucket"
          archetype                – string, extracted from title if absent
        """
        # ── Title / ID ────────────────────────────────────────────────────
        title = (
            p.get("title")
            or p.get("alert_title")
            or p.get("name")
            or "AIOps ALERT"
        )
        alert_id = p.get("alert_id") or p.get("id") or _make_id(p)

        # ── Timestamp ─────────────────────────────────────────────────────
        fired_at = _parse_dt(
            p.get("fired_at") or p.get("timestamp") or p.get("time")
        )

        # ── Severity from state ───────────────────────────────────────────
        state = str(p.get("state", "")).upper()
        severity = _aiops_state_to_severity(state)

        # ── Archetype ─────────────────────────────────────────────────────
        # Try explicit field first, then extract from the title
        # e.g. "AIOps ALERT: platform-mimir (use1)" → "platform-mimir (use1)"
        archetype = p.get("archetype") or _extract_archetype_from_title(title)

        # ── Affected instances (by Name tag) ─────────────────────────────
        raw_instances = p.get("affected_instances") or p.get("instances") or []
        if isinstance(raw_instances, str):
            raw_instances = [i.strip() for i in raw_instances.split(",") if i.strip()]
        instance_names = [str(n) for n in raw_instances if n]

        # ── Metric contributors ───────────────────────────────────────────
        contributors: list[AnomalyContributor] = []

        # "Contributors" section (categorical labels like "App logs") – informational
        contrib_labels = p.get("contributors") or []
        if isinstance(contrib_labels, str):
            contrib_labels = [c.strip() for c in contrib_labels.split(",") if c.strip()]

        # "Metric contributors" section (actual signal/metric names to investigate)
        metric_contribs = p.get("metric_contributors") or []
        if isinstance(metric_contribs, str):
            metric_contribs = [m.strip() for m in metric_contribs.split(",") if m.strip()]

        for name in metric_contribs:
            kind = classify_contributor(name)
            # For log signals, read the count directly from the alert payload
            value: float | None = None
            if name == "app_log_errors":
                value = _safe_float(p.get("app_log_errors"))
            elif name == "dag_log_errors":
                value = _safe_float(p.get("dag_log_errors"))
            contributors.append(
                AnomalyContributor(metric_name=name, kind=kind, value=value)
            )

        # If no metric contributors, fall back to categorical labels (informational)
        if not contributors:
            for label in contrib_labels:
                contributors.append(
                    AnomalyContributor(
                        metric_name=label,
                        kind=classify_contributor(label),
                    )
                )

        # ── AIOps scores ──────────────────────────────────────────────────
        aiops = AIOpsScores(
            health=_safe_float(p.get("health")),
            failure=_safe_float(p.get("failure")),
            risk=_safe_float(p.get("risk")),
            infra_anomalies=int(p.get("infra_anomalies") or 0),
            app_anomalies=int(p.get("app_anomalies") or 0),
            app_log_errors=int(p.get("app_log_errors") or 0),
            dag_log_errors=int(p.get("dag_log_errors") or 0),
            state=state or None,
            policy_reason=p.get("policy_reason"),
        )

        # ── Description ───────────────────────────────────────────────────
        description_parts = []
        if state:
            description_parts.append(f"State: {state}")
        if aiops.health is not None:
            description_parts.append(f"Health: {aiops.health}")
        if aiops.failure is not None:
            description_parts.append(f"Failure: {aiops.failure}")
        if aiops.app_log_errors:
            description_parts.append(f"App log errors: {aiops.app_log_errors}")
        description = " | ".join(description_parts)

        return Alert(
            alert_id=str(alert_id),
            source="aiops_archetype",
            title=title,
            description=description,
            severity=severity,
            fired_at=fired_at,
            instance_ids=[],        # populated by orchestrator after name resolution
            instance_names=instance_names,
            archetype=archetype,
            contributors=contributors,
            aiops=aiops,
            raw_payload=p,
        )

    # ── Canonical ─────────────────────────────────────────────────────────

    def _parse_canonical(self, p: dict[str, Any]) -> Alert:
        contributors = []
        for c in p.get("contributors", []):
            if isinstance(c, dict):
                # Classify if kind not already provided
                if "kind" not in c:
                    c = {**c, "kind": classify_contributor(c.get("metric_name", ""))}
                contributors.append(AnomalyContributor(**c))
            else:
                contributors.append(c)
        return Alert(
            alert_id=p["alert_id"],
            source=p.get("source", "unknown"),
            title=p.get("title", "Untitled alert"),
            description=p.get("description", ""),
            severity=AlertSeverity(p.get("severity", "UNKNOWN")),
            fired_at=_parse_dt(p.get("fired_at")),
            instance_ids=p.get("instance_ids", []),
            instance_names=p.get("instance_names", []),
            archetype=p.get("archetype"),
            aws_region=p.get("aws_region"),
            aws_account_id=p.get("aws_account_id"),
            contributors=contributors,
            raw_payload=p,
        )

    # ── CloudWatch alarm ──────────────────────────────────────────────────

    def _parse_cloudwatch_alarm(self, p: dict[str, Any]) -> Alert:
        """
        Parse a CloudWatch alarm state change event delivered via SNS or
        EventBridge.  Instance IDs are extracted from alarm dimensions.
        """
        detail = p.get("detail", p)
        config = detail.get("configuration", {})
        state = detail.get("state", {})

        alarm_name = config.get("description") or detail.get("alarmName", "CloudWatch Alarm")
        reason = state.get("reason", "")
        instance_ids = [
            d["value"]
            for d in config.get("metrics", [{}])
            for m in [d.get("metricStat", {}).get("metric", {})]
            for d in m.get("dimensions", [])
            if d.get("name") == "InstanceId"
        ]
        if not instance_ids:
            trigger = detail.get("Trigger", {})
            for dim in trigger.get("Dimensions", []):
                if dim.get("name") == "InstanceId":
                    instance_ids.append(dim["value"])

        cw_state = state.get("value", "")
        severity = AlertSeverity.HIGH if cw_state == "ALARM" else AlertSeverity.LOW
        contributors = []
        if reason:
            contributors.append(AnomalyContributor(metric_name="CloudWatch alarm reason", score=1.0))

        return Alert(
            alert_id=detail.get("alarmArn") or _make_id(p),
            source="cloudwatch_alarm",
            title=alarm_name,
            description=reason,
            severity=severity,
            fired_at=_parse_dt(detail.get("time") or p.get("time")),
            instance_ids=instance_ids,
            contributors=contributors,
            raw_payload=p,
        )

    # ── Datadog ────────────────────────────────────────────────────────────

    def _parse_datadog(self, p: dict[str, Any]) -> Alert:
        """
        Parse a Datadog monitor webhook payload.
        Instance IDs are expected in ``tags`` as ``instance_id:i-xxx``.
        Instance names can be passed as ``instance_name:hostname`` tags.
        """
        instance_ids = []
        instance_names = []
        for tag in p.get("tags", "").split(","):
            tag = tag.strip()
            if tag.startswith("instance_id:"):
                instance_ids.append(tag.split(":", 1)[1])
            elif tag.startswith("instance_name:"):
                instance_names.append(tag.split(":", 1)[1])

        severity_map = {
            "alert": AlertSeverity.HIGH,
            "warning": AlertSeverity.MEDIUM,
            "no data": AlertSeverity.LOW,
            "ok": AlertSeverity.LOW,
        }
        dd_status = p.get("alert_type", "").lower()
        severity = severity_map.get(dd_status, AlertSeverity.UNKNOWN)

        return Alert(
            alert_id=str(p.get("id", _make_id(p))),
            source="datadog",
            title=p.get("title", "Datadog monitor alert"),
            description=p.get("body", ""),
            severity=severity,
            fired_at=_parse_dt(p.get("date")),
            instance_ids=instance_ids,
            instance_names=instance_names,
            archetype=_extract_tag(p.get("tags", ""), "archetype"),
            contributors=[
                AnomalyContributor(metric_name=p.get("metric", "unknown"))
            ] if p.get("metric") else [],
            raw_payload=p,
        )

    # ── Fallback generic ───────────────────────────────────────────────────

    def _parse_generic(self, p: dict[str, Any]) -> Alert:
        """Best-effort parse for any unrecognised payload structure."""
        instance_ids = p.get("instance_ids") or p.get("instances") or []
        if isinstance(instance_ids, str):
            instance_ids = [instance_ids]
        instance_names = p.get("instance_names") or []
        if isinstance(instance_names, str):
            instance_names = [instance_names]
        return Alert(
            alert_id=_make_id(p),
            source=p.get("source", "unknown"),
            title=p.get("title") or p.get("name") or "Alert",
            description=str(p.get("description") or p.get("message") or ""),
            severity=AlertSeverity.UNKNOWN,
            fired_at=_parse_dt(p.get("fired_at") or p.get("timestamp")),
            instance_ids=instance_ids,
            instance_names=instance_names,
            raw_payload=p,
        )


# ── Helpers ────────────────────────────────────────────────────────────────

def _parse_dt(value: Any) -> datetime:
    if value is None:
        return datetime.now(tz=timezone.utc)
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (TypeError, ValueError):
        pass
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(tz=timezone.utc)


def _extract_tag(tags_str: str, key: str) -> str | None:
    for tag in tags_str.split(","):
        tag = tag.strip()
        if tag.startswith(f"{key}:"):
            return tag.split(":", 1)[1]
    return None


def _safe_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _aiops_state_to_severity(state: str) -> AlertSeverity:
    """Map AIOps state strings to AlertSeverity."""
    s = state.upper()
    if "CRITICAL" in s or "UNHEALTHY_DEGRADING" in s:
        return AlertSeverity.CRITICAL
    if "UNHEALTHY" in s or "DEGRADING" in s:
        return AlertSeverity.HIGH
    if "WARNING" in s or "AT_RISK" in s:
        return AlertSeverity.MEDIUM
    if "HEALTHY" in s or "RECOVERING" in s:
        return AlertSeverity.LOW
    return AlertSeverity.UNKNOWN


def _extract_archetype_from_title(title: str) -> str | None:
    """
    Extract the archetype name from a title like:
      'AIOps ALERT: platform-mimir (use1)'  →  'platform-mimir (use1)'
      '🔴 AIOps ALERT: platform-mimir (use1)'  →  'platform-mimir (use1)'
    """
    m = re.search(r"ALERT:\s*(.+)$", title, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return None


def _looks_like_aiops(payload: dict[str, Any]) -> bool:
    """
    Heuristic: return True if the payload looks like an AIOps Archetype
    Notifications payload even without an explicit source_hint.
    """
    aiops_keys = {"health", "failure", "risk", "affected_instances", "metric_contributors"}
    return bool(aiops_keys.intersection(payload.keys()))
