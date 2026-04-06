"""
Alert normalizer.

Translates arbitrary inbound payloads into the canonical Alert model.

Supported source formats:
  - generic  : already in canonical format (default)
  - cloudwatch_alarm : AWS CloudWatch alarm state change notification
  - datadog   : Datadog webhook payload

Additional formats can be registered by subclassing or extending the
normalizer without touching the rest of the system.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from ec2_troubleshooter.models.alert import Alert, AlertSeverity, AnomalyContributor


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
        """
        if "alert_id" in payload:
            return self._parse_canonical(payload)
        if source_hint == "cloudwatch_alarm":
            return self._parse_cloudwatch_alarm(payload)
        if source_hint == "datadog":
            return self._parse_datadog(payload)
        return self._parse_generic(payload)

    # ── Canonical ─────────────────────────────────────────────────────────

    def _parse_canonical(self, p: dict[str, Any]) -> Alert:
        contributors = [
            AnomalyContributor(**c) if isinstance(c, dict) else c
            for c in p.get("contributors", [])
        ]
        return Alert(
            alert_id=p["alert_id"],
            source=p.get("source", "unknown"),
            title=p.get("title", "Untitled alert"),
            description=p.get("description", ""),
            severity=AlertSeverity(p.get("severity", "UNKNOWN")),
            fired_at=_parse_dt(p.get("fired_at")),
            instance_ids=p.get("instance_ids", []),
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
        # Also check top-level Trigger dimensions (older format)
        if not instance_ids:
            trigger = detail.get("Trigger", {})
            for dim in trigger.get("Dimensions", []):
                if dim.get("name") == "InstanceId":
                    instance_ids.append(dim["value"])

        cw_state = state.get("value", "")
        severity = (
            AlertSeverity.HIGH if cw_state == "ALARM" else AlertSeverity.LOW
        )
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
        Parse a Datadog webhook payload (monitor alert format).
        Instance IDs are expected in the ``tags`` list as ``instance_id:i-xxx``.
        """
        instance_ids = []
        for tag in p.get("tags", "").split(","):
            tag = tag.strip()
            if tag.startswith("instance_id:"):
                instance_ids.append(tag.split(":", 1)[1])

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
        return Alert(
            alert_id=_make_id(p),
            source=p.get("source", "unknown"),
            title=p.get("title") or p.get("name") or "Alert",
            description=str(p.get("description") or p.get("message") or ""),
            severity=AlertSeverity.UNKNOWN,
            fired_at=_parse_dt(p.get("fired_at") or p.get("timestamp")),
            instance_ids=instance_ids,
            raw_payload=p,
        )


def _parse_dt(value: Any) -> datetime:
    if value is None:
        return datetime.now(tz=UTC)
    if isinstance(value, datetime):
        return value
    try:
        # Unix timestamp
        return datetime.fromtimestamp(float(value), tz=UTC)
    except (TypeError, ValueError):
        pass
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(tz=UTC)


def _extract_tag(tags_str: str, key: str) -> str | None:
    for tag in tags_str.split(","):
        tag = tag.strip()
        if tag.startswith(f"{key}:"):
            return tag.split(":", 1)[1]
    return None
