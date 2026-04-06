"""
Report formatter.

Converts an InvestigationReport into human-readable text suitable for
GChat cards, ticketing systems, or incident UIs.
"""

from __future__ import annotations

from ec2_troubleshooter.models.findings import (
    DiagnosticStatus,
    FindingSeverity,
    InvestigationReport,
)

_SEV_EMOJI = {
    FindingSeverity.CRITICAL: "🔴",
    FindingSeverity.HIGH: "🟠",
    FindingSeverity.MEDIUM: "🟡",
    FindingSeverity.LOW: "🔵",
    FindingSeverity.INFO: "⚪",
}

_STATUS_EMOJI = {
    DiagnosticStatus.OK: "✅",
    DiagnosticStatus.DEGRADED: "⚠️",
    DiagnosticStatus.FAILED: "❌",
    DiagnosticStatus.ERROR: "💥",
    DiagnosticStatus.SKIPPED: "⏭️",
}


def format_text(report: InvestigationReport) -> str:
    """Return a plain-text summary of the report."""
    lines: list[str] = [
        "=" * 60,
        "EC2 INVESTIGATION REPORT",
        f"Alert: {report.alert_title} [{report.alert_id}]",
        f"Source: {report.alert_source}  |  Severity: {report.severity}",
        f"Summary: {report.summary}",
        "=" * 60,
    ]

    if report.likely_causes:
        lines.append("\nLIKELY CAUSES:")
        for i, cause in enumerate(report.likely_causes, 1):
            lines.append(f"  {i}. {cause}")

    for inv in report.instances:
        status_icon = _STATUS_EMOJI.get(inv.overall_status, "❓")
        lines.append(f"\n--- Instance: {inv.instance_id} {status_icon} ---")
        if inv.instance_type:
            lines.append(
                f"  Type: {inv.instance_type}  |  "
                f"AZ: {inv.availability_zone}  |  "
                f"State: {inv.instance_state}"
            )
        if inv.private_ip:
            lines.append(f"  IP: {inv.private_ip}")
        if inv.tags:
            tag_str = ", ".join(f"{k}={v}" for k, v in list(inv.tags.items())[:5])
            lines.append(f"  Tags: {tag_str}")
        lines.append(f"  SSM-managed: {inv.ssm_managed}")

        if inv.findings:
            lines.append("  Findings:")
            for f in inv.findings:
                icon = _SEV_EMOJI.get(f.severity, "❓")
                lines.append(f"    {icon} [{f.category.upper()}] {f.message}")
                for ev in f.evidence[:2]:
                    lines.append(f"      > {ev[:120]}")
                if f.recommendation:
                    lines.append(f"      → {f.recommendation}")
        else:
            lines.append("  No significant findings.")

    if report.error:
        lines.append(f"\nERROR: {report.error}")

    lines.append("=" * 60)
    return "\n".join(lines)


def format_gchat_card(report: InvestigationReport) -> dict:
    """
    Return a GChat Cards v2 payload.
    https://developers.google.com/chat/api/reference/rest/v1/cards
    """
    sev_icon = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🔵",
        "UNKNOWN": "⚪",
    }.get(report.severity, "⚪")

    header_text = f"{sev_icon} {report.alert_title}"
    sub_text = f"Source: {report.alert_source} | Severity: {report.severity}"

    sections = []

    # Summary section
    sections.append(
        {
            "header": "Summary",
            "widgets": [
                {"textParagraph": {"text": report.summary}},
            ],
        }
    )

    # Likely causes
    if report.likely_causes:
        cause_text = "<br>".join(
            f"{i}. {c}" for i, c in enumerate(report.likely_causes, 1)
        )
        sections.append(
            {
                "header": "Likely Causes",
                "widgets": [{"textParagraph": {"text": cause_text}}],
            }
        )

    # Per-instance sections
    for inv in report.instances:
        status_icon = _STATUS_EMOJI.get(inv.overall_status, "❓")
        finding_lines = []
        for f in inv.findings[:8]:
            icon = _SEV_EMOJI.get(f.severity, "❓")
            finding_lines.append(f"{icon} <b>[{f.category.upper()}]</b> {f.message}")

        inst_text = (
            f"<b>{inv.instance_id}</b> {status_icon}<br>"
            f"Type: {inv.instance_type or 'unknown'} | "
            f"AZ: {inv.availability_zone or 'unknown'} | "
            f"State: {inv.instance_state or 'unknown'}<br>"
            f"IP: {inv.private_ip or 'N/A'} | SSM: {inv.ssm_managed}<br>"
        )
        if finding_lines:
            inst_text += "<br>".join(finding_lines)
        else:
            inst_text += "No significant findings."

        sections.append(
            {
                "header": f"Instance: {inv.instance_id}",
                "widgets": [{"textParagraph": {"text": inst_text}}],
            }
        )

    return {
        "cardsV2": [
            {
                "cardId": f"ec2-report-{report.alert_id}",
                "card": {
                    "header": {
                        "title": header_text,
                        "subtitle": sub_text,
                    },
                    "sections": sections,
                },
            }
        ]
    }


def format_json_payload(report: InvestigationReport) -> dict:
    """Return the report as a plain dict (for generic webhooks)."""
    return report.model_dump(mode="json")
