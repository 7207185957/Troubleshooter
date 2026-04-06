"""GChat reporter – sends findings as a Card v2 message to a GChat webhook."""

from __future__ import annotations

import httpx
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

from ec2_troubleshooter.models.findings import InvestigationReport

from .base import BaseReporter
from .formatter import format_gchat_card

log = structlog.get_logger(__name__)


class GChatReporter(BaseReporter):
    """
    Sends the investigation report to a Google Chat space via an incoming
    webhook URL.

    The webhook URL must be reachable from the agent's EC2 instance.  In fully
    air-gapped environments where Google Chat is blocked, use the
    WebhookReporter or LogReporter instead and route findings via an internal
    system.
    """

    def __init__(self, webhook_url: str) -> None:
        self._webhook_url = webhook_url

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    def send(self, report: InvestigationReport) -> None:
        payload = format_gchat_card(report)
        log.info("gchat.send", alert_id=report.alert_id)
        try:
            with httpx.Client(timeout=15) as client:
                resp = client.post(self._webhook_url, json=payload)
                resp.raise_for_status()
            log.info("gchat.sent", alert_id=report.alert_id, status=resp.status_code)
        except httpx.HTTPError as exc:
            log.error("gchat.send_failed", alert_id=report.alert_id, error=str(exc))
            raise
