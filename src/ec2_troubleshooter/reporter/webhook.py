"""Generic webhook reporter – posts the full JSON report to an HTTP endpoint."""

from __future__ import annotations

import httpx
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

from ec2_troubleshooter.models.findings import InvestigationReport

from .base import BaseReporter
from .formatter import format_json_payload

log = structlog.get_logger(__name__)


class WebhookReporter(BaseReporter):
    """
    POSTs the full investigation report as JSON to an arbitrary webhook URL.

    Useful for routing findings to ticketing systems (Jira, PagerDuty, etc.)
    or internal incident management UIs.  Extra headers (e.g. auth tokens) can
    be injected via the *extra_headers* constructor parameter.
    """

    def __init__(self, webhook_url: str, extra_headers: dict[str, str] | None = None) -> None:
        self._webhook_url = webhook_url
        self._headers = {"Content-Type": "application/json"}
        if extra_headers:
            self._headers.update(extra_headers)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        reraise=True,
    )
    def send(self, report: InvestigationReport) -> None:
        payload = format_json_payload(report)
        log.info("webhook.send", alert_id=report.alert_id, url=self._webhook_url)
        try:
            with httpx.Client(timeout=15) as client:
                resp = client.post(self._webhook_url, json=payload, headers=self._headers)
                resp.raise_for_status()
            log.info("webhook.sent", alert_id=report.alert_id, status=resp.status_code)
        except httpx.HTTPError as exc:
            log.error("webhook.send_failed", alert_id=report.alert_id, error=str(exc))
            raise
