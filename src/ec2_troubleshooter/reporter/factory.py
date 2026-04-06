"""Reporter factory – build the right reporter based on settings."""

from __future__ import annotations

from ec2_troubleshooter.config import Settings

from .base import BaseReporter
from .gchat import GChatReporter
from .log_reporter import LogReporter
from .webhook import WebhookReporter


def build_reporter(settings: Settings) -> BaseReporter:
    if settings.reporter_type == "gchat":
        return GChatReporter(webhook_url=settings.reporter_gchat_webhook_url)  # type: ignore[arg-type]
    if settings.reporter_type == "webhook":
        return WebhookReporter(
            webhook_url=settings.reporter_webhook_url,  # type: ignore[arg-type]
            extra_headers=settings.reporter_webhook_headers or None,
        )
    return LogReporter()
