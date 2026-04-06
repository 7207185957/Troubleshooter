"""
Alert Receiver – FastAPI application.

Exposes HTTP endpoints that accept inbound alert payloads, normalise them,
trigger the investigation orchestrator, and dispatch findings to the reporter.

Runs entirely inside the VPC (no public internet required) and is suitable
for deployment behind an internal ALB or as a standalone service on the
troubleshooter EC2 instance.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Annotated, Any  # Annotated used in verify_token header param

import structlog
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

from ec2_troubleshooter.config import Settings, get_settings
from ec2_troubleshooter.models.alert import Alert
from ec2_troubleshooter.orchestrator import InvestigationOrchestrator
from ec2_troubleshooter.reporter import build_reporter
from ec2_troubleshooter.tools import EC2ToolServer

from .normalizer import AlertNormalizer

log = structlog.get_logger(__name__)


# ── Application factory ────────────────────────────────────────────────────

def create_app(settings: Settings | None = None) -> FastAPI:
    cfg = settings or get_settings()

    tool_server = EC2ToolServer(cfg)
    orchestrator = InvestigationOrchestrator(tool_server)
    reporter = build_reporter(cfg)
    normalizer = AlertNormalizer()

    @asynccontextmanager
    async def lifespan(app: FastAPI):  # type: ignore[misc]
        log.info("ec2_troubleshooter.started", reporter=cfg.reporter_type)
        yield
        log.info("ec2_troubleshooter.stopped")

    app = FastAPI(
        title="EC2 Troubleshooter",
        description=(
            "Generic, read-only EC2 diagnostic agent. "
            "Receives anomaly alerts and investigates affected EC2 instances."
        ),
        version="0.1.0",
        lifespan=lifespan,
    )

    # ── Auth dependency ────────────────────────────────────────────────────

    def verify_token(
        authorization: Annotated[str | None, Header()] = None,
    ) -> None:
        if not cfg.api_secret_token:
            return
        expected = f"Bearer {cfg.api_secret_token}"
        if authorization != expected:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing Bearer token",
            )

    auth_dep = Depends(verify_token)

    # ── Routes ─────────────────────────────────────────────────────────────

    @app.get("/health", tags=["ops"])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/tools", tags=["ops"])
    async def list_tools(_auth: None = auth_dep) -> dict[str, list[str]]:
        """List all allowlisted diagnostic tools."""
        return {"tools": tool_server.list_tools()}

    @app.post("/alert", tags=["alert"], status_code=status.HTTP_202_ACCEPTED)
    async def receive_alert(
        request: Request,
        background_tasks: BackgroundTasks,
        source: str = "generic",
        _auth: None = auth_dep,
    ) -> dict[str, str]:
        """
        Accept an anomaly alert payload.

        The investigation is dispatched in the background so this endpoint
        returns immediately with HTTP 202.

        Query parameter ``source`` hints at the payload format:
        ``generic`` (default), ``cloudwatch_alarm``, or ``datadog``.
        """
        try:
            payload: dict[str, Any] = await request.json()
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Invalid JSON: {exc}") from exc

        try:
            alert = normalizer.normalize(payload, source_hint=source)
        except Exception as exc:
            raise HTTPException(
                status_code=422, detail=f"Failed to normalise alert: {exc}"
            ) from exc

        log.info(
            "alert.received",
            alert_id=alert.alert_id,
            source=source,
            instances=alert.instance_ids,
        )
        background_tasks.add_task(
            _investigate_and_report, alert, orchestrator, reporter
        )
        return {"alert_id": alert.alert_id, "status": "accepted"}

    @app.post("/alert/sync", tags=["alert"])
    async def receive_alert_sync(
        request: Request,
        source: str = "generic",
        _auth: None = auth_dep,
    ) -> JSONResponse:
        """
        Synchronous variant – investigates inline and returns the full report.
        Useful for testing and CI.
        """
        try:
            payload = await request.json()
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Invalid JSON: {exc}") from exc

        try:
            alert = normalizer.normalize(payload, source_hint=source)
        except Exception as exc:
            raise HTTPException(
                status_code=422, detail=f"Failed to normalise alert: {exc}"
            ) from exc

        report = await asyncio.get_event_loop().run_in_executor(
            None, orchestrator.investigate, alert
        )
        await asyncio.get_event_loop().run_in_executor(
            None, reporter.send, report
        )
        return JSONResponse(content=report.model_dump(mode="json"))

    return app


# ── Background task ────────────────────────────────────────────────────────

def _investigate_and_report(alert: Alert, orchestrator: InvestigationOrchestrator, reporter: Any) -> None:
    try:
        report = orchestrator.investigate(alert)
        reporter.send(report)
    except Exception as exc:
        log.error("background_investigation.failed", alert_id=alert.alert_id, error=str(exc))
