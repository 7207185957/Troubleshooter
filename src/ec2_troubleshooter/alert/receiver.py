"""
Alert Receiver – FastAPI application.

Alert intake flow
─────────────────
  POST /alert
      │
      ▼
  AlertNormalizer  (parse + classify contributors)
      │
      ▼
  AlertQueueManager.enqueue(alert)   ← bounded asyncio.Queue
      │                              ← returns HTTP 429 if full
      ▼
  Worker pool (ALERT_QUEUE_WORKERS concurrent coroutines)
      │
      ▼
  InvestigationOrchestrator.investigate(alert)
      │
      ▼
  Reporter.send(report)

POST /alert/sync  – investigates inline and returns the full report.
                    Useful for testing and CI.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Annotated, Any

import structlog
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

from ec2_troubleshooter.config import Settings, get_settings
from ec2_troubleshooter.orchestrator import InvestigationOrchestrator
from ec2_troubleshooter.reporter import build_reporter
from ec2_troubleshooter.tools import EC2ToolServer

from .normalizer import AlertNormalizer
from .queue import AlertQueueManager

log = structlog.get_logger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    cfg = settings or get_settings()

    tool_server = EC2ToolServer(cfg)
    orchestrator = InvestigationOrchestrator(tool_server, cfg)
    reporter = build_reporter(cfg)
    normalizer = AlertNormalizer()

    queue_manager = AlertQueueManager(
        max_size=cfg.alert_queue_max_size,
        workers=cfg.alert_queue_workers,
        retry_attempts=cfg.alert_queue_retry_attempts,
        orchestrator=orchestrator,
        reporter=reporter,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):  # type: ignore[misc]
        await queue_manager.start()
        log.info(
            "ec2_troubleshooter.started",
            reporter=cfg.reporter_type,
            queue_workers=cfg.alert_queue_workers,
            queue_max_size=cfg.alert_queue_max_size,
            infra_org=cfg.infra_org_id(),
            app_orgs=cfg.prometheus_app_org_ids,
        )
        yield
        await queue_manager.stop()
        log.info("ec2_troubleshooter.stopped")

    app = FastAPI(
        title="EC2 Troubleshooter",
        description=(
            "Generic, read-only EC2 diagnostic agent. "
            "Receives anomaly alerts, investigates affected EC2 instances via "
            "EC2 APIs, Prometheus/Mimir (multi-tenant), and SSM."
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

    @app.get("/queue/stats", tags=["ops"])
    async def queue_stats(_auth: None = auth_dep) -> dict[str, Any]:
        """Return current alert queue depth and worker statistics."""
        s = queue_manager.stats()
        return {
            "depth": s.depth,
            "workers_active": s.workers_active,
            "total_enqueued": s.total_enqueued,
            "total_processed": s.total_processed,
            "total_failed": s.total_failed,
            "total_retried": s.total_retried,
        }

    @app.get("/tools", tags=["ops"])
    async def list_tools(_auth: None = auth_dep) -> dict[str, list[str]]:
        """List all allowlisted diagnostic tools."""
        return {"tools": tool_server.list_tools()}

    @app.post("/alert", tags=["alert"], status_code=status.HTTP_202_ACCEPTED)
    async def receive_alert(
        request: Request,
        source: str = "generic",
        _auth: None = auth_dep,
    ) -> dict[str, Any]:
        """
        Accept an anomaly alert and enqueue it for async investigation.

        Returns HTTP 202 when enqueued, HTTP 429 when the queue is full.

        Query parameter ``source`` hints at the payload format:
        ``generic`` (default), ``aiops_archetype``, ``cloudwatch_alarm``,
        or ``datadog``.  Auto-detection is attempted when not specified.
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
            source=alert.source,
            archetype=alert.archetype,
            instance_ids=alert.instance_ids,
            instance_names=alert.instance_names,
        )

        accepted = queue_manager.enqueue(alert)
        if not accepted:
            stats = queue_manager.stats()
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Alert queue is full (depth={stats.depth}). "
                    "Retry after some investigations complete."
                ),
            )

        return {
            "alert_id": alert.alert_id,
            "status": "accepted",
            "queue_depth": queue_manager.stats().depth,
        }

    @app.post("/alert/sync", tags=["alert"])
    async def receive_alert_sync(
        request: Request,
        source: str = "generic",
        _auth: None = auth_dep,
    ) -> JSONResponse:
        """
        Synchronous variant — investigates inline and returns the full report.
        Useful for testing and one-off investigations.
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
