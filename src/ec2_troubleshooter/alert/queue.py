"""
Alert queue — async, bounded, multi-worker.

Architecture
────────────
                  HTTP /alert
                      │
                      ▼
              AlertQueueManager.enqueue(alert)
                      │
           asyncio.Queue (bounded, max_size configurable)
                      │
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
    Worker-1      Worker-2      Worker-N      (ALERT_QUEUE_WORKERS)
        │             │             │
        └─────────────┼─────────────┘
                      ▼
           orchestrator.investigate(alert)
                      ▼
              reporter.send(report)

Properties
──────────
- Bounded queue prevents memory runaway when alerts spike (returns HTTP 429)
- Multiple concurrent workers so a slow investigation (long SSM command)
  doesn't block other alerts
- Per-item retry: failed investigations are re-queued up to
  ALERT_QUEUE_RETRY_ATTEMPTS times before being discarded
- Graceful shutdown: workers drain the queue before stopping
- Queue depth metric exposed on GET /queue/stats
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

from ec2_troubleshooter.models.alert import Alert
from ec2_troubleshooter.models.findings import InvestigationReport

log = structlog.get_logger(__name__)


@dataclass
class QueuedAlert:
    alert: Alert
    enqueued_at: float = field(default_factory=time.monotonic)
    attempt: int = 0


@dataclass
class QueueStats:
    depth: int
    workers_active: int
    total_enqueued: int
    total_processed: int
    total_failed: int
    total_retried: int


class AlertQueueManager:
    """
    Manages an async bounded queue and a pool of worker coroutines that
    consume alerts and run investigations.

    Lifecycle::

        manager = AlertQueueManager(settings, orchestrator, reporter)
        await manager.start()          # spawns worker tasks
        manager.enqueue(alert)         # called from HTTP handler
        await manager.stop()           # graceful drain + shutdown
    """

    def __init__(
        self,
        max_size: int,
        workers: int,
        retry_attempts: int,
        orchestrator: Any,
        reporter: Any,
    ) -> None:
        self._max_size = max_size
        self._num_workers = workers
        self._retry_attempts = retry_attempts
        self._orchestrator = orchestrator
        self._reporter = reporter

        self._queue: asyncio.Queue[QueuedAlert] = asyncio.Queue(maxsize=max_size)
        self._worker_tasks: list[asyncio.Task] = []
        self._active_count = 0

        # Counters
        self._total_enqueued = 0
        self._total_processed = 0
        self._total_failed = 0
        self._total_retried = 0

    # ── Lifecycle ──────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Spawn worker coroutines."""
        for i in range(self._num_workers):
            task = asyncio.create_task(
                self._worker(worker_id=i), name=f"alert-worker-{i}"
            )
            self._worker_tasks.append(task)
        log.info("alert_queue.started", workers=self._num_workers, max_size=self._max_size)

    async def stop(self) -> None:
        """
        Signal workers to stop and wait for the queue to drain.
        Each worker receives a sentinel ``None`` value.
        """
        log.info("alert_queue.stopping", depth=self._queue.qsize())
        for _ in self._worker_tasks:
            await self._queue.put(None)  # type: ignore[arg-type]
        await asyncio.gather(*self._worker_tasks, return_exceptions=True)
        self._worker_tasks.clear()
        log.info("alert_queue.stopped")

    # ── Public methods ────────────────────────────────────────────────────

    def enqueue(self, alert: Alert) -> bool:
        """
        Add *alert* to the queue.  Returns True on success, False if the
        queue is full (caller should return HTTP 429).
        """
        try:
            self._queue.put_nowait(QueuedAlert(alert=alert))
            self._total_enqueued += 1
            log.info(
                "alert_queue.enqueued",
                alert_id=alert.alert_id,
                depth=self._queue.qsize(),
            )
            return True
        except asyncio.QueueFull:
            log.warning(
                "alert_queue.full – alert dropped",
                alert_id=alert.alert_id,
                depth=self._queue.qsize(),
            )
            return False

    def stats(self) -> QueueStats:
        return QueueStats(
            depth=self._queue.qsize(),
            workers_active=self._active_count,
            total_enqueued=self._total_enqueued,
            total_processed=self._total_processed,
            total_failed=self._total_failed,
            total_retried=self._total_retried,
        )

    # ── Worker ─────────────────────────────────────────────────────────────

    async def _worker(self, worker_id: int) -> None:
        log.debug("alert_worker.started", worker_id=worker_id)
        while True:
            item = await self._queue.get()
            if item is None:                # shutdown sentinel
                self._queue.task_done()
                break
            self._active_count += 1
            try:
                await self._process(item, worker_id)
            finally:
                self._active_count -= 1
                self._queue.task_done()
        log.debug("alert_worker.stopped", worker_id=worker_id)

    async def _process(self, item: QueuedAlert, worker_id: int) -> None:
        alert = item.alert
        wait_ms = (time.monotonic() - item.enqueued_at) * 1000
        log.info(
            "alert_worker.processing",
            worker_id=worker_id,
            alert_id=alert.alert_id,
            attempt=item.attempt + 1,
            queue_wait_ms=round(wait_ms),
        )
        try:
            # Run the blocking investigation in the default thread pool so
            # we don't block the event loop
            report: InvestigationReport = await asyncio.get_event_loop().run_in_executor(
                None, self._orchestrator.investigate, alert
            )
            await asyncio.get_event_loop().run_in_executor(
                None, self._reporter.send, report
            )
            self._total_processed += 1
            log.info(
                "alert_worker.done",
                worker_id=worker_id,
                alert_id=alert.alert_id,
                instances=len(report.instances),
                likely_causes=len(report.likely_causes),
            )
        except Exception as exc:
            log.error(
                "alert_worker.error",
                worker_id=worker_id,
                alert_id=alert.alert_id,
                attempt=item.attempt + 1,
                error=str(exc),
                exc_info=True,
            )
            if item.attempt < self._retry_attempts:
                retry_item = QueuedAlert(
                    alert=alert,
                    attempt=item.attempt + 1,
                )
                try:
                    self._queue.put_nowait(retry_item)
                    self._total_retried += 1
                    log.info(
                        "alert_worker.retry_queued",
                        alert_id=alert.alert_id,
                        attempt=retry_item.attempt,
                    )
                except asyncio.QueueFull:
                    log.warning(
                        "alert_worker.retry_dropped – queue full",
                        alert_id=alert.alert_id,
                    )
                    self._total_failed += 1
            else:
                self._total_failed += 1
                log.error(
                    "alert_worker.exhausted_retries",
                    alert_id=alert.alert_id,
                    attempts=item.attempt + 1,
                )
