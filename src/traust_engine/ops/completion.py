"""Shared order completion and its bounded terminal execution event."""

from __future__ import annotations

import logging
from uuid import UUID

from traust_core.v1.context import OpsService
from traust_core.v1.models.operations import JobResult, OrderState, RunOrder, WorkerId

from traust_engine.ops.events import lifecycle


def complete(
    ops: OpsService,
    logger: logging.Logger,
    order_id: UUID,
    worker: WorkerId,
    result: JobResult,
    started: float,
    *,
    returncode: int | None = None,
    error_type: str | None = None,
) -> RunOrder:
    """Complete once, preserving the caller's logger, correlation and exception behavior."""
    try:
        completed = ops.complete(order_id, worker, result)
    except Exception as error:
        lifecycle(
            logger,
            "execution",
            "failed",
            started=started,
            reason="completion_error",
            returncode=returncode,
            error_type=type(error).__name__,
        )
        raise
    state = str(completed.state)
    lifecycle(
        logger,
        "execution",
        state,
        started=started,
        level=logging.INFO if completed.state is OrderState.SUCCEEDED else logging.WARNING,
        reason=str(result.reason) if result.reason is not None else None,
        status=state,
        returncode=returncode,
        error_type=error_type,
    )
    return completed
