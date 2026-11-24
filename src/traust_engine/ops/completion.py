"""Shared order completion and its bounded terminal execution event."""

from __future__ import annotations

import logging

from traust_core.v1.context import OpsService
from traust_core.v1.errors import ConflictError
from traust_core.v1.models.operations import JobResult, OrderState, RunOrder, WorkerId

from traust_engine.ops.events import lifecycle


def complete(
    ops: OpsService,
    logger: logging.Logger,
    order: RunOrder,
    worker: WorkerId,
    result: JobResult,
    started: float,
    *,
    returncode: int | None = None,
    error_type: str | None = None,
) -> RunOrder:
    """Complete once, preserving the caller's logger, correlation and exception behavior."""
    assert order.id is not None
    try:
        completed = ops.complete(order.id, worker, result, lease_generation=order.lease_generation)
    except ConflictError:
        # Caller logs lost leases as lease_lost; never inflate completion_error.
        raise
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
