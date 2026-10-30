"""Bounded operational lifecycle events for the engine executable."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from time import perf_counter
from uuid import UUID

from traust_core.v1.context import correlation_scope, current_correlation


@contextmanager
def execution_scope(order_id: UUID) -> Iterator[None]:
    """Add order/run IDs for one execution, then restore the caller's scope."""
    current = current_correlation()
    if current is None:
        yield
        return
    with correlation_scope(
        current.request_id,
        order_id=order_id,
        run_id=order_id,
        actor_kind=current.actor_kind,
    ):
        yield


def lifecycle(
    logger: logging.Logger,
    operation: str,
    outcome: str,
    *,
    started: float,
    level: int | None = None,
    reason: str | None = None,
    status: str | None = None,
    returncode: int | None = None,
    error_type: str | None = None,
    count: int | None = None,
) -> None:
    """Emit only bounded codes, counts and elapsed time."""
    duration_ms = (perf_counter() - started) * 1000
    selected_level = level or (
        logging.INFO if outcome in {"completed", "ready"} else logging.WARNING
    )
    logger.log(
        selected_level,
        "engine operation=%s outcome=%s reason=%s status=%s "
        "returncode=%s count=%s duration_ms=%.1f",
        operation,
        outcome,
        reason or "-",
        status or "-",
        returncode if returncode is not None else "-",
        count if count is not None else "-",
        duration_ms,
        extra={
            "operation": f"engine.{operation}",
            "outcome": outcome,
            "reason": reason,
            "status": status,
            "returncode": returncode,
            "error_type": error_type,
            "count": count,
            "duration_ms": duration_ms,
        },
    )
