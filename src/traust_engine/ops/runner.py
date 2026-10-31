"""A claim-once runner (design D7): lease one queued order of an asset the pack runs as a
command, run that command with the order's params, keep the lease alive, complete the order.
A skill session is a command too: its `run` starts the session, and `{role}` is its model role."""

from __future__ import annotations

import logging
import re
import subprocess
import threading
from collections.abc import Callable, Mapping, Sequence
from datetime import timedelta
from uuid import UUID

from pydantic import ValidationError
from traust_core.v1.context.context import Services
from traust_core.v1.errors import ConflictError, TraustError
from traust_core.v1.models.operations import (
    AssetName,
    JobResult,
    OrderReason,
    RunOrder,
    WorkerId,
)
from traust_core.v1.models.values import HttpsRepoUrl

from traust_engine.ops.pack import AssetSpec, Pack

log = logging.getLogger(__name__)

# A whole argv token that names a param; text around a placeholder is never substituted.
_PLACEHOLDER = re.compile(r"^\{([a-z][a-z0-9_]*)\}$")
# Registered run-order reasons (contracts run-order-reason); the detail goes to the log.
NOT_IN_PACK = OrderReason.ASSET_NOT_IN_PACK
BAD_REQUEST = OrderReason.BAD_REQUEST
CRASHED = OrderReason.RUNNER_CRASHED
# PENDING(D7): claim-once, started by an operator or a scheduler, never a daemon (plan 01 row 3).


def outcome(done: subprocess.CompletedProcess[str]) -> JobResult:
    """A command whose last line is a JobResult (a materializer's door) is recorded as it
    answered; any other by its exit code (0 succeeded, anything else failed)."""
    lines = done.stdout.strip().splitlines()
    try:
        return JobResult.model_validate_json(lines[-1]) if lines else _by_exit(done)
    except ValidationError:
        return _by_exit(done)


def _by_exit(done: subprocess.CompletedProcess[str]) -> JobResult:
    """A command that didn't answer with a JobResult: 0 succeeded, anything else crashed."""
    if done.returncode == 0:
        return JobResult.succeeded()
    log.warning("%s: %s: exit %s", done.args, CRASHED, done.returncode)
    return JobResult.failed(CRASHED)


def runnable(pack: Pack) -> tuple[AssetName, ...]:
    """The assets this runner makes: enabled, with a command; a model role without one has
    nothing to start its session with."""
    return tuple(name for name, spec in pack.assets.items() if spec.enabled and spec.run)


class UnresolvedParam(TraustError):
    """A command names a param the order can't supply."""


def argv(spec: AssetSpec, values: Mapping[str, str]) -> list[str]:
    """The asset's command with each `{param}` token replaced; never a shell string."""
    out = []
    for token in spec.run:
        m = _PLACEHOLDER.match(token)
        if m is None:
            out.append(token)
        elif m[1] in values:
            out.append(values[m[1]])
        else:
            raise UnresolvedParam(f"{m[1]}: no value for this order")
    return out


class Runner:
    def __init__(
        self,
        services: Services,
        pack: Pack,
        worker: WorkerId,
        lease_for: timedelta,
        hosts: Sequence[str],
        run: Callable[[list[str]], subprocess.CompletedProcess[str]] | None = None,
    ) -> None:
        self._services = services
        self._pack = pack
        self._worker = worker
        self._lease_for = lease_for
        self._hosts = tuple(hosts)
        self._run = run or _run

    def claim_once(self) -> RunOrder | None:
        """Run one queued order to completion; None when nothing this runner makes is queued."""
        ops = self._services.ops
        order = ops.claim(self._worker, self._lease_for, runnable(self._pack))
        if order is None:
            return None
        assert order.id is not None
        spec = self._pack.assets.get(AssetName(order.asset))
        if spec is None:
            return ops.complete(order.id, self._worker, JobResult.failed(NOT_IN_PACK))
        try:
            command = argv(spec, self._values(order, spec))
        except (UnresolvedParam, ValueError, TraustError) as e:
            log.warning("order %s: %s: %s", order.id, BAD_REQUEST, e)
            return ops.complete(order.id, self._worker, JobResult.failed(BAD_REQUEST))
        log.info("order %s: running %s", order.id, order.asset)
        stop = threading.Event()
        beat = threading.Thread(target=self._heartbeat, args=(order.id, stop), daemon=True)
        beat.start()
        try:
            done = self._run(command)
            result = outcome(done)
        except OSError as e:
            log.warning("order %s: %s: %s", order.id, CRASHED, e)
            result = JobResult.failed(CRASHED)
        finally:
            stop.set()
            beat.join()
        return ops.complete(order.id, self._worker, result)

    def _values(self, order: RunOrder, spec: AssetSpec) -> dict[str, str]:
        """What the order supplies: its id, the asset's model role, the rule that routed it, and
        its repository's URL for a per-repository asset. NEED(model: order params): typed params
        beyond the repository have no column yet."""
        values = {"run_id": str(order.id), "worker": str(self._worker)}
        if spec.model is not None:
            values["role"] = spec.model.role
        if order.rule is not None:
            values["rule"] = order.rule
        if order.repository_id is not None:
            url = self._services.portfolio.get_repository(order.repository_id).url
            values["repo_url"] = str(HttpsRepoUrl.parse(url, self._hosts))
        return values

    def _heartbeat(self, order_id: UUID, stop: threading.Event) -> None:
        while not stop.wait(self._lease_for.total_seconds() / 3):
            try:
                self._services.ops.heartbeat(order_id, self._worker, self._lease_for)
            except ConflictError as e:
                log.warning("order %s: lease lost: %s", order_id, e)
                return


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False)
