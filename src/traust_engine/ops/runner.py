"""A claim-once runner (design D7): lease one queued order of an asset the pack runs as a
command, run that command with the order's params, keep the lease alive, complete the order.
A skill session is a command too: its `run` starts the session, and `{role}` is its model role.
A repository's orders wait for the runner whose lease holds it, so the repository's mirror is
fetched once per node."""

from __future__ import annotations

import contextlib
import logging
import os
import re
import signal
import subprocess
import threading
from collections.abc import Callable, Collection, Mapping, Sequence
from contextvars import copy_context
from datetime import timedelta
from time import perf_counter
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

from traust_engine.ops.completion import complete
from traust_engine.ops.events import execution_scope, lifecycle
from traust_engine.ops.pack import AGENT_LABEL, AssetSpec, Pack

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
    return JobResult.failed(CRASHED)


def runnable(
    pack: Pack, labels: Collection[str] = (), assets: Collection[AssetName] | None = None
) -> tuple[AssetName, ...]:
    """The assets this runner makes: enabled, with a command, and not routed to another
    executor by its runner labels. An `llm`-labeled asset is a skill session — a runner
    pool's unit of work (its image carries the agent harness); this engine's image has
    no agent CLI, so claiming one would only crash it. A host that does carry the
    harness (the local rig, an operator workstation with the agent CLI logged in)
    passes the label to include those assets. Unlabeled assets stay claimable: the
    label vocabulary is a proposal, and a pack yet to carry it names no executor this
    runner refuses to be. `assets` names the only ones to make — a worker pool split
    by asset (`claim --asset`); None makes every asset the labels allow, and the two
    compose: a named `llm` asset still needs its label to be claimable."""
    included = set(labels)
    chosen = None if assets is None else set(assets)
    return tuple(
        name
        for name, spec in pack.assets.items()
        if spec.enabled
        and spec.run
        and (AGENT_LABEL not in spec.runner.labels or AGENT_LABEL in included)
        and (chosen is None or name in chosen)
    )


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
        run: Callable[[list[str], threading.Event], subprocess.CompletedProcess[str]] | None = None,
        labels: Collection[str] = (),
        assets: Collection[AssetName] | None = None,
    ) -> None:
        self._services = services
        self._pack = pack
        self._worker = worker
        self._lease_for = lease_for
        self._hosts = tuple(hosts)
        self._run = run or _run
        self._labels = tuple(labels)
        self._assets = None if assets is None else frozenset(assets)

    def claim_once(self) -> RunOrder | None:
        """Run one queued order to completion; None when no eligible order can be leased."""
        started = perf_counter()
        order = self._lease()
        if order is None:
            lifecycle(log, "lease", "empty", started=started, level=logging.INFO, count=0)
            return None
        assert order.id is not None
        with execution_scope(order.id):
            return self._execute(order, started)

    def _execute(self, order: RunOrder, started: float) -> RunOrder:
        assert order.id is not None
        lifecycle(log, "lease", "claimed", started=started, level=logging.INFO, count=1)
        spec = self._pack.assets.get(AssetName(order.asset))
        if spec is None:
            return self._finish(order, JobResult.failed(NOT_IN_PACK), started)
        try:
            command = argv(spec, self._values(order, spec))
        except (UnresolvedParam, ValueError, TraustError) as error:
            return self._finish(
                order,
                JobResult.failed(BAD_REQUEST),
                started,
                error_type=type(error).__name__,
            )
        except Exception as error:
            lifecycle(
                log,
                "execution",
                "failed",
                started=started,
                reason="command_error",
                error_type=type(error).__name__,
            )
            raise
        stop = threading.Event()
        lost = threading.Event()
        context = copy_context()
        beat = threading.Thread(
            target=context.run,
            args=(self._heartbeat, order.id, order.lease_generation, stop, lost),
            daemon=True,
        )
        beat.start()
        returncode = None
        error_type = None
        try:
            done = self._run(command, lost)  # a lost lease stops the command
            returncode = done.returncode
            result = outcome(done)
        except OSError as error:
            error_type = type(error).__name__
            result = JobResult.failed(CRASHED)
        except Exception as error:
            lifecycle(
                log,
                "execution",
                "failed",
                started=started,
                reason="command_error",
                error_type=type(error).__name__,
            )
            raise
        finally:
            stop.set()
            beat.join()
        if lost.is_set():
            lifecycle(
                log,
                "execution",
                "lease_lost",
                started=started,
                reason="lease_conflict",
                returncode=returncode,
            )
            return order
        return self._finish(
            order,
            result,
            started,
            returncode=returncode,
            error_type=error_type,
        )

    def _finish(
        self,
        order: RunOrder,
        result: JobResult,
        started: float,
        *,
        returncode: int | None = None,
        error_type: str | None = None,
    ) -> RunOrder:
        try:
            return complete(
                self._services.ops,
                log,
                order,
                self._worker,
                result,
                started,
                returncode=returncode,
                error_type=error_type,
            )
        except ConflictError as error:
            lifecycle(
                log,
                "completion",
                "lease_lost",
                started=started,
                reason="lease_conflict",
                error_type=type(error).__name__,
                returncode=returncode,
            )
            return order

    def _lease(self) -> RunOrder | None:
        """Lease the next queued order of an asset this runner makes, most important first.

        The claim is core's own bounded query (`LIMIT 1 ... FOR UPDATE SKIP LOCKED` over
        the queue head) carrying the mirror-affinity exclusion: a repository another
        runner holds — its order is in flight, so its node already fetched the
        repository's mirror — keeps this runner off that repository's orders whatever
        asset holds it (they wait for the holder), and a pair an open non-queued order
        occupies (an order at its budget gate, planned) waits with it, so the runner is
        handed the first order it can actually take. One SQL statement answers what the
        pre-walk once read every open order to decide — at production's 7,300 open
        orders, ~10⁸ row-materializations a day — and the claim sweeps expired leases
        in the same transaction, so the runner needs no separate sweep. An order
        another runner completes mid-claim cannot be re-created either: the claim
        leases a queued row or answers none, never `start`ing a fresh one for a pair."""
        assets = set(runnable(self._pack, self._labels, self._assets))
        return self._services.ops.claim(self._worker, self._lease_for, assets, mirror_affinity=True)

    def _values(self, order: RunOrder, spec: AssetSpec) -> dict[str, str]:
        """What the order supplies: its id, the asset's model role, the rule that routed it, and
        its repository's URL for a per-repository asset. NEED(model: order params): typed params
        beyond the repository have no column yet."""
        values = {
            "run_id": str(order.id),
            "lease_generation": str(order.lease_generation),
            "worker": str(self._worker),
        }
        if spec.model is not None:
            values["role"] = spec.model.role
        if order.rule is not None:
            values["rule"] = order.rule
        if order.repository_id is not None:
            url = self._services.portfolio.get_repository(order.repository_id).url
            values["repo_url"] = str(HttpsRepoUrl.parse(url, self._hosts))
        return values

    def _heartbeat(
        self, order_id: UUID, lease_generation: int, stop: threading.Event, lost: threading.Event
    ) -> None:
        while not stop.wait(self._lease_for.total_seconds() / 3):
            started = perf_counter()
            try:
                self._services.ops.heartbeat(
                    order_id, self._worker, self._lease_for, lease_generation=lease_generation
                )
            except ConflictError as error:
                lost.set()
                lifecycle(
                    log,
                    "heartbeat",
                    "lease_lost",
                    started=started,
                    reason="lease_conflict",
                    error_type=type(error).__name__,
                )
                return
            except Exception as error:
                # a failed renewal is transient: only a lost lease stops renewal, or the
                # lease lapses while the command runs and the order is re-run
                lifecycle(
                    log,
                    "heartbeat",
                    "failed",
                    started=started,
                    reason="heartbeat_error",
                    error_type=type(error).__name__,
                )


# How long a command whose lease was lost gets to exit on SIGTERM before SIGKILL.
STOP_GRACE = timedelta(seconds=10)
_POLL = 0.5  # seconds between checks of the lost-lease flag while a command runs


def _run(command: list[str], cancel: threading.Event) -> subprocess.CompletedProcess[str]:
    """Run the command to completion, unless `cancel` is set first: a lost lease means Core has
    handed the order to a new claim, and Core fences only writes carrying the old generation.
    Effects outside Core (forge pushes, pull requests, model spend) are not fenced, so the
    command and everything it started (its own process group) get SIGTERM, then SIGKILL after
    STOP_GRACE."""
    with subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    ) as process:
        while True:
            try:
                stdout, stderr = process.communicate(timeout=_POLL)
                break
            except subprocess.TimeoutExpired:
                if not cancel.is_set():
                    continue
            _signal_group(process, signal.SIGTERM)
            try:
                stdout, stderr = process.communicate(timeout=STOP_GRACE.total_seconds())
            except subprocess.TimeoutExpired:
                _signal_group(process, signal.SIGKILL)
                stdout, stderr = process.communicate()
            break
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _signal_group(process: subprocess.Popen[str], sig: signal.Signals) -> None:
    with contextlib.suppress(ProcessLookupError):  # already gone
        os.killpg(process.pid, sig)
