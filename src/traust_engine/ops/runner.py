"""A claim-once runner (design D7): lease one queued order of an asset the pack runs as a
command, run that command with the order's params, keep the lease alive, complete the order.
A skill session is a command too: its `run` starts the session, and `{role}` is its model role.
A repository's orders wait for the runner whose lease holds it, so the repository's mirror is
fetched once per node."""

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
from traust_core.v1.models.common import every_item
from traust_core.v1.models.operations import (
    OPEN_ORDER_STATES,
    AssetName,
    JobResult,
    LaneName,
    OrderFilter,
    OrderReason,
    OrderRequest,
    OrderState,
    RunOrder,
    WorkerId,
)
from traust_core.v1.models.values import HttpsRepoUrl

from traust_engine.ops.controller import ENGINE
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
    """The assets this runner makes: those with a command; a model role without one has nothing
    to start its session with."""
    return tuple(name for name, spec in pack.assets.items() if spec.run)


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
        """Run one queued order to completion; None when nothing this runner makes is queued, or
        every queued order belongs to a repository another runner holds."""
        order = self._lease()
        if order is None:
            return None
        assert order.id is not None
        ops = self._services.ops
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

    def _lease(self) -> RunOrder | None:
        """Lease the next queued order of an asset this runner makes, most important first. A
        repository another runner holds — its order is in flight, so its node already fetched
        the repository's mirror — keeps this runner off that repository's other orders: they
        wait for the holder, and the runner takes other work instead.

        NEED(core: mirror affinity): a hold lasts only while the holder's order is leased —
        nothing records it between orders — and the claim API filters by asset, not repository,
        so when the next order waits for its repository's holder this picks a later order here
        and takes it over through core's `start`."""
        ops = self._services.ops
        ops.requeue_expired()  # a claim-once runner runs beside no loop: sweep, as `claim` did
        assets = set(runnable(self._pack))
        every_open = list(every_item(lambda p: ops.list(OrderFilter(states=OPEN_ORDER_STATES), p)))
        open_orders = [order for order in every_open if order.asset in assets]
        queued = sorted(
            (o for o in open_orders if o.state == OrderState.QUEUED),
            key=lambda o: (o.priority, o.created_at, o.id),
        )
        if not queued:
            return None
        # every open order counts, whatever pack or asset it belongs to: a repository held
        # by another runner's order is held, not just one this runner could also make
        held = {
            o.repository_id
            for o in every_open
            if o.state == OrderState.LEASED
            and o.repository_id is not None
            and o.lease_holder != self._worker
        }
        if queued[0].repository_id not in held:
            return ops.claim(self._worker, self._lease_for, assets)
        # `start` leases a pair's open order, whatever its state, so only a pair with no other
        # open order can be taken over without leasing a planned or already-leased one.
        busy = {(o.asset, o.repository_id) for o in open_orders if o.state != OrderState.QUEUED}
        for order in queued:
            if order.repository_id not in held and (order.asset, order.repository_id) not in busy:
                taken = self._take(order)
                if taken is not None:
                    return taken
        return None

    def _take(self, order: RunOrder) -> RunOrder | None:
        """Lease this queued order; None when another runner leased it first."""
        request = OrderRequest(
            asset=AssetName(order.asset),
            priority=order.priority,
            repository_id=order.repository_id,
            run_batch_id=order.run_batch_id,
            lane=LaneName(order.lane) if order.lane is not None else None,
            rule=order.rule,
            event_source=order.event_source,
        )
        try:
            return self._services.ops.start(request, ENGINE, self._worker, self._lease_for)
        except ConflictError:
            return None

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
