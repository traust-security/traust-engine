"""``traust-engine run|shadow|record|diff|claim``: the continuous-ops loop on a pack, the shadow run
beside cron (runs recorded as orders, the engine's would-be orders, the daily comparison), and a
claim-once runner for the pack's command assets."""

from __future__ import annotations

import argparse
import getpass
import importlib
import json
import logging
import os
import re
import socket
import sys
import time
import traceback
from collections.abc import Collection, Iterator, Sequence
from contextlib import ExitStack, contextmanager
from datetime import timedelta
from pathlib import Path
from time import perf_counter
from typing import Any
from uuid import uuid4

from traust_core.v1.context import Context, correlation_scope
from traust_core.v1.errors import ConfigError, NotFoundError, PreflightError, TraustError
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.operations import OrderRequest, OrderState, WorkerId
from traust_core.v1.models.vocabulary import ActorKind

from traust_engine.ops.events import lifecycle
from traust_engine.ops.loop import EngineLoop
from traust_engine.ops.pack import Pack
from traust_engine.ops.remediation import is_remediation_run
from traust_engine.ops.runner import Runner, runnable
from traust_engine.ops.shadow import (
    Diff,
    Tick,
    compare_routes,
    compare_runs,
    record,
    recorded_runs,
    repository_urls,
)

log = logging.getLogger(__name__)

_DURATION = re.compile(r"^([1-9]\d*)([mhd])$")
_UNITS = {"m": "minutes", "h": "hours", "d": "days"}
# Runs before the window say when the next falls due; eight days covers daily and weekly jobs.
LOOKBACK = timedelta(days=8)
_EXIT = {
    OrderState.SUCCEEDED: 0,
    OrderState.FAILED: 1,
    OrderState.DEGRADED: 4,
    OrderState.REFUSED: 5,
}


def _duration(value: str) -> timedelta:
    if not (m := _DURATION.match(value)):
        raise argparse.ArgumentTypeError(f"{value!r}: minutes, hours or days, e.g. 15m, 2h, 1d")
    return timedelta(**{_UNITS[m[2]]: int(m[1])})


def _router(spec: str) -> Any:
    """A pack's router by import path, `module:Class` (e.g. traust.ops.router:SecurityRouter)."""
    module, _, name = spec.partition(":")
    try:
        return getattr(importlib.import_module(module), name)()
    except (ImportError, AttributeError, ValueError) as e:
        raise ConfigError(f"router {spec}: {e}") from e


@contextmanager
def _loop(core: Context, pack: Pack, router: str | None) -> Iterator[EngineLoop]:
    with core.repository_observation() as observation:
        yield EngineLoop(
            core.services(),
            core.clock,
            pack,
            _router(router) if router else None,
            (lambda r: observation.query.repo_state(repository_id=r)) if router else None,
        )


def _request_id(operation: str) -> str:
    return f"engine-{operation}-{uuid4().hex}"


def _labels(names: Collection[str]) -> str:
    return "|".join(
        sorted(name if re.fullmatch(r"[a-z][a-z0-9_-]{0,39}", name) else "?" for name in names)[:5]
    )


def _passes(args: argparse.Namespace, core: Context, engine: EngineLoop[Any], shadow: bool) -> int:
    while True:
        with correlation_scope(_request_id("tick"), actor_kind=ActorKind.MACHINE):
            started = perf_counter()
            try:
                if shadow:
                    shadow_report = engine.shadow_once()
                    tick = shadow_report.tick
                    # Only the cadence work feeds the shadow comparison; the
                    # remediation trigger's orders are event-driven, not work
                    # cron was scheduled to run.
                    report = Tick(at=core.clock.now(), due=shadow_report.due)
                    status = (
                        f"shadow,due:{len(report.due)},"
                        f"remediation:{len(shadow_report.remediation)},"
                        f"planned:{tick.planned},"
                        f"routed:{tick.routed},unrouted:{tick.unrouted},"
                        f"refused:{tick.refused_again},stale:{sum(tick.stale.values())},"
                        f"overdue:{sum(tick.overdue.values())},"
                        f"unrunnable:{len(tick.unrunnable)}"
                    )
                    withheld = deferred = 0
                else:
                    report = engine.run_once()
                    tick = report.tick
                    withheld, deferred = report.admission.withheld, report.admission.deferred
                    status = (
                        f"planned:{tick.planned},routed:{tick.routed},"
                        f"unrouted:{tick.unrouted},refused:{tick.refused_again},"
                        f"stale:{sum(tick.stale.values())},"
                        f"overdue:{sum(tick.overdue.values())},"
                        f"unrunnable:{len(tick.unrunnable)},"
                        f"admitted:{report.admission.admitted},"
                        f"approval:{report.admission.awaiting_approval},"
                        f"withheld:{withheld},"
                        f"deferred:{deferred},requeued:{report.requeued}"
                    )
                for label, names in (
                    ("stale", tick.stale),
                    ("overdue", tick.overdue),
                    ("unrunnable", tick.unrunnable),
                ):
                    if names:
                        status += f",{label}_assets:{_labels(names)}"
                print(report.model_dump_json(), flush=True)
                unhealthy = bool(
                    tick.stale or tick.overdue or tick.unrunnable or withheld or deferred
                )
                lifecycle(
                    log,
                    "tick",
                    "completed",
                    started=started,
                    status=status,
                    level=logging.WARNING if unhealthy else logging.INFO,
                )
            except Exception as error:
                _debug_failure(error)
                lifecycle(
                    log,
                    "tick",
                    "failed",
                    started=started,
                    reason="tick_error",
                    error_type=type(error).__name__,
                )
                raise
        if args.once:
            return 0
        time.sleep(args.every.total_seconds())


def _record(args: argparse.Namespace, core: Context, pack: Pack) -> int:
    spec = pack.assets.get(args.asset)
    if spec is None:
        raise NotFoundError(f"pack {pack.pack} has no asset {args.asset}")
    if not args.command or bool(spec.partitions) != bool(args.repo):
        raise ConfigError("give the command after --, and --repo exactly when the asset has one")
    services = core.services()
    repository_id = None
    if args.repo:
        found = services.portfolio.find_repository(args.repo)
        if found is None:
            raise NotFoundError(f"{args.repo} is not in the inventory")
        repository_id = found.id
    host = socket.gethostname()
    order, done = record(
        services,
        OrderRequest(asset=args.asset, priority=spec.priority, repository_id=repository_id),
        Principal(
            identity=f"record:{getpass.getuser()}@{host}",
            kind=ActorKind.MACHINE,
            display=f"a run on {host}",
        ),
        WorkerId(f"{host}:{os.getpid()}"),
        args.command,
    )
    sys.stdout.write(done.stdout)
    sys.stderr.write(done.stderr)
    print(f"order {order.id}: {order.state}", file=sys.stderr)
    return done.returncode


def _diff(args: argparse.Namespace, core: Context, pack: Pack) -> int:
    services = core.services()
    until = core.clock.now()
    since = until - args.window
    lines = args.shadow.read_text(encoding="utf-8").splitlines()
    ticks = [t for t in (Tick.model_validate_json(x) for x in lines if x.strip()) if t.at >= since]
    cadence = {name: a.trigger.every for name, a in pack.assets.items() if a.trigger.every}
    runs = list(recorded_runs(services, since - LOOKBACK))
    # Remediation work — the trigger's rule-bearing orders, and the door's
    # work-item orders — is event-driven, never work the cadence due lists
    # asked for; comparing it would classify every such run as early.
    runs = [run for run in runs if not is_remediation_run(run)]
    matched, missed, early = compare_runs(ticks, runs, cadence, args.tolerance, since, until)
    same, different = 0, []
    if args.routes:
        raw = json.loads(args.routes.read_text(encoding="utf-8"))
        rows = raw.get("decisions") if isinstance(raw, dict) else raw
        if not isinstance(rows, list):
            raise ConfigError(f"{args.routes}: a list of rows, or an object with a decisions key")
        lanes = iter(pack.lanes)
        same, different = compare_routes(ticks, rows, repository_urls(services), lanes)
    report = Diff(
        since=since,
        until=until,
        matched=tuple(matched),
        missed=tuple(missed),
        early=tuple(early),
        routes_same=same,
        routes_different=tuple(different),
    )
    print(report.model_dump_json(indent=2))
    return 1 if report.differences else 0


def _claim(args: argparse.Namespace, core: Context, pack: Pack) -> int:
    worker = WorkerId(args.worker or f"{socket.gethostname()}:{os.getpid()}")
    runner = Runner(core.services(), pack, worker, args.lease, core.config.forge_hosts)
    order = runner.claim_once()
    if order is None:
        print(json.dumps({"claimed": None}))
        return 0
    print(order.model_dump_json())
    return _EXIT[order.state]


def _parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--core",
        type=Path,
        required=True,
        help="separate traust.yaml-format core file; set home: to the deployment home",
    )
    common.add_argument("--pack", type=Path, required=True, help="the pack's assets.yaml")
    common.add_argument(
        "--pin", type=Path, action="append", default=[], help="pinned config for run manifests"
    )
    common.add_argument(
        "--feeds", type=Path, help="the pack's feeds registry: its feeds are known to core"
    )
    common.add_argument(
        "--models",
        type=Path,
        help="the model registry: a completed order's measured usage is priced as its spend",
    )
    passes = argparse.ArgumentParser(add_help=False)
    passes.add_argument("--router", help="the pack's router, module:Class")
    passes.add_argument("--once", action="store_true", help="one pass, then exit (from cron)")
    passes.add_argument("--every", type=_duration, default="15m", help="pause between passes")

    ap = argparse.ArgumentParser(prog="traust-engine", description=__doc__)
    sub = ap.add_subparsers(dest="op", required=True)
    sub.add_parser("run", parents=[common, passes], help="reap, tick and admit, pass after pass")
    sub.add_parser(
        "shadow", parents=[common, passes], help="print what each pass would plan, planning nothing"
    )
    rec = sub.add_parser(
        "record", parents=[common], help="run an asset's command as an order: ASSET -- CMD"
    )
    rec.add_argument("asset")
    rec.add_argument("--repo", help="the repository, for an asset made per repository")
    diff = sub.add_parser(
        "diff", parents=[common], help="shadow passes against recorded runs; exit 1 on a difference"
    )
    diff.add_argument("--shadow", type=Path, required=True, help="`traust-engine shadow` output")
    diff.add_argument("--routes", type=Path, help="expected routing: rows of repo_url and lane")
    diff.add_argument("--window", type=_duration, default="24h", help="how far back to compare")
    diff.add_argument("--tolerance", type=_duration, default="2h", help="still the same run")
    claim = sub.add_parser(
        "claim", parents=[common], help="run one queued order of a command asset, then exit"
    )
    claim.add_argument("--worker", help="this runner's id (default: host:pid)")
    claim.add_argument(
        "--lease", type=_duration, default="15m", help="lease, renewed while running"
    )
    return ap


def _error(operation: str, error: Exception) -> None:
    detail = ""
    if isinstance(error, PreflightError):
        detail = str(error)
    elif isinstance(error, ConfigError):
        if str(error) == "give the command after --, and --repo exactly when the asset has one":
            detail = str(error)
        elif "no --router was given" in str(error):
            detail = "no --router was given; pass --router module:Class or remove route_on"
        else:
            detail = "check --core, --pack and the configuration files"
    elif isinstance(error, NotFoundError):
        detail = "check the asset and --repo against the pack and inventory"
    elif isinstance(error, FileNotFoundError) and operation == "startup":
        detail = "check --core, --pack and pinned file paths"
    suffix = f": {detail}" if detail else ""
    print(f"ERROR: {operation} failed ({type(error).__name__}){suffix}", file=sys.stderr)


def _debug_failure(error: Exception) -> None:
    if isinstance(error, (OSError, TraustError)):
        return
    frames = [
        f"{Path(frame.filename).name}:{frame.lineno}:{frame.name}"
        for frame in traceback.extract_tb(error.__traceback__)
        if "/traust_engine/" in frame.filename.replace("\\", "/")
    ]
    log.debug("engine unexpected error_type=%s frames=%s", type(error).__name__, frames)


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    split = argv.index("--") if "--" in argv else len(argv)
    args = _parser().parse_args(argv[:split])
    args.command = argv[split + 1 :]
    try:
        core = Context.from_file(args.core)
        core.configure_logging("traust_engine")
    except Exception as error:
        _debug_failure(error)
        _error("startup", error)
        return 2

    opened = perf_counter()
    try:
        return _run_with_stack(args, core)
    except Exception as error:
        with correlation_scope(_request_id("shutdown"), actor_kind=ActorKind.MACHINE):
            _debug_failure(error)
            lifecycle(
                log,
                "observation",
                "failed",
                started=opened,
                reason="cleanup_error",
                error_type=type(error).__name__,
            )
            _error("tick", error)
        return 2


def _run_with_stack(args: argparse.Namespace, core: Context) -> int:
    with ExitStack() as stack:
        with correlation_scope(_request_id("startup"), actor_kind=ActorKind.MACHINE):
            started = perf_counter()
            try:
                if args.feeds:
                    core.register_feeds(args.feeds)
                if args.models:
                    core.register_model_catalog(args.models)
                pack = Pack.load(args.pack, *args.pin, *([args.feeds] if args.feeds else []))
                if args.op in ("run", "shadow", "claim"):
                    core.register_toolchain()
                if args.op in ("run", "shadow"):
                    if pack.route_on is not None and not args.router:
                        raise ConfigError(
                            f"pack {pack.pack} sets route_on {pack.route_on}, but no --router was "
                            "given -- pass --router module:Class, or drop route_on from the pack"
                        )
                    core.preflight(pack.requirements())
                    engine = stack.enter_context(_loop(core, pack, args.router))
                else:
                    if args.op == "claim":
                        core.preflight(pack.assets[name].requires for name in runnable(pack))
                    engine = None
            except Exception as error:
                _debug_failure(error)
                lifecycle(
                    log,
                    "startup",
                    "failed",
                    started=started,
                    reason="preflight_error",
                    error_type=type(error).__name__,
                )
                _error("startup", error)
                return 2
            lifecycle(log, "startup", "ready", started=started, count=len(pack.assets))

        if engine is not None:
            try:
                return _passes(args, core, engine, shadow=args.op == "shadow")
            except Exception as error:
                _error("tick", error)
                return 2

        with correlation_scope(_request_id(args.op), actor_kind=ActorKind.MACHINE):
            started = perf_counter()
            try:
                ops = {"record": _record, "diff": _diff, "claim": _claim}
                returncode = ops[args.op](args, core, pack)
            except Exception as error:
                _debug_failure(error)
                lifecycle(
                    log,
                    args.op,
                    "failed",
                    started=started,
                    reason="operation_error",
                    error_type=type(error).__name__,
                )
                _error(args.op, error)
                return 2
            lifecycle(
                log,
                args.op,
                "completed",
                started=started,
                status=f"exit:{returncode}",
                returncode=returncode,
            )
            return returncode


if __name__ == "__main__":
    raise SystemExit(main())
