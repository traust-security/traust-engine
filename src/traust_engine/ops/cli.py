"""``traust-engine run|shadow|record|diff|claim``: the continuous-ops loop on a pack, the shadow run
beside cron (runs recorded as orders, the engine's would-be orders, the daily comparison), and a
claim-once runner for the pack's command assets."""

from __future__ import annotations

import argparse
import getpass
import importlib
import json
import os
import re
import socket
import sys
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from typing import Any

from traust_core.v1.context import Context
from traust_core.v1.errors import ConfigError, NotFoundError, TraustError
from traust_core.v1.models.identity import Principal
from traust_core.v1.models.operations import OrderRequest, OrderState, WorkerId
from traust_core.v1.models.vocabulary import ActorKind

from traust_engine.ops.loop import EngineLoop
from traust_engine.ops.pack import Pack
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


def _passes(args: argparse.Namespace, core: Context, pack: Pack, shadow: bool) -> int:
    with _loop(core, pack, args.router) as engine:
        while True:
            if shadow:
                report = Tick(at=core.clock.now(), due=engine.shadow_once().due)
            else:
                report = engine.run_once()
            print(report.model_dump_json(), flush=True)
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
    matched, missed, early = compare_runs(ticks, runs, cadence, args.tolerance, since, until)
    same, different = 0, []
    if args.routes:
        raw = json.loads(args.routes.read_text(encoding="utf-8"))
        rows = raw.get("decisions", []) if isinstance(raw, dict) else raw
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
    common.add_argument("--core", type=Path, required=True, help="traust-core's core.yaml")
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


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    split = argv.index("--") if "--" in argv else len(argv)
    args = _parser().parse_args(argv[:split])
    args.command = argv[split + 1 :]
    try:
        core = Context.from_file(args.core)
        if args.feeds:
            core.register_feeds(args.feeds)
        if args.models:
            core.register_model_catalog(args.models)
        pack = Pack.load(args.pack, *args.pin, *([args.feeds] if args.feeds else []))
        if args.op in ("run", "shadow", "claim"):
            # preflight checks tool requirements against core's shipped pins
            core.register_toolchain()
        if args.op in ("run", "shadow"):
            if pack.route_on is not None and not args.router:
                raise ConfigError(
                    f"pack {pack.pack} sets route_on {pack.route_on}, but no --router was "
                    "given -- pass --router module:Class, or drop route_on from the pack"
                )
            core.preflight(pack.requirements())
            return _passes(args, core, pack, shadow=args.op == "shadow")
        if args.op == "claim":
            core.preflight(pack.assets[name].requires for name in runnable(pack))
            return _claim(args, core, pack)
        return {"record": _record, "diff": _diff}[args.op](args, core, pack)
    except (OSError, TraustError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
