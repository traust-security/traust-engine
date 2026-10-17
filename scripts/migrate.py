#!/usr/bin/env python3
"""Preview and import unchanged artifacts into SQLite or PostgreSQL.

Canonical migration entrypoint, run engine-locally (no traust dependency):

    uv run python scripts/migrate.py plan|run|inspect ...

or through ``make migrate-plan``, ``make migrate-run`` and ``make migrate-inspect``.
All per-run parameters can live in one declarative profile file whose keys
mirror these flags; explicit flags override the profile:

    uv run python scripts/migrate.py run --profile migration.yaml

See migration.example.yaml for the profile schema. The logic lives in the
library module ``traust_engine.corpus.migrate``; this script only parses
arguments and prints. It sits outside the package because the engine is a
library with no command-line entry points (tests/test_no_cli_entrypoints.py).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from traust_engine.corpus import migrate


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-home", type=Path, help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan", help="validate and list decisions without a database")
    inspect = commands.add_parser("inspect", help="summarize a saved migration result")
    run = commands.add_parser("run", help="load, log failures, continue; keep the database")
    for command in (plan, run, inspect):
        command.add_argument(
            "--profile",
            type=Path,
            help="declarative migration profile (see migration.example.yaml)",
        )
    # Path/choice args default to None so profile values can fill them; explicit
    # flags always win. Required-ness is enforced after the profile merge.
    for command in (plan, run):
        command.add_argument("--results-root", type=Path)
        command.add_argument("--config", type=Path, help="deployment configuration")
        command.add_argument("--output", type=Path, help="new directory outside the source tree")
        command.add_argument(
            "--exclude",
            action="append",
            metavar="GLOB",
            help="ignore matching source files (repeatable; adds to config migration.exclude)",
        )
        command.add_argument(
            "--fresh",
            action="store_true",
            help="remove the resolved output dir before running (used by the make targets)",
        )
    inspect.add_argument("--output", type=Path, help="existing result directory")
    # Generic database destination: a type plus its connection info.
    run.add_argument("--database-type", choices=("postgres", "sqlite"), help="destination DB type")
    run.add_argument("--database-dsn", help="PostgreSQL connection string (literal)")
    run.add_argument("--database-dsn-env", help="env var holding the PostgreSQL connection string")
    run.add_argument("--database-path", type=Path, help="SQLite file path (new, nonexistent)")
    run.add_argument("--findings-db", type=Path, help="optional read-only reference snapshot")
    run.add_argument(
        "--max-seconds", type=float, help="optional time budget; exhaustion saves a blocked result"
    )
    return parser


_FLAG_NAMES = (
    "results_root",
    "config",
    "output",
    "exclude",
    "findings_db",
    "max_seconds",
    "database_type",
    "database_dsn",
    "database_dsn_env",
    "database_path",
    "fresh",
)


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    profile = migrate.load_profile(args.profile) if args.profile else {}
    flags = {name: getattr(args, name, None) for name in _FLAG_NAMES}
    try:
        options = migrate.resolve_options(args.command, flags, profile)
    except migrate.MigrationUsageError as error:
        parser.error(str(error))

    if args.command == "inspect":
        inspected = migrate.inspect_summary(options["output"])
        if inspected is None:
            print("Migration result is unavailable or invalid.", file=sys.stderr)
            return 2
        print(json.dumps(inspected, ensure_ascii=True))
        return 0

    migrate.prepare_output(options)
    try:
        dsn, ledger_target_url = migrate.resolve_database(options)
    except migrate.MigrationUsageError as error:
        parser.error(str(error))
    except migrate.MigrationConfigError as error:
        print(str(error), file=sys.stderr)
        return 2
    try:
        result = migrate.execute(options, dsn, ledger_target_url)
    except Exception as error:
        # Driver/configuration exceptions can contain credentials or source values.
        print(f"Migration unavailable: {type(error).__name__}.", file=sys.stderr)
        return 2
    print(json.dumps(migrate.summary(result), ensure_ascii=True))
    return migrate.exit_code(result)


if __name__ == "__main__":
    raise SystemExit(main())
