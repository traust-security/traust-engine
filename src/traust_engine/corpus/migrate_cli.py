"""Preview and import unchanged artifacts into SQLite or PostgreSQL.

Canonical migration entrypoint. Run engine-locally with:

    python -m traust_engine.corpus.migrate_cli plan|run|inspect ...

All per-run parameters can live in one declarative profile file whose keys
mirror the CLI flags; explicit flags override the profile:

    python -m traust_engine.corpus.migrate_cli run --profile migration.yaml

See migration.example.yaml for the profile schema. The downstream
``traust corpus migrate-postgres`` command is a thin wrapper over this module.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

import yaml

from traust_engine.corpus.migration_rehearsal import preview, rehearse

# Top-level profile keys mirror the top-level CLI flags (kebab-case).
_TOP_KEYS = frozenset(
    {
        "results-root",
        "config",
        "output",
        "layer-destination",
        "exclude",
        "findings-db",
        "max-seconds",
    }
)
# Keys under the generic `database:` block (type + connection info).
_DATABASE_KEYS = frozenset({"type", "dsn", "dsn-env", "path"})
# Internal argparse dests that hold filesystem paths (resolved against the profile dir).
_PATH_DESTS = frozenset({"results_root", "config", "output", "database_path", "findings_db"})


def _load_profile(path: Path) -> dict[str, Any]:
    """Read a migration profile into argparse dests (snake_case).

    Keys mirror the CLI flags. The nested ``database:`` block flattens to
    ``database_*`` dests. Relative paths resolve against the profile's directory.
    """
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("Migration profile must be a mapping")
    database = data.pop("database", {})
    unknown = set(data) - _TOP_KEYS
    if unknown:
        raise ValueError(f"Unknown migration profile keys: {', '.join(sorted(unknown))}")
    if not isinstance(database, dict):
        raise ValueError("Migration profile 'database' must be a mapping")
    unknown_db = set(database) - _DATABASE_KEYS
    if unknown_db:
        raise ValueError(f"Unknown database keys: {', '.join(sorted(unknown_db))}")

    resolved: dict[str, Any] = {key.replace("-", "_"): value for key, value in data.items()}
    for key, value in database.items():
        resolved["database_" + key.replace("-", "_")] = value

    if resolved.get("exclude") is not None and not isinstance(resolved["exclude"], list):
        raise ValueError("Migration profile 'exclude' must be a list of patterns")

    base = path.resolve().parent
    for dest in _PATH_DESTS:
        value = resolved.get(dest)
        if value is not None:
            candidate = Path(str(value)).expanduser()
            resolved[dest] = candidate if candidate.is_absolute() else base / candidate
    return resolved


def main(
    argv: list[str] | None = None,
    *,
    default_layer_destination: str = "storage",
) -> int:
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
            "--layer-destination",
            choices=("ledger", "storage"),
            help="route layer files to Ledger (separate migration) or legacy artifact storage",
        )
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
    args = parser.parse_args(argv)

    profile = _load_profile(args.profile) if args.profile else {}

    def pick(name: str, default: Any = None) -> Any:
        value = getattr(args, name, None)
        return value if value is not None else profile.get(name, default)

    results_root = pick("results_root")
    config = pick("config")
    output = pick("output")
    # A profile-sourced output is a base directory: give each command its own
    # subdir so plan and run don't collide (the importer refuses to reuse an
    # output dir). An explicit --output is used verbatim.
    if output is not None and getattr(args, "output", None) is None:
        output = output / ("run" if args.command == "inspect" else args.command)
    layer_destination = pick("layer_destination", default_layer_destination)
    exclude = pick("exclude")
    findings_db = pick("findings_db")
    max_seconds = pick("max_seconds")
    database_type = pick("database_type", "postgres")
    database_dsn = pick("database_dsn")
    database_dsn_env = pick("database_dsn_env", "TRAUST_MIGRATION_DSN")
    database_path = pick("database_path")

    if args.command == "inspect":
        if output is None:
            parser.error("inspect requires --output (or output: in the profile)")
        try:
            result = json.loads((output / "migration-result.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            print("Migration result is unavailable or invalid.", file=sys.stderr)
            return 2
        actions = {
            "unrecognized_artifact": "Configure migration.schemas or investigate the input.",
            "unknown_contract": "Correct the declared schema or the artifact producer.",
            "ambiguous_schema": "Resolve conflicting schema routes or declarations.",
            "unresolved_binding": "Configure migration.bindings after verifying ownership.",
            "contract_validation": "Correct the authored source or its producer; rerun validation.",
            "ingest_rejected": "Inspect the issue and target mapping; do not rewrite evidence.",
        }
        print(
            json.dumps(
                {
                    "status": result.get("status"),
                    "outcomes": result.get("outcomes", {}),
                    "ledger": result.get("ledger", {"status": "not_run", "selected": 0}),
                    "excluded_by_rule": result.get("excluded_by_rule", {}),
                    "issue_counts": result.get("issue_counts", {}),
                    "next_actions": {
                        code: actions.get(code, "Inspect issues.jsonl for the affected source.")
                        for code in result.get("issue_counts", {})
                    },
                },
                ensure_ascii=True,
            )
        )
        return 0
    for name, value in (("results-root", results_root), ("config", config), ("output", output)):
        if value is None:
            parser.error(f"--{name} is required (pass it or set it in --profile)")
    if getattr(args, "fresh", False) and output.exists():
        shutil.rmtree(output)
    dsn = None
    if args.command == "run":
        if database_type == "sqlite":
            if database_path is None:
                parser.error("sqlite requires database.path (--database-path)")
            dsn = str(database_path)
        else:
            dsn = database_dsn or os.environ.get(database_dsn_env)
            if not dsn:
                print(
                    "PostgreSQL connection string is not set (database.dsn or database.dsn-env).",
                    file=sys.stderr,
                )
                return 2
    try:
        result = (
            preview(
                results_root,
                config,
                output,
                route_layers_to_ledger=layer_destination == "ledger",
                exclude=exclude,
            )
            if args.command == "plan"
            else rehearse(
                results_root,
                config,
                dsn,
                output,
                findings_db=findings_db,
                max_seconds=max_seconds,
                route_layers_to_ledger=layer_destination == "ledger",
                database_type=database_type,
                exclude=exclude,
            )
        )
    except Exception as error:
        # Driver/configuration exceptions can contain credentials or source values.
        print(f"Migration unavailable: {type(error).__name__}.", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                key: result[key]
                for key in (
                    "status",
                    "database",
                    "issue_count",
                    "issue_counts",
                    "outcomes",
                    "ledger",
                )
                if key in result
            },
            ensure_ascii=True,
        )
    )
    if result["status"] == "planned":
        return 0 if result["blocking_issue_count"] == 0 else 1
    return {"passed": 0, "failed": 1, "blocked": 2}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
