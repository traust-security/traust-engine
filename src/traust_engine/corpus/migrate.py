"""Migration run logic: profile loading, option resolution and the run itself.

The engine is a library, so the command line lives outside the package, in
``scripts/migrate.py`` (run engine-locally by ``make migrate-plan``,
``make migrate-run`` and ``make migrate-inspect``). This module holds
everything that script does except parsing arguments and printing.

All per-run parameters can live in one declarative profile file whose keys
mirror the script's flags; explicit flags override the profile. See
``migration.example.yaml`` for the profile schema.
"""

from __future__ import annotations

import json
import os
import shutil
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
        "exclude",
        "findings-db",
        "max-seconds",
    }
)
# Keys under the generic `database:` block (type + connection info).
_DATABASE_KEYS = frozenset({"type", "dsn", "dsn-env", "path"})
# Option names that hold filesystem paths (resolved against the profile dir).
_PATH_DESTS = frozenset({"results_root", "config", "output", "database_path", "findings_db"})

# Next step to suggest for each issue code in an inspect summary.
_NEXT_ACTIONS = {
    "unrecognized_artifact": "Configure migration.schemas or investigate the input.",
    "unknown_contract": "Correct the declared schema or the artifact producer.",
    "ambiguous_schema": "Resolve conflicting schema routes or declarations.",
    "unresolved_binding": "Configure migration.bindings after verifying ownership.",
    "contract_validation": "Correct the authored source or its producer; rerun validation.",
    "ingest_rejected": "Inspect the issue and target mapping; do not rewrite evidence.",
}

_SUMMARY_KEYS = ("status", "database", "issue_count", "issue_counts", "outcomes", "ledger")


class MigrationUsageError(ValueError):
    """The options are incomplete or inconsistent (the caller's usage error)."""


class MigrationConfigError(ValueError):
    """The options are complete, but the environment can't satisfy them."""


def load_profile(path: Path) -> dict[str, Any]:
    """Read a migration profile into option names (snake_case).

    Keys mirror the CLI flags. The nested ``database:`` block flattens to
    ``database_*`` names. Relative paths resolve against the profile's directory.
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


def resolve_options(command: str, flags: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    """Merge explicit flags over the profile and apply the defaults.

    ``flags`` holds the explicitly passed values (``None`` when not passed).
    A profile-sourced ``output`` is a base directory: each command gets its own
    subdir so plan and run don't collide (the importer refuses to reuse an
    output dir). An explicit ``output`` is used verbatim.
    """

    def pick(name: str, default: Any = None) -> Any:
        value = flags.get(name)
        return value if value is not None else profile.get(name, default)

    output = pick("output")
    if output is not None and flags.get("output") is None:
        output = output / ("run" if command == "inspect" else command)
    options = {
        "command": command,
        "results_root": pick("results_root"),
        "config": pick("config"),
        "output": output,
        "exclude": pick("exclude"),
        "findings_db": pick("findings_db"),
        "max_seconds": pick("max_seconds"),
        "database_type": pick("database_type", "postgres"),
        "database_dsn": pick("database_dsn"),
        "database_dsn_env": pick("database_dsn_env", "TRAUST_MIGRATION_DSN"),
        "database_path": pick("database_path"),
        "fresh": bool(flags.get("fresh")),
    }
    if command == "inspect":
        if output is None:
            raise MigrationUsageError("inspect requires --output (or output: in the profile)")
        return options
    for name in ("results_root", "config", "output"):
        if options[name] is None:
            flag = name.replace("_", "-")
            raise MigrationUsageError(f"--{flag} is required (pass it or set it in --profile)")
    return options


def inspect_summary(output: Path) -> dict[str, Any] | None:
    """Summarize a saved migration result, or None when it is missing or invalid."""
    try:
        result = json.loads((output / "migration-result.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return {
        "status": result.get("status"),
        "outcomes": result.get("outcomes", {}),
        "ledger": result.get("ledger", {"status": "not_run", "selected": 0}),
        "excluded_by_rule": result.get("excluded_by_rule", {}),
        "issue_counts": result.get("issue_counts", {}),
        "next_actions": {
            code: _NEXT_ACTIONS.get(code, "Inspect issues.jsonl for the affected source.")
            for code in result.get("issue_counts", {})
        },
    }


def resolve_database(options: dict[str, Any]) -> tuple[str | None, str | None]:
    """Return ``(dsn, ledger_target_url)`` for a run; ``(None, None)`` otherwise."""
    if options["command"] != "run":
        return None, None
    if options["database_type"] == "sqlite":
        path = options["database_path"]
        if path is None:
            raise MigrationUsageError("sqlite requires database.path (--database-path)")
        return str(path), f"sqlite:///{Path(path).resolve()}"
    dsn = options["database_dsn"] or os.environ.get(options["database_dsn_env"])
    if not dsn:
        raise MigrationConfigError(
            "PostgreSQL connection string is not set (database.dsn or database.dsn-env)."
        )
    if dsn.startswith("postgresql+psycopg://"):
        return dsn.replace("postgresql+psycopg://", "postgresql://", 1), dsn
    if dsn.startswith("postgresql://"):
        return dsn, dsn.replace("postgresql://", "postgresql+psycopg://", 1)
    raise MigrationUsageError("PostgreSQL migration DSN must be a postgresql:// URL")


def prepare_output(options: dict[str, Any]) -> None:
    """With ``fresh``, remove the resolved output dir before running."""
    output = options["output"]
    if options["fresh"] and output.exists():
        shutil.rmtree(output)


def execute(
    options: dict[str, Any], dsn: str | None, ledger_target_url: str | None
) -> dict[str, Any]:
    """Run ``plan`` (preview) or ``run`` (rehearse) and return the full result."""
    if options["command"] == "plan":
        return preview(
            options["results_root"],
            options["config"],
            options["output"],
            route_layers_to_ledger=True,
            exclude=options["exclude"],
        )
    return rehearse(
        options["results_root"],
        options["config"],
        dsn,
        options["output"],
        findings_db=options["findings_db"],
        max_seconds=options["max_seconds"],
        route_layers_to_ledger=True,
        database_type=options["database_type"],
        exclude=options["exclude"],
        ledger_target_url=ledger_target_url,
    )


def summary(result: dict[str, Any]) -> dict[str, Any]:
    """The keys of a result worth printing."""
    return {key: result[key] for key in _SUMMARY_KEYS if key in result}


def exit_code(result: dict[str, Any]) -> int:
    """0 passed or planned clean; 1 failed or planned with blockers; 2 blocked."""
    if result["status"] == "planned":
        return 0 if result["blocking_issue_count"] == 0 else 1
    return {"passed": 0, "failed": 1, "blocked": 2}[result["status"]]
