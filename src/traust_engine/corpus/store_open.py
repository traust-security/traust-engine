"""Open the storage/v1 store a dashboard reads, and name its scopes.

WHY THIS EXISTS
    Without it every dashboard builder hand-rolls the same four lines --
    resolve a path, sqlite3.connect, wrap in Store, assemble a scope list --
    and the fourteenth copy is where they stop agreeing. The views were
    added to remove exactly that duplication; leaving it in the callers
    would move the problem rather than solve it.

WHAT IT IS NOT
    Not a second source of truth about location. `locations.store_db`
    answers where the store lives; this opens what that names.

    Not an ingest path. A builder READS. A store that does not exist is an
    operational state to report, not one to silently create -- a dashboard
    that quietly builds an empty store renders an empty dashboard and looks
    like a regression.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from traust_contracts.v1.storage import Store

from traust_engine import locations


class StoreUnavailable(RuntimeError):
    """The store is not where the deployment says it should be.

    Carries the path so the operator is told what to run, not merely that
    something is missing.
    """

    def __init__(self, path: Path | None) -> None:
        where = str(path) if path else "<unresolved: no analysis-results configured>"
        super().__init__(
            f"no storage/v1 store at {where}. Build it with "
            f"`python3 -m traust.cli store ingest`, or point `locations.store` "
            f"at an existing one."
        )
        self.path = path


def store_path(engine) -> Path | None:
    """Where this deployment's store lives, or None when unresolvable."""
    return locations.store_db(engine.ctx.locations)


def open_store(engine, *, must_exist: bool = True) -> Store:
    """A read-only Store over the configured database.

    Opened read-only on purpose: a dashboard has no business writing, and
    the mode makes an accidental projection write fail loudly instead of
    corrupting a cache other dashboards are reading in the same run.
    """
    path = store_path(engine)
    if path is None or (must_exist and not path.is_file()):
        raise StoreUnavailable(path)
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    return Store(conn)


def scope_ids(engine) -> list[str]:
    """The scopes this deployment may read, from corpus-config.

    Never a literal ["local"]. A deployment partitioned per business unit
    has several, and a query hard-coding one silently reports a slice as
    the whole estate.
    """
    return engine.corpus.config().readable_scopes()
