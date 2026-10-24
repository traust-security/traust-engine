"""Dates for review: when each candidate fix commit was authored, and when the
registry published each version the advisory says fixes it.

These are facts in the packet, not a ranking. Measured on the Phase 3
acceptance packets, a "too far from the fix release" rule changed no fix
choice and was wrong two times in three: real fixes often ship in a release
many months later. A reviewer can read a gap in context; a rule can't.
"""

from __future__ import annotations

import email.utils
import re
from datetime import UTC, datetime

from traust_engine.applicability.fixes import Commit
from traust_engine.osv.ranges import spans


def commit_date(commit: Commit) -> datetime | None:
    """The commit's author date from its format-patch `Date:` header."""
    m = re.search(r"(?m)^Date: (.+)$", commit.message)
    if not m:
        return None
    try:
        d = email.utils.parsedate_to_datetime(m.group(1).strip())
    except (TypeError, ValueError):
        return None
    return d if d.tzinfo else d.replace(tzinfo=UTC)


def latest(commits: list[Commit]) -> str | None:
    """The latest author date among the commits, ISO 8601, or None."""
    dates = [d for c in commits if (d := commit_date(c)) is not None]
    return max(dates).isoformat() if dates else None


def fixed_versions(view: dict, ecosystem: str, name: str) -> list[str]:
    """Every `fixed` version the record states for the package."""
    return sorted({s.fixed for s in spans(view, name, ecosystem) if s.fixed})
