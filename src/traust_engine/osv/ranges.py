"""Read one package's affected spans from an OSV record, and pick the fix for
one installed version.

An OSV range can hold several affected spans (introduced/fixed pairs), and a
span may end at ``last_affected`` rather than ``fixed``. So the right fix
depends on the installed version. For a record affected below 1.5.0 and again
from 2.0.0 to 2.3.0, the fix for 2.1.0 is 2.3.0, not 1.5.0.
"""

from __future__ import annotations

from dataclasses import dataclass

from traust_engine._util.versions import parse_version

# OSV ecosystem name -> the `parse_version` ecosystem tag. Unknown names fall
# through to the leading-numeric default.
_VERSION_TAG = {
    "Go": "go",
    "npm": "npm",
    "PyPI": "pypi",
    "Maven": "maven",
    "crates.io": "cargo",
    "RubyGems": "ruby",
    "NuGet": "nuget",
}

# GIT ranges carry commit hashes, not versions.
_GIT = "GIT"


@dataclass(frozen=True)
class Span:
    """One affected span. ``introduced`` "0" means every earlier version."""

    introduced: str
    fixed: str | None = None
    last_affected: str | None = None


def _entries(vuln: dict, name: str, ecosystem: str | None, ignore_case: bool):
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        pname = pkg.get("name")
        if ignore_case:
            if pname and pname.lower() != name.lower():
                continue
        elif ecosystem == "NuGet":
            # NuGet ids are case-insensitive; OSV records use the published casing.
            if (pname or "").lower() != name.lower():
                continue
        elif pname != name:
            continue
        if ecosystem and pkg.get("ecosystem") and pkg["ecosystem"] != ecosystem:
            continue
        yield aff


def spans(
    vuln: dict, name: str, ecosystem: str | None = None, *, ignore_case: bool = False
) -> list[Span]:
    """Every version span the record marks affected for this package.

    With ``ignore_case``, names compare case-insensitively and an affected
    entry that names no package applies to every package.
    """
    out: list[Span] = []
    for aff in _entries(vuln, name, ecosystem, ignore_case):
        for rng in aff.get("ranges") or []:
            if rng.get("type") == _GIT:
                continue
            start: str | None = None
            for ev in rng.get("events") or []:
                if "introduced" in ev:
                    if start is None:
                        start = str(ev["introduced"])
                elif "fixed" in ev:
                    out.append(Span(start or "0", fixed=str(ev["fixed"])))
                    start = None
                elif "last_affected" in ev:
                    out.append(Span(start or "0", last_affected=str(ev["last_affected"])))
                    start = None
                # `limit` bounds where the range is evaluated; it ends no span.
            if start is not None:
                out.append(Span(start))
    return out


def range_evidence(vuln: dict, name: str, ecosystem: str | None = None) -> dict:
    """The record's ranges and FIX references for this package, as stated."""
    ranges = [
        {k: rng[k] for k in ("type", "repo", "events") if k in rng}
        for aff in _entries(vuln, name, ecosystem, False)
        for rng in aff.get("ranges") or []
    ]
    fixes = [
        ref["url"]
        for ref in vuln.get("references") or []
        if ref.get("type") == "FIX" and ref.get("url")
    ]
    return {"osv_ranges": ranges, "fix_references": fixes}


class _Order:
    def __init__(self, ecosystem: str | None):
        self._tag = _VERSION_TAG.get(ecosystem or "", "")

    def key(self, version: str | None) -> tuple[int, ...] | None:
        parts = parse_version(version, self._tag) if version else None
        if parts is None:
            return None
        # 1.2 and 1.2.0 are the same release.
        while len(parts) > 1 and parts[-1] == 0:
            parts = parts[:-1]
        return parts

    def contains(self, span: Span, key: tuple[int, ...]) -> bool | None:
        """Whether the span covers ``key``; None when a bound can't be parsed."""
        low = () if span.introduced == "0" else self.key(span.introduced)
        if low is None:
            return None
        if key < low:
            return False
        if span.fixed is not None:
            high = self.key(span.fixed)
            return None if high is None else key < high
        if span.last_affected is not None:
            high = self.key(span.last_affected)
            return None if high is None else key <= high
        return True


def version_key(version: str | None, ecosystem: str | None) -> tuple[int, ...] | None:
    """A comparable key for one of an OSV ecosystem's versions, or None if it can't be parsed."""
    return _Order(ecosystem).key(version)


def containing_span(
    vuln: dict,
    name: str,
    ecosystem: str | None,
    installed: str | None,
    *,
    ignore_case: bool = False,
) -> Span | None:
    """The affected span that covers ``installed``, or None."""
    order = _Order(ecosystem)
    have = order.key(installed)
    if have is None:
        return None
    for span in spans(vuln, name, ecosystem, ignore_case=ignore_case):
        if order.contains(span, have):
            return span
    return None


def fixed_for(
    vuln: dict,
    name: str,
    ecosystem: str | None,
    installed: str | None,
    *,
    ignore_case: bool = False,
) -> str | None:
    """The fixed version that remediates ``installed``.

    It prefers the fix of a span that covers ``installed``, then any fix above
    it, and in each case the lowest one that no span marks affected again.
    When records overlap so that every candidate is still covered, it returns
    the covering span's own fix. That is what the record's author meant for
    that release line.

    Returns None when there is no fix above ``installed``. When the installed
    version (or every fixed version) can't be ordered, it returns the
    record's first fixed version, as the earlier helpers did.
    """
    ss = spans(vuln, name, ecosystem, ignore_case=ignore_case)
    fixes = [s.fixed for s in ss if s.fixed]
    if not fixes:
        return None
    order = _Order(ecosystem)
    have = order.key(installed)
    keyed = [(order.key(f), f) for f in fixes]
    if have is None or all(k is None for k, _ in keyed):
        return fixes[0]

    def above(candidates):
        return sorted((k, f) for k, f in candidates if k is not None and k > have)

    own = above((order.key(s.fixed), s.fixed) for s in ss if s.fixed and order.contains(s, have))
    for pool in (own, above(keyed)):
        clean = [(k, f) for k, f in pool if not any(order.contains(s, k) for s in ss)]
        if clean:
            return clean[0][1]
    return own[0][1] if own else None
