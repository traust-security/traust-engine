"""Below-range candidates: an installed version that every affected span of an
advisory starts above.

An advisory's ranges often stop at a support or testing boundary rather than
where the code changed, so a version below the stated start can still carry the
vulnerable code. This module only finds those versions. Whether one is really
affected is decided later, from code evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from traust_engine.osv.ranges import Span, containing_span, spans, version_key

BELOW_RANGE = "below_range"
GAP = "gap"


@dataclass(frozen=True)
class Candidate:
    """One (installed version, advisory) pair the stated ranges leave out."""

    ecosystem: str
    package: str
    version: str
    advisory_id: str
    kind: str  # BELOW_RANGE: under every span's start; GAP: between two spans
    stated_start: str  # the lowest explicit `introduced`, or the next span's start for a gap
    major_distance: int | None
    aliases: tuple[str, ...] = field(default_factory=tuple)


def normalize(ecosystem: str, name: str) -> str:
    """The comparison form of a package name (PyPI and NuGet names are case- and
    separator-insensitive)."""
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem == "NuGet":
        return name.lower()
    return name


def view(vuln: dict, ecosystem: str, name: str) -> dict:
    """The record reduced to the affected entries naming this package, renamed to
    `name` so the range helpers' exact match applies."""
    want = normalize(ecosystem, name)
    entries = [
        {**aff, "package": {**(aff.get("package") or {}), "name": name}}
        for aff in vuln.get("affected") or []
        if (aff.get("package") or {}).get("ecosystem") == ecosystem
        and normalize(ecosystem, (aff.get("package") or {}).get("name") or "") == want
    ]
    return {**vuln, "affected": entries}


def _listed(vuln: dict, name: str, ecosystem: str, version: str) -> bool:
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        if (
            pkg.get("name") == name
            and pkg.get("ecosystem") == ecosystem
            and version in {str(v) for v in aff.get("versions") or []}
        ):
            return True
    return False


def classify(vuln: dict, ecosystem: str, name: str, version: str) -> Candidate | None:
    """The candidate this record makes of the installed version, or None.

    None covers every case that isn't a candidate: OSV already reports the
    version affected (a span or the explicit `versions` list covers it), the
    version is above every fix, the record has no version ranges for the
    package, or a version or bound can't be ordered.
    """
    vuln = view(vuln, ecosystem, name)
    if _listed(vuln, name, ecosystem, version):
        return None
    ss: list[Span] = spans(vuln, name, ecosystem)
    have = version_key(version, ecosystem)
    if not ss or have is None:
        return None
    if containing_span(vuln, name, ecosystem, version) is not None:
        return None
    starts = []
    for s in ss:
        k = () if s.introduced == "0" else version_key(s.introduced, ecosystem)
        if k is None:
            return None
        starts.append((k, s))
    lowest_key, lowest = min(starts, key=lambda t: t[0])
    aliases = tuple(str(a) for a in vuln.get("aliases") or [])
    if lowest.introduced != "0" and have < lowest_key:
        return Candidate(
            ecosystem,
            name,
            version,
            str(vuln.get("id")),
            BELOW_RANGE,
            lowest.introduced,
            (lowest_key[0] - have[0]) if lowest_key and have else None,
            aliases,
        )
    ends = [
        k
        for s in ss
        if (s.fixed or s.last_affected)
        and (k := version_key(s.fixed or s.last_affected, ecosystem)) is not None
    ]
    for k, s in sorted(starts, key=lambda t: t[0]):
        if k > have and any(end <= have for end in ends):
            return Candidate(
                ecosystem,
                name,
                version,
                str(vuln.get("id")),
                GAP,
                s.introduced,
                (k[0] - have[0]) if k and have else None,
                aliases,
            )
    return None
