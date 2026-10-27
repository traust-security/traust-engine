"""The advisory an impact analysis runs against, as its source states it.

The vulnerable range and fixed version come from the fetched OSV record, never
from the caller. A typed range leaves no trace of where it came from, yet it
decides every repo's verdict; the record's URL goes into ``advisory_sources``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from traust_engine.adapters.osv import OSV_ECOSYSTEM
from traust_engine.osv import OsvClient
from traust_engine.osv.client import Query
from traust_engine.osv.ranges import Span, covers, spans, version_key


class AdvisoryUnavailable(Exception):
    """The record could not be fetched, or names no affected version of the module."""


@dataclass(frozen=True)
class ResolvedAdvisory:
    """The OSV record(s) for one advisory and the module's affected spans in them."""

    records: tuple[dict, ...]
    sources: tuple[str, ...]
    module: str
    osv_ecosystem: str

    @property
    def spans(self) -> list[Span]:
        return [s for r in self.records for s in self._spans(r)]

    def _spans(self, record: dict) -> list[Span]:
        return spans(record, self.module, self.osv_ecosystem) or spans(
            record, self.module, self.osv_ecosystem, ignore_case=True
        )

    def in_range(self, version: str | None) -> bool | None:
        """Whether any record marks ``version`` affected; None when it can't be decided."""
        verdicts = [covers(r, self._name(r), self.osv_ecosystem, version) for r in self.records]
        if True in verdicts:
            return True
        return None if None in verdicts else False

    def _name(self, record: dict) -> str:
        # PyPI/npm names compare case-insensitively; use the record's own spelling.
        for aff in record.get("affected") or []:
            name = (aff.get("package") or {}).get("name") or ""
            if name.lower() == self.module.lower():
                return name
        return self.module

    @property
    def vulnerable_range(self) -> str:
        """The spans as constraint text, e.g. '>=1.0.3 <1.2.1' (alternatives joined by ' || ')."""
        parts = []
        for s in self.spans:
            low = "" if s.introduced == "0" else f">={s.introduced}"
            high = f"<{s.fixed}" if s.fixed else f"<={s.last_affected}" if s.last_affected else ""
            parts.append(" ".join(p for p in (low, high) if p) or "*")
        return " || ".join(dict.fromkeys(parts))

    @property
    def fixed_version(self) -> str | None:
        """The highest fix across the spans: the one bump that clears every affected line."""
        fixes = [s.fixed for s in self.spans if s.fixed]
        if not fixes:
            return None
        return max(fixes, key=lambda f: version_key(f, self.osv_ecosystem) or ())


def _names(record: dict) -> set[str]:
    return {x.upper() for x in [record.get("id", ""), *(record.get("aliases") or [])] if x}


def resolve(
    advisory_id: str,
    module: str,
    ecosystem: str,
    *,
    client: OsvClient | None = None,
    osv_url: str | None = None,
    advisory_file: str | None = None,
) -> ResolvedAdvisory:
    """Fetch the advisory's OSV record (or read a supplied one, for air-gapped runs).

    An id OSV doesn't serve directly (a CVE whose records are GHSA/PYSEC entries) is
    found through the module's advisories; every record that carries it is used, and
    each one's URL recorded.
    """
    osv_eco = OSV_ECOSYSTEM.get(ecosystem)
    if osv_eco is None:
        raise AdvisoryUnavailable(f"OSV publishes no {ecosystem} advisories")
    want = advisory_id.upper()
    if advisory_file:
        path = Path(advisory_file).resolve()
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise AdvisoryUnavailable(f"{advisory_file}: {e}") from None
        if want not in _names(record):
            raise AdvisoryUnavailable(f"{advisory_file} is {record.get('id')}, not {advisory_id}")
        found = ResolvedAdvisory((record,), (path.as_uri(),), module, osv_eco)
    else:
        client = client or OsvClient(osv_url)
        direct, _ = client.get_vulns([advisory_id])
        records = list(direct.values())
        if not ResolvedAdvisory(tuple(records), (), module, osv_eco).spans:
            # e.g. a CVE id, or a record that names the module only through an alias
            outcome = client.query_batch([Query(osv_eco, module, None)])
            ids = outcome.ids[0]
            if ids is None:
                status = ", ".join(sorted(outcome.issues)) or "unanswered"
                raise AdvisoryUnavailable(f"OSV did not answer for {module} ({status})")
            fetched, _ = client.get_vulns(ids)
            records += [r for r in fetched.values() if want in _names(r) and r not in records]
        if not records:
            raise AdvisoryUnavailable(f"OSV has no record for {advisory_id}")
        records.sort(key=lambda r: r.get("id", ""))
        sources = tuple(f"{client.base_url}/vulns/{r['id']}" for r in records)
        found = ResolvedAdvisory(tuple(records), sources, module, osv_eco)
    if not found.spans:
        raise AdvisoryUnavailable(
            f"{advisory_id} names no affected version of {osv_eco} package {module}"
        )
    return found
