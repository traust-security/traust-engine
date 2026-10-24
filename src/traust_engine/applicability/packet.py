"""Evidence packets for below-range candidates in one repository.

For every exact installed version of a supported ecosystem, every OSV advisory
naming the package is fetched. Each version the stated ranges leave out becomes
a candidate, and each candidate gets a packet:

- the advisory (summary, details, ranges for the package);
- the chosen fix patch and how it was chosen;
- the installed version's source, from its registry;
- per-hunk presence of the fix's removed and added lines in that source.

A packet carries facts only. Whether the version is affected is decided by
review of the packet. Every candidate is accounted for: a packet, or a coverage
gap with its reason.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from traust_engine.adapters.osv import collect_packages
from traust_engine.applicability import dating, dependencies
from traust_engine.applicability.candidates import Candidate, classify, view
from traust_engine.applicability.fetch import Fetcher, FetchRefused
from traust_engine.applicability.fixes import (
    MAX_PATCHES,
    advisory_ids,
    narrow,
    only_adds,
    parse_mbox,
    patch_url,
    references,
    release_like,
    relevance,
)
from traust_engine.applicability.matching import anchor, presence, root_of
from traust_engine.osv import OsvClient, Query

SUPPORTED = ("Go", "PyPI", "npm", "Maven", "crates.io")
FULL_VERSION = re.compile(r"\d+\.\d+\.\d+(?:[-+.][0-9A-Za-z.+-]*)?")


def exact(ecosystem: str, version: str, basis: str | None) -> bool:
    """Whether the dependency pre-scan's version is the one installed.

    A lockfile always is (`locked`). A version read from a manifest without one
    (`manifest-floor`) depends on the ecosystem:
    - a pom.xml version is the version Maven uses, and go.mod lists the
      selected versions: both exact;
    - a package.json pin is exact only as a full x.y.z ("1.2" means 1.2.x);
    - a Cargo.toml version is a caret requirement ("1" means ^1), and a Python
      manifest version is a floor: neither is the installed version.
    Resolved and defaulted versions are approximations, never exact.
    """
    if basis == "locked":
        return True
    if basis != "manifest-floor":
        return False
    if ecosystem in ("Maven", "Go"):
        return True
    if ecosystem == "npm":
        return bool(FULL_VERSION.fullmatch(version))
    return False


def installed(
    repo: Path, ecosystems: tuple[str, ...]
) -> tuple[list[tuple[str, str, str]], Counter]:
    """(ecosystem, package, version) for exact installs; skipped counts by reason."""
    packages, _stats = collect_packages(repo)
    keep, skipped = [], Counter()
    for (eco, name, version), entry in sorted(packages.items()):
        if eco not in ecosystems:
            skipped[f"ecosystem:{eco}"] += 1
        elif not exact(eco, version, entry.get("version_basis")):
            skipped[f"basis:{eco}:{entry.get('version_basis')}"] += 1
        else:
            keep.append((eco, name, version))
    return keep, skipped


def candidates(
    pkgs: list[tuple[str, str, str]], client: OsvClient
) -> tuple[list[tuple[Candidate, dict, list[dict]]], list[dict]]:
    """Every below-range or gap candidate with its record and its aliases' records;
    lookups OSV didn't answer. Alias records only supply fix references: the
    candidate comes from the record that names the package."""
    names = sorted({(eco, name) for eco, name, _ in pkgs})
    outcome = client.query_batch([Query(eco, name, None) for eco, name in names])
    unanswered = [
        {"ecosystem": e, "package": n}
        for (e, n), ids in zip(names, outcome.ids, strict=True)
        if ids is None
    ]
    wanted = {vid for ids in outcome.ids if ids for vid in ids}
    details, _issues = client.get_vulns(sorted(wanted))
    by_pkg: dict[tuple[str, str], list[dict]] = {}
    for (eco, name), ids in zip(names, outcome.ids, strict=True):
        by_pkg[(eco, name)] = [details[v] for v in ids or [] if v in details]
    # One candidate per (package, version, vulnerability): a CVE with a GHSA and a
    # PYSEC (or GO-) record is one exposure. The first record found represents
    # it; the others join its aliases.
    found: dict[tuple[str, str, str, str], tuple[Candidate, dict, list[str]]] = {}
    for eco, name, version in pkgs:
        for rec in by_pkg.get((eco, name), []):
            if rec.get("withdrawn") or str(rec.get("id", "")).startswith("MAL-"):
                continue
            c = classify(rec, eco, name, version)
            if c is None:
                continue
            key = (eco, name, version, vulnerability_id(rec))
            if key in found:
                found[key][2].append(str(rec["id"]))
            else:
                found[key] = (c, rec, [str(a) for a in rec.get("aliases") or []])
    alias_ids = sorted({a for _, _, al in found.values() for a in al} - set(details))
    alias_recs, _ = client.get_vulns(alias_ids) if alias_ids else ({}, None)
    known = {**alias_recs, **details}
    out = [(c, rec, [known[a] for a in al if a in known]) for c, rec, al in found.values()]
    return out, unanswered


def vulnerability_id(rec: dict) -> str:
    """The CVE alias when the record has one, else the record's own id."""
    return next(
        (str(a) for a in rec.get("aliases") or [] if str(a).startswith("CVE-")), str(rec.get("id"))
    )


def case_id(c: Candidate) -> str:
    raw = f"{c.package}@{c.version}--{c.advisory_id}"
    return re.sub(r"[^A-Za-z0-9._@-]+", "_", raw)[:180]


def choose_fix(
    rec: dict, root: Path, fetcher: Fetcher, aliases: list[dict] = ()
) -> tuple[dict | None, list[dict], str | None]:
    """(chosen, alternatives, patch text) by the score in fixes' docstring."""
    ids = advisory_ids(rec)
    # The summary is the advisory's distilled claim; details add boilerplate
    # ("a flaw was found ... may lead to") that unrelated commits share too.
    wording = rec.get("summary") or rec.get("details") or ""
    package = next(
        ((a.get("package") or {}).get("name") or "" for a in rec.get("affected") or []), ""
    )
    tried = []
    for rank, url in references(rec, fetcher.forges, aliases)[:MAX_PATCHES]:
        purl = patch_url(url)
        if not purl:
            tried.append({"url": url, "rank": rank, "error": "no patch endpoint for this link"})
            continue
        try:
            text = fetcher.patch(purl)
        except (FetchRefused, OSError) as e:
            tried.append({"url": url, "rank": rank, "error": f"{type(e).__name__}: {e}"})
            continue
        commits = narrow(parse_mbox(text), ids)
        files = [f for c in commits for f in c.files]
        _strip, found = anchor(files, root)
        named = any(i in c.message for c in commits for i in ids)
        release = release_like(commits, files)
        shared = relevance(wording, commits, files, package)
        # Among patches that don't name the advisory, its own words outrank file
        # presence: a real fix whose files the older installed version lacks
        # must still beat an unrelated commit that touches files it has. A
        # patch naming the advisory is already known to be relevant, so file
        # presence decides among those.
        score = (
            not release,
            named,
            0 if named else shared,
            len(found) > 0,
            not only_adds(files),
            -rank,
            len(found),
        )
        tried.append(
            {
                "url": url,
                "rank": rank,
                "commits": [{"sha": c.sha, "subject": c.subject} for c in commits],
                "files": len(files),
                "files_in_installed_tree": len(found),
                "names_advisory": named,
                "only_adds_code": only_adds(files),
                "release_commit": release,
                "advisory_words_shared": shared,
                "commit_date": dating.latest(commits),
                "_score": score,
                "_files": files,
                "_text": text,
            }
        )
    usable = [t for t in tried if "_score" in t]
    best = max(usable, key=lambda t: t["_score"], default=None)
    public = [{k: v for k, v in t.items() if not k.startswith("_")} for t in tried]
    if best is None:
        return None, public, None
    chosen = {k: v for k, v in best.items() if not k.startswith("_")}
    chosen["files_changed"] = best["_files"]
    return chosen, public, best["_text"]


def build(
    repo: Path,
    out: Path,
    *,
    ecosystems: tuple[str, ...] = SUPPORTED,
    max_candidates: int = 100,
    client: OsvClient | None = None,
    fetcher: Fetcher | None = None,
    resolver=None,
) -> dict:
    """Write one packet directory per candidate under `out`; return the index."""
    client = client or OsvClient()
    fetcher = fetcher or Fetcher()
    out.mkdir(parents=True, exist_ok=True)
    pkgs, skipped = installed(repo, tuple(e for e in ecosystems if e in SUPPORTED))
    cands, unanswered = candidates(pkgs, client)
    gaps: list[dict] = [{"reason": "osv_unanswered", **u} for u in unanswered]
    packets: list[dict] = []
    sources: dict[tuple[str, str, str], dict] = {}
    for n, (c, rec, aliases) in enumerate(cands):
        cid = case_id(c)
        if n >= max_candidates:
            gaps.append({"reason": "over_max_candidates", "case": cid})
            continue
        d = out / cid
        key = (c.ecosystem, c.package, c.version)
        if key not in sources:
            try:
                sources[key] = fetcher.source(
                    c.ecosystem, c.package, c.version, out / "_sources" / cid
                )
                sources[key]["dir"] = out / "_sources" / cid
            except (FetchRefused, OSError, ValueError) as e:
                sources[key] = {"error": f"{type(e).__name__}: {e}"}
        src = sources[key]
        if "error" in src:
            gaps.append({"reason": "source_unavailable", "case": cid, "detail": src["error"]})
            continue
        root = root_of(src["dir"])
        chosen, tried, text = choose_fix(rec, root, fetcher, aliases)
        fixed = dating.fixed_versions(view(rec, c.ecosystem, c.package), c.ecosystem, c.package)
        fixed_releases = [
            {"version": v, "published": fetcher.release_time(c.ecosystem, c.package, v)}
            for v in fixed[:6]
        ]
        if chosen is None:
            gaps.append({"reason": "no_usable_fix_patch", "case": cid, "tried": tried})
            continue
        d.mkdir(parents=True, exist_ok=True)
        (d / "fix.patch").write_text(text or "")
        files = chosen.pop("files_changed")
        hunks = presence(files, root)
        touched = [root / h["installed_path"] for h in hunks if h["installed_path"]]
        dep_sources, dep_gaps = dependencies.gather(
            c.ecosystem,
            c.package,
            c.version,
            root,
            touched,
            resolver,
            fetcher,
            src["dir"].parent / "_deps",
        )
        packet = {
            "case": cid,
            "candidate": asdict(c),
            "advisory": {
                "id": rec.get("id"),
                "aliases": rec.get("aliases") or [],
                "summary": rec.get("summary"),
                "details": (rec.get("details") or "")[:6000],
                "affected": view(rec, c.ecosystem, c.package)["affected"],
            },
            "fix": {"chosen": chosen, "alternatives": tried, "fixed_releases": fixed_releases},
            "installed_source": {
                "url": src["url"],
                "sha256": src["sha256"],
                "files": src["files"],
                "root": str(root.relative_to(out)),
            },
            "hunk_presence": hunks,
            # sources of direct dependencies a file the fix touches imports
            "dependency_sources": [
                {
                    **{k: v for k, v in ds.items() if k != "dir"},
                    "root": str(root_of(ds["dir"]).relative_to(out)),
                }
                for ds in dep_sources
            ],
            "dependency_gaps": dep_gaps,
        }
        (d / "packet.json").write_text(json.dumps(packet, indent=1) + "\n")
        packets.append({"case": cid, "kind": c.kind, "ecosystem": c.ecosystem})
    index = {
        "repo": str(repo),
        "installed_exact": len(pkgs),
        "skipped_installs": dict(sorted(skipped.items())),
        "candidates": len(cands),
        "packets": packets,
        "coverage_gaps": gaps,
        "status": "degraded" if unanswered else "complete",
    }
    # every candidate is a packet or a gap; a mismatch is a defect, not a quiet day
    accounted = len(packets) + sum(1 for g in gaps if "case" in g)
    if accounted != len(cands):
        raise AssertionError(f"{len(cands)} candidates but {accounted} packets and gaps")
    (out / "below-range.json").write_text(json.dumps(index, indent=1) + "\n")
    return index
