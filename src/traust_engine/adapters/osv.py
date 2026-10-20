"""Dependency-CVE candidates from the OSV API (multi-ecosystem SCA stage).

Collects every declared package and version from a target checkout's
lockfiles and manifests (the engine's ``portfolio.parsers``, the same
parsers the portfolio graph uses, plus ``go.mod``), looks them up through
the shared OSV API client (``traust_engine.osv``), and reduces the result to
one candidate per (OSV advisory, package), tagged with the files the package
was declared in. No scanner binary and no local vulnerability database are
involved (owner decision 2026-10-20).

This is a CANDIDATE GENERATOR, never a finder or verdict of record
(docs/deterministic-inferential-mix.md: deterministic tools route,
gate, tag, or index — never conclude). Every candidate is merely
*declared*, evidence class ``dependency_declared``: the package may be
unused, dev-only, or the vulnerable code path unexercised.

**Coverage is reported, never assumed.** A lookup that fails, is
rate-limited or comes back partial is counted in the provenance block
(``unreachable`` / ``quota-deferred`` / ``error``) and the scan is
``degraded``. When the API cannot be used at all (one probe before the scan,
or not a single package answered) the scan is ``failed``: no dependency
results, and ``scan()`` raises. Neither is ever "no advisories". Versions
taken from a manifest rather than a lockfile are declared floors, tagged
``version_basis: manifest-floor``.

The OSV API is the default. The osv-scanner binary path (``run_scanner`` /
``parse_output``) serves air-gapped deployments, which run osv-scanner
offline against a local OSV database the adopter provides; the harness does
not install either (owner decision 2026-10-20). The engine reads no
configuration: the caller chooses the path.
"""

import os
import re
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from traust_contracts.models import AdapterResult, Location

from traust_engine.adapters._contract_bridge import (
    build_scan_result,
    map_severity,
    utc_now,
)
from traust_engine.assets import harness_version as engine_harness_version
from traust_engine.osv import OsvClient, Query, max_score
from traust_engine.portfolio import parsers as manifest_parsers
from traust_engine.portfolio.graph import parse_gomod


def harness_version():
    return engine_harness_version()


def repo_head(repo):
    try:
        return subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        ).stdout.strip()
    except (subprocess.SubprocessError, OSError):
        return None


def fixed_version(vuln: dict, pkg_name: str, ecosystem: str):
    """Best-effort fixed version for pkg from the OSV affected ranges."""
    for aff in vuln.get("affected") or []:
        p = aff.get("package") or {}
        if p.get("name") != pkg_name:
            continue
        if ecosystem and p.get("ecosystem") and p["ecosystem"] != ecosystem:
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    return ev["fixed"]
    return None


def parse_output(doc: dict, repo: Path) -> list[dict]:
    """Reduce osv-scanner JSON to per-(advisory, package) candidates."""
    candidates: dict[tuple, dict] = {}
    for result in doc.get("results") or []:
        src = result.get("source") or {}
        src_path = src.get("path") or ""
        try:
            src_rel = str(Path(src_path).resolve().relative_to(repo.resolve()))
        except ValueError:
            src_rel = src_path
        for pkg_entry in result.get("packages") or []:
            pkg = pkg_entry.get("package") or {}
            name = pkg.get("name") or ""
            eco = pkg.get("ecosystem") or ""
            ver = pkg.get("version") or ""
            sev_by_group = {}
            for grp in pkg_entry.get("groups") or []:
                for vid in grp.get("ids") or []:
                    sev_by_group[vid] = grp.get("max_severity")
            for vuln in pkg_entry.get("vulnerabilities") or []:
                vid = vuln.get("id")
                if not vid:
                    continue
                key = (vid, eco, name)
                cand = candidates.setdefault(
                    key,
                    {
                        "osv_id": vid,
                        "aliases": vuln.get("aliases") or [],
                        "summary": (vuln.get("summary") or (vuln.get("details") or "")[:200]),
                        "ecosystem": eco,
                        "package": name,
                        "found_version": ver,
                        "fixed_version": fixed_version(vuln, name, eco),
                        "max_severity": sev_by_group.get(vid),
                        "evidence": "dependency_declared",
                        "sources": [],
                    },
                )
                if src_rel and src_rel not in cand["sources"]:
                    cand["sources"].append(src_rel)
    return sorted(candidates.values(), key=lambda c: (c["ecosystem"], c["package"], c["osv_id"]))


def run_scanner(binary: str, repo: Path, timeout: int, *, freeze: bool = False):
    """Invoke osv-scanner, tolerating both the v2 (`scan source`) and v1
    CLI shapes. Returns (stdout, stderr, returncode) of the first shape
    that produces output, or the last attempt's result.

    When *freeze* is True, ``--offline`` is appended so osv-scanner uses
    only its local DB cache and never phones home mid-scan.
    """
    from traust_engine.toolchain import freeze_flags

    extra = freeze_flags("osv-scanner") if freeze else []
    shapes = [
        [binary, "scan", "source", "--recursive", "--format", "json", *extra, str(repo)],
        [binary, "--recursive", "--format", "json", *extra, str(repo)],
    ]
    last = None
    for cmd in shapes:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        last = (proc, " ".join(cmd))
        if proc.stdout.strip().startswith("{"):
            return proc, " ".join(cmd)
    return last


def _cvss_to_severity(max_severity: str | None) -> str:
    if not max_severity:
        return "medium"
    try:  # a numeric CVSS score ("9.8"): band it (CVSS v3 qualitative scale)
        score = float(max_severity)
    except (TypeError, ValueError):
        score = None
    if score is not None:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        return "low" if score > 0 else "medium"
    sev = str(max_severity).upper()
    if sev in ("CRITICAL",):
        return "critical"
    if sev in ("HIGH", "HIGHEST"):
        return "high"
    if sev in ("MEDIUM", "MODERATE"):
        return "medium"
    if sev in ("LOW",):
        return "low"
    return "medium"


def _candidates_to_findings(candidates: list[dict]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for cand in candidates:
        locs = []
        for src in cand.get("sources", []):
            loc = Location(path=src) if Location is not None else {"path": src}
            locs.append(loc)
        desc_parts = [
            f"{cand.get('package')}@{cand.get('found_version')}",
            f"ecosystem={cand.get('ecosystem')}",
        ]
        if cand.get("fixed_version"):
            desc_parts.append(f"fixed in {cand['fixed_version']}")
        findings.append(
            {
                "id": cand["osv_id"],
                "title": cand.get("summary") or cand["osv_id"],
                "severity": map_severity(_cvss_to_severity(cand.get("max_severity"))),
                "locations": locs,
                "description": "; ".join(desc_parts),
                "origin": "osv",
                "source_findings": cand.get("aliases", []),
                "category": cand.get("ecosystem", ""),
            }
        )
    return findings


# ---------------------------------------------------------------------------
# API-based adapter (the default; owner decision 2026-10-20)
# ---------------------------------------------------------------------------

# Parser ecosystem -> OSV ecosystem name. docker and helm have no OSV
# ecosystem; they stay graph-only, as in the fleet sweep.
OSV_ECOSYSTEM = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "cargo": "crates.io",
    "ruby": "RubyGems",
    "nuget": "NuGet",
    "go": "Go",
    "actions": "GitHub Actions",
}

# Files whose versions are resolved, not declared ranges. A directory that
# holds one of these for an ecosystem is read from it alone; that
# ecosystem's manifests in the same directory are skipped.
LOCKFILES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "Pipfile.lock",
    "uv.lock",
    "gradle.lockfile",
    "Cargo.lock",
    "Gemfile.lock",
    "packages.lock.json",
    "go.mod",
}

SKIP_DIRS = {".git", "node_modules"}

_EXACT_VERSION = re.compile(r"^v?[0-9][0-9A-Za-z.+_~-]*$")
_GO_DIRECTIVE = re.compile(r"^go\s+(\d+\.\d+(?:\.\d+)?)\s*$", re.M)
_GO_TOOLCHAIN = re.compile(r"^toolchain\s+go(\d+\.\d+(?:\.\d+)?)\S*\s*$", re.M)


def _requirements_all_pinned(text: str) -> bool:
    lines = [
        ln.split("#", 1)[0].split(";", 1)[0].strip()
        for ln in text.splitlines()
        if ln.strip() and not ln.strip().startswith(("#", "-"))
    ]
    lines = [ln for ln in lines if ln]
    return bool(lines) and all("==" in ln for ln in lines)


# A requirements file that pins every line can still list only the direct
# dependencies (``feast[minimal]==0.62.0`` pulls in dozens more). Only a
# compiled file (pip-compile, uv pip compile: ``# via`` annotations or
# ``--hash=`` lines) is known to carry the whole tree.
_COMPILED_REQUIREMENTS = re.compile(
    r"^\s*#\s+via\b|--hash=|^#.*\b(?:pip-compile|uv pip compile)\b", re.M
)


def discover_manifests(repo: Path) -> list[tuple[str, str, Any]]:
    """(repo-relative path, ecosystem, parser) for every manifest in the tree.

    Walks the checkout without running git in it (an audited repository's
    git config is untrusted), skipping ``.git`` and ``node_modules``. The
    parser is ``"gomod"`` for go.mod files.
    """
    found: list[tuple[str, str, Any]] = []
    for root, dirs, files in os.walk(repo):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            rel = str((Path(root) / name).relative_to(repo))
            if name == "go.mod":
                found.append((rel, "go", "gomod"))
                continue
            hit = manifest_parsers.parser_for_path(rel)
            if hit and hit[0] in OSV_ECOSYSTEM:
                found.append((rel, hit[0], hit[1]))
    return found


def collect_packages(repo: Path) -> tuple[dict[tuple[str, str, str], dict], dict]:
    """Every (OSV ecosystem, package, version) declared in the tree.

    Returns the packages (each with its ``sources`` and ``version_basis``)
    and a stats block: manifests read, files that failed to parse, and
    declarations skipped for lack of an exact version.
    """
    manifests = discover_manifests(repo)
    locked_dirs = {
        (str(Path(rel).parent), eco) for rel, eco, _ in manifests if Path(rel).name in LOCKFILES
    }
    packages: dict[tuple[str, str, str], dict] = {}
    stats = {
        "manifests": 0,
        "unparsed": [],
        "unpinned_skipped": 0,
        "superseded_by_lockfile": 0,
        # manifests with no lockfile beside them: their direct declarations
        # are queried at the declared floor, but the transitive tree is not
        # resolved (owner decision 2026-10-20, option c: reported as a
        # coverage gap now; resolution through deps.dev may follow)
        "unresolved_manifests": [],
    }

    def add(eco: str, name: str, version: str, src: str, basis: str) -> None:
        version = version.strip()
        if not name or not version or not _EXACT_VERSION.match(version) or "${" in version:
            stats["unpinned_skipped"] += 1
            return
        if eco == "Go":
            version = version.removeprefix("v")
        entry = packages.setdefault((eco, name, version), {"sources": [], "version_basis": basis})
        if src not in entry["sources"]:
            entry["sources"].append(src)
        if basis == "locked":  # a lockfile anywhere outranks a manifest floor
            entry["version_basis"] = "locked"

    for rel, eco, parser in manifests:
        name = Path(rel).name
        if name not in LOCKFILES and (str(Path(rel).parent), eco) in locked_dirs:
            stats["superseded_by_lockfile"] += 1
            continue
        try:
            text = (repo / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            stats["unparsed"].append(rel)
            continue
        stats["manifests"] += 1
        osv_eco = OSV_ECOSYSTEM[eco]
        try:
            if parser == "gomod":
                _, deps = parse_gomod(text)
                for path, version, _indirect in deps:
                    add(osv_eco, path, version, rel, "locked")
                m = _GO_TOOLCHAIN.search(text) or _GO_DIRECTIVE.search(text)
                if m:
                    ver = m.group(1)
                    ver = ver if ver.count(".") == 2 else ver + ".0"
                    add(osv_eco, "stdlib", ver, rel, "go-directive")
                continue
            _, deps = parser(text)
        except Exception:  # a malformed file is reported, never fatal
            stats["unparsed"].append(rel)
            continue
        requirements = "requirements" in name.lower()
        pinned_requirements = requirements and _requirements_all_pinned(text)
        # a workflow's action refs are exactly what runs: nothing to resolve
        exact = name in LOCKFILES or pinned_requirements or eco == "actions"
        basis = "locked" if exact else "manifest-floor"
        whole_tree = exact and not (pinned_requirements and not _COMPILED_REQUIREMENTS.search(text))
        if not whole_tree:
            stats["unresolved_manifests"].append(
                {"path": rel, "ecosystem": osv_eco, "declarations": len(deps)}
            )
        for dep_name, version, _indirect in deps:
            add(osv_eco, dep_name, version or "", rel, basis)
    return packages, stats


def _severity_of(vuln: dict) -> str | None:
    """A numeric v3 score when the record has a vector, else its declared word."""
    score = max_score(vuln)
    if score is not None:
        return f"{score:.1f}"
    word = (vuln.get("database_specific") or {}).get("severity")
    return str(word) if word else None


def lookup(
    packages: dict[tuple[str, str, str], dict], client: OsvClient
) -> tuple[list[dict], dict]:
    """Query OSV for every package; returns candidates and lookup provenance."""
    keys = sorted(packages)
    outcome = client.query_batch([Query(*k) for k in keys])
    matched: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    unanswered = 0
    for key, ids in zip(keys, outcome.ids, strict=True):
        if ids is None:
            unanswered += 1
            continue
        for vid in ids:
            matched[vid].append(key)
    details, detail_issues = client.get_vulns(matched)
    # Some databases (Go's, PyPA's) publish no severity; their GHSA or CVE
    # alias usually does. Borrow the highest alias score, as osv-scanner's
    # grouping did, and only fetch the aliases that are needed. Many CVE
    # ids have no OSV record (404): that only leaves the advisory unscored.
    needed = {
        alias
        for vid, vuln in details.items()
        if _severity_of(vuln) is None
        for alias in vuln.get("aliases") or []
        if alias.startswith(("GHSA-", "CVE-")) and alias not in details
    }
    alias_details, alias_issues = client.get_vulns(needed) if needed else ({}, Counter())
    known = {**alias_details, **details}

    def severity(vid: str, vuln: dict) -> tuple[str | None, str]:
        """(value, basis). Malicious packages carry no CVSS: they are critical."""
        if vid.startswith("MAL-"):
            return "CRITICAL", "malicious-package"
        own = max_score(vuln)
        if own is not None:
            return f"{own:.1f}", "cvss-v3"
        borrowed = [
            s
            for a in vuln.get("aliases") or []
            if a in known
            for s in [max_score(known[a])]
            if s is not None
        ]
        if borrowed:
            return f"{max(borrowed):.1f}", "alias-cvss-v3"
        word = (vuln.get("database_specific") or {}).get("severity")
        if word:
            return str(word), "declared"
        alias_words = [
            str((known[a].get("database_specific") or {}).get("severity"))
            for a in vuln.get("aliases") or []
            if a in known and (known[a].get("database_specific") or {}).get("severity")
        ]
        if alias_words:
            return alias_words[0], "alias-declared"
        # no score, vector or severity anywhere: banded medium by the
        # harness rule (dependency-watch), and labelled so it is never
        # mistaken for a scored medium
        return None, "unscored"

    candidates = []
    for vid in sorted(matched):
        vuln = details.get(vid) or {}
        sev, basis = severity(vid, vuln) if vuln else (None, "details-missing")
        if vid.startswith("MAL-"):
            sev, basis = "CRITICAL", "malicious-package"
        for eco, name, version in matched[vid]:
            entry = packages[(eco, name, version)]
            candidates.append(
                {
                    "osv_id": vid,
                    "aliases": vuln.get("aliases") or [],
                    # Red Hat records list their CVEs here, not in aliases
                    "upstream": vuln.get("upstream") or [],
                    "summary": vuln.get("summary") or (vuln.get("details") or "")[:200] or None,
                    "ecosystem": eco,
                    "package": name,
                    "found_version": version,
                    "fixed_version": fixed_version(vuln, name, eco) if vuln else None,
                    "max_severity": sev,
                    "severity_basis": basis,
                    "evidence": "dependency_declared",
                    "version_basis": entry["version_basis"],
                    "sources": list(entry["sources"]),
                    "details_fetched": bool(vuln),
                }
            )
    candidates.sort(key=lambda c: (c["ecosystem"], c["package"], c["osv_id"]))
    # a missing alias only costs a severity, never an advisory, so it is
    # reported but does not degrade the scan's coverage
    issues = Counter(outcome.issues) + Counter(detail_issues)
    provenance = {
        "source": "osv-api",
        "base_url": client.base_url,
        "queried_at": utc_now(),
        "packages_queried": len(keys),
        "packages_by_ecosystem": dict(sorted(Counter(k[0] for k in keys).items())),
        "packages_unanswered": unanswered,
        "advisory_details_missing": sum(detail_issues.values()),
        "alias_records_unavailable": sum(alias_issues.values()),
        "lookup_issues": dict(sorted(issues.items())),
        "status": "degraded" if issues else "complete",
    }
    if keys and unanswered == len(keys):
        provenance["status"] = "failed"
    return candidates, provenance


def _failed_lookup(keys: list, client: OsvClient, status: str, detail: str) -> dict:
    """Provenance for a scan that never reached the API: every package unanswered."""
    return {
        "source": "osv-api",
        "base_url": client.base_url,
        "queried_at": utc_now(),
        "packages_queried": len(keys),
        "packages_by_ecosystem": dict(sorted(Counter(k[0] for k in keys).items())),
        "packages_unanswered": len(keys),
        "advisory_details_missing": 0,
        "alias_records_unavailable": 0,
        "lookup_issues": {status: len(keys)},
        "status": "failed",
        "failure": {"status": status, "detail": detail},
    }


def scan_api(repo: Path, client: OsvClient | None = None) -> dict:
    """Collect packages and look them up. Returns the candidates document body."""
    repo = repo.resolve()
    if not repo.is_dir():
        raise ValueError(f"not a directory: {repo}")
    packages, stats = collect_packages(repo)
    client = client or OsvClient()
    keys = sorted(packages)
    failure = client.probe(Query(*keys[0])) if keys else None
    if failure:
        candidates, provenance = [], _failed_lookup(keys, client, *failure)
    else:
        candidates, provenance = lookup(packages, client)
    provenance.update(
        transitive_coverage="partial" if stats["unresolved_manifests"] else "complete",
        unresolved_manifests=stats["unresolved_manifests"],
        manifests_read=stats["manifests"],
        manifests_unparsed=stats["unparsed"],
        declarations_without_exact_version=stats["unpinned_skipped"],
        manifests_superseded_by_lockfile=stats["superseded_by_lockfile"],
    )
    if stats["unparsed"] and provenance["status"] == "complete":
        provenance["status"] = "degraded"
    return {"provenance": provenance, "candidates": candidates}


def scan(repo: Path, timeout: int = 600, *, client: OsvClient | None = None) -> AdapterResult:
    """Look up the checkout's declared packages through the OSV API.

    Raises ``RuntimeError`` when the API could not be used at all.
    """
    doc = scan_api(repo, client or OsvClient(timeout=timeout))
    prov = doc["provenance"]
    if prov["status"] == "failed":
        detail = (prov.get("failure") or {}).get("detail") or "no package was answered"
        raise RuntimeError(f"OSV API unavailable at {prov['base_url']}: {detail}")
    return build_scan_result(
        str(Path(repo).resolve()),
        "osv-api",
        _candidates_to_findings(doc["candidates"]),
        scanned_at=doc["provenance"]["queried_at"],
        scanner_version="osv-api",
    )


def _tool_version(binary: str):
    try:
        out = subprocess.run(
            [binary, "--version"], capture_output=True, text=True, timeout=15
        ).stdout
        return out.strip().splitlines()[0] if out.strip() else None
    except (subprocess.SubprocessError, OSError):
        return None
