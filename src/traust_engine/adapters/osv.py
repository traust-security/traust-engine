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

import json
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
from traust_engine.osv import NugetIds, OsvClient, Query, max_score
from traust_engine.osv.ranges import fixed_for, range_evidence
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


def fixed_version(vuln: dict, pkg_name: str, ecosystem: str, installed: str | None = None):
    """The fixed version that remediates ``installed``, from the OSV affected ranges."""
    return fixed_for(vuln, pkg_name, ecosystem, installed)


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
                        "fixed_version": fixed_version(vuln, name, eco, ver),
                        **range_evidence(vuln, name, eco),
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


# A bare requirement (``requests``, ``flask[async]``) carries no version. The
# shared parser drops those lines, so they are counted here: they are
# declarations the lookup cannot check, never silently absent.
_BARE_REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?$")


def _bare_requirements(text: str) -> list[str]:
    names = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        m = _BARE_REQUIREMENT.match(line) if line and not line.startswith("-") else None
        if m:
            names.append(re.sub(r"[-_.]+", "-", m.group(1)).lower())
    return names


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


_GO_REPLACE = re.compile(
    r"^(?P<old>\S+)(?:\s+(?P<oldv>v\S+))?\s*=>\s*(?P<new>\S+)(?:\s+(?P<newv>v\S+))?\s*$"
)


def gomod_replaces(text: str) -> dict[tuple[str, str | None], tuple[str, str | None]]:
    """``replace`` directives: (old path, old version or None) -> (new, new version).

    A new path starting ``./``, ``../`` or ``/`` is a local directory (version
    None): the module is built from the checkout itself, so it is not a
    published package to look up. The shared ``parse_gomod`` ignores
    ``replace``, hence this reader.
    """
    out: dict[tuple[str, str | None], tuple[str, str | None]] = {}
    in_block = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if line.startswith("replace ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if in_block:
            candidate = line
        elif line.startswith("replace "):
            candidate = line[len("replace ") :]
        else:
            continue
        m = _GO_REPLACE.match(candidate)
        if m:
            out[(m.group("old"), m.group("oldv"))] = (m.group("new"), m.group("newv"))
    return out


def _is_local(path: str) -> bool:
    return path.startswith(("./", "../", "/"))


_POM_DEP = re.compile(r"<dependency>(.*?)</dependency>", re.S)


def _tag(block: str, tag: str) -> str:
    m = re.search(rf"<{tag}>\s*([^<]*?)\s*</{tag}>", block)
    return m.group(1) if m else ""


def declared_scopes(filename: str, text: str) -> dict[str, str]:
    """Names a manifest declares ONLY as test or dev dependencies.

    ``test``: Maven ``<scope>test</scope>`` (in ``<dependencies>`` or
    ``<dependencyManagement>``). ``dev``: npm ``devDependencies``, Cargo
    ``[dev-dependencies]``, Poetry dev-dependencies and non-main groups.
    A name also declared for runtime is not listed. The shared parsers merge
    these sections, so scope is read here (owner decision 2026-10-21: tag
    test and dev dependencies, never skip them).
    """
    runtime: set[str] = set()
    scoped: dict[str, str] = {}
    try:
        if filename == "package.json":
            doc = json.loads(text)
            runtime = {k.lower() for k in (doc.get("dependencies") or {})}
            scoped = {k.lower(): "dev" for k in (doc.get("devDependencies") or {})}
        elif filename == "pom.xml":
            for block in _POM_DEP.findall(text):
                name = f"{_tag(block, 'groupId')}:{_tag(block, 'artifactId')}".lower()
                if _tag(block, "scope") == "test":
                    scoped[name] = "test"
                else:
                    runtime.add(name)
        elif filename in ("Cargo.toml", "pyproject.toml"):
            import tomllib

            doc = tomllib.loads(text)
            if filename == "Cargo.toml":
                runtime = {k.lower() for k in doc.get("dependencies") or {}}
                scoped = {k.lower(): "dev" for k in doc.get("dev-dependencies") or {}}
            else:
                poetry = (doc.get("tool") or {}).get("poetry") or {}
                runtime = {
                    re.sub(r"[-_.]+", "-", k).lower() for k in poetry.get("dependencies") or {}
                }
                dev = dict(poetry.get("dev-dependencies") or {})
                for gname, group in (poetry.get("group") or {}).items():
                    if gname != "main":
                        dev.update((group or {}).get("dependencies") or {})
                scoped = {re.sub(r"[-_.]+", "-", k).lower(): "dev" for k in dev}
    except (ValueError, TypeError, AttributeError):
        return {}
    return {k: v for k, v in scoped.items() if k not in runtime}


def _scope_tag(scopes: set[str] | None) -> str | None:
    """``test`` / ``dev`` when every path to a package is test or dev, else None."""
    if not scopes or "runtime" in scopes:
        return None
    return "test" if scopes == {"test"} else "dev"


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
        # are queried at the declared floor, and the transitive tree is
        # either resolved through deps.dev (resolve_transitive) or reported
        # as a coverage gap (owner decisions 2026-10-20 option c, 2026-10-21)
        "unresolved_manifests": [],
        # per unresolved manifest: the direct declarations that were added
        # (eco, name, version), and the declared names that carry no
        # version, for resolve_transitive
        "unresolved_direct": {},
        "unversioned_direct": {},
        # (manifest, (eco, name, version)) -> runtime / test / dev, so a
        # resolved tree inherits its direct dependency's scope
        "direct_scope": {},
        "unversioned_scope": {},
        # go.mod requires replaced with a directory in the checkout: the
        # project's own modules, not published packages
        "go_replaced_local": 0,
        "go_replaced_module": 0,
    }

    def add(eco: str, name: str, version: str, src: str, basis: str, scope: str = "runtime"):
        version = version.strip()
        if not name or not version or not _EXACT_VERSION.match(version) or "${" in version:
            stats["unpinned_skipped"] += 1
            return None
        if eco == "Go":
            version = version.removeprefix("v")
        entry = packages.setdefault((eco, name, version), {"sources": [], "version_basis": basis})
        if src not in entry["sources"]:
            entry["sources"].append(src)
        if basis == "locked":  # a lockfile anywhere outranks a manifest floor
            entry["version_basis"] = "locked"
        elif entry["version_basis"] == "resolved":
            entry["version_basis"] = basis  # declared outranks resolved
        entry.setdefault("scopes", set()).add(scope)
        stats["direct_scope"][(src, (eco, name, version))] = scope
        return (eco, name, version)

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
                module, deps = parse_gomod(text)
                replaces = gomod_replaces(text)
                for path, version, _indirect in deps:
                    if path == module:
                        continue
                    new = replaces.get((path, version)) or replaces.get((path, None))
                    if new and (_is_local(new[0]) or not new[1]):
                        stats["go_replaced_local"] += 1  # built from the checkout
                        continue
                    if new:  # another module is what gets built
                        stats["go_replaced_module"] += 1
                        path, version = new
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
        scopes = declared_scopes(name, text)

        def scope_of(dep_name: str, scopes=scopes, osv_eco=osv_eco) -> str:
            key = (
                dep_name.lower() if osv_eco != "PyPI" else re.sub(r"[-_.]+", "-", dep_name).lower()
            )
            return scopes.get(key, "runtime")

        added = [
            add(osv_eco, dep_name, version or "", rel, basis, scope_of(dep_name))
            for dep_name, version, _i in deps
        ]
        for (dep_name, _v, _i), k in zip(deps, added, strict=True):
            if k is None and dep_name:
                stats["unversioned_scope"][(rel, osv_eco, dep_name)] = scope_of(dep_name)
        bare = _bare_requirements(text) if requirements else []
        stats["unpinned_skipped"] += len(bare)
        if not whole_tree:
            stats["unresolved_manifests"].append(
                {"path": rel, "ecosystem": osv_eco, "declarations": len(deps) + len(bare)}
            )
            stats["unresolved_direct"][rel] = [k for k in added if k]
            stats["unversioned_direct"][rel] = [
                (osv_eco, n) for (n, _v, _i), k in zip(deps, added, strict=True) if k is None and n
            ] + [(osv_eco, n) for n in bare]
    return packages, stats


def resolve_transitive(packages: dict[tuple[str, str, str], dict], stats: dict, resolver) -> dict:
    """Add the transitive tree of every unresolved manifest through deps.dev.

    Each direct declaration of a manifest without a lockfile is resolved on
    its own; the graph's packages join the lookup with ``version_basis:
    resolved`` and ``resolved_via`` (the direct dependencies that brought
    them in). A manifest moves to ``resolved_manifests`` only when every
    declaration resolved; otherwise it stays unresolved with the reason.
    Returns the ``resolution`` provenance block.
    """
    from traust_engine.depsdev import ATTRIBUTION, LICENSE, SYSTEMS

    direct: dict[str, list] = stats.get("unresolved_direct") or {}
    unversioned: dict[str, list] = stats.get("unversioned_direct") or {}
    # A declared name overrides a resolved version of it where only one
    # version can be installed. pip installs one per environment, and each
    # requirements file is its own environment, so the rule is per file.
    # Maven takes the version the project declares or manages, and parent
    # poms manage it for every module, so the rule is repo-wide. npm and
    # Cargo may install several versions side by side: no rule.
    maven_declared = {n.lower() for (e, n, _v), ent in packages.items() if e == "Maven"}
    pypi_declared: dict[str, set[str]] = {}
    for (e, n, _v), ent in packages.items():
        if e == "PyPI":
            for src in ent["sources"]:
                pypi_declared.setdefault(src, set()).add(re.sub(r"[-_.]+", "-", n).lower())
    block: dict[str, Any] = {
        "source": "deps.dev",
        "base_url": resolver.base_url,
        "resolved_at": utc_now(),
        "license": LICENSE,
        "attribution": ATTRIBUTION,
    }
    wanted = sorted({k for keys in direct.values() for k in keys if k[0] in SYSTEMS})
    bare = sorted({k for names in unversioned.values() for k in names if k[0] in SYSTEMS})
    probe_key = wanted[0] if wanted else ((*bare[0], "0") if bare else None)
    failure = resolver.probe(probe_key) if probe_key else None
    defaults: dict = {}
    if failure:
        results, counts = {}, Counter({failure[0]: len(wanted) + len(bare)})
        block.update(status="failed", failure={"status": failure[0], "detail": failure[1]})
    else:
        # a declaration with no version: what an install gets today
        defaults = resolver.defaults_many(bare) if bare else {}
        for (eco, name), res in defaults.items():
            if not res.ok:
                continue
            version = res.nodes[0][1]
            entry = packages.setdefault(
                (eco, name, version), {"sources": [], "version_basis": "resolved-default"}
            )
            for m, names in unversioned.items():
                if (eco, name) in names and m not in entry["sources"]:
                    entry["sources"].append(m)
                    scope = stats.get("unversioned_scope", {}).get((m, eco, name), "runtime")
                    entry.setdefault("scopes", set()).add(scope)
                    stats.setdefault("direct_scope", {})[(m, (eco, name, version))] = scope
        todo = sorted(
            set(wanted) | {(e, n, r.nodes[0][1]) for (e, n), r in defaults.items() if r.ok}
        )
        results, counts = resolver.resolve_many(todo)
    block["direct_dependencies"] = len(wanted) + len(bare)
    block["defaulted"] = sum(1 for r in defaults.values() if r.ok)
    added = 0
    for key, res in results.items():
        if not res.ok:
            continue
        via = f"{key[1]}@{key[2]}"
        srcs = [m for m, keys in direct.items() if key in keys]
        d = defaults.get((key[0], key[1]))
        if d is not None and d.ok and d.nodes[0][1] == key[2]:  # resolved at the default
            srcs += [
                m for m, names in unversioned.items() if (key[0], key[1]) in names and m not in srcs
            ]
        for name, version, _relation in res.nodes:
            node_srcs = srcs
            if key[0] == "Maven" and name.lower() in maven_declared:
                node_srcs = []
            elif key[0] == "PyPI":
                norm = re.sub(r"[-_.]+", "-", name).lower()
                node_srcs = [m for m in srcs if norm not in pypi_declared.get(m, set())]
            if not node_srcs:
                block["overridden_by_declaration"] = block.get("overridden_by_declaration", 0) + 1
                continue
            entry = packages.get((key[0], name, version))
            if entry is None:
                entry = packages[(key[0], name, version)] = {
                    "sources": [],
                    "version_basis": "resolved",
                    "resolved_via": [],
                }
                added += 1
            if entry["version_basis"] != "resolved":
                continue  # declared or locked: the declaration already covers it
            for src in node_srcs:
                if src not in entry["sources"]:
                    entry["sources"].append(src)
                scope = (stats.get("direct_scope") or {}).get((src, key), "runtime")
                entry.setdefault("scopes", set()).add(scope)
            if via not in entry["resolved_via"]:
                entry["resolved_via"].append(via)
    still, resolved = [], []
    for m in stats["unresolved_manifests"]:
        keys = list(direct.get(m["path"]) or [])
        reasons = Counter()
        if m["ecosystem"] not in SYSTEMS:
            reasons[f"{m['ecosystem']} not resolvable through deps.dev"] += 1
        for eco, name in unversioned.get(m["path"]) or []:
            d = defaults.get((eco, name))
            if d is not None and d.ok:
                keys.append((eco, name, d.nodes[0][1]))
            else:
                reasons[f"no version, deps.dev default {d.status if d else 'not resolved'}"] += 1
        unaccounted = m["declarations"] - len(keys) - sum(reasons.values())
        if unaccounted > 0:
            reasons["declarations without an exact version or floor"] += unaccounted
        for k in keys:
            res = results.get(k)
            st = res.status if res else (failure[0] if failure else "not resolved")
            if st != "ok":
                reasons[f"deps.dev {st}"] += 1
        if reasons:
            still.append({**m, "reason": dict(reasons)})
        else:
            resolved.append({**m, "via": "deps.dev"})
    stats["unresolved_manifests"], stats["resolved_manifests"] = still, resolved
    block.update(
        resolved=counts.get("ok", 0),
        not_found=counts.get("not-found", 0),
        issues={k: v for k, v in sorted(counts.items()) if k not in ("ok", "not-found")},
        cache_hits=sum(1 for r in results.values() if r.cached),
        packages_added=added,
        manifests_resolved=len(resolved),
        manifests_still_unresolved=len(still),
    )
    block.setdefault("status", "degraded" if block["issues"] else "complete")
    return block


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
                    "fixed_version": fixed_version(vuln, name, eco, version) if vuln else None,
                    **range_evidence(vuln, name, eco),
                    "max_severity": sev,
                    "severity_basis": basis,
                    "evidence": "dependency_declared",
                    "version_basis": entry["version_basis"],
                    "sources": list(entry["sources"]),
                    **(
                        {"resolved_via": list(entry["resolved_via"])}
                        if entry.get("resolved_via")
                        else {}
                    ),
                    **(
                        {"dependency_scope": tag}
                        if (tag := _scope_tag(entry.get("scopes")))
                        else {}
                    ),
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
    # NuGet ids OSV only answered under nuget.org's casing (written -> published)
    if recased := dict(getattr(client, "recased", None) or {}):
        provenance["nuget_ids_recased"] = dict(sorted(recased.items()))
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


def scan_api(repo: Path, client: OsvClient | None = None, resolver=None) -> dict:
    """Collect packages and look them up. Returns the candidates document body.

    With a ``resolver`` (``traust_engine.depsdev.DepsDevClient``), manifests
    without a lockfile have their transitive tree resolved first.
    """
    repo = repo.resolve()
    if not repo.is_dir():
        raise ValueError(f"not a directory: {repo}")
    packages, stats = collect_packages(repo)
    resolution = resolve_transitive(packages, stats, resolver) if resolver else None
    client = client or OsvClient(nuget_ids=NugetIds())
    keys = sorted(packages)
    failure = client.probe(Query(*keys[0])) if keys else None
    if failure:
        candidates, provenance = [], _failed_lookup(keys, client, *failure)
    else:
        candidates, provenance = lookup(packages, client)
    provenance.update(
        transitive_coverage="partial" if stats["unresolved_manifests"] else "complete",
        unresolved_manifests=stats["unresolved_manifests"],
        resolved_manifests=stats.get("resolved_manifests") or [],
        manifests_read=stats["manifests"],
        manifests_unparsed=stats["unparsed"],
        declarations_without_exact_version=stats["unpinned_skipped"],
        go_requires_replaced_locally=stats.get("go_replaced_local", 0),
        go_requires_replaced_by_module=stats.get("go_replaced_module", 0),
        manifests_superseded_by_lockfile=stats["superseded_by_lockfile"],
    )
    if resolution is not None:
        provenance["resolution"] = resolution
    if stats["unparsed"] and provenance["status"] == "complete":
        provenance["status"] = "degraded"
    return {"provenance": provenance, "candidates": candidates}


def scan(repo: Path, timeout: int = 600, *, client: OsvClient | None = None) -> AdapterResult:
    """Look up the checkout's declared packages through the OSV API.

    Raises ``RuntimeError`` when the API could not be used at all.
    """
    doc = scan_api(repo, client or OsvClient(timeout=timeout, nuget_ids=NugetIds()))
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
