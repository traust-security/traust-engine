"""Container-image language packages through OSV (secure-container-audit).

Reads a **syft JSON** SBOM of an image and looks its *language* packages
(npm, PyPI, Maven, Go modules including the Go standard library, Cargo,
RubyGems, NuGet) up through the shared OSV client, reusing the dependency
pre-scan's ``lookup``. OS packages (rpm, deb, apk…) are never sent: grype,
with the distribution's own security data, owns them (owner decision
2026-10-20, option b).

**A language package installed by an OS package is skipped too.** In a Red
Hat image most Python and npm packages come from RPMs (``python3-urllib3``
puts urllib3 under ``/usr/lib/python3.9``). Red Hat backports fixes into
those RPMs without changing the upstream version, so an upstream lookup
would report CVEs the RPM already fixes; grype's Red Hat data covers them.
syft records that ownership as ``ownership-by-file-overlap`` relationships,
which CycloneDX output drops, hence the syft JSON input. On
``ubi9/python-311`` 216 of 218 language packages were RPM-installed
(measured 2026-10-20).

``mark_grype_duplicates`` tags each candidate that grype also reported for
the same package (same purl identity) and the same advisory (by OSV id,
alias or upstream id), so a report adds only what OSV found beyond grype.

Air-gapped deployments run osv-scanner offline instead: ``write_cyclonedx``
writes the filtered packages as a CycloneDX file osv-scanner reads with
``-L`` (osv-scanner itself cannot see ownership), and ``parse_offline``
maps its result back to the image paths.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from traust_engine.adapters.osv import _failed_lookup, fixed_version, lookup
from traust_engine.osv import OsvClient, Query

# purl type -> OSV ecosystem
PURL_ECOSYSTEM = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "golang": "Go",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "nuget": "NuGet",
}
OS_PACKAGE_TYPES = frozenset({"rpm", "deb", "apk", "alpm", "portage"})
OWNERSHIP = "ownership-by-file-overlap"
_VERSIONED = re.compile(r"^v?[0-9]")


class SbomFormatError(ValueError):
    """The input is not a syft JSON SBOM."""


def parse_purl(purl: str) -> tuple[str, str, str] | None:
    """(OSV ecosystem, package name, version) for a supported language purl."""
    if not purl or not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("?", 1)[0].split("#", 1)[0]
    ptype, _, rest = body.partition("/")
    eco = PURL_ECOSYSTEM.get(ptype.lower())
    if not eco:
        return None
    path, _, version = rest.rpartition("@") if "@" in rest else (rest, "", "")
    parts = [unquote(p) for p in path.split("/") if p]
    if not parts:
        return None
    version = unquote(version)
    if eco == "Maven":
        if len(parts) < 2:
            return None
        name = f"{parts[-2]}:{parts[-1]}"
    elif eco == "PyPI":
        name = re.sub(r"[-_.]+", "-", parts[-1]).lower()
    else:
        name = "/".join(parts)
    if eco == "Go":
        version = version.removeprefix("v")
        if name == "stdlib":
            version = version.removeprefix("go")
    return eco, name, version


def load_syft(path: Path) -> dict:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or "artifacts" not in doc or "artifactRelationships" not in doc:
        raise SbomFormatError(
            f"{path} is not a syft JSON SBOM (syft -o syft-json): CycloneDX and SPDX "
            "drop the file-ownership relationships the scan needs"
        )
    return doc


def collect_sbom_packages(doc: dict) -> tuple[dict[tuple[str, str, str], dict], dict]:
    """Language packages to look up, and what was skipped and why."""
    artifacts = {a.get("id"): a for a in doc.get("artifacts") or [] if isinstance(a, dict)}
    owned = {
        r.get("child")
        for r in doc.get("artifactRelationships") or []
        if r.get("type") == OWNERSHIP
        and (artifacts.get(r.get("parent")) or {}).get("type") in OS_PACKAGE_TYPES
    }
    packages: dict[tuple[str, str, str], dict] = {}
    stats: dict[str, Any] = {
        "artifacts": len(artifacts),
        "os_packages": 0,
        "language_packages": 0,
        "skipped_os_installed": 0,
        "skipped_os_installed_by_type": Counter(),
        "skipped_unversioned": 0,
        "unsupported_types": Counter(),
    }
    for aid, art in artifacts.items():
        atype = art.get("type") or ""
        if atype in OS_PACKAGE_TYPES:
            stats["os_packages"] += 1
            continue
        parsed = parse_purl(art.get("purl") or "")
        if parsed is None:
            stats["unsupported_types"][atype or "unknown"] += 1
            continue
        stats["language_packages"] += 1
        if aid in owned:
            stats["skipped_os_installed"] += 1
            stats["skipped_os_installed_by_type"][atype] += 1
            continue
        eco, name, version = parsed
        if not _VERSIONED.match(version):  # UNKNOWN, (devel): nothing to look up
            stats["skipped_unversioned"] += 1
            continue
        entry = packages.setdefault((eco, name, version), {"sources": [], "version_basis": "sbom"})
        for loc in art.get("locations") or []:
            p = (loc or {}).get("path")
            if p and p not in entry["sources"]:
                entry["sources"].append(p)
    stats["skipped_os_installed_by_type"] = dict(stats["skipped_os_installed_by_type"])
    stats["unsupported_types"] = dict(stats["unsupported_types"])
    return packages, stats


def _with_stats(provenance: dict, stats: dict, doc: dict) -> dict:
    provenance.update(
        input="syft-json",
        image=((doc.get("source") or {}).get("metadata") or {}).get("userInput")
        or (doc.get("source") or {}).get("name"),
        sbom_artifacts=stats["artifacts"],
        os_packages_left_to_grype=stats["os_packages"],
        language_packages=stats["language_packages"],
        skipped_os_installed=stats["skipped_os_installed"],
        skipped_os_installed_by_type=stats["skipped_os_installed_by_type"],
        skipped_unversioned=stats["skipped_unversioned"],
        unsupported_types=stats["unsupported_types"],
    )
    return provenance


def scan_sbom(sbom: Path | dict, client: OsvClient | None = None) -> dict:
    """Look an image's non-OS-installed language packages up through the OSV API."""
    doc = sbom if isinstance(sbom, dict) else load_syft(sbom)
    packages, stats = collect_sbom_packages(doc)
    client = client or OsvClient()
    keys = sorted(packages)
    failure = client.probe(Query(*keys[0])) if keys else None
    if failure:
        candidates, provenance = [], _failed_lookup(keys, client, *failure)
    else:
        candidates, provenance = lookup(packages, client)
    return {"provenance": _with_stats(provenance, stats, doc), "candidates": candidates}


# -- dedupe against grype ------------------------------------------------------


def _ids(c: dict) -> set[str]:
    return {c.get("osv_id") or "", *(c.get("aliases") or []), *(c.get("upstream") or [])} - {""}


def mark_grype_duplicates(candidates: list[dict], grype_doc: dict) -> dict:
    """Tag ``also_in_grype`` on each candidate; return counts."""
    seen: dict[tuple[str, str, str], set[str]] = {}
    for m in grype_doc.get("matches") or []:
        art, vuln = m.get("artifact") or {}, m.get("vulnerability") or {}
        key = parse_purl(art.get("purl") or "")
        if key is None:
            continue
        ids = seen.setdefault(key, set())
        ids.add(vuln.get("id") or "")
        ids.update(r.get("id") or "" for r in m.get("relatedVulnerabilities") or [])
    dup = 0
    for c in candidates:
        hit = bool(_ids(c) & seen.get((c["ecosystem"], c["package"], c["found_version"]), set()))
        c["also_in_grype"] = hit
        dup += hit
    return {"also_in_grype": dup, "osv_only": len(candidates) - dup}


# -- air-gapped: osv-scanner offline on the filtered packages ------------------

_PURL_TYPE = {v: k for k, v in PURL_ECOSYSTEM.items()}


def _purl(eco: str, name: str, version: str) -> str:
    ptype = _PURL_TYPE[eco]
    if eco == "Maven":
        group, _, artifact = name.partition(":")
        return f"pkg:maven/{group}/{artifact}@{version}"
    if eco == "Go":
        version = f"go{version}" if name == "stdlib" else f"v{version}"
    if eco == "npm" and name.startswith("@"):
        name = "%40" + name[1:]
    return f"pkg:{ptype}/{name}@{version}"


def write_cyclonedx(packages: dict[tuple[str, str, str], dict], path: Path) -> Path:
    """The filtered packages as a CycloneDX file (name must end ``.cdx.json``)."""
    if not str(path).endswith(".cdx.json"):
        raise ValueError("osv-scanner recognises a CycloneDX file only by a .cdx.json name")
    components = [
        {"type": "library", "name": n, "version": v, "purl": _purl(e, n, v)}
        for e, n, v in sorted(packages)
    ]
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": components}
    Path(path).write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    return Path(path)


def run_offline(binary: str, cdx: Path, timeout: int) -> tuple[subprocess.CompletedProcess, str]:
    """osv-scanner on the filtered CycloneDX, offline (local OSV database only)."""
    from traust_engine.toolchain import freeze_flags

    flags = freeze_flags("osv-scanner")  # --offline: never phones home
    cmd = [binary, "scan", "source", "-L", str(cdx), "--format", "json", *flags]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return proc, " ".join(cmd)


def parse_offline(doc: dict, packages: dict[tuple[str, str, str], dict]) -> list[dict]:
    """osv-scanner's result as candidates, with the image paths restored."""
    out = []
    for result in doc.get("results") or []:
        for entry in result.get("packages") or []:
            pkg = entry.get("package") or {}
            eco, name, ver = (
                pkg.get("ecosystem") or "",
                pkg.get("name") or "",
                pkg.get("version") or "",
            )
            if eco == "PyPI":
                name = re.sub(r"[-_.]+", "-", name).lower()
            if eco == "Go":
                ver = ver.removeprefix("v").removeprefix("go")
            src = (packages.get((eco, name, ver)) or {}).get("sources") or []
            groups = {
                vid: g.get("max_severity")
                for g in entry.get("groups") or []
                for vid in g.get("ids") or []
            }
            for vuln in entry.get("vulnerabilities") or []:
                vid = vuln.get("id")
                if not vid:
                    continue
                out.append(
                    {
                        "osv_id": vid,
                        "aliases": vuln.get("aliases") or [],
                        "upstream": vuln.get("upstream") or [],
                        "summary": vuln.get("summary") or (vuln.get("details") or "")[:200] or None,
                        "ecosystem": eco,
                        "package": name,
                        "found_version": ver,
                        "fixed_version": fixed_version(vuln, pkg.get("name") or name, eco),
                        "max_severity": groups.get(vid),
                        "severity_basis": "osv-scanner",
                        "evidence": "dependency_declared",
                        "version_basis": "sbom",
                        "sources": list(src),
                    }
                )
    return sorted(out, key=lambda c: (c["ecosystem"], c["package"], c["osv_id"]))
