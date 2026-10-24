"""Container/SBOM vulnerability candidates via grype (SCA stage).

Runs ``grype`` against an SBOM (CycloneDX/SPDX JSON) or a directory and
reduces its JSON output to normalised candidates — one per (CVE, package)
pair — with severity, fixed-in version, and location metadata.

This is a CANDIDATE GENERATOR, never a finder or verdict of record.
A matched CVE is context for the audit/triage agent to weigh — the
vulnerable code path may be unreachable or the package unused.

Usage:
    python3 -m traust_engine.adapters.grype --target <sbom-or-dir> [--out FILE]
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from traust_contracts.models import AdapterResult

from traust_engine.adapters._contract_bridge import (
    build_scan_result,
    map_severity,
    utc_now,
)


def _tool_version(binary: str) -> str | None:
    try:
        out = subprocess.run(
            [binary, "--version"], capture_output=True, text=True, timeout=15
        ).stdout
        import re

        m = re.search(r"(\d+\.\d+\.\d+)", out)
        return m.group(1) if m else None
    except (subprocess.SubprocessError, OSError):
        return None


def _run_grype(
    target: str,
    timeout: int,
    grype_bin: str,
    *,
    freeze: bool = True,
    output_format: str = "json",
) -> dict[str, Any]:
    from traust_engine.toolchain import freeze_env

    env = dict(os.environ)
    if freeze:
        env.update(freeze_env("grype"))

    cmd = [grype_bin, target, "-o", output_format]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"grype failed (exit {proc.returncode}): {proc.stderr.strip()[:500]}")
    return json.loads(proc.stdout)


def _parse_matches(doc: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for match in doc.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        related = match.get("relatedVulnerabilities", [])

        vuln_id = vuln.get("id", "UNKNOWN")
        severity_hint = vuln.get("severity", "unknown").lower()
        description = vuln.get("description", "")
        if not description and related:
            description = related[0].get("description", "")

        fixed_in = ", ".join(vuln.get("fix", {}).get("versions", [])) or None

        pkg_name = artifact.get("name", "")
        pkg_version = artifact.get("version", "")
        pkg_type = artifact.get("type", "")
        locations = artifact.get("locations", [])

        loc_dicts = []
        for loc in locations:
            loc_dicts.append(
                {
                    "path": loc.get("path", ""),
                }
            )
        if not loc_dicts:
            loc_dicts.append({"path": f"{pkg_type}:{pkg_name}"})

        cwes = []
        for url in vuln.get("urls", []):
            if "cwe.mitre.org" in url:
                import re

                m = re.search(r"CWE-(\d+)", url)
                if m:
                    cwes.append(f"CWE-{m.group(1)}")

        remediation = f"Upgrade {pkg_name} to {fixed_in}" if fixed_in else ""

        findings.append(
            {
                "id": f"{vuln_id}:{pkg_name}@{pkg_version}",
                "title": f"{vuln_id} in {pkg_name} {pkg_version}",
                "severity": map_severity(severity_hint),
                "cwes": cwes,
                "locations": loc_dicts,
                "description": description[:2000],
                "remediation": remediation,
                "category": "dependency_vulnerability",
            }
        )
    return findings


def scan(
    target: str | Path,
    timeout: int = 600,
    grype_bin: str = "grype",
    *,
    freeze: bool = True,
) -> AdapterResult:
    """Run grype and return typed scan result.

    *target* can be an SBOM path (``sbom:<path>``) or a directory.
    *freeze* (default True) disables grype's DB auto-update.
    """
    target_str = str(target)
    doc = _run_grype(target_str, timeout, grype_bin, freeze=freeze)

    return build_scan_result(
        target_str,
        "grype",
        _parse_matches(doc),
        scanned_at=utc_now(),
        scanner_version=_tool_version(grype_bin) or "",
    )
