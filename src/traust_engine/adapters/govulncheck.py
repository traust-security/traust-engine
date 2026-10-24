"""Dependency-CVE reachability candidates via govulncheck (reachability stage 1).

Runs `govulncheck -json ./...` against a pinned target clone and reduces
its finding stream to one candidate per OSV advisory, classified by the
most specific evidence govulncheck produced:

    symbol_reachable                — a vulnerable function is on a static
                                      call path from the target's own code
    package_imported_not_observed   — the vulnerable package is imported,
                                      but no call to a vulnerable symbol
                                      was observed by static analysis
    module_required_not_observed    — the module is required by go.mod only

This is a CANDIDATE GENERATOR, never a finder or verdict of record
(docs/deterministic-inferential-mix.md: deterministic tools route,
gate, tag, or index — never conclude). `not_observed` means exactly that:
static analysis did not observe a call path. It does not mean unreachable
— reflection, plugins, and config-driven dispatch are invisible to it —
so downstream consumers may lower a prior on this signal but never
auto-dismiss a finding. Design and staging:
docs/reachability.md.

Usage:
    python3 run_govulncheck.py --repo <clone> [--out <file>]
                               [--timeout SECONDS] [--govulncheck BIN]

Output defaults to <repo-basename>-govulncheck.json in the CWD.
Exit 0 on a completed scan (with or without candidates); 1 on tool failure.
"""

import json
import subprocess
from pathlib import Path
from typing import Any

from traust_contracts.models import AdapterResult, Location

from traust_engine.adapters._contract_bridge import (
    build_scan_result,
    map_severity,
    utc_now,
)
from traust_engine.assets import harness_version as engine_harness_version

REACH_ORDER = [
    "module_required_not_observed",
    "package_imported_not_observed",
    "symbol_reachable",
]


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


def classify(finding):
    """Map one govulncheck finding record to a reachability level."""
    trace = finding.get("trace") or []
    frame = trace[0] if trace else {}
    if frame.get("function"):
        return "symbol_reachable"
    if frame.get("package"):
        return "package_imported_not_observed"
    return "module_required_not_observed"


def trace_symbols(trace):
    """Render a govulncheck trace as compact call-path strings, caller first."""
    out = []
    for frame in reversed(trace):
        fn = frame.get("function")
        if not fn:
            continue
        recv = frame.get("receiver") or ""
        name = f"{recv}.{fn}" if recv else fn
        pkg = frame.get("package") or ""
        pos = frame.get("position") or {}
        loc = f" ({pos['filename']}:{pos['line']})" if pos.get("filename") else ""
        out.append(f"{pkg}.{name}{loc}" if pkg else f"{name}{loc}")
    return out


def iter_records(text):
    """Yield JSON objects from a govulncheck -json stream (a concatenation
    of pretty-printed objects, not JSONL)."""
    decoder = json.JSONDecoder()
    pos, end = 0, len(text)
    while pos < end:
        while pos < end and text[pos].isspace():
            pos += 1
        if pos >= end:
            break
        try:
            rec, pos = decoder.raw_decode(text, pos)
        except json.JSONDecodeError:
            break
        yield rec


def parse_stream(text):
    """Reduce the govulncheck -json stream to per-OSV candidates."""
    osv_meta = {}  # osv id -> advisory metadata
    candidates = {}  # osv id -> candidate dict (most specific evidence wins)
    tool = {}

    for rec in iter_records(text):
        if not isinstance(rec, dict):
            continue
        if "config" in rec:
            cfg = rec["config"]
            tool = {
                "name": cfg.get("scanner_name", "govulncheck"),
                "version": cfg.get("scanner_version"),
                "go_version": cfg.get("go_version"),
                "db": cfg.get("db"),
                "db_last_modified": cfg.get("db_last_modified"),
                "scan_level": cfg.get("scan_level"),
            }
        elif "osv" in rec:
            osv = rec["osv"]
            osv_meta[osv.get("id")] = {
                "aliases": osv.get("aliases") or [],
                "summary": osv.get("summary") or osv.get("details", "")[:200],
            }
        elif "finding" in rec:
            f = rec["finding"]
            osv_id = f.get("osv")
            if not osv_id:
                continue
            level = classify(f)
            trace = f.get("trace") or []
            frame = trace[0] if trace else {}
            cand = candidates.setdefault(
                osv_id,
                {
                    "osv_id": osv_id,
                    "reachability": level,
                    "module": frame.get("module"),
                    "found_version": frame.get("version"),
                    "fixed_version": f.get("fixed_version"),
                    "packages": [],
                    "example_trace": [],
                },
            )
            if REACH_ORDER.index(level) > REACH_ORDER.index(cand["reachability"]):
                cand["reachability"] = level
            pkg = frame.get("package")
            if pkg and pkg not in cand["packages"]:
                cand["packages"].append(pkg)
            if level == "symbol_reachable":
                symbols = trace_symbols(trace)
                # keep the shortest observed call path as the example
                if symbols and (
                    not cand["example_trace"] or len(symbols) < len(cand["example_trace"])
                ):
                    cand["example_trace"] = symbols

    for osv_id, cand in candidates.items():
        meta = osv_meta.get(osv_id, {})
        cand["aliases"] = meta.get("aliases", [])
        cand["summary"] = meta.get("summary", "")

    order = {lvl: i for i, lvl in enumerate(reversed(REACH_ORDER))}
    ranked = sorted(candidates.values(), key=lambda c: (order[c["reachability"]], c["osv_id"]))
    return tool, ranked


def _reachability_to_severity(reachability: str) -> str:
    return {
        "symbol_reachable": "high",
        "package_imported_not_observed": "medium",
        "module_required_not_observed": "low",
    }.get(reachability, "medium")


def _candidates_to_findings(candidates: list[dict]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for cand in candidates:
        locs = []
        for site in cand.get("example_trace", []):
            locs.append(
                Location(path=site, description="call path")
                if Location is not None
                else {"path": site, "description": "call path"}
            )
        for pkg in cand.get("packages", []):
            locs.append(
                Location(path=pkg, description="imported package")
                if Location is not None
                else {"path": pkg, "description": "imported package"}
            )
        desc = (
            f"module={cand.get('module')} "
            f"version={cand.get('found_version')} "
            f"reachability={cand['reachability']}"
        )
        findings.append(
            {
                "id": cand["osv_id"],
                "title": cand.get("summary") or cand["osv_id"],
                "severity": map_severity(_reachability_to_severity(cand["reachability"])),
                "locations": locs,
                "description": desc,
                "category": cand["reachability"],
            }
        )
    return findings


def _run_govulncheck(
    repo: Path,
    timeout: int,
    govulncheck_bin: str,
    *,
    profile_map: dict | None = None,
    freeze: bool = True,
) -> tuple[int, str, str, dict, list]:
    """Execute govulncheck under safe_exec and parse its JSON stream."""
    from traust_engine._util import safe_exec

    cmd = [govulncheck_bin, "-json", "./..."]
    extra_env = {}
    if freeze:
        from traust_engine.toolchain import freeze_env

        extra_env = freeze_env("govulncheck")

    rc, out, err = safe_exec.run(
        cmd,
        "go-scan",
        timeout=timeout,
        cwd=str(repo),
        extra_env=extra_env if extra_env else None,
        profile_map=profile_map,
    )
    tool, candidates = parse_stream(out)
    return rc, out, err, tool, candidates


def scan(
    repo: Path,
    timeout: int = 600,
    govulncheck_bin: str = "govulncheck",
    *,
    freeze: bool = True,
    profile_map: dict | None = None,
) -> AdapterResult:
    """Run govulncheck and return typed scan result.

    *freeze* (default True) injects env vars to prevent DB auto-update
    (govulncheck uses ``GOVULNDB`` for a local DB mirror).
    *profile_map* must come from ``AdaptersOps.safe_exec_profile_map()`` when
    running under a loaded engine; omit only in unit tests.
    """
    repo = repo.resolve()
    if not (repo / "go.mod").exists() and not list(repo.glob("*/go.mod")):
        raise ValueError(f"no go.mod under {repo}")

    rc, _out, err, tool, candidates = _run_govulncheck(
        repo,
        timeout,
        govulncheck_bin,
        profile_map=profile_map,
        freeze=freeze,
    )
    if not tool:
        raise RuntimeError(f"govulncheck produced no scan output (exit {rc}): {err.strip()[:500]}")

    return build_scan_result(
        str(repo),
        "govulncheck",
        _candidates_to_findings(candidates),
        scanned_at=utc_now(),
        scanner_version=tool.get("version", ""),
    )
