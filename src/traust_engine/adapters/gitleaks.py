"""Committed-credential candidates via gitleaks (secret pre-scan stage).

Runs `gitleaks` against a pinned target clone — working tree by default,
full git history with --mode history — and reduces its JSON report to
secret-FREE candidates: location, rule id, gitleaks fingerprint, entropy,
and a `liveness_class` tag that routes testable credential classes to the
validate-findings credential-liveness verifier. The matched secret value
itself is NEVER written to the output: downstream consumers that need it
(the liveness probe) re-read it from the checkout at probe time.

Inline ``gitleaks:allow`` comments in the target are IGNORED
(``--ignore-gitleaks-allow``): the target is the code under audit, and a
suppression it ships for itself is repository content, not an exemption
(docs/adversarial-content-doctrine.md in traust). Candidates on such lines
carry ``inline_allow: true`` so the judge sees the marker and weighs it.

This is a CANDIDATE GENERATOR, never a finder or verdict of record
(docs/deterministic-inferential-mix.md: deterministic tools route,
gate, tag, or index — never conclude). A regex hit may be a test fixture,
an example placeholder, or a revoked credential — the audit/triage agent
weighs it; the liveness verifier upgrades it to evidence.

The default ruleset is resolved via ``locations.gitleaks_config`` (injected
context), ``GITLEAKS_CONFIG`` env, or the bundled ``gitleaks-default.toml``.
Override with ``--config`` on the CLI.

Usage:
    python3 run_gitleaks.py --repo <clone> [--mode dir|history]
                            [--out <file>] [--config <toml>]
                            [--timeout SECONDS] [--gitleaks BIN]

Output defaults to <repo-basename>-gitleaks.json in the CWD.
Exit 0 on a completed scan (with or without candidates); 1 on tool failure.
"""

import contextlib
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from traust_contracts import Locations
from traust_contracts.models import AdapterResult, Location

from traust_engine.adapters._contract_bridge import (
    build_scan_result,
    format_lines,
    map_severity,
    utc_now,
)
from traust_engine.assets import harness_version as engine_harness_version

# gitleaks rule id (prefix) -> credential class the validate-findings
# liveness verifier knows how to probe read-only. Anything unmapped is
# UNTESTABLE by design — the list grows only with the probe registry.
LIVENESS_CLASSES = {
    "aws-access-token": "aws",
    "github-pat": "github",
    "github-fine-grained-pat": "github",
    "github-oauth": "github",
    "github-app-token": "github",
    "gitlab-pat": "gitlab",
    "gitlab-ptt": "gitlab",
    "gitlab-rrt": "gitlab",
    "slack-bot-token": "slack",
    "slack-user-token": "slack",
    "traust-openshift-sha256-token": "openshift",
}


def resolve_gitleaks_config(
    config: Path | None = None,
    loc: Locations | None = None,
) -> Path:
    """Config path: explicit arg → locations → env → bundled default."""
    if config is not None:
        path = config
    else:
        from traust_engine import locations as locs
        from traust_engine.assets import default_gitleaks_config

        raw = loc.gitleaks_config if loc else None
        if raw:
            configured = locs.gitleaks_config_path(loc)
            if configured is None:
                raise ValueError(
                    f"locations.gitleaks_config={raw!r} has no local path form "
                    "(remote URIs are not supported for gitleaks config)"
                )
            path = configured
        else:
            path = default_gitleaks_config()
    if not path.is_file():
        raise ValueError(
            "gitleaks config required (config, locations.gitleaks_config, or bundled default)"
        )
    return path


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


def tool_version(binary):
    try:
        out = subprocess.run([binary, "version"], capture_output=True, text=True, timeout=15).stdout
        return out.strip().splitlines()[0] if out.strip() else None
    except (subprocess.SubprocessError, OSError):
        return None


INLINE_ALLOW_MARKER = "gitleaks:allow"


def _has_inline_allow(finding: dict, repo: Path, path: str, mode: str) -> bool:
    """True when the matched line carries the target's own suppression marker.

    gitleaks redacts only the secret, so the marker survives in ``Line`` /
    ``Match``. Dir mode falls back to reading the line from the checkout;
    only the boolean leaves this function, never line content.
    """
    for key in ("Line", "Match"):
        if INLINE_ALLOW_MARKER in (finding.get(key) or ""):
            return True
    start = finding.get("StartLine")
    if mode != "dir" or not path or not isinstance(start, int) or start < 1:
        return False
    end = finding.get("EndLine") if isinstance(finding.get("EndLine"), int) else start
    try:
        with (repo / path).open(encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                if lineno > end:
                    break
                if lineno >= start and INLINE_ALLOW_MARKER in line:
                    return True
    except OSError:
        return False
    return False


def parse_report(findings: list, repo: Path, mode: str) -> list[dict]:
    """Reduce gitleaks findings to secret-free candidates."""
    candidates = []
    for f in findings:
        rule = f.get("RuleID") or ""
        path = f.get("File") or ""
        with contextlib.suppress(ValueError):
            path = str(Path(path).resolve().relative_to(repo.resolve()))
        cand = {
            "rule_id": rule,
            "description": f.get("Description") or "",
            "path": path,
            "start_line": f.get("StartLine"),
            "end_line": f.get("EndLine"),
            "entropy": f.get("Entropy"),
            # commit:file:rule:line — gitleaks' stable identity; carries
            # no secret material and is the dedup/correlation key
            "fingerprint": f.get("Fingerprint") or "",
            "liveness_class": LIVENESS_CLASSES.get(rule),
            "evidence": "secret_pattern_match",
            "inline_allow": _has_inline_allow(f, repo, path, mode),
        }
        if mode == "history":
            cand["commit"] = f.get("Commit") or None
            cand["commit_date"] = f.get("Date") or None
            # author email routes ownership; the *message* stays out —
            # commit messages are repository content (injection surface)
            cand["author_email"] = f.get("Email") or None
        candidates.append(cand)
    candidates.sort(key=lambda c: (c["path"], c["start_line"] or 0, c["rule_id"], c["fingerprint"]))
    return candidates


def _run_gitleaks(
    repo: Path,
    mode: str,
    config: Path,
    timeout: int,
    gitleaks_bin: str,
) -> list[dict]:
    """Run gitleaks and return raw finding list."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        report_path = Path(tf.name)
    try:
        cmd = [
            gitleaks_bin,
            "git" if mode == "history" else "dir",
            str(repo),
            "--config",
            str(config),
            "--report-format",
            "json",
            "--report-path",
            str(report_path),
            "--redact=100",
            # The target's own gitleaks:allow comments are data under audit,
            # never exemptions; parse_report flags them as inline_allow.
            "--ignore-gitleaks-allow",
            "--exit-code",
            "0",
            "--no-banner",
            "--log-level",
            "error",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0:
            raise RuntimeError(
                f"gitleaks failed (exit {proc.returncode}): {proc.stderr.strip()[:500]}"
            )
        findings = json.loads(report_path.read_text(encoding="utf-8"))
        return findings or []
    finally:
        report_path.unlink(missing_ok=True)


def _describe(cand: dict) -> str:
    text = cand.get("description", "")
    if cand.get("inline_allow"):
        note = (
            "The target marks this line gitleaks:allow; a suppression shipped "
            "by the audited repo is not an exemption, judge the candidate."
        )
        text = f"{text} ({note})" if text else note
    return text


def _candidates_to_findings(candidates: list[dict]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for cand in candidates:
        loc = (
            Location(
                path=cand["path"],
                lines=format_lines(cand.get("start_line"), cand.get("end_line")),
            )
            if Location is not None
            else {
                "path": cand["path"],
                "lines": format_lines(cand.get("start_line"), cand.get("end_line")),
            }
        )
        findings.append(
            {
                "id": f"gitleaks/{cand['rule_id']}",
                "title": cand.get("description") or cand["rule_id"],
                "severity": map_severity("high"),
                "locations": [loc],
                "description": _describe(cand),
                "category": cand.get("rule_id", ""),
            }
        )
    return findings


def scan(
    repo: Path,
    mode: str = "dir",
    config: Path | None = None,
    timeout: int = 900,
    gitleaks_bin: str = "gitleaks",
    *,
    loc: Locations | None = None,
) -> AdapterResult:
    """Run gitleaks and return typed scan result."""
    repo = repo.resolve()
    config = resolve_gitleaks_config(config, loc)
    if not repo.is_dir():
        raise ValueError(f"not a directory: {repo}")

    raw = _run_gitleaks(repo, mode, config, timeout, gitleaks_bin)
    candidates = parse_report(raw, repo, mode)
    return build_scan_result(
        str(repo),
        "gitleaks",
        _candidates_to_findings(candidates),
        scanned_at=utc_now(),
        scanner_version=tool_version(gitleaks_bin) or "",
    )
