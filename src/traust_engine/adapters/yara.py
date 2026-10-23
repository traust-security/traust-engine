"""Known-malware-family signature candidates via YARA (deterministic pre-scan).

Runs the YARA engine (BSD-3-Clause, invoked as a subprocess) over an
already-materialized blob tree — an exported container rootfs
(secure-container-audit) or an RPM prepared source tree
(secure-rpm-audit) — with an explicitly pinned rule pack, and reduces
its output to normalized FACTS for the audit skills to judge in context.

This is a CANDIDATE GENERATOR, never a finder or verdict of record
(docs/deterministic-inferential-mix.md: deterministic tools route,
gate, tag, or index — never conclude). A YARA match is a true statement
that a byte pattern for a known malware family is present; it is NOT a
confirmed compromise. The audit must judge whether the match is a real
implant vs. a benign carrier (a security tool's own signature corpus, a
test fixture, an EICAR-style sample, a detection rule shipped on purpose)
before promoting a fact to a finding, and must record dismissed facts in
`scanner_correlation`.

Because these are KNOWN-FAMILY signatures, recall is bounded: a clean scan
is not proof of absence, only absence of known families. High precision,
not high recall — a supply-chain tripwire, not a general malware detector.

RULE PACKS ARE A SWAPPABLE INPUT, NEVER A BAKED-IN ASSET — the same
contract as run_opengrep.py. Rules are fetched or referenced at run time
and are deliberately NOT vendored. Sources accepted by --rules:

    /path/to/rules(dir|.yar|.yara)  local rules, used as-is
    https://github.com/...@<SHA>    git repo, shallow-cloned to the cache
                                    at the pinned 40-hex commit SHA

Default (no --rules): the ReversingLabs YARA rules pack pinned below
(MIT — permissive, redistributable; license note carried into the report
for metadata.tools). It ships known-malware-family signatures organized
by family (ransomware/backdoor/trojan/…). Its freshness is watched by
/drift-watch's `yara-rules-pin` row: a frozen pin stops seeing new
families, so the pin is a deliberate, reviewed bump (never auto-advanced).

Usage:
    python3 run_yara.py <target-dir> [--rules SRC ...] [--out FILE]
                        [--timeout SECONDS] [--yara BIN] [--max-file-mb N]

Output defaults to <target-basename>-yara.json in the CWD.
Exit 0 on a completed scan (with or without facts); 1 on tool failure;
2 on usage errors.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from traust_contracts.models import AdapterResult, Location

from traust_engine.adapters._contract_bridge import (
    build_scan_result,
    map_severity,
    utc_now,
)
from traust_engine.assets import harness_version

CACHE_ROOT = Path.home() / ".cache" / "traust-engine"

# Default pack: ReversingLabs YARA rules (known-malware families).
RL_RULES_REPO = "https://github.com/reversinglabs/reversinglabs-yara-rules"
RL_RULES_SHA = "e0a0be54aa1e11ccfd6854e4f19e9476f328fd84"  # develop @ 2026-08
RL_RULES_LICENSE = (
    "ReversingLabs YARA rules: MIT (permissive, "
    "redistributable) — see docs/external-dependencies.md"
)

# A YARA match names a known-malware family — inherently high-signal, but
# still a candidate the audit judges (benign carrier vs. real implant).
DEFAULT_SEVERITY_HINT = "high"

# Rule-declaration line: optional `global`/`private` modifiers, `rule`,
# then the identifier. The opening `{` may sit on the same line or the
# next, and tags (`: tag1 tag2`) are irrelevant to the index, so anchor
# only on the keyword + identifier at line start. Comments (`//`, `/*`)
# never match — their first non-space char isn't `rule`/`global`/`private`.
RULE_DECL_RE = re.compile(r"^\s*(?:global\s+|private\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)\b")

# Carrier trees whose YARA hits are almost always the tool's own signature
# corpus / test fixtures rather than a live implant — tagged, not dropped,
# so the audit can weight them (a detection rule IS supposed to contain the
# byte pattern it detects; see the doctrine note above).
CARRIER_PATH_RE = re.compile(
    r"(^|/)(testdata|test|tests|fixtures?|samples?|examples?|"
    r"yara[-_]?rules?|signatures?|clamav|rules)(/|$)",
    re.IGNORECASE,
)


def discover_rule_files(root: Path) -> list[Path]:
    """Every .yar/.yara file under a resolved rules path (or the file
    itself if a single rule file was given)."""
    if root.is_file():
        return [root] if root.suffix in (".yar", ".yara") else []
    return sorted(p for p in root.rglob("*") if p.is_file() and p.suffix in (".yar", ".yara"))


def build_rule_index(rule_files: list[Path]) -> dict[str, dict]:
    """Map rule_id -> {source_file, category, family} by parsing rule
    declarations. YARA match output gives only the rule id and the scanned
    path, so this pre-index is how a fact recovers which family/category it
    belongs to. `category` = the immediate parent directory (ReversingLabs
    groups by family class: backdoor/ransomware/trojan/…); `family` is
    derived from the rule id's trailing segment."""
    index: dict[str, dict] = {}
    for f in rule_files:
        category = f.parent.name
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            m = RULE_DECL_RE.match(line)
            if not m:
                continue
            rid = m.group(1)
            family = rid.split("_")[-1] if "_" in rid else rid
            index[rid] = {
                "source_file": str(f),
                "category": category,
                "family": family,
            }
    return index


def generate_include_index(rule_files: list[Path], workdir: Path) -> Path:
    """Write a single index .yar that `include`s every rule file, so one
    `yara` invocation compiles the whole pack. Absolute include paths keep
    it independent of cwd."""
    index_path = workdir / "index.yar"
    lines = [f'include "{f.as_posix()}"' for f in rule_files]
    index_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return index_path


def resolve_rules(sources: list[str]) -> list[dict]:
    """Resolve each --rules source to {source, root, sha, license_note}.
    Mirrors run_opengrep.resolve_rules: https-only, immutable 40-hex SHA,
    cache trusted only when HEAD==pin and the worktree is pristine."""
    resolved: list[dict] = []
    if not sources:
        sources = [f"{RL_RULES_REPO}@{RL_RULES_SHA}"]
    for src in sources:
        if src.startswith(("http://", "https://", "git@")):
            m = re.match(
                r"^(?P<url>.+?)@(?P<ref>[A-Za-z0-9._/-]+)$",
                src.replace("://", "\x00", 1).replace("git@", "\x01", 1),
            )
            if m and "/" not in m.group("ref"):
                url = m.group("url").replace("\x00", "://", 1).replace("\x01", "git@", 1)
                ref = m.group("ref")
            else:
                url, ref = src, "HEAD"
            # A movable branch/tag/HEAD silently changes what the scan
            # reports despite a "pinned" claim — require an immutable
            # commit (same rule as run_opengrep; audit E6).
            if not re.fullmatch(r"[0-9a-f]{40}", ref):
                raise SystemExit(
                    f"rules source {src!r}: ref must be a 40-hex commit SHA "
                    "(movable refs change scan results silently)"
                )
            if not url.startswith("https://"):
                raise SystemExit(f"rules source {src!r}: https:// URLs only")
            dest = CACHE_ROOT / f"{Path(url).name}-{ref[:12]}"

            def _clone(_dest=dest, _url=url, _ref=ref) -> None:
                _dest.parent.mkdir(parents=True, exist_ok=True)
                subprocess.run(
                    ["git", "clone", "--quiet", "--", _url, str(_dest)],
                    check=True,
                    env={**os.environ, "GIT_ALLOW_PROTOCOL": "https"},
                )
                subprocess.run(["git", "-C", str(_dest), "checkout", "--quiet", _ref], check=True)

            def _cache_ok(_dest=dest, _ref=ref) -> bool:
                head = subprocess.run(
                    ["git", "-C", str(_dest), "rev-parse", "HEAD"], capture_output=True, text=True
                )
                if head.returncode != 0 or head.stdout.strip() != _ref:
                    return False
                dirty = subprocess.run(
                    ["git", "-C", str(_dest), "status", "--porcelain"],
                    capture_output=True,
                    text=True,
                )
                return dirty.returncode == 0 and not dirty.stdout.strip()

            if not dest.is_dir():
                _clone()
            elif not _cache_ok():
                print(
                    f"[run_yara] rule cache {dest} fails pin/cleanliness "
                    "verification — discarding and re-cloning",
                    file=sys.stderr,
                )
                shutil.rmtree(dest)
                _clone()
            if not _cache_ok():
                raise SystemExit(
                    f"rules source {src!r}: freshly cloned cache still fails "
                    "pin/cleanliness verification — refusing to scan with "
                    "unverifiable rules"
                )
            license_note = (
                RL_RULES_LICENSE
                if url.rstrip("/") == RL_RULES_REPO
                else "verify upstream license before redistribution"
            )
            resolved.append(
                {"source": src, "root": str(dest), "sha": ref, "license_note": license_note}
            )
            continue
        path = Path(src).expanduser().resolve()
        if not path.exists():
            print(f"rules source not found: {src}", file=sys.stderr)
            sys.exit(2)
        resolved.append(
            {
                "source": src,
                "root": str(path),
                "sha": None,
                "license_note": "local rules — license per author",
            }
        )
    return resolved


def parse_matches(stdout: str, target: Path, index: dict[str, dict]) -> list[dict]:
    """Turn `yara -r` output (`<rule_id> <path>` per match line) into
    normalized facts. Scanned with the default namespace and without
    -m/-g/-s, so each line is exactly the rule id, one space, then the
    absolute path — the id has no spaces, so split(' ', 1) is unambiguous."""
    facts: list[dict] = []
    for line in stdout.splitlines():
        if " " not in line.strip():
            continue
        rule_id, path = line.split(" ", 1)
        if not rule_id or not path.strip():
            continue
        try:
            rel = str(Path(path).resolve().relative_to(target))
        except ValueError:
            rel = path
        meta = index.get(rule_id, {})
        facts.append(
            {
                "rule_id": rule_id,
                "family": meta.get("family"),
                "category": meta.get("category"),
                "source_rule_file": meta.get("source_file"),
                "file": rel,
                "severity_hint": DEFAULT_SEVERITY_HINT,
                "match_type": "yara_signature",
                "carrier_path": bool(CARRIER_PATH_RE.search(rel)),
            }
        )
    return facts


def count_regular_files(target: Path) -> int:
    """Regular files under target, not following symlinks (the same tree
    yara -N walks). Bounded best-effort for the stats block."""
    n = 0
    for root, _dirs, files in os.walk(target, followlinks=False):
        n += sum(1 for f in files if not (Path(root) / f).is_symlink())
    return n


def _execute_yara_scan(
    target: Path,
    rule_sources: list[str],
    *,
    timeout: int,
    yara_bin: str,
    max_file_mb: int,
) -> dict[str, Any]:
    """Run yara subprocess and return report dict."""
    yara_version = subprocess.run(
        [yara_bin, "--version"], capture_output=True, text=True
    ).stdout.strip()

    rules = resolve_rules(rule_sources)
    rule_files: list[Path] = []
    for r in rules:
        rule_files.extend(discover_rule_files(Path(r["root"])))
    if not rule_files:
        raise RuntimeError("no .yar/.yara rule files found")

    index = build_rule_index(rule_files)
    with tempfile.TemporaryDirectory(prefix="run_yara_") as tmp:
        index_file = generate_include_index(rule_files, Path(tmp))
        cmd = [
            yara_bin,
            "-r",
            "-w",
            "-N",
            "-z",
            str(max_file_mb * 1024 * 1024),
            str(index_file),
            str(target),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    errors = [ln for ln in proc.stderr.splitlines() if ln.strip()]
    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(f"yara failed (exit {proc.returncode}): {proc.stderr[-500:]}")

    facts = parse_matches(proc.stdout, target, index)
    return {
        "tool": "run_yara",
        "version": harness_version(),
        "yara_version": yara_version,
        "target": str(target),
        "rules": rules,
        "stats": {
            "facts": len(facts),
            "rules_compiled": len(index),
            "rule_files": len(rule_files),
            "files_considered": count_regular_files(target),
            "carrier_facts": sum(1 for f in facts if f["carrier_path"]),
            "engine_errors": len(errors),
        },
        "facts": facts,
        "errors": errors[:100],
    }


def _facts_to_findings(facts: list[dict]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for fact in facts:
        loc = (
            Location(path=fact["file"])
            if Location is not None
            else {
                "path": fact["file"],
            }
        )
        title = f"YARA match: {fact['rule_id']}"
        if fact.get("family"):
            title += f" ({fact['family']})"
        findings.append(
            {
                "id": f"yara/{fact['rule_id']}",
                "title": title,
                "severity": map_severity(fact.get("severity_hint", "high")),
                "locations": [loc],
                "description": (
                    f"category={fact.get('category')} "
                    f"family={fact.get('family')} "
                    f"carrier_path={fact.get('carrier_path')}"
                ),
                "category": fact.get("category", ""),
            }
        )
    return findings


def scan(
    target: Path,
    rules: list[str] | None = None,
    timeout: int = 600,
) -> AdapterResult:
    """Run yara scan and return typed scan result."""
    yara_bin = "yara"
    max_file_mb = 64
    target = target.resolve()
    if not target.is_dir():
        raise ValueError(f"not a directory: {target}")
    if not shutil.which(yara_bin):
        raise FileNotFoundError(f"yara not found on PATH ({yara_bin})")

    try:
        report = _execute_yara_scan(
            target,
            rules or [],
            timeout=timeout,
            yara_bin=yara_bin,
            max_file_mb=max_file_mb,
        )
    except subprocess.TimeoutExpired as e:
        raise TimeoutError(f"yara timed out after {timeout}s") from e

    return build_scan_result(
        str(target),
        "yara",
        _facts_to_findings(report["facts"]),
        scanned_at=utc_now(),
        scanner_version=report.get("yara_version", ""),
    )
