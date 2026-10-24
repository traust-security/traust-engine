"""Semantic pattern/taint candidates via opengrep (deterministic pre-scan).

Runs the opengrep engine (LGPL-2.1, invoked as a subprocess) over a target
checkout with an explicitly pinned ruleset and reduces its JSON output to
normalized FACTS for the audit skills to judge in repository context.

This is a CANDIDATE GENERATOR, never a finder or verdict of record
(docs/deterministic-inferential-mix.md: deterministic tools route,
gate, tag, or index — never conclude). A pattern or taint match is a true
statement about the code's shape, not a vulnerability: the audit must judge
reachability, sanitization, and attacker control before promoting a fact to
a finding, and must record dismissed facts in `scanner_correlation`.

RULE PACKS ARE A SWAPPABLE INPUT, NEVER A BAKED-IN ASSET. Rules are fetched
or referenced at run time and are deliberately NOT vendored into this
repository — every currently available public pack carries licensing that
restricts commercial redistribution (see docs/external-dependencies.md,
"Commercialization assessment"). Sources accepted by --rules:

    /path/to/rules(.yaml|dir)      local rules, used as-is
    https://github.com/...[@SHA]   git repo, shallow-cloned to the cache at
                                   the pinned SHA (defaults to the pin below)
    p/<pack> | r/<ruleset>         Semgrep registry shorthand — allowed for
                                   internal runs; license varies per pack

Default (no --rules): the traust-authored pack bundled in this package
(``traust_engine/data/secure-code-audit/opengrep-rules``), unless
``locations.opengrep_rules`` points elsewhere, filtered to the language
directories present in the target. The bundled copy is the only copy: no
consumer needs to configure it. The opengrep-rules fork remains
available as an internal-run supplement:
`--rules https://github.com/opengrep/opengrep-rules@<sha>` (its license
note is carried into the output for metadata.tools). `--config auto` is
never used and the literal source "auto" is rejected: it fetches
Semgrep-registry rules with no per-pack license accounting.

Usage:
    python3 run_opengrep.py <target-dir> [--rules SRC ...] [--out FILE]
                            [--timeout SECONDS] [--opengrep BIN]

Output defaults to <target-basename>-opengrep.json in the CWD.
Exit 0 on a completed scan (with or without facts); 1 on tool failure;
2 on usage errors.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from traust_contracts import Locations, RulePackAllowlist
from traust_contracts.models import AdapterResult, EvidenceBlock, Location

from traust_engine.adapters._contract_bridge import (
    build_scan_result,
    format_lines,
    map_severity,
    utc_now,
)
from traust_engine.assets import default_rule_pack_dir, harness_version

try:
    import yaml
except ImportError:  # supplemental packs simply stay off
    yaml = None

CACHE_ROOT = Path.home() / ".cache" / "traust-engine"


def resolve_rule_pack_dir(
    pack: Path | None = None,
    loc: Locations | None = None,
) -> Path:
    """Rule pack directory: explicit arg → locations.opengrep_rules → bundled default."""
    if pack is not None:
        path = pack
    else:
        from traust_engine import locations as locs

        raw = loc.opengrep_rules if loc else None
        if raw:
            configured = locs.opengrep_rules_dir(loc)
            if configured is None:
                raise ValueError(
                    f"locations.opengrep_rules={raw!r} has no local path form "
                    "(remote URIs are not supported for the rule pack directory)"
                )
            path = configured
        else:
            path = default_rule_pack_dir()
    if not path.is_dir():
        raise ValueError(
            "opengrep rule pack required (rule_pack, locations.opengrep_rules, or bundled default)"
        )
    return path


TRAUST_PACK_LICENSE = (
    "traust-authored pack: our IP, licensed with the engine, no external restrictions"
)

# Optional internal-run supplement (never the default):
FORK_RULES_REPO = "https://github.com/opengrep/opengrep-rules"
FORK_RULES_SHA = "f1d2b562b414783763fd02a6ed2736eaed622efa"  # 2026-07 pin
FORK_RULES_LICENSE = (
    "LGPL-2.1 + Commons Clause (no-Sell): internal use "
    "OK, commercial redistribution restricted — see "
    "docs/external-dependencies.md"
)
# Optional internal-run supplement (never the default): a crypto /
# crypto-impl / PQC / runtime-security pack, ~500 Semgrep-YAML rules
# across 9 languages. MIT — the least restrictive pack available to us
# (the opengrep-rules fork carries a no-Sell clause; Semgrep-maintained
# registry rules are internal-use-only), so unlike those it may be
# redistributed and used commercially with attribution.
#
# NOT DEFAULT, AND NOT ON A PROMOTION PATH BY DEFAULT. The traust rule pack
# is calibrated against the campaign's triage-ledger ground truth; this
# one is not calibrated against anything of ours. Promotion requires the
# opengrep-ruleset-plan gate (>=3 rediscoveries + precision >~50%), per
# category. Stage A ran 2026-08-06/07 over 453 crypto-CWE TPs in
# argus-covered languages across 263 repos: 16 TLS/cert-validation rules
# clear the rediscovery gate; 15 are enabled in
# config/rule-pack-allowlist.yaml (go-crypto-tls-version held back); 19 rules
# in 4 families are 86% of
# volume and are excluded from any audit path. Its C/C++/C#/Rust rules
# are UNTESTABLE here — not for want of confirmed TPs (rust 42, c 10,
# cpp 9, csharp 7) but because no argus-covered CWE spans the 3 repos
# the gate needs there. Enable a calibrated subset with --rule-allow;
# enabling the pack wholesale would add ~143 findings/repo.
ARGUS_RULES_REPO = "https://github.com/smith-xyz/argus-observe-rules"
ARGUS_RULES_SHA = "2a94aebee9a26a7e0325582330c4eed232b984fb"  # 2026-08-05 pin
ARGUS_RULES_LICENSE = (
    "MIT (c) 2026 Argus Observe Rules Contributors: "
    "internal use, redistribution and commercial use "
    "permitted with attribution — see "
    "docs/external-dependencies.md"
)

REGISTRY_LICENSE = (
    "Semgrep registry pack: license varies per pack; "
    "Semgrep-maintained packs are restrictively licensed — "
    "see docs/external-dependencies.md"
)

TEST_PATH_RE = re.compile(r"(^|/)(tests?|e2e|examples?|testdata|hack)(/|$)")
EXCLUDES = ("vendor", "node_modules", "third_party", "_output", ".git")

SEVERITY_HINT = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}

# target file extensions -> opengrep-rules language directory names
LANG_DIRS = {
    ".go": "go",
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".rb": "ruby",
    ".c": "c",
    ".h": "c",
    ".rs": "rust",
    ".php": "php",
    ".cs": "csharp",
    ".scala": "scala",
    ".kt": "kotlin",
    ".swift": "swift",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".tf": "terraform",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".sh": "bash",
    ".html": "html",
    ".sol": "solidity",
}


def detect_language_dirs(target: Path) -> set[str]:
    dirs: set[str] = set()
    for path in target.rglob("*"):
        if not path.is_file():
            continue
        parts = path.relative_to(target).parts
        if parts and parts[0] in EXCLUDES:
            continue
        lang = LANG_DIRS.get(path.suffix)
        if lang:
            dirs.add(lang)
    return dirs


# Below this many traust rule pack rules for a detected language, the semantic
# pre-scan cannot meaningfully seed the review — audit skills switch the
# manual lanes for that language into the coverage-adaptive assertive
# posture (see secure-code-audit SKILL.md). 8 = two-thirds of the Go
# baseline (12); tune only alongside the language-coverage plan.
THIN_RULE_THRESHOLD = 8


def pack_rule_counts(pack: Path | None = None, *, loc: Locations | None = None) -> dict[str, int]:
    """'- id:' rule count per traust rule pack language directory."""
    counts: dict[str, int] = {}
    pack = resolve_rule_pack_dir(pack, loc)
    if not pack or not pack.is_dir():
        return counts
    for d in sorted(pack.iterdir()):
        if not d.is_dir():
            continue
        n = 0
        for y in list(d.glob("*.yaml")) + list(d.glob("*.yml")):
            n += sum(
                1
                for line in y.read_text(encoding="utf-8").splitlines()
                if line.strip().startswith("- id:")
            )
        counts[d.name] = n
    return counts


def coverage_block(target: Path, *, loc: Locations | None = None) -> dict:
    """Deterministic pre-scan coverage signal: which languages the repo
    contains vs how many traust rule pack rules exist for each. Consumed by the
    audit skills to decide the coverage-adaptive assertive posture —
    the block states facts; the posture decision lives in the skills."""
    # Manifest/IaC languages have their own deterministic scanners
    # (scan_k8s_hardening, run_checkov) — excluded here so they don't
    # read as semantic-pre-scan gaps.
    non_code = {"yaml", "html", "terraform"}
    detected = sorted(detect_language_dirs(target) - non_code)
    counts = pack_rule_counts(loc=loc)
    per_lang = {lang: counts.get(lang, 0) for lang in detected}
    return {
        "detected_languages": detected,
        "traust_rules_by_language": per_lang,
        "thin_threshold": THIN_RULE_THRESHOLD,
        "thin_languages": sorted(
            lang for lang, n in per_lang.items() if 0 < n < THIN_RULE_THRESHOLD
        ),
        "uncovered_languages": sorted(lang for lang, n in per_lang.items() if n == 0),
    }


def resolve_rules(
    sources: list[str],
    target: Path,
    pack: Path | None = None,
    *,
    loc: Locations | None = None,
) -> list[dict]:
    """Resolve each --rules source to {source, config_paths, sha, license}."""
    resolved = []
    pack = resolve_rule_pack_dir(pack, loc)
    if not sources:
        langs = detect_language_dirs(target)
        lang_paths = [str(pack / d) for d in sorted(langs) if (pack / d).is_dir()]
        resolved.append(
            {
                "source": "traust rule pack",
                "config": lang_paths or [str(pack)],
                "sha": None,
                "license_note": TRAUST_PACK_LICENSE,
            }
        )
        return resolved
    for src in sources:
        if src.strip() == "auto":
            print(
                "refusing '--rules auto': registry auto-fetch has no "
                "per-pack license accounting (see "
                "docs/external-dependencies.md)",
                file=sys.stderr,
            )
            sys.exit(2)
        if re.match(r"^[pr]/[\w./-]+$", src):
            resolved.append(
                {
                    "source": src,
                    "config": [src],
                    "sha": None,
                    "license_note": REGISTRY_LICENSE,
                }
            )
            continue
        if src.startswith(("http://", "https://", "git@")):
            try:
                url, ref = pinned_rules_source(src)
            except ValueError as e:
                raise SystemExit(str(e)) from None
            dest = rules_cache_dir(url, ref)

            def _clone(_dest=dest, _url=url, _ref=ref) -> None:
                _dest.parent.mkdir(parents=True, exist_ok=True)
                subprocess.run(
                    ["git", "clone", "--quiet", "--", _url, str(_dest)],
                    check=True,
                    env={**os.environ, "GIT_ALLOW_PROTOCOL": "https"},
                )
                if _ref != "HEAD":
                    subprocess.run(
                        ["git", "-C", str(_dest), "checkout", "--quiet", _ref], check=True
                    )

            def _cache_ok(_dest=dest, _ref=ref) -> bool:
                """A cached rule dir is trusted ONLY when its HEAD equals
                the pinned ref AND the worktree is pristine — otherwise
                a prior hostile-repo scan (or any local edit) could have
                poisoned the rules while the report still records the
                pinned SHA (self-audit example finding ID)."""
                head = subprocess.run(
                    ["git", "-C", str(_dest), "rev-parse", "HEAD"],
                    capture_output=True,
                    text=True,
                )
                if head.returncode != 0:
                    return False
                if _ref != "HEAD" and head.stdout.strip() != _ref:
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
                    f"[run_opengrep] rule cache {dest} fails pin/"
                    f"cleanliness verification — discarding and "
                    f"re-cloning",
                    file=sys.stderr,
                )
                shutil.rmtree(dest)
                _clone()
            if not _cache_ok():
                raise SystemExit(
                    f"rules source {src!r}: freshly cloned cache still "
                    f"fails pin/cleanliness verification — refusing to "
                    "scan with unverifiable rules"
                )
            sha = subprocess.run(
                ["git", "-C", str(dest), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            configs = [str(dest)]
            # Pack layouts differ. opengrep-rules puts language dirs at
            # the repo root; argus nests them under rules/languages/ and
            # ships a sibling tests/ tree of deliberately-vulnerable
            # fixtures. Pointing the config at the repo root would load
            # that fixture tree as scan input — scope to the rules
            # subtree, then filter to the target's languages as usual.
            root = rules_root(url, dest)
            if root != dest:
                configs = [str(root)]
            if url.rstrip("/").endswith(("opengrep-rules", "argus-observe-rules")):
                langs = detect_language_dirs(target)
                lang_paths = [str(root / d) for d in sorted(langs) if (root / d).is_dir()]
                if lang_paths:
                    configs = lang_paths
            resolved.append(
                {
                    "source": src,
                    "config": configs,
                    "sha": sha,
                    "license_note": ARGUS_RULES_LICENSE
                    if src.startswith(ARGUS_RULES_REPO)
                    else FORK_RULES_LICENSE
                    if url.rstrip("/").endswith("opengrep-rules")
                    else "verify upstream license before redistribution",
                }
            )
            continue
        path = Path(src).expanduser().resolve()
        if not path.exists():
            print(f"rules source not found: {src}", file=sys.stderr)
            sys.exit(2)
        resolved.append(
            {
                "source": src,
                "config": [str(path)],
                "sha": None,
                "license_note": "local rules — license per author",
            }
        )
    return resolved


def pinned_rules_source(src: str) -> tuple[str, str]:
    """A git rules source `URL[@SHA]` as (https URL, 40-hex SHA); ValueError otherwise."""
    # URL[@REF] — split only on a trailing ref, not the git@ host
    m = re.match(
        r"^(?P<url>.+?)@(?P<ref>[A-Za-z0-9._/-]+)$",
        src.replace("://", "\x00", 1).replace("git@", "\x01", 1),
    )
    if m and "/" not in m.group("ref"):
        url = m.group("url").replace("\x00", "://", 1).replace("\x01", "git@", 1)
        ref = m.group("ref")
    else:
        # bare fork URL gets the documented pin; anything else
        # must state its own SHA
        url, ref = (src, (FORK_RULES_SHA if src.rstrip("/") == FORK_RULES_REPO else "HEAD"))
    # rule packs steer what the scan reports — a movable
    # branch/tag/HEAD silently changes results despite the
    # "pinned by SHA" doc claim. Require an immutable commit
    # (audit E6, plan P1.8); https-only transport.
    if not re.fullmatch(r"[0-9a-f]{40}", ref):
        raise ValueError(
            f"rules source {src!r}: ref must be a 40-hex commit "
            "SHA (movable refs change scan results silently)"
        )
    if not url.startswith("https://"):
        raise ValueError(f"rules source {src!r}: https:// URLs only")
    return url, ref


def rules_cache_dir(url: str, ref: str) -> Path:
    """Where a pinned git rules source is cloned."""
    return CACHE_ROOT / f"{Path(url).name}-{ref[:12]}"


def rules_root(url: str, dest: Path) -> Path:
    """The rules subtree of a cloned pack: argus nests its rules (beside a tests/ tree of
    deliberately vulnerable fixtures) under rules/languages/."""
    if not url.rstrip("/").endswith("argus-observe-rules"):
        return dest
    nested = dest / "rules" / "languages"
    return nested if nested.is_dir() else dest / "rules"


def bare_rule_id(check_id: str) -> str:
    """opengrep's check_id embeds the rules path as a dotted prefix
    (e.g. 'skills.secure-code-audit.opengrep-rules.go.traust-go-...',
    or 'go.traust-go-...' depending on cwd). Rule ids themselves never
    contain dots, so the bare id is the final dotted segment. Without
    this, scanner_correlation entries fragment per-rule precision across
    path-prefix variants."""
    return check_id.rsplit(".", 1)[-1] if check_id else check_id


def load_supplemental_packs(
    path: Path | None = None,
    *,
    allowlist: RulePackAllowlist | None = None,
) -> list[dict]:
    """Enabled external packs and their per-rule allowlists.

    This config is the enable switch for supplemental packs: audits read
    it on every default run, so a rule listed here is live fleet-wide on
    the next audit and a deleted line is off. Without this wire the rule
    calibration lane could only *observe* an allowlist it had no way to
    act on, and precision — which exists only once a rule has actually
    run — could never start accruing. That deadlock is what this closes.

    Returns [] on any parse problem rather than raising: a malformed
    supplemental config must not break the default traust rule pack scan.
    """
    # Explicit path (tests/tools) parses that file; otherwise the allowlist is
    # loaded typed + schema-validated from the config home. Either way a parse
    # problem yields [] rather than breaking the default traust rule pack scan.
    if path is not None:
        if yaml is None or not path.is_file():
            return []
        try:
            packs = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("packs") or {}
        except yaml.YAMLError:
            return []
    elif allowlist is None:
        return []
    else:
        packs = allowlist.packs or {}
    out = []
    for name, cfg in packs.items():
        if not isinstance(cfg, dict) or not cfg.get("enabled"):
            continue
        rules = [str(r) for r in (cfg.get("rules") or []) if r]
        src = cfg.get("source")
        if not (rules and src):
            continue
        out.append({"name": name, "source": str(src), "rules": rules})
    return out


def harness_pack_rule_ids(pack: Path | None = None, *, loc: Locations | None = None) -> set:
    """Every rule id in the traust-authored pack.

    The external allowlist must not suppress our own calibrated rules
    when a supplemental pack is active — filtering is scoped to the
    supplement, so the traust rule pack's ids are unioned in.
    """
    ids = set()
    pack = resolve_rule_pack_dir(pack, loc)
    for y in list(pack.rglob("*.yaml")) + list(pack.rglob("*.yml")):
        for line in y.read_text(encoding="utf-8", errors="ignore").splitlines():
            t = line.strip()
            if t.startswith("- id:"):
                ids.add(t.split(":", 1)[1].strip().strip("\"'"))
    return ids


def load_rule_allowlist(spec: str | None) -> tuple[set | None, str | None]:
    """-> (allowed bare rule ids, provenance string), or (None, None).

    Without this, an external pack is all-or-nothing. That is what kept
    the calibrated argus tranche unshipped: its 16 gate-clearing
    TLS/cert rules could only be enabled together with the 19 rules that
    are 86% of the pack's volume, which would have buried triage.

    `spec` is a comma-separated id list, or `@path` to a YAML/newline
    file. Fail-closed: an unreadable or empty allowlist raises rather
    than silently degrading to "everything enabled" — a filter that
    quietly stops filtering is worse than no filter.
    """
    if not spec:
        return None, None
    if spec.startswith("@"):
        path = Path(spec[1:]).expanduser()
        if not path.is_file():
            raise SystemExit(f"--rule-allow: no such file {path}")
        text = path.read_text(encoding="utf-8")
        ids = set()
        doc = None
        if yaml is not None:
            try:
                doc = yaml.safe_load(text)
            except yaml.YAMLError:
                doc = None
        if isinstance(doc, dict) and isinstance(doc.get("packs"), dict):
            # Structured supplemental config: take every pack's rules.
            # Naming the file explicitly means "use these ids", so the
            # per-pack `enabled` switch does not apply here.
            for cfg in doc["packs"].values():
                if isinstance(cfg, dict):
                    ids.update(str(r) for r in (cfg.get("rules") or []) if r)
        elif isinstance(doc, list):
            ids.update(str(r) for r in doc if r)
        else:
            # Plain newline list. Skip `key: value` lines so a config
            # file can never contribute its own scalars as rule ids.
            for line in text.splitlines():
                line = line.split("#", 1)[0].strip()
                if not line.startswith("-") and ":" in line:
                    continue
                line = line.lstrip("-").strip().strip("'\"")
                if line and not line.endswith(":") and ":" not in line:
                    ids.add(line)
        src = str(path)
    else:
        ids = {s.strip() for s in spec.split(",") if s.strip()}
        src = "inline"
    if not ids:
        raise SystemExit(
            f"--rule-allow: {src} yielded no rule ids; refusing "
            "to run with an empty allowlist (fail-closed)"
        )
    return ids, src


# Inline suppression comments (`# nosemgrep`, `// nosem: rule-id`) shipped by
# the scanned target. The target is the code under audit, so its own
# suppressions are repository content, not exemptions: the scan runs with
# --disable-nosem and facts on such lines carry nosem_marked for the judge.
NOSEM_RE = re.compile(r"\bnosem(?:grep)?\b", re.IGNORECASE)


def _nosem_marked(extra: dict, target: Path, path: str, start: int, end: int) -> bool:
    """True when the match, or the line just above it, carries a nosem comment.

    Checks opengrep's matched ``lines`` first, then the checkout (the comment
    may sit on the preceding line). Only the boolean leaves this function.
    """
    if NOSEM_RE.search(extra.get("lines") or ""):
        return True
    if not path or start < 1:
        return False
    file = Path(path) if Path(path).is_absolute() else target / path
    first, last = max(1, start - 1), max(start, end)
    try:
        with file.open(encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                if lineno > last:
                    break
                if lineno >= first and NOSEM_RE.search(line):
                    return True
    except OSError:
        return False
    return False


def normalize(raw: dict, target: Path) -> tuple[list[dict], list[dict]]:
    facts = []
    for r in raw.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        cwes = meta.get("cwe") or []
        if isinstance(cwes, str):
            cwes = [cwes]
        owasp = meta.get("owasp") or []
        if isinstance(owasp, str):
            owasp = [owasp]
        path = r.get("path", "")
        try:
            rel = str(Path(path).resolve().relative_to(target))
        except ValueError:
            rel = path
        start = (r.get("start") or {}).get("line", 0)
        end = (r.get("end") or {}).get("line", 0)
        facts.append(
            {
                "rule_id": bare_rule_id(r.get("check_id", "?")),
                "severity_hint": SEVERITY_HINT.get(extra.get("severity", ""), "low"),
                "file": rel,
                "start_line": start,
                "end_line": end,
                "message": (extra.get("message") or "")[:400],
                "cwe": [str(c) for c in cwes],
                "owasp": [str(o) for o in owasp],
                "confidence": meta.get("confidence"),
                "taint": "dataflow_trace" in extra,
                "snippet": (extra.get("lines") or "")[:200],
                "test_path": bool(TEST_PATH_RE.search(rel)),
                "nosem_marked": _nosem_marked(extra, target, path, start, end),
            }
        )
    errors = [
        {
            "level": e.get("level"),
            "type": e.get("type"),
            "message": str(e.get("message", ""))[:300],
            "path": e.get("path"),
        }
        for e in raw.get("errors", [])
    ]
    return facts, errors


def _execute_opengrep_scan(
    target: Path,
    rule_sources: list[str],
    *,
    timeout: int,
    opengrep_bin: str,
    rule_pack: Path | None,
    rule_allow: str | None,
    allowlist: RulePackAllowlist | None = None,
    loc: Locations | None = None,
) -> dict[str, Any]:
    """Run opengrep subprocess and return the full report dict."""
    pack = resolve_rule_pack_dir(rule_pack, loc)
    rules = resolve_rules(rule_sources, target, pack=pack, loc=loc)

    supplemental, supp_allow, supp_skipped = [], set(), []
    if not rule_sources:
        for supp in load_supplemental_packs(allowlist=allowlist):
            try:
                resolved = resolve_rules([supp["source"]], target, pack=pack, loc=loc)
            except SystemExit as e:
                supp_skipped.append({"pack": supp["name"], "reason": str(e)})
                continue
            rules += resolved
            supplemental.append(supp["name"])
            supp_allow.update(supp["rules"])

    # --disable-nosem: the target's own nosem comments never suppress a fact
    # (see NOSEM_RE); normalize() flags those facts as nosem_marked instead.
    cmd = [opengrep_bin, "scan", "--json", "--quiet", "--disable-nosem"]
    for r in rules:
        for c in r["config"]:
            cmd += ["--config", c]
    for e in EXCLUDES:
        cmd += ["--exclude", e]
    cmd.append(str(target))

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    raw = json.loads(proc.stdout)

    facts, errors = normalize(raw, target)
    allow, allow_src = load_rule_allowlist(rule_allow)
    if allow is None and supp_allow:
        traust_ids = harness_pack_rule_ids(pack, loc=loc)
        allow = supp_allow | traust_ids
        allow_src = (
            "rule-pack-allowlist.yaml "
            f"({len(supp_allow)} supplemental + "
            f"{len(traust_ids)} traust rule pack rules)"
        )
    suppressed = 0
    if allow is not None:
        kept = [f for f in facts if f["rule_id"] in allow]
        suppressed = len(facts) - len(kept)
        facts = kept

    og_version = (
        subprocess.run([opengrep_bin, "--version"], capture_output=True, text=True)
        .stdout.strip()
        .splitlines()[-1]
    )

    return {
        "tool": "run_opengrep",
        "version": harness_version(),
        "opengrep_version": og_version,
        "target": str(target),
        "rules": [
            {k: v for k, v in r.items() if k != "config"} | {"config_paths": r["config"]}
            for r in rules
        ],
        "supplemental_packs": {"applied": supplemental, "skipped": supp_skipped},
        "rule_allowlist": (
            {
                "source": allow_src,
                "rules": sorted(allow),
                "suppressed_facts": suppressed,
            }
            if allow is not None
            else None
        ),
        "stats": {
            "facts": len(facts),
            "files_scanned": len((raw.get("paths") or {}).get("scanned", [])),
            "errors": len(errors),
            "skipped_rules": len(raw.get("skipped_rules", [])),
            "suppressed_by_allowlist": suppressed,
        },
        "coverage": coverage_block(target, loc=loc),
        "facts": facts,
        "errors": errors,
    }


def _describe(fact: dict) -> str:
    text = fact.get("message") or ""
    if fact.get("nosem_marked"):
        note = (
            "The target marks this line with a nosem comment; a suppression "
            "shipped by the audited repo is not an exemption, judge the fact."
        )
        text = f"{text} ({note})" if text else note
    return text


def _facts_to_findings(facts: list[dict]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for fact in facts:
        loc = (
            Location(
                path=fact["file"],
                lines=format_lines(fact.get("start_line"), fact.get("end_line")),
            )
            if Location is not None
            else {
                "path": fact["file"],
                "lines": format_lines(fact.get("start_line"), fact.get("end_line")),
            }
        )
        evidence = []
        if fact.get("snippet"):
            ev = (
                EvidenceBlock(code=fact["snippet"])
                if EvidenceBlock is not None
                else {"code": fact["snippet"]}
            )
            evidence.append(ev)
        findings.append(
            {
                "id": f"opengrep/{fact['rule_id']}",
                "title": fact["message"] or fact["rule_id"],
                "severity": map_severity(fact.get("severity_hint", "low")),
                "cwes": fact.get("cwe", []),
                "locations": [loc],
                "description": _describe(fact),
                "evidence": evidence,
                "category": fact["rule_id"],
            }
        )
    return findings


def scan(
    target: Path,
    rules: list[str] | None = None,
    timeout: int = 900,
    opengrep_bin: str = "opengrep",
    rule_pack: Path | None = None,
    rule_allow: str | None = None,
    allowlist: RulePackAllowlist | None = None,
    *,
    loc: Locations | None = None,
) -> AdapterResult:
    """Run opengrep and return typed scanner observations."""
    target = target.resolve()
    try:
        pack = resolve_rule_pack_dir(rule_pack, loc)
    except ValueError as e:
        raise ValueError(str(e)) from e
    if not target.is_dir():
        raise ValueError(f"not a directory: {target}")
    if not shutil.which(opengrep_bin):
        raise FileNotFoundError(f"opengrep not found on PATH ({opengrep_bin})")

    try:
        report = _execute_opengrep_scan(
            target,
            rules or [],
            timeout=timeout,
            opengrep_bin=opengrep_bin,
            rule_pack=pack,
            rule_allow=rule_allow,
            allowlist=allowlist,
            loc=loc,
        )
    except subprocess.TimeoutExpired as e:
        raise TimeoutError(f"opengrep timed out after {timeout}s") from e
    except json.JSONDecodeError as e:
        raise RuntimeError("opengrep produced no JSON") from e

    return build_scan_result(
        str(target),
        "opengrep",
        _facts_to_findings(report["facts"]),
        scanned_at=utc_now(),
        scanner_version=report.get("opengrep_version", ""),
    )
