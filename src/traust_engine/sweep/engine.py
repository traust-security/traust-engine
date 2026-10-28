"""Class-generalization sweep engine (mine-ledger extension).

Every confirmed finding with a *syntactic* signature is a class the whole
corpus should be checked for: a sink call form, a config key+value, an
annotation misuse — shapes an opengrep rule can pin. This engine turns
those confirmations into candidate rules and runs them corpus-wide **by
default** (not proposal-only), with results entering the triage workflow. Four
resumable stages:

  collect  Gather confirmed findings from disposition ledgers
           (`*-findings-current.json`, validity=confirmed) and the Phase-0
           confirmation artifacts (fast-track criticals, matrix stage-2
           votes, 0d fresh-only triage). Classify each as rule-expressible
           (evidence pins a concrete syntactic pattern) or not (reason
           recorded), and cluster expressible ones into (CWE, language)
           classes.                       -> <sweeps>/_state/collect.json

  draft    For each rule-expressible class NOT already covered by a traust
           rule pack rule or an existing draft, stage a candidate-rule draft
           under the configured rule-drafts directory (DRAFT.md +
           rule.skeleton.yaml, following the C6 draft conventions; each
           draft cites its source confirmed findings in
           metadata.generalized_from).    -> <sweeps>/_state/draft.json

  sweep    Run one authored rule (draft or shipped) corpus-wide: repo
           list + URLs come from the shared corpus resolver
           (traust_engine.corpus.resolver), targets are shallow-cloned on demand into
           a bounded temp root (--limit N repos), opengrep runs with just
           that rule.        -> <sweeps>/<rule-id>/repos/<slug>.json each

  emit     Aggregate per-repo hits into a triage-ready candidates file +
           summary.  -> <sweeps>/<rule-id>/sweep-candidates.json + .md

The engine NEVER files findings and NEVER routes externally:
sweep-candidates.json is triage workflow input — every hit is a
candidate whose verdict belongs to the triage adjudication loop, and
rule promotion into the shipped pack stays with the rule calibration
path (a human decision).

Authoring the draft's pattern remains the rule-mining (human+LLM) job;
the engine refuses to sweep an unauthored skeleton (patterns still TODO).

CLI:
    traust sweep collect [--results-root DIR]
        [--phase0-root DIR] [--sweeps-root DIR] [--force]
    traust sweep draft [--sweeps-root DIR]
        [--pack DIR] [--drafts-dir DIR]
    traust sweep sweep --rule ID|PATH [--limit N]
        [--repos FILE] [--sweeps-root DIR] [--work-dir DIR]
        [--analysis-results DIR] [--opengrep BIN] [--timeout SEC]
    traust sweep emit --rule ID|PATH
        [--sweeps-root DIR] [--force]

Resumability: collect/emit skip when their output exists (--force
re-runs); draft skips classes whose draft dir exists; sweep skips repos
whose per-repo hits file exists.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from traust_contracts import CorpusConfig

from traust_engine.adapters import opengrep as OG
from traust_engine.assets import harness_version as engine_harness_version
from traust_engine.sweep import mining as MINE

DEFAULT_SWEEP_LIMIT = 40  # bounded by default; raise deliberately

EXCLUDES = ("vendor", "node_modules", "third_party", "_output", ".git")


# ---------------------------------------------------------------------------
# classification — rule-expressible vs not
# ---------------------------------------------------------------------------
# A confirmed finding is rule-expressible when its evidence pins a concrete
# syntactic pattern: a sink call form (exec/query/deserialize/TLS-verify
# call), a config key+value, an annotation/flag misuse, a hardcoded
# credential literal. CWE families whose canonical manifestation IS such a
# shape are allowlisted; everything else is recorded with a reason, never
# silently dropped. This is a deterministic router — the classification
# routes rule-authoring attention, it does not conclude anything about the
# finding itself.
SYNTACTIC_CWES = {
    # injection sinks (command / SQL / code / template / XPath / LDAP / log)
    22,
    23,
    36,
    73,
    77,
    78,
    79,
    80,
    88,
    89,
    90,
    91,
    93,
    94,
    95,
    96,
    116,
    117,
    643,
    917,
    943,
    # config / environment shape (key+value, annotation, flag)
    15,
    614,
    1004,
    1244,
    # crypto & TLS shapes (weak algo call, verify-disable, static IV/seed)
    261,
    295,
    296,
    319,
    326,
    327,
    328,
    330,
    338,
    347,
    757,
    759,
    760,
    916,
    # secrets as literals / in logs / in world-readable state
    259,
    312,
    313,
    321,
    532,
    540,
    798,
    # deserialization / XXE / prototype pollution / regex literal
    502,
    611,
    776,
    1321,
    1333,
    # SSRF / open redirect (sink call with tainted URL)
    601,
    918,
    # temp-file and permission shapes
    377,
    379,
    732,
}
# dependency-version findings: version facts, not syntactic patterns —
# SCA territory (govulncheck/osv), never an opengrep sweep class
DEPENDENCY_CWES = {937, 1035, 1104, 1395}

RULEABLE_LANGS = set(MINE.RULEABLE_LANGS) | {"yaml"}

_CWE_NUM_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def _cwe_num(cwe: str | None) -> int | None:
    m = _CWE_NUM_RE.search(str(cwe or ""))
    return int(m.group(1)) if m else None


def _lang_of_file(path: str | None) -> str:
    ext = Path(str(path or "")).suffix.lower()
    return MINE.EXT_LANG.get(ext, "unknown")


def classify(finding: dict) -> tuple[bool, str]:
    """(rule_expressible, reason). Reasons are recorded, never silent."""
    num = _cwe_num(finding.get("cwe"))
    if num is None:
        return False, "no_cwe: no CWE anchor to generalize from"
    if not finding.get("file"):
        return False, "no_location_anchor: evidence pins no file"
    if num in DEPENDENCY_CWES:
        return False, (
            f"dependency_version_class: CWE-{num} is a version "
            "fact (SCA/govulncheck territory), not a syntactic "
            "pattern"
        )
    lang = finding.get("language") or "unknown"
    if lang not in RULEABLE_LANGS:
        return False, f"language_not_ruleable: {lang}"
    if num not in SYNTACTIC_CWES:
        return False, (
            f"semantic_logic_class: CWE-{num} evidence pins "
            "semantic logic (authn/authz/ordering/trust), not "
            "a concrete syntactic pattern"
        )
    return True, "syntactic: sink-call / config-key / annotation shape"


# ---------------------------------------------------------------------------
# collect — confirmed findings from ledgers + Phase-0 artifacts
# ---------------------------------------------------------------------------


def _norm(
    source: str,
    artifact: str,
    *,
    repo: str,
    url: str | None,
    finding_id: str | None,
    title: str,
    cwe: str | None,
    severity: str | None,
    file: str | None,
    line=None,
) -> dict:
    rec = {
        "source": source,
        "artifact": artifact,
        "repo": repo or "unknown",
        "url": url,
        "finding_id": finding_id,
        "title": str(title or "")[:160],
        "cwe": (f"CWE-{_cwe_num(cwe)}" if _cwe_num(cwe) else None),
        "severity": severity,
        "file": file or None,
        "line": int(line) if str(line or "").isdigit() else None,
        "language": _lang_of_file(file),
    }
    ok, reason = classify(rec)
    rec["rule_expressible"] = ok
    rec["reason"] = reason
    return rec


def _slug_from_url(url: str | None) -> str:
    if not url:
        return "unknown"
    return url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")


def collect_ledger(results_root: Path) -> list[dict]:
    """Ledger-confirmed TPs, reusing the mine-ledger extractor."""
    out = []
    if not results_root.is_dir():
        return out
    for tp in MINE.mine_corpus(results_root):
        locs = tp.get("locations") or []
        out.append(
            _norm(
                "ledger",
                tp.get("report", ""),
                repo=_slug_from_url(tp.get("repo"))
                if "/" in str(tp.get("repo"))
                else str(tp.get("repo")),
                url=tp.get("repo") if str(tp.get("repo", "")).startswith("http") else None,
                finding_id=tp.get("finding_id"),
                title=tp.get("title", ""),
                cwe=tp.get("cwe"),
                severity=tp.get("severity"),
                file=locs[0] if locs else None,
            )
        )
    return out


_SOURCE_SLUG_RE = re.compile(r"([A-Za-z0-9._-]+?)(?:-delta)?\.json")


def collect_fast_track(phase0: Path) -> list[dict]:
    """fast-track-criticals*.json — the ingested-criticals confirmations.
    Two confirmed shapes: {"findings":[… verdict=true_positive …]} (triage)
    and {"results":[… confirmed=true, slug/url/finding …]} (vote waves).
    Bare candidate lists are pre-confirmation input and are skipped."""
    out = []
    for path in sorted(phase0.glob("fast-track-criticals*.json")):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(doc, dict) and isinstance(doc.get("findings"), list):
            for f in doc["findings"]:
                if f.get("verdict") != "true_positive" or f.get("kind") == "weakness":
                    continue
                m = _SOURCE_SLUG_RE.search(str(f.get("source", "")).rsplit("/", 1)[-1])
                out.append(
                    _norm(
                        "fast-track",
                        path.name,
                        repo=m.group(1) if m else "unknown",
                        url=None,
                        finding_id=f.get("id"),
                        title=f.get("title", ""),
                        cwe=f.get("cwe"),
                        severity=f.get("severity") or f.get("claimed_severity"),
                        file=f.get("file"),
                        line=f.get("line"),
                    )
                )
        elif isinstance(doc, dict) and isinstance(doc.get("results"), list):
            for r in doc["results"]:
                if not r.get("confirmed"):
                    continue
                fin = r.get("finding") or {}
                out.append(
                    _norm(
                        "fast-track",
                        path.name,
                        repo=r.get("slug") or _slug_from_url(r.get("url")),
                        url=r.get("url"),
                        finding_id=None,
                        title=fin.get("title", ""),
                        cwe=fin.get("cwe"),
                        severity=fin.get("severity"),
                        file=fin.get("file"),
                        line=fin.get("line"),
                    )
                )
    return out


def collect_matrix(phase0: Path) -> list[dict]:
    """matrix/adj/stage2-*-votes.json confirmations, joined to
    stage2-candidates.json by result index."""
    adj = phase0 / "matrix" / "adj"
    cand_path = adj / "stage2-candidates.json"
    if not cand_path.is_file():
        return []
    try:
        candidates = json.loads(cand_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    out = []
    for path in sorted(adj.glob("stage2-*-votes.json")):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for r in doc.get("results", []):
            if not r.get("confirmed"):
                continue
            idx = r.get("idx")
            if not isinstance(idx, int) or idx >= len(candidates):
                continue
            cand = candidates[idx]
            fin = cand.get("finding") or {}
            target = str((cand.get("target") or {}).get("target", ""))
            url = target.split(" @ ")[0].strip() or None
            out.append(
                _norm(
                    "matrix-stage2",
                    path.name,
                    repo=_slug_from_url(url),
                    url=url,
                    finding_id=cand.get("uid"),
                    title=fin.get("title", ""),
                    cwe=fin.get("cwe"),
                    severity=fin.get("severity"),
                    file=fin.get("file"),
                    line=fin.get("line"),
                )
            )
    return out


def collect_0d(phase0: Path) -> list[dict]:
    """dual/0d-freshonly-triage-results.json confirmations."""
    path = phase0 / "dual" / "0d-freshonly-triage-results.json"
    if not path.is_file():
        return []
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    out = []
    for r in doc.get("results", []):
        if not r.get("confirmed"):
            continue
        fin = r.get("finding") or {}
        out.append(
            _norm(
                "dual-0d",
                path.name,
                repo=r.get("slug") or _slug_from_url(r.get("url")),
                url=r.get("url"),
                finding_id=None,
                title=fin.get("title", ""),
                cwe=fin.get("cwe") or fin.get("class"),
                severity=fin.get("severity"),
                file=fin.get("file"),
                line=fin.get("line"),
            )
        )
    return out


def do_collect(
    results_root: Path, phase0_root: Path, sweeps_root: Path, force: bool = False
) -> dict:
    state = sweeps_root / "_state" / "collect.json"
    if state.is_file() and not force:
        return {"skipped": True, "state": str(state)}

    findings, seen = [], set()
    counts: dict[str, int] = {}
    for batch in (
        collect_ledger(results_root),
        collect_fast_track(phase0_root),
        collect_matrix(phase0_root),
        collect_0d(phase0_root),
    ):
        for f in batch:
            key = (f["repo"].lower(), f["file"], f["cwe"], f["title"][:60].lower())
            if key in seen:
                continue
            seen.add(key)
            findings.append(f)
            counts[f["source"]] = counts.get(f["source"], 0) + 1

    classes: dict[tuple[str, str], dict] = {}
    for i, f in enumerate(findings):
        if not f["rule_expressible"]:
            continue
        key = (f["cwe"], f["language"])
        c = classes.setdefault(
            key,
            {
                "class_id": f"{f['cwe']}/{f['language']}",
                "cwe": f["cwe"],
                "language": f["language"],
                "count": 0,
                "repos": set(),
                "member_indexes": [],
            },
        )
        c["count"] += 1
        c["repos"].add(f["repo"])
        c["member_indexes"].append(i)
    class_list = []
    for c in sorted(classes.values(), key=lambda x: -x["count"]):
        c["repos"] = sorted(c["repos"])
        class_list.append(c)

    result = {
        "stage": "collect",
        "generated": datetime.now(UTC).isoformat(timespec="seconds"),
        "harness_version": harness_version(),
        "results_root": str(results_root),
        "phase0_root": str(phase0_root),
        "stats": {
            "confirmed_findings": len(findings),
            "by_source": counts,
            "rule_expressible": sum(f["rule_expressible"] for f in findings),
            "not_expressible": sum(not f["rule_expressible"] for f in findings),
            "classes": len(class_list),
        },
        "classes": class_list,
        "findings": findings,
    }
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return {"skipped": False, "state": str(state), **result["stats"]}


# ---------------------------------------------------------------------------
# draft — candidate rules for uncovered expressible classes
# ---------------------------------------------------------------------------


def existing_rule_ids(pack: Path, drafts_dir: Path) -> set[str]:
    ids = set()
    paths = list(pack.rglob("*.yaml")) if pack.is_dir() else []
    if drafts_dir.is_dir():
        paths += list(drafts_dir.glob("*/rule.skeleton.yaml"))
    for y in paths:
        try:
            text = y.read_text(encoding="utf-8")
        except OSError:
            continue
        for m in re.finditer(r"^\s*-\s*id:\s*(\S+)", text, re.MULTILINE):
            ids.add(m.group(1))
    return ids


def _class_slug(cwe: str, language: str) -> str:
    return f"sweep-{language}-{cwe.lower()}"


def draft_rule_id(cwe: str, language: str) -> str:
    return f"traust-{language}-sweep-{cwe.lower()}"


def write_sweep_draft(cls: dict, members: list[dict], drafts_dir: Path) -> str:
    slug = _class_slug(cls["cwe"], cls["language"])
    rule_id = draft_rule_id(cls["cwe"], cls["language"])
    draft = drafts_dir / slug
    draft.mkdir(parents=True, exist_ok=True)
    sources = [
        {
            "source_finding": m.get("finding_id") or "(unkeyed)",
            "repo": m["repo"],
            "url": m.get("url"),
            "file": m.get("file"),
            "line": m.get("line"),
            "artifact": f"{m['source']}:{m['artifact']}",
        }
        for m in members[:8]
    ]
    sev = "ERROR" if any(m.get("severity") in ("critical", "high") for m in members) else "WARNING"
    (draft / "rule.skeleton.yaml").write_text(
        "rules:\n"
        f"  - id: {rule_id}\n"
        f"    languages: [{cls['language']}]\n"
        f"    severity: {sev}\n"
        "    message: >-\n"
        "      TODO — one-sentence description of the confirmed syntactic\n"
        f"      shape this class generalizes. {cls['cwe']}.\n"
        "    metadata:\n"
        f'      cwe: ["{cls["cwe"]}"]\n'
        "      category: sweep-generalization\n"
        "      confidence: HIGH\n"
        "      generalized_from:\n"
        + "".join(
            f'        - source_finding: "{s["source_finding"]}"\n'
            f'          repo: "{s["repo"]}"\n'
            f'          location: "{s["file"]}' + (f":{s['line']}" if s.get("line") else "") + '"\n'
            f'          artifact: "{s["artifact"]}"\n'
            for s in sources
        )
        + "    patterns:\n"
        "      - pattern: TODO   # author from the cited confirmed "
        "findings' evidence\n",
        encoding="utf-8",
    )
    cites = "\n".join(
        f"- `{s['repo']}` — {s['file']}"
        + (f":{s['line']}" if s.get("line") else "")
        + f" · finding `{s['source_finding']}` · from `{s['artifact']}`"
        for s in sources
    )
    (draft / "DRAFT.md").write_text(
        f"""# Rule draft: {rule_id}

**Class-generalization sweep candidate**:
{cls["count"]} confirmed finding(s) across {len(cls["repos"])} repo(s)
pin the same syntactic shape — **{cls["cwe"]} × {cls["language"]}** —
and no shipped traust rule covers the class.

**Source confirmed findings (specification material):**

{cites}

**Authoring contract:** write `patterns:` in `rule.skeleton.yaml` from
the cited findings' evidence so the rule fires on each source shape.
Calibrate via the rule calibration path (fixture `ruleid:`/`ok:` lines,
the test-and-calibrate gate) before promotion into the pack — the
sweep engine will refuse to run an unauthored (TODO) skeleton. Once
authored, the corpus-wide sweep runs BY DEFAULT:

    traust sweep sweep --rule {slug}
    traust sweep emit  --rule {slug}

Sweep hits are triage input material only — feed them to the triage
workflow; they never become filed findings automatically.
""",
        encoding="utf-8",
    )
    return slug


def do_draft(sweeps_root: Path, pack: Path, drafts_dir: Path) -> dict:
    collect_state = sweeps_root / "_state" / "collect.json"
    if not collect_state.is_file():
        sys.exit(f"draft: run `collect` first (missing {collect_state})")
    col = json.loads(collect_state.read_text(encoding="utf-8"))
    pack_rules = MINE.load_pack_rules(pack)
    known_ids = existing_rule_ids(pack, drafts_dir)

    emitted, skipped = [], []
    for cls in col["classes"]:
        covering = [
            r["id"]
            for r in pack_rules
            if cls["cwe"] in r["cwes"] and cls["language"] in r["languages"]
        ]
        if covering:
            skipped.append({"class": cls["class_id"], "reason": f"covered_by_pack: {covering}"})
            continue
        rid = draft_rule_id(cls["cwe"], cls["language"])
        slug = _class_slug(cls["cwe"], cls["language"])
        if rid in known_ids or (drafts_dir / slug).is_dir():
            skipped.append({"class": cls["class_id"], "reason": "draft_exists"})
            continue
        members = [col["findings"][i] for i in cls["member_indexes"]]
        emitted.append(write_sweep_draft(cls, members, drafts_dir))

    result = {
        "stage": "draft",
        "generated": datetime.now(UTC).isoformat(timespec="seconds"),
        "pack": str(pack),
        "drafts_dir": str(drafts_dir),
        "emitted": emitted,
        "skipped": skipped,
    }
    state = sweeps_root / "_state" / "draft.json"
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


# ---------------------------------------------------------------------------
# sweep — run one rule corpus-wide (bounded, resumable per repo)
# ---------------------------------------------------------------------------


def resolve_rule(spec: str, pack: Path, drafts_dir: Path) -> Path:
    """--rule accepts a yaml path, a draft dir (or draft name), or a bare
    rule id searched across the pack and the drafts."""
    p = Path(spec)
    if p.is_dir():
        p = p / "rule.skeleton.yaml"
    if p.is_file():
        return p.resolve()
    if (drafts_dir / spec).is_dir():
        return (drafts_dir / spec / "rule.skeleton.yaml").resolve()
    candidates = (list(pack.rglob("*.yaml")) if pack.is_dir() else []) + (
        list(drafts_dir.glob("*/rule.skeleton.yaml")) if drafts_dir.is_dir() else []
    )
    rx = re.compile(rf"^\s*-\s*id:\s*{re.escape(spec)}\s*$", re.MULTILINE)
    for y in candidates:
        try:
            if rx.search(y.read_text(encoding="utf-8")):
                return y.resolve()
        except OSError:
            continue
    sys.exit(f"sweep: rule not found: {spec}")


def rule_id_of(rule_path: Path, spec: str | None = None) -> str:
    text = rule_path.read_text(encoding="utf-8")
    ids = re.findall(r"^\s*-\s*id:\s*(\S+)", text, re.MULTILINE)
    if spec and spec in ids:
        return spec
    if not ids:
        sys.exit(f"sweep: no rule id in {rule_path}")
    return ids[0]


def corpus_repos(analysis_results: Path, limit: int, cfg: CorpusConfig) -> list[dict]:
    """Repo list + URLs via the shared corpus resolver: HEAD code-audit
    records, one URL per base slug."""
    from traust_engine.corpus import resolver as C

    res = C.resolve(analysis_results, cfg, with_repo_urls=True)
    seen: dict[str, str] = {}
    for r in res.records:
        if r.report_kind != "code-audit" or r.is_branch_audit:
            continue
        url = r.repo_url
        if not url or not str(url).startswith("http"):
            continue
        seen.setdefault(r.base_slug, url)
    return [{"slug": s, "url": u} for s, u in sorted(seen.items())][:limit]


def sweep_one_repo(
    repo: dict, rule_path: Path, work_dir: Path, opengrep_bin: str, timeout: int
) -> dict:
    """Shallow-clone (or scan a local dir in place) and run the one rule."""
    url = repo["url"]
    # scan-in-place requires the explicit dir: prefix — a repos-file URL
    # that HAPPENS to name an existing local path must not silently
    # alias to it (plan P3 hardening note)
    if url.startswith("dir:"):
        target = Path(url[4:]).expanduser().resolve()
        if not target.is_dir():
            return {"slug": repo["slug"], "error": f"dir: target missing: {url}"}
    elif url.startswith("http"):
        target = work_dir / repo["slug"]
        if not target.is_dir():
            r = subprocess.run(
                ["git", "clone", "-q", "--depth", "1", "--", url, str(target)],
                capture_output=True,
                text=True,
                timeout=600,
                env={**os.environ, "GIT_ALLOW_PROTOCOL": "https"},
            )
            if r.returncode != 0:
                return {
                    "slug": repo["slug"],
                    "url": url,
                    "error": "clone_failed",
                    "detail": r.stderr[-400:],
                }
    else:
        return {
            "slug": repo["slug"],
            "url": url,
            "error": "unsupported url (use https://… or dir:<path>)",
        }
    cmd = [opengrep_bin, "scan", "--json", "--quiet", "--config", str(rule_path)]
    for e in EXCLUDES:
        cmd += ["--exclude", e]
    cmd.append(str(target))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        raw = json.loads(proc.stdout)
    except subprocess.TimeoutExpired:
        return {"slug": repo["slug"], "url": url, "error": "scan_timeout"}
    except json.JSONDecodeError:
        return {"slug": repo["slug"], "url": url, "error": "opengrep_no_json"}
    facts, errors = OG.normalize(raw, target)
    return {
        "slug": repo["slug"],
        "url": url,
        "files_scanned": len((raw.get("paths") or {}).get("scanned", [])),
        "engine_errors": len(errors),
        "facts": facts,
    }


def do_sweep(
    rule_spec: str,
    sweeps_root: Path,
    pack: Path,
    drafts_dir: Path,
    analysis_results: Path | None,
    repos_file: Path | None,
    limit: int,
    work_dir: Path | None,
    opengrep_bin: str,
    timeout: int,
    *,
    cfg: CorpusConfig,
) -> dict:
    rule_path = resolve_rule(rule_spec, pack, drafts_dir)
    text = rule_path.read_text(encoding="utf-8")
    if "TODO" in text:
        sys.exit(
            f"sweep: rule {rule_path} is an unauthored skeleton "
            "(TODO present) — author and calibrate it first "
            "(mine-ledger authoring contract)"
        )
    if not shutil.which(opengrep_bin):
        sys.exit(f"sweep: opengrep not found on PATH ({opengrep_bin})")
    rid = rule_id_of(rule_path, rule_spec)

    if repos_file:
        repos = json.loads(Path(repos_file).read_text(encoding="utf-8"))[:limit]
    else:
        if analysis_results is None:
            sys.exit("sweep: need --repos or --analysis-results")
        repos = corpus_repos(analysis_results, limit, cfg)

    repo_dir = sweeps_root / rid / "repos"
    repo_dir.mkdir(parents=True, exist_ok=True)
    cleanup = work_dir is None
    work = Path(work_dir) if work_dir else Path(tempfile.mkdtemp(prefix="sweep-"))
    work.mkdir(parents=True, exist_ok=True)

    swept, skipped, errors, hits = 0, 0, 0, 0
    try:
        for repo in repos:
            out = repo_dir / f"{repo['slug']}.json"
            if out.is_file():
                skipped += 1
                continue
            res = sweep_one_repo(repo, rule_path, work, opengrep_bin, timeout)
            res["rule_id"] = rid
            res["rule_path"] = str(rule_path)
            out.write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
            swept += 1
            if res.get("error"):
                errors += 1
            else:
                hits += len(res.get("facts", []))
    finally:
        if cleanup:
            shutil.rmtree(work, ignore_errors=True)
    return {
        "rule_id": rid,
        "rule_path": str(rule_path),
        "repos": len(repos),
        "swept": swept,
        "skipped": skipped,
        "repo_errors": errors,
        "hits": hits,
        "repo_results": str(repo_dir),
    }


# ---------------------------------------------------------------------------
# emit — triage-ready candidates file + summary
# ---------------------------------------------------------------------------

PURPOSE = (
    "TRIAGE INPUT MATERIAL — corpus-wide sweep of one candidate/"
    "shipped rule generalized from confirmed findings (run-by-default "
    "policy). Every entry is a CANDIDATE, not a finding: the sweep "
    "engine never files findings and never routes externally — feed "
    "this file to the triage workflow for adjudication."
)


def rule_provenance(rule_path: Path, rid: str) -> list:
    try:
        import yaml

        doc = yaml.safe_load(rule_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return []
    for r in doc.get("rules", []):
        if r.get("id") != rid:
            continue
        meta = r.get("metadata") or {}
        if meta.get("generalized_from"):
            return meta["generalized_from"]
        if meta.get("regression_of"):
            return [meta["regression_of"]]
    return []


def do_emit(
    rule_spec: str, sweeps_root: Path, pack: Path, drafts_dir: Path, force: bool = False
) -> dict:
    rule_path = resolve_rule(rule_spec, pack, drafts_dir)
    rid = rule_id_of(rule_path, rule_spec)
    out_dir = sweeps_root / rid
    out_json = out_dir / "sweep-candidates.json"
    if out_json.is_file() and not force:
        return {"skipped": True, "out": str(out_json)}
    repo_dir = out_dir / "repos"
    if not repo_dir.is_dir():
        sys.exit(f"emit: no sweep results at {repo_dir} — run `sweep` first")

    provenance = rule_provenance(rule_path, rid)
    prov_keys = [
        str(p.get("source_finding") or p.get("fingerprint") or "?")
        if isinstance(p, dict)
        else str(p)
        for p in provenance
    ]
    candidates, per_repo = [], []
    clone_failures = 0
    for path in sorted(repo_dir.glob("*.json")):
        res = json.loads(path.read_text(encoding="utf-8"))
        if res.get("error"):
            clone_failures += 1
            per_repo.append({"repo": res["slug"], "hits": 0, "error": res["error"]})
            continue
        facts = res.get("facts", [])
        per_repo.append({"repo": res["slug"], "hits": len(facts)})
        for f in facts:
            candidates.append(
                {
                    "repo": res["slug"],
                    "url": res.get("url"),
                    "file": f["file"],
                    "line": f["start_line"],
                    "end_line": f["end_line"],
                    "location": f"{f['file']}:{f['start_line']}",
                    "excerpt": f.get("snippet", ""),
                    "rule_id": rid,
                    "severity_hint": f.get("severity_hint"),
                    "test_path": f.get("test_path", False),
                    "source_finding_provenance": prov_keys,
                }
            )

    report = {
        "artifact": "sweep-candidates",
        "purpose": PURPOSE,
        "generated": datetime.now(UTC).isoformat(timespec="seconds"),
        "harness_version": harness_version(),
        "rule_id": rid,
        "rule_path": str(rule_path),
        "source_findings": provenance,
        "repos_swept": len(per_repo),
        "repos_with_hits": sum(1 for r in per_repo if r["hits"]),
        "repo_errors": clone_failures,
        "candidates": candidates,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    lines = [
        f"# Sweep summary — `{rid}`",
        "",
        f"> {PURPOSE}",
        "",
        f"- Generated: {report['generated']} · harness {report['harness_version']}",
        f"- Repos swept: {report['repos_swept']} "
        f"({report['repos_with_hits']} with hits, "
        f"{clone_failures} errored)",
        f"- Candidates: {len(candidates)}",
        f"- Source confirmed findings: "
        f"{', '.join(prov_keys) or '(none recorded in rule metadata)'}",
        "",
        "| repo | hits |",
        "|---|---:|",
    ]
    for r in sorted(per_repo, key=lambda x: -x["hits"]):
        lines.append(
            f"| {r['repo']} | {r['hits']}" + (f" ({r['error']})" if r.get("error") else "") + " |"
        )
    lines += [
        "",
        "Next step: triage workflow on "
        + str(out_json)
        + " — verdicts belong to triage; rule promotion stays with the "
        "rule calibration path.",
        "",
    ]
    (out_dir / "sweep-summary.md").write_text("\n".join(lines), encoding="utf-8")
    return {
        "skipped": False,
        "out": str(out_json),
        "candidates": len(candidates),
        "repos_swept": report["repos_swept"],
        "repos_with_hits": report["repos_with_hits"],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def harness_version() -> str:
    return engine_harness_version()


def _find_analysis_results(arg: str | None, ops) -> Path:
    if arg:
        return Path(arg)
    ar = ops._analysis_results()
    if ar.is_dir():
        return ar
    sys.exit("analysis-results not found; pass --analysis-results")
