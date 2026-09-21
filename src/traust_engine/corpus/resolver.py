"""Corpus resolver — one definition of the report population.

Every dashboard builder historically walked analysis-results/ its own way
(different roots, depths, symlink rules, dedup keys), so no two headline
numbers agreed. This module is the single implementation of:

1. DISCOVERY — depth-tolerant walk of the configured trees (28 repos sit
   at findings/<repo>/ with no product parent; a fixed */*/ glob misses
   them). File symlinks are never counted as reports: they are recorded
   as aliases mapping to their canonical target.

2. IDENTITY — ref provenance is resolved in two layers
   (branch-awareness Phase 0):

   a. DECLARED (preferred) — a report that carries `metadata.ref` (+
      `metadata.ref_kind`: branch|tag|default|stream) states its
      checked-out ref explicitly; the resolver takes it verbatim. Only a
      `ref_kind` of "branch" makes the record a branch re-audit —
      "default"/"tag"/"stream" checkouts are not branch re-audits
      (a dist-git stream is a mainline deliverable).

   b. LEGACY SLUG (fallback only) — a report base like
      `oc__release-5.1` splits into (base_slug="oc",
      ref="release-5.1"). Only known branch-ref suffixes are stripped
      (`__release-X.Y`, `__openshift-X.Y`): the same `__` separator
      also encodes org__repo names (`quay__enhancements`,
      `osbuild__.github`), so a general strip would corrupt identity.
      The suffix whitelist is legacy-only: it exists for the
      pre-0.122.0 corpus, which never declares `metadata.ref`, and is
      deliberately NOT extended for new refs — new audits declare the
      ref in metadata instead.

   ~60% of audit reports under findings/ are branch re-audits of an
   already-audited repo; base_slug (always slug-derived — declared refs
   never change report identity or fingerprints) is what collapses them
   for "distinct exposure" counts while `ref` keeps them countable as
   work performed.

3. OWNERSHIP — every record carries the label / ownership tag /
   business-unit of its tree from config/corpus-config.yaml
   (owned / upstream / external-bu / harness-qa). Registered engagement
   trees (any `<name>-findings` entry in corpus-config) activate
   automatically when they appear on disk. Unregistered trees that contain
   audit reports are surfaced as warnings, never silently counted or dropped. `harness-qa` trees
   (probe/benchmark/self-measurement artifacts, e.g. scan-testing/) are
   registered-but-not-corpus: resolve() never walks them, so their
   report-shaped files can never enter any metrics lens — the
   registration exists so the drift check knows the tree is vetted.

4. LAYER PREFERENCE — a repo's finding set is restated across audit /
   triage / findings-current artifacts. The preferred source is
   findings-current (disposition-aware) when present, else the audit JSON;
   md-only reports (no JSON sibling) are flagged as parse gaps rather than
   invisible.

The resolved population is projected into findings.db `repos` — the one
denominator source every dashboard cites — and render_population_block()
produces the standard provenance block generated reports embed.

CLI:
    traust corpus summary [--analysis-results PATH]
    traust corpus resolve --out corpus-manifest.json \\
        [--analysis-results PATH] [--config PATH] [--trees a,b] \\
        [--with-repo-urls]
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import yaml
from traust_contracts import (  # noqa: F401
    OWNERSHIP_TAGS,
    CorpusConfig,
    DeploymentConfigMissing,
    TreeMeta,
)

from traust_engine.assets import harness_version
from traust_engine.locations import analysis_results_dir, configured_locations

try:
    from traust_contracts.models import Finding

    HAS_CONTRACTS = True
except ImportError:
    HAS_CONTRACTS = False

AUDIT_JSON_SUFFIX = "-security-audit.json"
AUDIT_MD_SUFFIX = "-security-audit.md"
# Declared-layer IaC audits (/cloud-config-audit). A separate report
# kind, NEVER blended into code-audit counts: consumers that mix the
# two units (hardening-class IaC posture vs source-code vulnerability
# reports) recreate the scope/unit divergence the census exists to
# prevent. Filter on ReportRecord.report_kind.
CLOUD_JSON_SUFFIX = "-cloud-config-audit.json"
CLOUD_MD_SUFFIX = "-cloud-config-audit.md"
# Container-image audits (/secure-container-audit). Same rule as
# cloud-config: a separate report kind, NEVER blended into code-audit
# counts — the unit is a shipped artifact snapshot (digest-keyed), and
# an image finding is often the shipped manifestation of a code finding
# the campaign already counted (`source_findings` cross-links). Filter
# on ReportRecord.report_kind.
CONTAINER_JSON_SUFFIX = "-container-audit.json"
CONTAINER_MD_SUFFIX = "-container-audit.md"

# (kind, json suffix, md suffix) — the discovery table for the walk.
REPORT_KINDS = (
    ("code-audit", AUDIT_JSON_SUFFIX, AUDIT_MD_SUFFIX),
    ("cloud-config", CLOUD_JSON_SUFFIX, CLOUD_MD_SUFFIX),
    ("container-audit", CONTAINER_JSON_SUFFIX, CONTAINER_MD_SUFFIX),
)

# LEGACY-ONLY slug fallback (see module docstring 2b): only these
# `__<suffix>` forms are branch refs; anything else after `__` is part of
# the repo's identity (org__repo naming is in live use). Do not extend
# this whitelist for new refs — new reports declare `metadata.ref`
# (ref-provenance Phase 0), which takes precedence over slug parsing.
REF_SUFFIX_RX = re.compile(r"__((?:release|openshift)-\d+\.\d+(?:\.\d+)?)$")


# Dot-named REPOS are real audit targets (.github, .fullsend, .project org
# meta-repos), so dot-dirs cannot be pruned wholesale — only known harness
# state/cache dirs are skipped.
SKIP_DIR_NAMES = {
    "_manifest",
    ".git",
    ".claude",
    ".triage-state",
    ".threat-model-state",
    ".scratch",
}
SKIP_DIR_PREFIXES = (".cache", ".tmp", ".verify")


def _skip_dir(name: str) -> bool:
    return name in SKIP_DIR_NAMES or name.startswith(SKIP_DIR_PREFIXES)


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------


def _default_corpus() -> CorpusConfig:
    """Removed — use HarnessEngine.corpus.config() at CLI entry points."""
    raise DeploymentConfigMissing(
        "corpus config required — pass config_path or load via HarnessEngine.corpus.config()"
    )


def load_config(
    config_path: Path | None = None,
    *,
    cfg: CorpusConfig | None = None,
) -> CorpusConfig:
    """The corpus config, typed and validated (ownership tags + required
    fields enforced by the model). An explicit ``config_path`` loads that file;
    ``cfg`` is passed through when the caller already holds it (e.g. CorpusOps);
    otherwise it comes from the injected config context."""
    if cfg is not None:
        return cfg
    if config_path is not None:
        data = yaml.safe_load(Path(config_path).read_text(encoding="utf-8"))
        return CorpusConfig.model_validate(data)
    return _default_corpus()


def active_trees(cfg: CorpusConfig, analysis_results: Path) -> dict[str, TreeMeta]:
    """Configured trees plus any registered engagement tree that now
    exists on disk (tree-per-engagement activates automatically)."""
    trees: dict[str, TreeMeta] = dict(cfg.trees)
    for eng in cfg.engagements.values():
        if (analysis_results / eng.tree).is_dir():
            trees[eng.tree] = eng
    return trees


# ---------------------------------------------------------------------------
# identity
# ---------------------------------------------------------------------------


def split_ref(base: str) -> tuple[str, str | None]:
    """`oc__release-5.1` -> ("oc", "release-5.1"); org__repo names and
    everything else pass through untouched. LEGACY slug fallback: reports
    that declare `metadata.ref` bypass this for ref resolution (the
    base_slug half is still authoritative for identity collapse)."""
    m = REF_SUFFIX_RX.search(base)
    return (base[: m.start()], m.group(1)) if m else (base, None)


# "stream" (harness >= 0.140.0): a dist-git release stream (c10s, c9s)
# from /secure-rpm-audit — a mainline deliverable, deliberately NOT a
# branch re-audit (is_branch_audit keys on ref_kind == "branch" alone).
REF_KINDS = ("branch", "tag", "default", "stream")


def declared_ref(report_path: Path) -> tuple[str | None, str | None]:
    """`metadata.ref` / `metadata.ref_kind` when the report declares them
    (ref-provenance Phase 0), else (None, None).

    Cheap substring probe before parsing: a declared ref necessarily puts
    a literal '"ref"' or '"ref_kind"' key in the JSON text, so only files
    that can carry one are json.loads'ed. This keeps resolve() at
    walk-speed over the legacy corpus (0 of ~8k findings/ reports carry
    the key as of 2026-07-21; the probe fully parses only the handful of
    false-positive hits from '"ref"' appearing in string values)."""
    try:
        raw = report_path.read_text(encoding="utf-8")
    except OSError:
        return None, None
    if '"ref"' not in raw and '"ref_kind"' not in raw:
        return None, None
    try:
        md = json.loads(raw).get("metadata") or {}
    except (json.JSONDecodeError, AttributeError):
        return None, None
    ref = md.get("ref")
    kind = md.get("ref_kind")
    return (
        ref if isinstance(ref, str) and ref else None,
        kind if isinstance(kind, str) and kind in REF_KINDS else None,
    )


_URL_IN_TEXT_RX = re.compile(r"https?://[^\s;,()<>\"']+")


def normalize_repo_url(raw: str | None) -> str | None:
    """Extract a single clean repository URL from `metadata.repository`.

    Legacy reports carry markdown-autolink angle brackets (`<https://…>`),
    multi-URL prose, or trailing punctuation — all of which break ls-remote
    based inventories (PQC triage 2026-07-18: 26 of 109 "unreachable" repos
    were exactly this). Returns the first http(s) URL found, stripped of
    wrappers and trailing `/`/`.git`; None when no URL is present (bare
    names stay unresolvable here — classification belongs to the caller).
    """
    if not raw:
        return None
    m = _URL_IN_TEXT_RX.search(raw)
    if not m:
        return None
    url = m.group(0).rstrip(".").rstrip("/")
    return url.removesuffix(".git") or None


def analysis_results_root(arg=None) -> Path:
    """The analysis-results checkout: explicit arg or the configured root."""
    if arg:
        return Path(arg)
    ar = analysis_results_dir(configured_locations())
    if ar and (ar / "findings").is_dir():
        return ar
    raise FileNotFoundError(
        "analysis-results not found; pass it explicitly or set locations.analysis_results"
    )


def canonical(path, analysis_results=None) -> str:
    """Repo-relative path with symlinks resolved, relative to analysis-results."""
    root = analysis_results_root(analysis_results)
    return os.path.relpath(os.path.realpath(str(path)), os.path.realpath(str(root)))


def iter_report_paths(suffix: str = "-security-audit.json", analysis_results=None):
    """Yield each report once, as a canonical repo-relative path."""
    root = analysis_results_root(analysis_results)
    seen = set()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [
            d for d in dirnames if not _skip_dir(d) and not (Path(dirpath) / d).is_symlink()
        ]
        for fn in sorted(filenames):
            if not fn.endswith(suffix):
                continue
            full = Path(dirpath) / fn
            if full.is_symlink():
                continue
            rel = canonical(full, root)
            if rel in seen:
                continue
            seen.add(rel)
            yield rel


def walk_reports(root, suffix: str):
    """Absolute report paths under `root`, each physical file yielded once.

    Drop-in replacement for `root.rglob("*" + suffix)` that does not traverse
    the `findings/_orgs/` symlink index."""
    seen = set()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [
            d for d in dirnames if not _skip_dir(d) and not (Path(dirpath) / d).is_symlink()
        ]
        for fn in sorted(filenames):
            if not fn.endswith(suffix):
                continue
            full = Path(dirpath) / fn
            if full.is_symlink():
                continue
            real = os.path.realpath(full)
            if real in seen:
                continue
            seen.add(real)
            yield Path(full)


# ---------------------------------------------------------------------------
# resolution
# ---------------------------------------------------------------------------


@dataclass
class ReportRecord:
    tree: str
    label: str
    ownership: str
    business_unit: str
    product: str | None  # path between tree and repo dir; None = shallow
    repo_dir: str
    base: str  # report filename base
    base_slug: str  # base with branch-ref suffix stripped
    ref: str | None  # branch ref when this is a branch re-audit
    audit_json: str | None
    audit_md: str | None
    findings_current: str | None
    findings_layer: str | None
    triage_json: str | None
    threat_model: str | None
    priv_profile: str | None
    preferred: str  # findings_current | audit_json | audit_md_only
    repo_url: str | None = None
    report_kind: str = "code-audit"  # code-audit | cloud-config | container-audit
    ref_kind: str | None = None  # branch | tag | default (declared only)
    ref_source: str | None = None  # metadata | slug | None (HEAD legacy)

    @property
    def is_branch_audit(self) -> bool:
        # Declared provenance wins: only ref_kind == "branch" is a branch
        # re-audit (a declared "default"/"tag" checkout is not). Legacy
        # reports (no metadata.ref) keep the slug semantics: any
        # whitelisted slug ref is a branch re-audit.
        if self.ref_source == "metadata":
            return self.ref_kind == "branch"
        return self.ref is not None

    @property
    def is_md_only(self) -> bool:
        return self.audit_json is None

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if v is not None}
        d["is_branch_audit"] = self.is_branch_audit
        d["is_md_only"] = self.is_md_only
        return d


@dataclass
class Resolution:
    analysis_results: str
    records: list[ReportRecord] = field(default_factory=list)
    aliases: list[dict] = field(default_factory=list)  # symlink -> canonical
    warnings: list[str] = field(default_factory=list)
    trees: dict[str, dict] = field(default_factory=dict)


def _companion(dirpath: Path, base: str, suffix: str) -> str | None:
    p = dirpath / f"{base}{suffix}"
    return str(p) if p.is_file() else None


def resolve(
    analysis_results: Path,
    cfg: CorpusConfig,
    trees: list[str] | None = None,
    with_repo_urls: bool = False,
) -> Resolution:
    analysis_results = Path(analysis_results)
    configured = active_trees(cfg, analysis_results)
    # harness-qa trees are registered-but-not-corpus: probe/benchmark
    # artifacts must never enter a metrics lens, so they are excluded
    # here (centrally) rather than by each consumer.
    selected = {
        t: m
        for t, m in configured.items()
        if (trees is None or t in trees) and m.ownership != "harness-qa"
    }
    res = Resolution(analysis_results=str(analysis_results), trees=selected)

    for tree, meta in sorted(selected.items()):
        root = analysis_results / tree
        if not root.is_dir():
            res.warnings.append(f"configured tree missing on disk: {tree}")
            continue
        _walk_tree(root, tree, meta, res, with_repo_urls)

    _flag_unregistered_trees(analysis_results, configured, res)
    _flag_nested_duplicate_dirs(res)
    return res


def _flag_nested_duplicate_dirs(res: Resolution) -> None:
    """Flag the week1-fullaudit misplacement signature: the same report
    base present both at a directory and at a direct child of it
    (`<x>/<repo>/` and `<x>/<repo>/<repo>/`). A batch agent that treats a
    repo_key (`tree/[product/]repo_dir/base`) as an output DIRECTORY
    creates exactly this split state, and every baseline-beside-the-
    artifact consumer then misreads the dir (2026-07-27 week-1 batch: 6
    of 110 re-audits; repaired 2026-07-28). Canonical product dirs named
    after their repo (findings/clowder/clowder/) are NOT flagged — their
    reports live only in the child."""
    by_dir: dict[str, set[str]] = {}
    for r in res.records:
        report = r.audit_json or r.audit_md
        if not report:
            continue
        by_dir.setdefault(str(Path(report).parent), set()).add(r.base)
    for d, bases in sorted(by_dir.items()):
        parent = str(Path(d).parent)
        for base in sorted(bases & by_dir.get(parent, set())):
            res.warnings.append(
                f"nested duplicate report dir: {d} shadows {parent} for "
                f"base '{base}' — <repo>/<repo>/ misplacement (repo_key "
                f"is an identity, not a directory); reconcile to the "
                f"flat dir per docs/report-structure.md"
            )


def _walk_tree(
    root: Path, tree: str, meta: TreeMeta, res: Resolution, with_repo_urls: bool
) -> None:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirpath = Path(dirpath)
        # dir symlinks are aliases too; never descend or count through them
        for d in list(dirnames):
            if _skip_dir(d):
                dirnames.remove(d)
            elif (dirpath / d).is_symlink():
                dirnames.remove(d)
                res.aliases.append(
                    {
                        "link": str(dirpath / d),
                        "kind": "dir",
                        "target": str((dirpath / d).resolve()),
                    }
                )

        # Accumulated per DIRECTORY, not appended straight to the
        # resolution: a base can produce one record per audit kind, and the
        # kind-less companions beside them need one owner chosen before the
        # records escape. See _claim_shared_cumulative.
        dir_records: list[ReportRecord] = []
        for kind, json_suffix, md_suffix in REPORT_KINDS:
            json_bases, md_bases = set(), set()
            for fn in filenames:
                for suffix, bases in ((json_suffix, json_bases), (md_suffix, md_bases)):
                    if not fn.endswith(suffix):
                        continue
                    path = dirpath / fn
                    if path.is_symlink():
                        res.aliases.append(
                            {
                                "link": str(path),
                                "kind": "file",
                                "target": str(path.resolve()),
                            }
                        )
                    else:
                        bases.add(fn[: -len(suffix)])

            # Container reports live in the SAME directory as the source
            # repo's code audit (findings/<product>/<image>/), so a bare
            # image-name base would collide with the code record: same
            # repo_key, and the same companion artifacts
            # (<base>-findings-layer.json, <base>-triage.json, …). Keep
            # the "-container-audit" marker inside `base` — the record's
            # identity and every ledger companion then sit next to the
            # code audit's without clashing, matching the stems
            # build_cumulative.py and the ledger emitters derive.
            if kind == "container-audit":
                json_bases = {b + "-container-audit" for b in json_bases}
                md_bases = {b + "-container-audit" for b in md_bases}
                rec_json_suffix, rec_md_suffix = ".json", ".md"
            else:
                rec_json_suffix, rec_md_suffix = json_suffix, md_suffix

            for base in sorted(json_bases | md_bases):
                dir_records.append(
                    _record(
                        dirpath,
                        base,
                        root,
                        tree,
                        meta,
                        has_json=base in json_bases,
                        has_md=base in md_bases,
                        with_repo_urls=with_repo_urls,
                        report_kind=kind,
                        json_suffix=rec_json_suffix,
                        md_suffix=rec_md_suffix,
                    )
                )

        _claim_shared_cumulative(dir_records, res)
        res.records.extend(dir_records)


def _cumulative_kind(path: Path) -> str | None:
    """Which audit kind wrote this cumulative report, or None if unreadable.

    The two families are separated by the CONTRACT, not by a guess:
    `report.schema.json` requires `executive_summary`, and
    `cloud-config-findings-current.schema.json` sets
    `additionalProperties: false` without declaring it. A document
    carrying it cannot be a cloud-config restatement, and one lacking it
    cannot be a report. Returning None on an unreadable file is
    deliberate -- the caller leaves the ambiguity in place and warns
    rather than picking an owner at random.
    """
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return None
    if not isinstance(document, dict):
        return None
    return "code-audit" if "executive_summary" in document else "cloud-config"


def _claim_shared_cumulative(records: list[ReportRecord], res: Resolution) -> None:
    """One cumulative report, one owner.

    A directory holding both a code audit and a cloud-config audit for
    the same base yields one ReportRecord per KIND -- correct, because
    the two units must never blend. But the companions beside them carry
    no kind marker in their filename (`<base>-findings-current.json`),
    so `_record` hands the same file to both records, and every consumer
    that walks records then counts those findings twice. Measured on the
    live corpus before this: 181 duplicated open rows across three
    directories, the same fingerprints under both repo_keys.

    Container audits do not hit this -- the walk keeps `-container-audit`
    inside `base`, so their companions never collide. cloud-config never
    got that treatment because its audits historically sat in a tree of
    their own, with no code audit beside them.

    Only the ambiguous case is touched: a base with a single record keeps
    exactly what it had.
    """
    by_base: dict[str, list[ReportRecord]] = {}
    for record in records:
        by_base.setdefault(record.base, []).append(record)
    for _base, group in sorted(by_base.items()):
        if len(group) < 2:
            continue
        path = next((r.findings_current for r in group if r.findings_current), None)
        if path is None:
            continue
        owner = _cumulative_kind(Path(path))
        kinds = sorted({r.report_kind for r in group})
        if owner is None or owner not in kinds:
            res.warnings.append(
                f"shared cumulative report with no resolvable owner: {path} "
                f"is claimed by {len(group)} records ({', '.join(kinds)}) and "
                f"its shape matches none of them — every consumer counts its "
                f"findings once per record until this is reconciled"
            )
            continue
        for record in group:
            if record.report_kind == owner:
                continue
            record.findings_current = None
            record.preferred = "audit_json" if record.audit_json else "audit_md_only"


def _record(
    dirpath: Path,
    base: str,
    root: Path,
    tree: str,
    meta: TreeMeta,
    has_json: bool,
    has_md: bool,
    with_repo_urls: bool,
    report_kind: str = "code-audit",
    json_suffix: str = AUDIT_JSON_SUFFIX,
    md_suffix: str = AUDIT_MD_SUFFIX,
) -> ReportRecord:
    rel_parts = dirpath.relative_to(root).parts
    product = "/".join(rel_parts[:-1]) if len(rel_parts) > 1 else None
    repo_dir = rel_parts[-1] if rel_parts else root.name
    base_slug, ref = split_ref(base)
    if ref is None:  # dir naming carries the ref for some legacy layouts
        _, ref = split_ref(repo_dir)
    ref_source = "slug" if ref else None
    ref_kind = None

    audit_json = str(dirpath / f"{base}{json_suffix}") if has_json else None

    if audit_json:  # declared ref provenance wins over slug parsing
        decl_ref, decl_kind = declared_ref(Path(audit_json))
        if decl_ref:
            ref, ref_kind, ref_source = decl_ref, decl_kind, "metadata"
    findings_current = _companion(dirpath, base, "-findings-current.json")
    preferred = (
        "findings_current" if findings_current else "audit_json" if has_json else "audit_md_only"
    )

    repo_url = None
    if with_repo_urls and audit_json:
        try:
            rep = json.loads(Path(audit_json).read_text(encoding="utf-8"))
            raw = (rep.get("metadata") or {}).get("repository")
            repo_url = normalize_repo_url(raw) or raw
        except (OSError, json.JSONDecodeError):
            pass

    return ReportRecord(
        tree=tree,
        label=meta.label,
        ownership=meta.ownership,
        business_unit=meta.business_unit,
        product=product,
        repo_dir=repo_dir,
        base=base,
        base_slug=base_slug,
        ref=ref,
        audit_json=audit_json,
        audit_md=str(dirpath / f"{base}{md_suffix}") if has_md else None,
        findings_current=findings_current,
        findings_layer=_companion(dirpath, base, "-findings-layer.json"),
        triage_json=_companion(dirpath, base, "-triage.json"),
        threat_model=_companion(dirpath, base, "-threat-model.md"),
        priv_profile=_companion(dirpath, base, "-priv-profile.json"),
        preferred=preferred,
        repo_url=repo_url,
        report_kind=report_kind,
        ref_kind=ref_kind,
        ref_source=ref_source,
    )


def _flag_unregistered_trees(analysis_results: Path, configured: dict, res: Resolution) -> None:
    """Any top-level dir holding audit reports but absent from the config
    is drift between disk and corpus-config — flag it, never guess."""
    for entry in sorted(analysis_results.iterdir()):
        if (
            not entry.is_dir()
            or entry.is_symlink()
            or entry.name.startswith(".")
            or entry.name in configured
        ):
            continue
        for dirpath, dirnames, filenames in os.walk(entry, followlinks=False):
            dirnames[:] = [d for d in dirnames if not _skip_dir(d)]
            hits = [
                f
                for f in filenames
                if f.endswith(
                    (AUDIT_JSON_SUFFIX, AUDIT_MD_SUFFIX, CLOUD_JSON_SUFFIX, CLOUD_MD_SUFFIX)
                )
            ]
            if hits:
                res.warnings.append(
                    f"unregistered tree contains audit reports: "
                    f"{entry.name}/ (e.g. {Path(dirpath).name}/{hits[0]}) "
                    f"— register it in corpus-config.yaml via /corpus-intake"
                )
                break


# ---------------------------------------------------------------------------
# aggregates & manifest
# ---------------------------------------------------------------------------


def _ref_counts(recs) -> dict[str, int]:
    """Per-ref report counter (branch-awareness Phase 1):
    every record carrying a ref — legacy slug refs and declared
    `metadata.ref` alike — keyed by the literal ref string. Purely
    additive metadata: no pre-existing aggregate is derived from it."""
    counts: dict[str, int] = {}
    for r in recs:
        if r.ref:
            counts[r.ref] = counts.get(r.ref, 0) + 1
    return dict(sorted(counts.items()))


def aggregates(res: Resolution) -> dict:
    trees: dict[str, dict] = {}
    for tree, meta in res.trees.items():
        recs = [r for r in res.records if r.tree == tree]
        slugs = {r.base_slug for r in recs}
        head = [r for r in recs if not r.is_branch_audit]
        by_kind: dict[str, int] = {}
        for r in recs:
            by_kind[r.report_kind] = by_kind.get(r.report_kind, 0) + 1
        trees[tree] = {
            "label": meta.label,
            "ownership": meta.ownership,
            "business_unit": meta.business_unit,
            "reports": len(recs),
            # reports is ALL kinds in the tree; container-audit and
            # cloud-config records never blend into code-audit risk
            # cuts — consumers needing one unit filter on report_kind.
            "by_kind": by_kind,
            "reports_md_only": sum(r.is_md_only for r in recs),
            "branch_reaudits": sum(r.is_branch_audit for r in recs),
            "refs": _ref_counts(recs),
            "head_reports": len(head),
            "unique_base_slugs": len(slugs),
            "with_findings_current": sum(bool(r.findings_current) for r in recs),
            "with_triage": sum(bool(r.triage_json) for r in recs),
            "with_threat_model": sum(bool(r.threat_model) for r in recs),
            "shallow_dirs": sum(r.product is None for r in recs),
        }

    slug_trees: dict[str, set] = {}
    for r in res.records:
        slug_trees.setdefault(r.base_slug, set()).add(r.tree)
    overlap = {s: sorted(t) for s, t in slug_trees.items() if len(t) > 1}

    file_aliases = [a for a in res.aliases if a["kind"] == "file"]
    return {
        "trees": trees,
        "totals": {
            "reports": len(res.records),
            "unique_base_slugs": len(slug_trees),
            "branch_reaudits": sum(r.is_branch_audit for r in res.records),
            "refs": _ref_counts(res.records),
            "md_only": sum(r.is_md_only for r in res.records),
        },
        "duplication": {
            "symlink_aliases": len(file_aliases),
            "symlink_canonical_targets": len({a["target"] for a in file_aliases}),
            "dir_symlink_aliases": len(res.aliases) - len(file_aliases),
            "branch_reaudit_reports": sum(r.is_branch_audit for r in res.records),
            "cross_tree_slugs": len(overlap),
            "cross_tree_examples": dict(sorted(overlap.items())[:20]),
        },
    }


def build_manifest(res: Resolution, cfg: CorpusConfig) -> dict:
    agg = aggregates(res)
    return {
        "generated": datetime.now(UTC).isoformat(timespec="seconds"),
        "harness_version": harness_version(),
        "config": {"sha": cfg.source_sha, "version": cfg.version},
        "analysis_results": res.analysis_results,
        **agg,
        "warnings": res.warnings,
        "aliases": res.aliases,
        "records": [r.to_dict() for r in res.records],
    }


# ---------------------------------------------------------------------------
# population block
# ---------------------------------------------------------------------------


def roots_description(
    cfg: CorpusConfig, trees: list[str] | None = None, extra: list[str] | None = None
) -> list[str]:
    """DEPRECATED 2026-08-20 — the scheduled corpus-manifest.json write is retired.

    Kept for on-demand snapshots (`resolve --out`), not for consumers: the
    manifest was measurably read by nothing, and every field it carried now
    lives in findings.db `repos`, which adds repo_key, repo_url, ref,
    audit_date and the six artifact refs. Query the projection.
    Human-readable root descriptions with ownership tags, for tools
    whose roots are registered corpus trees. `extra` appends verbatim
    descriptions for non-tree roots (manifest CSVs, validations/, …)."""
    out = []
    known: dict[str, TreeMeta] = dict(cfg.trees)
    for eng in cfg.engagements.values():
        known.setdefault(eng.tree, eng)
    for t in trees or []:
        m = known.get(t)
        out.append(f"`{t}/` ({m.ownership}, {m.business_unit})" if m else f"`{t}/` (UNREGISTERED)")
    out.extend(extra or [])
    return out


def population_block_lines(
    *,
    tool: str,
    roots: list[str],
    unit: str,
    filters: str,
    denominator: str,
    counts: dict | None = None,
    warnings: list[str] | None = None,
) -> list[str]:
    """The standard provenance block every generated dashboard embeds so
    any two headline numbers can be reconciled on paper. Field-driven:
    each dashboard reports what IT actually scanned/skipped via `counts`
    (label -> value, rendered in order)."""
    lines = [
        "## Population",
        "",
        f"- **Tool:** {tool} · harness {harness_version()}",
        "- **Roots walked:** " + ", ".join(roots),
        f"- **Unit counted:** {unit}",
        f"- **Filters:** {filters}",
        f"- **Denominator source:** {denominator}",
    ]
    for label, value in (counts or {}).items():
        lines.append(f"- **{label}:** {value}")
    if warnings:
        lines.append(f"- **Warnings:** {len(warnings)} — " + " | ".join(warnings[:3]))
    return lines


def render_population_block(
    res: Resolution, *, tool: str, unit: str, filters: str, denominator: str
) -> str:
    """Resolution-driven convenience wrapper around
    population_block_lines() for tools built directly on resolve()."""
    agg = aggregates(res)
    return (
        "\n".join(
            population_block_lines(
                tool=tool,
                roots=[
                    f"`{t}/` ({m.ownership}, {m.business_unit})"
                    for t, m in sorted(res.trees.items())
                ],
                unit=unit,
                filters=filters,
                denominator=denominator,
                counts={
                    "Reports in scope": f"{agg['totals']['reports']} "
                    f"({agg['totals']['unique_base_slugs']} unique repo slugs; "
                    f"{agg['totals']['branch_reaudits']} branch re-audits; "
                    f"{agg['totals']['md_only']} md-only parse gaps)",
                    "Symlink aliases excluded": f"{agg['duplication']['symlink_aliases']} file, "
                    f"{agg['duplication']['dir_symlink_aliases']} dir "
                    f"(→ {agg['duplication']['symlink_canonical_targets']} "
                    f"canonical reports)",
                },
                warnings=res.warnings,
            )
        )
        + "\n"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _find_analysis_results(arg: str | None) -> Path:
    if arg:
        return Path(arg)
    ar = analysis_results_dir(configured_locations())
    if ar and ar.is_dir():
        return ar
    sys.exit("analysis-results not found; pass --analysis-results")


def load_findings_typed(report_path: Path) -> list[Finding]:
    """Load findings from a report JSON and return typed objects."""
    if not HAS_CONTRACTS:
        raise ImportError("traust_contracts required for typed findings")
    data = json.loads(report_path.read_text(encoding="utf-8"))
    return [Finding.from_dict(f) for f in data.get("findings", [])]
