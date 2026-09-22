"""Ingest the artifact tree into a traust-contracts storage/v1 store.

This is the seam that makes git-or-database an ADOPTER CHOICE rather than a
fork in the code. An adopter who keeps artifacts in git runs this to
materialise a local SQLite store; an adopter on a database gets the same
rows at submit time. Either way the dashboards read the same views, because
the views are the contract and the loading is not.

Uses `corpus.resolve()` for discovery -- never a hand-rolled walk -- so the
population here is the same population `/census` counts, and the two cannot
silently disagree about what the corpus is.

Binding, and why:

  scope_id    resolved from corpus-config via CorpusConfig.scope_for(tree),
              so a deployment that partitions per business unit gets that
              partition here without a code change.
  subject_id  the corpus repo_key. This is the join key `subject_ownership`
              is keyed on, which is what lets a finding reach its owner.
  run_id      one per repo per import. The audit, its findings-current
              restatement and its triage MUST share a run_id, because
              `findings_summary` joins finding to triage_verdict on it --
              give them different runs and every verdict silently
              disappears from the summary.
  layer_id    one per repo. Layer artifacts are layer-bound, not run-bound.

Idempotent: `artifact_evidence` is content-addressed, so re-running binds
nothing new and reports `already_bound`.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from itertools import chain
from pathlib import Path
from typing import Any

from traust_contracts.config import CorpusConfig
from traust_contracts.v1.storage import Binding, IngestError, Store

from traust_engine.corpus import resolver as corpus

#: Which artifact family a resolved ref belongs to. `report_kind` splits the
#: cloud-config lane off: those documents validate against their own schema
#: and ingesting them as `report` fails on required properties they do not
#: have. Routing by kind rather than by family name is the whole fix.
FAMILY_BY_REF: dict[str, dict[str, str]] = {
    "audit_json": {
        "code-audit": "report",
        "container-audit": "report",
        "cloud-config": "cloud-config-audit",
    },
    "findings_current": {
        "code-audit": "report",
        "container-audit": "report",
        "cloud-config": "cloud-config-findings-current",
    },
    "triage_json": {
        "code-audit": "triage",
        "container-audit": "triage",
        "cloud-config": "triage",
    },
    "findings_layer": {
        "code-audit": "layer",
        "container-audit": "layer",
        "cloud-config": "layer",
    },
    # Operator privilege profiles ride the same per-subject refs as the
    # reports beside them. Same family regardless of report_kind: the
    # profile describes shipped manifests, not the audit that found them.
    "priv_profile": {
        "code-audit": "operator-priv-profile",
        "container-audit": "operator-priv-profile",
        "cloud-config": "operator-priv-profile",
    },
}

#: Families whose artifact sits beside a ref the resolver already returns,
#: at the same base with a different suffix. Derived rather than added to
#: ReportRecord: report_store rebuilds that record from findings.db
#: FIELD-FOR-FIELD, so a new field forces a new findings.db column -- and a
#: file path is resolver bookkeeping, not something the contract schema
#: defines. The contract's expression of a threat model is the `threat`
#: projection and the threat_current view.
DERIVED_BY_SUFFIX: dict[str, tuple[str, str, str]] = {
    # family: (ref the resolver returns, its suffix, the suffix to swap in)
    "threat-model": ("threat_model", "-threat-model.md", "-threat-model.json"),
    # Verification closes the remediate loop: a fix is claimed, and this
    # adjudicates whether it held. They sit beside the audit they
    # re-check, every one with a sibling <base>-security-audit.json, so the
    # path derives rather than needing a ReportRecord field.
    "verification": (
        "audit_json",
        "-security-audit.json",
        "-remediation-verification.json",
    ),
    # Official-docs claims contradicted by code evidence. Same shape.
    "doc-variance": ("audit_json", "-security-audit.json", "-doc-variance.json"),
}


@dataclass
class IngestReport:
    ingested: int = 0
    already: int = 0
    rejected: int = 0
    missing: int = 0
    unregistered: dict[str, int] = field(default_factory=dict)
    #: Lane artifacts whose repository matches no corpus subject. Counted
    #: rather than bound to an invented subject: outside the declared
    #: corpus means no owner and no denominator.
    unmatched_lane: dict[str, int] = field(default_factory=dict)
    subjects: int = 0
    by_family: dict[str, int] = field(default_factory=dict)
    reasons: dict[str, int] = field(default_factory=dict)
    failures: list[tuple[str, str]] = field(default_factory=list)

    @property
    def considered(self) -> int:
        return self.ingested + self.already + self.rejected

    def rate(self) -> float:
        return (self.ingested + self.already) / self.considered if self.considered else 0.0


def repo_key(record: corpus.ReportRecord) -> str:
    """The corpus identity of one audited subject. Mirrors findings_db."""
    parts = [record.tree]
    if record.product:
        parts.append(record.product)
    parts.extend([record.repo_dir, record.base])
    key = "/".join(parts)
    return f"{key}#cloud-config" if record.report_kind == "cloud-config" else key


def _run_id(subject: str, path: Path | None, results: Path | None) -> str:
    """The run this artifact belongs to.

    Per-SUBJECT is wrong for the cross-cutting lanes. One subject can own
    many lane artifacts -- `acm-cli` has 18 validation runs, `acm.v040`
    through `acm.v060` plus an `acm.v058/spoke` variant -- and keying the
    run on the subject alone gave all 18 the identical binding context.
    They stayed distinct only because their CONTENT digests differ, which
    means no consumer could tell one run from another, order them, or ask
    which one a row came from.

    The lane directory is the run: `validations/acm.v060/…` and
    `validations/acm.v058/spoke/…` are what the operator actually named.
    Using it keeps the identifier inside the corpus layout rather than
    inventing one, and it is stable across re-ingest because it is on
    disk. Reports beside a subject keep the per-subject form: there is
    exactly one of each there, so it was never ambiguous.
    """
    if path is None or results is None:
        return f"corpus:run:{subject}"
    try:
        relative = Path(path).resolve().relative_to(Path(results).resolve())
    except ValueError:
        return f"corpus:run:{subject}"
    parts = relative.parts
    if len(parts) < 2 or parts[0] not in LANE_SPECS:
        return f"corpus:run:{subject}"
    # everything between the lane root and the filename
    return "corpus:run:" + "/".join(parts[:-1])


def _bindings(
    family: str,
    scope: str,
    subject: str | None,
    path: Path | None = None,
    results: Path | None = None,
) -> Binding:
    if family == "layer":
        return Binding(scope_id=scope, layer_id=f"corpus:layer:{subject}")
    if subject is None:
        # An aggregate belongs to the scope. No invented subject.
        return Binding(scope_id=scope)
    return Binding(
        scope_id=scope,
        subject_id=subject,
        run_id=_run_id(subject, path, results),
    )


@dataclass(frozen=True)
class LaneSpec:
    """How one cross-cutting lane is shaped.

    Lanes differ in two ways that matter and cannot be guessed:

      glob   pqc files one directory deep, validations up to three
             (core-ocp-4.12/aws/<component>/). Globbing too shallow
             silently drops 653 validations; too deep picks up retired
             duplicates under _manifest.
      link   how the artifact names its subject. pqc carries a repository
             URL; a validation names the audit REPORT it validated, and
             has no repository field at all.
    """

    glob: str
    families: dict[str, str]
    link: str  # "repo_url" | "source_report"


#: Cross-cutting lanes: artifacts that live in their OWN tree, keyed by
#: repository or by the report they derive from, rather than filed beside a
#: subject's reports. They still belong to a corpus subject.
LANE_SPECS: dict[str, LaneSpec] = {
    "pqc": LaneSpec(
        glob="*/*.json",
        families={
            "-pqc-readiness.json": "pqc-readiness",
            "-pqc-facts.json": "pqc-facts",
            "-pqc-blockers.json": "pqc-blockers",
        },
        link="repo_url",
    ),
    "validations": LaneSpec(
        glob="**/*.json",
        families={"-validation.json": "validation"},
        link="source_report",
    ),
}


def _canonical_repo_url(url: str | None) -> str | None:
    """Normalise a repo URL so two spellings of one repo match.

    Trailing slash, a `.git` suffix and case all vary between the corpus
    registry and a lane artifact's metadata. Measured across the live
    corpus, normalising these three gives a complete join.
    """
    if not url:
        return None
    return url.strip().rstrip("/").removesuffix(".git").lower() or None


def _corpus_relative(path: str | None) -> str | None:
    """The corpus-relative tail of a recorded artifact path.

    Lane artifacts record ABSOLUTE paths from the machine that produced
    them, so the leading directories are meaningless here. Everything from
    `analysis-results/` onward is the portable part.
    """
    if not path:
        return None
    return str(path).split("analysis-results/")[-1] or None


def _subject_index(resolution: Any, link: str) -> dict[str, Any]:
    """Index corpus records by whichever key this lane links on."""
    index: dict[str, Any] = {}
    for record in resolution.records:
        if link == "repo_url":
            key = _canonical_repo_url(getattr(record, "repo_url", None))
            if key:
                index.setdefault(key, record)
            continue
        # A validation names the report it validated, and which report that
        # is varies -- audit, findings-current, the markdown audit when
        # there is no JSON, or the triage. Index all of them.
        for attr in ("audit_json", "findings_current", "audit_md", "triage_json"):
            key = _corpus_relative(getattr(record, attr, None))
            if key:
                index.setdefault(key, record)
    return index


def _lane_subject(document: dict, spec: LaneSpec, index: dict[str, Any]) -> Any:
    """Resolve a lane artifact to its corpus record, or None."""
    if spec.link == "repo_url":
        # Where the repository lives differs BY FAMILY: pqc-readiness nests
        # it under metadata, pqc-facts carries it at the top level. Reading
        # one shape silently matched nothing for the other.
        url = _canonical_repo_url(
            (document.get("metadata") or {}).get("repository") or document.get("repository")
        )
        return index.get(url or "")
    for source in document.get("source_reports") or []:
        record = index.get(_corpus_relative(source.get("path")) or "")
        if record is not None:
            return record
    return None


def plan_lanes(
    results: Path, cfg: CorpusConfig, resolution: Any, lanes: list[str] | None = None
) -> Iterator[tuple]:
    """Yield (family, scope, subject, path) for cross-cutting lane artifacts.

    The subject and scope come from the SAME resolution the registry is
    built from, never from a second walk -- a lane that guessed its own
    ownership would be a second answer to "who owns this", which is the
    disagreement this whole projection exists to remove.

    A lane artifact that resolves to no corpus subject is reported rather
    than bound to an invented one: it means the work sits outside the
    declared corpus, so it has no owner and no denominator.
    """
    for lane, spec in LANE_SPECS.items():
        if lanes is not None and lane not in lanes:
            continue
        root = results / lane
        if not root.is_dir():
            continue
        index = _subject_index(resolution, spec.link)
        for path in sorted(root.glob(spec.glob)):
            # `_manifest` is corpus bookkeeping, not subject artifacts. It
            # holds retired-duplicate-slugs among other things, and
            # ingesting those would double-count 20 repos.
            if "_manifest" in path.parts:
                continue
            family = next(
                (f for suffix, f in spec.families.items() if path.name.endswith(suffix)),
                None,
            )
            if family is None:
                continue
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                yield ("__unreadable__", lane, path.name, None)
                continue
            record = _lane_subject(document, spec, index)
            if record is None:
                yield ("__unmatched_lane__", lane, path.name, None)
                continue
            try:
                scope = cfg.scope_for(record.tree)
            except KeyError:
                yield ("__unregistered__", record.tree, repo_key(record), None)
                continue
            yield family, scope, repo_key(record), path


#: Lanes whose artifacts belong to the SCOPE rather than to one subject.
#: An impact analysis is one advisory assessed across many repos -- it has
#: no single subject, which is exactly why profiles.json classes it
#: `aggregate` with no required binding context. Forcing a subject on it
#: would have to pick one of the repos it names, and every choice is wrong.
AGGREGATE_LANES: dict[str, tuple[str, str]] = {
    # directory: (glob, family)
    "impact": ("*-impact-analysis.json", "impact-analysis"),
}


def plan_aggregates(results: Path, cfg: CorpusConfig) -> Iterator[tuple]:
    """Yield (family, scope, None, path) for scope-level artifacts."""
    scope = cfg.readable_scopes()[0] if len(cfg.readable_scopes()) == 1 else cfg.scope.id
    for lane, (pattern, family) in AGGREGATE_LANES.items():
        root = results / lane
        if not root.is_dir():
            continue
        for path in sorted(root.glob(pattern)):
            if "_manifest" in path.parts:
                continue
            yield family, scope, None, path


def plan(results: Path, cfg: CorpusConfig, trees: list[str] | None = None) -> Iterator[tuple]:
    """Yield (family, scope, subject, path) for every ingestable artifact."""
    resolution = corpus.resolve(results, cfg, trees=trees, with_repo_urls=True)
    for record in resolution.records:
        subject = repo_key(record)
        try:
            scope = cfg.scope_for(record.tree)
        except KeyError:
            # corpus-config is the ownership authority. A tree it does not
            # declare has no ownership, so it has no denominator and must
            # not be counted -- but it also must not crash the run. The
            # resolver already surfaces unregistered trees as warnings;
            # this reports them the same way rather than guessing a scope.
            yield ("__unregistered__", record.tree, subject, None)
            continue
        for family, (ref_name, old_suffix, new_suffix) in DERIVED_BY_SUFFIX.items():
            ref = getattr(record, ref_name, None)
            if not ref or not str(ref).endswith(old_suffix):
                continue
            candidate = Path(str(ref)[: -len(old_suffix)] + new_suffix)
            if candidate.is_file():
                yield family, scope, subject, candidate
        for ref_name, by_kind in FAMILY_BY_REF.items():
            ref = getattr(record, ref_name, None)
            if not ref:
                continue
            family = by_kind.get(record.report_kind)
            if family is None:
                continue
            yield family, scope, subject, results / ref


def build_registry(results: Path, cfg: CorpusConfig, trees: list[str] | None = None) -> dict:
    """A corpus-registry artifact from the resolution.

    Ownership is the denominator every dashboard cut divides by, and it
    lives in corpus-config plus the inventory -- nowhere in the artifacts
    themselves. Without this, subject_ownership is empty and
    v_distinct_owned cannot be computed from storage/v1 at all.

    Unregistered trees are omitted for the same reason they are skipped on
    ingest: corpus-config is the ownership authority and a tree it does not
    declare has no denominator.
    """
    resolution = corpus.resolve(results, cfg, trees=trees, with_repo_urls=True)
    subjects = []
    for record in resolution.records:
        # tree_meta, not cfg.trees: a registered ENGAGEMENT tree is a
        # first-class ownership carrier and resolver.active_trees() merges
        # it in. Filtering on cfg.trees dropped 53 repos / 399 findings.
        meta = cfg.tree_meta(record.tree)
        if meta is None:
            continue
        subject: dict[str, Any] = {
            "subject_id": repo_key(record),
            "tree": record.tree,
            "ownership": meta.ownership,
            "business_unit": meta.business_unit,
            "is_branch_audit": bool(record.is_branch_audit),
        }
        for key, value in (
            ("label", meta.label),
            ("product", record.product),
            ("repo_url", record.repo_url),
            ("ref", record.ref),
        ):
            if value:
                subject[key] = value
        if record.ref_kind in ("branch", "tag", "default", "stream"):
            subject["ref_kind"] = record.ref_kind
        subjects.append(subject)
    return {
        "version": 1,
        "updated": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "subjects": subjects,
    }


def ingest_registry(store: Store, results: Path, cfg: CorpusConfig, trees=None) -> int:
    """Ingest the registry. Returns the subject count."""
    document = build_registry(results, cfg, trees)
    scope = cfg.readable_scopes()[0] if len(cfg.readable_scopes()) == 1 else cfg.scope.id
    payload = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode()
    store.ingest("corpus-registry", payload, Binding(scope_id=scope))
    return len(document["subjects"])


def ingest_tree(
    store: Store,
    results: Path,
    cfg: CorpusConfig,
    *,
    trees: list[str] | None = None,
    dry_run: bool = False,
) -> IngestReport:
    """Ingest every resolvable artifact. Reports rejections, never hides them."""
    report = IngestReport()
    # ONE resolution, shared by the registry, the tree walk and the lanes.
    # Resolving separately per consumer is how two of them come to disagree
    # about what the corpus is.
    resolution = corpus.resolve(results, cfg, trees=trees, with_repo_urls=True)
    if not dry_run:
        report.subjects = ingest_registry(store, results, cfg, trees)
    planned = chain(
        plan(results, cfg, trees),
        plan_lanes(results, cfg, resolution),
        plan_aggregates(results, cfg),
    )
    for family, scope, subject, path in planned:
        if family == "__unregistered__":
            report.unregistered[scope] = report.unregistered.get(scope, 0) + 1
            continue
        if family in ("__unmatched_lane__", "__unreadable__"):
            report.unmatched_lane[scope] = report.unmatched_lane.get(scope, 0) + 1
            continue
        if not path.exists():
            report.missing += 1
            continue
        payload = path.read_bytes()
        if dry_run:
            report.ingested += 1
            report.by_family[family] = report.by_family.get(family, 0) + 1
            continue
        try:
            result = store.ingest(family, payload, _bindings(family, scope, subject, path, results))
        except IngestError as error:
            report.rejected += 1
            reason = str(error).split("validation:", 1)[-1].strip()[:70]
            report.reasons[reason] = report.reasons.get(reason, 0) + 1
            if len(report.failures) < 20:
                report.failures.append((str(path), reason))
            continue
        if result.already_bound:
            report.already += 1
        else:
            report.ingested += 1
        report.by_family[family] = report.by_family.get(family, 0) + 1
    return report


def render(report: IngestReport) -> str:
    lines = [
        f"ingest: {report.ingested} new, {report.already} already bound, "
        f"{report.rejected} rejected, {report.missing} missing "
        f"({report.rate():.1%} of {report.considered} accepted)"
    ]
    for family, count in sorted(report.by_family.items(), key=lambda kv: -kv[1]):
        lines.append(f"  {count:6}  {family}")
    if report.subjects:
        lines.append(f"  {report.subjects:6}  subjects registered (ownership)")
    if report.unregistered:
        lines.append(
            "SKIPPED -- tree not declared in corpus-config, so it has no "
            "ownership and no denominator:"
        )
        for tree, count in sorted(report.unregistered.items(), key=lambda kv: -kv[1]):
            lines.append(f"  {count:6}  {tree}")
    if report.unmatched_lane:
        lines.append(
            "SKIPPED -- lane artifact whose repository is not a corpus subject, so it has no owner:"
        )
        for lane, count in sorted(report.unmatched_lane.items(), key=lambda kv: -kv[1]):
            lines.append(f"  {count:6}  {lane}")
    if report.reasons:
        lines.append("rejections:")
        for reason, count in sorted(report.reasons.items(), key=lambda kv: -kv[1]):
            lines.append(f"  {count:6}x {reason}")
    return "\n".join(lines)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))
