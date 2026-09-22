"""Tree -> storage/v1 ingest: the seam that makes git-or-database a choice."""

from __future__ import annotations

import json
import sqlite3

import yaml
from traust_contracts.config import CorpusConfig
from traust_contracts.v1.storage import Store

from traust_engine.corpus import store_ingest as si

CONFIG = yaml.safe_load("""
version: 1
trees:
  findings: {label: a, ownership: owned, business_unit: BU}
  cloud-config: {label: b, ownership: owned, business_unit: BU}
""")


def _cfg(**scope):
    payload = dict(CONFIG)
    if scope:
        payload["scope"] = scope
    return CorpusConfig(**payload)


def test_cloud_config_routes_to_its_own_family():
    """Ingesting a cloud-config document as `report` fails on required
    properties it does not have. Routing by report_kind is the fix."""
    assert si.FAMILY_BY_REF["findings_current"]["cloud-config"] == "cloud-config-findings-current"
    assert si.FAMILY_BY_REF["findings_current"]["code-audit"] == "report"
    assert si.FAMILY_BY_REF["audit_json"]["cloud-config"] == "cloud-config-audit"


def test_a_repo_audit_triage_and_current_share_one_run_id():
    """findings_summary joins finding to triage_verdict on run_id. Give them
    different runs and every verdict silently vanishes from the summary."""
    report = si._bindings("report", "local", "tree/repo/base")
    triage = si._bindings("triage", "local", "tree/repo/base")
    assert report.run_id == triage.run_id
    assert report.subject_id == triage.subject_id == "tree/repo/base"


def test_a_layer_binds_by_layer_not_by_run():
    layer = si._bindings("layer", "local", "tree/repo/base")
    assert layer.layer_id and layer.run_id is None and layer.subject_id is None


def test_scope_comes_from_config_so_partitioning_needs_no_code_change():
    assert si._bindings("report", "hybrid-platforms", "s").scope_id == "hybrid-platforms"


def test_an_unregistered_tree_is_skipped_and_reported_not_guessed(tmp_path):
    """corpus-config is the ownership authority. A tree it does not declare
    has no denominator, so it must not be counted -- and must not crash."""
    report = si.IngestReport()
    report.unregistered["lightwell-findings"] = 53
    rendered = si.render(report)
    assert "not declared in corpus-config" in rendered
    assert "lightwell-findings" in rendered


def test_render_surfaces_rejections_rather_than_hiding_them():
    report = si.IngestReport(ingested=10, rejected=2)
    report.reasons["schema rule required at /required"] = 2
    rendered = si.render(report)
    assert "rejections:" in rendered and "2x" in rendered
    assert "83.3%" in rendered or "83" in rendered


def test_repo_key_marks_cloud_config_so_it_cannot_collide():
    """A repo can have both a code audit and a cloud-config audit; they are
    different subjects and must not share an identity."""

    class R:
        tree, product, repo_dir, base = "findings", None, "org", "repo"
        report_kind = "code-audit"

    code = si.repo_key(R())
    R.report_kind = "cloud-config"
    assert si.repo_key(R()) == f"{code}#cloud-config" != code


def test_ingest_is_idempotent(tmp_path):
    """Content-addressed evidence: a second run binds nothing new."""
    results = tmp_path / "results"
    (results / "findings" / "org" / "repo").mkdir(parents=True)
    doc = {
        "metadata": {
            "audit_report": "audit.json",
            "repository": "https://example.test/r",
            "created": "2026-01-01T00:00:00Z",
            "harness_version": "0.1.0",
        },
        "events": [],
        "needs_review": [],
    }
    (results / "findings" / "org" / "repo" / "repo-findings-layer.json").write_text(json.dumps(doc))
    store = Store(sqlite3.connect(":memory:"))
    store.init()
    binding = si._bindings("layer", "local", "findings/org/repo")
    payload = json.dumps(doc).encode()
    first = store.ingest("layer", payload, binding)
    second = store.ingest("layer", payload, binding)
    assert not first.already_bound and second.already_bound
    assert first.binding_id == second.binding_id


def test_lane_artifacts_of_one_subject_get_distinct_run_ids(tmp_path):
    """One subject owns many lane runs, and they must be tellable apart.

    Measured on the live corpus: `acm-cli` owns 18 validation artifacts
    (`acm.v040-1239` … `acm.v060`, plus an `acm.v058/spoke` variant).
    Keying run_id on the subject alone gave all 18 an identical binding
    context, so nothing downstream could order them, distinguish them,
    or say which run a row came from — they survived only because their
    content digests differ.
    """
    results = tmp_path / "analysis-results"
    (results / "validations" / "acm.v060").mkdir(parents=True)
    (results / "validations" / "acm.v058" / "spoke").mkdir(parents=True)
    hub = results / "validations" / "acm.v060" / "acm-validation.json"
    spoke = results / "validations" / "acm.v058" / "spoke" / "acm-spoke-validation.json"

    subject = "findings/acm/acm-cli/acm-cli"
    hub_binding = si._bindings("validation", "local", subject, hub, results)
    spoke_binding = si._bindings("validation", "local", subject, spoke, results)

    assert hub_binding.run_id != spoke_binding.run_id, "18 runs, 18 identities"
    assert hub_binding.run_id == "corpus:run:validations/acm.v060"
    assert spoke_binding.run_id == "corpus:run:validations/acm.v058/spoke"
    assert hub_binding.subject_id == spoke_binding.subject_id, "same subject"


def test_reports_beside_a_subject_keep_the_per_subject_run(tmp_path):
    """There is exactly one audit per subject, so it was never ambiguous.

    Changing it would move every existing binding id for no gain.
    """
    results = tmp_path / "analysis-results"
    report = results / "findings" / "p" / "r" / "r-security-audit.json"
    report.parent.mkdir(parents=True)
    binding = si._bindings("report", "local", "findings/p/r/r", report, results)
    assert binding.run_id == "corpus:run:findings/p/r/r"


def test_an_aggregate_artifact_binds_to_the_scope_not_a_subject(tmp_path):
    """An impact analysis is one advisory across many repos.

    It has no single subject — profiles.json classes it `aggregate` with
    no required binding context for exactly that reason. Forcing a
    subject would mean picking one of the repos it names, and every
    choice is wrong.
    """
    binding = si._bindings("impact-analysis", "local", None)
    assert binding.scope_id == "local"
    assert binding.subject_id is None
    assert binding.run_id is None


def test_the_impact_lane_is_discovered(tmp_path):
    results = tmp_path / "analysis-results"
    (results / "impact").mkdir(parents=True)
    (results / "impact" / "cve-2026-1-impact-analysis.json").write_text("{}")
    (results / "impact" / "_manifest").mkdir()
    (results / "impact" / "_manifest" / "x-impact-analysis.json").write_text("{}")

    cfg = CorpusConfig.model_validate(
        yaml.safe_load(
            "version: 1\ntrees:\n  findings: {label: l, ownership: owned, business_unit: B}\n"
        )
    )
    planned = list(si.plan_aggregates(results, cfg))
    assert len(planned) == 1, "_manifest is bookkeeping, not an artifact"
    family, _scope, subject, path = planned[0]
    assert family == "impact-analysis"
    assert subject is None
    assert path.name == "cve-2026-1-impact-analysis.json"
