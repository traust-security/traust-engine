"""Tests for traust_engine.corpus.resolver — the corpus resolver.

Two layers:
1. Synthetic-fixture tests (always run) covering identity splitting,
   ownership tagging, symlink aliasing, layer preference, dot-repo
   handling, engagement activation, and drift warnings.
2. Live-tree pin tests against the 2026-07-17 census ground truth,
   gated behind CORPUS_LIVE_PINS=1 because the live tree grows with
   every audit batch; a light smoke test runs whenever the sibling
   analysis-results/ checkout is present.
"""

import json
import os
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# identity
# ---------------------------------------------------------------------------
from traust_engine.corpus import resolver as corpus

LIVE_ROOT = Path(__file__).resolve().parents[2] / "analysis-results"


@pytest.mark.parametrize(
    "base,expected",
    [
        ("oc__release-5.1", ("oc", "release-5.1")),
        ("client-go__release-4.19", ("client-go", "release-4.19")),
        ("thanos__release-4.14.2", ("thanos", "release-4.14.2")),
        ("logging-view-plugin__openshift-5.0", ("logging-view-plugin", "openshift-5.0")),
        # org__repo naming shares the `__` separator — must never be stripped
        ("quay__enhancements", ("quay__enhancements", None)),
        ("osbuild__.github", ("osbuild__.github", None)),
        ("os__master", ("os__master", None)),
        ("open-cluster-management-io__community", ("open-cluster-management-io__community", None)),
        ("plain-repo", ("plain-repo", None)),
        ("rhproxy-releases", ("rhproxy-releases", None)),
    ],
)
def test_split_ref(base, expected):
    assert corpus.split_ref(base) == expected


# ---------------------------------------------------------------------------
# config validation
# ---------------------------------------------------------------------------


def _write_config(tmp_path, body: str) -> Path:
    p = tmp_path / "corpus-config.yaml"
    p.write_text(body, encoding="utf-8")
    return p


def test_load_config_rejects_bad_ownership(tmp_path):
    p = _write_config(
        tmp_path,
        """
version: 1
trees:
  findings: {label: hp, ownership: mine, business_unit: EXAMPLE_BU}
""",
    )
    with pytest.raises(ValueError, match="ownership"):
        corpus.load_config(p)


def test_load_config_rejects_missing_label(tmp_path):
    p = _write_config(
        tmp_path,
        """
version: 1
trees:
  findings: {ownership: owned, business_unit: EXAMPLE_BU}
""",
    )
    with pytest.raises(ValueError, match="label"):
        corpus.load_config(p)


def test_load_config_rejects_engagement_without_tree(tmp_path):
    p = _write_config(
        tmp_path,
        """
version: 1
trees: {}
engagements:
  example-engagement: {label: example-engagement, ownership: external-bu, business_unit: ExampleEngagement}
""",
    )
    with pytest.raises(ValueError, match="tree"):
        corpus.load_config(p)


FIXTURE_CONFIG_HOME = Path(__file__).parent / "fixtures" / "config"
SHIPPED_CORPUS_CONFIG = FIXTURE_CONFIG_HOME / "corpus-config.yaml"


def test_shipped_config_is_valid():
    """The fixture config (= the shipped template) loads and has the documented
    shape. It used to assert an estate's engagement names — the leak this
    layout exists to prevent."""
    cfg = corpus.load_config(SHIPPED_CORPUS_CONFIG)
    assert cfg.version == 1
    assert cfg.trees["findings"].ownership == "owned"
    assert cfg.trees["oss-findings"].ownership == "upstream"
    assert cfg.engagements == {} and cfg.overrides == {}


# ---------------------------------------------------------------------------
# synthetic tree resolution
# ---------------------------------------------------------------------------

FIXTURE_CONFIG = """
version: 1
trees:
  findings: {label: example-platform, ownership: owned, business_unit: EXAMPLE_BU}
  oss-findings: {label: upstream-oss, ownership: upstream, business_unit: OSS}
engagements:
  example-engagement:
    label: example-engagement
    ownership: external-bu
    business_unit: ExampleEngagement
    tree: example-engagement-findings
    status: registered
"""


def _audit(dirpath: Path, base: str, md: bool = True, js: bool = True):
    dirpath.mkdir(parents=True, exist_ok=True)
    if js:
        (dirpath / f"{base}-security-audit.json").write_text(
            json.dumps(
                {"metadata": {"repository": f"https://github.com/org/{base}"}, "findings": []}
            ),
            encoding="utf-8",
        )
    if md:
        (dirpath / f"{base}-security-audit.md").write_text("# audit\n", encoding="utf-8")


@pytest.fixture
def synthetic(tmp_path):
    cfg_path = _write_config(tmp_path, FIXTURE_CONFIG)
    ar = tmp_path / "analysis-results"

    repo1 = ar / "findings" / "prodA" / "repo1"
    _audit(repo1, "repo1")
    (repo1 / "repo1-findings-current.json").write_text("{}")
    (repo1 / "repo1-triage.json").write_text("{}")
    (repo1 / "repo1-threat-model.md").write_text("# tm\n")

    # container-image audit sharing repo1's directory (the real layout:
    # findings/<product>/<image>/<image>-container-audit.json) — its
    # record identity and companions must NOT collide with the code
    # audit's, and its ledger companions carry the full report stem
    (repo1 / "repo1-container-audit.json").write_text(
        json.dumps({"metadata": {}, "findings": []}), encoding="utf-8"
    )
    (repo1 / "repo1-container-audit-findings-current.json").write_text("{}", encoding="utf-8")

    _audit(ar / "findings" / "prodA" / "repo1__release-4.19", "repo1__release-4.19", md=False)
    _audit(ar / "findings" / "shallow-repo", "shallow-repo", md=False)
    _audit(ar / "findings" / "prodA" / ".github", ".github", md=False)
    _audit(ar / "findings" / "prodA" / "mdonly", "mdonly", js=False)

    # cross-product symlink: prodB's repo1 report aliases prodA's
    linkdir = ar / "findings" / "prodB" / "repo1"
    linkdir.mkdir(parents=True)
    (linkdir / "repo1-security-audit.json").symlink_to(repo1 / "repo1-security-audit.json")

    # harness state dir must be skipped even though it holds a report name
    _audit(ar / "findings" / ".triage-state", "junk", md=False)

    # same slug in a second tree -> cross-tree overlap
    _audit(ar / "oss-findings" / "orgx" / "repo1", "repo1", md=False)

    # unregistered tree with a report -> warning, not counted
    _audit(ar / "stray-findings" / "p" / "r", "r", md=False)

    return ar, corpus.load_config(cfg_path)


def test_resolve_population(synthetic):
    ar, cfg = synthetic
    res = corpus.resolve(ar, cfg)
    agg = corpus.aggregates(res)

    f = agg["trees"]["findings"]
    # repo1, repo1__release-4.19, shallow-repo, .github, mdonly
    # + repo1's container-audit record (separate kind, same directory)
    assert f["reports"] == 6
    assert f["by_kind"] == {"code-audit": 5, "container-audit": 1}
    assert f["reports_md_only"] == 1
    assert f["branch_reaudits"] == 1
    assert f["head_reports"] == 5
    assert f["unique_base_slugs"] == 5  # repo1 collapses with branch
    assert f["shallow_dirs"] == 1
    assert f["with_findings_current"] == 2
    assert f["ownership"] == "owned"
    assert agg["trees"]["oss-findings"]["ownership"] == "upstream"


def test_resolve_identity_and_layers(synthetic):
    ar, cfg = synthetic
    res = corpus.resolve(ar, cfg)
    by_base = {r.base: r for r in res.records if r.tree == "findings"}

    head = by_base["repo1"]
    assert head.preferred == "findings_current"
    assert head.product == "prodA"
    assert head.triage_json and head.threat_model
    assert not head.is_branch_audit

    branch = by_base["repo1__release-4.19"]
    assert (branch.base_slug, branch.ref) == ("repo1", "release-4.19")
    assert branch.is_branch_audit and branch.preferred == "audit_json"

    assert by_base["shallow-repo"].product is None
    assert ".github" in by_base  # dot-repos are real targets
    assert by_base["mdonly"].is_md_only
    assert by_base["mdonly"].preferred == "audit_md_only"
    assert "junk" not in by_base  # state dirs skipped


def test_container_audit_kind(synthetic):
    ar, cfg = synthetic
    res = corpus.resolve(ar, cfg)
    recs = [r for r in res.records if r.report_kind == "container-audit"]
    assert len(recs) == 1
    c = recs[0]

    # identity keeps the -container-audit marker: no repo_key or
    # companion collision with the code audit in the same directory
    assert c.base == "repo1-container-audit"
    assert c.base_slug == "repo1-container-audit"
    assert c.product == "prodA" and c.repo_dir == "repo1"
    assert c.audit_json.endswith("repo1-container-audit.json")
    assert not c.is_branch_audit and c.ref is None

    # ledger companions carry the full report stem …
    assert c.findings_current.endswith("repo1-container-audit-findings-current.json")
    assert c.preferred == "findings_current"
    # … and the code audit keeps its own companions untouched
    code = next(r for r in res.records if r.base == "repo1" and r.tree == "findings")
    assert code.report_kind == "code-audit"
    assert code.findings_current.endswith("/repo1-findings-current.json")


def test_resolve_symlinks_and_overlap(synthetic):
    ar, cfg = synthetic
    res = corpus.resolve(ar, cfg)
    agg = corpus.aggregates(res)

    files = [a for a in res.aliases if a["kind"] == "file"]
    assert len(files) == 1
    assert files[0]["link"].endswith("prodB/repo1/repo1-security-audit.json")
    assert agg["duplication"]["symlink_canonical_targets"] == 1
    # the alias is never a record: only prodA's canonical repo1 remains
    assert sum(1 for r in res.records if r.base == "repo1" and r.tree == "findings") == 1

    assert agg["duplication"]["cross_tree_slugs"] == 1
    assert agg["duplication"]["cross_tree_examples"]["repo1"] == ["findings", "oss-findings"]


def test_unregistered_tree_warning(synthetic):
    ar, cfg = synthetic
    res = corpus.resolve(ar, cfg)
    assert any("stray-findings" in w for w in res.warnings)
    assert all(r.tree != "stray-findings" for r in res.records)


def test_engagement_tree_activates_on_disk(synthetic):
    ar, cfg = synthetic
    _audit(ar / "example-engagement-findings" / "p" / "lwrepo", "lwrepo", md=False)
    res = corpus.resolve(ar, cfg)
    recs = [r for r in res.records if r.tree == "example-engagement-findings"]
    assert len(recs) == 1
    assert recs[0].ownership == "external-bu"
    assert recs[0].label == "example-engagement"
    assert not any("example-engagement" in w for w in res.warnings)


def test_tree_subset_selection(synthetic):
    ar, cfg = synthetic
    res = corpus.resolve(ar, cfg, trees=["oss-findings"])
    assert {r.tree for r in res.records} == {"oss-findings"}


def test_with_repo_urls(synthetic):
    ar, cfg = synthetic
    res = corpus.resolve(ar, cfg, with_repo_urls=True)
    head = next(r for r in res.records if r.base == "repo1" and r.tree == "findings")
    assert head.repo_url == "https://github.com/org/repo1"


def test_manifest_and_population_block(synthetic):
    ar, cfg = synthetic
    res = corpus.resolve(ar, cfg)
    man = corpus.build_manifest(res, cfg)
    for key in (
        "generated",
        "harness_version",
        "trees",
        "totals",
        "duplication",
        "warnings",
        "records",
    ):
        assert key in man
    assert man["totals"]["reports"] == len(res.records)

    block = corpus.render_population_block(
        res, tool="unit-test", unit="findings", filters="none", denominator="directory walk"
    )
    assert "## Population" in block
    assert "owned" in block and "Roots walked" in block
    assert "branch re-audits" in block


def test_population_block_lines_and_roots_description(synthetic):
    _ar, cfg = synthetic
    roots = corpus.roots_description(
        cfg,
        ["findings", "example-engagement-findings", "mystery"],
        extra=["`validations/*/` (verdicts)"],
    )
    assert roots[0] == "`findings/` (owned, EXAMPLE_BU)"
    assert "external-bu" in roots[1]  # engagement tree resolves
    assert "UNREGISTERED" in roots[2]
    assert roots[3].startswith("`validations/")

    lines = corpus.population_block_lines(
        tool="demo",
        roots=roots,
        unit="widgets",
        filters="none",
        denominator="walk",
        counts={"Files scanned": 42},
        warnings=["w1", "w2"],
    )
    text = "\n".join(lines)
    assert "**Tool:** demo" in text
    assert "**Files scanned:** 42" in text
    assert "**Warnings:** 2" in text


# ---------------------------------------------------------------------------
# live tree
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not (LIVE_ROOT / "findings").is_dir(), reason="sibling analysis-results/ not checked out"
)
def test_live_smoke():
    from traust_engine import HarnessEngine

    res = corpus.resolve(LIVE_ROOT, HarnessEngine.load().corpus.config())
    agg = corpus.aggregates(res)
    assert agg["trees"]["findings"]["reports"] > 5000
    assert agg["duplication"]["symlink_aliases"] > 0
    assert agg["trees"]["findings"]["branch_reaudits"] > 1000
    # the resolver never counts a symlink as a report
    links = {a["link"] for a in res.aliases}
    assert not any(r.audit_json in links for r in res.records if r.audit_json)


@pytest.mark.skipif(
    os.environ.get("CORPUS_LIVE_PINS") != "1",
    reason="census pins are a point-in-time snapshot; set CORPUS_LIVE_PINS=1 to check them",
)
def test_live_census_pins_2026_07_17():
    """Ground truth from the 2026-07-17 filesystem census. These WILL
    drift as audit batches land; they exist to prove the resolver
    reproduces the census methodology, not to freeze the tree."""
    from traust_engine import HarnessEngine

    res = corpus.resolve(LIVE_ROOT, HarnessEngine.load().corpus.config())
    agg = corpus.aggregates(res)
    f = agg["trees"]["findings"]
    assert f["reports"] == 8047  # audit JSONs plus md-only models
    assert f["reports_md_only"] == 162
    assert f["branch_reaudits"] == 4214
    assert f["unique_base_slugs"] == 3283
    assert agg["trees"]["OpenStack-k8s-ops"]["reports"] == 61
    assert agg["trees"]["ecoengg-findings"]["reports"] == 117
    assert agg["trees"]["oss-findings"]["reports"] == 138
    d = agg["duplication"]
    assert d["symlink_aliases"] == 194
    assert d["symlink_canonical_targets"] == 174


def test_harness_qa_tree_registered_but_never_walked(tmp_path):
    cfg_path = _write_config(
        tmp_path,
        """
version: 1
trees:
  findings: {label: example-platform, ownership: owned, business_unit: EXAMPLE_BU}
  scan-testing: {label: harness-qa, ownership: harness-qa,
                 business_unit: EXAMPLE_BU QA}
""",
    )
    ar = tmp_path / "analysis-results"
    _audit(ar / "findings" / "prodA" / "repo1", "repo1", md=False)
    # probe artifact that LOOKS like an audit report
    _audit(ar / "scan-testing" / "example-app", "example-app", md=False)

    cfg = corpus.load_config(cfg_path)
    res = corpus.resolve(ar, cfg)

    # no records from the QA tree, in any lens
    assert all(r.tree != "scan-testing" for r in res.records)
    # not part of the corpus population either
    assert "scan-testing" not in res.trees
    # but registered: no unregistered-tree drift warning
    assert not any("scan-testing" in w for w in res.warnings)
    # the owned tree is unaffected
    assert any(r.tree == "findings" for r in res.records)


# ---------------------------------------------------------------------------
# nested duplicate-dir guard (week1-fullaudit misplacement signature)
# ---------------------------------------------------------------------------


def test_nested_duplicate_dir_warns(tmp_path):
    cfg = corpus.load_config(_write_config(tmp_path, FIXTURE_CONFIG))
    ar = tmp_path / "analysis-results"
    flat = ar / "findings" / "prodA" / "repoX"
    _audit(flat, "repoX")  # flat baseline
    _audit(flat / "repoX", "repoX", md=False)  # misplaced nested re-audit
    res = corpus.resolve(ar, cfg)
    hits = [w for w in res.warnings if "nested duplicate report dir" in w]
    assert len(hits) == 1
    assert "repoX" in hits[0]


def test_canonical_product_named_after_repo_not_flagged(tmp_path):
    # findings/clowder/clowder/ (product dir named after its repo, reports
    # only in the child) is canonical and must not warn.
    cfg = corpus.load_config(_write_config(tmp_path, FIXTURE_CONFIG))
    ar = tmp_path / "analysis-results"
    _audit(ar / "findings" / "clowder" / "clowder", "clowder")
    res = corpus.resolve(ar, cfg)
    assert not [w for w in res.warnings if "nested duplicate report dir" in w]


# ---------------------------------------------------------------------------
# one cumulative report, one owner
# ---------------------------------------------------------------------------


def _dual_audit_tree(tmp_path, cumulative: dict) -> tuple[Path, Path]:
    """A directory holding BOTH a code audit and a cloud-config audit.

    The real layout for the three such directories in the live corpus.
    Both audits share one `<base>-findings-current.json`, because the
    companion filename carries no kind marker.
    """
    cfg_path = _write_config(tmp_path, FIXTURE_CONFIG)
    ar = tmp_path / "analysis-results"
    d = ar / "findings" / "prodA" / "dual"
    _audit(d, "dual", md=False)
    (d / "dual-cloud-config-audit.json").write_text(
        json.dumps({"metadata": {}, "findings": []}), encoding="utf-8"
    )
    (d / "dual-findings-current.json").write_text(json.dumps(cumulative), encoding="utf-8")
    return cfg_path, ar


def test_shared_cumulative_goes_to_the_cloud_config_record_only(tmp_path):
    """Both kinds claiming one findings-current double-counts its findings.

    Measured on the live corpus before this: 181 duplicated open rows
    across three directories, the SAME fingerprints under both repo_keys,
    because every consumer walks records and each record pointed at the
    same file.
    """
    cfg_path, ar = _dual_audit_tree(
        tmp_path,
        # no executive_summary -> a cloud-config restatement by contract
        {"title": "t", "metadata": {}, "summary": {}, "findings": [], "disposition_summary": {}},
    )
    res = corpus.resolve(ar, corpus.load_config(cfg_path))
    dual = {r.report_kind: r for r in res.records if r.base == "dual"}
    assert set(dual) == {"code-audit", "cloud-config"}, "both audits still resolve"
    assert dual["cloud-config"].findings_current is not None
    assert dual["code-audit"].findings_current is None
    assert dual["code-audit"].preferred == "audit_json"
    assert dual["cloud-config"].preferred == "findings_current"


def test_shared_cumulative_goes_to_the_code_record_when_it_is_a_report(tmp_path):
    """The discriminator is the contract, and it cuts both ways.

    `report.schema.json` requires `executive_summary`;
    `cloud-config-findings-current.schema.json` sets
    `additionalProperties: false` and never declares it.
    """
    cfg_path, ar = _dual_audit_tree(
        tmp_path,
        {"title": "t", "metadata": {}, "executive_summary": "x", "findings": []},
    )
    res = corpus.resolve(ar, corpus.load_config(cfg_path))
    dual = {r.report_kind: r for r in res.records if r.base == "dual"}
    assert dual["code-audit"].findings_current is not None
    assert dual["cloud-config"].findings_current is None
    assert dual["cloud-config"].preferred == "audit_json"


def test_unreadable_shared_cumulative_warns_instead_of_picking(tmp_path):
    """No owner is better than a random one.

    Silently assigning it would make the duplication invisible again,
    which is the failure this whole change exists to end.
    """
    cfg_path, ar = _dual_audit_tree(tmp_path, {})
    (ar / "findings" / "prodA" / "dual" / "dual-findings-current.json").write_text(
        "{not json", encoding="utf-8"
    )
    res = corpus.resolve(ar, corpus.load_config(cfg_path))
    dual = {r.report_kind: r for r in res.records if r.base == "dual"}
    assert all(r.findings_current is not None for r in dual.values()), "left as-is"
    assert any("no resolvable owner" in w for w in res.warnings)


def test_single_kind_directory_is_untouched(synthetic):
    """Single-kind directories must see no change at all."""
    ar, cfg = synthetic
    res = corpus.resolve(ar, cfg)
    repo1 = [
        r
        for r in res.records
        if r.base == "repo1" and r.report_kind == "code-audit" and r.product == "prodA"
    ]
    assert len(repo1) == 1
    assert repo1[0].findings_current is not None
    assert repo1[0].preferred == "findings_current"
    # the container audit shares the directory but not the base, so its
    # own cumulative report is still its own
    container = [r for r in res.records if r.report_kind == "container-audit"]
    assert len(container) == 1
    assert container[0].findings_current is not None
