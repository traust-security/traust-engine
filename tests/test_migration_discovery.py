"""Discovery is contract-aware, not a census allowlist or implicit exclusion policy."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError
from traust_contracts.config import CorpusConfig
from traust_contracts.v1.storage.store import storage_profiles

from traust_engine.corpus.migration_discovery import (
    ArtifactCatalog,
    DiscoveryError,
    MigrationOptions,
)


def catalog(root: Path, **options: object) -> ArtifactCatalog:
    return ArtifactCatalog(root, CorpusConfig(version=1, trees={}), MigrationOptions(**options))


@pytest.mark.parametrize("family", sorted(storage_profiles()))
def test_every_contract_has_a_filename_route(tmp_path: Path, family: str) -> None:
    assert catalog(tmp_path).identify(f"any-tree/subject-{family}.json", {}).family == family


def test_shape_alone_and_declared_schema_do_not_route_scratch(tmp_path: Path) -> None:
    c = catalog(tmp_path)
    assert not c.is_candidate("org/repo/scratch.json")
    with pytest.raises(DiscoveryError) as caught:
        c.identify("org/repo/scratch.json", {"artifact": "layer"})
    assert caught.value.code == "unrecognized_artifact"
    assert c.is_candidate("org/repo/repo-findings-layer.json")
    with pytest.raises(DiscoveryError) as unknown:
        c.identify("org/repo/repo-findings-layer.json", {"$schema": "other.schema.json"})
    assert unknown.value.code == "unknown_contract"
    assert catalog(tmp_path, schemas={"custom/*.json": "layer"}).is_candidate("custom/scratch.json")


def test_source_companions_share_context_without_registered_tree(tmp_path: Path) -> None:
    c = catalog(tmp_path)
    report = c.identify("outside-census/org/repo/repo-security-audit.json", {})
    triage = c.identify("outside-census/org/repo/repo-triage.json", {})
    layer = c.identify("outside-census/org/repo/repo-findings-layer.json", {})
    assert c.binding(report, {}).subject_id == c.binding(triage, {}).subject_id
    assert c.binding(report, {}).run_id == c.binding(triage, {}).run_id
    assert c.binding(layer, {}).layer_id == "corpus:layer:" + report.subject


def test_cloud_current_uses_its_own_contract_and_identity(tmp_path: Path) -> None:
    c = catalog(tmp_path)
    doc = {
        "metadata": {"additional": {"cumulative": {"source_audit": "a-cloud-config-audit.json"}}}
    }
    current = c.identify("unregistered/a-findings-current.json", doc)
    code = c.identify("unregistered/a-security-audit.json", {})
    cloud = c.identify("unregistered/a-cloud-config-audit.json", {})
    assert current.family == "cloud-config-findings-current"
    assert current.subject == cloud.subject != code.subject


def test_layer_uses_the_referenced_cloud_audit_identity(tmp_path: Path) -> None:
    c = catalog(tmp_path)
    cloud = c.identify("unregistered/a-cloud-config-audit.json", {})
    c.add(cloud, {})
    layer = c.identify("unregistered/a-findings-layer.json", {})
    binding = c.binding(layer, {"metadata": {"audit_report": "a-cloud-config-audit.json"}})
    assert binding.layer_id == "corpus:layer:" + cloud.subject


def test_configured_routes_are_explicit_and_ambiguity_is_not_guessed(tmp_path: Path) -> None:
    c = catalog(tmp_path, schemas={"custom/*.json": "layer"})
    assert c.identify("custom/input.json", {}).family == "layer"
    with pytest.raises(DiscoveryError, match="disagree"):
        c.identify("custom/input.json", {"artifact": "report"})
    c = catalog(tmp_path, schemas={"custom/*": "layer", "*.json": "report"})
    with pytest.raises(DiscoveryError, match="Conflicting"):
        c.identify("custom/input.json", {})
    with pytest.raises(DiscoveryError, match="disagree"):
        catalog(tmp_path).identify("a-layer.json", {"artifact": "pqc-facts"})


def test_bindings_can_be_supplied_for_unresolvable_lane(tmp_path: Path) -> None:
    c = catalog(tmp_path)
    a = c.identify("validations/run/a-validation.json", {})
    with pytest.raises(DiscoveryError, match="zero or multiple"):
        c.binding(a, {"source_reports": []})
    c = catalog(tmp_path, bindings={"validations/**": {"subject_id": "declared-subject"}})
    bound = c.binding(a, {"source_reports": []})
    assert bound.subject_id == "declared-subject"
    assert bound.run_id == "corpus:run:validations/run"


def test_lane_references_can_use_a_different_authoring_machine_root(tmp_path: Path) -> None:
    c = catalog(tmp_path)
    a = c.identify("new-team/r/r-security-audit.json", {})
    c.add(a, {})
    v = c.identify("runs/one/r-validation.json", {})
    binding = c.binding(
        v, {"source_reports": [{"path": "/other/machine/output/new-team/r/r-security-audit.json"}]}
    )
    assert binding.subject_id == a.subject
    assert binding.run_id == "corpus:run:runs/one"


@pytest.mark.parametrize("pattern", ["", "/absolute/**", "../other/**", "a/../b", "a\\b"])
def test_exclusions_cannot_escape_or_change_path_conventions(pattern: str) -> None:
    with pytest.raises(ValidationError):
        MigrationOptions(exclude=[pattern])


def test_options_reject_typos_and_unknown_contracts() -> None:
    with pytest.raises(ValidationError):
        MigrationOptions(exlcude=["some/**"])
    with pytest.raises(ValidationError):
        MigrationOptions(schemas={"some/**": "nonexistent"})
