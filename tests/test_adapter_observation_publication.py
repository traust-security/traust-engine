"""Real scanner observations publish without acquiring authored conclusions."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from traust_core.v1.context import Config, Context
from traust_core.v1.models.artifacts import AdapterResultArtifact
from traust_core.v1.models.common import PageRequest
from traust_core.v1.models.findings import FindingFilter
from traust_core.v1.models.values import HttpsRepoUrl
from traust_core.v1.services.artifact_publishing import PublishSpec, PublishSpecs

from traust_engine.adapters import gitleaks
from traust_engine.assets import default_gitleaks_config
from traust_engine.reporting.validate import build_registry, load_schema, validate_report


@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks not on PATH")
def test_real_bundled_scanner_observations_publish_without_promoting_findings(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()
    config = default_gitleaks_config()
    fixture = config.parent / "fixtures" / "secrets-fixture.txt"
    (target / "observations.txt").write_bytes(fixture.read_bytes())
    result = gitleaks.scan(target, config=config, timeout=30)
    artifact = AdapterResultArtifact.from_document(result.to_dict())
    assert {
        "gitleaks/traust-openshift-sha256-token",
        "gitleaks/traust-dsn-url-credentials",
        "gitleaks/traust-ansible-vault-payload",
    } <= {finding.id for finding in artifact.findings}
    assert all(finding.cwes == () and finding.remediation == "" for finding in artifact.findings)
    path = tmp_path / "native-adapter-result.json"
    path.write_bytes(artifact.payload)
    validation = validate_report(
        str(path), load_schema(artifact.schema_path()), strict=True, registry=build_registry()
    )
    assert validation.passed, validation.errors
    assert all(
        finding.validation_status is None and finding.disposition is None
        for finding in artifact.findings
    )

    context = Context(Config(home=tmp_path / "store"))
    repository = context.services().portfolio.register_repository(
        HttpsRepoUrl.parse("https://github.com/example/scanner-observations", ("github.com",)),
        False,
    )
    publisher = context.artifact_publisher(PublishSpecs(PublishSpec(AdapterResultArtifact)))
    receipt = publisher.publish_artifact(artifact)
    restored = publisher.get(receipt.artifact_id)
    assert restored.payload == artifact.payload
    assert {finding.id for finding in restored.findings} == {
        finding.id for finding in artifact.findings
    }
    assert (
        context.services()
        .findings.list(FindingFilter(repository_id=repository.id), PageRequest(limit=10))
        .items
        == ()
    )
