"""Native scanner output must satisfy the artifact contract without hand-completing findings."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from traust_core.v1.errors import DocumentError
from traust_core.v1.models.artifacts import AdapterResultArtifact

from traust_engine.adapters import gitleaks
from traust_engine.assets import default_gitleaks_config


@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks not on PATH")
def test_real_gitleaks_output_is_an_admissible_adapter_artifact(tmp_path: Path) -> None:
    (tmp_path / "settings.py").write_text('TOKEN = "sha256~' + "B" * 43 + '"\n', encoding="utf-8")
    result = gitleaks.scan(tmp_path, config=default_gitleaks_config(), timeout=30)
    try:
        artifact = AdapterResultArtifact.from_document(result.to_dict())
    except DocumentError as error:
        error.add_note("\n".join(f"{issue.path}: {issue.message}" for issue in error.issues))
        raise
    assert any(
        finding.id == "gitleaks/traust-openshift-sha256-token"
        and any(location.path == "settings.py" for location in finding.locations)
        for finding in artifact.findings
    )
