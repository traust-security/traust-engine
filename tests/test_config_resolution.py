"""The engine ships no configuration: config resolution is traust-core's `Context`."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from traust_engine.ops import cli

CONFIG_FIXTURES = Path(__file__).parent / "fixtures" / "config"
PACK_FIXTURE = Path(__file__).parent / "fixtures" / "packs" / "security-source.yaml"


def test_engine_ships_no_config():
    """The engine owns the resolver's consumers, never the config files.

    Two data trees ship by design and are not configuration: the rule pack
    (secure-code-audit) and the public compliance reference data (NIST
    800-53 spine and profiles, framework catalogs, the control-to-check
    mapping). Neither varies per estate.
    """
    import traust_engine

    data = Path(traust_engine.__file__).parent / "data"
    shipped = {"secure-code-audit", "compliance"}
    stray = [
        p
        for p in data.rglob("*")
        if p.suffix in (".yaml", ".yml", ".json") and not shipped & set(p.parts)
    ]
    assert stray == [], stray


def test_documented_cli_invocation_uses_core_file_deployment_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--core names a separate traust.yaml-format file with an explicit deployment home."""
    core_file = tmp_path / "core.yaml"
    deployment_home = tmp_path / "deployment-home"
    core_file.write_text(yaml.safe_dump({"home": str(deployment_home)}))
    shutil.copytree(CONFIG_FIXTURES, tmp_path, dirs_exist_ok=True)

    pack_data = yaml.safe_load(PACK_FIXTURE.read_text())
    pack_data.pop("route_on")
    pack_file = tmp_path / "assets.yaml"
    pack_file.write_text(yaml.safe_dump(pack_data))

    fake_user_home = tmp_path / "user-home"
    monkeypatch.setenv("HOME", str(fake_user_home))
    assert cli.main(["run", "--once", "--core", str(core_file), "--pack", str(pack_file)]) == 0

    assert (deployment_home / "traust.db").is_file()
    assert not (fake_user_home / ".traust").exists()
