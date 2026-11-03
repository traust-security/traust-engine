"""Hook and collection subprocesses must not initialize the caller's Git repository."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="Git is required")


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, timeout=10, check=True
    ).stdout.strip()


@pytest.fixture
def hook_repo(tmp_path: Path) -> tuple[Path, Path, dict[str, str]]:
    main, worktree = tmp_path / "main", tmp_path / "worktree"
    _git(tmp_path, "init", "-q", "-b", "main", str(main))
    _git(
        main,
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "fixture",
    )
    _git(main, "worktree", "add", "-q", "-b", "hook-test", str(worktree))
    env = {**os.environ, "GIT_DIR": _git(worktree, "rev-parse", "--absolute-git-dir")}
    return main, worktree, env


def test_pre_push_clears_git_environment_before_running_tools(
    tmp_path: Path, hook_repo: tuple[Path, Path, dict[str, str]]
) -> None:
    main, worktree, env = hook_repo
    probe, receipt = tmp_path / "probe", tmp_path / "environment.json"
    tools = tmp_path / "bin"
    tools.mkdir()
    uv = tools / "uv"
    uv.write_text(
        f"#!{sys.executable}\n"
        "import json, os, subprocess\n"
        "from pathlib import Path\n"
        "names = subprocess.check_output(['git', 'rev-parse', '--local-env-vars'], text=True).split()\n"
        "Path(os.environ['ISOLATION_RECEIPT']).write_text(json.dumps([n for n in names if n in os.environ]))\n"
        "subprocess.run(['git', 'init', '-q', os.environ['ISOLATION_PROBE']], check=True)\n"
    )
    uv.chmod(0o755)
    subprocess.run(
        ["bash", str(ROOT / ".githooks" / "pre-push")],
        cwd=worktree,
        env={
            **env,
            "PATH": f"{tools}{os.pathsep}{env['PATH']}",
            "ISOLATION_PROBE": str(probe),
            "ISOLATION_RECEIPT": str(receipt),
        },
        capture_output=True,
        text=True,
        timeout=20,
        check=True,
    )
    assert json.loads(receipt.read_text()) == []
    assert (probe / ".git").is_dir()
    assert _git(main, "config", "core.bare") == "false"


def test_collection_clears_git_environment_for_non_hook_runners(
    tmp_path: Path, hook_repo: tuple[Path, Path, dict[str, str]]
) -> None:
    main, worktree, env = hook_repo
    probe = tmp_path / "collection-probe"
    subprocess.run(
        [
            sys.executable,
            "-c",
            "import runpy, subprocess, sys; runpy.run_path(sys.argv[1]); "
            "subprocess.run(['git', 'init', '-q', sys.argv[2]], check=True)",
            str(ROOT / "tests" / "conftest.py"),
            str(probe),
        ],
        cwd=worktree,
        env={**env, "TMPDIR": str(tmp_path)},
        capture_output=True,
        text=True,
        timeout=20,
        check=True,
    )
    assert (probe / ".git").is_dir()
    assert _git(main, "config", "core.bare") == "false"
