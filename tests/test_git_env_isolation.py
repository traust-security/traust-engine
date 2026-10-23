"""A hook's GIT_DIR must not let a test's `git init` turn this repository bare."""

import os
import subprocess
from pathlib import Path

import pytest

HOOK = Path(__file__).resolve().parents[1] / ".githooks" / "pre-push"


def _git(*args, cwd, env=None):
    return subprocess.run(
        ["git", *args], cwd=cwd, env=env, capture_output=True, text=True, check=True
    )


@pytest.mark.requires_git
def test_the_suite_runs_without_git_repo_variables():
    assert "GIT_DIR" not in os.environ and "GIT_WORK_TREE" not in os.environ


@pytest.mark.requires_git
def test_hook_clears_git_dir_before_tests_could_init(tmp_path):
    main = tmp_path / "main"
    _git("init", "-q", str(main), cwd=tmp_path)
    _git(
        "-c",
        "user.email=t@t",
        "-c",
        "user.name=t",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "i",
        cwd=main,
    )
    _git("worktree", "add", "-q", str(tmp_path / "wt"), "-b", "x", cwd=main)
    gitdir = _git("rev-parse", "--absolute-git-dir", cwd=tmp_path / "wt").stdout.strip()
    env = {**os.environ, "GIT_DIR": gitdir}
    # the hook's guard, then what a fixture does
    guard = next(line for line in HOOK.read_text().splitlines() if line.startswith("unset $(git"))
    subprocess.run(
        ["bash", "-c", f"{guard}; git init -q {tmp_path / 'probe'}"],
        cwd=tmp_path / "wt",
        env=env,
        check=True,
    )
    assert _git("config", "core.bare", cwd=main).stdout.strip() == "false"
    assert (tmp_path / "probe" / ".git").is_dir()


@pytest.mark.requires_git
def test_without_the_guard_git_init_turns_the_repository_bare(tmp_path):
    # documents the failure the guard prevents
    main = tmp_path / "main"
    _git("init", "-q", str(main), cwd=tmp_path)
    _git(
        "-c",
        "user.email=t@t",
        "-c",
        "user.name=t",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "i",
        cwd=main,
    )
    _git("worktree", "add", "-q", str(tmp_path / "wt"), "-b", "x", cwd=main)
    gitdir = _git("rev-parse", "--absolute-git-dir", cwd=tmp_path / "wt").stdout.strip()
    subprocess.run(
        ["git", "init", "-q", str(tmp_path / "probe")],
        cwd=tmp_path / "wt",
        env={**os.environ, "GIT_DIR": gitdir},
        check=True,
    )
    assert _git("config", "core.bare", cwd=main).stdout.strip() == "true"
