"""Hook and collection subprocesses must not initialize the caller's Git repository."""

from __future__ import annotations

import json
import os
import shlex
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


def _local_git_env_vars() -> tuple[str, ...]:
    return tuple(
        subprocess.run(
            ["git", "rev-parse", "--local-env-vars"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        ).stdout.split()
    )


def _install_failing_enumeration_git(tmp_path: Path) -> Path:
    real_git = shutil.which("git")
    assert real_git is not None
    tools = tmp_path / "bin"
    tools.mkdir()
    git_shim = tools / "git"
    git_shim.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "rev-parse" ] && [ "$2" = "--local-env-vars" ]; then\n'
        "  exit 1\n"
        "fi\n"
        f'exec {shlex.quote(real_git)} "$@"\n'
    )
    git_shim.chmod(0o755)
    return tools


def _install_probe_uv(tools: Path) -> None:
    uv = tools / "uv"
    uv.write_text(
        f"#!{sys.executable}\n"
        "import json, os, subprocess\n"
        "from pathlib import Path\n"
        "names = json.loads(os.environ['ISOLATION_LOCAL_ENV_VARS'])\n"
        "survivors = [name for name in names if name in os.environ]\n"
        "probe = Path(os.environ['ISOLATION_PROBE'])\n"
        "subprocess.run(['git', 'init', '-q', str(probe)], check=True)\n"
        "payload = probe / 'payload'\n"
        "payload.write_text(os.environ['ISOLATION_PAYLOAD'])\n"
        "oid = subprocess.check_output(\n"
        "    ['git', '-C', str(probe), 'hash-object', '-w', str(payload)], text=True\n"
        ").strip()\n"
        "Path(os.environ['ISOLATION_RECEIPT']).write_text(\n"
        "    json.dumps({'survivors': survivors, 'oid': oid})\n"
        ")\n"
    )
    uv.chmod(0o755)


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


def test_collection_fallback_clears_object_directory_when_enumeration_fails(
    tmp_path: Path, hook_repo: tuple[Path, Path, dict[str, str]]
) -> None:
    main, worktree, env = hook_repo
    tools = _install_failing_enumeration_git(tmp_path)
    local_vars = _local_git_env_vars()
    probe, receipt = tmp_path / "fallback-probe", tmp_path / "fallback-receipt.json"
    child_env = {key: value for key, value in env.items() if key not in local_vars}
    child_env.update(
        {
            "GIT_OBJECT_DIRECTORY": str(main / ".git" / "objects"),
            "PATH": f"{tools}{os.pathsep}{env['PATH']}",
            "ISOLATION_LOCAL_ENV_VARS": json.dumps(local_vars),
            "ISOLATION_PROBE": str(probe),
            "ISOLATION_RECEIPT": str(receipt),
            "ISOLATION_PAYLOAD": f"collection-fallback:{tmp_path}",
            "TMPDIR": str(tmp_path),
        }
    )
    script = (
        "import json, os, runpy, subprocess, sys\n"
        "from pathlib import Path\n"
        "runpy.run_path(sys.argv[1])\n"
        "names = json.loads(os.environ['ISOLATION_LOCAL_ENV_VARS'])\n"
        "survivors = [name for name in names if name in os.environ]\n"
        "probe = Path(os.environ['ISOLATION_PROBE'])\n"
        "subprocess.run(['git', 'init', '-q', str(probe)], check=True)\n"
        "payload = probe / 'payload'\n"
        "payload.write_text(os.environ['ISOLATION_PAYLOAD'])\n"
        "oid = subprocess.check_output(\n"
        "    ['git', '-C', str(probe), 'hash-object', '-w', str(payload)], text=True\n"
        ").strip()\n"
        "Path(os.environ['ISOLATION_RECEIPT']).write_text(\n"
        "    json.dumps({'survivors': survivors, 'oid': oid})\n"
        ")\n"
    )
    subprocess.run(
        [sys.executable, "-c", script, str(ROOT / "tests" / "conftest.py")],
        cwd=worktree,
        env=child_env,
        capture_output=True,
        text=True,
        timeout=20,
        check=True,
    )

    result = json.loads(receipt.read_text())
    oid = result["oid"]
    object_path = Path("objects") / oid[:2] / oid[2:]
    assert result["survivors"] == []
    assert (probe / ".git" / object_path).is_file()
    assert not (main / ".git" / object_path).exists()
    assert _git(main, "config", "core.bare") == "false"


def test_pre_push_fallback_clears_object_directory_when_enumeration_fails(
    tmp_path: Path, hook_repo: tuple[Path, Path, dict[str, str]]
) -> None:
    main, worktree, env = hook_repo
    tools = _install_failing_enumeration_git(tmp_path)
    _install_probe_uv(tools)
    local_vars = _local_git_env_vars()
    probe, receipt = tmp_path / "hook-fallback-probe", tmp_path / "hook-fallback-receipt.json"
    child_env = {key: value for key, value in env.items() if key not in local_vars}
    child_env.update(
        {
            "GIT_OBJECT_DIRECTORY": str(main / ".git" / "objects"),
            "PATH": f"{tools}{os.pathsep}{env['PATH']}",
            "ISOLATION_LOCAL_ENV_VARS": json.dumps(local_vars),
            "ISOLATION_PROBE": str(probe),
            "ISOLATION_RECEIPT": str(receipt),
            "ISOLATION_PAYLOAD": f"hook-fallback:{tmp_path}",
        }
    )
    hook_result = subprocess.run(
        ["bash", str(ROOT / ".githooks" / "pre-push")],
        cwd=worktree,
        env=child_env,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert hook_result.returncode == 0, hook_result.stderr

    result = json.loads(receipt.read_text())
    oid = result["oid"]
    object_path = Path("objects") / oid[:2] / oid[2:]
    assert result["survivors"] == []
    assert (probe / ".git" / object_path).is_file()
    assert not (main / ".git" / object_path).exists()
    assert _git(main, "config", "core.bare") == "false"
