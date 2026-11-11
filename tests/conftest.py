"""Harness-engine test configuration — standalone package install."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

_FALLBACK_LOCAL_GIT_ENV_VARS = (
    # Keep in sync with Git's local_repo_env table used by rev-parse --local-env-vars.
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_OBJECT_DIRECTORY",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_GRAFT_FILE",
    "GIT_INDEX_FILE",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_REPLACE_REF_BASE",
    "GIT_PREFIX",
    "GIT_SHALLOW_FILE",
    "GIT_COMMON_DIR",
)


def _clear_git_repo_env() -> None:
    """Isolate repository-creating tests, including runners outside the pre-push hook."""
    try:
        names = subprocess.run(
            ["git", "rev-parse", "--local-env-vars"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        ).stdout.split()
    except (OSError, subprocess.SubprocessError):
        names = _FALLBACK_LOCAL_GIT_ENV_VARS
    for name in names:
        os.environ.pop(name, None)


_clear_git_repo_env()

_FIXTURES = Path(__file__).resolve().parent / "fixtures"

# The suite must never read an operator's real configuration: point the config home at a
# private copy of the estate-neutral fixture.
_TEST_HOME = Path(tempfile.mkdtemp(prefix="traust-test-cfg-"))
shutil.copytree(_FIXTURES / "config", _TEST_HOME, dirs_exist_ok=True)
os.environ["TRAUST_CONFIG_HOME"] = str(_TEST_HOME)
