# Contributing

## Setup

```bash
git clone <repo-url> && cd traust-engine
make setup
```

Installs deps (`uv sync`) and enables git hooks. One time per clone.

## Commit messages

Conventional commits required. Format: `type(scope): subject`

Types: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `chore`, `ci`, `build`, `style`, `revert`

```
feat(adapters): add semgrep adapter
fix(validation): handle empty SARIF
perf!: drop Python 3.11 support        ← breaking change
```

## Hooks

| Hook | Runs | Speed |
|------|------|-------|
| `commit-msg` | subject format check | instant |
| `pre-commit` | ruff lint on staged `.py` | <1s |
| `pre-push` | full lint + unit tests | ~10s |

Bypass: `--no-verify` on commit or push. CI still enforces.

## Releasing

If your MR has `feat:`, `fix:`, `perf:`, or `!` (breaking) commits:

```bash
make bump minor
# add ## [X.Y.Z] section to CHANGELOG.md
make check-release
git add VERSION pyproject.toml CHANGELOG.md
git commit -m "chore: release X.Y.Z"
```

CI validates on MR. On merge to main, CI tags automatically.

## CI pipeline

**MR:** lint → conventional commits → release-ready → tests

**Main:** tag if `VERSION` > latest git tag

## Downstream pins

Consumers pin this repo by commit sha (`[tool.uv.sources] rev = "<sha>"`), not
a release tag — a tag needs this repo's own release cut first, a commit
doesn't. After your change merges to main, bump the pin to the new commit in
each direct downstream repo's `pyproject.toml`, `uv lock`, and run that
repo's own tests before opening its PR.

No repo pins traust-engine any more: traust depends on traust-core only, and the
engine is deployed as the `traust-engine` service.

## Running tests

```bash
make test              # the suite, in parallel
uv run pytest -q       # the same, serially
```

## Architecture

See [README.md](README.md) for module layout, install, and runtime config.
