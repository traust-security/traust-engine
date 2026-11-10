PYTHON ?= python3
RELEASE := ./release.py
BUMP_PARTS := patch minor major

.PHONY: help setup sync hooks lint lint-fix test perf check-release status bump gitleaks $(BUMP_PARTS)

help:
	@echo "Targets ($(notdir $(CURDIR))):"
	@echo "  make setup          — uv sync + enable .githooks (run once per clone)"
	@echo "  make sync           — uv sync only"
	@echo "  make hooks          — git config core.hooksPath .githooks"
	@echo "  make lint           — ruff check + format --check"
	@echo "  make lint-fix       - ruff --fix"
	@echo "  make test           — pytest unit tests, excludes integration (parallel via pytest-xdist)"
	@echo "  make perf           — the planning pass at fleet volume on Postgres (db-up in traust-core)"
	@echo "  make check-release  — VERSION + CHANGELOG gate for current branch vs main"
	@echo "  make status         — current version, tag, git state"
	@echo "  make bump patch|minor|major — bump VERSION + pyproject.toml"
	@echo "  make gitleaks        — fetch the pinned gitleaks binary for this arch (image build input)"

setup: sync hooks
	@echo "ready — local hooks enabled (.githooks). Bypass: git commit --no-verify"

sync:
	uv sync

hooks:
	git config core.hooksPath .githooks
	@chmod +x .githooks/* 2>/dev/null || true

lint:
	uv run ruff check .
	uv run ruff format --check .

lint-fix:
	uv run ruff check --fix .
	uv run ruff format .

test:
	uv run pytest tests/ -q -n auto -m "not integration"
perf:
	uv run pytest perf/ -q

