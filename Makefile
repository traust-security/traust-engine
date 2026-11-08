PYTHON ?= python3
RELEASE := ./release.py
BUMP_PARTS := patch minor major

.PHONY: help setup sync hooks lint lint-fix test check-release status bump gitleaks $(BUMP_PARTS)

help:
	@echo "Targets ($(notdir $(CURDIR))):"
	@echo "  make setup          — uv sync + enable .githooks (run once per clone)"
	@echo "  make sync           — uv sync only"
	@echo "  make hooks          — git config core.hooksPath .githooks"
	@echo "  make lint           — ruff check + format --check"
	@echo "  make lint-fix       - ruff --fix"
	@echo "  make test           — pytest unit tests, excludes integration (parallel via pytest-xdist)"
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

check-release:
	@base="$${RELEASE_BASE:-origin/main}"; \
	head="$${RELEASE_HEAD:-HEAD}"; \
	$(PYTHON) ci/gates.py mr "$$base" "$$head"

$(BUMP_PARTS):
	@:

status:
	$(PYTHON) $(RELEASE) status

bump:
	@part="$(filter $(BUMP_PARTS),$(MAKECMDGOALS))"; \
	if [ -z "$$part" ]; then \
		echo "usage: make bump patch|minor|major" >&2; \
		exit 1; \
	fi; \
	$(PYTHON) $(RELEASE) bump $$part

# The container build's gitleaks input (Containerfile COPY gitleaks): the upstream
# v8.21.2 release artifact for the BUILD MACHINE's architecture, digest-verified —
# never committed. Multi-arch image builds fetch inside each arch's build step.
GITLEAKS_VERSION := 8.21.2
GITLEAKS_SHA256_amd64 := 50b742abd7daad8bbddb6301f3017efb680632d9a5b3b4d8f137b3aac250e359
GITLEAKS_SHA256_arm64 := b337056f2c68bef812b378f2841225f1e52f87a293fe0c457507634defdc6fb8
GITLEAKS_ARCH := $(shell uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')

gitleaks:
	@test "$(GITLEAKS_ARCH)" = "amd64" || test "$(GITLEAKS_ARCH)" = "arm64" \
		|| { echo "unsupported build arch: $(GITLEAKS_ARCH)"; exit 1; }
	curl -sSfL --retry 3 -o gitleaks.tar.gz \
		"https://github.com/gitleaks/gitleaks/releases/download/v$(GITLEAKS_VERSION)/gitleaks_$(GITLEAKS_VERSION)_linux_$(GITLEAKS_ARCH).tar.gz"
	tar -xzf gitleaks.tar.gz gitleaks
	echo "$(GITLEAKS_SHA256_$(GITLEAKS_ARCH))  gitleaks" | shasum -a 256 -c -
	rm gitleaks.tar.gz
	@echo "gitleaks $(GITLEAKS_VERSION) $(GITLEAKS_ARCH) ready at ./gitleaks (never committed)"
