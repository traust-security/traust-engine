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
# v8.30.1 release artifact for the BUILD MACHINE's architecture, digest-verified —
# never committed. Multi-arch image builds fetch inside each arch's build step.
GITLEAKS_VERSION := 8.30.1
GITLEAKS_SHA256_amd64 := 88f91962aa2f93ac6ab281d553b9e125f5197bbbce38f9f2437f7299c32e5509
GITLEAKS_SHA256_arm64 := 00e91bbe655bd7c47753e8cfe61cb76ea1a5d7e7702fe161ee40102b46b3823b
# ARCH overrides the fetch for cross-builds: pass the image build's TARGETARCH
# (e.g. `make gitleaks ARCH=arm64` when building an arm image from an amd64 host);
# the default is the build machine's own.
GITLEAKS_ARCH ?= $(if $(ARCH),$(ARCH),$(shell uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/'))

gitleaks:
	@test "$(GITLEAKS_ARCH)" = "amd64" || test "$(GITLEAKS_ARCH)" = "arm64" \
		|| { echo "unsupported build arch: $(GITLEAKS_ARCH)"; exit 1; }
	curl -sSfL --retry 3 -o gitleaks.tar.gz \
		"https://github.com/gitleaks/gitleaks/releases/download/v$(GITLEAKS_VERSION)/gitleaks_$(GITLEAKS_VERSION)_linux_$(subst amd64,x64,$(GITLEAKS_ARCH)).tar.gz"
	tar -xzf gitleaks.tar.gz gitleaks
	echo "$(GITLEAKS_SHA256_$(GITLEAKS_ARCH))  gitleaks" | shasum -a 256 -c -
	rm gitleaks.tar.gz
	@echo "gitleaks $(GITLEAKS_VERSION) $(GITLEAKS_ARCH) ready at ./gitleaks (never committed)"
	@test "$(GITLEAKS_ARCH)" = "$(shell uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')" \
		|| echo "note: fetched for $(GITLEAKS_ARCH), not this machine's arch — pass ARCH= to match the image build's TARGETARCH"
