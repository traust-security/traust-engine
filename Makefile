PYTHON ?= python3
RELEASE := ./release.py
BUMP_PARTS := patch minor major

# Shared traust-postgres instance (identical container/image/port/creds/volume
# as traust-contracts and traust-ledger). The migration e2e creates its own
# dedicated empty database per run — the importer refuses a non-empty target —
# so this DSN points at the bootstrap database it connects to for CREATE DATABASE.
DB_CONTAINER ?= traust-postgres
DB_IMAGE ?= docker.io/library/postgres:16
DB_PORT ?= 5432
DB_USER ?= traust
DB_PASSWORD ?= traust-test-only
DB_BOOTSTRAP ?= traust_test
DB_NAME ?= traust_migration
TRAUST_MIGRATION_TEST_DATABASE_URL ?= postgresql://$(DB_USER):$(DB_PASSWORD)@127.0.0.1:$(DB_PORT)/$(DB_BOOTSTRAP)
TRAUST_MIGRATION_DSN ?= postgresql://$(DB_USER):$(DB_PASSWORD)@127.0.0.1:$(DB_PORT)/$(DB_NAME)
export TRAUST_MIGRATION_TEST_DATABASE_URL TRAUST_MIGRATION_DSN

# Running the migration against real findings, engine-local (no downstream
# traust dep). All per-run parameters live in one declarative profile file;
# see migration.example.yaml. Override the path with MIGRATION_PROFILE=...
MIGRATE := uv run --extra postgres python -m traust_engine.corpus.migrate_cli
MIGRATION_PROFILE ?= migration.yaml

.PHONY: help setup sync hooks lint lint-fix test db-up db-down db-test db-migration-reset migrate-plan migrate-run migrate-inspect check-release status bump $(BUMP_PARTS)

help:
	@echo "Targets ($(notdir $(CURDIR))):"
	@echo "  make setup          — uv sync + enable .githooks (run once per clone)"
	@echo "  make sync           — uv sync only"
	@echo "  make hooks          — git config core.hooksPath .githooks"
	@echo "  make lint           — ruff check + format --check"
	@echo "  make lint-fix       - ruff --fix"
	@echo "  make test           — pytest unit tests (excludes integration + postgres e2e)"
	@echo "  make db-up          — start the shared traust-postgres instance for e2e tests"
	@echo "  make db-down        — stop and remove the database container"
	@echo "  make db-test        — db-up + run the Postgres migration e2e tests"
	@echo "  make migrate-plan   — validate + list decisions, no DB (MIGRATION_PROFILE=migration.yaml)"
	@echo "  make migrate-run    — import per the profile (backend/layer routing declared there)"
	@echo "  make migrate-inspect — summarize a saved run (MIGRATION_PROFILE=migration.yaml)"
	@echo "  make check-release  — VERSION + CHANGELOG gate for current branch vs main"
	@echo "  make status         — current version, tag, git state"
	@echo "  make bump patch|minor|major — bump VERSION + pyproject.toml"

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
	uv run pytest tests/ -q -m "not integration and not postgres"

db-up: ## Start the shared traust-postgres instance (same as contracts/ledger)
	@if podman container exists $(DB_CONTAINER) 2>/dev/null; then \
		echo "$(DB_CONTAINER) already running"; \
	else \
		podman run --name $(DB_CONTAINER) --rm -d \
			-e POSTGRES_USER=$(DB_USER) \
			-e POSTGRES_PASSWORD=$(DB_PASSWORD) \
			-e POSTGRES_DB=$(DB_BOOTSTRAP) \
			-p 127.0.0.1:$(DB_PORT):5432 \
			-v traust-postgres-data:/var/lib/postgresql/data \
			$(DB_IMAGE); \
		echo "waiting for database..."; \
		for i in $$(seq 1 30); do \
			podman exec $(DB_CONTAINER) pg_isready -U $(DB_USER) -q 2>/dev/null && break; \
			sleep 1; \
		done; \
		echo "$(DB_CONTAINER) ready on port $(DB_PORT)"; \
	fi
	@echo "TRAUST_MIGRATION_TEST_DATABASE_URL=$(TRAUST_MIGRATION_TEST_DATABASE_URL)"

db-down:
	@podman stop $(DB_CONTAINER) 2>/dev/null || true

db-test: db-up
	uv run --extra postgres pytest tests/ -q -m postgres

db-migration-reset: db-up ## Drop+recreate the dedicated empty migration DB on the shared instance
	@podman exec $(DB_CONTAINER) dropdb -U $(DB_USER) --if-exists $(DB_NAME)
	@podman exec $(DB_CONTAINER) createdb -U $(DB_USER) $(DB_NAME)
	@echo "TRAUST_MIGRATION_DSN=$(TRAUST_MIGRATION_DSN)"

migrate-plan: ## Validate + list decisions, no database (clears its own output first)
	$(MIGRATE) plan --profile $(MIGRATION_PROFILE) --fresh

migrate-run: db-migration-reset ## Import per the profile (clears its own output first)
	$(MIGRATE) run --profile $(MIGRATION_PROFILE) --fresh

migrate-inspect: ## Summarize a saved migration result
	$(MIGRATE) inspect --profile $(MIGRATION_PROFILE)

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
