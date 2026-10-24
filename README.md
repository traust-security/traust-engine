# traust-engine

Processing library for Traust: scanner adapters, report tooling and deterministic
workflows. Finding identity, disposition and persistence belong to traust-core,
not the engine or app CLI. Import as `traust_engine`.

## Architecture

| Module | Role |
|---|---|
| `traust_engine.validation` | Scope enforcement and soundness gates |
| `traust_engine.sweep.calibration` | Rule-pack calibration library API |
| `traust_engine.adapters` | Scanner adapters (gitleaks, opengrep, …) |
| `traust_engine.reporting` | Report validation, SARIF, render |
| `traust_engine.ops` | Continuous ops: `Pack` (the pack's `assets.yaml`, checked against contracts `config/v1/pack`), the tick, admission and the reaper (`EngineLoop.run_once`), all through traust-core services |

Finding identity, disposition and persisted finding reads belong to
`traust_core.v1.services.findings`; the old engine cumulative replay is retired.
Scanner adapters keep tool identity in `metadata.tool`, not finding `origin`.
Native scanner fingerprints remain native scanner data, never invented Traust
identity stamps. Supplied finding classifier/dependency metadata survives the
typed bridge, and unknown severity or undeclared top-level fields are refused.
Final artifact admission goes through core's `AdapterResultArtifact` and
`ArtifactPublisher`; sparse scanner claims are not padded into audit findings.

Native scanner results use the adapter-specific observation contract.
Unreported CWEs/description/remediation stay unreported; shared supplied-value
constraints remain enforced. Authored report findings keep their strict schema.
`tests/test_native_adapter_artifact.py` runs the real binary directly through
`AdapterResultArtifact.from_document` without hand-completing fields.
The real bundled token, DSN and encrypted-Vault publication regression also
verifies that storing observations does not create canonical findings/verdicts.

Rule packs ship under `data/secure-code-audit/` (`opengrep-rules/`,
`gitleaks-rules/`). This library ships **no configuration files and never loads
config itself — it is a pure consumer.** A caller builds the context once
(`traust_contracts.load_context()`, done for you by
`HarnessEngine.load(config_home=…)`) and the engine receives it *injected*: the
ops namespaces (`h.metrics`, `h.adapters`, …) hold the frozen `HarnessContext` and
derive paths from it; stateless functions take already-resolved arguments. No
environment overrides, no cwd or workspace-shaped guessing; a required-but-absent
file fails closed with `DeploymentConfigMissing` at the entry point. The config
ownership model (contract / resolution / consumer) is documented in
`traust/docs/architecture.md` → *Configuration & context*; the runtime paths this
engine reads from `locations.yaml` are in *Runtime configuration* below.

## Install

Private Git (after tags are published):

```bash
uv add "traust-engine @ git+ssh://git@<your-forge>/<namespace>/traust-engine.git@v0.1.0"
```

Consumers pin library dependencies by commit, not release tag — a tag
needs a release cut first, a `rev` doesn't, which is what lets the
dependency chain (contracts to ledger to engine to downstream) propagate
PR-to-PR instead of waiting on a tag at every hop:

```toml
[project]
dependencies = [
    "traust-engine",
    "traust-ledger",
    "traust-contracts",
]

[tool.uv.sources]
traust-engine = { git = "git@<your-forge>:<namespace>/traust-engine.git", rev = "<commit-sha>" }
traust-ledger = { git = "git@<your-forge>:<namespace>/traust-ledger.git", rev = "<commit-sha>" }
traust-contracts = { git = "git@<your-forge>:<namespace>/traust-contracts.git", rev = "<commit-sha>" }
```

Note `dependencies` carries bare names, no `>=` floor — the `rev` above is
the floor now, and a duplicated semver constraint is a second number that
can drift out of sync with it.

Local mono-checkout (sibling repos):

```bash
cd traust-engine && make setup && make test
```

`make setup` runs `uv sync` and enables `.githooks/`. Before opening an MR that
ships user-facing changes, run `make bump patch|minor|major`, add a
`## [X.Y.Z]` section to `CHANGELOG.md`, and `make check-release` (same gate as
CI `release:check-mr`). On merge to `main`, CI tags when `VERSION` is ahead of
the latest tag.

## Optional extras

```bash
uv sync --extra graph --extra signing
```

## Runtime configuration

Runtime configuration is **config-owned** — there are no environment overrides for
deployment values. One directory, `$TRAUST_CONFIG_HOME` (default `~/.traust/config`),
holds every config file; edit them there (the AWS/SSH model).

| Config | Purpose |
|---|---|
| `$TRAUST_CONFIG_HOME` | The one config directory (corpus-config, model-registry, feeds, external-tools, safe-exec profiles, product map, budget policy, rule-pack allowlist, hardening weights, dist-git watch, internal vocabulary, optional signing pubkey). Default `~/.traust/config`; else `DeploymentConfigMissing`. |
| `locations.yaml` → `workspace` | Workspace root the harness reads repos from |
| `locations.yaml` → `analysis_results` | Findings-side artifact root (local path or `file://`/`s3://`… URI) |
| `locations.yaml` → `progress_tracker` | Metrics journal + dashboard output root |
| `locations.yaml` → `feeds_cache` | Feed cache directory |
| `locations.yaml` → `portfolio_graph` | Portfolio graph DB (defaults under `analysis_results`) |
| `locations.yaml` → `gitleaks_config` | Gitleaks TOML (overrides the bundled default) |
| `locations.yaml` → `opengrep_rules` | Opengrep rule pack dir (overrides the bundled default) |
| `locations.yaml` → `product_definitions` | Product/ownership registry endpoint (optional) |
| `locations.yaml` → `sarif_tool_uri` | SARIF `informationUri` (optional; omitted when unset) |

Secrets and OS/tool standards stay environment-driven (`GITHUB_TOKEN`, signing key
material, `XDG_*`, `JAVA_OPTS`, `SAFE_EXEC_DISABLED`).

No config ships in the wheel. Templates for every operational file live in the
harness repo as `config/*.example.*`; `install_traust` copies them into
`$TRAUST_CONFIG_HOME`.

## Development

After clone:

```bash
make setup    # uv sync + enable .githooks
make lint
make test
```

Manual equivalents:

```bash
uv run ruff check .
uv run ruff format --check .
uv run pytest -m "not integration" -q   # unit tests (no external binaries)
uv run pytest -q                        # full suite; integration skips when gitleaks/opengrep absent
uv build
```

Tests use minimal scanner fixtures under `tests/fixtures/` — no sibling
`traust` checkout required.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
