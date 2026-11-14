# traust-engine

The continuous-ops service for Traust, on traust-core: `traust_engine.ops` runs a
pack's assets through traust-core services. Finding identity, disposition,
persistence, tools and reporting belong to traust-core. Import as `traust_engine`.

## Architecture

| Module | Role |
|---|---|
| `traust_engine.ops` | Continuous ops: `Pack` (the pack's `assets.yaml`, checked against contracts `config/v1/pack`), the tick, admission and the reaper (`EngineLoop.run_once`), all through traust-core services |

This library ships **no configuration files and never loads config itself.**
The service entry point (`traust-engine run|shadow|record|diff|claim --core <core.yaml>
--pack <assets.yaml>`) builds traust-core's `Context` once from the files it is given and
passes core's services in; everything below it takes already-resolved arguments. `--core`
takes a separate core configuration file in `traust.yaml` format, not the `traust.yaml` in
an old configuration home. Set its `home:` to the deployment home (otherwise core defaults
to `~/.traust`); inline `locations:` are resolved relative to `core.yaml` by traust-core.
The engine imports only traust-core's public API: `traust_core.v1.context`, `models` and
`errors` (the consumer ratchet in CI holds it there).

Command templates can use `{worker}` alongside `{run_id}`, `{repo_url}`, `{role}` and
`{rule}`. `{worker}` is the claiming runner's ID, so artifact-only session commands can
record their audit evidence under the same lease; claim, heartbeat and completion are unchanged.

`claim` leases only the assets the host can run. An asset whose `runner` labels carry
`llm` is a skill session — a runner pool's unit of work, whose image carries the agent
harness; the engine image has no agent CLI, so the claim leaves those orders queued for
their pool (the deployed claim workers' shape). A host that does carry the harness (the
local rig, an operator workstation with the agent CLI logged in) passes `--label llm` to
include them. Unlabeled assets stay claimable: the label vocabulary is a proposal, and a
pack yet to carry it names no executor the claim refuses to be.

## Migrating from the processing-library API on main

The continuous-ops engine is **not a drop-in replacement** for the processing library
on `main`. Its public exports are `EngineLoop` and `Pack`; the old `HarnessEngine`
facade and processing modules are removed. Library consumers build
`traust_core.v1.context.Context` once and use its public services. Command-line
consumers use the corresponding `traust` doors, installing `traust-engine` separately
when they need the continuous-ops service.

| Previous API, input or output | Replacement / migration action |
|---|---|
| `from traust_engine import HarnessEngine`; `HarnessEngine.load(config_home=...)` | `from traust_core.v1.context import Context`; `Context.from_file(Path("core.yaml"))`, then `context.services()`. For scheduling, use `traust-engine run\|shadow\|record\|diff\|claim --core core.yaml --pack assets.yaml`; `core.yaml` is separate from the old config-home `traust.yaml` and sets `home:` to the deployment home. |
| `corpus`, finding identity/disposition, `ledger`, file-backed findings projections | Core's `findings`, `assessment`, `artifacts` and optional `ledger` services. Existing files/ledger layers are not imported automatically; legacy-data migration and cutover are separate work. |
| `adapters`, `_util.safe_exec`, `toolchain` | Core's provider catalog and code-facts/validation services, configured through `Context`; use the corresponding `traust` scanner commands. Engine-internal adapter imports are no longer supported. |
| `impact`, `osv`, `depsdev`, `applicability` | Core's `exposure` and `below_range` services and `traust impact` commands. The portfolio graph is replaced by recorded inventory/SBOMs, so unmeasured dependencies require SBOM ingestion. |
| Impact `verified_versions` / `verified_by` inputs | No equivalent integration into impact analysis yet. Core records below-range review findings, but those verdicts do not currently extend impact range evaluation. Do not assume this use case was preserved. |
| `portfolio` graph queries and `portfolio-graph.db` | Core's `portfolio`, `exposure`, `code_facts` and `insight` services. Graph-only queries such as `internal-coupling`, `crd-consumers`, `ships-module`, `imports-package` and `exports-of` are retired, not compatibility aliases. |
| `sweep` and file-backed sweep state | Core's `detection_quality` service and `traust sweep` commands. State is core-owned; the first new rule-lane run establishes a new baseline. |
| `reporting`, `compliance`, metrics journal, model registry | Core's `reporting`, `compliance`, `spend` and `insight` services; `Context.register_model_catalog` registers model pricing. Views/exports replace legacy journal/dashboard files, not their file formats. |
| Bundled `data/secure-code-audit/` rule packs | The harness's `packs/security/detection/` owns the rule packs. Install the harness pack and configure it through core; the engine wheel no longer supplies it. |
| Engine extras `graph`, `signing`, `postgres`, `ledger-migration`, `remote`, `s3`, `gcs` | These extras are removed. Select database/provider dependencies in the core deployment; installing an old engine extra no longer enables the feature. |
| `$TRAUST_CONFIG_HOME` plus `locations.yaml` and per-feature configuration files | Pass a separate core file (for example, `core.yaml`) explicitly with `--core`; it uses `traust.yaml` format, sets `home:` to the deployment home, and contains inline `locations:` resolved beside that file. Use `traust config migrate <old-home>` for old configuration homes. Core ships the stock tool pins, safe-exec profiles and feeds registry, but a feed-backed pack must still pass its registry path with `--feeds`; the engine registers those feeds with core and pins the registry into the run manifest. `--pin` and `--models` are also available on the engine CLI. |

Only core's public `context`, `models` and `errors` modules are consumer APIs; do not
replace removed engine imports with core provider/repository internals. See
[traust-core](https://github.com/traust-security/traust-core) for its service API and
[traust](https://github.com/traust-security/traust) for CLI and pack configuration.

Typed adapter `scan()` results are scanner observations validated against
`adapter-result.schema.json`, not authored audit findings. Unreported CWEs,
description and remediation stay empty; adapters do not supply validity
verdicts. Scanner identity lives in `metadata.tool`; native fingerprints remain
in raw scanner candidates, not the domain finding fingerprint. Supplied
Finding metadata and declared workflow origins are preserved, and an explicit
unknown severity raises rather than becoming `low`.

## Install

Private Git (after tags are published):

```bash
uv add "traust-engine @ git+ssh://git@<your-forge>/<namespace>/traust-engine.git@v0.1.0"
```

Consumers pin library dependencies by commit, not release tag — a tag
needs a release cut first, a `rev` doesn't, which is what lets the
dependency chain (traust-core to engine) propagate
PR-to-PR instead of waiting on a tag at every hop:

```toml
[project]
dependencies = [
    "traust-engine",
]

[tool.uv.sources]
traust-engine = { git = "git@<your-forge>:<namespace>/traust-engine.git", rev = "<commit-sha>" }
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

## Runtime configuration

Everything the service needs comes from its arguments: `--core` (a separate `core.yaml`
file in `traust.yaml` format, with `home:` set to the deployment home and inline
`locations:` resolved beside the file), `--pack` (the pack's `assets.yaml`), and
optionally `--pin`, `--feeds` and `--models`. Without an explicit `home:`, core defaults
to `~/.traust`. For feed-backed packs, pass the feeds registry path with `--feeds`;
the engine registers that registry with core and pins it into the run manifest. Without
`--feeds`, feed requirements are not registered, even though core ships a stock registry.
The harness documents deployment configuration; core owns and ships the stock tool pins,
safe-exec profiles and feeds registry, while runtime feed registration is explicit.

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
uv run pytest -q
uv build
```

Tests use minimal fixtures under `tests/fixtures/` (an estate-neutral config
home and a pack) — no sibling `traust` checkout required.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
