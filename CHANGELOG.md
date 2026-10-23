# Changelog

All notable changes to traust-engine are documented here.

## [0.41.0]

- **New: `traust_engine.applicability`, below-range evidence packets** (CVE
  identification plan, Phase 3; Go and PyPI first). An advisory's ranges often
  stop at a support or testing boundary rather than where the code changed, so
  an installed version below the stated start can still carry the vulnerable
  code. `build(repo, out)` finds those versions and writes the facts a review
  needs. It writes no verdicts.
  - **Candidates:** every exact install (locked or declared) is checked against
    every OSV advisory naming the package. A version is a candidate when it is
    below every span's explicit `introduced` (`below_range`), or after a span
    that ends at `last_affected` (no known fix) and before the next span's
    start (`gap`). A version past a span's `fixed` end is fixed, not a gap. A CVE with several records (GHSA, PYSEC, GO-) is one
    candidate.
  - **Fix choice:** references are ranked GIT `fixed` commit, then `FIX`, then
    other commit or PR links, and alias records (the CVE record often carries
    the fix commits) are included. Each patch is scored on files present in the
    installed tree, whether its message names the advisory, and whether it only
    adds code (the shape of a feature introduction); release and version-bump
    commits always lose and are flagged `release_commit`. A bundle is narrowed to the
    commits that name the advisory. The choice and every alternative are
    recorded.
  - **Installed source:** fetched from the registry (proxy.golang.org; PyPI
    sdist, falling back to the wheel) on allow-listed hosts only, with checked
    redirects, size caps and safe extraction. Nothing fetched is executed.
  - **Matching:** patch paths are anchored by stripping a consistent prefix,
    never by base name alone. Per hunk, the packet counts the removed and added
    lines present in the installed file.
  - **Accounting:** every candidate is a packet or a coverage gap with its
    reason, and a mismatch raises.
- `osv.Query.version` may be None: the query then asks for every advisory
  naming the package.

## [0.40.0]

- **Fix: the OSV fixed version now depends on the installed version.**
  `adapters.osv.fixed_version` returned the first `fixed` event in the
  record and never looked at the installed version. A record with several
  affected spans (for example, below 1.5.0, and from 2.0.0 to 2.3.0)
  therefore told a 2.1.0 install to "upgrade" to 1.5.0. It could also
  return a GIT commit hash as the version. The fix comes from the new
  `traust_engine.osv.ranges`:
  - `spans()` reads every introduced/fixed pair and `last_affected`
    ending, and skips GIT ranges.
  - `version_key()` gives a comparable key for one ecosystem's versions.
  - `fixed_for()` picks the lowest fix above the installed version that no
    span marks affected again. It prefers the fix of the span covering the
    installed version, and returns None when there is no fix above it.
  The API adapter, the osv-scanner adapter and the SBOM adapter all pass
  the installed version. When a version can't be ordered, the old first-fix
  answer is kept.
- **New: candidates carry the record's range evidence.** Each OSV candidate
  gains two fields: `osv_ranges` (the package's ranges as stated: type,
  repo, events) and `fix_references` (the record's `FIX` reference URLs).
  These are inputs for checking applicability against code later. They
  don't change any verdict.
- `parse_version` and `parse_semver` moved to `traust_engine._util.versions`
  so the OSV package can use them without importing the impact analyzer.
  `impact.analyzer` still exports both.

## [0.39.0]

- **New: LLM-application rule pack (plan step D3) for Python, TypeScript
  and Go** (`opengrep-rules/<lang>/llm-application.yaml`, rule-pack README
  v1.10). These are deterministic rules for shapes that can be decided from
  code. Each carries `metadata.owasp_llm` next to its CWEs.
  - **Model output reaching a dangerous sink:** taint from SDK completion
    calls and response shapes into a shell, code evaluation, SQL text or a
    file path (LLM05; CWE-1426 plus the sink's CWE).
  - **Model supply chain (Python):** `trust_remote_code=True`,
    `torch.load` with `weights_only=False` or left at the default, and Hub
    downloads with no pinned `revision` (LLM03).
  - **MCP server on HTTP/SSE with no authentication in the file** (LLM06,
    CWE-306). A per-tool "no auth call in the handler" rule was dropped
    after it flagged almost every tool in real MCP servers; per-tool
    authorization is left to review.
  - **Unbounded agent loops:** an unconditional loop that calls a model
    and names no step, budget, deadline or timeout bound (LLM10, CWE-834).
- **Opengrep facts carry `owasp_llm`.** The adapter copied `metadata.owasp`
  into each fact but dropped the new `metadata.owasp_llm`, so the category
  never reached the audit. Facts now have an `owasp_llm` list (empty for
  rules without it), which the audit copies into `owasp_llm_references`.

## [0.38.2]

- **Pins traust-contracts 0.62.0 (`f8c9cbd`) and traust-ledger 0.11.4
  (`366ccb0`):** report findings gain `owasp_llm_references` (OWASP Top 10
  for LLM Applications category IDs). Storage revision 6 carries it in
  `report_finding`.
- **Fixed: the validator named a fingerprint command that does nothing.**
  - **The problem:** fingerprint-mismatch and autolink errors told you to
    run `python3 -m traust_engine._util.finding_identity fingerprint …
    --write`. That module has no entry point, because the CLI moved to
    traust, so the command exited silently without stamping anything.
  - **The fix:** the messages now name
    `python3 -m traust.cli corpus finding-identity`. The module docstring
    points at the same command, and the empty `# CLI` section is gone.

## [0.38.1]

- **Fixed: seeded-fixture reports could never pass validation.**
  - **The conflict:** recall-benchmark seeded fixtures are local git
    checkouts registered with a `file://` `repo_url` (`build_canaries.py`),
    and the scorer matches a run's `metadata.repository` against that URL.
    The validator accepted only `https://` URLs, so a fixture report could
    either validate or be scored, never both.
  - **The fix:** a `file:///…` repository is now a single warning ("local
    fixture checkout; benchmark and seeded-fixture runs only"), not an
    error plus a "does not parse" warning.
  - A bare `file:///` or a trailing slash is still an error. Every other
    shape is unchanged.
  - Found by the first audit of the `llm-app` fixture.

## [0.38.0]

- **New `adapters/llm_app.py`: deterministic detection of LLM, agent and
  MCP applications** (deepsec-comparison plan v2.1, workstream D1).
  `detect(repo)` tags a checkout, and the files in it, when any of these
  appears:
  - **Source imports**, with `file:line` evidence, in Python, JS/TS, Go,
    Java/Kotlin and Rust:
    - model SDKs (OpenAI, Anthropic, Google GenAI, Mistral, Cohere, Groq,
      Ollama, LiteLLM, transformers, vLLM…);
    - agent frameworks (LangChain/LangGraph, LlamaIndex, CrewAI, AutoGen,
      Semantic Kernel, Haystack, DSPy, langchaingo, LangChain4j, Spring
      AI…);
    - MCP server SDKs;
    - vector stores (Chroma, Pinecone, Qdrant, Weaviate, Milvus, FAISS,
      LanceDB, pgvector).
  - **Direct manifest declarations**: never lockfiles, which also list
    transitive libraries, and never indirect `go.mod` requires.
  - **Prompt-template files**: `.prompt`, `.prompty`, and templates under
    a `prompt(s)/` directory.
- **One deterministic hop through in-repo wrappers:** a file that imports
  a tagged in-repo module (Python, or relative JS/TS imports) is tagged
  with the module's kinds and listed in `files_via_wrapper`. Calling the
  SDK through an internal `llm.py` is the common shape. On mlflow that
  adds 252 files (484 in total).
- **Output:** `llm_application`, `kinds`, `signals` (kind, library, via
  import/declared/file, evidence), the tagged `files` and
  `files_via_wrapper`.
- **It is a fact and a candidate generator, never a finding.** It reads
  files only: nothing is imported or run, and no git command runs in the
  target. It gates the LLM application review checklist and the
  `llm-integration` review surface.
- **On real clones:**
  - etcd and mp-export-api: none;
  - mlflow: tagged (model SDKs, agent frameworks, MCP, vector stores; 232
    files);
  - feast: tagged (vector stores, a declared MCP server; 12 files).

## [0.37.1]

- **Fixed: `go.mod` `replace` directives were ignored** by the dependency
  pre-scan; the shared `parse_gomod` doesn't read them.
  - **A require replaced with a directory in the checkout**
    (`go.etcd.io/etcd/server/v3 => ./server`) is the project's own
    module. It is no longer looked up as a published package. On etcd
    that removes 3 false positives and 45 such requires.
  - **A require replaced with another module or version** queries what
    actually builds: `github.com/old/lib => github.com/fork/lib v1.2.5`,
    or ARO-RP's 22 version pins such as
    `k8s.io/api => k8s.io/api v0.29.15`.
  - Version-specific replaces apply only to the version they name. The
    module's own path is never a dependency.
  - Provenance counts both: `go_requires_replaced_locally` and
    `go_requires_replaced_by_module`.

## [0.37.0]

- **Test and dev dependencies are tagged, never skipped** (owner decision
  2026-10-21). The dependency pre-scan reads each manifest's scope:
  - Maven `<scope>test</scope>`, including under `dependencyManagement`;
  - npm `devDependencies`;
  - Cargo `[dev-dependencies]`;
  - Poetry dev-dependencies and non-main groups.

  The shared parsers merge those sections, so `declared_scopes` reads them
  in the adapter. A deps.dev-resolved tree inherits its direct
  dependency's scope.
  - A candidate carries `dependency_scope: test` or `dev` only when
    **every** path to it is test or dev. A runtime path removes the tag,
    so an untagged candidate means runtime or unknown.
  - On keycloak, 114 of 203 deps.dev-resolved candidates are `test`
    (JMeter, ApacheDS, Arquillian trees) and 13 more are `dev`.

## [0.36.0]

- **Manifests without a lockfile are resolved through deps.dev** (owner
  decisions 2026-10-20 option c and 2026-10-21: on by default, opt-out by
  configuration).
  - **New `traust_engine.depsdev` client** for
    `GET /v3/systems/{system}/packages/{name}/versions/{version}:dependencies`
    (npm, PyPI, Maven, Cargo) and the package's default version.
    - It follows the OSV client's failure rule: `ok`, `not-found` (404),
      or `unreachable` / `quota-deferred` / `error`, and never an empty
      graph on failure.
    - Low concurrency and an optional on-disk cache (24 h; failures are
      never cached).
    - `ATTRIBUTION` carries the CC BY 4.0 notice for deps.dev-generated
      data. API use is subject to the Google APIs Terms of Service.
  - **`adapters.osv.resolve_transitive`**, used by
    `scan_api(..., resolver=)`:
    - every direct declaration of an unresolved manifest is resolved on
      its own;
    - the packages in its graph join the OSV lookup with
      `version_basis: resolved` and `resolved_via`;
    - a declaration with no version resolves at deps.dev's default version
      (`version_basis: resolved-default`), what an install gets today.
  - **A declared name overrides resolved versions where only one version
    installs.** For PyPI the rule applies per requirements file, since
    each file is its own environment. For Maven it is repo-wide, since
    parent poms manage versions for every module. npm and Cargo keep every
    version.
  - **Coverage:** a manifest moves to `resolved_manifests` only when every
    declaration resolved. Otherwise it stays in `unresolved_manifests`
    with a `reason`.
  - **Provenance:** a `resolution` block with source, time, counts,
    issues, cache hits, license and attribution.
- **Fixed: requirement lines with no version** (`requests`,
  `flask[async]`) were dropped by the shared parser and never counted.
  Coverage was overstated. They now count as declarations, and deps.dev
  resolves them.

## [0.35.1]

- **`adapters/osv_sbom.py` fixes from the 0.35.0 review:**
  - `scan_sbom` now validates a dict input the same way `load_syft` validates
    a file: a CycloneDX or SPDX document passed as a dict raises
    `SbomFormatError` instead of silently returning a "complete" scan with
    zero candidates.
  - `grype_os_installed_matches` attributes a match through its artifact id —
    grype carries syft's ids, which name the exact copy — so two OS packages
    that each installed the same name+version are never conflated, and a
    match without locations is still attributed. Without a usable id, the
    purl plus the match's paths decide: an app-installed copy of an
    RPM-installed name+version (under `/opt` vs `/usr`) is no longer labeled
    `installed_by` the RPM.

## [0.35.0]

- **Container images: language packages through OSV** (`adapters/osv_sbom.py`,
  owner decision 2026-10-20, option b). It reads a **syft JSON** SBOM and
  sends only language packages through the shared OSV client and the
  pre-scan's `lookup`: npm, PyPI, Maven, Go modules including the Go
  standard library, Cargo, RubyGems and NuGet. OS packages (rpm, deb, apk)
  stay with grype and the distribution's security data.
  - **A language package installed by an OS package is skipped**, using
    syft's `ownership-by-file-overlap` relationships. A Red Hat RPM such as
    `python3-urllib3` carries backported fixes under an unchanged upstream
    version, so an upstream lookup would report CVEs it already fixes. On
    `ubi9/python-311`, 216 of 218 language packages were RPM-installed.
  - CycloneDX and SPDX are refused (`SbomFormatError`): they drop those
    relationships.
  - **Provenance** gives the same `status` (`complete` / `degraded` /
    `failed`, with the fail-fast probe), plus what was skipped and why:
    OS-installed (by type), unversioned (Go main modules), and
    unsupported types (generic binaries, which grype matches by CPE).
  - `mark_grype_duplicates` tags `also_in_grype` when grype reported the
    same package (purl identity) and the same advisory (OSV id, alias or
    upstream id).
  - `grype_os_installed_matches` lists grype's own matches on language
    packages an OS package installed, with the owning packages. grype
    applies file ownership only partly, even on syft JSON: on
    `ubi9/python-311`, 26 of its 32 language-package matches (1 critical,
    12 high) were against packages the nodejs, npm and
    python3.11-setuptools RPMs installed.
  - **Air-gapped:** `write_cyclonedx` and `run_offline` give the filtered
    packages to osv-scanner offline (`-L <file>.cdx.json --offline`), and
    `parse_offline` restores the image paths. On external-secrets v0.9.0
    this matched the API exactly (205/205).
- **`lookup` candidates carry `upstream`**: Red Hat OSV records list
  their CVEs there, not in `aliases`.

## [0.34.0]

- **The harness no longer fetches or tracks osv-scanner's offline
  database** (scanner-currency step 6, owner decision 2026-10-20). OSV is
  queried through its API; an air-gapped deployment provides osv-scanner and
  its database itself.
  - `toolchain._fetch_dbs` populates grype only; `db_status("osv-scanner")`
    is `None` (no tracked database), and `db_cache_dirs()` no longer
    includes an osv-scanner cache, so offline bundles carry grype's only.
  - Kept for air-gapped runs: `adapters.osv.run_scanner` / `parse_output`
    and the `--offline` freeze flag.

## [0.33.0]

- **The osv adapter queries the OSV API; no scanner binary or local
  database is needed** (owner decision 2026-10-20). `adapters/osv.py` reads
  the checkout's lockfiles and manifests with the portfolio parsers (plus
  `go.mod`, with the Go stdlib version from `toolchain`/`go`), then looks
  every package up through the new shared client.
  - **`traust_engine.osv`** is the one OSV client for every caller:
    `querybatch` with page tokens followed, `vulns/{id}` details, retries
    with backoff. **A failed lookup is never an empty result**: unanswered
    queries are `None` and counted as `unreachable`, `quota-deferred` or
    `error`.
  - **Lookup provenance** comes with every scan: source, query time,
    packages per ecosystem, unanswered packages, missing details, and
    `status`: `complete`, `degraded` (some lookups failed), or `failed`.
  - **An unusable API fails fast.** One probe lookup runs before the scan;
    if it fails, or if no package at all is answered, the status is
    `failed` with a `failure` block (`status`, `detail`), no candidates,
    and `scan()` raises `RuntimeError`. Before, an outage retried every
    batch and read as a degraded scan.
  - **`transitive_coverage`** is `partial` when a manifest has no lockfile
    beside it, and `unresolved_manifests` lists those files. A requirements
    file that pins every line counts too unless it was compiled
    (`pip-compile` / `uv pip compile`: `# via` or `--hash=` lines), since
    pinned direct dependencies say nothing about the rest of the tree. Their direct
    declarations are queried at the declared floor (`version_basis:
    manifest-floor`); the transitive tree is not resolved. Owner decision
    (c): report this as a coverage gap now; deps.dev resolution may follow.
  - **Severity:** `max_severity` is a CVSS v3 base score computed from the
    record's vector (new `osv.cvss` calculator), or one borrowed from a GHSA
    or CVE alias, or the record's declared word. `severity_basis` says which.
    `MAL-` malicious-package advisories are critical. An advisory with no
    score anywhere is `unscored`, banded medium by the harness rule and
    labelled so it is never mistaken for a scored medium.
  - The osv-scanner functions (`run_scanner`, `parse_output`) stay for
    **air-gapped deployments**, which run osv-scanner offline against a
    local OSV database the adopter provides. The API is the default; the
    harness installs neither the binary nor the database.
- **Parser fixes** (they also affect the portfolio graph):
  - `requirements.txt` lines with extras (`aiohttp[speedups]==3.14.1`) were
    dropped.
  - Requirements files are recognised by any name containing
    `requirements` (`dev-requirements.txt`, `py3.10-ci-requirements.txt`),
    not only `requirements*.txt`.
  - New `yarn.lock` (classic and Berry) and `uv.lock` parsers. Workspace
    members are the project itself and are skipped.
- **Numeric CVSS scores are banded** (9.0+ critical, 7.0+ high, 4.0+ medium,
  below 4.0 low). Before, every numeric score fell through to medium.

## [0.32.0]

- **The migration command line moves out of the package.** The engine is a
  library: `tests/test_no_cli_entrypoints.py` forbids `argparse`, `def main`
  and `__main__` blocks in `src/traust_engine`. `corpus/migrate_cli.py`
  (2026-09-29) broke all three tests, which had failed on main ever since.
  - `scripts/migrate.py` (outside the package) parses arguments and prints.
    `make migrate-plan`, `make migrate-run` and `make migrate-inspect` run it
    engine-locally, unchanged.
  - `traust_engine.corpus.migrate` holds the logic as library functions:
    `load_profile`, `resolve_options`, `inspect_summary`, `resolve_database`,
    `prepare_output`, `execute`, `summary`, `exit_code`.
  - `python -m traust_engine.corpus.migrate_cli` no longer exists; use
    `uv run python scripts/migrate.py`. Flags, profile keys, output and exit
    codes are unchanged.
  - The old docstring named a `traust corpus migrate-postgres` wrapper; no
    such command exists, and the reference is gone.

## [0.31.0]

- **Nothing reads `progress-tracker/configs/` any more.** Deployment config
  lives in the config home (`TRAUST_CONFIG_HOME`); public reference data
  ships in the package.
  - **SLA policy:** `metrics.default_sla_policy()` is `sla-policy.yaml` in the
    config home. When it's missing, it raises `DeploymentConfigMissing`
    naming traust's `config/sla-policy.example.yaml`; it never falls back to
    another tree. `--policy` still overrides.
  - **Compliance scope:** `compliance.scope_registry()` and
    `scope.default_scope_path()` point at `compliance-scope.yaml` in the
    config home. The file may not exist until a scope is declared.
  - **Compliance reference data ships in the engine** (`data/compliance/`,
    reached with `assets.compliance_data_dir()`): the NIST 800-53 rev5 spine,
    the 800-53B High and Moderate profiles, the PCI DSS v4, SOC 2 and GDPR
    catalogs, their provenance, and the harness's control-to-check mapping
    (`compliance-mapping.yaml`). A deployment that needs a different mapping
    passes `--registry`.
- `compliance.dashboard.build()` drops its `progress_tracker` argument, which
  it used only to find the scope registry.

## [0.30.0]

- **Section 5 (Deprioritized) carries review-surface tags.** traust-contracts
  0.60.0 lets a deprioritized threat carry `review_surfaces`. The renderer adds
  a trailing `review_surfaces` column to section 5 when any row is tagged (an
  untagged section renders as before), and the linter accepts that column and
  checks each value against the enum.
- **Pins traust-contracts 0.60.0 and traust-ledger 0.11.3.** The vuln-findings
  schema now enforces the full-scan `out_of_scope` rule itself; this
  validator's cross-check stays and reports the same rule.

## [0.29.0]

- **Threat-model review-surface tags survive the Markdown.** The rendered
  `<repo>-threat-model.md` used to drop `review_surfaces`
  (traust-contracts 0.57.0), so a reader of the `.md` couldn't see which
  threats and entry points sit on a review surface.
  - **Renderer:** adds a trailing `review_surfaces` column to section 3
    (entry points) and section 4 (threats) when any row carries tags. An
    untagged model renders exactly as before.
  - **Linter** (the prose contract): accepts that optional trailing column
    in both sections and checks every value against the `review_surface`
    enum.
  - **Corpus parser** (`parse_threats`): reads the tags back, so the
    round trip stays lossless.

## [0.28.0]

- **Python rule pack v1.9: two misses from the `team-notes` recall-fixture
  run.**
  - `traust-python-injection-like-wildcard-unescaped` catches a bound
    f-string parameter with an interpolation and a `%` anywhere in it
    (`(f"{owner}/{folder}/%",)`).
  - `traust-python-ssrf-request-taint` gains `request.get_json`,
    `request.json.get`, `request.values.get` and `request.form[...]`
    sources, and more `requests`/`httpx` sinks. A database fetch ends
    request taint.
  - New `traust-python-ssrf-stored-url` (CWE-918, low confidence) flags an
    outbound call whose URL is a database row subscript or a url-type model
    field. Operator config, settings, environment and API response objects
    are excluded.
  - On five estate repos, nothing outside these rules changed. The
    fixture's two misses are now found. Two new candidates in
    qontract-reconcile: Prometheus URLs from model fields.

## [0.27.0]

- **Per-model cache rates and long-prompt pricing** (traust-contracts 0.59.0).
  - `cost_usd` prices cache hits at the model's `cache_read_multiplier`
    (0.1 when unset).
  - It takes an optional `long_prompt` usage block (`tokens_in`,
    `tokens_out`, `cache_read`, `cache_creation`): the tokens from requests
    over the model's long-prompt threshold. Those are priced at the
    long-prompt rates and the rest at base rates.
  - **Collectors:** both transcript collectors (`collect_spend.collect`,
    `attribute_spend.collect_attributed`) judge each request on its own. A
    request whose prompt (input, cache reads and cache writes) is over the
    model's threshold is also counted in the bucket's `long_prompt`, and
    metrics rows carry it when it's non-zero.
  - **Reports:** every report that re-derives cost from a row
    (`metrics/spend.py`) passes it through.
  - New helpers: `long_prompt_thresholds()` and `collect_spend.add_usage()`.
    The `HarnessEngine.models` facade exposes `long_prompt_thresholds()`, and
    its `cost_usd` takes `long_prompt`.
  - Old rows have no `long_prompt` block and keep base pricing.
- **`out_of_scope` only on diff scans.** A vuln-findings
  `review_surface_coverage` entry of `out_of_scope` is an error unless the
  report carries `metadata.additional.coverage_diff` (traust-contracts
  0.58.0). Verification reports are always diff-scoped.
- Pins traust-contracts `f7869db` (0.59.0) and traust-ledger `2ffc506`.

## [0.26.0]

- **Review-surface coverage is checked on the scans that follow an audit,
  and on rpm audits** (traust-contracts 0.57.0).
  - `vuln-findings` and `verification` reports from traust 0.21.0 on must
    carry `review_surface_coverage`. The schema already checks its shape,
    including the note that every status except `finding` needs. The validator
    adds one check: each `finding_ids` entry must be a finding of the scan
    itself. For vuln-findings that means `findings[].id`; for verification,
    `regressions[].id` or a re-checked original finding's `original_id`.
  - rpm-profile audits from traust 0.21.0 on must carry the record, as
    code-profile audits have since 0.20.0. Container audits still don't.
  - Gating is epoch-aware (`_gate`) and reads each scan's own fields: the
    top-level `metadata.harness_version`, with `metadata.date` for
    verification and `scanned_at` for vuln-findings. Earlier reports are
    unaffected.
  - The audit requirement's error now names the profile and lists
    `out_of_scope` among the statuses.

## [0.25.2]

- **Directory sweeps no longer crash on skill working files.**
  `collect_report_files` skips hidden directories below the swept root
  (`.triage-state/`, `.threat-model-state/` and similar), which hold skill
  working state, not artifacts.
- **The identity, repository and strict checks run only on a report-shaped
  document:** an object whose `metadata` is an object and whose `findings` is
  a list of objects. On anything else they raised (`'str' object has no
  attribute 'get'`), which aborted the sweep for the whole directory. Such a
  document still fails on its schema errors.

## [0.25.1]

- **The validator detects three more artifact kinds by filename.**
  `*-remediation-verification.json`, `*-refuted-register.json` and
  `*-priv-profile.json` fell through to the audit-report schema, so every one
  of them failed `traust reporting validate`, in a directory sweep or on its
  own. They now validate against `verification.schema.json`,
  `refuted-register.schema.json` and `operator-priv-profile.schema.json`.
  - Verification reports get their existing cross-checks.
  - Refuted registers and privilege profiles are not finding reports, so
    they are schema-only, like `cloud-config-audit`. They skip the code-audit
    cross-checks, the identity and repository checks, and strict mode.
  - Directory sweeps still skip refuted registers.

## [0.25.0]

- **Version gates read the audit date first, so they hold across the
  2026-09-10 reset.** traust reset its version to 0.1.0 that day, and the
  numberings overlap: a pre-reset `0.186.2` and a post-reset `0.18.6`
  compared the wrong way round. `_gate()` takes the numbering from the
  audit's date (a cumulative report's `cumulative.original_report_date`,
  since `build_cumulative` re-stamps `metadata.date`) and only then compares.
  - Pre-reset reports keep today's numeric gates.
  - Post-reset reports meet every pre-reset gate (canonical IDs, the 0.15.0
    consistency rules, and `deterministic_steps`, which no post-reset report
    could reach before).
  - Revalidating 4,922 corpus reports (all 304 pre-reset 0.1xx audits, all
    4,118 cumulative reports, 500 random audits) gives identical results.
- **`review_surface_coverage` cross-checks (traust-contracts 0.56.0).**
  - Code-profile audits from traust 0.20.0 must carry the record.
  - `finding` must name findings that exist.
  - `negative` needs a `negative_results` entry whose `area` is the surface
    ID, optionally followed by a space and a qualifier.
  - `not_assessed` needs a `coverage_gaps` entry
    `{tool: review-surfaces, system: <surface>}`.
  - The schema already checks the record's shape.

## [0.24.0]

- **The opengrep adapter no longer honours the scanned target's own `nosem`
  comments.** opengrep, like semgrep, drops a match on a line ending in
  `# nosemgrep` (or `// nosem`) by default, so an audited repository could
  hide its own facts. The adapter passes `--disable-nosem`. Facts whose
  match, or the line just above it, carries such a comment get
  `nosem_marked: true` and a note in the finding description, so the judge
  sees the marker and weighs it. Same doctrine as the gitleaks
  `inline_allow` change in 0.22.0.

## [0.23.0]

- **The bundled rule packs are the only copy, and they are current.** The
  opengrep pack and gitleaks config under
  `src/traust_engine/data/secure-code-audit/` are what every default run
  loads (no rule-pack argument, no `locations` override), and traust now
  deletes its own copies. This release brings the opengrep pack to rule
  pack v1.8: seven new rules plus wider deserialization sinks.
  - `traust-python-injection-like-wildcard-unescaped` and
    `traust-go-injection-like-wildcard-unescaped` (CWE-155): a LIKE/ILIKE
    pattern built from a run-time value with `%`/`_` left live.
  - `traust-python-authentication-jwt-signature-unverified` and
    `traust-go-authentication-jwt-signature-unverified` (CWE-347): token
    decoding with signature verification switched off, including under a
    test/debug flag.
  - `traust-python-input-validation-pickle-loads-taint` gains
    `Unpickler(...).load()`, `dill`, `jsonpickle` and `shelve` sinks;
    `traust-python-input-validation-restricted-unpickler-inventory` lists
    restricted unpicklers.
  - `traust-python-cryptography-secret-compare-not-constant-time` and
    `traust-go-cryptography-secret-compare-not-constant-time` (CWE-208).
- **`tests/test_bundled_rule_packs.py` pins the default.** With no argument
  and no config the adapters resolve to the bundled copies; every rule file
  has a fixture; every language passes `opengrep test`; and a default
  `opengrep.scan()` / `gitleaks.scan()` on canary code reports recent rules.
  The scanner-dependent tests are not marked `integration`, so the pre-push
  hook runs them wherever opengrep and gitleaks are installed.
- The opengrep adapter docstring no longer lists `OPENGREP_RULES_DIR` /
  `RULE_PACK_DIR`, which the code never read.

## [0.22.1]

- **`registry.models.stamp()` omits unknown values instead of writing
  `null`.** A role missing from the registry used to produce
  `"floor": null`, which traust-contracts 0.55.0 rejects, since it types
  `metadata.additional.model_routing.floor` as a string. The stamp now
  leaves out `floor`, and `registry_sha` when the registry has no source
  sha, so every stamp validates against the report schema.
- Pins traust-contracts 0.55.0 (`0f3298b`) and traust-ledger `a5bdf19`.

## [0.22.0]

- **The gitleaks adapter no longer honours `gitleaks:allow` comments in the
  scanned target.** `traust_engine.adapters.gitleaks` passes
  `--ignore-gitleaks-allow`: a suppression the audited repository ships for
  its own lines is repository content under audit, not an exemption. Hits on
  such lines are now reported, with `inline_allow: true` on the candidate and
  a note in the finding description so the judge sees the marker and weighs
  it. Only that boolean leaves the adapter, never line content. Tested
  against gitleaks 8.30.1.

## [0.21.0]

## Changes (breaking)

- **The ledger is configured only by the injected context.** `ClientSettings`
  resolves every `LedgerClient` argument once from `ctx.ledger`
  (`ledger.yaml`, traust-contracts 0.53.0) and passes all of them explicitly,
  so the Ledger SDK's environment fallbacks never apply:
  - `dsn` set: database mode on the one layer the caller binds
    (`engine.ledger.service(…, layer=…)`, `engine.ledger.bind(layer)` once per
    run, `engine.ledger.pull(path)`). No `dsn`: file mode.
  - `signing` → `SigningConfig` + `signing_required`; `identity` → the token
    verifier (JWKS, or discovered from the issuer) and the employee-directory
    check (fail closed on a missing command).
  - Unconfigured parts get explicit defaults — no signing requirement, no
    key, no directory — **not** `LAAS_SIGNING_*`, `LAAS_DATA_DIR`,
    `LAAS_BACKEND_TYPE`, `LAAS_DATABASE_URL`, `LEDGER_OIDC_*` or
    `LEDGER_DIRECTORY_COMMAND`. **Deployments that signed through
    `LAAS_SIGNING_*` must move those settings into `ledger.yaml` `signing`.**
  - The only value still resolved by the Ledger is the caller's token
    (`ledger auth login`, a token file or `LAAS_TOKEN`) and, without
    `identity`, its verifier — a caller credential, not deployment config.
- `LedgerService(data_dir=…, settings=…)` is file mode and needs a directory
  (no `LAAS_DATA_DIR` default); `LedgerService.database(settings, binding)` is
  database mode. `engine.ledger.service()` builds both from the context, and
  refuses a missing binding when `dsn` is set, a binding when it is not, and a
  missing layer directory. `LayerBinding()` without either field is refused.
- Pins traust-contracts 0.53.0 and traust-ledger 0.11.1 (traust-security/traust-ledger#83).
- Snapshot, single-path and file-mode guards from 0.20.0 are unchanged.

## [0.20.0]

## Changes

- **`LedgerService` database mode.** With `LAAS_BACKEND_TYPE=db` and
  `LAAS_DATABASE_URL`, the Ledger database is the authority: the run is bound to
  one layer (`TRAUST_LEDGER_LAYER_ID` and/or `TRAUST_LEDGER_PRODUCT_REPO_ID`, an
  explicit ID must belong to the owner), every read and write goes to it, and
  the layer file becomes a read-only snapshot re-exported after each read and
  write. Countersigns written to the database out of band (e.g. from SCI) are
  visible to the next read. Database mode never creates a layer and never
  falls back to the file; a missing URL or binding fails the call.
- **Database-mode guards.** One service binds one layer *and* one snapshot
  path; a second path is refused instead of reading or writing the bound
  layer under another repo's name. Each snapshot carries a read-only
  `<layer>.snapshot` marker (layer ID, Merkle root/size, export time), and
  file mode refuses to write or initialize a marked file, so a process that
  lost the database environment cannot fork the ledger on disk. An unchanged
  snapshot is not rewritten (mtime and git status stay meaningful). If a
  committed write's snapshot refresh fails, the stale snapshot is removed
  and the call does not raise. A missing layer says who creates it. Binding
  and export are logged (`traust_engine.ledger.service`, INFO; never the DSN).
- `LedgerService.write_snapshot`, `LedgerService.layer_id_for`,
  `LedgerOps.pull`, and `LayerBinding` (exported from `traust_engine.ledger`).
- File mode is unchanged and now pins `backend_type="file"`, so a stray
  environment cannot switch backends silently.
- **Migration always imports layers into the Ledger.** `migrate_cli` imports
  selected layer artifacts into `traust_ledger` in the same migration database
  after artifact reconciliation (SQLite file or the PostgreSQL DSN); layers are
  never routed to artifact storage. `--layer-destination`,
  `--ledger-target-url-env` and their config keys are removed, `make migrate-*`
  installs the `ledger-migration` extra, and local `migration.yaml` is
  gitignored.
- Pins traust-ledger 0.11.0 (`get_layer`/`find_layer`, traust-ledger#82) and
  traust-contracts 0.52.0, both from `traust-security`.

## [0.19.3]

## Changes

- Record projection rows as contracts writes them, reject dropped rows by rowcount, and
  verify evidence, bindings and projection values in one bulk pass at reconciliation
  instead of re-projecting and reading back each artifact.
- Replace the SQLite and PostgreSQL rehearsal databases with one `MigrationTarget`.
- Share one database-free resolve step between preview and load; record per-phase timing.
- Type migration decisions and plans; migration modules pass `mypy --strict`.

## [0.19.2]

## Changes

- Add bounded, opt-in spawned validation processes while retaining deterministic
  decisions and ordered single-connection database writes.
- Index directory ownership, cache exact repository registrations and prepared
  bindings, and avoid repeating schema validation for hash-verified bytes.
- Expose validation/registration phase progress and exclude derived PostgreSQL
  views from physical projection counts during final reconciliation.

## [0.19.1]

## Changes

- Add opt-in `migration.multi_ref_policy: newest` for unqualified companion
  ownership. Rank recorded baseline audit dates, preserve explicit branches,
  block cross-ref ties and missing dates, and record the selected audit/ref.
- Do not reassign historical reports, triages or Ledger histories to a newer
  branch without an exact baseline binding. Default ambiguity handling is unchanged.

## [0.19.0]

## Changes

- Import filesystem product/repo/ref relationships into the contracts 0.50.0 registry
  before ingesting artifacts; bind repository IDs and commit SHAs to evidence.
- Export ledger selections with product_repo IDs, or import them into a selected
  ledger target after storage reconciliation (`ledger-migration` extra).
- Pin traust-contracts 9e5e6605 and traust-ledger 5c326338; bootstrap fresh
  storage with `Store.migrate()`.

## [0.18.2]

## Changes

- **Fix:** `render` writes a threat model's update history inside section 7.
  It was written at the end of the document, which only fell inside section 7
  while nothing came after it. On an OWASP-rated model it landed in section 11,
  and lint rejected it.
- **Fix:** `render` writes an asset's optional `regulatory_scope` and
  `example_records` columns when any asset carries them; they were dropped.
- **Fix:** attack-scenario steps render as prose paragraphs, as `schema.md`
  section 9 specifies, instead of bullets.
- traust-contracts 0.47.0 (every threat-model section defined) and
  traust-ledger 0.8.5.

## [0.18.1]

## Changes

- traust-contracts v0.46.0 (OWASP risk ratings in the storage `threat` table)
  and traust-ledger 0.8.4. Ingesting a rated threat model now fills the
  threat `severity`, score, level and basis columns. Nothing else changes.

## [0.18.0]

## Changes

- **Threat models rated with the OWASP Risk Rating Methodology.** Pins
  traust-contracts v0.45.0, whose threat schema adds `risk_rating`, and
  traust-ledger 0.8.3 (the same contracts pin). The arithmetic stays in
  `traust_contracts.v1.risk_rating`. The new `reporting/threat_rating.py` owns
  how a rating is written in Markdown and read back:
  - `render` gives a rated model `severity | likelihood | impact` columns
    (`high | medium 4.375 | high 7.25 technical`) and a section 11,
    "Risk ratings", with every factor score and its reason. A threat not yet
    re-rated shows `unrated | legacy <label> | legacy <label>`. Legacy models
    render exactly as before.
  - `lint` accepts the rated variant. It checks that each level matches its
    score and that severity follows from the levels, and it recomputes every
    rating from its section 11 factors.
  - `validate` rejects a threat-model JSON whose rating scores, levels or
    severity disagree with its factors, which a JSON Schema can't express.
  - `corpus.threat_model.parse_threats` returns `severity` and
    `severity_source`, plus the scores and basis for rated rows. It drops the
    home-grown `score` (impact weight × likelihood weight).
  - Legacy labels are ordered on the OWASP table by a fixed crosswalk until
    each model is re-rated. The crosswalk is used only for ordering, is never
    written back as a rating, and is reported as
    `severity_source: legacy-crosswalk`.

## [0.17.0]

## Changes

- **`locations.analysis_results` chooses where reports live.** A path or
  `file://` stays on local disk; an `s3://` / `gs://` URI goes through fsspec
  (`traust-engine[s3]` / `[gcs]`, configured by the existing `HARNESS_S3_*`
  env). New `report_store.open_backend(location)` picks the backend and
  `FsspecBackend` implements it; `engine.corpus.report_store()` and
  `corpus.precedent` use it instead of hard-coding `LocalBackend`.
  `storage.filesystem(uri)` is public, and a missing scheme driver is a
  `StorageError` naming the extra rather than fsspec's `ImportError`.
- Remote `analysis_results` covers verified reads and writes through
  `ReportStore`; ingest and resolution still walk a local tree.
- `FsspecBackend` failures are `StorageError`, never "absent": `exists()` no
  longer returns `False` on bad credentials or an unreachable endpoint,
  `list()` wraps backend errors, and a missing bucket fails at construction
  instead of reading as "report not found". Only writable schemes (`s3`,
  `gs`/`gcs`, `az`/`abfs`) are accepted as a report location; `http(s)://` is
  refused up front. `SoundnessResolver` refuses a remote `analysis_results`
  (precedent resolution is local-only) instead of treating `s3://b/p` as a
  local folder.
- Pins: traust-contracts 0.44.0 (from 0.35.0), traust-ledger 0.8.2 (from
  0.6.32). 0.8.2 makes `LedgerClient.restate()` usable in-process (0.8.0/0.8.1
  always refused it) and pins SDK OIDC verification to the configured issuer.
- **`LedgerService.restate()`**: the only way to overwrite a signed
  `claim_hashes` / `audit_report_sha256` / `artifact_digests` value. The prior
  value, verified actor, ticket and rationale are recorded in the layer.
  `patch_layer_file` still does first writes and new keys only.
- `LedgerService.stamp_report_file()` pins `audit_report_sha256` once and
  returns `False` when it's unchanged. It refuses to overwrite a different
  pinned digest (use `restate`) instead of re-patching unconditionally, which
  ledger ≥0.8 refuses mid-write.
- **Consumers: ledger writes now need a verifiable identity.** Ledger ≥0.7
  verifies the actor before `sign()` / `patch_metadata()` /
  `stamp_event_identities()`, so a placeholder token (`token="test-token"`)
  is refused. Configure OIDC (`LEDGER_OIDC_ISSUER` / `LEDGER_OIDC_JWKS_URL`)
  or local auth (`LEDGER_LOCAL_IDENTITY`, or `ledger auth local`); test
  suites can set `LEDGER_LOCAL_IDENTITY` in an isolated `HOME`. Ledger 0.8
  also refuses to sign a layer without an initialized shell (`audit_report`,
  `repository`, `created`, `harness_version`). `finding_identity.rebaseline`
  is unchanged; its tests now supply a verifier, a complete layer shell, and
  sha256-shaped claim hashes.

## [0.3.0]

## Changes

- **Reverted the 0.15.0 findings.db changes.** `findings_db` builds the
  previous nine-table projection again (`SCHEMA_REVISION` 3), `store_ingest`
  and the SLA view are as in 0.13.3. Pins: contracts 0.35.0 (the 0.33.0
  storage contract), ledger 0.6.32. 0.15.0 remains tagged and should not be
  pinned.

## [0.2.5]

- Pin traust-contracts v0.5.0 (evidence projection + postgres storage
  namespace) and traust-ledger v0.3.0 (stamp + whoami over REST).

## [0.2.4]

- Point the traust-contracts and traust-ledger pins at the new
  `traust-security` GitHub organisation (ledger v0.2.3, which carries the
  corrected URL inside its own tag).

## [0.2.3]

- Pin traust-contracts v0.4.0 and traust-ledger v0.2.2, carrying the typed
  patch-evidence block on the VERIFICATION family through to the report
  validator. No engine logic changes: `reporting/validate.py` validates
  against the pinned schema, so accepting the block on a verification report
  is a consequence of the pin.

## [0.2.2]

- Pin traust-contracts v0.3.0 and traust-ledger v0.2.1, carrying the optional
  `evidence[]` block on remediation reports through to the report validator.
  No engine logic changes: `reporting/validate.py` validates against the
  pinned schema, so accepting the block is a consequence of the pin. The
  existing cross-check tying `summary.status == 'revalidated_fixed'` to
  `revalidation.fixed` is untouched, since no status depends on `evidence[]`
  yet.

## [0.2.0]

## Changes

- delegate countersign/whoami/stamp_event_identities to the engine

## [0.1.1]

## Changes

- Adopt traust-contracts 0.1.1 and traust-ledger 0.1.1, which enforce RFC
  3339 on `LayerEvent.recorded_at` / `.occurred_at`. No engine code changes
  were needed — dependency pins only.

### Upgrading

Contracts 0.1.1 validates timestamps on read as well as write, so a corpus
holding non-conforming values must be migrated before this release is used
against it (`python3 -m traust.migrations.fix_event_timestamps <root>
--apply`). `traust_engine.reporting.validate` also asserts `format:
date-time` now that the format assertor ships as a declared dependency.

## [0.1.0]

Self-contained processing library for Traust: deterministic workflow code
for disposition merge, validation gates, and rule calibration — the
`traust_engine` package consumed by the app CLI and other components.
