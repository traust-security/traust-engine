# Changelog

All notable changes to traust-engine are documented here.

## [0.3.0]

## Changes

- **`findings.db` is storage/v1 on SQLite.** `traust_engine.corpus.findings_db`
  builds the contract's tables and views (`Store.init()` at the installed
  storage `REVISION`) and populates them through `store_ingest` from the same
  corpus resolution `/census` counts. The legacy `findings`, `events`,
  `validations` and `impact` tables and the `v_open`, `v_hardening` and
  `v_distinct_owned` views are gone; their contract homes are `report_finding`,
  `layer_event`, `validation_finding`, `impact_repo` and `open_findings`,
  `hardening_findings`, `distinct_exposure`, read through `current_finding`
  with `subject_id` as the repo key. Only `repos`, `graph_edges`, `provenance`,
  `decisions` and `meta` remain harness-defined (dashboard plan, C1).
  `SCHEMA_REVISION` 3 → 4; a reader on 3 is refused.

  The build writes to a sibling `.building` file and renames it into place, so
  a reader never sees a half-populated store. `meta` records the ingest
  outcome (`ingest_rejected`, `ingest_reasons`, `ingest_by_family`): an
  artifact the contract refuses is absent from every contract table, and the
  projection says so rather than quietly projecting fewer findings.

- **One `repo_key`.** `store_ingest.repo_key` suffixes every non-default
  report kind, as `findings_db` always did; the two disagreed on
  container-audit subjects, whose `repos` row and `subject_ownership` row
  therefore never joined. `findings_db.repo_key` is the same function.

- **Layer bindings carry their subject.** `store_ingest` binds a ledger layer
  with `subject_id` as well as `layer_id`, so `layer_event` joins to a repo
  through `artifact_binding` rather than by parsing the layer id. The corpus
  registry now declares each subject's `report_kind`.

- **The SLA view reads the contract.** `metrics.sla.build_view` reads
  `layer_event` and `current_finding` (with `cvss_score`), and its
  routed-or-filed and resolving source types come from the enums: the previous
  lists named four source types and one resolution that exist in no enum, so
  the "filed" clock rung could never fire. It fires now, matching the
  `finding_timeline` view's definition.

### Upgrading

Contracts 0.34.0 (storage `REVISION` 16). Rebuild `findings.db`
(`traust corpus findings-db`); the build now takes minutes and the file is
several GB because the store retains exact artifact evidence, as the contract
specifies.

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
