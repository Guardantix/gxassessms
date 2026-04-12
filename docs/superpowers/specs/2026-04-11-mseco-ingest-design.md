# `mseco ingest` — Client-Provided Raw Output Ingestion

**Date:** 2026-04-11
**Issue:** Guardantix/gxassessms#78
**Status:** Design approved; implementation plan pending

## Problem

The runbook at `docs/runbook.md` documents a "Client-Provided Pre-Collected Output Ingestion" scenario (section 3) for engagements where the client refuses to grant assessment-tool credentials and instead sends their own pre-collected ScubaGear / Maester / Monkey365 output. The scenario as written is not executable with the current CLI:

- `mseco replay` reads `RawToolOutput` JSON manifests from `<engagement_dir>/raw-output/manifests/<slug>.json`.
- These manifests contain structured metadata (tool slug, schema version, manifest version, `file_manifest` with canonical POSIX paths and per-file sha256, execution metadata) that cannot be hand-crafted by an operator from a folder of client files.
- There is currently no command to bootstrap that manifest structure from operator-provided files. The "copy files and replay" path in the runbook silently fails with a missing-manifest error.

This spec defines `mseco ingest`, the command that closes that gap.

## Goals

1. Allow operators to take an operator-provided directory of raw tool output and produce a valid `RawToolOutput` manifest + `raw-output/artifacts/<slug>/` layout such that `mseco replay <id> --from parse` works as documented in runbook section 3.
2. Apply to **5 of the 7 collection-capable built-in adapters**: ScubaGear, Maester, Prowler, Azure Advisor, Secure Score. Monkey365 and M365-Assess are deliberately excluded; see Non-goals for the rationale.
3. Record unambiguous audit provenance distinguishing ingested manifests from live-collected ones, at the manifest level, so reviews months later can tell how the data arrived.
4. Preserve the `save_raw_outputs()` / replay trust boundary: ingest is a write-side convenience, not a relaxation of replay's read-side validation.
5. Update runbook scenario 3 to reference the new command for the 5 supported adapters and clearly document that Monkey365 and M365-Assess ingest require a follow-up design.

## Non-goals

- **Ingesting from a `raw-output.tar.gz` archive** — covered by the existing archive/restore path; out of scope here.
- **Multi-tool ingest in a single invocation** — one `--tool` per call; operators run it 3× for a 3-tool engagement. Keeps the error surface tight.
- **Ingest support for Monkey365 and M365-Assess.** Both adapters' live `collect()` methods rely on pre-run filesystem snapshots to filter out stale files from prior runs: Monkey365 captures an `existing_files` set at `monkey365/adapter.py:130`, and M365-Assess captures a `pre_run_state` mtime+size dict at `m365_assess/adapter.py:211-219`. Ingest has no "before" snapshot to filter against. A naive ingest implementation for these adapters would silently merge stale and current files from the operator's source directory into a single manifest, producing wrong or duplicated findings with no error surfaced. We deliberately ship ingest without these two adapters rather than with a known silent-data-corruption failure mode. Monkey365 and M365-Assess ingest is deferred to a follow-up issue where the freshness-ambiguity problem is solved with a proper design (operator-supplied file lists, timestamp-grouped validation, or a "single-run export" adapter contract). Parity tests for the `build_collection_output` refactor still cover all 7 adapters; the scope reduction applies only to the new `ingest_from_directory()` code path.
- **Stricter ingest-time discovery than live collect for the 5 supported adapters** — ingest inherits each supported adapter's pick-first-match and other quirks verbatim. See Section 3.2 for the UX tradeoff.
- **Propagating `source_mode` into `ResolvedManifest` / reports** — collected vs. ingested is recorded on `RawToolOutput` at the storage layer, but the pipeline-internal `ResolvedManifest` does not carry the distinction. If reports need to surface it later, that's a follow-up.
- **Write-side canonical path enforcement for `raw-output/`** — a broader pre-existing repo concern, not introduced by ingest.

## Architecture overview

`mseco ingest` is an operator-driven, filesystem-only command. It does not invoke any tool, authenticate to any tenant, or fetch data over the network. Its job is to accept a directory of client-provided raw output, hash the files, build the `RawToolOutput` manifest the replay machinery needs, commit it atomically alongside any existing data in the engagement directory, and reset the engagement state so downstream pipeline stages know the raw output is fresh.

The design has seven coordinated pieces across the layers:

1. **Engagement bootstrap fix** (`cli/commands/engagement.py`): `mseco engagement create` is extended to provision the on-disk engagement directory AND write the `config_snapshot.json` mirror immediately after inserting the DB row, with an orphan-row rollback if filesystem provisioning fails. This is the foundation that lets ingest-only engagements work end-to-end and is the single place where the replay DR snapshot path gets seeded for both collect and ingest workflows.
2. **Data model** (`core/domain/models.py`, `core/domain/constants.py`): two new optional fields on `RawToolOutput` plus a new `IngestProvenance` model, gated by a `manifest_version` bump from `"1.0.0"` to `"1.1.0"` that preserves backward-read compatibility for existing engagements on disk.
3. **Shared adapter helper** (`adapters/_base.py`): new module-level `build_collection_output()` that hashes a pre-computed list of `(source_path, target_relpath)` pairs and assembles a `CollectionOutput`. Used by both live `collect()` and the new ingest path. Discovery and freshness filtering stay in each adapter's `collect()` exactly as today.
4. **Per-adapter ingest method** (`adapters/<tool>/adapter.py`): new `ingest_from_directory()` method on **5 of the 7** adapters (ScubaGear, Maester, Prowler, Azure Advisor, Secure Score), implementing the same file-walk logic as live collect. Monkey365 and M365-Assess are explicitly excluded per Non-goals — their freshness-dependent discovery makes directory-based ingest unsafe without a follow-up design.
5. **Protocol extension** (`core/contracts/types.py`): new `IngestCapableAdapter(ToolAdapter, Protocol)` adding `ingest_from_directory()` and a `default_schema_version: str` class attribute, plus an `"ingest"` entry in `AdapterCapability`.
6. **Persistence layer** (`persistence/artifacts.py`): new `save_ingested_raw_output()` method on `ArtifactManager`, providing atomic single-slug writes (unlike the existing full-generation-swap `save_raw_outputs()`), fail-closed on missing engagement directory for the normal path, with a narrow legacy-migration fallback that auto-provisions for engagements created before this PR, and a per-side rollback on commit failure.
7. **CLI command** (`cli/commands/ingest.py`, `cli/main.py`, `cli/_helpers.py`, `pipeline/orchestrator.py`, `pipeline/state.py`): the `mseco ingest` Click command, new canonical helpers (`resolve_enabled_adapter`, `require_ingest_capable`, `get_engagement_lock`), a new `"raw_output_ingested"` `EventType` variant and public `record_raw_output_ingested` orchestrator wrapper, and state reset via `reset_for_rerun(Stage.PARSE)` ordered **before** the filesystem commit so any commit failure leaves the engagement in a cleanly retryable state.

## Section 1: End-to-end flow

**Bootstrap precondition (new, from the engagement create fix in Section 1a):** After `mseco engagement create` succeeds, the engagement has (a) a DB row, (b) an on-disk `<engagement_dir>/` with `raw-output/manifests/`, `raw-output/artifacts/`, and `reports/` subdirectories, and (c) a `<engagement_dir>/config_snapshot.json` mirror that `replay` can use for DR recovery. Ingest assumes this precondition and does not re-provision it on the normal path; a narrow legacy-migration fallback in `save_ingested_raw_output` handles engagements created before this PR.

The flow below is the **normal path** (when `--repair-event` is NOT set). The repair-event dispatch takes a different, much narrower path documented in Section 5.5b: it skips steps 5-9 entirely, reads committed provenance from the manifest on disk, and emits only the missing `raw_output_ingested` event. The repair path is audit-neutral — it does not touch any filesystem state or engagement state.

```
1. CLI arg validation (before any I/O)
   - engagement_id matches ENGAGEMENT_ID_PATTERN (same gate as replay)
   - --tool is a non-empty string (further checked in step 4)
   - --repair-event validation: if set, --from/--replace/--schema-version/--run-at
     must all be absent; if any is present, click.UsageError with exit 1.
   - --from path exists, is a directory, is not a symlink, is readable
     (required unless --repair-event is set)
   - --schema-version (if passed): non-empty, no control chars, <= 64 chars
   - --run-at (if passed): parseable via parse_utc (handles Z, +00:00, naive-as-UTC)
   - --operator (if passed): sanitized for the PipelineEvent actor field
     (default: getpass.getuser(), fallback "unknown")

2. Engagement lookup (DB-required, NO filesystem fallback for config)
   - EngagementRepo.get(engagement_id): raises PersistenceError if missing.
   - EngagementConfig.model_validate(decode_config_snapshot(row)).
   - The CLI DELIBERATELY does NOT call ArtifactManager.get_engagement_dir()
     at this step. Calling it here would short-circuit the Section 4.2a
     legacy-migration path for pre-PR engagements, because get_engagement_dir()
     cannot distinguish the two missing-directory cases the design must
     handle differently:
       * (engagement_row['engagement_dir'] IS NULL, directory missing)
         -> legacy migration path (Section 4.2a). Must succeed.
       * (engagement_row['engagement_dir'] IS NOT NULL, directory missing)
         -> post-PR corruption. Must fail closed with an actionable error.
     Only the DB row's `engagement_dir` column can distinguish these cases.
     The loaded engagement_row dict is passed through to
     save_ingested_raw_output so the persistence layer runs the
     discriminator under the lock (Section 4.2a).

3. Adapter resolution
   - registry = discover_adapters()
   - adapter = resolve_enabled_adapter(tool_slug, registry, config)
     - raises click.UsageError on unknown slug or disabled-in-config
   - ingest_adapter = require_ingest_capable(adapter)
     - raises click.UsageError on missing "ingest" capability

4. Acquire engagement_lock.hold(engagement_id)
   --- EVERYTHING BELOW RUNS UNDER THE LOCK ---

5. Conflict check (inside the lock, avoids TOCTOU)
   - If raw-output/manifests/<slug>.json OR raw-output/artifacts/<slug>/ exists:
     - Without --replace: print error, exit 1
     - With --replace: proceed; the persistence layer (Section 4.2 Phase 1)
       re-probes under the same lock and sets IngestProvenance.replaced=True
       on the manifest it serializes. The CLI does NOT remember a local
       "replaced" value -- the canonical value is read back from the
       committed manifest when building the event payload (Section 5.5 step 6).

6. Adapter-owned ingest walk
   - collection_output = ingest_adapter.ingest_from_directory(
         source_dir, schema_version=..., timestamp=run_at,
     )
   - Internally walks the source directory (no freshness filtering) and calls
     build_collection_output() with execution_metadata={}

7. Pre-commit validate_raw (ingest-private preflight)
   - Build a throwaway ResolvedManifest pointing at absolute source_paths
   - ingest_adapter.validate_raw(preflight_manifest)
   - Any failure -> abort, release lock, exit 1, NOTHING written

8. DB state reset (ordered BEFORE filesystem commit, intentionally)
   - orchestrator.reset_for_rerun(engagement_id, Stage.PARSE)
     - Resets engagement state to COLLECTED (PARSE's entry state per
       stages.py:386). No-op when already at COLLECTED. Emits existing
       "rerun" event via the orchestrator's standard path.
   - Why this runs BEFORE the filesystem commit: if Step 9 (filesystem
     commit) fails and Section 4.3's per-side rollback restores the
     pre-call filesystem state, the engagement is left with (a) its
     original raw-output unchanged and (b) state reset to COLLECTED.
     That's a benign, idempotent, retryable state -- the operator just
     reruns ingest. By contrast, reversing the order (commit first,
     then reset) would leave a committed filesystem with stale DB state
     on DB failure, which is the DB/filesystem split-brain case Codex
     called out in the first adversarial review round (the reordering
     here is the fix for that finding).

9. Atomic single-slug filesystem commit
   - ArtifactManager.save_ingested_raw_output(
         engagement_id, collection_output,
         ingest_provenance=..., replace=...,
     )
   - Phase 1 validate, Phase 2 stage, Phase 3 atomic per-slug rename
   - Legacy migration: if the engagement dir is missing, save_ingested_raw_output
     provisions the dir AND mirrors config_snapshot.json from the DB via a
     narrow one-time path (see Section 4.2a)

10. Ingest event emission
    - orchestrator.record_raw_output_ingested(
          engagement_id=..., actor=f"human:{operator}",
          tool_slug=..., source_path=..., file_count=..., replaced=...,
      )
      - New public wrapper. Internally routes through _emit_event to write
        the new "raw_output_ingested" event with a typed payload.
    - This is the ONE step that can fail after the filesystem is committed.
      Recovery procedure is documented in Section 5.5a and the runbook.

11. Release lock (finally block)

12. Success output
    - Ingested file count, manifest path, next-step hint:
      "Run `mseco replay <id> --from parse` to process this data."
```

**Layering invariants:**

- **DB-required, no DR fallback for config.** Unlike `replay`, ingest has no disaster-recovery path that falls back to `config_snapshot.json` for reading config. If the engagement isn't in the DB, the operator runs `mseco engagement create` first. Ingest is a pre-normalization step, not a recovery tool. (But ingest DOES write the filesystem `config_snapshot.json` mirror on legacy migration, so that replay-after-DB-loss still works for ingest-only engagements — see Section 4.2a.)
- **Lock scope.** Conflict check, adapter walk, `validate_raw` preflight, DB state reset, atomic filesystem commit, and event emission all happen inside a single `engagement_lock.hold(engagement_id)` region. Other mutating commands (collect, replay, review UI plugins) are serialized against ingest via the same advisory filelock mechanism documented in runbook section 9.
- **DB writes bracket the filesystem commit.** State reset happens BEFORE the filesystem commit (idempotent and safely retryable if commit fails); event emission happens AFTER (the one failure mode that requires an explicit audit-neutral `--repair-event` recovery, documented in Section 5.5a/5.5b).
- **`validate_raw` is an ingest-private preflight**, not a weakening of the replay trust boundary. Replay still performs its own `confine_and_resolve()` + `validate_raw()` on read. Ingest just runs the check earlier so the operator finds out immediately whether the client's files are usable.
- **save_ingested_raw_output has a distinct contract from save_raw_outputs.** It writes only one slug, constructs the `RawToolOutput` internally with `source_mode="ingested"` (the one place in the codebase where that value is materialized), and fails closed on missing engagement dir unless the narrow legacy-migration condition applies (Section 4.2a).

## Section 1a: Engagement bootstrap fix

`mseco engagement create` today at `cli/commands/engagement.py:74-103` inserts a DB row but does not provision the on-disk engagement directory. That worked up to now because `save_raw_outputs()` at `persistence/artifacts.py:476` has a lazy fallback that calls `create_engagement_dir()` on first write. For ingest-only engagements, which may never call `save_raw_outputs()`, that lazy fallback was never going to fire — the happy path in runbook scenario 3 would immediately hit "engagement directory not found" on the first `mseco ingest` call.

The fix: `engagement create` provisions both halves at bootstrap time, populates the existing `engagements.engagement_dir` column with the resolved path, and uses a new strict variant of the config-snapshot mirror helper so failures actually propagate into the rollback path.

### 1a.1 New strict mirror helper

The existing public `mirror_config_snapshot_from_db(engagement_repo, artifact_manager, engagement_id)` at `pipeline/config_snapshot_mirror.py:28-61` is deliberately **fail-open** — it catches `ConfigSnapshotMirrorError` and `Exception` and logs at ERROR level, returning normally so collect's pipeline is never blocked by a DR-gap on mirror failure. That fail-open contract is exactly what `_runner.py:84-97` wants for its existing caller and must not change.

Bootstrap rollback needs the opposite contract: a mirror failure must propagate so the rollback path can fire. Add a new public function in the same module:

```python
def mirror_config_snapshot_from_db_strict(
    engagement_repo: EngagementRepo,
    artifact_manager: ArtifactManager,
    engagement_id: str,
) -> None:
    """Strict variant of mirror_config_snapshot_from_db.

    Unlike the fail-open public wrapper used by collect's runner, this
    variant raises ConfigSnapshotMirrorError on any failure. Used by:
      - mseco engagement create (bootstrap) -- the caller rolls back
        the DB row and filesystem directory on failure.
      - save_ingested_raw_output's legacy-migration path -- the caller
        aborts the ingest before any raw output is written.

    Implementation delegates to the existing _do_mirror() internal at
    pipeline/config_snapshot_mirror.py:64, which already raises typed
    errors. No new mirroring logic -- just a second entry point with a
    different error-handling contract.
    """
    from gxassessms.pipeline.config_snapshot_mirror import _do_mirror
    _do_mirror(engagement_repo, artifact_manager, engagement_id)
```

(If `_do_mirror` is deemed too private to call across module boundaries, alternatively promote it to a public name like `_mirror_config_snapshot_core` and have both the fail-open and strict wrappers call it. Implementation plan decides the naming; the shape is a new-public strict wrapper + unchanged-public fail-open wrapper sharing one inner body.)

### 1a.2 New behavior of `mseco engagement create`

Prerequisite: `EngagementRepo.create()` gets a new additive keyword argument (detailed in Section 1a.6). Today, `create()` at `engagement_repo.py:72-101` generates its own UUID internally, so the CLI cannot pre-compute the engagement directory path before inserting the row — the UUID doesn't exist until `create()` returns. The additive `engagement_id: str | None = None` parameter lets the CLI pre-generate the UUID when it needs an atomic bootstrap flow, while preserving today's auto-generate behavior for all other callers.

With that prerequisite in place, the new bootstrap flow is:

1. Validate the config file (unchanged from today).
2. **NEW:** CLI pre-generates the engagement identity so the row and the directory can be committed atomically:
    - (a) Generate `engagement_id = str(uuid.uuid4())` at the CLI layer.
    - (b) Compute the target directory path using the same `_sanitize_slug(client_name)-<engagement_id>` logic `artifacts.py:158` uses (expose the slug helper or duplicate the one-liner — implementation plan decides).
    - (c) Insert the DB row via `EngagementRepo.create(client_name, tenant_id, config_snapshot, engagement_id=<pre-generated>, engagement_dir=<computed path as str>)`. Both new kwargs populated. The row now claims `engagement_dir=<path>` but the directory does not yet exist on disk.
    - (d) Call `artifact_manager.create_engagement_dir(engagement_id, client_name)` to materialize the directory tree on disk. This method uses the same path computation as (b), so the resolved path MUST match the value stored in (c). The implementation plan should either have both sides call a single shared helper, or add a post-create assertion that the returned path equals the pre-stored value — drift here would silently break the `engagement_dir IS NOT NULL` discriminator.
3. **NEW:** Call `mirror_config_snapshot_from_db_strict(engagement_repo, artifact_manager, engagement_id)` to write `<engagement_dir>/config_snapshot.json`. Strict, not fail-open, so the rollback path actually fires on mirror failure.
4. **NEW orphan-row + orphan-directory rollback:** If step (c), (d), or 3 fails, the rollback must:
    1. Best-effort `shutil.rmtree(engagement_dir, ignore_errors=True)` — clean up any partially-created directory tree. Skipped if the directory was never created (step (c) or earlier failed).
    2. `engagement_repo.delete(engagement_id)` — removes the row from `engagements` and all child tables in dependency order, using the existing method at `engagement_repo.py:237`. No new delete helper needed. Only runs if step (c) succeeded (the row actually exists).
    3. Re-raise as a `GxAssessError` with a message that names which step failed.
    The user sees a single clean error. A crash between steps (c) and (d)/3 that escapes the rollback (e.g., SIGKILL) can leave a DB row whose `engagement_dir` column points at a nonexistent directory. That state is indistinguishable from post-PR filesystem corruption and is handled by the Section 4.2a "post-PR corruption" branch, which fails closed and names `mseco engagement purge` as the recovery. The bootstrap flow's rollback covers the programmatic-failure case; the "post-PR corruption" branch covers the crash-during-bootstrap case.

### 1a.3 Populating `engagements.engagement_dir`

The `engagements.engagement_dir` column already exists in the schema at `persistence/migrations/001_initial.sql:18` and `EngagementRepo.create()` at `engagement_repo.py:77` already accepts an optional `engagement_dir` parameter. Today every caller passes `engagement_dir=None` (the column is always NULL on existing rows). The bootstrap fix starts populating it with the resolved absolute path as a string.

This is more than cleanup — the populated column becomes the **legacy-vs-post-PR discriminator** that Section 4.2a uses. After this PR:

- `engagement_dir IS NULL` in the DB row → legacy, created before this PR, no on-disk directory ever provisioned → the Section 4.2a migration path runs on first ingest.
- `engagement_dir IS NOT NULL` in the DB row → post-PR, directory was provisioned at bootstrap → if `get_engagement_dir()` now raises, that's real filesystem corruption or manual deletion, and `save_ingested_raw_output` fails closed.

No new column, no new migration, no new marker field — just start maintaining a column the schema already provides.

### 1a.4 Why this fixes Codex Findings 1 and 2

- **Finding 1** (fresh ingest-only engagements cannot work): after this change, `mseco engagement create` → `mseco ingest` is a working sequence for new engagements, because the directory is created at step (d) above and `ingest` then writes into it.
- **Finding 2** (ingest-only engagements lose replay DR): after this change, every engagement — collect-only, ingest-only, or mixed — has a `<engagement_dir>/config_snapshot.json` mirror from bootstrap onward. Replay's existing DR-fallback code at `cli/commands/replay.py:60-125` works uniformly regardless of which write path last touched the engagement. The existing fail-open `mirror_config_snapshot_from_db()` call in collect's pipeline runner at `_runner.py:84-97` stays as a defense-in-depth refresh, but it's no longer the sole path and no longer the only write site.

### 1a.5 Files changed

- `cli/commands/engagement.py` — `create_cmd` gets the new provision + mirror + rollback logic. Estimated ~30 lines of additional code (the rollback logic is the bulk of it, plus the pre-generated UUID and path computation).
- `persistence/engagement_repo.py` — `EngagementRepo.create()` gets an additive `engagement_id: str | None = None` kwarg. When None, the method generates a UUID as today; when provided, it uses the caller's value. Backward-compatible: all existing callers pass None (explicitly or by omission) and see no behavior change. Estimated ~5 lines including the docstring note.
- `pipeline/config_snapshot_mirror.py` — new `mirror_config_snapshot_from_db_strict()` public function. Estimated ~10 lines (thin wrapper over the existing `_do_mirror`). Per Rick's implementation caveat: the existing fail-open `mirror_config_snapshot_from_db()` stays **exactly as-is** for its existing caller in `_runner.py:84-97`; the strict variant is an additive new public function, not a contract change on the existing one.

### 1a.6 What this does NOT change

- The lazy `save_raw_outputs` fallback at `artifacts.py:476` stays in place as-is. It's belt-and-suspenders for any write path that hits a missing-dir condition (which should now be impossible for freshly-created engagements but is still the safety net for legacy engagements that haven't hit their first write yet).
- Collect's fail-open `mirror_config_snapshot_from_db()` call at `_runner.py:84-97` stays in place with its existing signature and fail-open contract. It refreshes the mirror after every successful collect, which is the right behavior when the DB config changes between runs and when a mirror gap shouldn't block the pipeline. The strict variant from Section 1a.1 is additive, not a replacement.
- `EngagementRepo.create()`'s existing parameters are unchanged. The new `engagement_id` kwarg is additive and optional; all existing callers (zero-argument pass-through) keep their current behavior and return value semantics.
- The non-ingest path `engagement status` → `engagement create` → `engagement status` gets marginally different output (the second `status` call sees a directory that didn't exist before), but this is benign and not tested behavior today.

## Section 2: Data model changes

### 2.1 New `IngestProvenance` model

```python
class IngestProvenance(BaseModel):
    """Operator-visible provenance for ingested raw output.

    Present only on manifests written by `mseco ingest`. Records what the
    operator did, when they did it, and where the source data came from --
    enough audit trail to answer "where did this data come from" six months
    after the engagement, and enough to reconstruct the raw_output_ingested
    event payload during an audit-neutral repair (see Section 5.5a/5.5b).
    """

    model_config = ConfigDict(extra="forbid")

    source_path: str  # absolute path the operator passed to --from
    ingested_at: datetime  # UTC timestamp of the ingest call (NOT the tool run time)
    ingested_by: str  # PipelineEvent actor convention: "human:<operator>"
    replaced: bool  # True iff this ingest overwrote prior raw output for this slug

    @field_validator("ingested_at")
    @classmethod
    def ingested_at_must_be_utc(cls, v: datetime) -> datetime:
        return ensure_utc(v)

    @field_validator("source_path")
    @classmethod
    def source_path_must_be_absolute_and_sane(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("source_path must be non-empty")
        if len(stripped) > 4096:
            raise ValueError("source_path must not exceed 4096 characters")
        if not Path(stripped).is_absolute():
            raise ValueError(f"source_path must be absolute: {stripped!r}")
        return stripped

    @field_validator("ingested_by")
    @classmethod
    def ingested_by_must_be_human(cls, v: str) -> str:
        # Manifest ingest is human-driven; automated ingest is not a use case
        # for this feature. PipelineEvent.actor can stay broader for other
        # event types.
        if not v.startswith("human:") or len(v) <= len("human:"):
            raise ValueError(
                f"ingested_by must be 'human:<operator>' (manifest ingest is "
                f"a human-driven operation), got {v!r}"
            )
        return v
```

Key semantic: `ingested_at` is the **ingest call timestamp**, distinct from `RawToolOutput.timestamp` which is the **tool run timestamp** (operator-supplied via `--run-at` or defaulted to `utc_now()` at ingest time when unknown). Conflating them would erase the "client ran the tool last Tuesday; we ingested it today" distinction that matters for report assessment dates.

Key semantic for `replaced`: this is the **committed audit record** of whether this ingest overwrote prior raw output for the same slug. The persistence layer is the single source of truth — it sets this field based on what was actually replaced at commit time, not what the operator intended with `--replace`. Operators who pass `--replace` against a slug with no prior data still get `replaced=False` in the committed manifest (because nothing was actually replaced). This makes `replaced` a reliable input to the `--repair-event` recovery path (Section 5.5a/5.5b), which reconstructs the missing `raw_output_ingested` event payload from committed provenance without rewriting manifest bytes.

### 2.2 Two new optional fields on `RawToolOutput`

```python
class RawToolOutput(BaseModel):
    """On-disk replay manifest. POSIX-relative canonical paths."""

    model_config = ConfigDict(extra="forbid")

    # ... existing fields (tool, tool_slug, schema_version, manifest_version,
    #     timestamp, file_manifest, execution_metadata) unchanged ...

    # NEW fields (added at the end to minimize diff noise in existing tests)
    source_mode: Literal["collected", "ingested"] = "collected"
    ingest_provenance: IngestProvenance | None = None

    @model_validator(mode="after")
    def source_mode_matches_provenance(self) -> RawToolOutput:
        """source_mode and ingest_provenance must agree (bidirectional)."""
        if self.source_mode == "ingested" and self.ingest_provenance is None:
            raise ValueError(
                "source_mode='ingested' requires ingest_provenance to be set"
            )
        if self.source_mode == "collected" and self.ingest_provenance is not None:
            raise ValueError(
                "source_mode='collected' must not carry ingest_provenance"
            )
        return self
```

**Why defaults on both fields:** Existing `"1.0.0"` manifests on disk have neither field. With defaults, Pydantic validation succeeds on read — `source_mode` defaults to `"collected"` (semantically correct: those manifests came from live `collect()` calls) and `ingest_provenance` defaults to `None`. No migration needed for engagements in the field.

### 2.3 Constants file changes (`core/domain/constants.py`)

Surgical edits:

```python
# Line 149: extend the Literal
ManifestVersion = Literal["1.0.0", "1.1.0"]

# Line 151: bump the current version
MANIFEST_VERSION_CURRENT: str = "1.1.0"

# Line 153: extend the recognized set
RECOGNIZED_MANIFEST_VERSIONS: frozenset[str] = frozenset({"1.0.0", "1.1.0"})

# Line 165: add a 1.1.0 entry to the allowlist, identical per-tool key sets
EXECUTION_METADATA_ALLOWLIST: dict[str, dict[str, frozenset[str]]] = {
    "1.0.0": {
        "scubagear": frozenset({"modules", "module_provenance"}),
        "maester": frozenset({"module_provenance"}),
        "monkey365": frozenset({"output_dir", "module_provenance"}),
        "m365-assess": frozenset({"script", "tenant_id", "controls_dir"}),
        "prowler": frozenset({"output_dir", "auth_method", "checks"}),
        "azure-advisor": frozenset({"recommendation_count"}),
        "secure-score": frozenset({"profiles_count", "scores_count"}),
    },
    "1.1.0": {  # NEW — same per-tool keys; no ingest keys here because
                # ingest provenance lives at RawToolOutput top level
        "scubagear": frozenset({"modules", "module_provenance"}),
        "maester": frozenset({"module_provenance"}),
        "monkey365": frozenset({"output_dir", "module_provenance"}),
        "m365-assess": frozenset({"script", "tenant_id", "controls_dir"}),
        "prowler": frozenset({"output_dir", "auth_method", "checks"}),
        "azure-advisor": frozenset({"recommendation_count"}),
        "secure-score": frozenset({"profiles_count", "scores_count"}),
    },
}
```

The 1.0.0 and 1.1.0 entries are deliberately duplicated rather than sharing a single dict: future additions to 1.2.0 should not silently leak backward to 1.0.0/1.1.0 via a shared reference. Explicit duplication costs ~7 lines and eliminates an entire class of version-drift bugs.

### 2.4 Version flow through existing code

- **`persistence/artifacts.py:468,575`**: `save_raw_outputs` imports `MANIFEST_VERSION_CURRENT` and uses it unconditionally. After the bump it writes `"1.1.0"` on every new manifest. One additional change at the `RawToolOutput(...)` construction around line 602: explicitly set `source_mode="collected"` for clarity (the default would work, but being explicit pins intent).
- **`pipeline/confinement.py:95`**: the manifest version gate uses `RECOGNIZED_MANIFEST_VERSIONS` from constants. After the frozenset is extended, both 1.0.0 and 1.1.0 manifests pass the gate with zero code changes.
- **`pipeline/confinement.py:328`**: `ResolvedManifest(..., manifest_version=raw.manifest_version, ...)` preserves whichever version was on the source manifest.
- **`ResolvedManifest` does NOT get the new fields.** It's a pipeline-internal object that's never serialized back to disk; it doesn't need `source_mode` or `ingest_provenance` to do its job. Keeping the new fields on `RawToolOutput` only narrows the blast radius of the schema change.

### 2.5 Backward compatibility guarantees

1. **Read-compat**: Any `"1.0.0"` manifest on disk today loads successfully via `RawToolOutput.model_validate_json()` after these changes, with `source_mode="collected"` and `ingest_provenance=None` applied as defaults.
2. **Model-semantic round-trip**: A `"1.0.0"` manifest loaded via `model_validate_json()` and re-dumped via `model_dump_json()` produces a byte string that is **not** byte-identical to the original (the new fields serialize as `"source_mode": "collected", "ingest_provenance": null`) but reparsing yields a `RawToolOutput` model that is `==` to the originally-loaded one. `manifest_version` stays `"1.0.0"` on reload (it reflects the source manifest's version, not `MANIFEST_VERSION_CURRENT`), so the existing `save_raw_outputs` code path does not silently upgrade on-disk manifests.
3. **Replay-compat**: `load_raw_outputs()` + `confine_and_resolve()` + adapter `validate_raw()` produce the same `ResolvedManifest` for a 1.0.0 manifest as they did before this PR.

Deliberate non-goal: we do **not** attempt to retrofit ingested status onto pre-1.1.0 manifests. If an engagement was created and raw output was ingested before this feature existed (via the undocumented manual-manifest-construction workaround in the current runbook), it will parse as `source_mode="collected"` after upgrade. The current runbook workaround is explicitly not-yet-implemented and has no known production users.

## Section 3: Adapter refactor

### 3.1 New shared helper at module level

Discovery and freshness filtering are live-collect state that does not exist at ingest time. Rather than pushing adapter-specific discovery into a shared helper (which would break parity for Monkey365 and M365-Assess), the shared helper shrinks to hashing + `CollectionOutput` assembly only:

```python
# adapters/_base.py — new module-level helper alongside find_latest_output_dir, etc.

def build_collection_output(
    *,
    tool: ToolSource,
    tool_slug: str,
    items: list[tuple[Path, str]],
    schema_version: str,
    timestamp: datetime,
    execution_metadata: dict[str, Any],
) -> CollectionOutput:
    """Hash a set of source files and assemble a CollectionOutput.

    Called AFTER the caller has done adapter-specific discovery (and, for
    live collect(), adapter-specific freshness filtering). The helper is
    layout-agnostic: callers provide pre-computed (source_path, target_relpath)
    pairs, the helper hashes each source_path, builds CollectedArtifact
    records, sorts them by target_relpath for deterministic output, and
    returns a CollectionOutput.

    Args:
        tool: ToolSource enum value.
        tool_slug: Storage slug. No leading/trailing slashes.
        items: List of (absolute source path, canonical POSIX target_relpath) pairs.
            Each target_relpath MUST start with f"{tool_slug}/".
        schema_version: Caller-controlled. For live collect: adapter's default
            constant. For ingest: operator --schema-version or adapter default.
        timestamp: Caller-controlled. For live collect: utc_now(). For ingest:
            --run-at override or utc_now() at ingest time.
        execution_metadata: Caller-controlled. For live collect: real provenance dict.
            For ingest: {} (ingest provenance lives on RawToolOutput, not here).

    Raises:
        CollectionError: On hash failure or zero items.
        ValueError: On target_relpath format violation (via validate_canonical_posix_path).
    """
```

Responsibilities:

1. Validate `items` is non-empty
2. Validate every target_relpath via `validate_canonical_posix_path()` from `core/domain/path_validation.py` and confirm it starts with `f"{tool_slug}/"`
3. For each `(source_path, target_relpath)` pair: `sha256_file(source_path)` → build `CollectedArtifact`
4. Sort artifacts by `target_relpath` (deterministic ordering for manifest hash stability)
5. Wrap in `CollectionOutput` with the caller-supplied `schema_version`, `timestamp`, `execution_metadata`

**Discovery logic lives exclusively in the callers.** `collect()` keeps its freshness filtering (pre_run_state, existing_files, etc.) unchanged. `ingest_from_directory()` implements a simpler directory scan that matches what collect's post-tool-run state would look like, minus the freshness filter.

### 3.2 Per-adapter discovery contracts (unchanged from today)

The `build_collection_output` refactor (Section 3.1) preserves `collect()`'s discovery logic verbatim for **all 7 adapters** — parity is enforced by the refactor tests in Section 6.3. For the **5 ingest-capable adapters only** (ScubaGear, Maester, Prowler, Azure Advisor, Secure Score), `ingest_from_directory()` (Section 3.4) uses the same discovery rules as `collect()` minus freshness filtering. **Monkey365 and M365-Assess have no `ingest_from_directory()` in this PR** (see Non-goals / Codex Finding 2); their rows below document `collect()` discovery for the refactor's parity obligation only, NOT for any ingest path.

| Adapter | Discovery (matches current `collect()` exactly) |
|---|---|
| **ScubaGear** | `_find_scuba_results_file()` returns the first `scubaresults*.json` basename match (case-insensitive). No "reject if multiple." Matches `adapters/scubagear/adapter.py:369`. |
| **Maester** | `sorted(run_dir.glob("TestResults*.json"))`; require exactly one. Maester already rejects zero or multiple. |
| **Monkey365** | Collects all newly-produced `_OUTPUT_FILE_PREFIX*.json` files, freshness-filtered against an `existing_files` set captured BEFORE the tool runs. Matches `adapters/monkey365/adapter.py:130`. |
| **M365-Assess** | Two source roots: CSVs in `output_dir` (filtered by `pre_run_state` mtime+size snapshot), controls metadata in a fallback-resolved `controls_dir`. Matches `adapters/m365_assess/adapter.py:229,261`. |
| **Prowler** | `output_dir.rglob(f"{_DEFAULT_OUTPUT_FILENAME}{_OCSF_EXTENSION}")` — recursive glob for a specific fixed filename pattern, NOT arbitrary `*.ocsf.json`. Matches `adapters/prowler/adapter.py:366`. |
| **Azure Advisor** | Single file at `output_dir / _OUTPUT_FILENAME`. |
| **Secure Score** | Two specific files (profiles + scores) at fixed filenames. |

**Documented UX tradeoff:** ingest inherits pick-first-match semantics for ScubaGear, meaning that if a client hands over a directory with two `ScubaResults*.json` files, ingest silently selects the first one. This is consistent with live collect. If operators hit it in the field, a `--strict` mode for `ingest_from_directory` is a follow-up issue.

### 3.3 `collect()` refactor — zero behavioral change

Each adapter's `collect()` keeps all its existing logic up to and including freshness filtering, then constructs `items` inline and calls the shared helper. Net behavioral change for `collect()`: zero, enforced by parity tests in Section 6.

**M365-Assess** uses `output_dir = Path(tc.output_dir)` directly (no run subdir). Its `collect()` passes both roots:

```python
csv_items = [(csv, f"{self.storage_slug}/{csv.name}") for csv in sorted(csv_files, key=lambda f: f.name)]
controls_items = [
    (controls_dir / filename, f"{self.storage_slug}/controls/{filename}")
    for filename in ("risk-severity.json", "registry.json")
    if (controls_dir / filename).is_file()
]

execution_metadata: dict[str, str] = {
    "script_path": script_path,  # Real key — matches current adapter.py:307
    "tenant_id": config.tenant_id,
}
if tc.controls_dir:
    execution_metadata["controls_dir"] = str(controls_dir)

return build_collection_output(
    tool=ToolSource.M365_ASSESS,
    tool_slug=self.storage_slug,
    items=csv_items + controls_items,
    schema_version=_SCHEMA_VERSION,
    timestamp=utc_now(),
    execution_metadata=execution_metadata,
)
```

The M365-Assess allowlist at `constants.py:170` lists `"script"` but the adapter writes `"script_path"`. This is a pre-existing inconsistency (the key gets filtered out by `save_raw_outputs`'s allowlist pass). The refactor preserves the current behavior exactly; fixing the allowlist/adapter mismatch is out of scope for this PR.

### 3.4 `ingest_from_directory()` method

**Only 5 of the 7 built-in adapters implement this method in this PR**: ScubaGear, Maester, Prowler, Azure Advisor, Secure Score. Each of them declares the same uniform public signature:

```python
def ingest_from_directory(
    self,
    source_dir: Path,
    *,
    schema_version: str,
    timestamp: datetime,
) -> CollectionOutput:
```

Each implementation does a simple directory scan matching its own `collect()` discovery rules (minus freshness filtering), builds `items`, and calls `build_collection_output(..., execution_metadata={})`. **Prowler** passes the fixed output filename constant to match its rglob pattern. Every ingest-capable adapter passes `execution_metadata={}` as a literal, not a default — this makes it mechanically impossible to forge provenance on the ingest path.

**Monkey365 and M365-Assess are deliberately excluded from this method**, do NOT declare the `"ingest"` capability, do NOT declare `default_schema_version`, and do NOT expose `ingest_from_directory()` at all in this PR. The rationale is the silent-stale-data problem documented in Non-goals and surfaced by Codex Finding 2: their `collect()` paths rely on pre-run filesystem snapshots (Monkey365's `existing_files` at `monkey365/adapter.py:130`, M365-Assess's `pre_run_state` mtime/size dict at `m365_assess/adapter.py:211-219`) that ingest has no way to reconstruct. A naive directory-scan ingest for those adapters would silently merge stale and current files into one manifest. The exclusion is not just prose — it is pinned by the negative tests in Section 6.5 (`test_monkey365_has_no_ingest_capability`, `test_m365_assess_has_no_ingest_capability`). A proper freshness-safe design for those two adapters is tracked as follow-up work in the "Future work" section.

### 3.5 Protocol surface: `IngestCapableAdapter`

```python
# core/contracts/types.py — new Protocol after ToolAdapter

@runtime_checkable
class IngestCapableAdapter(ToolAdapter, Protocol):
    """ToolAdapter that can construct a CollectionOutput from operator-
    provided raw tool output.

    An adapter declares this capability via ``"ingest" in capabilities``,
    by implementing ``ingest_from_directory``, AND by declaring
    ``default_schema_version`` as a class attribute.
    """

    default_schema_version: str = ""
    """The schema_version string used when ingest is invoked without
    an explicit --schema-version override. Must match the value the
    adapter's own collect() writes into CollectionOutput.schema_version
    for live collections of the same tool version."""

    def ingest_from_directory(
        self,
        source_dir: Path,
        *,
        schema_version: str,
        timestamp: datetime,
    ) -> CollectionOutput:
        ...
```

Each **ingest-capable** built-in adapter declares its `default_schema_version` as a class attribute (5 of 7 in this PR):

| Adapter | `default_schema_version` | Source of the value |
|---|---|---|
| ScubaGear | `_SCHEMA_VERSION` (`"1.7.1"`) | existing constant at `scubagear/adapter.py:46` |
| Maester | `"1.0.0"` | literal, matching the inline hardcode at `maester/adapter.py:159` |
| Prowler | `_SCHEMA_VERSION` | existing constant |
| Azure Advisor | `_ADVISOR_API_VERSION` (`"2025-01-01"`) | existing constant at `azure_advisor/adapter.py:53` |
| Secure Score | `_SCHEMA_VERSION` | existing constant |

Monkey365 and M365-Assess are absent from this table deliberately. They do NOT declare `default_schema_version` and do NOT declare the `"ingest"` capability in this PR, per the Non-goals / Codex Finding 2 scope reduction documented in Section 3.4.

**Capability consistency check**: `_validate_adapter()` at `adapters/__init__.py:84` is extended so that an adapter declaring `"ingest"` in `capabilities` must have BOTH a callable `ingest_from_directory` attribute AND a non-empty `default_schema_version` string attribute. Adapters that declare the capability without fulfilling both requirements fail discovery and are excluded from the registry with a clear error message.

**`"ingest"` is added to `AdapterCapability`** at `constants.py:113` and to the `ADAPTER_CAPABILITIES` frozenset at line 122. Only the **5 ingest-capable built-in adapters** (ScubaGear, Maester, Prowler, Azure Advisor, Secure Score) add `"ingest"` to their `capabilities` frozenset. Monkey365 and M365-Assess do NOT — their capability sets are unchanged by this PR.

**`_REQUIRED_ATTRIBUTES` at `adapters/__init__.py:29` is NOT extended.** The capability is opt-in — a third-party adapter for a tool with no useful file-on-disk output may legitimately not support ingest. The registry's capability-consistency check is what keeps declared and implemented in sync at discovery time.

## Section 4: Persistence layer

### 4.1 New `ArtifactManager.save_ingested_raw_output()` method

Lives in `persistence/artifacts.py` alongside `save_raw_outputs()`.

```python
def save_ingested_raw_output(
    self,
    engagement_id: str,
    collection_output: CollectionOutput,
    *,
    ingest_provenance: IngestProvenance,
    replace: bool,
) -> LoadedManifest:
    """Persist a single tool's ingested raw output atomically.

    Writes artifacts into raw-output/artifacts/<slug>/ and a manifest into
    raw-output/manifests/<slug>.json without disturbing other tools' data.
    The written RawToolOutput has source_mode="ingested" and carries the
    provided ingest_provenance at the top level.
    """
```

**Contract summary:**

- **Fails closed on missing engagement dir for the normal path, with a narrow legacy-migration fallback.** For engagements created after the Section 1a bootstrap fix, the directory always exists, and a missing dir is a real inconsistency to be reported to the operator. For engagements created before this PR (DB row present, directory not yet provisioned), a narrow migration path auto-creates the directory and mirrors `config_snapshot.json`. See Section 4.2a for the exact conditions and logging.
- **Single-slug atomicity.** Only the target tool's artifacts subdirectory and manifest file are touched. All other tools' existing data remains byte-for-byte untouched.
- **Conflict-gated.** If the slug's artifacts or manifest already exists and `replace=False`, raises `PersistenceError` before any mutation. With `replace=True`, the prior data is atomically renamed aside as part of the commit and cleaned up best-effort afterwards.
- **Owns manifest materialization.** Constructs the `RawToolOutput` internally with `source_mode="ingested"` and the caller-provided `ingest_provenance`. The caller does not construct the `RawToolOutput` — this method is the **only** place in the codebase that writes `source_mode="ingested"`, enforced by code review.
- **Owns the `IngestProvenance.replaced` field.** The caller passes an `IngestProvenance` with `replaced=False`; the persistence layer observes the actual pre-commit state (in Phase 1 after the conflict check) and, if prior data existed for this slug, sets `replaced=True` on the provenance object that gets serialized into the committed manifest. This ensures `replaced` is the **committed audit record of what actually happened**, not the operator's intent. Passing `--replace` against a slug with no prior data yields `replaced=False` in the committed manifest. Rationale: this makes the committed `replaced` value a reliable input to the `--repair-event` recovery path (Section 5.5a/5.5b), which has no way to re-observe pre-commit state after the fact.
- **Invariant assertion: `execution_metadata == {}`.** The method asserts `collection_output.execution_metadata == {}` at the top and raises `PersistenceError` if violated. Ingest must never synthesize per-tool execution metadata; that field is exclusively for real tool-run provenance.
- **Caller must hold `EngagementLock`.** This method does not acquire a lock; it trusts the caller to serialize concurrent mutations (same convention as `save_raw_outputs`).
- **Caller must have already run the adapter's `validate_raw()`** against the source files. This method does not call `validate_raw()` itself; that's the CLI command's pre-commit check.
- **Caller must have already called `reset_for_rerun(Stage.PARSE)`.** The CLI command orders state reset before this method for idempotency on commit failure (see Section 1 step 8). This method does not call the orchestrator itself.

### 4.2 Implementation sketch

**Upfront slug validation** before any path construction:

```python
slug = collection_output.tool_slug
if not re.fullmatch(TOOL_SLUG_PATTERN, slug):
    raise PersistenceError(
        f"CollectionOutput.tool_slug {slug!r} does not match required pattern "
        f"{TOOL_SLUG_PATTERN!r}. This indicates an adapter bug; the slug should "
        f"already have been validated at the adapter layer."
    )
```

This closes the window between adapter-produced `CollectionOutput` (where `tool_slug` is typed as plain `str` at `models.py:202`) and `ArtifactManager`'s use of that slug in filesystem paths. `TOOL_SLUG_PATTERN` at `constants.py:156` is `[a-z0-9][a-z0-9-]*` — the same pattern `RawToolOutput.tool_slug` enforces. Defense-in-depth: the slug regex check is the primary gate; `_validate_path_within_root(...)` on staging and aside paths is the secondary fence.

**Three-phase discipline** matching `save_raw_outputs`:

1. **Phase 1 — validate all inputs (no I/O beyond hashing):** source file presence, hash match, canonical POSIX target_relpath, slug prefix, duplicate/case-collision checks (mirroring `save_raw_outputs` Phase 1). **Conflict probe and `replaced` determination (Finding 3 fix):** at the end of Phase 1, probe the existing slug state under the engagement lock (caller holds it). Compute `had_prior = (manifest_path.exists() or (artifacts_root / slug).is_dir())`. If `had_prior and not replace_flag`, raise `PersistenceError` with the operator-facing conflict message. Otherwise, set `ingest_provenance = ingest_provenance.model_copy(update={"replaced": had_prior})` — this is the single place in the codebase where `IngestProvenance.replaced` transitions from its caller-side placeholder to its committed audit value. The rest of Phase 1, Phase 2, and Phase 3 use this updated `ingest_provenance` for all manifest construction and serialization, so the bytes written to disk carry the correct `replaced` value. Assert invariant: `not updated.replaced or replace_flag` (you cannot have replaced prior data without the operator permitting it); if violated, that's an internal bug and raises `PersistenceError`.
2. **Phase 2 — stage to `.ingest-staging-<slug>-<uuid>/`:** copy files with hash-verified copies, construct the `RawToolOutput` with `source_mode="ingested"` and the Phase-1-updated `ingest_provenance`, then write the manifest JSON to the staging directory. On any failure, `shutil.rmtree(staging_dir, ignore_errors=True)` and re-raise.
3. **Phase 3 — atomic per-slug commit:** rename-aside any existing slug data (if `replace=True`), then commit new artifacts first and manifest last (matching `save_raw_outputs` Phase 3 ordering). The committed manifest bytes are the single source of truth for the `--repair-event` recovery path (Section 5.5b).

### 4.2a Legacy migration fallback

The Section 1a bootstrap fix ensures every new engagement has its directory provisioned at creation time AND has `engagements.engagement_dir` populated in the DB row. Engagements that exist in the DB today were created before that fix — they have `engagement_dir IS NULL` and no on-disk directory. To avoid breaking those engagements on the first ingest, `save_ingested_raw_output()` has one specific escape hatch from its fail-closed rule, applied before the three-phase discipline in Section 4.2 runs:

```python
try:
    eng_dir = self.get_engagement_dir(engagement_id)
except PersistenceError:
    # Directory is missing. Use the engagement_dir column from the DB row
    # as the discriminator between "legacy, never provisioned" and
    # "post-PR, directory was provisioned but got deleted".
    #
    # Caller (CLI layer) passes the already-loaded engagement_row dict as
    # a keyword argument so we don't re-query the DB. See Section 5.3 for
    # how client_name, engagement_row, and engagement_repo are threaded
    # through from the CLI layer.
    stored_dir = engagement_row.get("engagement_dir")
    if stored_dir is not None:
        # Post-PR engagement with a recorded directory that no longer
        # exists on disk. This is filesystem corruption or manual
        # deletion -- NOT a legacy-migration case. Fail closed with a
        # clear, actionable error.
        raise PersistenceError(
            f"Engagement {engagement_id} has engagement_dir={stored_dir!r} "
            f"recorded in the database, but that directory is missing from "
            f"disk. This indicates filesystem corruption or manual deletion. "
            f"Restore from backup or run `mseco engagement purge {engagement_id}` "
            f"to remove the stale row."
        )

    # Legacy migration: engagement_dir IS NULL in the DB row, meaning this
    # engagement was created before PR #78 and never had its directory
    # provisioned. Provision it now AS A ONE-SHOT TRANSITION to post-PR
    # state: create directory, write strict mirror, backfill the column.
    # After this migration succeeds, the row is indistinguishable from a
    # post-PR bootstrap row, and any FUTURE missing-directory case for
    # this engagement hits the fail-closed corruption branch -- NOT the
    # migration branch. Codex Finding 3: without the backfill, migrated
    # rows stayed "legacy forever" and masked later data loss.
    logger.warning(
        "Legacy engagement %s has engagement_dir IS NULL and no on-disk "
        "directory; provisioning it now as a one-time migration. After "
        "successful migration, the engagement_dir column is backfilled "
        "and subsequent missing-directory cases for this engagement will "
        "fail closed as corruption.",
        engagement_id,
    )

    # Step 1: Create the directory on disk.
    eng_dir = self.create_engagement_dir(engagement_id, client_name)

    # Step 2: Write the strict mirror. Fails -> clean up directory, reraise.
    from gxassessms.pipeline.config_snapshot_mirror import (
        mirror_config_snapshot_from_db_strict,
    )
    try:
        mirror_config_snapshot_from_db_strict(
            engagement_repo,
            self,  # ArtifactManager
            engagement_id,
        )
    except ConfigSnapshotMirrorError as exc:
        shutil.rmtree(eng_dir, ignore_errors=True)
        raise PersistenceError(
            f"Legacy migration failed for engagement {engagement_id}: "
            f"config_snapshot mirror write failed ({exc}). No raw output "
            f"was committed. Directory cleanup attempted."
        ) from exc

    # Step 3: Backfill engagement_dir in the DB. This is the commit step
    # that turns the row from "legacy" into "post-PR bootstrap equivalent."
    # If it fails, roll back steps 1 and 2.
    try:
        engagement_repo.update_engagement_dir(
            engagement_id,
            engagement_dir=str(eng_dir),
        )
    except PersistenceError as exc:
        # Clean up directory + mirror. The mirror lives inside eng_dir so
        # rmtree of eng_dir takes it out automatically.
        shutil.rmtree(eng_dir, ignore_errors=True)
        raise PersistenceError(
            f"Legacy migration failed for engagement {engagement_id}: "
            f"backfill of engagement_dir column failed ({exc}). No raw "
            f"output was committed. Directory cleanup attempted."
        ) from exc

    # Migration complete: eng_dir is now provisioned AND the DB row has
    # engagement_dir populated. Any FUTURE missing-directory case for
    # this engagement hits the "post-PR corruption" branch above instead
    # of re-entering this migration branch. Proceed with the normal
    # three-phase ingest commit.
```

**Why this is narrow, not "relax the fail-closed rule entirely":**

- The `except PersistenceError` block only fires when the directory is missing. Every other failure mode (wrong permissions, partial state on disk, etc.) still falls through the original code path.
- The `engagement_dir IS NULL` check is the explicit legacy discriminator. Post-PR engagements have a non-null value in that column and go to the fail-closed branch. Legacy engagements have NULL and go to the migration branch.
- The legacy migration calls `create_engagement_dir()`, `mirror_config_snapshot_from_db_strict()`, AND `update_engagement_dir()` as a three-step sequence. If any step fails, the rollback cleans up the directory and the error propagates with no raw output committed.
- **The migration is truly one-shot because step 3 backfills the column.** After a successful migration, the row's `engagement_dir` is populated and the next ingest sees the discriminator flip to post-PR. If the directory is later deleted or corrupted, the next ingest hits the fail-closed corruption branch — NOT a silent re-migration that could mask data loss. This is the Codex Finding 3 fix.
- The WARNING log line distinguishes a legacy-migration auto-provision from a first-write provision, so operators can tell the difference when reviewing logs months later.
- New engagements created via the fixed `engagement create` will never hit this path, because the directory is always already present AND `engagement_dir` is populated. Over time, the legacy branch becomes cold code, and the "engagement_dir is set but the directory is gone" branch becomes the only way to hit this error at all.

**What this is NOT:**

- This is NOT a general-purpose "auto-create if missing" behavior for `save_ingested_raw_output`. It is a one-shot migration gated on `engagement_dir IS NULL`. Filesystem corruption or manual deletion of a post-PR engagement directory hits the other branch and raises.
- It does NOT handle the case where the DB row itself is missing. That case is caught earlier at the CLI layer by `EngagementRepo.get(engagement_id)` and results in a clean user-facing error.

**Constructor wiring:** `ArtifactManager` does not currently hold a reference to `EngagementRepo` — the two are independent layers. The legacy migration path needs the engagement row AND a repo handle to call `mirror_config_snapshot_from_db_strict` and `update_engagement_dir`. The CLI layer, which already holds both, passes them into `save_ingested_raw_output` as optional keyword arguments:

```python
def save_ingested_raw_output(
    self,
    engagement_id: str,
    collection_output: CollectionOutput,
    *,
    ingest_provenance: IngestProvenance,
    replace: bool,
    # Legacy-migration support (only consumed on the Section 4.2a path):
    client_name: str | None = None,
    engagement_row: dict[str, Any] | None = None,
    engagement_repo: EngagementRepo | None = None,
) -> LoadedManifest:
```

On the normal path (directory already exists), the three new parameters are unused. On the legacy path, they're required; if any is None, `save_ingested_raw_output` raises `PersistenceError` with a "legacy migration requested but CLI did not supply migration context" message. This keeps the happy-path signature usable in tests that don't need migration support, while making the migration path explicit at every call site.

**Layering note on `update_engagement_dir`:** The migration branch calls `engagement_repo.update_engagement_dir(engagement_id, engagement_dir=...)`, which is a new thin method on `EngagementRepo` that this PR adds. Rationale: the method's general layer contract is "filesystem writes only, no DB updates" (see the list in Section 4.4), but the legacy-migration branch is explicitly an exception. It's a one-shot state transition that atomically (a) creates a filesystem directory, (b) writes a filesystem mirror, and (c) commits the DB column flip that makes (a) and (b) "official." Splitting (c) across layers would break the one-shot atomicity — a separate CLI-layer call to `update_engagement_dir` after `save_ingested_raw_output` returns would open a window where the migration looks successful to the operator but isn't committed in the DB, and a subsequent crash would leave a migrated directory with a NULL column. The layering exception is narrow (one branch inside one method) and is acceptable because the alternative splits a state transition that must be atomic.

**`EngagementRepo.update_engagement_dir` — new method:**

```python
# persistence/engagement_repo.py — new thin method, ~10 lines

def update_engagement_dir(
    self,
    engagement_id: str,
    engagement_dir: str | None,
) -> None:
    """Set or clear the engagement_dir column on an engagement row.

    Used by:
    - save_ingested_raw_output's legacy-migration path, which backfills
      a non-null path after successfully provisioning the directory (the
      one-shot transition from "legacy" to "post-PR equivalent").
    - Potentially by a future `mseco engagement migrate` batch command
      (see Future work) that backfills legacy rows without ingesting.

    Accepts None to explicitly clear the column (used by the legacy
    migration's rollback path if a later step fails after this one
    succeeds; not used in this PR's final rollback shape but exposed for
    completeness).

    Raises PersistenceError if the engagement row does not exist.
    """
    now = format_utc(utc_now())
    with self._db.connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM engagements WHERE engagement_id = ?",
            (engagement_id,),
        ).fetchone()
        if row is None:
            raise PersistenceError(f"Engagement not found: {engagement_id}")
        conn.execute(
            "UPDATE engagements SET engagement_dir = ?, updated_at = ? "
            "WHERE engagement_id = ?",
            (engagement_dir, now, engagement_id),
        )
    logger.info(
        "Updated engagement_dir for %s to %r",
        engagement_id,
        engagement_dir,
    )
```

### 4.3 Per-side rollback for single-slug atomicity

Phase 3 tracks `committed_artifacts` and `committed_manifest` independently. If the second rename (manifest) fails after the first (artifacts) succeeds, the rollback path handles each side independently to restore the exact pre-call state. The four pre-call cases × `replace=True` are all covered:

| Case | Pre-call state | Rollback action | Post-rollback state |
|---|---|---|---|
| **A** | neither | delete new artifacts; no old to restore | neither ✓ |
| **B** | both | delete new artifacts, restore old artifacts; no committed manifest, restore old manifest | both ✓ |
| **C** | old artifacts only | delete new artifacts, restore old artifacts; no committed manifest, no old to restore | old artifacts only ✓ |
| **D** | old manifest only | delete new artifacts, no old artifacts to restore; no committed manifest, restore old manifest | old manifest only ✓ |

Case D is the case a naive rollback breaks — without per-side handling, the new artifacts stay committed alongside the restored old manifest, creating a mismatched pair. The per-side logic explicitly handles this by deleting the new artifacts when there were none to restore.

A "rollback itself fails" fallback logs an error and leaves the `.old-ingest-*` aside paths on disk so a human can manually recover, then raises `PersistenceError`.

### 4.4 What this method does NOT do

- Does not acquire the engagement lock (caller's job)
- Does not call `validate_raw()` on the `CollectionOutput` (CLI's job, runs pre-commit against source paths)
- Does not emit events or update engagement state (CLI's job, runs under the same lock, and the CLI orders `reset_for_rerun` **before** this method for retry safety)
- Does not filter `execution_metadata` through the allowlist (ingest's execution_metadata is `{}` by invariant, so no filtering is needed; the assertion at the top ensures this can never change)
- Does not update the DB `engagements` row
- Does not write `<engagement_dir>/config_snapshot.json` on the normal path — that file is written by `mseco engagement create` at bootstrap (Section 1a) and refreshed by collect's existing `mirror_config_snapshot_from_db()` call at `_runner.py:84-97`. The only ingest-time write to that file is inside the Section 4.2a legacy-migration fallback, one-shot per engagement.

## Section 5: CLI command

### 5.1 Command signature

New file `src/gxassessms/cli/commands/ingest.py`, mirroring `replay.py`'s shape. New registration line in `cli/main.py:_register_commands()`:

```python
_try_register("gxassessms.cli.commands.ingest", "ingest_cmd", "ingest")
```

Click command:

```python
@click.command("ingest")
@click.argument("engagement_id")
@click.option(
    "--tool", "tool_slug", required=True,
    help="Storage slug of the adapter to ingest (e.g. 'scubagear', 'maester'). "
         "Must match a tool enabled in this engagement's config.",
)
@click.option(
    "--from", "source_path", default=None,  # required on the normal path; validated in-handler
    type=click.Path(exists=True, file_okay=False, dir_okay=True, readable=True, resolve_path=False),
    help="Path to a directory containing this tool's raw output files, "
         "laid out as if the tool had just run against them. "
         "Required on the normal path; must be omitted with --repair-event.",
)
@click.option(
    "--replace", is_flag=True, default=False,
    help="Overwrite existing raw output for this tool in the engagement. "
         "Mutually exclusive with --repair-event.",
)
@click.option(
    "--schema-version", "schema_version_override", default=None,
    help="Override the adapter's default schema_version string. "
         "Mutually exclusive with --repair-event.",
)
@click.option(
    "--run-at", "run_at_arg", default=None,
    help="ISO-8601 UTC timestamp of when the client actually ran the tool. "
         "Defaults to the ingest time if omitted (reports will show ingest date). "
         "Mutually exclusive with --repair-event.",
)
@click.option(
    "--operator", default=None,
    help="Operator identity recorded in the manifest provenance and event journal. "
         "Defaults to getpass.getuser().",
)
@click.option(
    "--repair-event", "repair_event", is_flag=True, default=False,
    help="Audit-neutral recovery mode. Emits the raw_output_ingested event for an "
         "already-committed ingest whose original event emission failed (see Section "
         "5.5a). Reads committed manifest provenance; does NOT rewrite any files, "
         "does NOT mutate engagement state, and does NOT accept --from, --replace, "
         "--schema-version, or --run-at. Idempotent: no-op success if the event is "
         "already present in the journal.",
)
def ingest_cmd(...)
```

### 5.2 Validation details

- **`engagement_id`**: matches `ENGAGEMENT_ID_PATTERN` from `pipeline/state.py:94` (same gate as replay).
- **`--operator`**: defaults to `getpass.getuser()` with `OSError` fallback to `"unknown"`. Sanitized, non-empty-checked, wrapped as `f"human:{operator}"` before writing to `IngestProvenance.ingested_by` and the event actor field.
- **`--from`**: `source_dir = Path(source_path)` — rejected if `is_symlink()`, then `.expanduser().resolve()` to an absolute path, then `is_dir()` re-checked (defense-in-depth after resolve). **Required when `--repair-event` is NOT set; MUST be omitted when `--repair-event` IS set** — the handler raises `click.UsageError` with an explicit message if either precondition is violated.
- **`--schema-version`**: optional free-form string, sanity-checked for non-empty-after-strip, no control characters, ≤64 chars. No PEP-440, no semver — adapters use various formats including date-like (`"2025-01-01"`), so validation must not be tighter than `RawToolOutput.schema_version: str` already enforces. **Mutually exclusive with `--repair-event`** (the repair path reads committed `schema_version` from the manifest, not a new override).
- **`--run-at`**: parsed via `parse_utc()` from `core/config/datetime_utils.py:16`. Handles `"Z"` suffix, `"+00:00"` offset, and naive-assumed-UTC. **`datetime.fromisoformat()` must not be called directly**; the convention test at `tests/conventions/test_datetime_conventions.py` bans it outside `datetime_utils.py`. Missing `--run-at` defaults to `utc_now()` with a yellow warning that reports will reflect the ingest date. **Mutually exclusive with `--repair-event`** (the repair path preserves committed `timestamp` without rewriting it).
- **`--replace`**: **Mutually exclusive with `--repair-event`**. Repair never mutates filesystem state, so a replace flag on it is incoherent. The handler raises `click.UsageError` if both are set.
- **`--repair-event`**: boolean flag, no arguments. When set, the handler validates that `--from`, `--replace`, `--schema-version`, and `--run-at` are all absent/default; on violation, raises `click.UsageError` listing all conflicting flags.

### 5.3 Engagement lookup

```python
# DB row required -- no filesystem fallback (unlike replay's DR path).
try:
    engagement = repo.get(engagement_id)
except PersistenceError as e:
    console.print(
        f"[bright_red]Error:[/bright_red] Engagement {engagement_id!r} "
        f"not found in the database. Run `mseco engagement create` first. "
        f"(Details: {e})"
    )
    raise SystemExit(1) from None

# Load the engagement config (DB only; no DR fallback for ingest).
from gxassessms.persistence.engagement_repo import decode_config_snapshot
snapshot = decode_config_snapshot(engagement)
config = EngagementConfig.model_validate(snapshot)
client_name = config.client_name  # needed for legacy-migration fallback
# `engagement` itself is the dict row from EngagementRepo.get() and
# already contains engagement_dir (None for legacy rows, populated for
# post-PR rows). Save it to pass through to save_ingested_raw_output
# for the Section 4.2a legacy-vs-corruption discriminator.
engagement_row = engagement

# On-disk directory check is deferred: save_ingested_raw_output handles
# missing-dir either as the Section 4.2a legacy migration fallback
# (when engagement_row["engagement_dir"] IS NULL) or as a fail-closed
# post-PR corruption error (when engagement_row["engagement_dir"] is
# populated but the directory is gone). The CLI does NOT pre-check
# get_engagement_dir here; it passes the migration context through to
# the persistence layer.
```

### 5.4 Adapter resolution via new helpers in `cli/_helpers.py`

```python
def resolve_enabled_adapter(
    tool_slug: str,
    registry: AdapterRegistry,
    config: EngagementConfig,
) -> ToolAdapter:
    """Find an adapter by storage_slug and verify it is enabled in the engagement config.

    Handles the storage_slug vs. tool_name.lower() mismatch: adapters are
    identified by storage_slug (e.g., "secure-score") on the CLI but registered
    in config.tools under tool_name.lower() (e.g., "securescore"). This is the
    one place that knows that mapping.
    """
    matches = [
        cls() for cls in registry.adapters.values()
        if getattr(cls, "storage_slug", None) == tool_slug
    ]
    if not matches:
        available = sorted(getattr(cls, "storage_slug", "?") for cls in registry.adapters.values())
        raise click.UsageError(
            f"Unknown tool slug {tool_slug!r}. Available: {', '.join(available)}"
        )
    if len(matches) > 1:
        raise click.UsageError(f"Multiple adapters claim slug {tool_slug!r}; registry is corrupt.")
    adapter = matches[0]

    enabled_names = {name.lower() for name, tc in config.tools.items() if tc.enabled}
    if adapter.tool_name.lower() not in enabled_names:
        raise click.UsageError(
            f"Tool {tool_slug!r} (adapter {adapter.tool_name!r}) is not enabled "
            f"in this engagement's config. Enable it in config.tools before ingesting."
        )
    return adapter


def require_ingest_capable(adapter: ToolAdapter) -> IngestCapableAdapter:
    """Narrow a ToolAdapter to IngestCapableAdapter or raise."""
    if "ingest" not in adapter.capabilities:
        raise click.UsageError(
            f"Adapter {adapter.tool_name!r} does not support ingest "
            f"(capability 'ingest' not declared)."
        )
    if not isinstance(adapter, IngestCapableAdapter):
        raise click.UsageError(
            f"Adapter {adapter.tool_name!r} declares 'ingest' capability but "
            f"does not implement ingest_from_directory(). Adapter packaging bug."
        )
    return adapter


def get_engagement_lock() -> EngagementLock:
    """Factory for the EngagementLock matching the engagements root."""
    from gxassessms.pipeline.state import EngagementLock
    return EngagementLock(get_engagements_root())
```

### 5.5 The lock-held region — `_ingest_under_lock()` (normal path)

Kept as a separate helper so the lock acquisition stays narrow and readable. `ingest_cmd` dispatches to this helper on the normal path (when `--repair-event` is NOT set) and to `_repair_event_under_lock()` (Section 5.5b) otherwise. The normal path runs in this specific order (see Section 1 step 8 for the rationale on DB-reset-before-filesystem-commit):

1. **Conflict check** (TOCTOU-safe inside the lock) — uses `artifacts.get_engagement_dir()` opportunistically; if the dir is missing (legacy migration case), the conflict check becomes "no prior state," which is correct.
2. **Adapter walk**: `ingest_adapter.ingest_from_directory(source_dir, schema_version=..., timestamp=run_at)`. Schema version resolution: `schema_version_override or ingest_adapter.default_schema_version`
3. **Pre-commit `validate_raw`**: build a throwaway `ResolvedManifest` with absolute source_paths as `file_manifest` keys, call `ingest_adapter.validate_raw(preflight_manifest)`. On failure, abort without mutating the engagement directory.
4. **DB state reset**: `orchestrator.reset_for_rerun(engagement_id, Stage.PARSE)` — resets the engagement state to `EngagementState.COLLECTED` (PARSE's entry state per `stages.py:386`). No-op when already at COLLECTED. Emits the existing `"rerun"` event via the orchestrator's standard path. **This runs BEFORE the filesystem commit**: if step 5 fails and Section 4.3's per-side rollback restores the pre-call filesystem state, the engagement is left at COLLECTED with its original raw output unchanged — a clean retry state. The alternative order (commit first, then reset) would leave committed filesystem data paired with stale DB state on DB failure, which is the split-brain case from the first adversarial review round.
5. **Atomic filesystem commit**: construct `IngestProvenance(source_path=str(source_dir), ingested_at=utc_now(), ingested_by=f"human:{operator}", replaced=False)`. The caller-side `replaced=False` is a placeholder: `save_ingested_raw_output` observes the actual pre-commit state in Phase 1 and, if prior raw output exists for this slug, flips the `replaced` field on the provenance before serializing it into the committed manifest (see Section 4.1 contract). Call `artifacts.save_ingested_raw_output(engagement_id, collection_output, ingest_provenance=..., replace=replace_flag, client_name=client_name, engagement_row=engagement_row, engagement_repo=repo)`. The three legacy-migration kwargs (`client_name`, `engagement_row`, `engagement_repo`) are only consumed on the Section 4.2a legacy-migration path when `engagement_row["engagement_dir"] IS NULL` and the directory is missing; on the normal path they're unused.
6. **Dedicated ingest event**: `orchestrator.record_raw_output_ingested(...)` — new public wrapper. The payload is built from the committed manifest's `IngestProvenance` (not from local CLI variables), so the event is populated from the same bytes the repair path will read on recovery:
    ```python
    loaded = artifacts.save_ingested_raw_output(...)  # Phase-3 materialized manifest
    committed_provenance = loaded.raw_output.ingest_provenance  # canonical source of truth
    orchestrator.record_raw_output_ingested(
        engagement_id=engagement_id,
        actor=committed_provenance.ingested_by,
        tool_slug=loaded.raw_output.tool_slug,
        source_path=committed_provenance.source_path,
        file_count=len(loaded.raw_output.file_manifest),
        replaced=committed_provenance.replaced,
    )
    ```
   **This is the one step that can fail after the filesystem is committed**, producing the missing-audit-event failure mode documented in Section 5.5a below.

### 5.5a Recovery from partial-ingest failures

The two DB operations in the lock-held region (`reset_for_rerun` at step 4 and `record_raw_output_ingested` at step 6) can in principle fail under SQLite errors, disk-full conditions, or concurrent-lock escalation. The ordering in Section 5.5 is chosen to make most failure modes cleanly retryable, with one specific mode that requires an explicit — but audit-neutral — recovery procedure.

**Failure mode analysis:**

| Step that fails | Filesystem state after failure | DB state after failure | Recovery |
|---|---|---|---|
| 1-3 (pre-mutation) | unchanged | unchanged | Retry with corrected inputs. No recovery needed. |
| 4 (DB state reset) | unchanged (nothing committed yet) | unchanged (reset never applied) | Retry. Clean, idempotent. |
| 5 (filesystem commit) | unchanged (Section 4.3 per-side rollback restores pre-call state) | state reset to COLLECTED; spurious "rerun" event in journal | Retry. The spurious rerun event is minor audit noise. If the engagement was at COLLECTED before step 4, even the spurious event is avoided because `reset_for_rerun` is a no-op. |
| 6 (ingest event emission) | **committed** (new manifest and artifacts are on disk) | state is COLLECTED; rerun event in journal; **raw_output_ingested event is missing** | **`mseco ingest <id> --tool <slug> --repair-event`** — audit-neutral replay of step 6 only. See Section 5.5b. |

**Manual recovery for step 6 failure:**

The command exits with an error message that explicitly instructs the operator to run the repair flag:

```
[bright_red]Error:[/bright_red] Ingest committed raw output to disk, but the
audit event could not be recorded: <db error>.
The engagement state is consistent, but the audit trail is incomplete.

To complete the audit record, re-run with --repair-event:
    mseco ingest <id> --tool <slug> --repair-event

This is audit-neutral: the committed manifest is NOT rewritten, its provenance
(source_path, ingested_at, ingested_by, replaced) is NOT regenerated, and the
raw_output_ingested event is emitted against the same bytes currently on disk.
Do NOT use --replace for this recovery; --replace would destructively rewrite
the committed manifest with a new timestamp.

The replay pipeline will still work correctly in the meantime; only the audit
event is missing.
```

**Design constraint: the recovery path must not rewrite `RawToolOutput.timestamp` or `IngestProvenance.ingested_at` / `ingested_by` / `source_path` / `replaced` on the committed manifest.** The original adversarial-review finding was that the previous recovery procedure (rerun with `--replace`) would:
1. Re-resolve `--run-at` to `utc_now()` if the operator omitted it, silently shifting `RawToolOutput.timestamp` from the original tool-run-ish timestamp to "hours after the first attempt."
2. Construct a fresh `IngestProvenance(ingested_at=utc_now(), ...)`, so the committed manifest's provenance timestamp would be the *recovery* time, not the original *ingest* time — six months later, audits would see the recovery wall-clock rather than the operator's actual action.
3. Set `replaced=True` in the new event payload because the retry conflict-gated against the just-committed slug, even though the operator was *not* semantically overwriting prior data — the "replace" flag was a workaround, not intent.

All three of those are provenance drift. The `--repair-event` path avoids them by reading committed values from the filesystem manifest rather than regenerating them from ingest-time inputs.

**Why not a deterministic event ID / insert-or-ignore path instead?**

Deterministic event IDs (`event_id = f"ingest:{engagement_id}:{tool_slug}:{ingested_at}"`) combined with an `INSERT OR IGNORE` in `EventRepo.append()` would also solve this — the retry would naturally short-circuit on the already-committed event. Two reasons not to go that way in this PR:
1. It requires a schema change on the event journal (event IDs are not currently exposed for callers to compute) and a new path through `EventRepo`. Scope creep for a low-frequency failure mode.
2. The `--repair-event` flag is explicit operator action. An operator running recovery knows what they're doing and wants visibility; a silent retry-succeeds path hides a rare-but-important audit-completion event from logs.

If step-6 failures turn out to be common in practice, a follow-up PR can add deterministic event IDs as the next layer of defense. Scope it when we see the problem, not speculatively.

**Test for this recovery procedure:** see Section 6.13.

### 5.5b The lock-held region — `_repair_event_under_lock()` (repair path)

Dispatched from `ingest_cmd` when `--repair-event` is set. The repair path takes the same engagement lock as the normal path (Section 5.5) to serialize against concurrent collect/replay/ingest runs. It runs in this specific order:

1. **Load the committed manifest**: read `raw-output/manifests/<slug>.json` via the existing `load_raw_outputs()` helper (or a narrower single-slug read; implementation plan decides). If the file is missing, raise `click.UsageError(f"No ingested manifest found for slug {slug!r} under engagement {id}. There is nothing to repair; run `mseco ingest` normally.")` and exit 1.
2. **Validate the manifest is ingest-originated**: assert `raw.source_mode == "ingested"` and `raw.ingest_provenance is not None`. If either check fails (the slug came from `collect()`, not `ingest`), raise `click.UsageError(f"Slug {slug!r} was collected, not ingested. The raw_output_ingested event does not apply to collected data.")` and exit 1.
3. **Check whether the event already exists** (idempotency): query `EventRepo` (a new helper method `find_raw_output_ingested(engagement_id, tool_slug, ingested_at)` or an ad-hoc filter over `EventRepo.list(engagement_id)`) for an existing `raw_output_ingested` event whose payload's `tool_slug == raw.tool_slug` and whose `created_at` is >= `raw.ingest_provenance.ingested_at`. If found, print a success message — "`raw_output_ingested` event already present in the journal; no action taken." — and exit 0 without emitting anything. This makes repeated `--repair-event` invocations safe.
4. **Emit the missing event** with values read verbatim from the committed manifest:
    ```python
    prov = raw.ingest_provenance
    orchestrator.record_raw_output_ingested(
        engagement_id=engagement_id,
        actor=prov.ingested_by,         # e.g. "human:rickp" from original ingest
        tool_slug=raw.tool_slug,
        source_path=prov.source_path,    # original absolute path operator passed
        file_count=len(raw.file_manifest),
        replaced=prov.replaced,          # original committed audit value
    )
    ```
5. **Explicitly do NOT touch any filesystem state.** The repair path never calls `save_ingested_raw_output`, never calls `ingest_from_directory`, never calls `reset_for_rerun`, never rewrites the manifest, and never stages or copies files. The committed manifest and artifacts are byte-identical before and after repair — `sha256` over the manifest file is unchanged.
6. **Print a success message** confirming which event was emitted, with the original `ingested_at` and `ingested_by` values for audit confirmation.

**Explicit non-guarantees of `--repair-event`:**
- It does NOT verify that the files under `raw-output/artifacts/<slug>/` still exist or still match `file_manifest` hashes. Filesystem corruption is a separate failure mode and is the responsibility of replay's confinement/validate_raw checks. `--repair-event` repairs the audit journal, not the filesystem.
- It does NOT repair any other missing events (e.g., a missing `rerun` event from a step-4 failure that somehow escaped the rollback). It repairs exactly the `raw_output_ingested` event.
- It does NOT accept `--from`, `--replace`, `--schema-version`, or `--run-at` (Section 5.2 mutual exclusion). Any of those flags being set with `--repair-event` is a `click.UsageError`.

**LockTimeoutError handling** uses `e.timeout_seconds` only (the exception type at `errors.py:216` has no `lock_path` attribute):

```python
except LockTimeoutError as e:
    console.print(
        f"[bright_red]Error:[/bright_red] Engagement {engagement_id!r} is "
        f"locked by another process (concurrent CLI or review UI). "
        f"Lock acquisition timed out after {e.timeout_seconds}s. "
        f"See runbook section 9 for lock troubleshooting."
    )
    raise SystemExit(1) from None
```

### 5.6 New `EventType` and Orchestrator wrapper

Add `"raw_output_ingested"` to the `EventType` Literal at `pipeline/state.py:28` (same pattern as PR #74's extension for narrative/render/tracking events). Derived `_VALID_EVENT_TYPES` at line 44 picks it up automatically.

Add public wrapper on `Orchestrator`:

```python
def record_raw_output_ingested(
    self,
    *,
    engagement_id: str,
    actor: str,
    tool_slug: str,
    source_path: str,
    file_count: int,
    replaced: bool,
) -> None:
    """Record a raw_output_ingested event in the engagement journal.

    Called by the ingest CLI command after a successful save_ingested_raw_output.
    Must be called under the engagement lock; does not acquire or release it.

    The actor convention matches PipelineEvent.actor: "human:<operator>" for
    manual ingest. This is the only public entry point that writes this event
    type; other layers MUST NOT call _emit_event("raw_output_ingested", ...)
    directly.
    """
    self._emit_event(
        engagement_id,
        "raw_output_ingested",
        actor,
        {
            "tool_slug": tool_slug,
            "source_path": source_path,
            "file_count": file_count,
            "replaced": replaced,
        },
    )
```

This wrapper is the single public entry point for writing `raw_output_ingested` events. Layering discipline: no other caller reaches into `_emit_event` with that event type.

### 5.7 Runbook scenario 3 update (part of this PR)

`docs/runbook.md:144-197` — the "Client-Provided Pre-Collected Output Ingestion" section gets updated to:

- Remove the "(see issue #78 -- command not yet implemented)" note for the 5 supported adapters
- Remove the "Until `mseco ingest` is available:" manual-workaround paragraph for those same 5 adapters
- Add a concrete example showing a 2-tool supported ingest workflow (ScubaGear + Maester are the most common case)
- **Explicitly document that Monkey365 and M365-Assess ingest is NOT yet supported** and still requires the manual-manifest-construction workaround the original runbook section described. The runbook should name both adapters, cite the freshness-ambiguity reason ("their live collectors use pre-run filesystem snapshots that ingest has no way to reconstruct"), and point at the follow-up issue tracking the proper design.
- Add a caveat about the pick-first-match UX tradeoff (applies only to the 5 supported adapters)
- Add a caveat about `--run-at` / assessment-date
- Document the `--repair-event` recovery flag and when to use it: only when a normal ingest exited with the "audit event could not be recorded" error. Emphasize the operator MUST use `--repair-event` rather than `--replace` for that recovery, because `--replace` would rewrite the committed manifest with new timestamps. Cross-reference runbook section 9 (lock troubleshooting) and Section 5.5a/5.5b of this design.

## Section 6: Testing strategy

### 6.1 New test files

- `tests/unit/cli/test_ingest_cmd.py` — CLI unit tests (enumerated in Section 6.6 and Section 6.13)
- `tests/unit/adapters/test_build_collection_output.py` — shared helper (validation, sorting, target_relpath checks, empty items rejection)
- **`tests/unit/adapters/test_<each>_ingest.py`** — one file per **ingest-supporting** adapter (5 files: ScubaGear, Maester, Prowler, Azure Advisor, Secure Score). Each file contains the adapter's `ingest_from_directory` happy path + error paths + `default_schema_version` parity test. Monkey365 and M365-Assess do NOT get ingest test files (those two don't implement `ingest_from_directory` in this PR).
- **`tests/unit/adapters/test_<each>_collect_parity.py`** — one file per **refactor-affected** adapter (7 files: all the built-in adapters). Each file contains the collect() parity test proving the `build_collection_output` extraction is behavior-preserving. These are separate from the ingest test files because the refactor covers all 7 adapters even though ingest only covers 5.
- `tests/integration/test_ingest_flow.py` — 4 end-to-end scenarios

### 6.2 Existing test files to extend

- `tests/unit/core/test_models.py` — `IngestProvenance` validators, `RawToolOutput` source_mode invariant, 1.0.0→1.1.0 backward read
- `tests/unit/core/test_types.py` — `IngestCapableAdapter` Protocol `isinstance` checks
- `tests/unit/core/test_constants.py` — `MANIFEST_VERSION_CURRENT`, `RECOGNIZED_MANIFEST_VERSIONS`, allowlist entries
- `tests/unit/adapters/test_adapter_registry.py` — capability-consistency check
- `tests/unit/persistence/test_artifacts.py` — `save_ingested_raw_output` happy path, four rollback cases, other-tools isolation, `replace=True` semantics, **legacy-migration fallback (Section 6.11)**
- `tests/unit/pipeline/test_orchestrator.py` — `record_raw_output_ingested` forwarding test
- `tests/unit/pipeline/test_replay.py` — case loading a 1.1.0 `source_mode="ingested"` manifest
- `tests/unit/pipeline/test_confinement.py` — `RECOGNIZED_MANIFEST_VERSIONS` gate accepts 1.1.0
- `tests/unit/cli/test_helpers.py` — `resolve_enabled_adapter`, `require_ingest_capable`, `get_engagement_lock`
- **`tests/unit/cli/test_engagement_create.py` (new if not present, or extend existing)** — engagement create bootstrap behavior (Section 6.12): directory provisioned, config_snapshot.json mirrored, orphan-row rollback on filesystem failure

### 6.3 Property-based parity tests (the merge gate for the refactor)

Per-adapter parity tests in `tests/unit/adapters/test_<adapter>_ingest.py`. Each test mocks the tool invocation to copy a fixture file into `output_dir`, runs the refactored `collect()`, and asserts the produced `CollectionOutput` against fixture-derived expected values.

**Source_path handling**: do NOT assert `Path(artifact.source_path).resolve() == fixture_file.resolve()`. The mock copies fixture bytes into `output_dir`, so the produced `source_path` points at the staged file, not the original fixture. Assert basename, hash, and "path is under the staged output dir":

```python
assert Path(artifact.source_path).name == fixture_file.name
assert Path(artifact.source_path).is_relative_to(tmp_path / "output")
assert artifact.sha256 == expected_sha
```

**No committed JSON snapshots.** The platform-native absolute `source_path` strings would vary by machine; committed snapshots would fail on every run on a different checkout root.

**Per-adapter special handling:**

- **Monkey365**: fixture has some pre-existing files (simulated via dropping them into `output_dir` before the mocked tool call) and some new files (copied in by the mock). Assert only the new files appear in the `CollectionOutput`. This proves freshness filtering is preserved.
- **M365-Assess**: fixture has CSVs with controlled mtimes; the mock touches some of them; assert only the touched ones make it into the output. Plus the controls/ root assertion.
- **Prowler**: fixture has the correctly-named `<_DEFAULT_OUTPUT_FILENAME>.ocsf.json` plus an unrelated `other.ocsf.json`; assert only the correctly-named file is collected.

### 6.4 Four mandatory rollback tests (the merge gate for persistence atomicity)

All in `tests/unit/persistence/test_artifacts.py`. Each monkey-patches `Path.rename` to make the second (manifest) rename fail after the first (artifacts) succeeds:

| Test | Pre-call state | Assert post-rollback |
|---|---|---|
| `test_rollback_case_a_fresh_ingest` | neither exists | neither exists; no aside paths; `PersistenceError` raised |
| `test_rollback_case_b_both_existed` | both exist | both restored byte-identical |
| `test_rollback_case_c_artifacts_only` | orphan artifacts | artifacts restored, no manifest present |
| `test_rollback_case_d_manifest_only` | orphan manifest | manifest restored, no artifacts present (the case a naive rollback breaks) |

Plus a `test_rollback_itself_fails` case: both the second rename AND the rollback restore fail; assert `PersistenceError`, assert the error log, assert aside paths still exist.

**These tests are required merge gates for this PR.** Section 4's single-slug atomicity claim lives in them.

### 6.5 Per-adapter `default_schema_version` parity tests

One test per **ingest-supporting** adapter (5 adapters) asserting `adapter.default_schema_version == <hardcoded expected value>`. The expected value is written inline in the test, not read from the same constant the adapter uses — so drift between the two values is caught by the test:

```python
# test_scubagear_ingest.py
def test_default_schema_version_matches_collect():
    assert ScubaGearAdapter().default_schema_version == "1.7.1"

# test_maester_ingest.py
def test_default_schema_version_matches_collect():
    assert MaesterAdapter().default_schema_version == "1.0.0"

# test_prowler_ingest.py
def test_default_schema_version_matches_collect():
    assert ProwlerAdapter().default_schema_version == "<existing _SCHEMA_VERSION>"

# test_azure_advisor_ingest.py
def test_default_schema_version_matches_collect():
    assert AzureAdvisorAdapter().default_schema_version == "2025-01-01"

# test_secure_score_ingest.py
def test_default_schema_version_matches_collect():
    assert SecureScoreAdapter().default_schema_version == "<existing _SCHEMA_VERSION>"
```

Plus a **negative** test asserting that Monkey365 and M365-Assess do NOT declare `"ingest"` in their `capabilities` frozenset and do NOT have a `default_schema_version` attribute (those are the two adapters excluded by the Section "Non-goals" scope reduction — the test pins that exclusion so a future well-intentioned "add ingest to every adapter" change is caught):

```python
# tests/unit/adapters/test_adapter_capabilities.py (extend existing file)
def test_monkey365_has_no_ingest_capability():
    adapter = Monkey365Adapter()
    assert "ingest" not in adapter.capabilities
    assert not hasattr(adapter, "default_schema_version") or adapter.default_schema_version == ""
    assert not hasattr(adapter, "ingest_from_directory")

def test_m365_assess_has_no_ingest_capability():
    adapter = M365AssessAdapter()
    assert "ingest" not in adapter.capabilities
    assert not hasattr(adapter, "default_schema_version") or adapter.default_schema_version == ""
    assert not hasattr(adapter, "ingest_from_directory")
```

Rationale for the negative tests: the scope exclusion is a deliberate safety line from Codex Finding 2. If someone in a later PR adds ingest to these adapters without addressing the freshness-ambiguity problem, the negative test forces them to confront the deletion and (presumably) also delete the Non-goals paragraph that explains why the exclusion existed.

### 6.6 CLI unit tests

All CLI unit test cases go in `tests/unit/cli/test_ingest_cmd.py`. Each uses Click's `CliRunner` to invoke `ingest_cmd` with mocked dependencies.

1. Invalid `engagement_id` format → exit 1, no mutation
2. `--from` is a symlink → exit 1, no mutation
3. `--schema-version` empty / control chars / too long → exit 1 per case
4. `--run-at` unparseable → exit 1
5. `--run-at` omitted → warning printed, `utc_now()` used
6. Engagement missing from DB → exit 1, no mutation
7a. Legacy engagement (`engagement_row['engagement_dir'] IS NULL` in the DB AND the on-disk directory is missing): `save_ingested_raw_output` is invoked with the three legacy-migration kwargs (`client_name`, `engagement_row`, `engagement_repo`) and is mocked to return success (the persistence-layer migration logic is covered in Section 6.11). Assert: exit 0, and all three migration kwargs are passed through verbatim. The CLI MUST NOT call `get_engagement_dir` before invoking `save_ingested_raw_output`, because that pre-check would short-circuit the legacy-migration path (Finding 2 regression fence).
7b. Post-PR corruption (`engagement_row['engagement_dir']` populated but the directory is missing): `save_ingested_raw_output` is mocked to raise `PersistenceError` with "filesystem corruption or manual deletion" and the `mseco engagement purge` recovery hint in the message. Assert: exit 1, the CLI surfaces the underlying message verbatim (including the purge hint), no lock leaked, no retry loop.
8. `--tool` disabled in config → exit 1, no lock acquired
9. Unknown `--tool` slug → exit 1, UsageError lists available slugs
10. Adapter lacks `"ingest"` capability → exit 1
11. Happy path (fresh ingest) → exit 0, `save_ingested_raw_output(replace=False)`, `reset_for_rerun(PARSE)`, `record_raw_output_ingested(replaced=False)`
12. Happy path with `--replace` → exit 0, `replace=True`, `replaced=True` in event
13. Conflict without `--replace` → exit 1, lock released, nothing mutated
14. Adapter `ingest_from_directory` raises `CollectionError` → exit 1, no mutation
15. Pre-commit `validate_raw` raises → exit 1, `save_ingested_raw_output` never called, nothing mutated
16. `save_ingested_raw_output` raises `PersistenceError` → exit 1
17. `LockTimeoutError` → exit 1, runbook section 9 pointer
18. `--operator` override → provenance and event actor reflect the override

### 6.7 Integration tests

`tests/integration/test_ingest_flow.py`, 4 scenarios. All use supported adapters only (ScubaGear, Maester, Prowler, Azure Advisor, Secure Score):

1. **Single-tool ingest + replay** — create engagement, ingest scubagear from fixture, assert state is COLLECTED, replay `--from parse` with `--qa-strategy noop` for determinism, assert findings landed.
2. **Multi-tool mixed** — live-collect maester (mocked subprocess), ingest scubagear from fixture, assert both coexist, maester's manifest unchanged, scubagear's manifest shows `source_mode="ingested"`.
3. **Replace path** — ingest scubagear, ingest again with `--replace` and different content, assert new files in place, two separate `raw_output_ingested` events in the journal.
4. **Runbook scenario 3 end-to-end for supported adapters** — reproduce the exact command sequence from the updated runbook for the 5 supported adapters. A realistic operator workflow: `engagement create` → `ingest --tool scubagear` → `ingest --tool maester` → `replay --from parse --qa-strategy noop`. Assert the pipeline reaches RENDERED state with findings from both tools.

All integration tests pin `--qa-strategy noop` explicitly for determinism even though `pyproject.toml:50` currently registers only noop — future QA strategies shouldn't be able to make these tests flaky.

**Explicit non-test:** no integration test attempts to ingest Monkey365 or M365-Assess. If someone adds `"ingest"` capability to those adapters in a future PR without addressing the freshness ambiguity problem, the negative tests from Section 6.5 (`test_monkey365_has_no_ingest_capability`, `test_m365_assess_has_no_ingest_capability`) will fail before this integration layer is even exercised.

### 6.8 `record_raw_output_ingested` test scope

The test asserts that the public wrapper forwards `actor` and `payload` correctly to `_emit_event`, NOT that it enforces actor format. `PipelineEvent.__post_init__` at `state.py:66` validates only `event_type`, not actor syntax. If actor format enforcement is desired, that's a separate code change.

Two tests:
- `test_record_raw_output_ingested_forwards_to_emit_event`: assert event shape (event_type, actor, payload) matches inputs.
- `test_record_raw_output_ingested_rejects_invalid_event_type` (sanity): direct `PipelineEvent` construction with `"raw_output_ingested"` must not raise after the PR; direct construction with a bogus type still raises.

### 6.9 Convention checks

- **mypy**: `cli/commands/ingest.py` passes type-check. The `require_ingest_capable` narrowing works because `IngestCapableAdapter` is `@runtime_checkable`.
- **ruff**: new file passes repo's ruleset.
- **Line count**: `cli/commands/ingest.py` stays under the 400-line-per-file target from `CLAUDE.md`.
- **Datetime convention**: existing test at `tests/conventions/test_datetime_conventions.py` already bans `datetime.fromisoformat` / `datetime.now` / `datetime.utcnow` outside `datetime_utils.py`; the new file must pass it.

### 6.10 What this PR explicitly does NOT test

- **Write-side canonical path enforcement for `raw-output/`** — broader pre-existing repo concern, follow-up issue.
- **Ingest stricter than collect's discovery quirks** — follow-up `--strict` mode issue if operators hit it.
- **Ingesting from `raw-output.tar.gz`** — out of scope per the issue.
- **Multi-tool ingest in a single invocation** — follow-up if operators ask for it.
- **Report layer showing `source_mode`** — follow-up issue.

### 6.11 Legacy migration fallback tests (from Section 4.2a)

New cases in `tests/unit/persistence/test_artifacts.py`:

1. `test_legacy_migration_provisions_dir_mirrors_snapshot_and_backfills_column`: pre-condition is a DB row with `engagement_dir IS NULL` and no on-disk directory (simulate by creating an engagement row via `repo.create()` with `engagement_dir=None` — the current default — and NOT calling `create_engagement_dir`). Call `save_ingested_raw_output` with a valid `CollectionOutput`, passing `client_name`, `engagement_row`, and `engagement_repo` as kwargs. Assert: (a) the engagement directory is created via `create_engagement_dir`, (b) `<engagement_dir>/config_snapshot.json` is written and its content round-trips to the original snapshot via `decode_config_snapshot`, (c) `EngagementRepo.update_engagement_dir` is called with the provisioned path and the DB column is now populated, (d) the raw output commit proceeds and succeeds, (e) a WARNING log line is emitted mentioning "legacy engagement" and "one-time migration". This test pins the Codex Finding 3 fix: without the backfill assertion (c), the test would pass even if backfill is silently omitted.
2. `test_legacy_migration_fails_if_dir_creation_fails`: same pre-condition, but monkey-patch `create_engagement_dir` to raise `OSError`. Assert `PersistenceError` raised, no raw output committed, no partial state on disk, `update_engagement_dir` was NOT called.
3. `test_legacy_migration_fails_if_strict_mirror_fails_and_cleans_up_dir`: same pre-condition, but monkey-patch `mirror_config_snapshot_from_db_strict` to raise `ConfigSnapshotMirrorError`. Assert: (a) `PersistenceError` raised, (b) no raw output committed, (c) the engagement directory created at the first step of migration is removed via `shutil.rmtree(..., ignore_errors=True)`, (d) `update_engagement_dir` was NOT called (the engagement_dir column remains NULL so the next ingest will retry from scratch), (e) the error message mentions "config_snapshot mirror write failed" and "Directory cleanup attempted".
4. `test_legacy_migration_fails_if_backfill_fails_and_rolls_back`: same pre-condition, but monkey-patch `update_engagement_dir` to raise `PersistenceError` after both `create_engagement_dir` and `mirror_config_snapshot_from_db_strict` have succeeded. Assert: (a) `PersistenceError` raised, (b) the just-created engagement directory is removed via `shutil.rmtree` (which also takes out the mirror file inside it), (c) the engagement_dir column remains NULL (rollback leaves it in pre-migration state), (d) no raw output committed, (e) the error message mentions "backfill of engagement_dir column failed".
5. `test_post_pr_engagement_with_missing_dir_fails_closed`: simulate a post-PR engagement (DB row has `engagement_dir="/path/to/eng-dir"` populated, but the directory was manually deleted). Call `save_ingested_raw_output` with the engagement_row containing the populated `engagement_dir` column. Assert: (a) `PersistenceError` raised, (b) the error message mentions `engagement_dir=...` from the DB and "filesystem corruption or manual deletion", (c) `create_engagement_dir` is NOT called (the migration branch is NOT entered), (d) no raw output committed, (e) the error message names the `mseco engagement purge` recovery option.
6. `test_post_migration_fails_closed_on_later_corruption`: the Codex Finding 3 regression fence. First, run the successful legacy migration from test 1 (engagement now has a populated `engagement_dir` column and a provisioned directory on disk). Then manually delete the directory (`shutil.rmtree(eng_dir)`) to simulate filesystem corruption or manual deletion AFTER migration. Then attempt a second ingest. Assert: (a) `PersistenceError` raised, (b) the error message mentions "filesystem corruption or manual deletion", (c) `create_engagement_dir` is NOT called (the migration branch does NOT re-enter), (d) no raw output committed. Before the Finding 3 fix, this test would have failed because the re-entered migration would silently recreate the directory and mask the data loss.
7. `test_legacy_migration_requires_migration_kwargs`: pre-condition is a DB row with `engagement_dir IS NULL` and no on-disk directory, but the caller does NOT pass `client_name`, `engagement_row`, or `engagement_repo`. Assert `PersistenceError` raised with a message naming "legacy migration requested but CLI did not supply migration context".

### 6.12 Engagement bootstrap tests (from Section 1a)

New cases in `tests/unit/cli/test_engagement_create.py` (or whatever test file currently covers `create_cmd`):

1. `test_create_provisions_engagement_dir`: happy path. After `mseco engagement create <config>`, assert the on-disk engagement directory exists with the expected subdirectories (`raw-output/manifests/`, `raw-output/artifacts/`, `reports/`).
2. `test_create_populates_engagement_dir_column`: after create, fetch the engagement row via `EngagementRepo.get(engagement_id)` and assert `row["engagement_dir"]` is a non-None string matching the on-disk directory path. This is the load-bearing assertion for Section 4.2a's legacy-vs-corruption discriminator — if this test fails, legacy migration will incorrectly fire on post-PR engagements.
3. `test_create_mirrors_config_snapshot`: after create, assert `<engagement_dir>/config_snapshot.json` exists and its content round-trips through `decode_config_snapshot` back to an equivalent `EngagementConfig`.
4. `test_create_uses_strict_mirror_helper`: assert that `create_cmd` calls `mirror_config_snapshot_from_db_strict`, NOT the fail-open `mirror_config_snapshot_from_db`. Verify by monkey-patching `mirror_config_snapshot_from_db_strict` to raise and asserting the command fails; then monkey-patching `mirror_config_snapshot_from_db` (fail-open) to raise and asserting the command still fails (because strict is called, not fail-open).
5. `test_create_rolls_back_on_dir_provision_failure`: monkey-patch `create_engagement_dir` to raise `OSError` after the DB insert. Assert: (a) the command fails with a clean error message, (b) `EngagementRepo.get(engagement_id)` raises `PersistenceError` (row was deleted), (c) no directory was left on disk.
6. `test_create_rolls_back_on_mirror_failure_including_dir_cleanup`: monkey-patch `mirror_config_snapshot_from_db_strict` to raise after `create_engagement_dir` succeeds. Assert: (a) the command fails with a clean error message naming the mirror step, (b) the DB row is deleted, (c) the newly-created engagement directory is removed via `shutil.rmtree` (best-effort). This is the test for Finding 2's filesystem-cleanup requirement.
7. `test_create_rollback_is_idempotent_if_dir_already_cleaned`: same as test 6, but the directory has already been partially removed by a concurrent hand cleanup. Assert the rollback's `shutil.rmtree(..., ignore_errors=True)` does not raise and the final state is still clean.
8. `test_create_idempotent_on_prior_partial_state`: simulate an engagement directory that exists from a prior failed create attempt (directory present, no DB row). Run `engagement create` again with the same config. Assert it either cleanly succeeds (by reusing the existing directory and creating a new DB row with a new UUID) or cleanly fails with a message directing the operator to delete the stale directory first. (Implementation plan decides which behavior is correct; document the choice.)

### 6.13 Partial-ingest recovery and `--repair-event` tests (from Section 5.5a/5.5b)

All in `tests/unit/cli/test_ingest_cmd.py`. These collectively pin the Codex Finding 3 fix — the recovery path must be audit-neutral.

1. `test_step_6_failure_surfaces_repair_event_hint`: mock `record_raw_output_ingested` to raise `PersistenceError` AFTER `save_ingested_raw_output` succeeds. Assert the command exits 1 and the stderr/error message:
   - Names `--repair-event` as the recovery procedure (not `--replace`).
   - Explicitly warns against using `--replace` for this recovery, with a one-line explanation that `--replace` would rewrite the committed manifest with a new timestamp.
   - States that the replay pipeline still works in the meantime.
   Also assert that the committed manifest on disk is unchanged (no rollback; Phase 3 committed successfully before step 6 failed).

2. `test_repair_event_happy_path`: set up a committed `source_mode="ingested"` manifest on disk with a known `IngestProvenance(source_path="/tmp/original-from", ingested_at=<T0>, ingested_by="human:alice", replaced=True)`. Capture the manifest file's sha256 before the repair run. Invoke `mseco ingest <id> --tool <slug> --repair-event`. Assert:
   - Exit 0.
   - `save_ingested_raw_output` was NOT called (filesystem is not touched).
   - `ingest_from_directory` was NOT called (adapter walk is skipped).
   - `reset_for_rerun` was NOT called (engagement state is untouched).
   - `record_raw_output_ingested` WAS called exactly once with `actor="human:alice"`, `source_path="/tmp/original-from"`, `replaced=True`, and `file_count` matching the committed manifest's `len(file_manifest)`.
   - The manifest file's sha256 is byte-identical to the pre-repair value.
   - The engagement's last state-transition timestamp is unchanged (no state mutation side effects).

3. `test_repair_event_is_idempotent_when_event_already_present`: same committed manifest as test 2, but the `raw_output_ingested` event for this slug is already in the journal (simulate a prior successful repair). Invoke `--repair-event` again. Assert:
   - Exit 0.
   - `record_raw_output_ingested` was NOT called (idempotent no-op).
   - Stdout contains a clear "already present in the journal; no action taken" message.
   - Journal still has exactly one `raw_output_ingested` event for this slug (no duplicate).

4. `test_repair_event_rejects_missing_manifest`: no committed manifest exists for the slug. Invoke `--repair-event`. Assert exit 1, error message includes `"No ingested manifest found for slug"`, and `record_raw_output_ingested` was NOT called.

5. `test_repair_event_rejects_collected_manifest`: set up a committed manifest with `source_mode="collected"` (no `ingest_provenance`). Invoke `--repair-event`. Assert exit 1, error message mentions `"was collected, not ingested"`, and `record_raw_output_ingested` was NOT called.

6. `test_repair_event_rejects_conflicting_flags`: invoke with each of the mutually-exclusive flag combinations and assert each one exits 1 with a `click.UsageError`-style message naming the conflicting flag:
   - `--repair-event --from /some/path`
   - `--repair-event --replace`
   - `--repair-event --schema-version 1.2.3`
   - `--repair-event --run-at 2026-04-11T00:00:00Z`

7. `test_repair_event_preserves_committed_provenance_exactly`: this is the direct Finding 3 regression fence. Set up a committed manifest with `IngestProvenance(ingested_at=<T0 from 2 days ago>, ...)` and `RawToolOutput.timestamp=<T0>`. Invoke `--repair-event` at a later wall-clock time (mock `utc_now()` to return `<T0 + 2 days>`). Assert:
   - The committed manifest bytes are unchanged (re-read and compare to a pre-repair snapshot byte-for-byte).
   - The emitted event's `created_at` reflects the repair time (`<T0 + 2 days>`, because SQLite stamps it), but the payload's `source_path`, `tool_slug`, `file_count`, and `replaced` all reflect committed values from `<T0>`.
   - `RawToolOutput.timestamp` on the committed manifest is still `<T0>`, not `<T0 + 2 days>`.
   Before the Finding 3 fix, the `--replace` retry path would have rewritten all three timestamps; this test would have caught that by reading the manifest bytes and comparing. With the `--repair-event` fix, it passes.

8. `test_repair_event_takes_engagement_lock`: assert that the repair path acquires and releases the engagement lock exactly once per invocation (same as the normal path). Use a lock-observer fixture to verify.

## Future work

- **Ingest support for Monkey365 and M365-Assess.** The adapters excluded from this PR by Section "Non-goals" need a proper freshness-safe design before ingest can be added. Open design questions: (a) require operators to provide a clean single-run export directory (documentation contract, no code enforcement — matches current Option A rationale); (b) operator-supplied `--file` arguments listing the exact files to include (clunky for Monkey365's multi-file output but eliminates the ambiguity); (c) timestamp-based grouping for adapters whose filenames include timestamps; (d) a new "single-run export" adapter contract that the tool runners themselves can emit in a well-defined shape. Whichever direction wins, the follow-up issue should explicitly restate the silent-stale-data failure mode as the problem being solved so it doesn't regress.
- `--strict` flag on `mseco ingest` that rejects ambiguous adapter discovery for the 5 supported adapters too (e.g., multiple ScubaResults*.json files). Complements the pick-first-match current behavior.
- Multi-tool ingest in a single invocation for engagements where the client sends a single archive containing multiple tools' output.
- Ingesting from a `raw-output.tar.gz` archive (mirrors `ArtifactManager.restore`).
- Propagating `source_mode` / `ingest_provenance` into `ResolvedManifest` and the report payload so downstream consumers can distinguish collected vs. ingested data.
- Reconciling the M365-Assess `script_path` / `script` allowlist mismatch at `adapters/m365_assess/adapter.py:307` vs `core/domain/constants.py:170`.
- Write-side canonical path enforcement for `raw-output/` (symlink + non-canonical-subtree rejection at write time, matching replay's read-time confinement).
- **`mseco engagement migrate` batch command** — backfill `engagements.engagement_dir` for all legacy rows that have a matching directory on disk but no first-ingest-driven migration yet. After the Section 4.2a backfill fix (Codex Finding 3), the per-ingest migration is one-shot and durable, so the batch command is a nice-to-have for operators who want to clean up all legacy rows at once without ingesting into each one. Out of scope for this PR because the per-ingest migration already handles the correctness case.
