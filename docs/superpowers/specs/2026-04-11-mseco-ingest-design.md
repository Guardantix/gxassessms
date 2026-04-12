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
2. Apply to all 7 collection-capable built-in adapters (ScubaGear, Maester, Monkey365, M365-Assess, Prowler, Azure Advisor, Secure Score).
3. Record unambiguous audit provenance distinguishing ingested manifests from live-collected ones, at the manifest level, so reviews months later can tell how the data arrived.
4. Preserve the `save_raw_outputs()` / replay trust boundary: ingest is a write-side convenience, not a relaxation of replay's read-side validation.
5. Update runbook scenario 3 to reference the new command.

## Non-goals

- **Ingesting from a `raw-output.tar.gz` archive** — covered by the existing archive/restore path; out of scope here.
- **Multi-tool ingest in a single invocation** — one `--tool` per call; operators run it 3× for a 3-tool engagement. Keeps the error surface tight.
- **Stricter ingest-time discovery than live collect** — ingest inherits each adapter's pick-first-match and other quirks verbatim. See Section 3.2 for the UX tradeoff.
- **Propagating `source_mode` into `ResolvedManifest` / reports** — collected vs. ingested is recorded on `RawToolOutput` at the storage layer, but the pipeline-internal `ResolvedManifest` does not carry the distinction. If reports need to surface it later, that's a follow-up.
- **Write-side canonical path enforcement for `raw-output/`** — a broader pre-existing repo concern, not introduced by ingest.

## Architecture overview

`mseco ingest` is an operator-driven, filesystem-only command. It does not invoke any tool, authenticate to any tenant, or fetch data over the network. Its job is to accept a directory of client-provided raw output, hash the files, build the `RawToolOutput` manifest the replay machinery needs, commit it atomically alongside any existing data in the engagement directory, and reset the engagement state so downstream pipeline stages know the raw output is fresh.

The design has seven coordinated pieces across the layers:

1. **Engagement bootstrap fix** (`cli/commands/engagement.py`): `mseco engagement create` is extended to provision the on-disk engagement directory AND write the `config_snapshot.json` mirror immediately after inserting the DB row, with an orphan-row rollback if filesystem provisioning fails. This is the foundation that lets ingest-only engagements work end-to-end and is the single place where the replay DR snapshot path gets seeded for both collect and ingest workflows.
2. **Data model** (`core/domain/models.py`, `core/domain/constants.py`): two new optional fields on `RawToolOutput` plus a new `IngestProvenance` model, gated by a `manifest_version` bump from `"1.0.0"` to `"1.1.0"` that preserves backward-read compatibility for existing engagements on disk.
3. **Shared adapter helper** (`adapters/_base.py`): new module-level `build_collection_output()` that hashes a pre-computed list of `(source_path, target_relpath)` pairs and assembles a `CollectionOutput`. Used by both live `collect()` and the new ingest path. Discovery and freshness filtering stay in each adapter's `collect()` exactly as today.
4. **Per-adapter ingest method** (`adapters/<tool>/adapter.py`): new `ingest_from_directory()` method on each of the 7 adapters, implementing the same file-walk logic as live collect but without freshness filtering (since ingest has no "before" snapshot).
5. **Protocol extension** (`core/contracts/types.py`): new `IngestCapableAdapter(ToolAdapter, Protocol)` adding `ingest_from_directory()` and a `default_schema_version: str` class attribute, plus an `"ingest"` entry in `AdapterCapability`.
6. **Persistence layer** (`persistence/artifacts.py`): new `save_ingested_raw_output()` method on `ArtifactManager`, providing atomic single-slug writes (unlike the existing full-generation-swap `save_raw_outputs()`), fail-closed on missing engagement directory for the normal path, with a narrow legacy-migration fallback that auto-provisions for engagements created before this PR, and a per-side rollback on commit failure.
7. **CLI command** (`cli/commands/ingest.py`, `cli/main.py`, `cli/_helpers.py`, `pipeline/orchestrator.py`, `pipeline/state.py`): the `mseco ingest` Click command, new canonical helpers (`resolve_enabled_adapter`, `require_ingest_capable`, `get_engagement_lock`), a new `"raw_output_ingested"` `EventType` variant and public `record_raw_output_ingested` orchestrator wrapper, and state reset via `reset_for_rerun(Stage.PARSE)` ordered **before** the filesystem commit so any commit failure leaves the engagement in a cleanly retryable state.

## Section 1: End-to-end flow

**Bootstrap precondition (new, from the engagement create fix in Section 1a):** After `mseco engagement create` succeeds, the engagement has (a) a DB row, (b) an on-disk `<engagement_dir>/` with `raw-output/manifests/`, `raw-output/artifacts/`, and `reports/` subdirectories, and (c) a `<engagement_dir>/config_snapshot.json` mirror that `replay` can use for DR recovery. Ingest assumes this precondition and does not re-provision it on the normal path; a narrow legacy-migration fallback in `save_ingested_raw_output` handles engagements created before this PR.

```
1. CLI arg validation (before any I/O)
   - engagement_id matches ENGAGEMENT_ID_PATTERN (same gate as replay)
   - --tool is a non-empty string (further checked in step 4)
   - --from path exists, is a directory, is not a symlink, is readable
   - --schema-version (if passed): non-empty, no control chars, <= 64 chars
   - --run-at (if passed): parseable via parse_utc (handles Z, +00:00, naive-as-UTC)
   - --operator (if passed): sanitized for the PipelineEvent actor field
     (default: getpass.getuser(), fallback "unknown")

2. Engagement lookup (DB-required, NO filesystem fallback)
   - EngagementRepo.get(engagement_id): raises PersistenceError if missing
   - ArtifactManager.get_engagement_dir(engagement_id): raises if no on-disk dir
     - Normal case: the dir exists because `engagement create` provisioned it.
     - Legacy case: the dir is missing because the engagement was created
       before this PR landed. Ingest does NOT fail here; the missing-dir
       branch is handled inside save_ingested_raw_output's migration
       fallback (Section 4.2a).
   - EngagementConfig.model_validate(decode_config_snapshot(row))

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
     - With --replace: remember replaced=True for the event payload

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
     on DB failure, which is the split-brain case Codex Finding 3 called
     out.

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
- **DB writes bracket the filesystem commit.** State reset happens BEFORE the filesystem commit (idempotent and safely retryable if commit fails); event emission happens AFTER (the one failure mode that requires an explicit retry-with-replace recovery, documented in Section 5.5a).
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

1. Validate the config file (unchanged from today).
2. **NEW:** Compute the engagement directory path via `artifact_manager.create_engagement_dir(engagement_id, client_name)` AFTER but atomically with the DB row creation. The creation order is: (a) generate engagement_id via `uuid.uuid4()`, (b) compute the expected directory path (same `_sanitize_slug(client_name)-<id>` logic `artifacts.py:158` uses), (c) insert the DB row via `EngagementRepo.create(..., engagement_dir=<computed path>)` so the `engagement_dir` column is populated from the start, (d) actually create the directory tree on disk, (e) write the config snapshot mirror.
3. **NEW:** Call `mirror_config_snapshot_from_db_strict(engagement_repo, artifact_manager, engagement_id)` to write `<engagement_dir>/config_snapshot.json`.
4. **NEW orphan-row + orphan-directory rollback:** If any step between (c) and (e) fails, the rollback must:
    1. Best-effort `shutil.rmtree(engagement_dir, ignore_errors=True)` — clean up any partially-created directory tree. Skipped if the directory wasn't created yet.
    2. `engagement_repo.delete(engagement_id)` — removes the row from `engagements` and all child tables in dependency order, using the existing method at `engagement_repo.py:237`. No new delete helper needed.
    3. Re-raise as a `GxAssessError` with a message that names which step failed.
    The user sees a single clean error and the engagement never exists in a half-bootstrapped state on disk or in the DB.

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

- `cli/commands/engagement.py` — `create_cmd` gets the new provision + mirror + rollback logic. Estimated ~25 lines of additional code (the rollback logic is the bulk of it).
- `pipeline/config_snapshot_mirror.py` — new `mirror_config_snapshot_from_db_strict()` public function. Estimated ~10 lines (thin wrapper over the existing `_do_mirror`).

### 1a.6 What this does NOT change

- The lazy `save_raw_outputs` fallback at `artifacts.py:476` stays in place as-is. It's belt-and-suspenders for any write path that hits a missing-dir condition (which should now be impossible for freshly-created engagements but is still the safety net for legacy engagements that haven't hit their first write yet).
- Collect's fail-open `mirror_config_snapshot_from_db()` call at `_runner.py:84-97` stays in place with its existing signature and fail-open contract. It refreshes the mirror after every successful collect, which is the right behavior when the DB config changes between runs and when a mirror gap shouldn't block the pipeline.
- `EngagementRepo.create()`'s signature is unchanged; the `engagement_dir` parameter already exists and the CLI just starts passing a non-None value.
- The non-ingest path `engagement status` → `engagement create` → `engagement status` gets marginally different output (the second `status` call sees a directory that didn't exist before), but this is benign and not tested behavior today.

## Section 2: Data model changes

### 2.1 New `IngestProvenance` model

```python
class IngestProvenance(BaseModel):
    """Operator-visible provenance for ingested raw output.

    Present only on manifests written by `mseco ingest`. Records what the
    operator did, when they did it, and where the source data came from --
    enough audit trail to answer "where did this data come from" six months
    after the engagement.
    """

    model_config = ConfigDict(extra="forbid")

    source_path: str  # absolute path the operator passed to --from
    ingested_at: datetime  # UTC timestamp of the ingest call (NOT the tool run time)
    ingested_by: str  # PipelineEvent actor convention: "human:<operator>"

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

Ingest inherits each adapter's `collect()` discovery rules verbatim. The following table documents the discovery logic already in each adapter today; the refactor preserves it exactly.

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

Every adapter implementing the `"ingest"` capability declares this uniform public signature:

```python
def ingest_from_directory(
    self,
    source_dir: Path,
    *,
    schema_version: str,
    timestamp: datetime,
) -> CollectionOutput:
```

Single-root adapters (ScubaGear, Maester, Monkey365, Azure Advisor, Secure Score) do a simple directory scan matching `collect()`'s discovery rules (minus freshness filtering), build `items`, and call `build_collection_output(..., execution_metadata={})`.

**M365-Assess** uses an inferred `source_dir / "controls"`:

```python
def ingest_from_directory(self, source_dir, *, schema_version, timestamp):
    controls_dir = source_dir / "controls"
    if not controls_dir.is_dir():
        raise CollectionError(
            f"M365-Assess ingest: source must contain a 'controls/' subdirectory "
            f"alongside CSV output files; found no such directory under {source_dir}",
            adapter_name=self.tool_name,
        )
    csv_files = sorted(
        (f for f in source_dir.iterdir() if f.is_file() and f.name.endswith(_CSV_SUFFIX)),
        key=lambda f: f.name,
    )
    if not csv_files:
        raise CollectionError(
            f"M365-Assess ingest: no CSV files found directly under {source_dir}",
            adapter_name=self.tool_name,
        )
    control_files = [controls_dir / filename for filename in ("risk-severity.json", "registry.json")]
    missing = [f.name for f in control_files if not f.is_file()]
    if missing:
        raise CollectionError(
            f"M365-Assess ingest: missing required controls files in "
            f"{controls_dir}: {', '.join(missing)}",
            adapter_name=self.tool_name,
        )
    items = [
        *[(csv, f"{self.storage_slug}/{csv.name}") for csv in csv_files],
        *[(ctrl, f"{self.storage_slug}/controls/{ctrl.name}") for ctrl in control_files],
    ]
    return build_collection_output(
        tool=ToolSource.M365_ASSESS,
        tool_slug=self.storage_slug,
        items=items,
        schema_version=schema_version,
        timestamp=timestamp,
        execution_metadata={},
    )
```

**Prowler** passes the fixed output filename constant to match its rglob pattern; every adapter passes `execution_metadata={}` as a literal, not a default — this makes it mechanically impossible to forge provenance on the ingest path.

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

Each built-in adapter declares its `default_schema_version` as a class attribute:

| Adapter | `default_schema_version` | Source of the value |
|---|---|---|
| ScubaGear | `_SCHEMA_VERSION` (`"1.7.1"`) | existing constant at `scubagear/adapter.py:46` |
| Maester | `"1.0.0"` | literal, matching the inline hardcode at `maester/adapter.py:159` |
| Monkey365 | `_SCHEMA_VERSION` | existing constant |
| M365-Assess | `_SCHEMA_VERSION` | existing constant |
| Prowler | `_SCHEMA_VERSION` | existing constant |
| Azure Advisor | `_ADVISOR_API_VERSION` (`"2025-01-01"`) | existing constant at `azure_advisor/adapter.py:53` |
| Secure Score | `_SCHEMA_VERSION` | existing constant |

**Capability consistency check**: `_validate_adapter()` at `adapters/__init__.py:84` is extended so that an adapter declaring `"ingest"` in `capabilities` must have BOTH a callable `ingest_from_directory` attribute AND a non-empty `default_schema_version` string attribute. Adapters that declare the capability without fulfilling both requirements fail discovery and are excluded from the registry with a clear error message.

**`"ingest"` is added to `AdapterCapability`** at `constants.py:113` and to the `ADAPTER_CAPABILITIES` frozenset at line 122. All 7 built-in adapters add `"ingest"` to their `capabilities` frozenset.

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

1. **Phase 1 — validate all inputs (no I/O beyond hashing):** source file presence, hash match, canonical POSIX target_relpath, slug prefix, duplicate/case-collision checks (mirroring `save_raw_outputs` Phase 1).
2. **Phase 2 — stage to `.ingest-staging-<slug>-<uuid>/`:** copy files with hash-verified copies, write the manifest JSON to the staging directory. On any failure, `shutil.rmtree(staging_dir, ignore_errors=True)` and re-raise.
3. **Phase 3 — atomic per-slug commit:** rename-aside any existing slug data (if `replace=True`), then commit new artifacts first and manifest last (matching `save_raw_outputs` Phase 3 ordering).

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
    # provisioned. Provision it now as a one-time migration.
    logger.warning(
        "Legacy engagement %s has engagement_dir IS NULL and no on-disk "
        "directory; provisioning it now as a one-time migration. Future "
        "engagements created via `mseco engagement create` will have the "
        "directory provisioned at bootstrap time instead.",
        engagement_id,
    )
    eng_dir = self.create_engagement_dir(engagement_id, client_name)

    # Mirror the config_snapshot so replay's DR path works for this
    # engagement. Use the new STRICT variant (Section 1a.1) so any
    # mirror failure propagates up and we abort the ingest before any
    # raw output is committed. The existing fail-open helper would
    # silently log and return, leaving the operator thinking the
    # migration succeeded when the mirror is actually missing.
    from gxassessms.pipeline.config_snapshot_mirror import (
        mirror_config_snapshot_from_db_strict,
    )
    try:
        mirror_config_snapshot_from_db_strict(
            engagement_repo=engagement_repo,
            artifact_manager=self,
            engagement_id=engagement_id,
        )
    except ConfigSnapshotMirrorError as exc:
        # Best-effort cleanup of the directory we just created, then
        # re-raise as PersistenceError so the CLI's outer handler
        # produces a clean user-facing message.
        shutil.rmtree(eng_dir, ignore_errors=True)
        raise PersistenceError(
            f"Legacy migration failed for engagement {engagement_id}: "
            f"config_snapshot mirror write failed ({exc}). No raw output "
            f"was committed. Directory cleanup attempted."
        ) from exc

    # NOTE: updating the engagements.engagement_dir column to reflect
    # the newly-provisioned path is deliberately deferred to a follow-up
    # observation, NOT done here. Reasoning: this method's layer contract
    # is "filesystem writes only, no DB updates." The CLI layer OR a
    # one-shot migration command is the right place to backfill
    # engagement_dir for migrated legacy rows. See "Open question" below.
```

**Why this is narrow, not "relax the fail-closed rule entirely":**

- The `except PersistenceError` block only fires when the directory is missing. Every other failure mode (wrong permissions, partial state on disk, etc.) still falls through the original code path.
- The `engagement_dir IS NULL` check is the explicit legacy discriminator. Post-PR engagements have a non-null value in that column and go to the fail-closed branch. Legacy engagements have NULL and go to the migration branch.
- The legacy migration calls `create_engagement_dir()` AND `mirror_config_snapshot_from_db_strict()`. If either fails, the error propagates, the partially-created directory is cleaned up, and no raw output is written.
- The WARNING log line distinguishes a legacy-migration auto-provision from a first-write provision, so operators can tell the difference when reviewing logs months later.
- New engagements created via the fixed `engagement create` will never hit this path, because the directory is always already present AND `engagement_dir` is populated. Over time, the legacy branch becomes cold code, and the "engagement_dir is set but the directory is gone" branch becomes the only way to hit this error at all.

**What this is NOT:**

- This is NOT a general-purpose "auto-create if missing" behavior for `save_ingested_raw_output`. It is a one-shot migration gated on `engagement_dir IS NULL`. Filesystem corruption or manual deletion of a post-PR engagement directory hits the other branch and raises.
- It does NOT handle the case where the DB row itself is missing. That case is caught earlier at the CLI layer by `EngagementRepo.get(engagement_id)` and results in a clean user-facing error.

**Constructor wiring:** `ArtifactManager` does not currently hold a reference to `EngagementRepo` — the two are independent layers. The legacy migration path needs the engagement row AND a repo handle to call `mirror_config_snapshot_from_db_strict`. The CLI layer, which already holds both, passes them into `save_ingested_raw_output` as optional keyword arguments:

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

**Open question (flagged for implementation plan):** Should the legacy migration backfill `engagements.engagement_dir` after successful directory creation? Arguments for yes: the migration is meant to be one-shot per engagement, and backfilling means the next ingest call will hit the normal path instead of re-entering the migration branch (which is harmless but noisy). Arguments for no: updating the DB column means the method reaches into `EngagementRepo.update_engagement_dir(engagement_id, path)` (which doesn't exist today), crossing the layering line the rest of the method respects. Simpler alternative: leave the column NULL on legacy rows, accept that every ingest against a legacy engagement re-enters the migration branch until a no-op (the `create_engagement_dir` and mirror calls are idempotent), and provide a one-shot `mseco engagement migrate` command in a follow-up PR to batch-backfill `engagement_dir` for all legacy rows. Recommend the simpler alternative for this PR; flag the follow-up migrate command in Future Work.

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
    "--from", "source_path", required=True,
    type=click.Path(exists=True, file_okay=False, dir_okay=True, readable=True, resolve_path=False),
    help="Path to a directory containing this tool's raw output files, "
         "laid out as if the tool had just run against them.",
)
@click.option(
    "--replace", is_flag=True, default=False,
    help="Overwrite existing raw output for this tool in the engagement.",
)
@click.option(
    "--schema-version", "schema_version_override", default=None,
    help="Override the adapter's default schema_version string.",
)
@click.option(
    "--run-at", "run_at_arg", default=None,
    help="ISO-8601 UTC timestamp of when the client actually ran the tool. "
         "Defaults to the ingest time if omitted (reports will show ingest date).",
)
@click.option(
    "--operator", default=None,
    help="Operator identity recorded in the manifest provenance and event journal. "
         "Defaults to getpass.getuser().",
)
def ingest_cmd(...)
```

### 5.2 Validation details

- **`engagement_id`**: matches `ENGAGEMENT_ID_PATTERN` from `pipeline/state.py:94` (same gate as replay).
- **`--operator`**: defaults to `getpass.getuser()` with `OSError` fallback to `"unknown"`. Sanitized, non-empty-checked, wrapped as `f"human:{operator}"` before writing to `IngestProvenance.ingested_by` and the event actor field.
- **`--from`**: `source_dir = Path(source_path)` — rejected if `is_symlink()`, then `.expanduser().resolve()` to an absolute path, then `is_dir()` re-checked (defense-in-depth after resolve).
- **`--schema-version`**: optional free-form string, sanity-checked for non-empty-after-strip, no control characters, ≤64 chars. No PEP-440, no semver — adapters use various formats including date-like (`"2025-01-01"`), so validation must not be tighter than `RawToolOutput.schema_version: str` already enforces.
- **`--run-at`**: parsed via `parse_utc()` from `core/config/datetime_utils.py:16`. Handles `"Z"` suffix, `"+00:00"` offset, and naive-assumed-UTC. **`datetime.fromisoformat()` must not be called directly**; the convention test at `tests/conventions/test_datetime_conventions.py` bans it outside `datetime_utils.py`. Missing `--run-at` defaults to `utc_now()` with a yellow warning that reports will reflect the ingest date.

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

### 5.5 The lock-held region — `_ingest_under_lock()`

Kept as a separate helper so the lock acquisition stays narrow and readable. Runs in this specific order (see Section 1 step 8 for the rationale on DB-reset-before-filesystem-commit):

1. **Conflict check** (TOCTOU-safe inside the lock) — uses `artifacts.get_engagement_dir()` opportunistically; if the dir is missing (legacy migration case), the conflict check becomes "no prior state," which is correct.
2. **Adapter walk**: `ingest_adapter.ingest_from_directory(source_dir, schema_version=..., timestamp=run_at)`. Schema version resolution: `schema_version_override or ingest_adapter.default_schema_version`
3. **Pre-commit `validate_raw`**: build a throwaway `ResolvedManifest` with absolute source_paths as `file_manifest` keys, call `ingest_adapter.validate_raw(preflight_manifest)`. On failure, abort without mutating the engagement directory.
4. **DB state reset**: `orchestrator.reset_for_rerun(engagement_id, Stage.PARSE)` — resets the engagement state to `EngagementState.COLLECTED` (PARSE's entry state per `stages.py:386`). No-op when already at COLLECTED. Emits the existing `"rerun"` event via the orchestrator's standard path. **This runs BEFORE the filesystem commit**: if step 5 fails and Section 4.3's per-side rollback restores the pre-call filesystem state, the engagement is left at COLLECTED with its original raw output unchanged — a clean retry state. The alternative order (commit first, then reset) would leave committed filesystem data paired with stale DB state on DB failure, which is the split-brain case Codex Finding 3 called out.
5. **Atomic filesystem commit**: construct `IngestProvenance(source_path=str(source_dir), ingested_at=utc_now(), ingested_by=f"human:{operator}")`, call `artifacts.save_ingested_raw_output(engagement_id, collection_output, ingest_provenance=..., replace=..., client_name=client_name, engagement_row=engagement_row, engagement_repo=repo)`. The three legacy-migration kwargs (`client_name`, `engagement_row`, `engagement_repo`) are only consumed on the Section 4.2a legacy-migration path when `engagement_row["engagement_dir"] IS NULL` and the directory is missing; on the normal path they're unused.
6. **Dedicated ingest event**: `orchestrator.record_raw_output_ingested(...)` — new public wrapper. **This is the one step that can fail after the filesystem is committed**, producing the missing-audit-event failure mode documented in Section 5.5a below.

### 5.5a Recovery from partial-ingest failures

The two DB operations in the lock-held region (`reset_for_rerun` at step 4 and `record_raw_output_ingested` at step 6) can in principle fail under SQLite errors, disk-full conditions, or concurrent-lock escalation. The ordering in Section 5.5 is chosen to make most failure modes cleanly retryable, with one specific mode that requires an explicit recovery procedure.

**Failure mode analysis:**

| Step that fails | Filesystem state after failure | DB state after failure | Recovery |
|---|---|---|---|
| 1-3 (pre-mutation) | unchanged | unchanged | Retry with corrected inputs. No recovery needed. |
| 4 (DB state reset) | unchanged (nothing committed yet) | unchanged (reset never applied) | Retry. Clean, idempotent. |
| 5 (filesystem commit) | unchanged (Section 4.3 per-side rollback restores pre-call state) | state reset to COLLECTED; spurious "rerun" event in journal | Retry. The spurious rerun event is minor audit noise. If the engagement was at COLLECTED before step 4, even the spurious event is avoided because `reset_for_rerun` is a no-op. |
| 6 (ingest event emission) | **committed** (new manifest and artifacts are on disk) | state is COLLECTED; rerun event in journal; **raw_output_ingested event is missing** | **Manual recovery required.** See below. |

**Manual recovery for step 6 failure:**

The command exits with an error message that explicitly instructs the operator:

```
[bright_red]Error:[/bright_red] Ingest committed raw output to disk, but the
audit event could not be recorded: <db error>.
The engagement state is consistent, but the audit trail is incomplete.

To complete the audit record, re-run the same ingest command with --replace:
    mseco ingest <id> --tool <slug> --from <path> --replace

The replay pipeline will still work correctly in the meantime; only the audit
event is missing.
```

On the retry with `--replace`, the conflict gate passes (because `--replace` permits overwriting the just-committed slug), `save_ingested_raw_output` atomically replaces the slug with identical content (the source files haven't changed), and `record_raw_output_ingested` is called again with `replaced=True`. The resulting event says `replaced=True` even though the second write was semantically a recovery, not a replace. That's a known minor audit artifact documented in the runbook and accepted in this design as the pragmatic cost of avoiding a more complex idempotency layer.

**Why not a fancier recovery (auto-reconcile, deterministic event IDs, etc.)?**

- The probability of step 6 failure is low: SQLite with WAL mode is quite reliable, and the event append happens under the engagement lock so there's no contention with other writers.
- The recovery procedure is one command the operator can run without understanding internals.
- A more elaborate reconciliation path (detecting "slug is already committed, just emit the missing event, don't rewrite files") would require new logic for "is this a recovery?" detection, new tests, and new failure modes of its own.
- If step-6 failures turn out to be more common in practice than expected, a follow-up PR can add deterministic event IDs (`event_id = f"ingest:{engagement_id}:{tool_slug}:{ingested_at}"`) and an insert-or-ignore path in `EventRepo.append()`, letting retries be fully idempotent. Scope it when we see the problem, not speculatively.

**Test for this recovery procedure:** `tests/unit/cli/test_ingest_cmd.py` includes a case that mocks `record_raw_output_ingested` to raise `PersistenceError` after `save_ingested_raw_output` succeeds, asserts the error message names `--replace` as the recovery, and asserts a follow-up invocation with `--replace` emits the ingest event (with `replaced=True`) and exits cleanly.

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

- Remove the "(see issue #78 -- command not yet implemented)" note
- Remove the "Until `mseco ingest` is available:" manual-workaround paragraph
- Add a concrete example showing a three-tool ingest workflow
- Add a caveat about the pick-first-match UX tradeoff
- Add a caveat about `--run-at` / assessment-date

## Section 6: Testing strategy

### 6.1 New test files

- `tests/unit/cli/test_ingest_cmd.py` — CLI unit tests (18 cases, enumerated below)
- `tests/unit/adapters/test_build_collection_output.py` — shared helper (validation, sorting, target_relpath checks, empty items rejection)
- `tests/unit/adapters/test_<each>_ingest.py` — one file per adapter (7 files) combining parity tests and ingest tests for that adapter
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

One test per adapter asserting `adapter.default_schema_version == <hardcoded expected value>`. The expected value is written inline in the test, not read from the same constant the adapter uses — so drift between the two values is caught by the test:

```python
# test_scubagear_ingest.py
def test_default_schema_version_matches_collect():
    assert ScubaGearAdapter().default_schema_version == "1.7.1"

# test_maester_ingest.py
def test_default_schema_version_matches_collect():
    assert MaesterAdapter().default_schema_version == "1.0.0"

# test_azure_advisor_ingest.py
def test_default_schema_version_matches_collect():
    assert AzureAdvisorAdapter().default_schema_version == "2025-01-01"
```

### 6.6 CLI unit tests

All 18 cases go in `tests/unit/cli/test_ingest_cmd.py`. Each uses Click's `CliRunner` to invoke `ingest_cmd` with mocked dependencies.

1. Invalid `engagement_id` format → exit 1, no mutation
2. `--from` is a symlink → exit 1, no mutation
3. `--schema-version` empty / control chars / too long → exit 1 per case
4. `--run-at` unparseable → exit 1
5. `--run-at` omitted → warning printed, `utc_now()` used
6. Engagement missing from DB → exit 1, no mutation
7. Engagement dir missing but DB row present → exit 1
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

`tests/integration/test_ingest_flow.py`, 4 scenarios:

1. **Single-tool ingest + replay** — create engagement, ingest scubagear from fixture, assert state is COLLECTED, replay `--from parse` with `--qa-strategy noop` for determinism, assert findings landed.
2. **Multi-tool mixed** — live-collect maester (mocked subprocess), ingest scubagear from fixture, assert both coexist, maester's manifest unchanged, scubagear's manifest shows `source_mode="ingested"`.
3. **Replace path** — ingest scubagear, ingest again with `--replace` and different content, assert new files in place, two separate `raw_output_ingested` events in the journal.
4. **Runbook scenario 3 end-to-end** — reproduce the exact command sequence from the updated runbook (`engagement create` → 3× `ingest` → `replay --from parse --qa-strategy noop`), assert the pipeline reaches RENDERED state.

All integration tests pin `--qa-strategy noop` explicitly for determinism even though `pyproject.toml:50` currently registers only noop — future QA strategies shouldn't be able to make these tests flaky.

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

1. `test_legacy_migration_provisions_dir_and_mirrors_snapshot`: pre-condition is a DB row with `engagement_dir IS NULL` and no on-disk directory (simulate by creating an engagement row via `repo.create()` with `engagement_dir=None` — the current default — and NOT calling `create_engagement_dir`). Call `save_ingested_raw_output` with a valid `CollectionOutput`, passing `client_name`, `engagement_row`, and `engagement_repo` as kwargs. Assert: (a) the engagement directory is created via `create_engagement_dir`, (b) `<engagement_dir>/config_snapshot.json` is written and its content round-trips to the original snapshot via `decode_config_snapshot`, (c) the raw output commit proceeds and succeeds, (d) a WARNING log line is emitted mentioning "legacy engagement" and "one-time migration".
2. `test_legacy_migration_fails_if_dir_creation_fails`: same pre-condition, but monkey-patch `create_engagement_dir` to raise `OSError`. Assert `PersistenceError` raised, no raw output committed, no partial state on disk.
3. `test_legacy_migration_fails_if_strict_mirror_fails_and_cleans_up_dir`: same pre-condition, but monkey-patch `mirror_config_snapshot_from_db_strict` to raise `ConfigSnapshotMirrorError`. Assert: (a) `PersistenceError` raised, (b) no raw output committed, (c) the engagement directory created at the first step of migration is removed via `shutil.rmtree(..., ignore_errors=True)`, (d) the error message mentions "config_snapshot mirror write failed" and "Directory cleanup attempted".
4. `test_post_pr_engagement_with_missing_dir_fails_closed`: simulate a post-PR engagement (DB row has `engagement_dir="/path/to/eng-dir"` populated, but the directory was manually deleted). Call `save_ingested_raw_output` with the engagement_row containing the populated `engagement_dir` column. Assert: (a) `PersistenceError` raised, (b) the error message mentions `engagement_dir=...` from the DB and "filesystem corruption or manual deletion", (c) `create_engagement_dir` is NOT called (the migration branch is NOT entered), (d) no raw output committed, (e) the error message names the `mseco engagement purge` recovery option.
5. `test_legacy_migration_requires_migration_kwargs`: pre-condition is a DB row with `engagement_dir IS NULL` and no on-disk directory, but the caller does NOT pass `client_name`, `engagement_row`, or `engagement_repo`. Assert `PersistenceError` raised with a message naming "legacy migration requested but CLI did not supply migration context".

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

### 6.13 Partial-ingest recovery test (from Section 5.5a)

One case in `tests/unit/cli/test_ingest_cmd.py`:

- `test_step_6_failure_recovery_via_replace`: mock `record_raw_output_ingested` to raise `PersistenceError`. Assert the command exits 1 with an error message that names `--replace` as the recovery procedure. Then invoke the same command again with `--replace` (mocks return to normal) and assert: (a) exit 0, (b) `save_ingested_raw_output` was called with `replace=True`, (c) `record_raw_output_ingested` was called with `replaced=True` in the payload, (d) the engagement has exactly one `raw_output_ingested` event in the journal (the successful one), (e) the engagement state is COLLECTED.

## Future work

- `--strict` flag on `mseco ingest` that rejects ambiguous adapter discovery (e.g., multiple ScubaResults*.json files).
- Multi-tool ingest in a single invocation for engagements where the client sends a single archive containing multiple tools' output.
- Ingesting from a `raw-output.tar.gz` archive (mirrors `ArtifactManager.restore`).
- Propagating `source_mode` / `ingest_provenance` into `ResolvedManifest` and the report payload so downstream consumers can distinguish collected vs. ingested data.
- Reconciling the M365-Assess `script_path` / `script` allowlist mismatch at `adapters/m365_assess/adapter.py:307` vs `core/domain/constants.py:170`.
- Write-side canonical path enforcement for `raw-output/` (symlink + non-canonical-subtree rejection at write time, matching replay's read-time confinement).
- **`mseco engagement migrate` batch command** — backfill `engagements.engagement_dir` for all legacy rows where the column is `NULL` but a matching directory exists on disk. Makes the Section 4.2a legacy migration a one-time process instead of a branch that re-enters on every ingest against a legacy engagement. Out of scope for this PR because the branch is idempotent and the noise is minor.
