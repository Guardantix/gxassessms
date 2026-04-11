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

The design has six coordinated pieces across the layers:

1. **Data model** (`core/domain/models.py`, `core/domain/constants.py`): two new optional fields on `RawToolOutput` plus a new `IngestProvenance` model, gated by a `manifest_version` bump from `"1.0.0"` to `"1.1.0"` that preserves backward-read compatibility for existing engagements on disk.
2. **Shared adapter helper** (`adapters/_base.py`): new module-level `build_collection_output()` that hashes a pre-computed list of `(source_path, target_relpath)` pairs and assembles a `CollectionOutput`. Used by both live `collect()` and the new ingest path. Discovery and freshness filtering stay in each adapter's `collect()` exactly as today.
3. **Per-adapter ingest method** (`adapters/<tool>/adapter.py`): new `ingest_from_directory()` method on each of the 7 adapters, implementing the same file-walk logic as live collect but without freshness filtering (since ingest has no "before" snapshot).
4. **Protocol extension** (`core/contracts/types.py`): new `IngestCapableAdapter(ToolAdapter, Protocol)` adding `ingest_from_directory()` and a `default_schema_version: str` class attribute, plus an `"ingest"` entry in `AdapterCapability`.
5. **Persistence layer** (`persistence/artifacts.py`): new `save_ingested_raw_output()` method on `ArtifactManager`, providing atomic single-slug writes (unlike the existing full-generation-swap `save_raw_outputs()`) with fail-closed enforcement of pre-existing engagement directory and a per-side rollback on commit failure.
6. **CLI command** (`cli/commands/ingest.py`, `cli/main.py`, `cli/_helpers.py`, `pipeline/orchestrator.py`, `pipeline/state.py`): the `mseco ingest` Click command, new canonical helpers (`resolve_enabled_adapter`, `require_ingest_capable`, `get_engagement_lock`), a new `"raw_output_ingested"` `EventType` variant and public `record_raw_output_ingested` orchestrator wrapper, and the documented state reset via `reset_for_rerun(Stage.PARSE)`.

## Section 1: End-to-end flow

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

8. Atomic single-slug commit
   - ArtifactManager.save_ingested_raw_output(
         engagement_id, collection_output,
         ingest_provenance=..., replace=...,
     )
   - Phase 1 validate, Phase 2 stage, Phase 3 atomic per-slug rename

9. State reset + event emission (still under the lock)
   - orchestrator.reset_for_rerun(engagement_id, Stage.PARSE)
     - Resets engagement state to COLLECTED (PARSE's entry state per
       stages.py:386). No-op when already at COLLECTED. Emits existing
       "rerun" event via the orchestrator's standard path.
   - orchestrator.record_raw_output_ingested(
         engagement_id=..., actor=f"human:{operator}",
         tool_slug=..., source_path=..., file_count=..., replaced=...,
     )
     - New public wrapper. Internally routes through _emit_event to write
       the new "raw_output_ingested" event with a typed payload.

10. Release lock (finally block)

11. Success output
    - Ingested file count, manifest path, next-step hint:
      "Run `mseco replay <id> --from parse` to process this data."
```

**Layering invariants:**

- **DB-required, no DR fallback.** Unlike `replay`, ingest has no disaster-recovery path that falls back to `config_snapshot.json`. If the engagement isn't in the DB, the operator runs `mseco engagement create` first. Ingest is a pre-normalization step, not a recovery tool.
- **Lock scope.** Conflict check, adapter walk, `validate_raw` preflight, atomic commit, state reset, and event emission all happen inside a single `engagement_lock.hold(engagement_id)` region. Other mutating commands (collect, replay, review UI plugins) are serialized against ingest via the same advisory filelock mechanism documented in runbook section 9.
- **`validate_raw` is an ingest-private preflight**, not a weakening of the replay trust boundary. Replay still performs its own `confine_and_resolve()` + `validate_raw()` on read. Ingest just runs the check earlier so the operator finds out immediately whether the client's files are usable.
- **Save_ingested_raw_output has a distinct contract from save_raw_outputs.** It does NOT auto-create the engagement dir, it writes only one slug, and it constructs the `RawToolOutput` internally with `source_mode="ingested"` (the one place in the codebase where that value is materialized).

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

- **Fails closed on missing on-disk engagement directory.** No `create_engagement_dir()` fallback. Caller (the CLI layer) is responsible for enforcing any higher-level invariants (e.g., "engagement row must exist in the DB"); this method only knows about filesystem state.
- **Single-slug atomicity.** Only the target tool's artifacts subdirectory and manifest file are touched. All other tools' existing data remains byte-for-byte untouched.
- **Conflict-gated.** If the slug's artifacts or manifest already exists and `replace=False`, raises `PersistenceError` before any mutation. With `replace=True`, the prior data is atomically renamed aside as part of the commit and cleaned up best-effort afterwards.
- **Owns manifest materialization.** Constructs the `RawToolOutput` internally with `source_mode="ingested"` and the caller-provided `ingest_provenance`. The caller does not construct the `RawToolOutput` — this method is the **only** place in the codebase that writes `source_mode="ingested"`, enforced by code review.
- **Invariant assertion: `execution_metadata == {}`.** The method asserts `collection_output.execution_metadata == {}` at the top and raises `PersistenceError` if violated. Ingest must never synthesize per-tool execution metadata; that field is exclusively for real tool-run provenance.
- **Caller must hold `EngagementLock`.** This method does not acquire a lock; it trusts the caller to serialize concurrent mutations (same convention as `save_raw_outputs`).
- **Caller must have already run the adapter's `validate_raw()`** against the source files. This method does not call `validate_raw()` itself; that's the CLI command's pre-commit check.

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
- Does not emit events or update engagement state (CLI's job, runs under the same lock)
- Does not filter `execution_metadata` through the allowlist (ingest's execution_metadata is `{}` by invariant, so no filtering is needed; the assertion at the top ensures this can never change)
- Does not update the DB `engagements` row or `raw-output/config_snapshot.json`

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

# On-disk directory required.
try:
    engagement_dir = artifacts.get_engagement_dir(engagement_id)
except PersistenceError:
    console.print(
        f"[bright_red]Error:[/bright_red] No engagement directory found "
        f"for {engagement_id!r}. The DB row exists but the on-disk "
        f"directory is missing -- this engagement is in an inconsistent state."
    )
    raise SystemExit(1) from None

# Load the engagement config (DB only; no DR fallback for ingest).
from gxassessms.persistence.engagement_repo import decode_config_snapshot
snapshot = decode_config_snapshot(engagement)
config = EngagementConfig.model_validate(snapshot)
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

Kept as a separate helper so the lock acquisition stays narrow and readable. Runs:

1. **Conflict check** (TOCTOU-safe inside the lock)
2. **Adapter walk**: `ingest_adapter.ingest_from_directory(source_dir, schema_version=..., timestamp=run_at)`. Schema version resolution: `schema_version_override or ingest_adapter.default_schema_version`
3. **Pre-commit `validate_raw`**: build a throwaway `ResolvedManifest` with absolute source_paths as `file_manifest` keys, call `ingest_adapter.validate_raw(preflight_manifest)`. On failure, abort without mutating the engagement directory.
4. **Atomic commit**: construct `IngestProvenance(source_path=str(source_dir), ingested_at=utc_now(), ingested_by=f"human:{operator}")`, call `artifacts.save_ingested_raw_output(...)`.
5. **State reset**: `orchestrator.reset_for_rerun(engagement_id, Stage.PARSE)` — resets the engagement state to `EngagementState.COLLECTED` (PARSE's entry state per `stages.py:386`). No-op when already at COLLECTED. Emits the existing `"rerun"` event via the orchestrator's standard path.
6. **Dedicated ingest event**: `orchestrator.record_raw_output_ingested(...)` — new public wrapper.

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
- `tests/unit/persistence/test_artifacts.py` — `save_ingested_raw_output` happy path, four rollback cases, other-tools isolation, `replace=True` semantics
- `tests/unit/pipeline/test_orchestrator.py` — `record_raw_output_ingested` forwarding test
- `tests/unit/pipeline/test_replay.py` — case loading a 1.1.0 `source_mode="ingested"` manifest
- `tests/unit/pipeline/test_confinement.py` — `RECOGNIZED_MANIFEST_VERSIONS` gate accepts 1.1.0
- `tests/unit/cli/test_helpers.py` — `resolve_enabled_adapter`, `require_ingest_capable`, `get_engagement_lock`

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

## Future work

- `--strict` flag on `mseco ingest` that rejects ambiguous adapter discovery (e.g., multiple ScubaResults*.json files).
- Multi-tool ingest in a single invocation for engagements where the client sends a single archive containing multiple tools' output.
- Ingesting from a `raw-output.tar.gz` archive (mirrors `ArtifactManager.restore`).
- Propagating `source_mode` / `ingest_provenance` into `ResolvedManifest` and the report payload so downstream consumers can distinguish collected vs. ingested data.
- Reconciling the M365-Assess `script_path` / `script` allowlist mismatch at `adapters/m365_assess/adapter.py:307` vs `core/domain/constants.py:170`.
- Write-side canonical path enforcement for `raw-output/` (symlink + non-canonical-subtree rejection at write time, matching replay's read-time confinement).
