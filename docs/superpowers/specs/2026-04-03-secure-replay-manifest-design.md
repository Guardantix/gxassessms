# Secure Replay Manifest Design

**Issue:** #35 -- confine replay manifest paths to raw-output/ and verify artifact integrity
**Date:** 2026-04-03
**Branch:** security/replay-manifest

## Problem

`RawToolOutput.file_manifest` accepts arbitrary string paths. Collection
persists absolute filesystem paths into manifests. Replay loads those
manifests and opens whichever files the paths reference without confining
them to the engagement root. A local user or process that can modify
persisted manifests can redirect replay to out-of-scope files, creating
report-integrity risk, cross-engagement contamination, and limited local
file disclosure.

## Security Scope

This design provides **confinement** and **artifact-drift detection**, not
**tamper-evidence**.

- **Confinement:** Replay cannot access files outside the engagement root.
- **Drift detection:** Replay detects when on-disk artifacts do not match
  what was originally collected (via SHA-256 content hashes).
- **Not in scope:** An attacker with write access to `raw-output/` who
  replaces both the manifest and its referenced artifacts consistently
  will not be detected. Detecting that attack requires an external trust
  root (signatures, HMAC, separate digest store) and is a separate issue
  with a different threat model.

## Artifact Scope

This design persists only the minimal artifact set required for replay --
one JSON result file per tool. HTML reports, CSVs, images, markdown
summaries, and other presentation or archival artifacts are excluded by
design. Full tool archival is a separate concern.

## Platform

GxAssessMS runs on Windows in production. Linux is the development
environment only. Collection-time paths are Windows-native (backslashes,
drive letters). Persisted manifest paths use a platform-independent
canonical POSIX format.

---

## Section 1: Data Types and Directory Layout

### Three Data Types

The design uses three explicit types to enforce boundaries at the type
level. No type serves double duty.

| Type | Paths | Scope | Creator | Consumer |
|------|-------|-------|---------|----------|
| `CollectionOutput` | Absolute, platform-native | Adapter -> persistence | Adapter `collect()` | `save_raw_outputs()` |
| `RawToolOutput` | POSIX-relative canonical | On disk only | `save_raw_outputs()` | `load_raw_outputs()`, `confine_and_resolve()` |
| `ResolvedManifest` | Absolute, engagement-controlled | Runtime only | `confine_and_resolve()` | `validate_raw()`, `parse()`, `coverage()` |

`RawToolOutput` is immutable as the on-disk contract. It is never reused
for resolved absolute paths.

### Models

```python
class ArtifactRecord(BaseModel):
    """Per-artifact integrity binding."""
    model_config = ConfigDict(extra="forbid")
    encoding: FileEncoding
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class CollectedArtifact(BaseModel):
    """Single artifact from adapter collection."""
    source_path: str        # absolute, platform-native
    target_relpath: str     # canonical POSIX relative (e.g. "scubagear/ScubaResults.json")
    encoding: FileEncoding
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class CollectionOutput(BaseModel):
    """Adapter collection result. Platform-native absolute paths."""
    tool: ToolSource
    tool_slug: str          # stable storage namespace, [a-z0-9][a-z0-9-]*
    schema_version: str     # tool output format
    timestamp: datetime
    artifacts: list[CollectedArtifact]   # sorted by target_relpath
    execution_metadata: dict[str, Any]


class RawToolOutput(BaseModel):
    """On-disk replay manifest. POSIX-relative canonical paths."""
    model_config = ConfigDict(extra="forbid")
    tool: ToolSource
    tool_slug: str
    schema_version: str
    manifest_version: str   # replay security contract, required, no default
                             # initial value: "1.0.0"
    timestamp: datetime
    file_manifest: dict[str, ArtifactRecord]   # POSIX-relative -> {encoding, sha256}
    execution_metadata: dict[str, Any]

    # Validators:
    #   file_manifest: validate_canonical_posix_path() on all keys,
    #     non-empty, extra="forbid"
    #   tool_slug: [a-z0-9][a-z0-9-]* format
    #   timestamp: ensure_utc


class ResolvedManifest(BaseModel):
    """Runtime-resolved manifest. Absolute engagement-controlled paths."""
    model_config = ConfigDict(extra="forbid")
    tool: ToolSource
    tool_slug: str
    schema_version: str
    manifest_version: str
    timestamp: datetime
    file_manifest: dict[str, ArtifactRecord]   # resolved absolute paths
    execution_metadata: dict[str, Any]
    # No path format validators -- paths are trusted output of
    # confine_and_resolve()
```

### Result Types

```python
class CollectionResult(BaseModel):
    """Wraps CollectionOutput from the collect stage."""
    adapter_name: str
    status: AdapterRunStatus
    collection_output: CollectionOutput | None = None
    error: str | None = None
    duration_seconds: float = Field(ge=0)

    # model_validator preserving current invariants:
    #   SUCCESS requires collection_output, must not have error
    #   FAILED/TIMEOUT require error message
    #   SKIPPED must not carry collection_output


class AdapterResult(BaseModel):
    """Wraps ResolvedManifest for parse/coverage stages."""
    adapter_name: str
    status: AdapterRunStatus
    raw_output: ResolvedManifest | None = None
    error: str | None = None
    duration_seconds: float = Field(ge=0)

    # model_validator preserving current invariants:
    #   SUCCESS requires raw_output, must not have error
    #   FAILED/TIMEOUT require error message
    #   SKIPPED must not carry raw_output
```

Both result types preserve the status/payload invariants from the
current `AdapterResult` (see `src/gxassessms/core/domain/models.py:166`).
These `model_validator`s enforce stage-boundary correctness and prevent
silent construction of bad intermediate state.

The runner keeps `collection_results` and `loaded_manifests` / `adapter_results`
as separate variables. `CollectionResult` is preserved for COLLECT stage
bookkeeping (includes failed/timeout/skipped statuses).

### Adapter Protocol

```python
class ToolAdapter(Protocol):
    tool_name: str = ""
    storage_slug: str = ""       # stable, unique, [a-z0-9][a-z0-9-]*
    tool_source: ToolSource      # identity, not presentation

    def collect(self, config, auth) -> CollectionOutput: ...
    def validate_raw(self, raw: ResolvedManifest) -> None: ...
    def parse(self, raw: ResolvedManifest) -> list[ToolObservation]: ...
    def coverage(self, raw: ResolvedManifest) -> list[CoverageRecord]: ...
```

### Adapter Registry Startup Validation

Hard failure on any of:
- Missing or empty `storage_slug`
- `storage_slug` not matching `[a-z0-9][a-z0-9-]*`
- Duplicate `storage_slug` across registered adapters
- Duplicate `tool_source` across registered adapters

### Directory Layout

```
<engagement>/
  raw-output/
    manifests/                 # one RawToolOutput per tool
      scubagear.json
      maester.json
    artifacts/                 # actual tool output files
      scubagear/
        ScubaResults_<guid>.json
      maester/
        TestResults-<timestamp>.json
```

Manifest paths are relative to `raw-output/artifacts/`
(e.g., `scubagear/ScubaResults_<guid>.json`).

`create_engagement_dir()` is updated to create `raw-output/manifests/`
and `raw-output/artifacts/` instead of the flat `raw-output/` directory.

### Shared Path Validation Helper

`validate_canonical_posix_path(path_str: str) -> None`

Used by both `RawToolOutput` field validators and `confine_and_resolve()`.
Single source of truth.

Checks:
- No backslashes
- No absolute paths (leading `/`)
- No parent traversal (`..` in parts)
- No colon in any path segment
- Round-trip normalization: `str(PurePosixPath(path_str)) == path_str`
- No empty or trivial paths
- No Windows reserved device names in any segment (`CON`, `PRN`, `AUX`,
  `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9`, case-insensitive, with or
  without extension)
- No trailing dots or spaces in any segment
- No characters illegal in Windows filenames (`<`, `>`, `"`, `|`, `?`, `*`)

### Namespace Identity

`storage_slug` is the canonical persistence AND dispatch identity:
- Manifest filenames: `manifests/<storage_slug>.json`
- Artifact subtrees: `artifacts/<storage_slug>/`
- Replay lookup and confinement keyed by `storage_slug`
- `AdapterResult.adapter_name` carries `storage_slug` (not `tool_name`)
- `parse()` and `coverage()` stage functions match adapters by
  `storage_slug`, not `tool_name`
- `tool` (`ToolSource` enum) is a consistency check, not persistence or
  dispatch key

This requires updating the adapter lookup in `stages.py` (currently
keyed by `tool_name`) to key by `storage_slug`. `tool_name` remains
available for display/logging but is no longer used for dispatch.

### execution_metadata

Per-`manifest_version` allowlist of persisted keys. Only keys the adapter
truly knows at collection time:

| Adapter | Allowed keys |
|---------|-------------|
| ScubaGear | `modules` |
| Maester | (none currently) |

`output_dir`, `exit_code`, `duration_seconds`, `tool_version` are all
excluded. `save_raw_outputs()` drops non-allowlisted keys during
conversion from `CollectionOutput` to `RawToolOutput`.

---

## Section 2: Replay Trust Boundary -- `confine_and_resolve()`

Single function where all replay security enforcement happens. Sits
between "loaded from disk" and "handed to adapters." Runs on **both**
live and replay paths.

### Signature

```python
def confine_and_resolve(
    loaded_manifests: list[LoadedManifest],
    engagement_dir: Path,
    adapters: list[ToolAdapter],
) -> list[ResolvedManifest]:
```

### Input

```python
class LoadedManifest(NamedTuple):
    source_path: Path           # e.g., .../manifests/scubagear.json
    raw_output: RawToolOutput
```

`load_raw_outputs()` returns `list[LoadedManifest]`, preserving the
manifest file path for the filename-stem check.

### Check Order

1. **`manifest_version` gate:** Reject any unrecognized version. Hard
   failure, no fallback. This is the hard-cutover mechanism.

2. **Three-way slug check:**
   - `loaded_manifest.source_path.stem` == `raw_output.tool_slug`
   - `raw_output.tool_slug` == registered adapter `storage_slug`
   - `raw_output.tool` == registered adapter `tool_source`

   Reject on any mismatch.

3. **Per-path canonical format:** `validate_canonical_posix_path()` on
   each `file_manifest` key (defense-in-depth -- model validators already
   ran, but same helper, same rules).

4. **Per-path tool confinement:** Verify each path starts with
   `<tool_slug>/`.

5. **Per-path strict resolve:** `(artifacts_root / relpath).resolve(strict=True)`.
   `strict=True` surfaces missing files as `FileNotFoundError`, not hash
   noise.

6. **Per-path tool-subtree containment:**
   `resolved.is_relative_to((artifacts_root / tool_slug).resolve())`.
   Confines to the tool's own subtree, not just artifacts root. A
   symlink inside `artifacts/scubagear/` that resolves to
   `artifacts/maester/...` is rejected. This is the actual security
   property: tool-subtree confinement after resolution.

7. **Per-path file type:** `resolved.is_file()`. Rejects directories,
   devices.

8. **Per-path SHA-256 verify:** Compute hash of file on disk, compare to
   `ArtifactRecord.sha256`. Reject on mismatch with actionable error:
   file name, expected hash, actual hash.

9. **Duplicate resolution check:** Reject duplicate resolved absolute
   paths within one manifest.

### Error Handling

Every rejection raises `ManifestConfinementError` (inherits
`PipelineError`) with:
- `engagement_id`
- `stage`
- `tool_slug`
- `check_name` (which check failed)
- `detail` (specific path/field, expected vs. found)

Error messages say "failed confinement/integrity checks relative to the
persisted manifest" -- no implication of tamper-evidence.

No partial results. If any manifest or any path within a manifest fails,
the entire operation fails.

### Symlink Handling

`resolve(strict=True)` + tool-subtree containment. If the resolved path
stays under `artifacts/<tool_slug>/`, any intermediate symlinks are
acceptable. A symlink that resolves outside the tool's own subtree --
even to another tool's subtree -- is rejected.

### Replaces `validate_raw_outputs()`

The old `validate_raw_outputs()` function that called
`adapter.validate_raw()` before any confinement is removed. The new flow
is:

1. `confine_and_resolve()` (confinement + integrity)
2. `adapter.validate_raw(resolved)` (structural validation)
3. `adapter.parse(resolved)` / `adapter.coverage(resolved)`

`confine_and_resolve()` MUST complete before any adapter method runs.

---

## Section 3: Persistence -- `save_raw_outputs()`

Converts `CollectionOutput` to `RawToolOutput` and copies artifacts
under engagement control using generation-staged writes.

### Signature

```python
def save_raw_outputs(
    self,
    engagement_id: str,
    client_name: str,
    collection_results: list[CollectionResult],
) -> list[LoadedManifest]:
```

Returns `list[LoadedManifest]` so the live path enters
`confine_and_resolve()` with the same input shape as replay.

### Phase 1: Validate All Inputs (Before Any I/O)

For each successful `CollectionResult`:

1. Source paths are absolute, exist, are regular files, not
   symlinks/junctions/reparse points
2. Source file content matches `CollectedArtifact.sha256` (reject if
   source changed since collection)
3. Each `target_relpath` passes `validate_canonical_posix_path()` and
   starts with `<tool_slug>/`
4. No duplicate `target_relpath` within a single `CollectionOutput`
5. No duplicate `target_relpath` across all `CollectionOutput` objects
6. No path-shape collisions:
   - Case-insensitive collisions (`Foo.json` vs `foo.json`)
   - Ancestor/descendant conflicts (`scubagear/out` vs
     `scubagear/out/file.json`)
7. Windows filesystem legality (via shared helper)
8. `execution_metadata` filtered through per-`manifest_version`
   allowlist
9. No duplicate successful `CollectionResult` for the same
   `storage_slug`

If any validation fails, the entire save fails. No partial work.

### Phase 2: Stage the Full Generation

Create staging directory: `raw-output/.staging-<uuid>/`

For each tool:
1. Create `artifacts/<target_relpath>` parent directories as needed
2. Binary-copy (`shutil.copy2` or `rb`/`wb`) each source file to
   `artifacts/<target_relpath>`
3. Verify copied file hash matches `CollectedArtifact.sha256`
4. Build `RawToolOutput` with:
   - `manifest_version` = current version constant
   - `file_manifest` keyed by `target_relpath`, values are
     `ArtifactRecord(encoding, sha256)`
   - `execution_metadata` with only allowlisted keys
5. Serialize manifest to `manifests/<slug>.json`

If any copy or verify fails, remove entire staging directory and fail.

### Phase 3: Commit the Generation (Fail-Closed, Generation-Preserving)

Uses generation indirection to avoid destroying the last known-good
replay state on a mid-commit failure:

1. Rename existing `raw-output/artifacts/` to
   `raw-output/.old-artifacts-<uuid>/` (if present)
2. Rename existing `raw-output/manifests/` to
   `raw-output/.old-manifests-<uuid>/` (if present)
3. Move staging `artifacts/` into place as `raw-output/artifacts/`
4. Move staging `manifests/` into place as `raw-output/manifests/`
5. Remove `.old-artifacts-<uuid>/` and `.old-manifests-<uuid>/`
   (best-effort)
6. Remove staging directory (best-effort)

Manifests written last. On failure:
- If step 1-2 fail: old generation intact, staging orphaned (harmless).
- If step 3-4 fail: old generation preserved under `.old-*` names.
  Replay discovers nothing (no `manifests/`), which fails closed.
  The `.old-*` directories can be recovered manually or by a future
  save attempt.
- If step 5-6 fail: new generation is live, old data is orphaned but
  not discoverable by replay. Cleaned up best-effort on next save.

**Availability risk:** A mid-commit failure temporarily loses replay
capability until the next successful run or manual recovery. This is
fail-closed behavior -- no silent data corruption -- but replay is
unavailable during that window.

### Phase 4: Return LoadedManifest List

```python
return [
    LoadedManifest(
        source_path=manifests_dir / f"{slug}.json",
        raw_output=raw_output,
    )
    for slug, raw_output in persisted.items()
]
```

### Source Cleanup

Best-effort removal of source run directories after successful
generation commit. Failure to clean is logged, not fatal. The
engagement-controlled copy is authoritative after commit.

### Orphaned Staging Directories

`.staging-*` directories under `raw-output/` are ignored by
`load_raw_outputs()` (it reads only `manifests/`) and cleaned up
best-effort on next `save_raw_outputs()`.

### Error Taxonomy

`PersistenceError` covers both I/O failures and persistence-boundary
validation failures:
- Source hash mismatch
- Duplicate target path / path-shape collision
- Source symlink/junction detection
- Illegal target path
- Copy corruption
- Stale cleanup failure
- Directory creation failure

---

## Section 4: Adapter Collection Changes

### ScubaGear (`storage_slug = "scubagear"`, `tool_source = ToolSource.SCUBAGEAR`)

Current behavior: `run_dir.iterdir()` with `.json`/`.html` filter,
stores absolute paths as strings.

New behavior:

1. Run `_find_scuba_results_file()` at collection time against top-level
   JSON files in `run_dir`
2. Hard-fail if zero or more than one `ScubaResults*.json` candidate
3. Include only that single JSON file
4. Compute SHA-256 from source file bytes
5. Build `CollectedArtifact` with:
   - `source_path = str(results_file)` (absolute, Windows-native)
   - `target_relpath = "scubagear/" + results_file.name`
   - `encoding = "utf-8"`, `sha256 = <computed>`
6. Return `CollectionOutput` with single-element `artifacts` list

ScubaGear already has fresh-output detection (snapshots pre-run
directories, rejects stale `run_dir`). No change needed there.

### Maester (`storage_slug = "maester"`, `tool_source = ToolSource.MAESTER`)

Current behavior: globs `TestResults*` from a reusable `output_dir`,
picks newest by filename sort. Stale-output contamination risk.

New behavior:

1. Create a unique per-run subdirectory:
   `run_dir = output_dir / f"run-{uuid4()}"`
2. Pass `run_dir` to `Invoke-Maester -OutputFolder` (Maester creates the
   directory and writes directly into it)
3. After collection, run `_find_results_file()` against JSON files in
   `run_dir` (not `output_dir`)
4. Include exactly the selected `TestResults*.json` -- exclude `.html`
   and `.md`
5. Build `CollectedArtifact` with:
   - `source_path = str(results_file)` (absolute, Windows-native)
   - `target_relpath = "maester/" + results_file.name`
   - `encoding = "utf-8"`, `sha256 = <computed>`
6. Return `CollectionOutput` with single-element `artifacts` list

Per-run subdirectory eliminates stale-output contamination. No timestamp
collision risk.

### Encoding Classification

Advisory metadata, defined once as a constant mapping:

| Extension | Encoding |
|-----------|----------|
| `.json` | `"utf-8"` |
| all others | `"binary"` |

Adapters currently ignore the encoding value and use `load_json_file()`
which defaults to `utf-8-sig`. The encoding field is reserved metadata
for future use.

---

## Section 5: Converged Lifecycle

Both live and replay paths converge at `confine_and_resolve()`.

### Live Run

```
collect()
  -> list[CollectionResult]

save_raw_outputs(collection_results)
  -> Phase 1: validate sources, hashes, paths, collisions
  -> Phase 2: stage artifacts + manifests
  -> Phase 3: commit generation (artifacts first, manifests last)
  -> list[LoadedManifest]

confine_and_resolve(loaded_manifests, engagement_dir, adapters)
  -> version gate, slug check, path confinement, hash verify
  -> list[ResolvedManifest]

validate_raw(resolved) -> parse(resolved) / coverage(resolved)
```

### Replay

```
load_raw_outputs(engagement_dir)
  -> read manifests/*.json, validate slug against registry
  -> list[LoadedManifest]

confine_and_resolve(loaded_manifests, engagement_dir, adapters)
  -> same function, same checks
  -> list[ResolvedManifest]

validate_raw(resolved) -> parse(resolved) / coverage(resolved)
```

### Runner Variables

```python
if stage == Stage.COLLECT:
    collection_results = collect(config, adapters)
    loaded_manifests = orchestrator._artifact_manager.save_raw_outputs(
        engagement_id, config.client_name, collection_results
    )
    # collection_results: preserved for COLLECT stage hashing/bookkeeping
    # loaded_manifests: flows to confine_and_resolve -> parse

elif stage == Stage.PARSE:
    # loaded_manifests already set (from COLLECT above or from replay)
    resolved = confine_and_resolve(loaded_manifests, engagement_dir, adapters)
    adapter_results = [
        AdapterResult(adapter_name=r.tool_slug, status=SUCCESS, raw_output=r)
        for r in resolved
    ]
    observations = parse(adapter_results, adapters)
```

---

## Section 6: Error Taxonomy

### New Error

`ManifestConfinementError(PipelineError)` -- raised by
`confine_and_resolve()`. Inherits `engagement_id` and `stage` from
`PipelineError`. Additional fields:
- `tool_slug: str`
- `check_name: str` (which check failed)
- `detail: str` (specific path/field, expected vs. found)

### Existing Errors

- `MissingRawOutputError` -- missing `manifests/` directory or empty
  manifest set
- `InvalidRawOutputError` -- malformed JSON, schema validation failures
  during deserialization, AND manifest-directory shape violations:
  - Manifest filename with unregistered slug
  - Mixed-case manifest filename
  - Non-JSON file in `manifests/`
  - Subdirectory inside `manifests/`

  These are all classified as invalid raw output because they represent
  malformed or unexpected content at the replay input boundary.
- `PersistenceError` -- I/O failures AND persistence-boundary validation
  failures in `save_raw_outputs()`:
  - Source hash mismatch
  - Duplicate target path / path-shape collision
  - Source symlink/junction detection
  - Illegal target path
  - Copy corruption
  - Stale cleanup failure

---

## Section 7: Testing Strategy

### 7.1 Model Validation Tests

`tests/unit/core/domain/test_models.py`:

**RawToolOutput validators:**
- Rejects backslash, absolute POSIX, `..` traversal, colon in segments,
  non-canonical paths, empty manifest, unknown fields
- Accepts valid canonical POSIX paths

**ArtifactRecord:**
- Rejects non-64-hex SHA-256, unknown fields

**CollectionOutput / CollectedArtifact:**
- Accepts platform-native absolute paths

**Shared path helper (`validate_canonical_posix_path`):**
- Windows reserved device names (CON, NUL, COM1, etc.)
- Trailing dots/spaces
- Illegal characters
- Case-insensitive collision detection
- Round-trip normalization

### 7.2 Persistence Tests

`tests/unit/persistence/test_artifacts.py`:

**Generation staging:**
- Full success: all tools copied, verified, manifests written, staging
  cleaned
- Partial failure: one tool fails -> entire generation fails, no stale
  data
- Source modified post-collect -> pre-copy hash check rejects
- Copy corruption -> post-copy hash check rejects
- Commit ordering: artifacts move before manifests

**Source validation:**
- Non-absolute source path, missing file, directory, symlink/junction
  -> rejected
- Duplicate target_relpath (exact and case-insensitive) -> rejected
- Ancestor/descendant path conflicts -> rejected
- Duplicate storage_slug in collection results -> rejected

**Layout:**
- Creates `manifests/` and `artifacts/<slug>/`
- Stale cleanup removes prior generation
- Orphaned `.staging-*` cleaned on next save

**Return value:**
- Returns `list[LoadedManifest]` with correct source_path

**execution_metadata allowlist:**
- Only allowlisted keys survive round-trip
- Unknown keys silently dropped
- Allowlist tied to manifest_version

### 7.3 Replay Confinement Tests

`tests/unit/pipeline/test_replay.py`:

**confine_and_resolve():**
- Rejects unknown manifest_version
- Rejects tool_slug not matching any registered adapter
- Rejects manifest filename stem != tool_slug
- Rejects tool != adapter tool_source
- Rejects absolute paths, `..` traversal, paths not starting with slug
- Rejects symlink escape from tool subtree (symlink under
  artifacts/scubagear/ pointing outside artifacts/scubagear/, including
  to artifacts/maester/)
- Rejects missing artifact, non-file artifact (directory)
- Rejects SHA-256 mismatch
- Rejects duplicate resolved absolute paths
- Accepts valid manifest -> returns ResolvedManifest

**load_raw_outputs():**
- Loads from `manifests/*.json` only
- Rejects: wrong slug, mixed-case filename, non-JSON file,
  subdirectory under `manifests/`
- Returns `list[LoadedManifest]` preserving source path

### 7.4 Adapter Collection Tests

`tests/unit/adapters/`:

**ScubaGear:**
- Includes exactly one ScubaResults*.json, fails on zero or >1
- target_relpath starts with `scubagear/`
- SHA-256 matches file content
- TestResults.json, HTML, CSV excluded

**Maester:**
- Uses unique per-run subdirectory
- Includes exactly the selected TestResults*.json
- .html and .md excluded
- target_relpath starts with `maester/`

### 7.5 Runner/Orchestrator/CLI Sequencing Tests

`tests/unit/pipeline/test_stages.py`, `test_orchestrator.py`,
`tests/unit/cli/test_commands.py`:

- Live path: collect -> save_raw_outputs -> confine_and_resolve ->
  validate_raw -> parse ordering enforced
- Replay path: load -> confine_and_resolve -> validate_raw -> parse
  ordering enforced
- Data types flow correctly: CollectionResult -> LoadedManifest ->
  ResolvedManifest -> AdapterResult
- Old validate_raw_outputs() call site removed and unreachable
- CLI replay commands invoke the correct pipeline entry points

### 7.6 Conformance Suite Updates

`tests/conformance/adapter_suite.py`, `test_scubagear_conformance.py`,
`test_maester_conformance.py`:

The conformance suite is fixture-driven and intentionally bypasses tool
execution. It does NOT use `collect()`. Updates:

- Fixtures updated to build `ResolvedManifest` objects (replacing the
  old `RawToolOutput` fixtures) with absolute paths pointing to the
  existing fixture JSON files
- `validate_raw()`, `parse()`, and `coverage()` calls updated to pass
  `ResolvedManifest` instead of `RawToolOutput`
- No collection-time types (`CollectionOutput`, `CollectionResult`)
  appear in conformance tests

### 7.7 Windows-Specific Tests

**Cross-platform (always run):** String/path helper tests --
validate_canonical_posix_path(), reserved names, illegal characters,
case-insensitive collisions.

**Windows-only (`@pytest.mark.skipif(sys.platform != 'win32')`):** Real
junction/reparse-point rejection, actual case-insensitive filesystem
behavior, `os.lstat()` with `FILE_ATTRIBUTE_REPARSE_POINT`.

### 7.8 Live/Replay Equivalence Test

`tests/integration/`:

End-to-end: collect from fixture files -> save -> confine_and_resolve ->
parse AND coverage. Then separately: load persisted manifests ->
confine_and_resolve -> parse AND coverage. Assert both paths produce
identical ToolObservation and CoverageRecord lists.

### 7.9 Registry Startup Tests

- Duplicate storage_slug -> hard failure
- Duplicate tool_source -> hard failure
- Missing/empty storage_slug -> hard failure
- Invalid slug format -> hard failure
