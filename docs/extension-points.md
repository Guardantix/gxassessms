# Extension Points Reference

GxAssessMS exposes every customization seam as a `Protocol` declared in
[`core/contracts/types.py`](../src/gxassessms/core/contracts/types.py)
(except `CredentialProvider`, which lives in
[`core/contracts/credentials.py`](../src/gxassessms/core/contracts/credentials.py)).
Implementations are discovered through `importlib.metadata` entry points.

This document is the contract reference: signatures, return shapes,
semantics, and registration. For pipeline context see
[architecture.md](architecture.md) and [pipeline.md](pipeline.md). For the
domain models referenced below see [data-model.md](data-model.md).

## Index

| Protocol | Entry-point group | Required attrs |
|----------|-------------------|----------------|
| [`ToolAdapter`](#tooladapter) | `gxassessms.adapters` | `tool_name`, `storage_slug`, `tool_source`, `capabilities`, six methods |
| [`IngestCapableAdapter`](#ingestcapableadapter) | `gxassessms.adapters` | `ToolAdapter` + `"ingest"` cap + `default_schema_version` + `ingest_from_directory` |
| [`ReportRenderer`](#reportrenderer) | `gxassessms.renderers` | `format`, `supported_payload_versions`, `render` |
| [`QAStrategy`](#qastrategy) | `gxassessms.qa_strategies` | `review_findings`, `generate_narratives` |
| [`ConsolidationRule`](#consolidationrule) | `gxassessms.consolidation_rules` | `consolidate` |
| [`NormalizationPolicy`](#normalizationpolicy) | `gxassessms.policies` (`normalization`) | `normalize` |
| [`ConsolidationPolicy`](#consolidationpolicy) | `gxassessms.policies` (`consolidation`) | `consolidate`, `merge_group` |
| [`CredentialProvider`](#credentialprovider) | `gxassessms.credentials` | `get_credential`, `has_credential` |

All `core/contracts/types.py` Protocols use `@runtime_checkable`, so
`isinstance(impl, ProtocolName)` works for structural verification at test
time.

---

## `ToolAdapter`

Source: [`core/contracts/types.py:66-101`](../src/gxassessms/core/contracts/types.py)

```python
@runtime_checkable
class ToolAdapter(Protocol):
    tool_name: str
    storage_slug: str         # stable; [a-z0-9][a-z0-9-]*
    tool_source: ToolSource
    capabilities: frozenset[AdapterCapability]

    def check_prerequisites(self) -> PrerequisiteResult: ...
    def authenticate(self, config: EngagementConfig) -> AuthContext | None: ...
    def collect(self, config: EngagementConfig, auth: AuthContext | None) -> CollectionOutput: ...
    def validate_raw(self, raw: ResolvedManifest) -> None: ...
    def parse(self, raw: ResolvedManifest) -> list[ToolObservation]: ...
    def coverage(self, raw: ResolvedManifest) -> list[CoverageRecord]: ...
```

### Class attributes

| Attribute | Type | Semantics |
|-----------|------|-----------|
| `tool_name` | `str` | Human-readable display name (e.g. `"ScubaGear"`). Non-empty. |
| `storage_slug` | `str` | Filesystem namespace for raw output. Must match `[a-z0-9][a-z0-9-]*` and be unique across registered adapters. Used as the per-tool subdirectory under `<engagement_dir>/raw-output/`. |
| `tool_source` | `ToolSource` | Identity enum used in `Finding.tool`, `SourceEvidence.tool`, and the persistence layer. Must be unique across registered adapters. |
| `capabilities` | `frozenset[AdapterCapability]` | Declared capabilities. Drives which orchestrator phases call which methods. |

### Capabilities

`AdapterCapability` is a `Literal` type in `core/domain/constants.py`. The
known values, with the methods each enables:

| Capability | Required methods called by the pipeline |
|-----------|----------------------------------------|
| `collect` | `authenticate`, `collect` |
| `parse` | `validate_raw`, `parse` |
| `prerequisites` | `check_prerequisites` |
| `shared_auth` | `authenticate` (result reusable across adapters) |
| `coverage_export` | `coverage` |
| `benchmark_mapping` | observation `benchmark_refs` populated |
| `ingest` | `ingest_from_directory` (see [`IngestCapableAdapter`](#ingestcapableadapter)) |

The runtime registry enforces a subset of these checks during discovery
(see [`adapters/__init__.py`](../src/gxassessms/adapters/__init__.py)):

- All members of `_REQUIRED_ATTRIBUTES` must be present on the class.
- Instantiation must not raise.
- `tool_name` must be a non-empty string.
- `storage_slug` must be non-empty and match the slug pattern.
- `storage_slug` and `tool_source` must each be unique across all registered
  adapters.
- If `"ingest"` is in `capabilities`, `ingest_from_directory` must be
  callable and `default_schema_version` must be a non-empty string.

### Method contracts

#### `check_prerequisites() -> PrerequisiteResult`

```python
class PrerequisiteResult(TypedDict):
    satisfied: bool
    message: str
```

Verify the tool is installed at an allowed version. For PowerShell adapters
this typically validates against the adapter's
`policy.py:MODULE_POLICY` via `_verification.check_module_prerequisites()`.
Must not perform network I/O or authenticate. Called by
`mseco preflight`, `mseco adapters check`, and (optionally) at the start of
the `COLLECT` stage.

#### `authenticate(config) -> AuthContext | None`

Resolve credentials and acquire any session needed by the tool. Return
`None` when the tool authenticates itself (e.g. ScubaGear calls
`Connect-MgGraph` internally). The returned `AuthContext` is passed back
into `collect()`. `AuthContext.credential_refs` must contain only lookup
identifiers; raw secrets must live on `AuthContext.token` (a `SecretStr`)
or be resolved inside `collect()` via the registered `CredentialProvider`.

#### `collect(config, auth) -> CollectionOutput`

Run the tool and capture raw output. Returns a `CollectionOutput` whose
`artifacts` list contains every file produced, each with its
platform-native absolute path, canonical POSIX relative path, SHA-256, and
encoding. The pipeline persists this output through `ArtifactManager`.

Tool execution should use `subprocess.run(shell=False, ...)` with arguments
as a list. Adapter-level timeouts should be enforced at the subprocess
boundary (`subprocess.run(timeout=...)`).

#### `validate_raw(raw) -> None`

Structural validation at the tool-output boundary, called before any
`parse()`. Verify that expected files exist in the manifest, that JSON
payloads have expected top-level keys, and that the result is not
suspiciously empty. Raise `RawOutputValidationError` on any structural
mismatch. The pipeline treats this as a fail-fast: a validation failure
fails the PARSE stage; downstream stages do not run.

#### `parse(raw) -> list[ToolObservation]`

Transform the tool-native output into `ToolObservation` records. One adapter
parse = one list. Severity, status, and category fields hold the tool's
native string values; normalization happens in the policy layer.

#### `coverage(raw) -> list[CoverageRecord]`

Extract per-control assessment status. Called only for adapters that
declare `"coverage_export"` in `capabilities`. Returns one record per
control the tool evaluated, with status `assessed`, `partially_assessed`,
or `not_assessed` and an optional human-readable reason.

### Reference adapter

[`adapters/scubagear/adapter.py`](../src/gxassessms/adapters/scubagear/adapter.py)
is the reference implementation. The package layout per adapter is fixed:

```
adapters/<name>/
    __init__.py    # exports the class
    adapter.py     # Protocol implementation
    parser.py      # native output parsing
    mappings.py    # severity / category / dedup-key tables
    policy.py      # MODULE_POLICY (PowerShell adapters only)
    fixtures/      # representative test data
```

---

## `IngestCapableAdapter`

Source: [`core/contracts/types.py:104-122`](../src/gxassessms/core/contracts/types.py)

```python
@runtime_checkable
class IngestCapableAdapter(ToolAdapter, Protocol):
    default_schema_version: str

    def ingest_from_directory(
        self,
        source_dir: Path,
        *,
        schema_version: str,
        timestamp: datetime,
    ) -> CollectionOutput: ...
```

Optional capability for adapters that can construct a `CollectionOutput`
from operator-supplied raw output (the tool was run elsewhere, the client
delivered a results bundle, or the adapter author wants to replay against
captured fixtures).

Declared by including `"ingest"` in `capabilities`, defining
`default_schema_version` as a class attribute, and implementing
`ingest_from_directory`. The registry rejects adapters that fail any of
these requirements.

`mseco ingest` is the CLI entry point; it calls `ingest_from_directory`,
persists the resulting artifacts through `ArtifactManager`, and records a
`raw_output_ingested` event in the journal.

---

## `ReportRenderer`

Source: [`core/contracts/types.py:125-131`](../src/gxassessms/core/contracts/types.py)

```python
@runtime_checkable
class ReportRenderer(Protocol):
    format: str
    theme: str
    supported_payload_versions: str    # semver range, e.g. ">=1.0.0,<2.0.0"

    def render(self, payload: ReportPayload, output_dir: Path) -> Path: ...
```

### Class attributes

| Attribute | Semantics |
|-----------|-----------|
| `format` | Output format identifier (e.g. `"docx"`, `"pptx"`, `"html"`). Used by `RendererRegistry.get_by_format()` to group renderers. |
| `theme` | Free-form theme identifier. The registry does not interpret this; renderers may surface it in output filenames or metadata. |
| `supported_payload_versions` | Comma-separated semver constraints (`>=`, `<=`, `>`, `<`, `==`). Validated by `validate_version_compatibility()` before render is invoked. |

### `render(payload, output_dir) -> Path`

Render `payload` to a file inside `output_dir`. Return the path actually
written. The caller (`RendererRegistry` invoking `NodeRenderer`) is
responsible for:

1. Validating payload version compatibility (raises `PayloadVersionError`).
2. Writing `payload.json` and `constants.json` into a temp directory.
3. Invoking the Node.js entry point with `--payload`, `--output`, and
   `--constants` arguments.
4. Wrapping any non-zero exit, missing output, or empty output as
   `ReportError`.

The bundled implementation `NodeRenderer` validates two further conditions
at construction time (catches problems before `RENDER` rather than during):

- `render.js` exists in the renderer package path.
- `node` is available on `PATH` and runs `node --version` successfully.

Either failure raises `RendererDependencyError`. This is what
`mseco preflight` step 4 checks for every registered renderer
([`renderer_registry.py:159-169`](../src/gxassessms/reporting/renderer_registry.py)).

A Python-only renderer is not required to use `NodeRenderer`. A
class implementing `render()` directly is fine; the Protocol is structural.

### Bundled renderer

`BasicDocxRenderer` (entry-point `basic_docx`) wraps a Node.js renderer
package shipped alongside the public package. It produces a plain `.docx`
summary suitable for engagement archives.

---

## `QAStrategy`

Source: [`core/contracts/types.py:134-154`](../src/gxassessms/core/contracts/types.py)

```python
@runtime_checkable
class QAStrategy(Protocol):
    is_noop: bool = False

    def review_findings(self, findings: list[ConsolidatedFinding]) -> list[QAResult]: ...
    def generate_narratives(
        self, findings: list[ConsolidatedFinding], config: EngagementConfig
    ) -> Narratives: ...
```

The `QA_REVIEW` stage calls `review_findings()`. If `is_noop` is `True` the
orchestrator auto-advances `QA_REVIEW -> QA_APPROVED` without further
gating; otherwise the engagement parks at `QA_REVIEW` for downstream
approval.

### Result shapes

```python
class QAResult(TypedDict):
    finding_instance_id: str
    adjusted_severity: Severity | None   # None means "no change recommended"
    confidence_delta: float              # Positive = increased confidence
    narrative: str | None                # Per-finding text, if generated
    flags: list[str]                     # e.g. ["budget_exhausted",
                                         #       "low_confidence",
                                         #       "potential_duplicate",
                                         #       "qa_quality_failed"]

class Narratives(TypedDict):
    executive_summary: str
    roadmap: str
    findings_narrative: str | None
    flags: NotRequired[list[str]]
```

`flags` is a free-form list of string tokens. The pipeline does not require
specific values; downstream consumers (reports, review interfaces) decide
how to surface them.

### Optional class attributes

| Attribute | Default | Effect |
|-----------|---------|--------|
| `is_noop` | `False` | When `True`, auto-advance state machine through QA |
| `priority` | `0` | Used during selection when multiple strategies are registered; higher wins. The `--qa-strategy <name>` CLI flag overrides priority. |

### Selection rules

1. `--qa-strategy <name>` on the CLI loads that exact entry point or fails.
2. Otherwise, the highest-`priority` strategy among loaded entry points
   wins. Ties resolve by `importlib.metadata` discovery order.
3. Convention: ship `priority = 0` for any default/no-op strategy and
   `priority >= 100` for any production strategy that wants to be preferred
   automatically when installed.

### Bundled strategy

`NoOpQAStrategy` (entry-point `noop`,
[`qa/noop.py`](../src/gxassessms/qa/noop.py)) returns no review results
and empty narratives. It satisfies the Protocol so the pipeline can run
end-to-end without any external dependency.

---

## `ConsolidationRule`

Source: [`core/contracts/types.py:157-168`](../src/gxassessms/core/contracts/types.py)

```python
@runtime_checkable
class ConsolidationRule(Protocol):
    def consolidate(self, findings: list[Finding]) -> list[ConsolidatedFinding]: ...
```

### Invariants

Property-based tests
([`tests/property/`](../tests/property/) -- see spec Section 11) enforce:

1. `len(output) <= len(input)` -- never produce more groups than inputs.
2. Every input `Finding` appears in exactly one output group.
3. Severity never decreases during merge.
4. No `dedup_key` appears in more than one consolidated finding.

### Bundled rule

`DefaultConsolidationRule` ([`consolidation/rules.py`](../src/gxassessms/consolidation/rules.py))
composes `UnionFindDedup` (grouping) with a `ConsolidationPolicy`
implementation (merging). To swap one piece, register a new rule via
`gxassessms.consolidation_rules`; to swap only the merge step, register a
new policy via `gxassessms.policies`.

---

## `NormalizationPolicy`

Source: [`core/contracts/types.py:171-185`](../src/gxassessms/core/contracts/types.py)

```python
@runtime_checkable
class NormalizationPolicy(Protocol):
    def normalize(
        self,
        observations: list[ToolObservation],
        adapter_severity_map: dict[tuple[str, str], str],
        adapter_category_map: dict[str, str],
        adapter_dedup_keys: dict[str, str],
    ) -> list[Finding]: ...
```

Transform tool-native `ToolObservation` records into normalized `Finding`
records by applying severity, category, and dedup-key mapping. The
orchestrator resolves the adapter-specific mapping tables (declarative
data in `adapters/<name>/mappings.py`) and passes them through.

`NormalizationPolicy` implementations must not perform I/O. YAML rule data
is loaded by `core/config/` and passed through the implementation's
constructor as a plain dict.

The default implementation in
[`policy/normalization.py`](../src/gxassessms/policy/normalization.py)
resolves severity in three passes (adapter-specific table, default rules,
fallback to a domain-status-driven default).

---

## `ConsolidationPolicy`

Source: [`policy/consolidation.py:34-52`](../src/gxassessms/policy/consolidation.py)

```python
@runtime_checkable
class ConsolidationPolicy(Protocol):
    def consolidate(self, findings: list[Finding]) -> list[ConsolidatedFinding]: ...
    def merge_group(
        self, finding_key: str, findings: list[Finding]
    ) -> ConsolidatedFinding: ...
```

Two usage patterns:

- `consolidate()` -- full pipeline: receives raw findings and returns a
  flat consolidated list. Bypasses the dedup engine and groups by
  `finding_key` directly.
- `merge_group()` -- called by `DefaultConsolidationRule` after the
  union-find dedup engine has built groups. Reconciles severity and status
  across the group, computes `ConfidenceScore`, builds the `SourceEvidence`
  list, and returns one `ConsolidatedFinding`.

Contract: `merge_group()` requires `findings` to be non-empty.
Implementations must raise `ConsolidationError` if called with an empty
list.

---

## `CredentialProvider`

Source: [`core/contracts/credentials.py:13-23`](../src/gxassessms/core/contracts/credentials.py)

```python
@runtime_checkable
class CredentialProvider(Protocol):
    def get_credential(self, key: str) -> str: ...
    def has_credential(self, key: str) -> bool: ...
```

Resolve credential lookup keys to actual secret values. Implementations
must:

- Raise `KeyError` from `get_credential` if the key cannot be resolved.
- Return `False` from `has_credential` for unresolvable keys (without
  raising).
- Never log resolved values or write them to disk.

Adapter code calls `provider.get_credential(key)` only inside the
narrowest possible scope (`collect()` or `authenticate()`), immediately
hands the resulting string to the underlying SDK or subprocess, and never
stores it on `self`.

### Bundled provider

`EnvVarProvider` (entry-point `env_var`) reads from environment variables.
The `client_secret_env`, `client_id_env`, and similar fields in the
engagement config carry the env var *name*; resolution happens at run
time.

---

## Discovery and Validation

All discovery flows go through
[`registry.discover_entry_points()`](../src/gxassessms/registry.py), which
returns a `DiscoveryResult` containing successfully loaded plugins plus a
list of `DiscoveryError` records for entry points that failed to import.
`ImportError` and `AttributeError` are caught individually so one broken
plugin cannot prevent the others from loading; any other exception
propagates.

Plugin-type-specific validation lives in the registry module for that type
(e.g. `adapters/__init__.py` for adapters,
`reporting/renderer_registry.py` for renderers). Failed validation
produces a `DiscoveryError` and excludes the plugin from the active
registry; it never raises.

`mseco preflight` reports both the loaded plugins and the discovery /
validation errors so problems are surfaced before a client engagement
runs.

## Versioning Discipline

Pre-1.0 the public API is unstable. After 1.0:

- Adding optional methods to a Protocol is a minor change.
- Renaming or removing methods, changing signatures, or tightening type
  parameters is a major change.
- `ReportPayload.schema_version` follows additive-fields = minor /
  removing-or-renaming = major.

See the architecture spec's "Formal Compatibility Policy" section
(deferred to v1) for the longer-form rules.
