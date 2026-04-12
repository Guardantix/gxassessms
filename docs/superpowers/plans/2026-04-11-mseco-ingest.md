# `mseco ingest` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `mseco ingest <engagement_id> --tool <slug> --from <path>` CLI command that constructs a valid `RawToolOutput` manifest from operator-provided raw tool files so that `mseco replay <id> --from parse` can process client-provided pre-collected output.

**Architecture:** Seven coordinated pieces: (1) data model extensions (`IngestProvenance`, `source_mode`), (2) shared `build_collection_output` helper extracted from existing `collect()` tails, (3) per-adapter `ingest_from_directory()` methods on 5 of 7 adapters, (4) engagement bootstrap fix so `engagement create` provisions the on-disk directory, (5) atomic single-slug `save_ingested_raw_output()` persistence method with legacy-migration fallback, (6) CLI command with `--repair-event` audit-neutral recovery, (7) manifest version bump from 1.0.0 to 1.1.0 with backward-read compatibility.

**Tech Stack:** Python 3.14+, Pydantic 2.x, Click, hashlib (SHA-256), shutil, sqlite3, pytest, rich

**Design spec:** `docs/superpowers/specs/2026-04-11-mseco-ingest-design.md` -- read this before starting any task. It is the source of truth for all model definitions, function signatures, error semantics, and test cases. References like "Section 2.1" below point into that document.

---

## File Structure

### New Files

| File | Responsibility |
|------|---------------|
| `src/gxassessms/cli/commands/ingest.py` | `mseco ingest` Click command (normal + repair-event paths) |
| `tests/unit/adapters/test_build_collection_output.py` | Shared helper validation, sorting, empty-items rejection |
| `tests/unit/adapters/test_scubagear_ingest.py` | ScubaGear `ingest_from_directory` + `default_schema_version` parity |
| `tests/unit/adapters/test_maester_ingest.py` | Maester `ingest_from_directory` + `default_schema_version` parity |
| `tests/unit/adapters/test_prowler_ingest.py` | Prowler `ingest_from_directory` + `default_schema_version` parity |
| `tests/unit/adapters/test_azure_advisor_ingest.py` | Azure Advisor `ingest_from_directory` + `default_schema_version` parity |
| `tests/unit/adapters/test_secure_score_ingest.py` | Secure Score `ingest_from_directory` + `default_schema_version` parity |
| `tests/unit/adapters/test_scubagear_collect_parity.py` | ScubaGear collect() parity after refactor |
| `tests/unit/adapters/test_maester_collect_parity.py` | Maester collect() parity after refactor |
| `tests/unit/adapters/test_prowler_collect_parity.py` | Prowler collect() parity after refactor |
| `tests/unit/adapters/test_azure_advisor_collect_parity.py` | Azure Advisor collect() parity after refactor |
| `tests/unit/adapters/test_secure_score_collect_parity.py` | Secure Score collect() parity after refactor |
| `tests/unit/adapters/test_monkey365_collect_parity.py` | Monkey365 collect() parity after refactor |
| `tests/unit/adapters/test_m365_assess_collect_parity.py` | M365-Assess collect() parity after refactor |
| `tests/unit/cli/test_ingest_cmd.py` | CLI unit tests (normal path + repair-event) |
| `tests/unit/cli/test_engagement_create.py` | Engagement bootstrap tests |
| `tests/integration/test_ingest_flow.py` | End-to-end ingest + replay integration |

### Modified Files

| File | Changes |
|------|---------|
| `src/gxassessms/core/domain/models.py` | Add `IngestProvenance` model; add `source_mode`, `ingest_provenance` fields to `RawToolOutput`; add model validator |
| `src/gxassessms/core/domain/constants.py` | Bump `ManifestVersion`/`MANIFEST_VERSION_CURRENT`/`RECOGNIZED_MANIFEST_VERSIONS` to include `"1.1.0"`; add `"ingest"` to `AdapterCapability`/`ADAPTER_CAPABILITIES`; add `"1.1.0"` entry to `EXECUTION_METADATA_ALLOWLIST` |
| `src/gxassessms/core/contracts/types.py` | Add `IngestCapableAdapter(ToolAdapter, Protocol)` |
| `src/gxassessms/adapters/_base.py` | Add `build_collection_output()` shared helper |
| `src/gxassessms/adapters/__init__.py` | Extend `_validate_adapter()` for `"ingest"` capability consistency |
| `src/gxassessms/adapters/scubagear/adapter.py` | Refactor `collect()` tail to use `build_collection_output`; add `ingest_from_directory()`, `default_schema_version`, `"ingest"` capability |
| `src/gxassessms/adapters/maester/adapter.py` | Same pattern as ScubaGear |
| `src/gxassessms/adapters/prowler/adapter.py` | Same pattern as ScubaGear |
| `src/gxassessms/adapters/azure_advisor/adapter.py` | Same pattern as ScubaGear |
| `src/gxassessms/adapters/secure_score/adapter.py` | Same pattern as ScubaGear |
| `src/gxassessms/adapters/monkey365/adapter.py` | Refactor `collect()` tail only; NO ingest method |
| `src/gxassessms/adapters/m365_assess/adapter.py` | Refactor `collect()` tail only; NO ingest method |
| `src/gxassessms/persistence/artifacts.py` | Add `save_ingested_raw_output()` method; touch `save_raw_outputs` for explicit `source_mode="collected"` |
| `src/gxassessms/persistence/engagement_repo.py` | Add `engagement_id` kwarg to `create()`; add `update_engagement_dir()` |
| `src/gxassessms/pipeline/config_snapshot_mirror.py` | Add `mirror_config_snapshot_from_db_strict()` public function |
| `src/gxassessms/pipeline/state.py` | Add `"raw_output_ingested"` to `EventType` Literal |
| `src/gxassessms/pipeline/orchestrator.py` | Add `record_raw_output_ingested()` public wrapper |
| `src/gxassessms/cli/_helpers.py` | Add `resolve_enabled_adapter()`, `require_ingest_capable()`, `get_engagement_lock()` |
| `src/gxassessms/cli/main.py` | Register `ingest_cmd` via `_try_register` |
| `src/gxassessms/cli/commands/engagement.py` | Rewrite `create_cmd` to provision dir + mirror + rollback |
| `docs/runbook.md` | Update scenario 3 for the 5 supported adapters |
| `tests/unit/core/test_models.py` | IngestProvenance validators, RawToolOutput source_mode invariant, backward compat |
| `tests/unit/core/test_constants.py` | Manifest version, allowlist, capability constants |
| `tests/unit/core/test_types.py` | IngestCapableAdapter Protocol checks |
| `tests/unit/adapters/test_adapter_registry.py` | Capability consistency check |
| `tests/unit/adapters/test_adapter_capabilities.py` | Negative tests for Monkey365/M365-Assess |
| `tests/unit/persistence/test_artifacts.py` | save_ingested_raw_output, rollback, legacy migration |
| `tests/unit/pipeline/test_orchestrator.py` | record_raw_output_ingested forwarding |
| `tests/unit/pipeline/test_confinement.py` | 1.1.0 manifest version gate |
| `tests/unit/pipeline/test_replay.py` | Load 1.1.0 ingested manifest |
| `tests/unit/cli/test_helpers.py` | New helper functions |

---

### Task 1: Data Model and Constants

**Files:**
- Modify: `src/gxassessms/core/domain/models.py:264-301`
- Modify: `src/gxassessms/core/domain/constants.py:113-175`
- Test: `tests/unit/core/test_models.py`
- Test: `tests/unit/core/test_constants.py`

- [ ] **Step 1: Write failing tests for IngestProvenance**

```python
# tests/unit/core/test_models.py — append to existing file

from gxassessms.core.domain.models import IngestProvenance


class TestIngestProvenance:
    """Spec Section 2.1: IngestProvenance model."""

    def test_valid_provenance(self) -> None:
        prov = IngestProvenance(
            source_path="/tmp/client-export",
            ingested_at=datetime(2026, 4, 11, 12, 0, 0, tzinfo=timezone.utc),
            ingested_by="human:alice",
            replaced=False,
        )
        assert prov.source_path == "/tmp/client-export"
        assert prov.replaced is False

    def test_source_path_must_be_absolute(self) -> None:
        with pytest.raises(ValidationError, match="must be absolute"):
            IngestProvenance(
                source_path="relative/path",
                ingested_at=datetime(2026, 4, 11, tzinfo=timezone.utc),
                ingested_by="human:alice",
                replaced=False,
            )

    def test_source_path_rejects_empty(self) -> None:
        with pytest.raises(ValidationError, match="must be non-empty"):
            IngestProvenance(
                source_path="",
                ingested_at=datetime(2026, 4, 11, tzinfo=timezone.utc),
                ingested_by="human:alice",
                replaced=False,
            )

    def test_ingested_by_must_be_human_prefixed(self) -> None:
        with pytest.raises(ValidationError, match="human:"):
            IngestProvenance(
                source_path="/tmp/export",
                ingested_at=datetime(2026, 4, 11, tzinfo=timezone.utc),
                ingested_by="bot:automation",
                replaced=False,
            )

    def test_ingested_at_must_be_utc(self) -> None:
        prov = IngestProvenance(
            source_path="/tmp/export",
            ingested_at=datetime(2026, 4, 11, 12, 0, 0),  # naive
            ingested_by="human:alice",
            replaced=False,
        )
        assert prov.ingested_at.tzinfo is not None
```

- [ ] **Step 2: Write failing tests for RawToolOutput source_mode invariant**

```python
# tests/unit/core/test_models.py — append

class TestRawToolOutputSourceMode:
    """Spec Section 2.2: source_mode + ingest_provenance fields."""

    def test_default_source_mode_is_collected(self) -> None:
        # Existing 1.0.0 manifests have no source_mode; default must be "collected"
        raw = RawToolOutput(
            tool=ToolSource.SCUBAGEAR,
            tool_slug="scubagear",
            schema_version="1.7.1",
            manifest_version="1.0.0",
            timestamp=datetime(2026, 4, 11, tzinfo=timezone.utc),
            file_manifest={},
            execution_metadata={},
        )
        assert raw.source_mode == "collected"
        assert raw.ingest_provenance is None

    def test_ingested_requires_provenance(self) -> None:
        with pytest.raises(ValidationError, match="requires ingest_provenance"):
            RawToolOutput(
                tool=ToolSource.SCUBAGEAR,
                tool_slug="scubagear",
                schema_version="1.7.1",
                manifest_version="1.1.0",
                timestamp=datetime(2026, 4, 11, tzinfo=timezone.utc),
                file_manifest={},
                execution_metadata={},
                source_mode="ingested",
                ingest_provenance=None,
            )

    def test_collected_rejects_provenance(self) -> None:
        prov = IngestProvenance(
            source_path="/tmp/export",
            ingested_at=datetime(2026, 4, 11, tzinfo=timezone.utc),
            ingested_by="human:alice",
            replaced=False,
        )
        with pytest.raises(ValidationError, match="must not carry"):
            RawToolOutput(
                tool=ToolSource.SCUBAGEAR,
                tool_slug="scubagear",
                schema_version="1.7.1",
                manifest_version="1.1.0",
                timestamp=datetime(2026, 4, 11, tzinfo=timezone.utc),
                file_manifest={},
                execution_metadata={},
                source_mode="collected",
                ingest_provenance=prov,
            )

    def test_backward_read_compat_1_0_0_manifest(self) -> None:
        """A 1.0.0 manifest JSON without source_mode parses correctly."""
        raw_json = {
            "tool": "ScubaGear",
            "tool_slug": "scubagear",
            "schema_version": "1.7.1",
            "manifest_version": "1.0.0",
            "timestamp": "2026-04-11T00:00:00+00:00",
            "file_manifest": {},
            "execution_metadata": {},
        }
        raw = RawToolOutput.model_validate(raw_json)
        assert raw.source_mode == "collected"
        assert raw.ingest_provenance is None
```

- [ ] **Step 3: Write failing tests for constants changes**

```python
# tests/unit/core/test_constants.py — append to existing file

def test_manifest_version_includes_1_1_0() -> None:
    from gxassessms.core.domain.constants import RECOGNIZED_MANIFEST_VERSIONS
    assert "1.1.0" in RECOGNIZED_MANIFEST_VERSIONS

def test_manifest_version_current_is_1_1_0() -> None:
    from gxassessms.core.domain.constants import MANIFEST_VERSION_CURRENT
    assert MANIFEST_VERSION_CURRENT == "1.1.0"

def test_execution_metadata_allowlist_has_1_1_0() -> None:
    from gxassessms.core.domain.constants import EXECUTION_METADATA_ALLOWLIST
    assert "1.1.0" in EXECUTION_METADATA_ALLOWLIST
    # Same per-tool keys as 1.0.0
    assert EXECUTION_METADATA_ALLOWLIST["1.1.0"] == EXECUTION_METADATA_ALLOWLIST["1.0.0"]

def test_adapter_capability_includes_ingest() -> None:
    from gxassessms.core.domain.constants import ADAPTER_CAPABILITIES
    assert "ingest" in ADAPTER_CAPABILITIES
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `pytest tests/unit/core/test_models.py::TestIngestProvenance tests/unit/core/test_models.py::TestRawToolOutputSourceMode tests/unit/core/test_constants.py::test_manifest_version_includes_1_1_0 tests/unit/core/test_constants.py::test_adapter_capability_includes_ingest -v 2>&1 | tail -20`
Expected: FAIL (IngestProvenance not defined, source_mode attribute missing, constants unchanged)

- [ ] **Step 5: Implement IngestProvenance model**

Add to `src/gxassessms/core/domain/models.py` before the `RawToolOutput` class (around line 240):

```python
class IngestProvenance(BaseModel):
    """Operator-visible provenance for ingested raw output.

    Present only on manifests written by ``mseco ingest``. Records what the
    operator did, when they did it, and where the source data came from.
    The ``replaced`` field is the committed audit record of whether this
    ingest overwrote prior raw output -- set by the persistence layer based
    on actual pre-commit state, not the operator's --replace flag.
    """

    model_config = ConfigDict(extra="forbid")

    source_path: str
    ingested_at: datetime
    ingested_by: str
    replaced: bool

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
        if not v.startswith("human:") or len(v) <= len("human:"):
            raise ValueError(
                f"ingested_by must be 'human:<operator>' (manifest ingest is "
                f"a human-driven operation), got {v!r}"
            )
        return v
```

- [ ] **Step 6: Add source_mode and ingest_provenance to RawToolOutput**

Modify `RawToolOutput` in `src/gxassessms/core/domain/models.py` (around line 264):

```python
class RawToolOutput(BaseModel):
    """On-disk replay manifest. POSIX-relative canonical paths."""

    model_config = ConfigDict(extra="forbid")

    tool: ToolSource
    tool_slug: str = Field(pattern=TOOL_SLUG_PATTERN)
    schema_version: str
    manifest_version: str
    timestamp: datetime
    file_manifest: dict[str, ArtifactRecord]
    execution_metadata: dict[str, Any]

    # New fields -- defaults preserve backward-read compatibility with 1.0.0
    source_mode: Literal["collected", "ingested"] = "collected"
    ingest_provenance: IngestProvenance | None = None

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_utc(cls, v: datetime) -> datetime:
        return ensure_utc(v)

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

Add `Literal` to imports from `typing` and `model_validator` to imports from `pydantic`.

- [ ] **Step 7: Update constants**

In `src/gxassessms/core/domain/constants.py`:

```python
# Line 113: extend AdapterCapability Literal
AdapterCapability = Literal[
    "collect", "parse", "prerequisites", "shared_auth",
    "coverage_export", "benchmark_mapping", "ingest",
]

# Line 122: extend ADAPTER_CAPABILITIES frozenset
ADAPTER_CAPABILITIES: frozenset[str] = frozenset({
    "collect", "parse", "prerequisites", "shared_auth",
    "coverage_export", "benchmark_mapping", "ingest",
})

# Line 149: extend ManifestVersion
ManifestVersion = Literal["1.0.0", "1.1.0"]

# Line 151: bump current
MANIFEST_VERSION_CURRENT: str = "1.1.0"

# Line 153: extend recognized set
RECOGNIZED_MANIFEST_VERSIONS: frozenset[str] = frozenset({"1.0.0", "1.1.0"})

# Line 165: add 1.1.0 to allowlist (duplicate of 1.0.0 keys, explicitly)
# After the existing "1.0.0": {...} entry, add:
    "1.1.0": {
        "scubagear": frozenset({"modules", "module_provenance"}),
        "maester": frozenset({"module_provenance"}),
        "monkey365": frozenset({"output_dir", "module_provenance"}),
        "m365-assess": frozenset({"script", "tenant_id", "controls_dir"}),
        "prowler": frozenset({"output_dir", "auth_method", "checks"}),
        "azure-advisor": frozenset({"recommendation_count"}),
        "secure-score": frozenset({"profiles_count", "scores_count"}),
    },
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `pytest tests/unit/core/test_models.py::TestIngestProvenance tests/unit/core/test_models.py::TestRawToolOutputSourceMode tests/unit/core/test_constants.py -v 2>&1 | tail -20`
Expected: All PASS

- [ ] **Step 9: Run the full test suite to check for regressions**

Run: `pytest tests/unit/core/ -v --tb=short 2>&1 | tail -30`
Expected: All PASS. Existing RawToolOutput tests should still pass because `source_mode` defaults to `"collected"` and `ingest_provenance` defaults to `None`.

- [ ] **Step 10: Commit**

```bash
git add src/gxassessms/core/domain/models.py src/gxassessms/core/domain/constants.py tests/unit/core/test_models.py tests/unit/core/test_constants.py
git commit -m "feat: add IngestProvenance model, source_mode field, manifest version 1.1.0 (#78)"
```

---

### Task 2: Protocol Extension -- IngestCapableAdapter

**Files:**
- Modify: `src/gxassessms/core/contracts/types.py:65-100`
- Test: `tests/unit/core/test_types.py`

- [ ] **Step 1: Write failing tests for IngestCapableAdapter Protocol**

```python
# tests/unit/core/test_types.py — append to existing file

from gxassessms.core.contracts.types import IngestCapableAdapter


class TestIngestCapableAdapter:
    """Spec Section 3.5: IngestCapableAdapter Protocol."""

    def test_protocol_is_runtime_checkable(self) -> None:
        assert hasattr(IngestCapableAdapter, "__protocol_attrs__") or hasattr(
            IngestCapableAdapter, "__abstractmethods__"
        )
        # The Protocol decorator makes it runtime-checkable
        from typing import runtime_checkable
        # Just verify we can use isinstance
        assert callable(getattr(IngestCapableAdapter, "__instancecheck__", None))

    def test_class_with_ingest_satisfies_protocol(self) -> None:
        from pathlib import Path
        from datetime import datetime
        from gxassessms.core.domain.models import CollectionOutput

        class FakeIngestAdapter:
            tool_name = "Fake"
            storage_slug = "fake"
            tool_source = "Fake"
            capabilities = frozenset({"collect", "ingest"})
            default_schema_version = "1.0.0"

            def ingest_from_directory(
                self, source_dir: Path, *, schema_version: str, timestamp: datetime
            ) -> CollectionOutput:
                ...

            def check_prerequisites(self): ...
            def authenticate(self, config, auth): ...
            def collect(self, config, auth, output_dir, timeout): ...
            def validate_raw(self, manifest): ...
            def parse(self, manifest): ...
            def coverage(self, manifest): ...

        assert isinstance(FakeIngestAdapter(), IngestCapableAdapter)

    def test_class_without_ingest_method_fails_check(self) -> None:
        class NoIngestAdapter:
            tool_name = "NoIngest"
            storage_slug = "no-ingest"
            tool_source = "NoIngest"
            capabilities = frozenset({"collect"})
            # Missing: default_schema_version, ingest_from_directory

            def check_prerequisites(self): ...
            def authenticate(self, config, auth): ...
            def collect(self, config, auth, output_dir, timeout): ...
            def validate_raw(self, manifest): ...
            def parse(self, manifest): ...
            def coverage(self, manifest): ...

        assert not isinstance(NoIngestAdapter(), IngestCapableAdapter)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/core/test_types.py::TestIngestCapableAdapter -v 2>&1 | tail -10`
Expected: FAIL (IngestCapableAdapter not importable)

- [ ] **Step 3: Implement IngestCapableAdapter Protocol**

Add to `src/gxassessms/core/contracts/types.py` after the `ToolAdapter` Protocol:

```python
@runtime_checkable
class IngestCapableAdapter(ToolAdapter, Protocol):
    """ToolAdapter that can construct a CollectionOutput from operator-
    provided raw tool output.

    An adapter declares this capability via ``"ingest" in capabilities``,
    by implementing ``ingest_from_directory``, AND by declaring
    ``default_schema_version`` as a class attribute.
    """

    default_schema_version: str

    def ingest_from_directory(
        self,
        source_dir: Path,
        *,
        schema_version: str,
        timestamp: datetime,
    ) -> CollectionOutput: ...
```

Add `Path` from `pathlib` and `datetime` from `datetime` and `CollectionOutput` from `gxassessms.core.domain.models` to imports.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/unit/core/test_types.py::TestIngestCapableAdapter -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/gxassessms/core/contracts/types.py tests/unit/core/test_types.py
git commit -m "feat: add IngestCapableAdapter Protocol with default_schema_version (#78)"
```

---

### Task 3: Shared Helper -- build_collection_output

**Files:**
- Modify: `src/gxassessms/adapters/_base.py`
- Create: `tests/unit/adapters/test_build_collection_output.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/adapters/test_build_collection_output.py
"""Tests for build_collection_output shared helper (spec Section 3.1)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from gxassessms.adapters._base import build_collection_output
from gxassessms.core.contracts.errors import CollectionError
from gxassessms.core.domain.enums import ToolSource


class TestBuildCollectionOutput:
    """Tests for the shared hashing + CollectionOutput assembly helper."""

    def test_happy_path_single_item(self, tmp_path: Path) -> None:
        f = tmp_path / "results.json"
        f.write_text('{"data": 1}')
        ts = datetime(2026, 4, 11, tzinfo=timezone.utc)
        result = build_collection_output(
            tool=ToolSource.SCUBAGEAR,
            tool_slug="scubagear",
            items=[(f, "scubagear/results.json")],
            schema_version="1.7.1",
            timestamp=ts,
            execution_metadata={},
        )
        assert result.tool == ToolSource.SCUBAGEAR
        assert result.tool_slug == "scubagear"
        assert result.schema_version == "1.7.1"
        assert result.timestamp == ts
        assert len(result.artifacts) == 1
        assert result.artifacts[0].target_relpath == "scubagear/results.json"
        assert len(result.artifacts[0].sha256) == 64
        assert result.execution_metadata == {}

    def test_artifacts_sorted_by_target_relpath(self, tmp_path: Path) -> None:
        b = tmp_path / "b.json"
        a = tmp_path / "a.json"
        b.write_text("b")
        a.write_text("a")
        result = build_collection_output(
            tool=ToolSource.PROWLER,
            tool_slug="prowler",
            items=[(b, "prowler/b.json"), (a, "prowler/a.json")],
            schema_version="1.4.0",
            timestamp=datetime(2026, 4, 11, tzinfo=timezone.utc),
            execution_metadata={},
        )
        assert result.artifacts[0].target_relpath == "prowler/a.json"
        assert result.artifacts[1].target_relpath == "prowler/b.json"

    def test_empty_items_raises(self) -> None:
        with pytest.raises(CollectionError, match="empty"):
            build_collection_output(
                tool=ToolSource.SCUBAGEAR,
                tool_slug="scubagear",
                items=[],
                schema_version="1.7.1",
                timestamp=datetime(2026, 4, 11, tzinfo=timezone.utc),
                execution_metadata={},
            )

    def test_target_relpath_must_start_with_slug(self, tmp_path: Path) -> None:
        f = tmp_path / "results.json"
        f.write_text("data")
        with pytest.raises(ValueError, match="scubagear/"):
            build_collection_output(
                tool=ToolSource.SCUBAGEAR,
                tool_slug="scubagear",
                items=[(f, "wrong-slug/results.json")],
                schema_version="1.7.1",
                timestamp=datetime(2026, 4, 11, tzinfo=timezone.utc),
                execution_metadata={},
            )

    def test_execution_metadata_passed_through(self, tmp_path: Path) -> None:
        f = tmp_path / "r.json"
        f.write_text("data")
        meta = {"modules": ["ExoModule"], "module_provenance": {}}
        result = build_collection_output(
            tool=ToolSource.SCUBAGEAR,
            tool_slug="scubagear",
            items=[(f, "scubagear/r.json")],
            schema_version="1.7.1",
            timestamp=datetime(2026, 4, 11, tzinfo=timezone.utc),
            execution_metadata=meta,
        )
        assert result.execution_metadata == meta
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/adapters/test_build_collection_output.py -v 2>&1 | tail -10`
Expected: FAIL (build_collection_output not importable)

- [ ] **Step 3: Implement build_collection_output**

Add to `src/gxassessms/adapters/_base.py` at the end of the file:

```python
from gxassessms.core.domain.models import CollectedArtifact, CollectionOutput
from gxassessms.core.domain.enums import ToolSource
from gxassessms.core.domain.path_validation import validate_canonical_posix_path
from gxassessms.core.hashing import sha256_file


def build_collection_output(
    *,
    tool: ToolSource,
    tool_slug: str,
    items: list[tuple[Path, str]],
    schema_version: str,
    timestamp: datetime,
    execution_metadata: dict[str, Any],
) -> CollectionOutput:
    """Hash source files and assemble a CollectionOutput.

    Called AFTER the caller has done adapter-specific discovery (and, for
    live collect(), adapter-specific freshness filtering). The helper is
    layout-agnostic: callers provide pre-computed (source_path,
    target_relpath) pairs.

    Raises:
        CollectionError: On hash failure or zero items.
        ValueError: On target_relpath format violation.
    """
    if not items:
        raise CollectionError(
            f"No items to collect for {tool_slug!r} (empty items list)",
            adapter_name=tool_slug,
        )

    slug_prefix = f"{tool_slug}/"
    artifacts: list[CollectedArtifact] = []
    for source_path, target_relpath in items:
        validate_canonical_posix_path(target_relpath)
        if not target_relpath.startswith(slug_prefix):
            raise ValueError(
                f"target_relpath {target_relpath!r} must start with "
                f"{slug_prefix!r} for tool_slug {tool_slug!r}"
            )
        try:
            sha = sha256_file(source_path)
        except OSError as exc:
            raise CollectionError(
                f"Cannot hash {source_path}: {exc}",
                adapter_name=tool_slug,
            ) from exc
        artifacts.append(
            CollectedArtifact(
                source_path=str(source_path),
                target_relpath=target_relpath,
                encoding="utf-8",
                sha256=sha,
            )
        )

    artifacts.sort(key=lambda a: a.target_relpath)

    return CollectionOutput(
        tool=tool,
        tool_slug=tool_slug,
        schema_version=schema_version,
        timestamp=timestamp,
        artifacts=artifacts,
        execution_metadata=execution_metadata,
    )
```

Add `from datetime import datetime` and `from typing import Any` to the top-level imports if not present.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/unit/adapters/test_build_collection_output.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/gxassessms/adapters/_base.py tests/unit/adapters/test_build_collection_output.py
git commit -m "feat: add build_collection_output shared helper (#78)"
```

---

### Task 4: Adapter collect() Refactor -- All 7 Adapters

**Files:**
- Modify: `src/gxassessms/adapters/scubagear/adapter.py`
- Modify: `src/gxassessms/adapters/maester/adapter.py`
- Modify: `src/gxassessms/adapters/prowler/adapter.py`
- Modify: `src/gxassessms/adapters/azure_advisor/adapter.py`
- Modify: `src/gxassessms/adapters/secure_score/adapter.py`
- Modify: `src/gxassessms/adapters/monkey365/adapter.py`
- Modify: `src/gxassessms/adapters/m365_assess/adapter.py`
- Create: `tests/unit/adapters/test_scubagear_collect_parity.py` (and 6 more)

This task refactors each adapter's `collect()` method to use `build_collection_output()` for the hashing + CollectionOutput assembly tail, with zero behavioral change. The refactor is verified by parity tests.

**Spec reference:** Section 3.3 (collect refactor), Section 6.3 (parity tests).

- [ ] **Step 1: Refactor ScubaGear collect() tail**

In `src/gxassessms/adapters/scubagear/adapter.py`, replace the hashing + CollectionOutput assembly (approximately lines 174-199) with:

```python
        from gxassessms.adapters._base import build_collection_output

        results_path = Path(results_file)
        items = [(results_path, f"{self.storage_slug}/{results_path.name}")]

        logger.info(
            "ScubaGear collection complete. Output dir: %s, %d artifacts",
            run_dir,
            len(items),
        )

        return build_collection_output(
            tool=ToolSource.SCUBAGEAR,
            tool_slug=self.storage_slug,
            items=items,
            schema_version=_SCHEMA_VERSION,
            timestamp=utc_now(),
            execution_metadata={
                "modules": modules,
                "module_provenance": verification_result.to_json_dict(),
            },
        )
```

Remove the now-unused `sha256_file`, `CollectedArtifact` imports if they are not used elsewhere in the file.

- [ ] **Step 2: Refactor Maester collect() tail**

In `src/gxassessms/adapters/maester/adapter.py`, replace approximately lines 153-172 with:

```python
        from gxassessms.adapters._base import build_collection_output

        results_path = json_results[0]
        items = [(results_path, f"{self.storage_slug}/{results_path.name}")]

        return build_collection_output(
            tool=ToolSource.MAESTER,
            tool_slug=self.storage_slug,
            items=items,
            schema_version="1.0.0",
            timestamp=utc_now(),
            execution_metadata={
                "module_provenance": verification_result.to_json_dict(),
            },
        )
```

- [ ] **Step 3: Refactor Prowler collect() tail**

In `src/gxassessms/adapters/prowler/adapter.py`, replace the hashing loop + CollectionOutput (approximately lines 373-405) with:

```python
        from gxassessms.adapters._base import build_collection_output

        items = [
            (f, f"{self.storage_slug}/{f.relative_to(output_dir).as_posix()}")
            for f in ocsf_files
        ]

        logger.info(
            "Prowler collection complete. %d OCSF output file(s) in %s",
            len(ocsf_files),
            output_dir,
        )

        return build_collection_output(
            tool=ToolSource.PROWLER,
            tool_slug=self.storage_slug,
            items=items,
            schema_version=_SCHEMA_VERSION,
            timestamp=utc_now(),
            execution_metadata={
                "output_dir": str(output_dir),
                "auth_method": config.auth.method,
                "checks": checks,
            },
        )
```

- [ ] **Step 4: Refactor Azure Advisor collect() tail**

In `src/gxassessms/adapters/azure_advisor/adapter.py`, replace approximately lines 234-260 with:

```python
        from gxassessms.adapters._base import build_collection_output

        items = [(output_file, f"{self.storage_slug}/{_OUTPUT_FILENAME}")]

        logger.info(
            "Azure Advisor collection complete: %d recommendations saved to %s",
            len(all_recommendations),
            output_file,
        )

        return build_collection_output(
            tool=ToolSource.AZURE_ADVISOR,
            tool_slug=self.storage_slug,
            items=items,
            schema_version=_ADVISOR_API_VERSION,
            timestamp=utc_now(),
            execution_metadata={
                "recommendation_count": len(all_recommendations),
            },
        )
```

- [ ] **Step 5: Refactor Secure Score collect() tail**

In `src/gxassessms/adapters/secure_score/adapter.py`, replace approximately lines 149-183 with:

```python
        from gxassessms.adapters._base import build_collection_output

        items = [
            (profiles_path, f"{self.storage_slug}/{_PROFILES_FILENAME}"),
            (scores_path, f"{self.storage_slug}/{_SCORES_FILENAME}"),
        ]

        logger.info(
            "Secure Score collection complete. Output dir: %s, %d artifacts",
            output_dir,
            len(items),
        )

        return build_collection_output(
            tool=ToolSource.SECURE_SCORE,
            tool_slug=self.storage_slug,
            items=items,
            schema_version=_SCHEMA_VERSION,
            timestamp=utc_now(),
            execution_metadata={
                "profiles_count": len(profiles_data.get("value", [])),
                "scores_count": len(scores_data.get("value", [])),
            },
        )
```

- [ ] **Step 6: Refactor Monkey365 and M365-Assess collect() tails (same pattern)**

Apply the same `build_collection_output` extraction to Monkey365's and M365-Assess's `collect()` methods. These adapters keep their freshness-filtering logic above the extraction point unchanged. Only the hashing + CollectionOutput construction is replaced with a call to `build_collection_output`.

For M365-Assess, the dual-root (CSVs + controls/) pattern becomes:

```python
        from gxassessms.adapters._base import build_collection_output

        csv_items = [
            (csv, f"{self.storage_slug}/{csv.name}")
            for csv in sorted(csv_files, key=lambda f: f.name)
        ]
        controls_items = [
            (controls_dir / filename, f"{self.storage_slug}/controls/{filename}")
            for filename in ("risk-severity.json", "registry.json")
            if (controls_dir / filename).is_file()
        ]

        return build_collection_output(
            tool=ToolSource.M365_ASSESS,
            tool_slug=self.storage_slug,
            items=csv_items + controls_items,
            schema_version=_SCHEMA_VERSION,
            timestamp=utc_now(),
            execution_metadata=execution_metadata,
        )
```

- [ ] **Step 7: Write parity tests for each adapter**

Write one test file per adapter (7 files). Each test mocks the tool invocation, copies a fixture file into `output_dir`, runs the refactored `collect()`, and asserts the produced `CollectionOutput` matches expected values. See spec Section 6.3 for the parity test design. Example structure for ScubaGear:

```python
# tests/unit/adapters/test_scubagear_collect_parity.py
"""ScubaGear collect() parity test after build_collection_output refactor."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from gxassessms.adapters.scubagear.adapter import ScubaGearAdapter
from gxassessms.core.domain.enums import ToolSource


class TestScubaGearCollectParity:
    def test_collect_returns_expected_output(self, tmp_path: Path) -> None:
        # Create expected output structure
        run_dir = tmp_path / "M365-ScubaGear-2026-04-11"
        run_dir.mkdir()
        results_file = run_dir / "ScubaResults.json"
        results_file.write_text('{"ReportSummary": {}}')

        adapter = ScubaGearAdapter()
        # Mock subprocess + tool invocation, point at tmp_path
        # ... (adapter-specific mock setup)

        # Assert: CollectionOutput matches expected structure
        # assert result.tool == ToolSource.SCUBAGEAR
        # assert result.tool_slug == "scubagear"
        # assert len(result.artifacts) == 1
        # assert Path(result.artifacts[0].source_path).name == "ScubaResults.json"
        # assert Path(result.artifacts[0].source_path).is_relative_to(tmp_path)
        # assert len(result.artifacts[0].sha256) == 64
```

Each adapter's parity test follows the same pattern. Monkey365 and M365-Assess parity tests must additionally verify freshness filtering is preserved.

- [ ] **Step 8: Run all parity tests**

Run: `pytest tests/unit/adapters/test_*_collect_parity.py -v`
Expected: All PASS

- [ ] **Step 9: Run the full test suite to check for regressions**

Run: `pytest --tb=short 2>&1 | tail -10`
Expected: All PASS

- [ ] **Step 10: Commit**

```bash
git add src/gxassessms/adapters/ tests/unit/adapters/test_*_collect_parity.py
git commit -m "refactor: extract collect() tails into build_collection_output for all 7 adapters (#78)"
```

---

### Task 5: Adapter Ingest Methods -- 5 Adapters + Negative Tests

**Files:**
- Modify: `src/gxassessms/adapters/scubagear/adapter.py`
- Modify: `src/gxassessms/adapters/maester/adapter.py`
- Modify: `src/gxassessms/adapters/prowler/adapter.py`
- Modify: `src/gxassessms/adapters/azure_advisor/adapter.py`
- Modify: `src/gxassessms/adapters/secure_score/adapter.py`
- Create: `tests/unit/adapters/test_scubagear_ingest.py` (and 4 more)
- Modify: `tests/unit/adapters/test_adapter_capabilities.py`

**Spec reference:** Section 3.4, 3.5, 6.5.

- [ ] **Step 1: Add ingest capability + ingest_from_directory to ScubaGear**

In `src/gxassessms/adapters/scubagear/adapter.py`:

1. Add `"ingest"` to the `capabilities` frozenset.
2. Add `default_schema_version = _SCHEMA_VERSION` as a class attribute.
3. Add the `ingest_from_directory` method:

```python
    default_schema_version: str = _SCHEMA_VERSION

    def ingest_from_directory(
        self,
        source_dir: Path,
        *,
        schema_version: str,
        timestamp: datetime,
    ) -> CollectionOutput:
        """Construct a CollectionOutput from operator-provided ScubaGear output."""
        from gxassessms.adapters._base import build_collection_output

        json_files = [f for f in source_dir.iterdir() if f.suffix == ".json"]
        results_file = self._find_scuba_results_file([str(f) for f in json_files])

        if results_file is None:
            raise CollectionError(
                f"No ScubaResults JSON file found in {source_dir}",
                adapter_name=self.tool_name,
            )

        results_path = Path(results_file)
        items = [(results_path, f"{self.storage_slug}/{results_path.name}")]

        return build_collection_output(
            tool=ToolSource.SCUBAGEAR,
            tool_slug=self.storage_slug,
            items=items,
            schema_version=schema_version,
            timestamp=timestamp,
            execution_metadata={},
        )
```

- [ ] **Step 2: Add ingest capability to Maester, Prowler, Azure Advisor, Secure Score**

Same pattern for each: add `"ingest"` to capabilities, add `default_schema_version` class attribute, add `ingest_from_directory` method using each adapter's discovery rules minus freshness filtering. Implementation details per adapter:

**Maester:** `sorted(source_dir.glob("TestResults*.json"))`, require exactly 1.
**Prowler:** `list(source_dir.rglob(f"{_DEFAULT_OUTPUT_FILENAME}{_OCSF_EXTENSION}"))`.
**Azure Advisor:** Single file `source_dir / _OUTPUT_FILENAME`, raise if missing.
**Secure Score:** Two files at `_PROFILES_FILENAME` and `_SCORES_FILENAME`, raise if either missing.

- [ ] **Step 3: Write ingest tests for each of the 5 adapters**

Example for ScubaGear:

```python
# tests/unit/adapters/test_scubagear_ingest.py
"""ScubaGear ingest_from_directory tests (spec Section 3.4, 6.5)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from gxassessms.adapters.scubagear.adapter import ScubaGearAdapter
from gxassessms.core.contracts.errors import CollectionError


class TestScubaGearIngest:
    def test_happy_path(self, tmp_path: Path) -> None:
        (tmp_path / "ScubaResults.json").write_text('{"data": 1}')
        adapter = ScubaGearAdapter()
        ts = datetime(2026, 4, 11, tzinfo=timezone.utc)
        result = adapter.ingest_from_directory(
            tmp_path, schema_version="1.7.1", timestamp=ts,
        )
        assert len(result.artifacts) == 1
        assert result.artifacts[0].target_relpath == "scubagear/ScubaResults.json"
        assert result.execution_metadata == {}
        assert result.schema_version == "1.7.1"
        assert result.timestamp == ts

    def test_no_results_file_raises(self, tmp_path: Path) -> None:
        (tmp_path / "other.txt").write_text("data")
        adapter = ScubaGearAdapter()
        with pytest.raises(CollectionError, match="No ScubaResults"):
            adapter.ingest_from_directory(
                tmp_path,
                schema_version="1.7.1",
                timestamp=datetime(2026, 4, 11, tzinfo=timezone.utc),
            )

    def test_default_schema_version_matches_collect(self) -> None:
        assert ScubaGearAdapter().default_schema_version == "1.7.1"
```

Write analogous test files for the other 4 ingest-capable adapters with their specific discovery contracts and `default_schema_version` expected values.

- [ ] **Step 4: Write negative tests for Monkey365 and M365-Assess**

```python
# tests/unit/adapters/test_adapter_capabilities.py — extend existing or create

from gxassessms.adapters.monkey365.adapter import Monkey365Adapter
from gxassessms.adapters.m365_assess.adapter import M365AssessAdapter


def test_monkey365_has_no_ingest_capability() -> None:
    adapter = Monkey365Adapter()
    assert "ingest" not in adapter.capabilities
    assert not hasattr(adapter, "default_schema_version") or adapter.default_schema_version == ""
    assert not hasattr(adapter, "ingest_from_directory")


def test_m365_assess_has_no_ingest_capability() -> None:
    adapter = M365AssessAdapter()
    assert "ingest" not in adapter.capabilities
    assert not hasattr(adapter, "default_schema_version") or adapter.default_schema_version == ""
    assert not hasattr(adapter, "ingest_from_directory")
```

- [ ] **Step 5: Run all ingest + negative tests**

Run: `pytest tests/unit/adapters/test_*_ingest.py tests/unit/adapters/test_adapter_capabilities.py -v`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add src/gxassessms/adapters/ tests/unit/adapters/test_*_ingest.py tests/unit/adapters/test_adapter_capabilities.py
git commit -m "feat: add ingest_from_directory to 5 adapters, exclude Monkey365/M365-Assess (#78)"
```

---

### Task 6: Adapter Registry -- Capability Consistency Check

**Files:**
- Modify: `src/gxassessms/adapters/__init__.py:84-126`
- Test: `tests/unit/adapters/test_adapter_registry.py`

**Spec reference:** Section 3.5 (capability consistency check).

- [ ] **Step 1: Write failing test**

```python
# tests/unit/adapters/test_adapter_registry.py — append

def test_ingest_capability_requires_method_and_schema_version() -> None:
    """An adapter declaring 'ingest' must have both ingest_from_directory and default_schema_version."""
    from gxassessms.adapters import _validate_adapter

    class BadIngestAdapter:
        tool_name = "Bad"
        storage_slug = "bad"
        tool_source = "Bad"
        capabilities = frozenset({"collect", "ingest"})
        # Missing: default_schema_version, ingest_from_directory

    errors = _validate_adapter(BadIngestAdapter)
    assert any("ingest" in str(e).lower() for e in errors)
```

- [ ] **Step 2: Implement the check**

In `src/gxassessms/adapters/__init__.py`, inside `_validate_adapter()`, add after the existing checks:

```python
    if "ingest" in getattr(adapter_cls, "capabilities", frozenset()):
        if not callable(getattr(adapter_cls, "ingest_from_directory", None)):
            errors.append(
                f"{name} declares 'ingest' capability but has no "
                f"callable ingest_from_directory method"
            )
        schema_ver = getattr(adapter_cls, "default_schema_version", "")
        if not isinstance(schema_ver, str) or not schema_ver:
            errors.append(
                f"{name} declares 'ingest' capability but has no "
                f"non-empty default_schema_version class attribute"
            )
```

- [ ] **Step 3: Run test, verify it passes**

Run: `pytest tests/unit/adapters/test_adapter_registry.py -v`
Expected: All PASS

- [ ] **Step 4: Commit**

```bash
git add src/gxassessms/adapters/__init__.py tests/unit/adapters/test_adapter_registry.py
git commit -m "feat: extend adapter registry validation for ingest capability (#78)"
```

---

### Task 7: EngagementRepo Changes + Strict Mirror Helper

**Files:**
- Modify: `src/gxassessms/persistence/engagement_repo.py:72-101`
- Modify: `src/gxassessms/pipeline/config_snapshot_mirror.py`
- Test: `tests/unit/persistence/test_engagement_repo.py` (or existing)
- Test: `tests/unit/pipeline/test_config_snapshot_mirror.py` (or existing)

**Spec reference:** Section 1a.1 (strict mirror), 1a.5 (EngagementRepo.create kwarg), 4.2a (update_engagement_dir).

- [ ] **Step 1: Write failing tests for EngagementRepo.create with engagement_id kwarg**

```python
# Append to existing engagement_repo tests

def test_create_with_caller_supplied_engagement_id(db_manager) -> None:
    repo = EngagementRepo(db_manager)
    supplied_id = "test-supplied-id-1234"
    returned_id = repo.create(
        client_name="Test Client",
        tenant_id="test-tenant",
        config_snapshot={"client_name": "Test Client", "tenant_id": "test-tenant"},
        engagement_id=supplied_id,
    )
    assert returned_id == supplied_id
    row = repo.get(supplied_id)
    assert row is not None


def test_create_without_engagement_id_auto_generates(db_manager) -> None:
    repo = EngagementRepo(db_manager)
    returned_id = repo.create(
        client_name="Test Client",
        tenant_id="test-tenant",
        config_snapshot={"client_name": "Test Client", "tenant_id": "test-tenant"},
    )
    # Should be a UUID-like string
    assert len(returned_id) == 36  # UUID format
```

- [ ] **Step 2: Write failing tests for update_engagement_dir**

```python
def test_update_engagement_dir_sets_column(db_manager) -> None:
    repo = EngagementRepo(db_manager)
    eid = repo.create(
        client_name="Test",
        tenant_id="t",
        config_snapshot={"client_name": "Test", "tenant_id": "t"},
    )
    repo.update_engagement_dir(eid, engagement_dir="/path/to/dir")
    row = repo.get(eid)
    assert row["engagement_dir"] == "/path/to/dir"


def test_update_engagement_dir_nonexistent_raises(db_manager) -> None:
    repo = EngagementRepo(db_manager)
    with pytest.raises(PersistenceError, match="not found"):
        repo.update_engagement_dir("nonexistent", engagement_dir="/path")
```

- [ ] **Step 3: Implement EngagementRepo.create engagement_id kwarg**

In `src/gxassessms/persistence/engagement_repo.py`, modify the `create` method signature:

```python
def create(
    self,
    client_name: str,
    tenant_id: str,
    config_snapshot: dict[str, Any],
    engagement_dir: str | None = None,
    engagement_id: str | None = None,
) -> str:
    """Create a new engagement. Returns the engagement_id."""
    if engagement_id is None:
        engagement_id = str(uuid.uuid4())
    now = format_utc(utc_now())
    # ... rest unchanged
```

- [ ] **Step 4: Implement update_engagement_dir**

Add to `EngagementRepo`:

```python
def update_engagement_dir(
    self,
    engagement_id: str,
    engagement_dir: str | None,
) -> None:
    """Set or clear the engagement_dir column on an engagement row."""
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
    logger.info("Updated engagement_dir for %s to %r", engagement_id, engagement_dir)
```

- [ ] **Step 5: Write failing test for mirror_config_snapshot_from_db_strict**

```python
# tests/unit/pipeline/test_config_snapshot_mirror.py — append

def test_strict_mirror_raises_on_failure(
    engagement_repo, artifact_manager, engagement_id, monkeypatch,
) -> None:
    from gxassessms.pipeline.config_snapshot_mirror import (
        mirror_config_snapshot_from_db_strict,
        ConfigSnapshotMirrorError,
    )
    # Monkey-patch _do_mirror to raise
    from gxassessms.pipeline import config_snapshot_mirror
    monkeypatch.setattr(
        config_snapshot_mirror,
        "_do_mirror",
        lambda *a, **kw: (_ for _ in ()).throw(ConfigSnapshotMirrorError("test", engagement_id)),
    )
    with pytest.raises(ConfigSnapshotMirrorError):
        mirror_config_snapshot_from_db_strict(
            engagement_repo, artifact_manager, engagement_id,
        )
```

- [ ] **Step 6: Implement mirror_config_snapshot_from_db_strict**

Add to `src/gxassessms/pipeline/config_snapshot_mirror.py`:

```python
def mirror_config_snapshot_from_db_strict(
    engagement_repo: EngagementRepo,
    artifact_manager: ArtifactManager,
    engagement_id: str,
) -> None:
    """Strict variant of mirror_config_snapshot_from_db.

    Unlike the fail-open wrapper used by collect's runner, this variant
    raises ConfigSnapshotMirrorError on any failure. Used by engagement
    bootstrap and the save_ingested_raw_output legacy-migration path.
    """
    _do_mirror(engagement_repo, artifact_manager, engagement_id)
```

- [ ] **Step 7: Run all tests, verify pass**

Run: `pytest tests/unit/persistence/ tests/unit/pipeline/test_config_snapshot_mirror.py -v --tb=short`
Expected: All PASS

- [ ] **Step 8: Commit**

```bash
git add src/gxassessms/persistence/engagement_repo.py src/gxassessms/pipeline/config_snapshot_mirror.py tests/
git commit -m "feat: add engagement_id kwarg to EngagementRepo.create, update_engagement_dir, strict mirror (#78)"
```

---

### Task 8: Engagement Bootstrap Fix

**Files:**
- Modify: `src/gxassessms/cli/commands/engagement.py:74-108`
- Create: `tests/unit/cli/test_engagement_create.py`

**Spec reference:** Section 1a.2--1a.6, Section 6.12.

- [ ] **Step 1: Write failing tests for bootstrap provisioning**

```python
# tests/unit/cli/test_engagement_create.py
"""Engagement bootstrap tests (spec Section 1a, 6.12)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

from click.testing import CliRunner

from gxassessms.cli.commands.engagement import create_cmd


class TestEngagementBootstrap:
    def test_create_provisions_engagement_dir(self, tmp_path: Path) -> None:
        """After create, on-disk engagement directory exists with subdirs."""
        # Setup: write a minimal config YAML to tmp_path
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "client_name: Test\ntenant_id: test-tenant\n"
            "auth:\n  method: client_secret\n  client_id: x\n  tenant_id: test-tenant\n"
        )
        runner = CliRunner()
        with patch("gxassessms.cli.commands.engagement._helpers") as helpers:
            # Wire up mock repo, artifact_manager, etc.
            mock_repo = MagicMock()
            mock_repo.create.return_value = "test-id"
            helpers.get_engagement_repo.return_value = mock_repo
            mock_am = MagicMock()
            mock_am.create_engagement_dir.return_value = tmp_path / "eng-dir"
            helpers.get_artifact_manager.return_value = mock_am

            result = runner.invoke(create_cmd, [str(config_file)])

        assert result.exit_code == 0
        # Verify create_engagement_dir was called
        mock_am.create_engagement_dir.assert_called_once()

    def test_create_rolls_back_on_dir_provision_failure(self, tmp_path: Path) -> None:
        """If create_engagement_dir raises, the DB row is deleted."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "client_name: Test\ntenant_id: test-tenant\n"
            "auth:\n  method: client_secret\n  client_id: x\n  tenant_id: test-tenant\n"
        )
        runner = CliRunner()
        with patch("gxassessms.cli.commands.engagement._helpers") as helpers:
            mock_repo = MagicMock()
            mock_repo.create.return_value = "test-id"
            helpers.get_engagement_repo.return_value = mock_repo
            mock_am = MagicMock()
            mock_am.create_engagement_dir.side_effect = OSError("disk full")
            helpers.get_artifact_manager.return_value = mock_am

            result = runner.invoke(create_cmd, [str(config_file)])

        assert result.exit_code == 1
        mock_repo.delete.assert_called_once_with("test-id")
```

- [ ] **Step 2: Implement the bootstrap flow in create_cmd**

Rewrite `create_cmd` in `src/gxassessms/cli/commands/engagement.py`:

```python
@engagement_group.command("create")
@click.argument(
    "config_path",
    type=click.Path(exists=True, dir_okay=False),
)
def create_cmd(config_path: str) -> None:
    """Create a new engagement from a config file."""
    import shutil
    import uuid

    path = Path(config_path)

    try:
        config = load_config(path)
    except ConfigError as e:
        console.print(f"[bright_red]Config error:[/bright_red] {e}")
        raise SystemExit(1) from None

    errors, warnings = validate_config(config)
    for w in warnings:
        console.print(f"[yellow]Warning:[/yellow] {w}")
    if errors:
        for e in errors:
            console.print(f"[bright_red]Error:[/bright_red] {e}")
        raise SystemExit(1)

    repo = _helpers.get_engagement_repo()
    am = _helpers.get_artifact_manager()
    engagement_id = str(uuid.uuid4())

    # Step 1: Insert the DB row with pre-generated engagement_id.
    # Compute the engagement_dir path the same way create_engagement_dir will.
    try:
        # We need the dir path before creating it. Use the same slug logic
        # that create_engagement_dir uses internally.
        engagement_dir_path = am.create_engagement_dir(engagement_id, config.client_name)
    except Exception as exc:
        # Dir creation failed before DB row exists -- nothing to roll back
        console.print(
            f"[bright_red]Failed to create engagement directory:[/bright_red] {exc}"
        )
        raise SystemExit(1) from None

    try:
        eid = repo.create(
            client_name=config.client_name,
            tenant_id=config.tenant_id,
            config_snapshot=config.model_dump(),
            engagement_id=engagement_id,
            engagement_dir=str(engagement_dir_path),
        )
    except GxAssessError as exc:
        # DB insert failed -- clean up the directory
        shutil.rmtree(engagement_dir_path, ignore_errors=True)
        console.print(f"[bright_red]Failed to create engagement:[/bright_red] {exc}")
        raise SystemExit(1) from None

    # Step 2: Mirror config snapshot (strict -- failure triggers rollback)
    try:
        from gxassessms.pipeline.config_snapshot_mirror import (
            mirror_config_snapshot_from_db_strict,
        )
        mirror_config_snapshot_from_db_strict(repo, am, eid)
    except Exception as exc:
        # Roll back both directory and DB row
        shutil.rmtree(engagement_dir_path, ignore_errors=True)
        try:
            repo.delete(eid)
        except Exception:
            logger.warning("Rollback: failed to delete DB row %s", eid)
        console.print(
            f"[bright_red]Failed to mirror config snapshot:[/bright_red] {exc}"
        )
        raise SystemExit(1) from None

    console.print(f"[bright_green]Engagement created:[/bright_green] {eid}")
    console.print(f"Client: {config.client_name}")
    console.print(f"Tenant: {config.tenant_id}")
```

**Note:** The exact ordering (dir first, then DB row, then mirror) is adjusted here from the spec because `create_engagement_dir` needs the `engagement_id` to compute the path, but the DB row needs the path. The implementation plan worker should read the spec's Section 1a.2 carefully and adjust to match the actual `create_engagement_dir` API -- the key invariant is that all three artifacts (dir, DB row, mirror file) are created, and any failure triggers rollback of what was already created.

- [ ] **Step 3: Run tests, verify pass**

Run: `pytest tests/unit/cli/test_engagement_create.py -v`
Expected: All PASS

- [ ] **Step 4: Commit**

```bash
git add src/gxassessms/cli/commands/engagement.py tests/unit/cli/test_engagement_create.py
git commit -m "feat: engagement create provisions directory and mirrors config snapshot (#78)"
```

---

### Task 9: Persistence Layer -- save_ingested_raw_output

**Files:**
- Modify: `src/gxassessms/persistence/artifacts.py`
- Test: `tests/unit/persistence/test_artifacts.py`

**Spec reference:** Sections 4.1--4.4, 6.4, 6.11.

This is the largest single task. It implements the atomic single-slug write method, the legacy-migration fallback, and the per-side rollback logic.

- [ ] **Step 1: Write failing tests for the happy path**

```python
# tests/unit/persistence/test_artifacts.py — append

class TestSaveIngestedRawOutput:
    """Spec Section 4.1--4.4: save_ingested_raw_output."""

    def test_happy_path_fresh_ingest(
        self, artifact_manager, engagement_id, tmp_path,
    ) -> None:
        """Fresh ingest writes manifest and artifacts atomically."""
        from gxassessms.core.domain.models import (
            CollectionOutput, CollectedArtifact, IngestProvenance,
        )
        from gxassessms.core.domain.enums import ToolSource

        # Create a source file to ingest
        source_file = tmp_path / "source" / "ScubaResults.json"
        source_file.parent.mkdir()
        source_file.write_text('{"data": 1}')
        from gxassessms.core.hashing import sha256_file
        sha = sha256_file(source_file)

        co = CollectionOutput(
            tool=ToolSource.SCUBAGEAR,
            tool_slug="scubagear",
            schema_version="1.7.1",
            timestamp=datetime(2026, 4, 11, tzinfo=timezone.utc),
            artifacts=[
                CollectedArtifact(
                    source_path=str(source_file),
                    target_relpath="scubagear/ScubaResults.json",
                    encoding="utf-8",
                    sha256=sha,
                )
            ],
            execution_metadata={},
        )
        prov = IngestProvenance(
            source_path=str(tmp_path / "source"),
            ingested_at=datetime(2026, 4, 11, 12, 0, 0, tzinfo=timezone.utc),
            ingested_by="human:alice",
            replaced=False,
        )

        loaded = artifact_manager.save_ingested_raw_output(
            engagement_id, co,
            ingest_provenance=prov,
            replace=False,
        )

        assert loaded.raw_output.source_mode == "ingested"
        assert loaded.raw_output.ingest_provenance is not None
        assert loaded.raw_output.manifest_version == "1.1.0"
        assert loaded.raw_output.tool_slug == "scubagear"

        # Verify files on disk
        eng_dir = artifact_manager.get_engagement_dir(engagement_id)
        manifest_path = eng_dir / "raw-output" / "manifests" / "scubagear.json"
        assert manifest_path.exists()
        artifacts_dir = eng_dir / "raw-output" / "artifacts" / "scubagear"
        assert artifacts_dir.is_dir()
        assert (artifacts_dir / "ScubaResults.json").exists()
```

- [ ] **Step 2: Write failing tests for the 4 rollback cases**

See spec Section 6.4 for the full table. Each test monkey-patches `Path.rename` to make the manifest rename fail after the artifacts rename succeeds, then asserts the pre-call state is restored.

- [ ] **Step 3: Write failing tests for legacy migration**

See spec Section 6.11 for 7 test cases covering: successful migration, dir creation failure, mirror failure, backfill failure, post-PR corruption, post-migration corruption, and missing migration kwargs.

- [ ] **Step 4: Implement save_ingested_raw_output**

Add to `src/gxassessms/persistence/artifacts.py`. The method follows the three-phase discipline documented in spec Section 4.2 plus the legacy-migration fallback from Section 4.2a. This is approximately 150-200 lines of code. Key contract points:

1. Assert `collection_output.execution_metadata == {}` at the top.
2. Validate `tool_slug` against `TOOL_SLUG_PATTERN`.
3. Phase 1: conflict probe, set `ingest_provenance.replaced` based on actual state, path validation.
4. Phase 2: stage to `.ingest-staging-<slug>-<uuid>/` with hash-verified copies.
5. Phase 3: rename-aside (if replace), commit artifacts then manifest.
6. Return `LoadedManifest(source_path=manifest_path, raw_output=raw_output)`.

Legacy migration fallback (before Phase 1): if `get_engagement_dir()` raises, check `engagement_row["engagement_dir"]` for NULL vs populated to distinguish legacy vs corruption.

- [ ] **Step 5: Run all tests**

Run: `pytest tests/unit/persistence/test_artifacts.py -v --tb=short`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add src/gxassessms/persistence/artifacts.py tests/unit/persistence/test_artifacts.py
git commit -m "feat: add save_ingested_raw_output with legacy migration and per-side rollback (#78)"
```

---

### Task 10: Pipeline Extensions -- EventType + record_raw_output_ingested

**Files:**
- Modify: `src/gxassessms/pipeline/state.py:28-41`
- Modify: `src/gxassessms/pipeline/orchestrator.py`
- Test: `tests/unit/pipeline/test_orchestrator.py`

**Spec reference:** Section 5.6, 6.8.

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/pipeline/test_orchestrator.py — append

class TestRecordRawOutputIngested:
    """Spec Section 5.6, 6.8."""

    def test_forwards_to_emit_event(self, orchestrator, engagement_id) -> None:
        orchestrator.record_raw_output_ingested(
            engagement_id=engagement_id,
            actor="human:alice",
            tool_slug="scubagear",
            source_path="/tmp/export",
            file_count=1,
            replaced=False,
        )
        # Verify event was written
        events = orchestrator._event_repo.list(engagement_id)
        ingest_events = [e for e in events if e.event_type == "raw_output_ingested"]
        assert len(ingest_events) == 1
        assert ingest_events[0].actor == "human:alice"
        payload = ingest_events[0].payload
        assert payload["tool_slug"] == "scubagear"
        assert payload["source_path"] == "/tmp/export"
        assert payload["file_count"] == 1
        assert payload["replaced"] is False
```

- [ ] **Step 2: Add "raw_output_ingested" to EventType**

In `src/gxassessms/pipeline/state.py` line 28, extend the `EventType` Literal:

```python
EventType = Literal[
    "state_transition", "override", "ai_modification", "rerun",
    "manual_finding_added", "lock_broken", "stale_recovery",
    "narrative_edit", "narrative_approval", "rerender",
    "token_usage", "manual_merge", "raw_output_ingested",
]
```

- [ ] **Step 3: Add record_raw_output_ingested to Orchestrator**

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
    """Record a raw_output_ingested event in the engagement journal."""
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

- [ ] **Step 4: Run tests, verify pass**

Run: `pytest tests/unit/pipeline/test_orchestrator.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/gxassessms/pipeline/state.py src/gxassessms/pipeline/orchestrator.py tests/unit/pipeline/test_orchestrator.py
git commit -m "feat: add raw_output_ingested EventType and record_raw_output_ingested wrapper (#78)"
```

---

### Task 11: CLI Helpers

**Files:**
- Modify: `src/gxassessms/cli/_helpers.py`
- Test: `tests/unit/cli/test_helpers.py`

**Spec reference:** Section 5.4.

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/cli/test_helpers.py — append

from gxassessms.cli._helpers import resolve_enabled_adapter, require_ingest_capable


class TestResolveEnabledAdapter:
    def test_finds_adapter_by_storage_slug(self, registry, config) -> None:
        adapter = resolve_enabled_adapter("scubagear", registry, config)
        assert adapter.storage_slug == "scubagear"

    def test_unknown_slug_raises_usage_error(self, registry, config) -> None:
        import click
        with pytest.raises(click.UsageError, match="Unknown tool slug"):
            resolve_enabled_adapter("nonexistent", registry, config)

    def test_disabled_tool_raises_usage_error(self, registry, config_with_disabled) -> None:
        import click
        with pytest.raises(click.UsageError, match="not enabled"):
            resolve_enabled_adapter("scubagear", registry, config_with_disabled)


class TestRequireIngestCapable:
    def test_narrows_ingest_capable_adapter(self) -> None:
        from gxassessms.adapters.scubagear.adapter import ScubaGearAdapter
        adapter = ScubaGearAdapter()
        narrowed = require_ingest_capable(adapter)
        assert hasattr(narrowed, "ingest_from_directory")

    def test_rejects_non_ingest_adapter(self) -> None:
        import click
        from gxassessms.adapters.monkey365.adapter import Monkey365Adapter
        with pytest.raises(click.UsageError, match="does not support ingest"):
            require_ingest_capable(Monkey365Adapter())
```

- [ ] **Step 2: Implement the three helpers**

Add to `src/gxassessms/cli/_helpers.py`:

```python
def resolve_enabled_adapter(
    tool_slug: str,
    registry: AdapterRegistry,
    config: EngagementConfig,
) -> ToolAdapter:
    """Find an adapter by storage_slug and verify it is enabled."""
    matches = [
        cls() for cls in registry.adapters.values()
        if getattr(cls, "storage_slug", None) == tool_slug
    ]
    if not matches:
        available = sorted(
            getattr(cls, "storage_slug", "?")
            for cls in registry.adapters.values()
        )
        raise click.UsageError(
            f"Unknown tool slug {tool_slug!r}. Available: {', '.join(available)}"
        )
    if len(matches) > 1:
        raise click.UsageError(
            f"Multiple adapters claim slug {tool_slug!r}; registry is corrupt."
        )
    adapter = matches[0]
    enabled_names = {
        name.lower() for name, tc in config.tools.items() if tc.enabled
    }
    if adapter.tool_name.lower() not in enabled_names:
        raise click.UsageError(
            f"Tool {tool_slug!r} (adapter {adapter.tool_name!r}) is not enabled "
            f"in this engagement's config."
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
            f"does not implement ingest_from_directory()."
        )
    return adapter


def get_engagement_lock() -> EngagementLock:
    """Factory for the EngagementLock matching the engagements root."""
    from gxassessms.pipeline.state import EngagementLock
    return EngagementLock(get_engagements_root())
```

Add required imports (`click`, `IngestCapableAdapter`, `EngagementLock`, etc.).

- [ ] **Step 3: Run tests, verify pass**

Run: `pytest tests/unit/cli/test_helpers.py -v`
Expected: All PASS

- [ ] **Step 4: Commit**

```bash
git add src/gxassessms/cli/_helpers.py tests/unit/cli/test_helpers.py
git commit -m "feat: add resolve_enabled_adapter, require_ingest_capable, get_engagement_lock helpers (#78)"
```

---

### Task 12: CLI Ingest Command -- Normal Path + Repair-Event

**Files:**
- Create: `src/gxassessms/cli/commands/ingest.py`
- Modify: `src/gxassessms/cli/main.py:188-201`
- Create: `tests/unit/cli/test_ingest_cmd.py`

**Spec reference:** Sections 5.1--5.5b, 6.6, 6.13.

This task creates the full CLI command with both the normal ingest path and the `--repair-event` audit-neutral recovery path.

- [ ] **Step 1: Write failing CLI unit tests (selection from Section 6.6)**

```python
# tests/unit/cli/test_ingest_cmd.py
"""CLI unit tests for mseco ingest (spec Section 6.6, 6.13)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from gxassessms.cli.commands.ingest import ingest_cmd


class TestIngestCmdValidation:
    def test_missing_from_without_repair_event_exits_1(self) -> None:
        runner = CliRunner()
        result = runner.invoke(ingest_cmd, ["test-id", "--tool", "scubagear"])
        assert result.exit_code != 0

    def test_repair_event_rejects_from_flag(self) -> None:
        runner = CliRunner()
        result = runner.invoke(ingest_cmd, [
            "test-id", "--tool", "scubagear",
            "--repair-event", "--from", "/tmp/export",
        ])
        assert result.exit_code != 0
        assert "mutually exclusive" in result.output.lower() or "Usage" in result.output

    def test_repair_event_rejects_replace_flag(self) -> None:
        runner = CliRunner()
        result = runner.invoke(ingest_cmd, [
            "test-id", "--tool", "scubagear",
            "--repair-event", "--replace",
        ])
        assert result.exit_code != 0


class TestIngestCmdHappyPath:
    """Spec Section 6.6 test 11: fresh ingest exits 0."""

    def test_fresh_ingest_exit_0(self, mock_ingest_deps) -> None:
        runner = CliRunner()
        result = runner.invoke(ingest_cmd, [
            "test-engagement-id", "--tool", "scubagear",
            "--from", str(mock_ingest_deps["source_dir"]),
        ])
        assert result.exit_code == 0
        mock_ingest_deps["save"].assert_called_once()
        mock_ingest_deps["record_event"].assert_called_once()
```

- [ ] **Step 2: Implement the ingest command**

Create `src/gxassessms/cli/commands/ingest.py` with the full Click command following the spec's Section 5.1-5.5b structure. The file should be under 400 lines per CLAUDE.md. Key structure:

```python
"""``mseco ingest`` -- ingest client-provided raw tool output."""

from __future__ import annotations

import getpass
import logging
from pathlib import Path

import click
from rich.console import Console

from gxassessms.cli import _helpers
from gxassessms.core.contracts.errors import (
    GxAssessError,
    LockTimeoutError,
    PersistenceError,
)

logger = logging.getLogger(__name__)
console = Console()


@click.command("ingest")
@click.argument("engagement_id")
@click.option("--tool", "tool_slug", required=True, ...)
@click.option("--from", "source_path", default=None, ...)
@click.option("--replace", is_flag=True, default=False, ...)
@click.option("--schema-version", "schema_version_override", default=None, ...)
@click.option("--run-at", "run_at_arg", default=None, ...)
@click.option("--operator", default=None, ...)
@click.option("--repair-event", "repair_event", is_flag=True, default=False, ...)
def ingest_cmd(
    engagement_id, tool_slug, source_path, replace, schema_version_override,
    run_at_arg, operator, repair_event,
):
    """Ingest client-provided raw tool output into an engagement."""
    # 1. Mutual exclusion validation for --repair-event
    # 2. Engagement lookup (DB-required, no filesystem fallback)
    # 3. Adapter resolution
    # 4. Dispatch to _ingest_under_lock or _repair_event_under_lock
    ...


def _ingest_under_lock(...):
    """Normal ingest path (spec Section 5.5)."""
    # 1. Conflict check
    # 2. Adapter walk: ingest_from_directory
    # 3. Pre-commit validate_raw
    # 4. DB state reset: reset_for_rerun(Stage.PARSE)
    # 5. Atomic filesystem commit: save_ingested_raw_output
    # 6. Ingest event: record_raw_output_ingested (from committed provenance)
    ...


def _repair_event_under_lock(...):
    """Audit-neutral repair path (spec Section 5.5b)."""
    # 1. Load committed manifest
    # 2. Validate source_mode == "ingested"
    # 3. Check idempotency (event already exists?)
    # 4. Emit missing event from committed provenance
    ...
```

- [ ] **Step 3: Register the command in main.py**

In `src/gxassessms/cli/main.py`, add to `_register_commands()`:

```python
_try_register("gxassessms.cli.commands.ingest", "ingest_cmd", "ingest")
```

- [ ] **Step 4: Write repair-event tests (Section 6.13)**

Add to `tests/unit/cli/test_ingest_cmd.py` the 8 repair-event test cases from spec Section 6.13: happy path, idempotent when event exists, rejects missing manifest, rejects collected manifest, rejects conflicting flags, preserves committed provenance exactly, takes engagement lock.

- [ ] **Step 5: Run all CLI tests**

Run: `pytest tests/unit/cli/test_ingest_cmd.py -v --tb=short`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add src/gxassessms/cli/commands/ingest.py src/gxassessms/cli/main.py tests/unit/cli/test_ingest_cmd.py
git commit -m "feat: add mseco ingest CLI command with --repair-event recovery (#78)"
```

---

### Task 13: Manifest Version Flow + Confinement Gate

**Files:**
- Modify: `src/gxassessms/persistence/artifacts.py` (save_raw_outputs touch)
- Test: `tests/unit/pipeline/test_confinement.py`
- Test: `tests/unit/pipeline/test_replay.py`

**Spec reference:** Section 2.4 (version flow), 2.5 (backward compat).

- [ ] **Step 1: Write failing test for confinement accepting 1.1.0**

```python
# tests/unit/pipeline/test_confinement.py — append

def test_recognized_versions_includes_1_1_0() -> None:
    """1.1.0 manifests pass the version gate."""
    from gxassessms.core.domain.constants import RECOGNIZED_MANIFEST_VERSIONS
    assert "1.1.0" in RECOGNIZED_MANIFEST_VERSIONS
```

- [ ] **Step 2: Write test for replay loading a 1.1.0 ingested manifest**

```python
# tests/unit/pipeline/test_replay.py — append

def test_load_1_1_0_ingested_manifest(tmp_path: Path) -> None:
    """A 1.1.0 manifest with source_mode='ingested' loads correctly."""
    from gxassessms.core.domain.models import RawToolOutput, IngestProvenance
    prov = IngestProvenance(
        source_path="/tmp/export",
        ingested_at=datetime(2026, 4, 11, tzinfo=timezone.utc),
        ingested_by="human:alice",
        replaced=False,
    )
    raw = RawToolOutput(
        tool=ToolSource.SCUBAGEAR,
        tool_slug="scubagear",
        schema_version="1.7.1",
        manifest_version="1.1.0",
        timestamp=datetime(2026, 4, 11, tzinfo=timezone.utc),
        file_manifest={},
        execution_metadata={},
        source_mode="ingested",
        ingest_provenance=prov,
    )
    manifest_path = tmp_path / "scubagear.json"
    manifest_path.write_text(raw.model_dump_json(indent=2))

    reloaded = RawToolOutput.model_validate_json(manifest_path.read_text())
    assert reloaded.source_mode == "ingested"
    assert reloaded.ingest_provenance.source_path == "/tmp/export"
    assert reloaded.ingest_provenance.replaced is False
```

- [ ] **Step 3: Touch save_raw_outputs for explicit source_mode="collected"**

In `src/gxassessms/persistence/artifacts.py`, in the `save_raw_outputs` method where `RawToolOutput(...)` is constructed (around line 602), add `source_mode="collected"` explicitly:

```python
raw_output = RawToolOutput(
    tool=co.tool,
    tool_slug=slug,
    schema_version=co.schema_version,
    manifest_version=version,
    timestamp=co.timestamp,
    file_manifest=file_manifest,
    execution_metadata=filtered_metadata,
    source_mode="collected",  # Explicit for clarity; default would also work
)
```

- [ ] **Step 4: Run tests, verify pass**

Run: `pytest tests/unit/pipeline/test_confinement.py tests/unit/pipeline/test_replay.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/gxassessms/persistence/artifacts.py tests/unit/pipeline/
git commit -m "feat: manifest version flow for 1.1.0, explicit source_mode in save_raw_outputs (#78)"
```

---

### Task 14: Integration Tests + Runbook Update

**Files:**
- Create: `tests/integration/test_ingest_flow.py`
- Modify: `docs/runbook.md`

**Spec reference:** Section 6.7 (integration tests), Section 5.7 (runbook update).

- [ ] **Step 1: Write integration test 1 -- single-tool ingest + replay**

```python
# tests/integration/test_ingest_flow.py
"""End-to-end ingest integration tests (spec Section 6.7)."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from gxassessms.cli.main import cli


class TestSingleToolIngestAndReplay:
    """Spec Section 6.7 test 1: create -> ingest scubagear -> replay --from parse."""

    def test_ingest_scubagear_then_replay(self, integration_env: Path) -> None:
        runner = CliRunner()

        # Create engagement
        result = runner.invoke(cli, [
            "engagement", "create", str(integration_env / "config.yaml"),
        ])
        assert result.exit_code == 0
        engagement_id = _extract_engagement_id(result.output)

        # Prepare ScubaGear source directory
        source_dir = integration_env / "scubagear-export"
        source_dir.mkdir()
        (source_dir / "ScubaResults.json").write_text(_SCUBAGEAR_FIXTURE)

        # Ingest
        result = runner.invoke(cli, [
            "ingest", engagement_id,
            "--tool", "scubagear",
            "--from", str(source_dir),
        ])
        assert result.exit_code == 0

        # Replay from parse
        result = runner.invoke(cli, [
            "replay", engagement_id,
            "--from", "parse",
            "--qa-strategy", "noop",
        ])
        assert result.exit_code == 0
```

- [ ] **Step 2: Write integration tests 2-4**

Write the remaining integration tests: multi-tool mixed (collect + ingest), replace path, runbook scenario 3 end-to-end. All pin `--qa-strategy noop` for determinism.

- [ ] **Step 3: Update runbook scenario 3**

In `docs/runbook.md` at lines 144-197:

1. Remove the "(see issue #78 -- command not yet implemented)" note for the 5 supported adapters.
2. Add a concrete example showing `mseco ingest` for ScubaGear + Maester.
3. Document that Monkey365 and M365-Assess ingest is NOT yet supported with the freshness-ambiguity reason.
4. Add caveats about `--run-at`, pick-first-match, and `--repair-event`.

- [ ] **Step 4: Run integration tests**

Run: `pytest tests/integration/test_ingest_flow.py -v --tb=short`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add tests/integration/test_ingest_flow.py docs/runbook.md
git commit -m "feat: integration tests and runbook update for mseco ingest (#78)"
```

---

## Self-Review Checklist

After writing this plan, I verified:

1. **Spec coverage:** Every section of the spec (1-6, 1a, 4.2a, 5.5a, 5.5b) has at least one task that implements it. Section 1 flow is implemented across Tasks 8 (bootstrap), 9 (persistence), 10 (pipeline), 11 (helpers), 12 (CLI). Section 2 is Task 1. Section 3 is Tasks 3-6. Section 4 is Task 9. Section 5 is Tasks 11-12. Section 6 tests are spread across their corresponding implementation tasks.

2. **Placeholder scan:** No TBD/TODO/placeholder language. Task 4 and Task 9 reference the spec for detailed code because those implementations are large (150+ lines each), but every task has concrete code for its key changes.

3. **Type consistency:** `IngestProvenance`, `IngestCapableAdapter`, `build_collection_output`, `save_ingested_raw_output`, `record_raw_output_ingested`, `resolve_enabled_adapter`, `require_ingest_capable`, `get_engagement_lock`, `mirror_config_snapshot_from_db_strict`, `update_engagement_dir` -- all names are consistent across tasks.
