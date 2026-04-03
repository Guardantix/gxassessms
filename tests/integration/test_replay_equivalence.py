"""Live/replay equivalence test (spec Section 7.8).

Collects from fixture files, saves, confines, parses.
Then separately loads persisted manifests, confines, parses.
Asserts both paths produce identical ResolvedManifest contents.
"""

from __future__ import annotations

import hashlib
import shutil
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from gxassessms.core.contracts.types import AdapterRunStatus
from gxassessms.core.domain.enums import ToolSource
from gxassessms.core.domain.models import (
    CollectedArtifact,
    CollectionOutput,
    CollectionResult,
)
from gxassessms.persistence.artifacts import ArtifactManager
from gxassessms.pipeline.confinement import confine_and_resolve
from gxassessms.pipeline.replay import load_raw_outputs


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def fixture_dir() -> Path:
    """Path to ScubaGear adapter fixtures."""
    return (
        Path(__file__).parent.parent.parent
        / "src"
        / "gxassessms"
        / "adapters"
        / "scubagear"
        / "fixtures"
    )


@pytest.fixture
def scuba_adapter() -> MagicMock:
    """Mock adapter with required attributes for confine_and_resolve."""
    adapter = MagicMock()
    adapter.storage_slug = "scubagear"
    adapter.tool_source = ToolSource.SCUBAGEAR
    adapter.tool_name = "ScubaGear"
    return adapter


class TestLiveReplayEquivalence:
    def test_resolved_manifests_match(
        self, tmp_path: Path, fixture_dir: Path, scuba_adapter: MagicMock
    ) -> None:
        """Live path and replay path produce identical ResolvedManifest contents."""
        scuba_results_orig = fixture_dir / "ScubaResults.json"

        # Copy fixture to tmp_path so save_raw_outputs source cleanup does not
        # delete the fixture file from the repository.
        scuba_results = tmp_path / "ScubaResults.json"
        shutil.copy2(str(scuba_results_orig), str(scuba_results))

        sha = _sha256(scuba_results)

        # --- Live path ---
        co = CollectionOutput(
            tool=ToolSource.SCUBAGEAR,
            tool_slug="scubagear",
            schema_version="1.0.0",
            timestamp=datetime(2026, 4, 1, 10, 0, 0, tzinfo=UTC),
            artifacts=[
                CollectedArtifact(
                    source_path=str(scuba_results),
                    target_relpath="scubagear/ScubaResults.json",
                    encoding="utf-8",
                    sha256=sha,
                ),
            ],
            execution_metadata={},
        )
        cr = CollectionResult(
            adapter_name="scubagear",
            status=AdapterRunStatus.SUCCESS,
            collection_output=co,
            duration_seconds=1.0,
        )

        engagements_root = tmp_path / "engagements"
        engagements_root.mkdir()
        mgr = ArtifactManager(engagements_root=engagements_root)

        live_loaded = mgr.save_raw_outputs("eng-live", "Acme", [cr])
        eng_dir = mgr.get_engagement_dir("eng-live")
        live_resolved = confine_and_resolve(live_loaded, eng_dir, [scuba_adapter])

        # --- Replay path ---
        replay_loaded = load_raw_outputs(eng_dir)
        replay_resolved = confine_and_resolve(replay_loaded, eng_dir, [scuba_adapter])

        # Assert equivalence
        assert len(live_resolved) == len(replay_resolved) == 1
        live_rm = live_resolved[0]
        replay_rm = replay_resolved[0]

        assert live_rm.tool == replay_rm.tool
        assert live_rm.tool_slug == replay_rm.tool_slug
        assert live_rm.schema_version == replay_rm.schema_version
        assert live_rm.manifest_version == replay_rm.manifest_version
        assert live_rm.file_manifest.keys() == replay_rm.file_manifest.keys()
        for key in live_rm.file_manifest:
            assert live_rm.file_manifest[key].sha256 == replay_rm.file_manifest[key].sha256
            assert live_rm.file_manifest[key].encoding == replay_rm.file_manifest[key].encoding
