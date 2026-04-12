"""Mirror the DB's config_snapshot to the engagement directory.

Disaster-recovery helper: if the DB is wiped, `mseco replay` can
still load the engagement's config from the filesystem mirror. A
mirror-write failure does not block the pipeline -- the DB remains
the primary source of truth -- but it is logged at ERROR level so
operators notice the DR gap.
"""

from __future__ import annotations

import logging
import sqlite3

from gxassessms.core.contracts.errors import (
    ConfigSnapshotMirrorError,
    PersistenceError,
)
from gxassessms.persistence.artifacts import ArtifactManager
from gxassessms.persistence.engagement_repo import (
    EngagementRepo,
    decode_config_snapshot,
)

logger = logging.getLogger(__name__)


def mirror_config_snapshot_from_db(
    engagement_repo: EngagementRepo,
    artifact_manager: ArtifactManager,
    engagement_id: str,
) -> None:
    """Mirror `config_snapshot` from the DB row to the engagement directory.

    Fail-open public contract: catches ConfigSnapshotMirrorError and logs
    at ERROR level. The narrow internal `_do_mirror` raises typed errors
    so unit tests can exercise every failure branch. A final
    `except Exception` catches anything the narrow branches missed --
    defensible here and ONLY here because this helper's entire purpose
    is to never block the primary pipeline.
    """
    try:
        _do_mirror(engagement_repo, artifact_manager, engagement_id)
    except ConfigSnapshotMirrorError as exc:
        logger.error(
            "Failed to mirror config_snapshot to filesystem for %s: %s -- "
            "replay after DB wipe will NOT be possible for this engagement. "
            "To verify engagement state: mseco engagement show %s. "
            "To retry the mirror: re-run 'mseco collect --engagement-id %s <config.yaml>'",
            engagement_id,
            exc,
            engagement_id,
            engagement_id,
        )
    except Exception:
        logger.error(
            "Unexpected failure mirroring config_snapshot for %s -- "
            "replay after DB wipe will NOT be possible for this engagement",
            engagement_id,
            exc_info=True,
        )


def _do_mirror(
    engagement_repo: EngagementRepo,
    artifact_manager: ArtifactManager,
    engagement_id: str,
) -> None:
    """Inner mirror: raises ConfigSnapshotMirrorError on typed failures."""
    try:
        eng_record = engagement_repo.get(engagement_id)
    except (PersistenceError, sqlite3.Error) as exc:
        raise ConfigSnapshotMirrorError(
            f"engagement lookup failed at mirror time: {exc}",
            engagement_id=engagement_id,
        ) from exc

    try:
        snapshot_dict = decode_config_snapshot(eng_record)
    except PersistenceError as exc:
        raise ConfigSnapshotMirrorError(
            f"DB config_snapshot unparseable (may be corrupt or hand-edited): {exc}",
            engagement_id=engagement_id,
        ) from exc

    # Sanity invariant: a usable snapshot must at minimum name the client.
    # Empty, missing, or whitespace-only snapshots indicate hand-crafted
    # DB rows. Prefer fail-fast at mirror time over writing an invalid
    # mirror that would later fail at replay time with a confusing error.
    client_name_raw = snapshot_dict.get("client_name", "")
    if not isinstance(client_name_raw, str) or not client_name_raw.strip():
        raise ConfigSnapshotMirrorError(
            "DB config_snapshot missing client_name; "
            "row may have been hand-crafted or created by an older version",
            engagement_id=engagement_id,
        )

    try:
        artifact_manager.write_config_snapshot(engagement_id, snapshot_dict)
    except (PersistenceError, OSError) as exc:
        raise ConfigSnapshotMirrorError(
            f"write_config_snapshot failed: {exc}",
            engagement_id=engagement_id,
        ) from exc


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
