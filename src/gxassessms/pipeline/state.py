"""Engagement state machine, PipelineEvent, and EngagementLock.

EngagementState defines the pipeline state machine. PipelineEvent is the
append-only event journal record. EngagementLock provides advisory file
locking per engagement to prevent concurrent state mutation.
"""

from __future__ import annotations

import logging
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from filelock import BaseFileLock, FileLock, Timeout

from gxassessms.core.contracts.errors import LockTimeoutError

logger = logging.getLogger(__name__)


class EngagementState(StrEnum):
    """Pipeline state machine states."""

    CREATED = "CREATED"
    COLLECTING = "COLLECTING"
    COLLECTED = "COLLECTED"
    PARSING = "PARSING"
    PARSED = "PARSED"
    NORMALIZING = "NORMALIZING"
    NORMALIZED = "NORMALIZED"
    CONSOLIDATING = "CONSOLIDATING"
    CONSOLIDATED = "CONSOLIDATED"
    QA_REVIEW = "QA_REVIEW"
    QA_APPROVED = "QA_APPROVED"
    RENDERING = "RENDERING"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


@dataclass(frozen=True)
class PipelineEvent:
    """Append-only event journal record.

    Every state transition, override, re-run, and AI modification is recorded
    as a PipelineEvent. The event journal is the source of truth for what
    happened to an engagement.
    """

    event_id: str
    engagement_id: str
    timestamp: datetime
    event_type: str  # "state_transition", "override", "ai_modification", "rerun", etc.
    actor: str  # "system", "human:<name>", "ai:severity_review", etc.
    payload: dict[str, Any]  # Treat as immutable; serialized to SQLite on append


class EngagementLock:
    """Advisory file lock per engagement using filelock.

    Prevents concurrent pipeline operations (CLI + review UI) from corrupting
    state. Lock file is placed at <engagement_dir>/.lock.
    """

    def __init__(self, engagements_root: Path) -> None:
        self._engagements_root = engagements_root
        self._locks: dict[str, BaseFileLock] = {}

    def _lock_path(self, engagement_id: str) -> Path:
        return self._engagements_root / engagement_id / ".lock"

    def acquire(self, engagement_id: str, timeout: float = 30.0) -> None:
        """Acquire advisory lock for an engagement.

        Creates the engagement directory if it does not exist.
        Raises LockTimeoutError if the lock cannot be acquired within timeout.
        """
        eng_dir = self._engagements_root / engagement_id
        eng_dir.mkdir(parents=True, exist_ok=True)

        lock_path = self._lock_path(engagement_id)
        lock = FileLock(str(lock_path))
        try:
            lock.acquire(timeout=timeout)
        except Timeout as err:
            raise LockTimeoutError(
                message=(
                    f"Engagement locked by another process (review UI or concurrent CLI). "
                    f"Use `mseco engagement unlock {engagement_id}` to force-release "
                    f"if the locking process has exited."
                ),
                engagement_id=engagement_id,
                timeout_seconds=timeout,
            ) from err
        self._locks[engagement_id] = lock
        logger.debug("Acquired lock for engagement %s", engagement_id)

    def release(self, engagement_id: str) -> None:
        """Release advisory lock for an engagement. Safe to call if not held."""
        lock = self._locks.pop(engagement_id, None)
        if lock is not None and lock.is_locked:
            lock.release()
            logger.debug("Released lock for engagement %s", engagement_id)

    @contextmanager
    def hold(self, engagement_id: str, timeout: float = 30.0) -> Generator[None]:
        """Context manager for holding an engagement lock."""
        self.acquire(engagement_id, timeout=timeout)
        try:
            yield
        finally:
            self.release(engagement_id)
