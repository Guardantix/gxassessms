"""Engagement lifecycle states, PipelineEvent, and EngagementLock.

EngagementState defines the pipeline lifecycle states. PipelineEvent is the
append-only event journal record. EngagementLock provides advisory file
locking per engagement to prevent concurrent state mutation.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Generator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, get_args

from filelock import BaseFileLock, FileLock, Timeout

from gxassessms.core.contracts.errors import LockTimeoutError, PersistenceError
from gxassessms.core.domain.enums import EngagementState as EngagementState  # re-export

logger = logging.getLogger(__name__)

EventType = Literal[
    "state_transition",
    "override",
    "ai_modification",
    "rerun",
    "manual_finding_added",
    "lock_broken",
    "stale_recovery",
    "narrative_edit",
    "narrative_approval",
    "rerender",
    "token_usage",
    "manual_merge",
    "raw_output_ingested",
]

# Derive valid values from the EventType Literal for runtime validation
_VALID_EVENT_TYPES: frozenset[str] = frozenset(get_args(EventType))


@dataclass(frozen=True)
class PipelineEvent:
    """Append-only event journal record.

    Every state transition, override, re-run, and AI modification is recorded
    as a PipelineEvent. The event journal is the source of truth for what
    happened to an engagement.

    payload is stored as an immutable MappingProxyType. Callers may pass a
    plain dict; __post_init__ converts it automatically.
    """

    event_id: str
    engagement_id: str
    timestamp: datetime
    event_type: EventType
    actor: str  # "system", "human:<name>", "ai:severity_review", etc.
    payload: Mapping[str, Any]  # always stored as a fresh MappingProxyType copy

    def __post_init__(self) -> None:
        if self.event_type not in _VALID_EVENT_TYPES:
            raise ValueError(f"Invalid event_type: {self.event_type!r}")
        # Always create a new MappingProxyType backed by a fresh dict copy so
        # that neither the caller's original dict nor a passed MappingProxyType
        # referencing an external dict can be mutated to alter the audit record.
        object.__setattr__(self, "payload", MappingProxyType(dict(self.payload)))


def _extract_payload(event: Any) -> dict[str, Any]:  # pyright: ignore[reportUnusedFunction]
    """Extract the payload dict from an event row or object.

    EventRepo.get_events_by_type() returns list[dict[str, Any]] where
    the 'payload' value is a JSON string. Objects with a .payload attribute
    (e.g. PipelineEvent) are also accepted.
    """
    if isinstance(event, dict):
        raw: str | dict[str, Any] = event["payload"]  # pyright: ignore[reportUnknownVariableType]
        if isinstance(raw, str):
            try:
                result: dict[str, Any] = json.loads(raw)
            except json.JSONDecodeError as e:
                raise PersistenceError(f"Corrupt event payload: {e}") from e
            return result
        return raw  # type: ignore[no-any-return]
    return dict(event.payload)  # type: ignore[union-attr]


ENGAGEMENT_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")


class EngagementLock:
    """Advisory file lock per engagement using filelock.

    Prevents concurrent pipeline operations (CLI + review UI) from corrupting
    state. Lock file is placed at <engagements_root>/.locks/<engagement_id>.lock.
    Separate from artifact directories, which use <slug>-<engagement_id> naming.
    """

    def __init__(self, engagements_root: Path) -> None:
        self._engagements_root = engagements_root
        self._locks: dict[str, BaseFileLock] = {}

    def _lock_path(self, engagement_id: str) -> Path:
        if not ENGAGEMENT_ID_PATTERN.match(engagement_id):
            raise PersistenceError(f"Invalid engagement ID format: {engagement_id!r}")
        return self._engagements_root / ".locks" / f"{engagement_id}.lock"

    def acquire(self, engagement_id: str, timeout: float = 30.0) -> None:
        """Acquire advisory lock for an engagement.

        Creates the .locks/ directory if it does not exist.
        Raises LockTimeoutError if the lock cannot be acquired within timeout.
        """
        if engagement_id in self._locks:
            raise PersistenceError(
                f"Lock already held for engagement {engagement_id} in this process"
            )

        from gxassessms.core.security.permissions import secure_mkdir

        lock_path = self._lock_path(engagement_id)  # validates ID format first
        secure_mkdir(lock_path.parent, parents=True, exist_ok=True)  # creates .locks/ dir
        lock = FileLock(str(lock_path))
        try:
            lock.acquire(timeout=timeout)
        except Timeout as err:
            raise LockTimeoutError(
                message=(
                    f"Engagement locked by another process (review UI or concurrent CLI). "
                    f"Lock file: {lock_path}"
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
