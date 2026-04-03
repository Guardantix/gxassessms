"""Replay trust boundary -- confinement and integrity verification.

confine_and_resolve() is the single function where all replay security
enforcement happens. It sits between "loaded from disk" and "handed to
adapters." Both live and replay paths pass through it.
"""

from __future__ import annotations

from pathlib import Path
from typing import NamedTuple

from gxassessms.core.domain.models import RawToolOutput


class LoadedManifest(NamedTuple):
    """Pairs a deserialized manifest with its on-disk source path."""

    source_path: Path  # e.g., .../manifests/scubagear.json
    raw_output: RawToolOutput
