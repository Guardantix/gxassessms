"""Shared SHA-256 hashing utilities.

Single source of truth for file and content hashing across the pipeline.
Used by adapters (collection), persistence (save verification), and
confinement (integrity verification).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

_HASH_BUFFER_SIZE = 65536  # 64 KiB read chunks


def sha256_file(path: Path) -> str:
    """Compute SHA-256 hex digest of a file using chunked reads."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(_HASH_BUFFER_SIZE):
            h.update(chunk)
    return h.hexdigest()
