"""sha256tree:v1 -- deterministic directory tree hash.

Scheme:
1. Enumerate all files recursively (including hidden)
2. Reject any item with ReparsePoint/symlink attributes
3. Sort by forward-slash-normalized relative path (lexicographic)
4. Per-file: SHA-256 of raw bytes
5. Concatenate: "relative/path\\0<sha256hex>\\n"
6. Final: "sha256tree:v1:" + SHA-256 of concatenation

The scheme version (v1) locks file-selection rules, path normalization,
and hash algorithm. A future v2 can revise without silently invalidating
existing hashes.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

_PREFIX = "sha256tree:v1:"


def compute_tree_hash(directory: Path) -> str:
    """Compute sha256tree:v1 hash for a directory tree.

    Args:
        directory: Root directory to hash.

    Returns:
        Hash string prefixed with "sha256tree:v1:".

    Raises:
        ValueError: If any item in the tree is a symlink or reparse point.
        OSError: If files cannot be read.
    """
    files: list[tuple[str, Path]] = []

    for item in directory.rglob("*"):
        # Symlink check must come before is_file() -- a symlink to a file
        # would pass is_file() on platforms that follow links by default.
        if item.is_symlink():
            raise ValueError(f"Symlink/reparse point detected in tree: {item}")
        if not item.is_file():
            continue

        rel = item.relative_to(directory).as_posix()
        files.append((rel, item))

    # Sort by forward-slash relative path for cross-platform determinism.
    files.sort(key=lambda entry: entry[0])

    manifest_parts: list[str] = []
    for rel, item in files:
        file_hash = hashlib.sha256(item.read_bytes()).hexdigest()
        manifest_parts.append(f"{rel}\0{file_hash}\n")

    manifest = "".join(manifest_parts)
    tree_hash = hashlib.sha256(manifest.encode()).hexdigest()
    return f"{_PREFIX}{tree_hash}"
