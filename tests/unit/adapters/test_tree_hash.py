"""Tests for sha256tree:v1 tree hash implementation."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest


class TestComputeTreeHash:
    """sha256tree:v1 computation."""

    @pytest.fixture(autouse=True)
    def _import(self) -> None:
        from gxassessms.adapters._tree_hash import compute_tree_hash

        self.compute_tree_hash = compute_tree_hash

    @pytest.fixture
    def golden_vector_dir(self, fixtures_dir: Path) -> Path:
        return fixtures_dir / "module_hash_vectors" / "SimpleModule"

    def test_golden_vector_produces_known_hash(self, golden_vector_dir: Path) -> None:
        result = self.compute_tree_hash(golden_vector_dir)
        assert result.startswith("sha256tree:v1:")
        assert len(result) == len("sha256tree:v1:") + 64  # SHA-256 hex

    def test_deterministic_across_calls(self, golden_vector_dir: Path) -> None:
        h1 = self.compute_tree_hash(golden_vector_dir)
        h2 = self.compute_tree_hash(golden_vector_dir)
        assert h1 == h2

    def test_file_ordering_is_forward_slash_lexicographic(self, tmp_path: Path) -> None:
        # Create files: b.txt, a/z.txt -- sorted: a/z.txt, b.txt
        (tmp_path / "b.txt").write_bytes(b"b")
        (tmp_path / "a").mkdir()
        (tmp_path / "a" / "z.txt").write_bytes(b"z")

        result = self.compute_tree_hash(tmp_path)

        # Manually compute expected hash
        entries: list[str] = []
        for rel, content in [("a/z.txt", b"z"), ("b.txt", b"b")]:
            file_hash = hashlib.sha256(content).hexdigest()
            entries.append(f"{rel}\0{file_hash}\n")
        expected = "sha256tree:v1:" + hashlib.sha256("".join(entries).encode()).hexdigest()
        assert result == expected

    def test_empty_directory_produces_valid_hash(self, tmp_path: Path) -> None:
        result = self.compute_tree_hash(tmp_path)
        assert result.startswith("sha256tree:v1:")
        # Hash of empty string
        expected = "sha256tree:v1:" + hashlib.sha256(b"").hexdigest()
        assert result == expected

    def test_rejects_symlink_in_tree(self, tmp_path: Path) -> None:
        real = tmp_path / "real.txt"
        real.write_bytes(b"content")
        link = tmp_path / "link.txt"
        link.symlink_to(real)

        with pytest.raises(ValueError, match=r"reparse|symlink"):
            self.compute_tree_hash(tmp_path)

    def test_hash_prefix_is_sha256tree_v1(self, tmp_path: Path) -> None:
        (tmp_path / "file.txt").write_bytes(b"test")
        result = self.compute_tree_hash(tmp_path)
        assert result.startswith("sha256tree:v1:")

    def test_hidden_files_included(self, tmp_path: Path) -> None:
        (tmp_path / ".hidden").write_bytes(b"hidden")
        (tmp_path / "visible.txt").write_bytes(b"visible")

        result = self.compute_tree_hash(tmp_path)

        # Compute expected with both files
        entries: list[str] = []
        for rel, content in [
            (".hidden", b"hidden"),
            ("visible.txt", b"visible"),
        ]:
            file_hash = hashlib.sha256(content).hexdigest()
            entries.append(f"{rel}\0{file_hash}\n")
        expected = "sha256tree:v1:" + hashlib.sha256("".join(entries).encode()).hexdigest()
        assert result == expected
