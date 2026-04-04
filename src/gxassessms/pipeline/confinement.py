"""Replay trust boundary -- confinement and integrity verification.

confine_and_resolve() is the single function where all replay security
enforcement happens. It sits between "loaded from disk" and "handed to
adapters." Both live and replay paths pass through it.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, NamedTuple

from gxassessms.core.contracts.errors import ManifestConfinementError
from gxassessms.core.domain.constants import RECOGNIZED_MANIFEST_VERSIONS
from gxassessms.core.domain.models import ArtifactRecord, RawToolOutput, ResolvedManifest
from gxassessms.core.domain.path_validation import validate_canonical_posix_path
from gxassessms.core.hashing import sha256_file

logger = logging.getLogger(__name__)


class LoadedManifest(NamedTuple):
    """Pairs a deserialized manifest with its on-disk source path."""

    source_path: Path  # e.g., .../manifests/scubagear.json
    raw_output: RawToolOutput


def confine_and_resolve(
    loaded_manifests: list[LoadedManifest],
    engagement_dir: Path,
    adapters: list[Any],
) -> list[ResolvedManifest]:
    """Replay trust boundary: confine paths and verify artifact integrity.

    All replay security enforcement happens here. No partial results:
    if any manifest or any path within a manifest fails, the entire
    operation fails with ManifestConfinementError.
    """
    artifacts_root = engagement_dir / "raw-output" / "artifacts"

    # Defense-in-depth: reject symlinked artifacts root before resolving
    # manifest paths. Without this, a symlink at raw-output/artifacts could
    # redirect the entire confinement check to an attacker-controlled tree.
    resolved_root = artifacts_root.resolve()
    resolved_engagement = engagement_dir.resolve()
    if not resolved_root.is_relative_to(resolved_engagement):
        raise ManifestConfinementError(
            message="Artifacts root resolves outside engagement directory (symlink?)",
            engagement_id=engagement_dir.name,
            stage="confine",
            tool_slug="*",
            check_name="artifacts_root_confinement",
            detail=f"artifacts_root={resolved_root}, engagement={resolved_engagement}",
        )

    # Canonical-path check: even if resolved_root is inside the engagement,
    # a symlink could redirect it to a different subtree (e.g.,
    # raw-output/artifacts -> <engagement>/reports/artifacts), breaking
    # the trust boundary while staying within the engagement directory.
    expected_root = resolved_engagement / "raw-output" / "artifacts"
    if resolved_root != expected_root:
        raise ManifestConfinementError(
            message="Artifacts root resolves to non-canonical location (symlink?)",
            engagement_id=engagement_dir.name,
            stage="confine",
            tool_slug="*",
            check_name="artifacts_root_canonical",
            detail=f"resolved={resolved_root}, expected={expected_root}",
        )

    adapter_by_slug: dict[str, Any] = {a.storage_slug: a for a in adapters}

    resolved_manifests: list[ResolvedManifest] = []

    for lm in loaded_manifests:
        raw = lm.raw_output
        slug = raw.tool_slug
        eng_id = engagement_dir.name

        # 1. manifest_version gate
        if raw.manifest_version not in RECOGNIZED_MANIFEST_VERSIONS:
            raise ManifestConfinementError(
                message=(f"Unrecognized manifest_version {raw.manifest_version!r} for tool {slug}"),
                engagement_id=eng_id,
                stage="confine",
                tool_slug=slug,
                check_name="manifest_version_gate",
                detail=f"recognized versions: {sorted(RECOGNIZED_MANIFEST_VERSIONS)}",
            )

        # 2. Three-way slug check
        filename_stem = lm.source_path.stem
        if filename_stem != slug:
            raise ManifestConfinementError(
                message=(
                    f"Manifest filename stem {filename_stem!r} does not match tool_slug {slug!r}"
                ),
                engagement_id=eng_id,
                stage="confine",
                tool_slug=slug,
                check_name="filename_stem_slug_match",
                detail=f"expected {slug}.json, got {lm.source_path.name}",
            )

        adapter = adapter_by_slug.get(slug)
        if adapter is None:
            raise ManifestConfinementError(
                message=f"No registered adapter with storage_slug {slug!r}",
                engagement_id=eng_id,
                stage="confine",
                tool_slug=slug,
                check_name="slug_adapter_match",
                detail=f"registered slugs: {sorted(adapter_by_slug)}",
            )

        if raw.tool != adapter.tool_source:
            raise ManifestConfinementError(
                message=(
                    f"Manifest tool {raw.tool!r} does not match adapter "
                    f"tool_source {adapter.tool_source!r} for slug {slug!r}"
                ),
                engagement_id=eng_id,
                stage="confine",
                tool_slug=slug,
                check_name="tool_source_match",
                detail=f"manifest={raw.tool!r}, adapter={adapter.tool_source!r}",
            )

        # Per-path checks
        resolved_manifest: dict[str, ArtifactRecord] = {}
        seen_resolved: set[str] = set()
        tool_subtree = (artifacts_root / slug).resolve()

        # Defense-in-depth: reject symlinked per-tool subtrees.
        # The artifacts_root check above covers raw-output/artifacts/ itself,
        # but a symlink at raw-output/artifacts/<slug>/ would let both
        # tool_subtree and resolved paths escape together, passing the
        # is_relative_to check while reading files outside the engagement.
        # Canonical-path equality catches both out-of-engagement escapes AND
        # in-engagement redirections (e.g., scubagear/ -> maester/).
        expected_subtree = resolved_root / slug
        if tool_subtree != expected_subtree:
            raise ManifestConfinementError(
                message=(
                    f"Tool subtree for {slug!r} resolves to non-canonical location (symlink?)"
                ),
                engagement_id=eng_id,
                stage="confine",
                tool_slug=slug,
                check_name="tool_subtree_canonical",
                detail=f"resolved={tool_subtree}, expected={expected_subtree}",
            )

        for relpath, record in raw.file_manifest.items():
            # 3. Canonical format (defense-in-depth)
            try:
                validate_canonical_posix_path(relpath)
            except ValueError as e:
                raise ManifestConfinementError(
                    message=f"Non-canonical path in manifest: {relpath!r}: {e}",
                    engagement_id=eng_id,
                    stage="confine",
                    tool_slug=slug,
                    check_name="canonical_path",
                    detail=str(e),
                ) from e

            # 4. Tool confinement (path starts with slug/)
            if not relpath.startswith(f"{slug}/"):
                raise ManifestConfinementError(
                    message=(f"Path {relpath!r} does not start with {slug}/"),
                    engagement_id=eng_id,
                    stage="confine",
                    tool_slug=slug,
                    check_name="tool_path_confinement",
                    detail=f"expected prefix: {slug}/",
                )

            # 5. Strict resolve
            target = artifacts_root / relpath
            try:
                resolved = target.resolve(strict=True)
            except (FileNotFoundError, OSError) as e:
                raise ManifestConfinementError(
                    message=f"Artifact not found: {relpath!r}",
                    engagement_id=eng_id,
                    stage="confine",
                    tool_slug=slug,
                    check_name="artifact_exists",
                    detail=str(e),
                ) from e

            if not resolved.is_relative_to(tool_subtree):
                raise ManifestConfinementError(
                    message=(
                        f"Resolved path for {relpath!r} escapes tool subtree (symlink or traversal)"
                    ),
                    engagement_id=eng_id,
                    stage="confine",
                    tool_slug=slug,
                    check_name="tool_subtree_containment",
                    detail=f"resolved={resolved}, tool_subtree={tool_subtree}",
                )

            # 7. File type check
            if not resolved.is_file():
                raise ManifestConfinementError(
                    message=f"Artifact is not a regular file: {relpath!r}",
                    engagement_id=eng_id,
                    stage="confine",
                    tool_slug=slug,
                    check_name="artifact_is_file",
                    detail=f"resolved={resolved}",
                )

            # 8. SHA-256 verify
            actual_hash = sha256_file(resolved)
            if actual_hash != record.sha256:
                raise ManifestConfinementError(
                    message=(
                        f"SHA-256 mismatch for {relpath!r}: "
                        f"expected {record.sha256}, got {actual_hash}"
                    ),
                    engagement_id=eng_id,
                    stage="confine",
                    tool_slug=slug,
                    check_name="sha256_verify",
                    detail=f"file={relpath}, expected={record.sha256}, actual={actual_hash}",
                )

            # 9. Duplicate resolution check
            resolved_str = str(resolved)
            if resolved_str in seen_resolved:
                raise ManifestConfinementError(
                    message=(
                        f"Duplicate resolved path: {resolved_str} "
                        f"(multiple manifest entries resolve to same file)"
                    ),
                    engagement_id=eng_id,
                    stage="confine",
                    tool_slug=slug,
                    check_name="duplicate_resolved_path",
                    detail=f"relpath={relpath}",
                )
            seen_resolved.add(resolved_str)

            resolved_manifest[resolved_str] = record

        resolved_manifests.append(
            ResolvedManifest(
                tool=raw.tool,
                tool_slug=slug,
                schema_version=raw.schema_version,
                manifest_version=raw.manifest_version,
                timestamp=raw.timestamp,
                file_manifest=resolved_manifest,
                execution_metadata=raw.execution_metadata,
            )
        )
        logger.info(
            "Confined and resolved manifest for %s: %d artifacts verified",
            slug,
            len(resolved_manifest),
        )

    return resolved_manifests
