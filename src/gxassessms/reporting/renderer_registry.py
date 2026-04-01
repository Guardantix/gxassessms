"""Renderer registry -- discovers renderers, validates versions, invokes Node.js.

Renderers are discovered via entry points in the 'gxassessms.renderers'
group. Each renderer is a Python class that wraps a Node.js package
(render.js entry point). The registry validates payload version
compatibility before invoking a renderer.

Renderer boundary validation follows the same principle as adapter
boundary validation: validate before crossing the process boundary,
capture diagnostics on failure, and never produce silent empty output.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from gxassessms.core.contracts.errors import (
    PayloadVersionError,
    RendererDependencyError,
    ReportError,
)
from gxassessms.core.domain.models import ReportPayload
from gxassessms.registry import DiscoveryError, discover_entry_points
from gxassessms.reporting.constants_bridge import write_constants_file

logger = logging.getLogger(__name__)

RENDERER_GROUP = "gxassessms.renderers"

_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")

_DEFAULT_TIMEOUT_SECONDS = 120


def _parse_version(version: str) -> tuple[int, int, int]:
    """Parse a semver string into a (major, minor, patch) tuple."""
    if not _SEMVER_RE.match(version):
        raise PayloadVersionError(f"Invalid payload version: '{version}' (expected semver X.Y.Z)")
    parts = version.split(".")
    return int(parts[0]), int(parts[1]), int(parts[2])


def _parse_constraint(constraint: str) -> tuple[str, tuple[int, int, int]]:
    """Parse a single version constraint like '>=1.0.0' or '<2.0.0'."""
    for op in (">=", "<=", ">", "<", "=="):
        if constraint.startswith(op):
            version_str = constraint[len(op) :]
            if not _SEMVER_RE.match(version_str):
                raise PayloadVersionError(f"Invalid version in constraint: '{constraint}'")
            parts = version_str.split(".")
            return op, (int(parts[0]), int(parts[1]), int(parts[2]))
    raise PayloadVersionError(f"Invalid version constraint: '{constraint}'")


def _check_constraint(
    version: tuple[int, int, int],
    operator: str,
    target: tuple[int, int, int],
) -> bool:
    """Check if version satisfies the constraint."""
    ops = {
        ">=": version >= target,
        "<=": version <= target,
        ">": version > target,
        "<": version < target,
        "==": version == target,
    }
    return ops.get(operator, False)


def validate_version_compatibility(payload_version: str, supported_range: str) -> None:
    """Validate that a payload version is within the supported range.

    Args:
        payload_version: Semver string from the ReportPayload (e.g. "1.0.0").
        supported_range: Semver range from the renderer (e.g. ">=1.0.0,<2.0.0").

    Raises:
        PayloadVersionError: If the version is outside the supported range
            or if either version string is malformed.
    """
    version = _parse_version(payload_version)
    constraints = [c.strip() for c in supported_range.split(",")]

    for constraint_str in constraints:
        operator, target = _parse_constraint(constraint_str)
        if not _check_constraint(version, operator, target):
            raise PayloadVersionError(
                f"Payload version {payload_version} is not compatible "
                f"with renderer range '{supported_range}'"
            )


def check_node_available() -> bool:
    """Check whether Node.js is available on the system PATH."""
    node_exe = shutil.which("node")
    if node_exe is None:
        return False
    try:
        result = subprocess.run(  # noqa: S603
            [node_exe, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except FileNotFoundError, subprocess.TimeoutExpired:
        return False


class NodeRenderer:
    """Wraps a Node.js renderer package for invocation from Python.

    Each renderer is a directory containing a render.js entry point
    and a package.json with dependencies. The render cycle:
    1. Validate payload version against renderer's supported range
    2. Check Node.js availability
    3. Write payload JSON and constants.json to temp directory
    4. Invoke: node render.js --payload <path> --output <path> --constants <path>
    5. Validate output file was created and is non-zero bytes
    6. Capture stderr on failure, wrap in ReportError

    Output file naming: the renderer constructs the output filename as
    ``{engagement_id}.{format}`` within the output_dir passed to render().
    The pipeline's render stage passes a directory (output_dir), not a
    specific file path. This supports multiple renderers writing to the
    same directory without filename conflicts.
    """

    def __init__(
        self,
        package_path: Path,
        format: str,
        supported_payload_versions: str,
        timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
        keep_temp_on_failure: bool = False,
    ) -> None:
        self.package_path = package_path
        self.format = format
        self.supported_payload_versions = supported_payload_versions
        self._timeout_seconds = timeout_seconds
        self._keep_temp_on_failure = keep_temp_on_failure

        # Fail at discovery time, not render time (spec Section 7)
        render_js = self.package_path / "render.js"
        if not render_js.exists():
            raise RendererDependencyError(
                f"render.js not found at {render_js}. "
                f"Renderer package may not be installed correctly."
            )

    def render(self, payload: ReportPayload, output_dir: Path) -> Path:
        """Render the payload to a document in output_dir.

        Args:
            payload: The assembled ReportPayload.
            output_dir: Directory to write the rendered document into.
                The filename is constructed as {engagement_id}.{format}.

        Returns:
            The path to the rendered file on success.

        Raises:
            PayloadVersionError: If the payload version is incompatible.
            RendererDependencyError: If Node.js is missing.
            ReportError: If the Node.js process exits non-zero, or if the
                output file is missing/empty after a successful exit.
        """
        validate_version_compatibility(payload.schema_version, self.supported_payload_versions)

        if not check_node_available():
            raise RendererDependencyError("Node.js is not available on the system PATH")

        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / f"{payload.engagement_id}.{self.format}"
        render_js = self.package_path / "render.js"

        tmpdir_obj = tempfile.TemporaryDirectory(prefix="gxassessms_render_")
        tmp = Path(tmpdir_obj.name)
        try:
            payload_path = tmp / "payload.json"
            constants_path = tmp / "constants.json"

            payload_json = payload.model_dump_json(indent=2)
            payload_path.write_text(payload_json, encoding="utf-8")
            write_constants_file(constants_path)

            # shutil.which confirmed node exists in check_node_available() above
            node_exe = shutil.which("node") or "node"
            cmd = [
                node_exe,
                str(render_js),
                "--payload",
                str(payload_path),
                "--output",
                str(output_path),
                "--constants",
                str(constants_path),
            ]

            logger.info(
                "Invoking renderer: %s (format=%s, timeout=%ds)",
                self.package_path.name,
                self.format,
                self._timeout_seconds,
            )

            try:
                result = subprocess.run(  # noqa: S603
                    cmd,
                    capture_output=True,
                    text=True,
                    cwd=str(self.package_path),
                    timeout=self._timeout_seconds,
                )
            except subprocess.TimeoutExpired as exc:
                raise ReportError(
                    f"Renderer '{self.package_path.name}' (format={self.format}) "
                    f"timed out after {self._timeout_seconds}s"
                ) from exc

            if result.returncode != 0:
                if self._keep_temp_on_failure:
                    logger.warning("Render failed. Temp files preserved at: %s", tmp)
                raise ReportError(
                    f"Renderer '{self.package_path.name}' (format={self.format}) "
                    f"exited with code {result.returncode}. "
                    f"stderr: {result.stderr.strip()}"
                )

            # Validate output (fail-closed: no silent empty files)
            if not output_path.exists() or output_path.stat().st_size == 0:
                raise ReportError(
                    f"Renderer '{self.package_path.name}' (format={self.format}) "
                    f"exited successfully but did not produce output at "
                    f"{output_path}. Check renderer implementation."
                )

        except ReportError, PayloadVersionError, RendererDependencyError:
            if self._keep_temp_on_failure:
                logger.warning("Render failed. Temp files preserved at: %s", tmp)
            else:
                tmpdir_obj.cleanup()
            raise
        else:
            tmpdir_obj.cleanup()

        logger.info("Render complete: %s -> %s", self.package_path.name, output_path)
        return output_path


class RendererRegistry:
    """Registry of available report renderers.

    Renderers are discovered via entry points or registered manually.
    Supports lookup by name or by format.
    """

    def __init__(self) -> None:
        self._renderers: dict[str, Any] = {}
        self.discovery_errors: list[DiscoveryError] = []

    def register(self, name: str, renderer: Any) -> None:
        """Register a renderer by name."""
        self._renderers[name] = renderer
        logger.debug("Registered renderer '%s' (format=%s)", name, renderer.format)

    def get(self, name: str) -> Any | None:
        """Get a renderer by name, or None if not found."""
        return self._renderers.get(name)

    def list_renderers(self) -> list[str]:
        """List names of all registered renderers."""
        return list(self._renderers.keys())

    def get_by_format(self, format: str) -> list[Any]:
        """Get all renderers that produce a given format."""
        return [r for r in self._renderers.values() if r.format == format]

    @classmethod
    def discover(cls) -> RendererRegistry:
        """Discover and register all renderers from entry points.

        Returns a populated RendererRegistry.
        """
        registry = cls()
        discovery = discover_entry_points(RENDERER_GROUP)

        registry.discovery_errors.extend(discovery.errors)

        for name, renderer_cls in discovery.plugins.items():
            try:
                instance = renderer_cls()
                registry.register(name, instance)
            except (TypeError, RendererDependencyError) as exc:
                error = DiscoveryError(
                    plugin_name=name,
                    error_type=type(exc).__name__,
                    message=f"Failed to instantiate renderer '{name}': {exc}",
                )
                registry.discovery_errors.append(error)
                logger.warning("Renderer '%s' failed instantiation: %s", name, exc)

        logger.info(
            "Renderer discovery: %d registered, %d errors",
            len(registry._renderers),
            len(registry.discovery_errors),
        )
        return registry
