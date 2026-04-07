"""BasicDocxRenderer -- Python wrapper for the basic unbranded .docx renderer.

Registered as the 'basic_docx' entry point in the 'gxassessms.renderers'
group. Delegates rendering to NodeRenderer, which invokes the Node.js
render.js in report-renderers/basic/.
"""

from __future__ import annotations

import logging
from pathlib import Path

from gxassessms.core.domain.models import ReportPayload
from gxassessms.reporting.renderer_registry import NodeRenderer

logger = logging.getLogger(__name__)


def _find_renderer_path() -> Path:
    """Locate the basic renderer's directory.

    Searches for report-renderers/basic/ relative to the package root.
    The package root is three levels up from this file:
    src/gxassessms/reporting/basic_renderer.py -> src/gxassessms -> src -> repo root
    """
    here = Path(__file__).resolve()
    repo_root = here.parent.parent.parent.parent
    renderer_path = repo_root / "report-renderers" / "basic"

    if renderer_path.exists():
        return renderer_path

    # Fallback: check relative to CWD (covers some installed-package scenarios)
    cwd_path = Path.cwd() / "report-renderers" / "basic"
    if cwd_path.exists():
        return cwd_path

    raise FileNotFoundError(f"Basic renderer not found. Searched: {renderer_path}, {cwd_path}")


class BasicDocxRenderer:
    """Basic unbranded .docx report renderer.

    Produces a clean document with executive summary, findings grouped
    by category, and methodology sections. No branding or custom styling.
    """

    format: str = "docx"
    supported_payload_versions: str = ">=1.0.0,<2.0.0"

    def __init__(self) -> None:
        self._renderer_path = _find_renderer_path()
        self._node_renderer = NodeRenderer(
            package_path=self._renderer_path,
            format=self.format,
            supported_payload_versions=self.supported_payload_versions,
            name="basic_docx",
        )

    def render(self, payload: ReportPayload, output_dir: Path) -> Path:
        """Render the payload to an unbranded .docx document."""
        logger.info("BasicDocxRenderer: rendering to %s", output_dir)
        return self._node_renderer.render(payload, output_dir)
