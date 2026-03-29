"""No-op QA strategy -- ships with the public package.

Returns empty results and empty narratives. The orchestrator detects
the is_noop flag and auto-advances QA_REVIEW -> QA_APPROVED without
requiring UI interaction. This allows open-source users to complete
the full pipeline without AI QA or a review UI.
"""

from __future__ import annotations

from gxassessms.core.config.config import EngagementConfig
from gxassessms.core.contracts.types import Narratives, QAResult
from gxassessms.core.domain.models import ConsolidatedFinding


class NoOpQAStrategy:
    """No-op QA strategy -- satisfies QAStrategy Protocol with no AI calls.

    Attributes:
        is_noop: Flag checked by the orchestrator to determine whether
            to auto-advance QA_REVIEW -> QA_APPROVED.
    """

    is_noop: bool = True

    def review_findings(self, findings: list[ConsolidatedFinding]) -> list[QAResult]:
        """Return empty list -- no findings are reviewed."""
        return []

    def generate_narratives(
        self, findings: list[ConsolidatedFinding], config: EngagementConfig
    ) -> Narratives:
        """Return empty narratives -- no AI-generated text."""
        return Narratives(
            executive_summary="",
            roadmap="",
            findings_narrative=None,
        )
