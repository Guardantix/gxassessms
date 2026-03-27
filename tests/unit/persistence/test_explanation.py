"""Tests for FindingExplanationService."""

from pathlib import Path

import pytest

from gxassessms.core.contracts.errors import PersistenceError
from gxassessms.core.domain.enums import Severity
from gxassessms.persistence.database import DatabaseManager
from gxassessms.persistence.explanation import FindingExplanationService
from gxassessms.persistence.repositories import EngagementRepo, FindingRepo


@pytest.fixture
def db_manager(tmp_path: Path) -> DatabaseManager:
    """Create a test DatabaseManager with real migrations."""
    db_path = tmp_path / "test.db"
    migrations_dir = (
        Path(__file__).parent.parent.parent.parent / "src/gxassessms/persistence/migrations"
    )
    mgr = DatabaseManager(db_path=db_path, migrations_dir=migrations_dir)
    mgr.initialize()
    return mgr


@pytest.fixture
def engagement_repo(db_manager: DatabaseManager) -> EngagementRepo:
    return EngagementRepo(db_manager)


@pytest.fixture
def finding_repo(db_manager: DatabaseManager) -> FindingRepo:
    return FindingRepo(db_manager)


def _create_engagement_with_finding(
    engagement_repo: EngagementRepo,
    finding_repo: FindingRepo,
    finding_instance_id: str = "cf-explain-001",
) -> str:
    """Helper: create an engagement and a consolidated finding, return eng_id."""
    eng_id = engagement_repo.create(
        client_name="Test",
        tenant_id="t-001",
        config_snapshot={},
    )
    finding_repo.save_consolidated(
        eng_id,
        [
            {
                "finding_instance_id": finding_instance_id,
                "finding_key": "cis:m365:1.1.1",
                "title": "Test finding",
                "severity": "HIGH",
                "status": "FAIL",
                "category": "Identity & Access",
                "description": "Test",
                "sources": [{"tool": "ScubaGear", "check_id": "MS.AAD.3.1v1", "raw_data": {}}],
                "confidence": {
                    "evidence_strength": 0.9,
                    "corroborating_tools": 2,
                    "data_freshness": 0.95,
                    "provenance": "system-generated",
                    "overall": 0.88,
                },
            },
        ],
    )
    return eng_id


class TestFindingExplanationService:
    def test_explain_returns_stub_structure(
        self,
        engagement_repo: EngagementRepo,
        finding_repo: FindingRepo,
        db_manager: DatabaseManager,
    ) -> None:
        _create_engagement_with_finding(engagement_repo, finding_repo)
        svc = FindingExplanationService(db_manager)
        explanation = svc.explain("cf-explain-001")
        assert explanation["finding_instance_id"] == "cf-explain-001"
        assert "sources" in explanation
        assert "severity_basis" in explanation
        assert "override_history" in explanation
        assert "ai_modifications" in explanation
        assert "confidence_basis" in explanation

    def test_explain_nonexistent_finding_raises(self, db_manager: DatabaseManager) -> None:
        svc = FindingExplanationService(db_manager)
        with pytest.raises(PersistenceError):
            svc.explain("nonexistent-finding")

    def test_explain_with_overrides(
        self,
        engagement_repo: EngagementRepo,
        finding_repo: FindingRepo,
        db_manager: DatabaseManager,
    ) -> None:
        eng_id = _create_engagement_with_finding(engagement_repo, finding_repo, "cf-ovr-001")
        finding_repo.override_severity(
            finding_id="cf-ovr-001",
            new_severity=Severity.CRITICAL,
            reason="Client-specific risk",
            actor="human:rick",
            engagement_id=eng_id,
        )
        svc = FindingExplanationService(db_manager)
        explanation = svc.explain("cf-ovr-001")
        assert explanation["severity_basis"]["override_count"] == 1
        assert len(explanation["override_history"]) == 1
        assert explanation["override_history"][0]["new_value"] == "CRITICAL"
