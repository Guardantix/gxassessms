"""Regression test: all names in the gxassessms.policy public API are importable.

G13: Verifies that the __init__.py re-export style (Name as Name) correctly exposes
all public policy classes from the gxassessms.policy namespace.
"""


def test_all_public_policy_names_importable() -> None:
    """G13: All policy classes are importable from the gxassessms.policy namespace."""
    from gxassessms.policy import (
        ConsolidationPolicy,
        DefaultConsolidationPolicy,
        DefaultNormalizationPolicy,
        DefaultReportingPolicy,
        DefaultRoadmapPolicy,
        DefaultSeverityPolicy,
        NormalizationPolicy,
        ReportingPolicy,
        RoadmapPolicy,
        SeverityPolicy,
    )

    assert ConsolidationPolicy is not None
    assert DefaultConsolidationPolicy is not None
    assert DefaultNormalizationPolicy is not None
    assert DefaultReportingPolicy is not None
    assert DefaultRoadmapPolicy is not None
    assert DefaultSeverityPolicy is not None
    assert NormalizationPolicy is not None
    assert ReportingPolicy is not None
    assert RoadmapPolicy is not None
    assert SeverityPolicy is not None
