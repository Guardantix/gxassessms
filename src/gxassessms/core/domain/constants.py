"""Domain constants -- Literal types + frozenset companions (AD-79 pattern).

Single source of truth for all domain value sets. Never use raw string
literals for these values outside this module.
"""

from typing import Literal

# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

SeverityLevel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SEVERITIES: frozenset[str] = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})

SEVERITY_ORDER: dict[str, int] = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "bright_red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}

# ---------------------------------------------------------------------------
# Remediation Phases
# ---------------------------------------------------------------------------

RemediationPhase = Literal["IMMEDIATE", "SHORT_TERM", "MEDIUM_TERM", "LONG_TERM"]

REMEDIATION_PHASES: frozenset[str] = frozenset(
    {"IMMEDIATE", "SHORT_TERM", "MEDIUM_TERM", "LONG_TERM"}
)

REMEDIATION_PHASE_TIMELINES: dict[str, str] = {
    "IMMEDIATE": "0-30 days",
    "SHORT_TERM": "30-90 days",
    "MEDIUM_TERM": "90-180 days",
    "LONG_TERM": "180+ days",
}

# ---------------------------------------------------------------------------
# Categories
# ---------------------------------------------------------------------------

CategoryName = Literal[
    "Identity & Access",
    "Data Protection",
    "Device Management",
    "Email & Collaboration",
    "Infrastructure Security",
    "Network Security",
    "Logging & Monitoring",
    "Cost Optimization",
    "Operational Excellence",
    "Compliance & Governance",
    "Application Security",
]

CATEGORY_DISPLAY_NAMES: dict[str, str] = {
    "IDENTITY_ACCESS": "Identity & Access",
    "DATA_PROTECTION": "Data Protection",
    "DEVICE_MANAGEMENT": "Device Management",
    "EMAIL_COLLABORATION": "Email & Collaboration",
    "INFRASTRUCTURE_SECURITY": "Infrastructure Security",
    "NETWORK_SECURITY": "Network Security",
    "LOGGING_MONITORING": "Logging & Monitoring",
    "COST_OPTIMIZATION": "Cost Optimization",
    "OPERATIONAL_EXCELLENCE": "Operational Excellence",
    "COMPLIANCE": "Compliance & Governance",
    "APPLICATION_SECURITY": "Application Security",
}

# ---------------------------------------------------------------------------
# Confidence
# ---------------------------------------------------------------------------

ConfidenceLabel = Literal["HIGH", "MEDIUM", "LOW", "UNSCORED"]

CONFIDENCE_LABELS: frozenset[str] = frozenset({"HIGH", "MEDIUM", "LOW", "UNSCORED"})

# ---------------------------------------------------------------------------
# Adapter Capabilities
# ---------------------------------------------------------------------------

AdapterCapability = Literal[
    "collect",
    "parse",
    "prerequisites",
    "shared_auth",
    "coverage_export",
    "benchmark_mapping",
]

ADAPTER_CAPABILITIES: frozenset[str] = frozenset(
    {
        "collect",
        "parse",
        "prerequisites",
        "shared_auth",
        "coverage_export",
        "benchmark_mapping",
    }
)

# ToolSource values that are reserved placeholders (no adapter yet)
ADAPTER_PLACEHOLDERS: frozenset[str] = frozenset(
    {
        "Steampipe",
        "DefenderCloud",
        "M365DSC",
        "IntuneExport",
        "AzureResourceGraph",
        "Custom",
    }
)
