"""Domain constants -- Literal types + frozenset companions (AD-79 pattern).

Single source of truth for all domain value sets. Never use raw string
literals for these values outside this module.
"""

from typing import Literal

from gxassessms.core.domain.enums import Category, FindingStatus, Severity

# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

SeverityLevel = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SEVERITIES: frozenset[str] = frozenset(s.value for s in Severity)

SEVERITY_ORDER: dict[str, int] = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

# Identity severity map for adapters that pre-compute domain-level severity
# in the parser (e.g., SecureScore rank+tier, Azure Advisor impact mapping).
# Maps every (Severity, non-passing-status) pair back to the same severity.
# PASS and NOT_APPLICABLE short-circuit to INFO before this map is consulted.
SEVERITY_IDENTITY_MAP: dict[tuple[Severity, FindingStatus], Severity] = {
    (severity, status): severity
    for severity in Severity
    for status in (
        FindingStatus.FAIL,
        FindingStatus.WARNING,
        FindingStatus.ERROR,
        FindingStatus.MANUAL,
    )
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

RemediationPhaseName = Literal["IMMEDIATE", "SHORT_TERM", "MEDIUM_TERM", "LONG_TERM"]

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

CATEGORY_DISPLAY_NAMES: dict[str, str] = {c.name: c.value for c in Category}

# ---------------------------------------------------------------------------
# Confidence
# ---------------------------------------------------------------------------

ConfidenceLabel = Literal["HIGH", "MEDIUM", "LOW", "UNSCORED"]

CONFIDENCE_LABELS: frozenset[str] = frozenset({"HIGH", "MEDIUM", "LOW", "UNSCORED"})

ConfidenceProvenance = Literal["system-generated", "human-overridden", "AI-adjusted"]

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

AuthMethod = Literal["client_credential", "device_code", "interactive"]

# ---------------------------------------------------------------------------
# File Encoding (RawToolOutput file_manifest values)
# ---------------------------------------------------------------------------

FileEncoding = Literal["utf-8", "binary"]

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

ADAPTER_CAPABILITIES: frozenset[AdapterCapability] = frozenset(
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

# ---------------------------------------------------------------------------
# Manifest / Replay Security
# ---------------------------------------------------------------------------

ManifestVersion = Literal["1.0.0"]

MANIFEST_VERSION_CURRENT: str = "1.0.0"

RECOGNIZED_MANIFEST_VERSIONS: frozenset[str] = frozenset({"1.0.0"})

# Regex for storage_slug: [a-z0-9][a-z0-9-]*
TOOL_SLUG_PATTERN: str = r"[a-z0-9][a-z0-9-]*"

# Extension -> FileEncoding mapping for artifact classification.
ENCODING_BY_EXTENSION: dict[str, FileEncoding] = {
    ".json": "utf-8",
}

# Per-manifest_version allowlist of execution_metadata keys per adapter.
# Keys not in the allowlist are silently dropped during persistence.
EXECUTION_METADATA_ALLOWLIST: dict[str, dict[str, frozenset[str]]] = {
    "1.0.0": {
        "scubagear": frozenset({"modules", "module_provenance"}),
        "maester": frozenset({"module_provenance"}),
        "monkey365": frozenset({"output_dir", "module_provenance"}),
        "m365-assess": frozenset({"script", "tenant_id", "controls_dir"}),
        "prowler": frozenset({"output_dir", "auth_method", "checks"}),
        "azure-advisor": frozenset({"recommendation_count"}),
        "secure-score": frozenset({"profiles_count", "scores_count"}),
    },
}

# ---------------------------------------------------------------------------
# Module Verification
# ---------------------------------------------------------------------------

EvidencePath = Literal["signature_and_hash", "hash_only"]

EVIDENCE_PATHS: frozenset[str] = frozenset({"signature_and_hash", "hash_only"})

VerificationMode = Literal["preflight", "collection"]
