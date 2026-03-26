"""Domain enums -- str-based for JSON serialization and human readability."""

from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(StrEnum):
    FAIL = "FAIL"
    PASS = "PASS"  # noqa: S105
    WARNING = "WARNING"
    ERROR = "ERROR"
    NOT_APPLICABLE = "N/A"
    MANUAL = "MANUAL"


class Category(StrEnum):
    IDENTITY_ACCESS = "Identity & Access"
    DATA_PROTECTION = "Data Protection"
    DEVICE_MANAGEMENT = "Device Management"
    EMAIL_COLLABORATION = "Email & Collaboration"
    INFRASTRUCTURE_SECURITY = "Infrastructure Security"
    NETWORK_SECURITY = "Network Security"
    LOGGING_MONITORING = "Logging & Monitoring"
    COST_OPTIMIZATION = "Cost Optimization"
    OPERATIONAL_EXCELLENCE = "Operational Excellence"
    COMPLIANCE = "Compliance & Governance"
    APPLICATION_SECURITY = "Application Security"


class ToolSource(StrEnum):
    SCUBAGEAR = "ScubaGear"
    MAESTER = "Maester"
    MONKEY365 = "Monkey365"
    M365_ASSESS = "M365Assess"
    PROWLER = "Prowler"
    STEAMPIPE = "Steampipe"
    SECURE_SCORE = "SecureScore"
    AZURE_ADVISOR = "AzureAdvisor"
    DEFENDER_CLOUD = "DefenderCloud"
    M365DSC = "M365DSC"
    INTUNE_EXPORT = "IntuneExport"
    AZURE_RESOURCE_GRAPH = "AzureResourceGraph"
    CUSTOM = "Custom"
    MANUAL = "Manual"
