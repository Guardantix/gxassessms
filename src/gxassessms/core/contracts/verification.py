"""Module provenance verification DTOs.

Frozen dataclasses for policy definitions, candidate outcomes, and
verification results. Lives in core/contracts (neutral location, no
cross-layer dependencies).

Construction invariants are enforced in __post_init__ -- invalid
policy cannot exist at runtime.
"""

from __future__ import annotations

import json
import operator as _op
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

# ---------------------------------------------------------------------------
# Version constraint parsing (shared by ModulePolicy + ModulePolicyOverride)
# ---------------------------------------------------------------------------

_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
_CONSTRAINT_RE = re.compile(r"^(>=|<=|>|<|==)(\d+\.\d+\.\d+)$")


def parse_semver(version: str) -> tuple[int, int, int]:
    """Parse an X.Y.Z string into (major, minor, patch).

    Raises ValueError if format is not exactly X.Y.Z.
    """
    if not _SEMVER_RE.match(version):
        raise ValueError(f"Not a valid X.Y.Z version: {version!r}")
    parts = version.split(".")
    return int(parts[0]), int(parts[1]), int(parts[2])


def version_satisfies_range(version: str, version_range: str) -> bool:
    """Check if an X.Y.Z version satisfies a semver constraint string.

    Supports: >=X.Y.Z, <=X.Y.Z, >X.Y.Z, <X.Y.Z, ==X.Y.Z
    Multiple constraints separated by commas (all must pass).
    """
    ops = {">=": _op.ge, "<=": _op.le, ">": _op.gt, "<": _op.lt, "==": _op.eq}
    ver = parse_semver(version)

    constraints = [c.strip() for c in version_range.split(",")]
    for constraint in constraints:
        m = _CONSTRAINT_RE.match(constraint)
        if m is None:
            raise ValueError(f"Invalid version constraint: {constraint!r}")
        op_str, target_str = m.group(1), m.group(2)
        target = parse_semver(target_str)
        if not ops[op_str](ver, target):
            return False
    return True


def _validate_version_range(version_range: str) -> None:
    """Validate that version_range parses as valid constraints."""
    constraints = [c.strip() for c in version_range.split(",")]
    for constraint in constraints:
        if not _CONSTRAINT_RE.match(constraint):
            raise ValueError(f"version_range contains invalid constraint: {constraint!r}")


# ---------------------------------------------------------------------------
# SignerIdentity
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SignerIdentity:
    """Structured signer identity -- full subject + issuer."""

    subject: str
    issuer: str


# ---------------------------------------------------------------------------
# ModulePolicy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ModulePolicy:
    """Code-owned approved-module policy. Adapters define these as constants."""

    module_name: str
    version_range: str
    allowed_signers: frozenset[SignerIdentity]
    approved_package_hashes: frozenset[str]
    allow_package_hash_fallback: bool

    def __post_init__(self) -> None:
        if not self.allowed_signers:
            raise ValueError("allowed_signers must be non-empty")
        if not self.approved_package_hashes:
            raise ValueError("approved_package_hashes must be non-empty")
        for h in self.approved_package_hashes:
            if not h.startswith("sha256tree:v1:"):
                raise ValueError(f"Hash must be prefixed 'sha256tree:v1:', got: {h!r}")
        _validate_version_range(self.version_range)


# ---------------------------------------------------------------------------
# ModulePolicyOverride (config narrowing)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ModulePolicyOverride:
    """Optional config narrowing. Can restrict, never widen."""

    version_range: str | None = None
    pinned_package_hashes: frozenset[str] | None = None

    def __post_init__(self) -> None:
        if self.version_range is not None:
            if not self.version_range.startswith("=="):
                raise ValueError(
                    f"Override version_range must be an exact-version pin "
                    f"(==X.Y.Z), got: {self.version_range!r}"
                )
            pin = self.version_range[2:]
            parse_semver(pin)  # validates X.Y.Z format
        if self.pinned_package_hashes is not None:
            if not self.pinned_package_hashes:
                raise ValueError("pinned_package_hashes cannot be empty (use None to skip)")
            for h in self.pinned_package_hashes:
                if not h.startswith("sha256tree:v1:"):
                    raise ValueError(f"Hash must be prefixed 'sha256tree:v1:', got: {h!r}")


# ---------------------------------------------------------------------------
# CandidateOutcome
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CandidateOutcome:
    """Per-candidate verification details."""

    version: str
    live_manifest_path: str
    live_module_root: str
    staged_manifest_path: str | None
    staged_module_root: str | None

    provenance_approved: bool
    execution_supported: bool
    rejection_reasons: tuple[str, ...] = ()

    confinement_violation: str | None = None
    package_hash: str | None = None
    hash_approved: bool = False

    live_signature_status: str | None = None
    live_signer_subject: str | None = None
    live_signer_issuer: str | None = None
    live_signer_thumbprint: str | None = None

    staged_signature_status: str | None = None
    staged_signer_subject: str | None = None
    staged_signer_issuer: str | None = None
    staged_signer_thumbprint: str | None = None
    staged_signer_approved: bool | None = None

    evidence_path: Literal["signature_and_hash", "hash_only"] | None = None


# ---------------------------------------------------------------------------
# ModuleVerificationResult
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ModuleVerificationResult:
    """Full verification result. JSON-serializable for persistence and preflight."""

    module_name: str
    provenance_approved: bool
    execution_supported: bool
    evidence_path: Literal["signature_and_hash", "hash_only"] | None
    rejection_reasons: tuple[str, ...]

    approved_candidate: CandidateOutcome | None
    candidates: tuple[CandidateOutcome, ...]
    required_modules_logged: tuple[str, ...]
    powershell_executable: str

    @property
    def can_execute(self) -> bool:
        """Both axes must pass for collection to proceed."""
        return self.provenance_approved and self.execution_supported

    def to_json_dict(self) -> dict[str, Any]:
        """Explicit JSON serialization for execution_metadata and preflight."""
        from dataclasses import asdict

        data = asdict(self)
        data["can_execute"] = self.can_execute
        return data


# ---------------------------------------------------------------------------
# Approval logic (spec Section 4.2 decision matrix)
# ---------------------------------------------------------------------------


def apply_approval_logic(
    *,
    candidates: list[CandidateOutcome] | tuple[CandidateOutcome, ...],
    policy: ModulePolicy,
    powershell_executable: str,
    required_modules_logged: tuple[str, ...],
) -> ModuleVerificationResult:
    """Apply the approval decision matrix from spec Section 4.2.

    Pure function: no I/O, no subprocess. Takes pre-evaluated candidates
    and returns the final ModuleVerificationResult.
    """
    candidates_tuple = tuple(candidates)

    def _result(
        *,
        provenance_approved: bool = False,
        execution_supported: bool = False,
        evidence_path: Literal["signature_and_hash", "hash_only"] | None = None,
        rejection_reasons: tuple[str, ...] = (),
        approved_candidate: CandidateOutcome | None = None,
    ) -> ModuleVerificationResult:
        return ModuleVerificationResult(
            module_name=policy.module_name,
            provenance_approved=provenance_approved,
            execution_supported=execution_supported,
            evidence_path=evidence_path,
            rejection_reasons=rejection_reasons,
            approved_candidate=approved_candidate,
            candidates=candidates_tuple,
            required_modules_logged=required_modules_logged,
            powershell_executable=powershell_executable,
        )

    if not candidates_tuple:
        return _result(rejection_reasons=("no_candidates",))

    can_execute = [c for c in candidates_tuple if c.provenance_approved and c.execution_supported]
    provenance_only = [c for c in candidates_tuple if c.provenance_approved]

    if len(can_execute) == 1:
        winner = can_execute[0]
        return _result(
            provenance_approved=True,
            execution_supported=True,
            evidence_path=winner.evidence_path,
            approved_candidate=winner,
        )

    if len(can_execute) > 1:
        return _result(execution_supported=True, rejection_reasons=("ambiguity",))

    if len(provenance_only) == 1:
        winner = provenance_only[0]
        return _result(
            provenance_approved=True,
            evidence_path=winner.evidence_path,
            approved_candidate=winner,
        )

    if len(provenance_only) > 1:
        return _result(rejection_reasons=("ambiguity",))

    return _result(rejection_reasons=("provenance_rejected",))


# ---------------------------------------------------------------------------
# Verification report JSON parsing
# ---------------------------------------------------------------------------


def parse_verification_report(report_path: Path) -> ModuleVerificationResult:
    """Parse a PowerShell verification report JSON into a ModuleVerificationResult.

    Raises VerificationInfrastructureError on missing/empty/malformed reports.
    """
    from gxassessms.core.contracts.errors import VerificationInfrastructureError

    try:
        text = report_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise VerificationInfrastructureError(
            f"Missing verification report: {report_path}",
            report_path=str(report_path),
        ) from None
    except OSError as exc:
        raise VerificationInfrastructureError(
            f"Cannot read verification report: {exc}",
            report_path=str(report_path),
        ) from exc

    if not text.strip():
        raise VerificationInfrastructureError(
            f"Empty verification report: {report_path}",
            report_path=str(report_path),
        )

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise VerificationInfrastructureError(
            f"Malformed JSON in verification report: {exc}",
            report_path=str(report_path),
        ) from exc

    try:
        return _parse_result(data)
    except (KeyError, TypeError) as exc:
        raise VerificationInfrastructureError(
            f"Missing required field in verification report: {exc}",
            report_path=str(report_path),
        ) from exc


def _parse_candidate(data: dict[str, Any]) -> CandidateOutcome:
    """Convert a raw candidate dict into a CandidateOutcome."""
    return CandidateOutcome(
        version=data["version"],
        live_manifest_path=data["live_manifest_path"],
        live_module_root=data["live_module_root"],
        staged_manifest_path=data.get("staged_manifest_path"),
        staged_module_root=data.get("staged_module_root"),
        provenance_approved=data["provenance_approved"],
        execution_supported=data["execution_supported"],
        rejection_reasons=tuple(data.get("rejection_reasons", ())),
        confinement_violation=data.get("confinement_violation"),
        package_hash=data.get("package_hash"),
        hash_approved=data.get("hash_approved", False),
        live_signature_status=data.get("live_signature_status"),
        live_signer_subject=data.get("live_signer_subject"),
        live_signer_issuer=data.get("live_signer_issuer"),
        live_signer_thumbprint=data.get("live_signer_thumbprint"),
        staged_signature_status=data.get("staged_signature_status"),
        staged_signer_subject=data.get("staged_signer_subject"),
        staged_signer_issuer=data.get("staged_signer_issuer"),
        staged_signer_thumbprint=data.get("staged_signer_thumbprint"),
        staged_signer_approved=data.get("staged_signer_approved"),
        evidence_path=data.get("evidence_path"),
    )


def _parse_result(data: dict[str, Any]) -> ModuleVerificationResult:
    """Convert a raw report dict into a ModuleVerificationResult."""
    approved = data.get("approved_candidate")
    candidates_raw = data.get("candidates", [])

    return ModuleVerificationResult(
        module_name=data["module_name"],
        provenance_approved=data["provenance_approved"],
        execution_supported=data["execution_supported"],
        evidence_path=data.get("evidence_path"),
        rejection_reasons=tuple(data.get("rejection_reasons", ())),
        approved_candidate=_parse_candidate(approved) if approved else None,
        candidates=tuple(_parse_candidate(c) for c in candidates_raw),
        required_modules_logged=tuple(data.get("required_modules_logged", ())),
        powershell_executable=data.get("powershell_executable", ""),
    )
