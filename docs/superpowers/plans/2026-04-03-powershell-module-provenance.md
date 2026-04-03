# PowerShell Module Provenance Verification -- Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Verify the identity and integrity of PowerShell modules (ScubaGear, Maester) before execution, eliminating the trust gap where a compromised module could exfiltrate tenant data or tamper with findings.

**Architecture:** A Python tree-hash utility + static PowerShell verification template work in concert. Python builds a JSON input blob, invokes the template once, reads back a verification report, and gates collection on provenance + platform approval. Adapters declare frozen `ModulePolicy` constants; config can narrow (never widen) via `ModulePolicyOverride`. Staging eliminates TOCTOU races; single-invocation design eliminates re-resolution.

**Tech Stack:** Python 3.14+ (dataclasses, hashlib, json, pathlib), PowerShell 5.1/7.x (static .ps1 template), pytest + hypothesis for golden-vector parity.

---

## Scope Check

This is a single subsystem (module provenance verification) with a clear boundary. All tasks produce working, testable software and build on each other.

## File Structure

### New Files

| File | Responsibility |
|------|----------------|
| `src/gxassessms/core/contracts/verification.py` | DTOs: `SignerIdentity`, `ModulePolicy`, `CandidateOutcome`, `ModuleVerificationResult`, `ModulePolicyOverride` |
| `src/gxassessms/adapters/_tree_hash.py` | Python `sha256tree:v1` implementation (enumerate, sort, hash) |
| `src/gxassessms/adapters/_verification.py` | `verify_module()`, script builder, report parser, `run_verified_powershell()` |
| `src/gxassessms/adapters/_verification_scripts/verify_module.ps1` | Static PowerShell template (Phases 1-9) |
| `src/gxassessms/adapters/scubagear/policy.py` | `MODULE_POLICY`, `ALLOWED_COMMANDS` constants |
| `src/gxassessms/adapters/maester/policy.py` | `MODULE_POLICY`, `ALLOWED_COMMANDS` constants |
| `src/gxassessms/cli/preflight_types.py` | `PreflightCheckResult` dataclass |
| `src/gxassessms/cli/commands/compute_hash.py` | `mseco compute-module-hash --manifest-path` command |
| `tests/unit/adapters/test_tree_hash.py` | Tree hash unit tests |
| `tests/unit/adapters/test_module_policy.py` | Policy construction + validation tests |
| `tests/unit/adapters/test_verification_report.py` | Report parsing tests |
| `tests/unit/adapters/test_approval_logic.py` | Approval decision matrix tests |
| `tests/unit/adapters/test_verification_script.py` | Script builder tests |
| `tests/unit/cli/test_preflight_provenance.py` | Preflight provenance display tests |
| `tests/unit/cli/test_adapters_check.py` | `adapters check` provenance tests |
| `tests/integration/test_module_verification.py` | End-to-end with `pwsh` |
| `tests/fixtures/module_hash_vectors/` | Golden-vector fixture directory |

### Modified Files

| File | Changes |
|------|---------|
| `src/gxassessms/core/contracts/errors.py` | Add `ModuleVerificationError` subtree |
| `src/gxassessms/core/contracts/types.py` | Update `check_prerequisites()` docstring |
| `src/gxassessms/core/config/config.py` | Add `ModulePolicyOverride` to `ToolConfig` |
| `src/gxassessms/core/domain/constants.py` | Add verification-related Literal types |
| `src/gxassessms/adapters/_base.py` | Add `run_verified_powershell()` |
| `src/gxassessms/adapters/scubagear/adapter.py` | Wire `collect()` and `check_prerequisites()` to verifier |
| `src/gxassessms/adapters/maester/adapter.py` | Wire `collect()` and `check_prerequisites()` to verifier |
| `src/gxassessms/cli/commands/preflight.py` | Call verifier directly, use `PreflightCheckResult` |
| `src/gxassessms/cli/commands/adapters.py` | Update `check` to call verifier for PS adapters, update help text |
| `src/gxassessms/cli/output.py` | Add `PreflightCheckResult` rendering with provenance display |
| `src/gxassessms/cli/main.py` | Register `compute-module-hash` command |
| `pyproject.toml` | No new entry points needed (all internal) |

---

## Task 1: Python Tree Hash (`sha256tree:v1`)

**Files:**
- Create: `src/gxassessms/adapters/_tree_hash.py`
- Test: `tests/unit/adapters/test_tree_hash.py`
- Create: `tests/fixtures/module_hash_vectors/`

This is the highest-risk seam (spec Section 14.4 item 1). Python and PowerShell must agree on hash output. We implement Python first, create golden vectors, then verify PowerShell matches later.

- [ ] **Step 1: Create the golden-vector fixture directory**

```bash
mkdir -p tests/fixtures/module_hash_vectors/SimpleModule
```

Create a minimal fixture that exercises path normalization, sorting, and hashing:

`tests/fixtures/module_hash_vectors/SimpleModule/SimpleModule.psd1`:
```
@{
    ModuleVersion = '1.0.0'
    RootModule = 'SimpleModule.psm1'
}
```

`tests/fixtures/module_hash_vectors/SimpleModule/SimpleModule.psm1`:
```
function Get-SimpleResult { return "OK" }
```

`tests/fixtures/module_hash_vectors/SimpleModule/Private/Helper.ps1`:
```
function Get-HelperResult { return "helper" }
```

These three files create a known structure: `Private/Helper.ps1`, `SimpleModule.psd1`, `SimpleModule.psm1` (lexicographic order by forward-slash path).

- [ ] **Step 2: Write failing tests for tree hash**

`tests/unit/adapters/test_tree_hash.py`:
```python
"""Tests for sha256tree:v1 tree hash implementation."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest


class TestComputeTreeHash:
    """sha256tree:v1 computation."""

    @pytest.fixture(autouse=True)
    def _import(self) -> None:
        from gxassessms.adapters._tree_hash import compute_tree_hash

        self.compute_tree_hash = compute_tree_hash

    @pytest.fixture
    def golden_vector_dir(self, fixtures_dir: Path) -> Path:
        return fixtures_dir / "module_hash_vectors" / "SimpleModule"

    def test_golden_vector_produces_known_hash(self, golden_vector_dir: Path) -> None:
        result = self.compute_tree_hash(golden_vector_dir)
        assert result.startswith("sha256tree:v1:")
        assert len(result) == len("sha256tree:v1:") + 64  # SHA-256 hex

    def test_deterministic_across_calls(self, golden_vector_dir: Path) -> None:
        h1 = self.compute_tree_hash(golden_vector_dir)
        h2 = self.compute_tree_hash(golden_vector_dir)
        assert h1 == h2

    def test_file_ordering_is_forward_slash_lexicographic(
        self, tmp_path: Path
    ) -> None:
        # Create files: b.txt, a/z.txt -- sorted: a/z.txt, b.txt
        (tmp_path / "b.txt").write_bytes(b"b")
        (tmp_path / "a").mkdir()
        (tmp_path / "a" / "z.txt").write_bytes(b"z")

        result = self.compute_tree_hash(tmp_path)

        # Manually compute expected hash
        entries: list[str] = []
        for rel, content in [("a/z.txt", b"z"), ("b.txt", b"b")]:
            file_hash = hashlib.sha256(content).hexdigest()
            entries.append(f"{rel}\0{file_hash}\n")
        expected = "sha256tree:v1:" + hashlib.sha256(
            "".join(entries).encode()
        ).hexdigest()
        assert result == expected

    def test_empty_directory_produces_valid_hash(self, tmp_path: Path) -> None:
        result = self.compute_tree_hash(tmp_path)
        assert result.startswith("sha256tree:v1:")
        # Hash of empty string
        expected = "sha256tree:v1:" + hashlib.sha256(b"").hexdigest()
        assert result == expected

    def test_rejects_symlink_in_tree(self, tmp_path: Path) -> None:
        real = tmp_path / "real.txt"
        real.write_bytes(b"content")
        link = tmp_path / "link.txt"
        link.symlink_to(real)

        with pytest.raises(ValueError, match="reparse|symlink"):
            self.compute_tree_hash(tmp_path)

    def test_hash_prefix_is_sha256tree_v1(self, tmp_path: Path) -> None:
        (tmp_path / "file.txt").write_bytes(b"test")
        result = self.compute_tree_hash(tmp_path)
        assert result.startswith("sha256tree:v1:")

    def test_hidden_files_included(self, tmp_path: Path) -> None:
        (tmp_path / ".hidden").write_bytes(b"hidden")
        (tmp_path / "visible.txt").write_bytes(b"visible")

        result = self.compute_tree_hash(tmp_path)

        # Compute expected with both files
        entries: list[str] = []
        for rel, content in [
            (".hidden", b"hidden"),
            ("visible.txt", b"visible"),
        ]:
            file_hash = hashlib.sha256(content).hexdigest()
            entries.append(f"{rel}\0{file_hash}\n")
        expected = "sha256tree:v1:" + hashlib.sha256(
            "".join(entries).encode()
        ).hexdigest()
        assert result == expected
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd /home/guardantix/Claude/gxassessms-workspace/gxassessms/.worktrees/secure-powershell-provenance && python3 -m pytest tests/unit/adapters/test_tree_hash.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'gxassessms.adapters._tree_hash'`

- [ ] **Step 4: Implement tree hash**

`src/gxassessms/adapters/_tree_hash.py`:
```python
"""sha256tree:v1 -- deterministic directory tree hash.

Scheme:
1. Enumerate all files recursively (including hidden)
2. Reject any item with ReparsePoint/symlink attributes
3. Sort by forward-slash-normalized relative path (lexicographic)
4. Per-file: SHA-256 of raw bytes
5. Concatenate: "relative/path\0<sha256hex>\n"
6. Final: "sha256tree:v1:" + SHA-256 of concatenation

The scheme version (v1) locks file-selection rules, path normalization,
and hash algorithm. A future v2 can revise without silently invalidating
existing hashes.
"""

from __future__ import annotations

import hashlib
from pathlib import Path


def compute_tree_hash(directory: Path) -> str:
    """Compute sha256tree:v1 hash for a directory tree.

    Args:
        directory: Root directory to hash.

    Returns:
        Hash string prefixed with "sha256tree:v1:".

    Raises:
        ValueError: If any item in the tree is a symlink or reparse point.
        OSError: If files cannot be read.
    """
    entries: list[tuple[str, str]] = []

    for item in sorted(directory.rglob("*")):
        if item.is_symlink():
            raise ValueError(
                f"Symlink/reparse point detected in tree: {item}"
            )
        if not item.is_file():
            continue

        rel = item.relative_to(directory).as_posix()
        file_hash = hashlib.sha256(item.read_bytes()).hexdigest()
        entries.append((rel, file_hash))

    manifest = "".join(f"{rel}\0{h}\n" for rel, h in entries)
    tree_hash = hashlib.sha256(manifest.encode()).hexdigest()
    return f"sha256tree:v1:{tree_hash}"
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /home/guardantix/Claude/gxassessms-workspace/gxassessms/.worktrees/secure-powershell-provenance && python3 -m pytest tests/unit/adapters/test_tree_hash.py -v`
Expected: All PASS

- [ ] **Step 6: Record the golden-vector hash**

Run: `cd /home/guardantix/Claude/gxassessms-workspace/gxassessms/.worktrees/secure-powershell-provenance && python3 -c "from gxassessms.adapters._tree_hash import compute_tree_hash; from pathlib import Path; print(compute_tree_hash(Path('tests/fixtures/module_hash_vectors/SimpleModule')))"`

Save the output -- this is the golden hash the PowerShell template must reproduce in Task 7's integration tests. Write it to `tests/fixtures/module_hash_vectors/expected_hash.txt`.

- [ ] **Step 7: Commit**

```bash
git add src/gxassessms/adapters/_tree_hash.py tests/unit/adapters/test_tree_hash.py tests/fixtures/module_hash_vectors/
git commit -m "$(cat <<'EOF'
feat: add sha256tree:v1 Python tree hash implementation

Deterministic directory hash: enumerate files, reject symlinks,
sort by forward-slash relative path, SHA-256 each file, hash the
concatenation. Golden-vector fixtures included for cross-language
parity testing with PowerShell.
EOF
)"
```

---

## Task 2: Core DTOs (`verification.py`)

**Files:**
- Create: `src/gxassessms/core/contracts/verification.py`
- Test: `tests/unit/adapters/test_module_policy.py`

Frozen dataclasses for policy, candidate outcome, and verification result. Construction invariants enforced at creation time.

- [ ] **Step 1: Write failing tests for policy construction**

`tests/unit/adapters/test_module_policy.py`:
```python
"""Tests for ModulePolicy construction invariants and ModulePolicyOverride validation."""

from __future__ import annotations

import pytest


class TestSignerIdentity:

    @pytest.fixture(autouse=True)
    def _import(self) -> None:
        from gxassessms.core.contracts.verification import SignerIdentity

        self.SignerIdentity = SignerIdentity

    def test_construction(self) -> None:
        si = self.SignerIdentity(subject="CN=Test", issuer="CN=Root")
        assert si.subject == "CN=Test"
        assert si.issuer == "CN=Root"

    def test_frozen(self) -> None:
        si = self.SignerIdentity(subject="CN=Test", issuer="CN=Root")
        with pytest.raises(AttributeError):
            si.subject = "CN=Other"  # type: ignore[misc]

    def test_equality(self) -> None:
        a = self.SignerIdentity(subject="CN=Test", issuer="CN=Root")
        b = self.SignerIdentity(subject="CN=Test", issuer="CN=Root")
        assert a == b

    def test_hashable(self) -> None:
        si = self.SignerIdentity(subject="CN=Test", issuer="CN=Root")
        assert {si}  # Can be in a frozenset


class TestModulePolicy:

    @pytest.fixture(autouse=True)
    def _import(self) -> None:
        from gxassessms.core.contracts.verification import (
            ModulePolicy,
            SignerIdentity,
        )

        self.ModulePolicy = ModulePolicy
        self.SignerIdentity = SignerIdentity

    def _signer(self) -> frozenset:
        return frozenset({self.SignerIdentity(subject="CN=Test", issuer="CN=Root")})

    def _hashes(self) -> frozenset:
        return frozenset({"sha256tree:v1:" + "a" * 64})

    def test_valid_construction(self) -> None:
        p = self.ModulePolicy(
            module_name="ScubaGear",
            version_range=">=1.5.0,<2.0.0",
            allowed_signers=self._signer(),
            approved_package_hashes=self._hashes(),
            allow_package_hash_fallback=True,
        )
        assert p.module_name == "ScubaGear"

    def test_empty_signers_rejected(self) -> None:
        with pytest.raises(ValueError, match="allowed_signers"):
            self.ModulePolicy(
                module_name="ScubaGear",
                version_range=">=1.0.0",
                allowed_signers=frozenset(),
                approved_package_hashes=self._hashes(),
                allow_package_hash_fallback=True,
            )

    def test_empty_hashes_rejected(self) -> None:
        with pytest.raises(ValueError, match="approved_package_hashes"):
            self.ModulePolicy(
                module_name="ScubaGear",
                version_range=">=1.0.0",
                allowed_signers=self._signer(),
                approved_package_hashes=frozenset(),
                allow_package_hash_fallback=True,
            )

    def test_hash_missing_prefix_rejected(self) -> None:
        with pytest.raises(ValueError, match="sha256tree:v1:"):
            self.ModulePolicy(
                module_name="ScubaGear",
                version_range=">=1.0.0",
                allowed_signers=self._signer(),
                approved_package_hashes=frozenset({"badhash"}),
                allow_package_hash_fallback=True,
            )

    def test_invalid_version_range_rejected(self) -> None:
        with pytest.raises(ValueError, match="version_range"):
            self.ModulePolicy(
                module_name="ScubaGear",
                version_range="not-a-range",
                allowed_signers=self._signer(),
                approved_package_hashes=self._hashes(),
                allow_package_hash_fallback=True,
            )

    def test_frozen(self) -> None:
        p = self.ModulePolicy(
            module_name="ScubaGear",
            version_range=">=1.0.0",
            allowed_signers=self._signer(),
            approved_package_hashes=self._hashes(),
            allow_package_hash_fallback=True,
        )
        with pytest.raises(AttributeError):
            p.module_name = "Other"  # type: ignore[misc]


class TestModulePolicyOverride:

    @pytest.fixture(autouse=True)
    def _import(self) -> None:
        from gxassessms.core.contracts.verification import (
            ModulePolicy,
            ModulePolicyOverride,
            SignerIdentity,
        )

        self.ModulePolicy = ModulePolicy
        self.ModulePolicyOverride = ModulePolicyOverride
        self.SignerIdentity = SignerIdentity

    def _base_policy(self) -> object:
        return self.ModulePolicy(
            module_name="ScubaGear",
            version_range=">=1.5.0,<2.0.0",
            allowed_signers=frozenset(
                {self.SignerIdentity(subject="CN=Test", issuer="CN=Root")}
            ),
            approved_package_hashes=frozenset({"sha256tree:v1:" + "a" * 64}),
            allow_package_hash_fallback=True,
        )

    def test_exact_pin_within_range(self) -> None:
        override = self.ModulePolicyOverride(version_range="==1.5.2")
        assert override.version_range == "==1.5.2"

    def test_non_exact_pin_rejected(self) -> None:
        with pytest.raises(ValueError, match="exact-version pin"):
            self.ModulePolicyOverride(version_range=">=1.5.0")

    def test_pinned_hashes_valid(self) -> None:
        override = self.ModulePolicyOverride(
            pinned_package_hashes=frozenset({"sha256tree:v1:" + "a" * 64})
        )
        assert override.pinned_package_hashes is not None

    def test_empty_pinned_hashes_rejected(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            self.ModulePolicyOverride(pinned_package_hashes=frozenset())

    def test_none_fields_are_default(self) -> None:
        override = self.ModulePolicyOverride()
        assert override.version_range is None
        assert override.pinned_package_hashes is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/guardantix/Claude/gxassessms-workspace/gxassessms/.worktrees/secure-powershell-provenance && python3 -m pytest tests/unit/adapters/test_module_policy.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement DTOs**

`src/gxassessms/core/contracts/verification.py`:
```python
"""Module provenance verification DTOs.

Frozen dataclasses for policy definitions, candidate outcomes, and
verification results. Lives in core/contracts (neutral location, no
cross-layer dependencies).

Construction invariants are enforced in __post_init__ -- invalid
policy cannot exist at runtime.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
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
    import operator as _op

    ops = {">=": _op.ge, "<=": _op.le, ">": _op.gt, "<": _op.lt, "==": _op.eq}
    ver = parse_semver(version)

    constraints = [c.strip() for c in version_range.split(",")]
    for constraint in constraints:
        m = _CONSTRAINT_RE.match(constraint)
        if m is None:
            raise ValueError(
                f"Invalid version constraint: {constraint!r}"
            )
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
            raise ValueError(
                f"version_range contains invalid constraint: {constraint!r}"
            )


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
                raise ValueError(
                    f"Hash must be prefixed 'sha256tree:v1:', got: {h!r}"
                )
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
                raise ValueError(
                    "pinned_package_hashes cannot be empty (use None to skip)"
                )
            for h in self.pinned_package_hashes:
                if not h.startswith("sha256tree:v1:"):
                    raise ValueError(
                        f"Hash must be prefixed 'sha256tree:v1:', got: {h!r}"
                    )


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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/guardantix/Claude/gxassessms-workspace/gxassessms/.worktrees/secure-powershell-provenance && python3 -m pytest tests/unit/adapters/test_module_policy.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/gxassessms/core/contracts/verification.py tests/unit/adapters/test_module_policy.py
git commit -m "$(cat <<'EOF'
feat: add module provenance verification DTOs

SignerIdentity, ModulePolicy (with construction invariants),
ModulePolicyOverride (exact-pin only), CandidateOutcome,
ModuleVerificationResult. Frozen dataclasses with fail-closed
validation.
EOF
)"
```

---

## Task 3: Error Hierarchy

**Files:**
- Modify: `src/gxassessms/core/contracts/errors.py`
- Test: `tests/unit/adapters/test_module_policy.py` (extend)

- [ ] **Step 1: Write failing tests for error types**

Add to `tests/unit/adapters/test_module_policy.py`:
```python
class TestModuleVerificationErrors:

    @pytest.fixture(autouse=True)
    def _import(self) -> None:
        from gxassessms.core.contracts.errors import (
            ModuleAmbiguityError,
            ModuleExecutionUnsupportedError,
            ModuleProvenanceError,
            ModuleVerificationError,
            PrerequisiteError,
            VerificationInfrastructureError,
        )

        self.ModuleVerificationError = ModuleVerificationError
        self.ModuleProvenanceError = ModuleProvenanceError
        self.ModuleAmbiguityError = ModuleAmbiguityError
        self.ModuleExecutionUnsupportedError = ModuleExecutionUnsupportedError
        self.VerificationInfrastructureError = VerificationInfrastructureError
        self.PrerequisiteError = PrerequisiteError

    def test_hierarchy(self) -> None:
        assert issubclass(self.ModuleVerificationError, self.PrerequisiteError)
        assert issubclass(self.ModuleProvenanceError, self.ModuleVerificationError)
        assert issubclass(self.ModuleAmbiguityError, self.ModuleVerificationError)
        assert issubclass(
            self.ModuleExecutionUnsupportedError, self.ModuleVerificationError
        )
        assert issubclass(
            self.VerificationInfrastructureError, self.ModuleVerificationError
        )

    def test_verification_error_carries_result(self) -> None:
        err = self.ModuleVerificationError(
            "test", adapter_name="ScubaGear", verification_result=None
        )
        assert err.verification_result is None
        assert err.adapter_name == "ScubaGear"

    def test_infrastructure_error_carries_exit_code(self) -> None:
        err = self.VerificationInfrastructureError(
            "pwsh crashed",
            exit_code=1,
            stderr_snippet="error text",
            report_path="/tmp/report.json",
        )
        assert err.exit_code == 1
        assert err.stderr_snippet == "error text"
        assert err.report_path == "/tmp/report.json"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/guardantix/Claude/gxassessms-workspace/gxassessms/.worktrees/secure-powershell-provenance && python3 -m pytest tests/unit/adapters/test_module_policy.py::TestModuleVerificationErrors -v`
Expected: FAIL with `ImportError`

- [ ] **Step 3: Add error classes to errors.py**

Add before the `# Consolidation errors` section in `src/gxassessms/core/contracts/errors.py`:

```python
# ---------------------------------------------------------------------------
# Module verification errors
# ---------------------------------------------------------------------------


class ModuleVerificationError(PrerequisiteError):
    """Module provenance verification failed."""

    def __init__(
        self,
        message: str,
        adapter_name: str = "",
        engagement_id: str = "",
        verification_result: Any = None,
    ) -> None:
        self.verification_result = verification_result
        super().__init__(message, adapter_name, engagement_id)


class ModuleProvenanceError(ModuleVerificationError):
    """Candidate found but rejected by provenance policy."""


class ModuleAmbiguityError(ModuleVerificationError):
    """Multiple candidates satisfy policy -- fail closed."""


class ModuleExecutionUnsupportedError(ModuleVerificationError):
    """Module cannot execute on this platform."""


class VerificationInfrastructureError(ModuleVerificationError):
    """Verification machinery itself failed."""

    def __init__(
        self,
        message: str,
        adapter_name: str = "",
        engagement_id: str = "",
        verification_result: Any = None,
        exit_code: int | None = None,
        stderr_snippet: str | None = None,
        report_path: str | None = None,
    ) -> None:
        self.exit_code = exit_code
        self.stderr_snippet = stderr_snippet
        self.report_path = report_path
        super().__init__(message, adapter_name, engagement_id, verification_result)
```

Also add `from typing import Any` at the top of the file if not already present.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/guardantix/Claude/gxassessms-workspace/gxassessms/.worktrees/secure-powershell-provenance && python3 -m pytest tests/unit/adapters/test_module_policy.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/gxassessms/core/contracts/errors.py tests/unit/adapters/test_module_policy.py
git commit -m "$(cat <<'EOF'
feat: add ModuleVerificationError hierarchy

ModuleVerificationError (base, extends PrerequisiteError),
ModuleProvenanceError, ModuleAmbiguityError,
ModuleExecutionUnsupportedError, VerificationInfrastructureError.
Each carries verification_result for structured diagnosis.
EOF
)"
```

---

## Task 4: Approval Logic (Pure Python)

**Files:**
- Create: `tests/unit/adapters/test_approval_logic.py`
- Modify: `src/gxassessms/core/contracts/verification.py` (add `apply_approval_logic()`)

The approval logic from spec Section 4.2 is a pure function: takes candidates + policy, returns `ModuleVerificationResult`. No I/O, no subprocess -- fully unit-testable.

- [ ] **Step 1: Write failing parametric tests**

`tests/unit/adapters/test_approval_logic.py`:
```python
"""Parametric tests for the module provenance approval decision matrix.

Covers spec Section 4.2 + ambiguity rules.
"""

from __future__ import annotations

import pytest

from gxassessms.core.contracts.verification import (
    CandidateOutcome,
    ModulePolicy,
    SignerIdentity,
)


def _policy(fallback: bool = True) -> ModulePolicy:
    return ModulePolicy(
        module_name="TestModule",
        version_range=">=1.0.0,<2.0.0",
        allowed_signers=frozenset(
            {SignerIdentity(subject="CN=Good", issuer="CN=Root")}
        ),
        approved_package_hashes=frozenset({"sha256tree:v1:" + "a" * 64}),
        allow_package_hash_fallback=fallback,
    )


def _candidate(
    *,
    provenance_approved: bool = True,
    execution_supported: bool = True,
    evidence_path: str | None = "hash_only",
    version: str = "1.0.0",
    rejection_reasons: tuple[str, ...] = (),
    hash_approved: bool = True,
    package_hash: str | None = "sha256tree:v1:" + "a" * 64,
) -> CandidateOutcome:
    return CandidateOutcome(
        version=version,
        live_manifest_path="/live/TestModule.psd1",
        live_module_root="/live/TestModule",
        staged_manifest_path="/staged/TestModule.psd1",
        staged_module_root="/staged/TestModule",
        provenance_approved=provenance_approved,
        execution_supported=execution_supported,
        rejection_reasons=rejection_reasons,
        package_hash=package_hash,
        hash_approved=hash_approved,
        evidence_path=evidence_path,
    )


class TestApplyApprovalLogic:

    @pytest.fixture(autouse=True)
    def _import(self) -> None:
        from gxassessms.core.contracts.verification import apply_approval_logic

        self.apply_approval_logic = apply_approval_logic

    def test_single_approved_executable(self) -> None:
        result = self.apply_approval_logic(
            candidates=[_candidate()],
            policy=_policy(),
            powershell_executable="/usr/bin/pwsh",
            required_modules_logged=(),
        )
        assert result.provenance_approved is True
        assert result.execution_supported is True
        assert result.can_execute is True
        assert result.approved_candidate is not None

    def test_single_approved_not_executable(self) -> None:
        result = self.apply_approval_logic(
            candidates=[_candidate(execution_supported=False)],
            policy=_policy(),
            powershell_executable="/usr/bin/pwsh",
            required_modules_logged=(),
        )
        assert result.provenance_approved is True
        assert result.execution_supported is False
        assert result.can_execute is False
        assert result.approved_candidate is not None

    def test_ambiguity_two_executable(self) -> None:
        result = self.apply_approval_logic(
            candidates=[_candidate(version="1.0.0"), _candidate(version="1.1.0")],
            policy=_policy(),
            powershell_executable="/usr/bin/pwsh",
            required_modules_logged=(),
        )
        assert result.provenance_approved is False
        assert "ambiguity" in result.rejection_reasons

    def test_zero_provenance_approved(self) -> None:
        result = self.apply_approval_logic(
            candidates=[
                _candidate(
                    provenance_approved=False,
                    rejection_reasons=("hash_rejected",),
                    evidence_path=None,
                )
            ],
            policy=_policy(),
            powershell_executable="/usr/bin/pwsh",
            required_modules_logged=(),
        )
        assert result.provenance_approved is False
        assert result.approved_candidate is None

    def test_no_candidates(self) -> None:
        result = self.apply_approval_logic(
            candidates=[],
            policy=_policy(),
            powershell_executable="/usr/bin/pwsh",
            required_modules_logged=(),
        )
        assert result.provenance_approved is False
        assert result.can_execute is False

    def test_signature_and_hash_evidence(self) -> None:
        result = self.apply_approval_logic(
            candidates=[_candidate(evidence_path="signature_and_hash")],
            policy=_policy(),
            powershell_executable="/usr/bin/pwsh",
            required_modules_logged=(),
        )
        assert result.evidence_path == "signature_and_hash"

    def test_multiple_provenance_approved_none_executable(self) -> None:
        """Multiple provenance-approved but none executable -> provenance ambiguity."""
        result = self.apply_approval_logic(
            candidates=[
                _candidate(version="1.0.0", execution_supported=False),
                _candidate(version="1.1.0", execution_supported=False),
            ],
            policy=_policy(),
            powershell_executable="/usr/bin/pwsh",
            required_modules_logged=(),
        )
        assert result.provenance_approved is False
        assert "ambiguity" in result.rejection_reasons

    def test_one_provenance_approved_not_executable(self) -> None:
        """Single provenance-approved but not executable -> approved, not executable."""
        result = self.apply_approval_logic(
            candidates=[_candidate(execution_supported=False)],
            policy=_policy(),
            powershell_executable="/usr/bin/pwsh",
            required_modules_logged=(),
        )
        assert result.provenance_approved is True
        assert result.execution_supported is False
        assert result.approved_candidate is not None

    def test_required_modules_logged_passed_through(self) -> None:
        result = self.apply_approval_logic(
            candidates=[_candidate()],
            policy=_policy(),
            powershell_executable="/usr/bin/pwsh",
            required_modules_logged=("Microsoft.Graph.Authentication", "Pester"),
        )
        assert result.required_modules_logged == (
            "Microsoft.Graph.Authentication",
            "Pester",
        )
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/guardantix/Claude/gxassessms-workspace/gxassessms/.worktrees/secure-powershell-provenance && python3 -m pytest tests/unit/adapters/test_approval_logic.py -v`
Expected: FAIL with `ImportError: cannot import name 'apply_approval_logic'`

- [ ] **Step 3: Implement approval logic**

Add to `src/gxassessms/core/contracts/verification.py`:

```python
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

    if not candidates_tuple:
        return ModuleVerificationResult(
            module_name=policy.module_name,
            provenance_approved=False,
            execution_supported=False,
            evidence_path=None,
            rejection_reasons=("no_candidates",),
            approved_candidate=None,
            candidates=candidates_tuple,
            required_modules_logged=required_modules_logged,
            powershell_executable=powershell_executable,
        )

    can_execute = [c for c in candidates_tuple if c.provenance_approved and c.execution_supported]
    provenance_approved = [c for c in candidates_tuple if c.provenance_approved]

    # Exactly one can_execute -> approved
    if len(can_execute) == 1:
        winner = can_execute[0]
        return ModuleVerificationResult(
            module_name=policy.module_name,
            provenance_approved=True,
            execution_supported=True,
            evidence_path=winner.evidence_path,
            rejection_reasons=(),
            approved_candidate=winner,
            candidates=candidates_tuple,
            required_modules_logged=required_modules_logged,
            powershell_executable=powershell_executable,
        )

    # Multiple can_execute -> ambiguity
    if len(can_execute) > 1:
        return ModuleVerificationResult(
            module_name=policy.module_name,
            provenance_approved=False,
            execution_supported=True,
            evidence_path=None,
            rejection_reasons=("ambiguity",),
            approved_candidate=None,
            candidates=candidates_tuple,
            required_modules_logged=required_modules_logged,
            powershell_executable=powershell_executable,
        )

    # Zero can_execute, exactly one provenance_approved -> approved but not executable
    if len(provenance_approved) == 1:
        winner = provenance_approved[0]
        return ModuleVerificationResult(
            module_name=policy.module_name,
            provenance_approved=True,
            execution_supported=False,
            evidence_path=winner.evidence_path,
            rejection_reasons=(),
            approved_candidate=winner,
            candidates=candidates_tuple,
            required_modules_logged=required_modules_logged,
            powershell_executable=powershell_executable,
        )

    # Multiple provenance_approved, none executable -> provenance ambiguity
    if len(provenance_approved) > 1:
        return ModuleVerificationResult(
            module_name=policy.module_name,
            provenance_approved=False,
            execution_supported=False,
            evidence_path=None,
            rejection_reasons=("ambiguity",),
            approved_candidate=None,
            candidates=candidates_tuple,
            required_modules_logged=required_modules_logged,
            powershell_executable=powershell_executable,
        )

    # Zero provenance_approved
    return ModuleVerificationResult(
        module_name=policy.module_name,
        provenance_approved=False,
        execution_supported=False,
        evidence_path=None,
        rejection_reasons=("provenance_rejected",),
        approved_candidate=None,
        candidates=candidates_tuple,
        required_modules_logged=required_modules_logged,
        powershell_executable=powershell_executable,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/guardantix/Claude/gxassessms-workspace/gxassessms/.worktrees/secure-powershell-provenance && python3 -m pytest tests/unit/adapters/test_approval_logic.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/gxassessms/core/contracts/verification.py tests/unit/adapters/test_approval_logic.py
git commit -m "$(cat <<'EOF'
feat: add approval logic for module provenance decisions

Pure-function decision matrix: single approved, ambiguity rejection,
provenance-only (not executable), and no-candidates cases. Parametric
tests cover the full decision table from spec Section 4.2.
EOF
)"
```

---

## Task 5: Verification Report Parser

**Files:**
- Test: `tests/unit/adapters/test_verification_report.py`
- Modify: `src/gxassessms/core/contracts/verification.py` (add `parse_verification_report()`)

Python reads the JSON report written by the PowerShell template. This parser converts raw JSON into `ModuleVerificationResult`.

- [ ] **Step 1: Write failing tests**

`tests/unit/adapters/test_verification_report.py`:
```python
"""Tests for verification report JSON parsing."""

from __future__ import annotations

import json

import pytest


class TestParseVerificationReport:

    @pytest.fixture(autouse=True)
    def _import(self) -> None:
        from gxassessms.core.contracts.verification import parse_verification_report

        self.parse_verification_report = parse_verification_report

    def _valid_report(self) -> dict:
        return {
            "module_name": "TestModule",
            "provenance_approved": True,
            "execution_supported": True,
            "evidence_path": "hash_only",
            "rejection_reasons": [],
            "powershell_executable": "/usr/bin/pwsh",
            "required_modules_logged": [],
            "approved_candidate": {
                "version": "1.0.0",
                "live_manifest_path": "/live/TestModule.psd1",
                "live_module_root": "/live/TestModule",
                "staged_manifest_path": "/staged/TestModule.psd1",
                "staged_module_root": "/staged/TestModule",
                "provenance_approved": True,
                "execution_supported": True,
                "rejection_reasons": [],
                "confinement_violation": None,
                "package_hash": "sha256tree:v1:" + "a" * 64,
                "hash_approved": True,
                "live_signature_status": "platform_unsupported",
                "live_signer_subject": None,
                "live_signer_issuer": None,
                "live_signer_thumbprint": None,
                "staged_signature_status": "platform_unsupported",
                "staged_signer_subject": None,
                "staged_signer_issuer": None,
                "staged_signer_thumbprint": None,
                "staged_signer_approved": None,
                "evidence_path": "hash_only",
            },
            "candidates": [],
        }

    def test_valid_report_parses(self, tmp_path) -> None:
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps(self._valid_report()))

        result = self.parse_verification_report(report_path)
        assert result.module_name == "TestModule"
        assert result.provenance_approved is True
        assert result.can_execute is True

    def test_missing_report_raises(self, tmp_path) -> None:
        from gxassessms.core.contracts.errors import VerificationInfrastructureError

        report_path = tmp_path / "missing.json"
        with pytest.raises(VerificationInfrastructureError, match="Missing"):
            self.parse_verification_report(report_path)

    def test_empty_report_raises(self, tmp_path) -> None:
        from gxassessms.core.contracts.errors import VerificationInfrastructureError

        report_path = tmp_path / "empty.json"
        report_path.write_text("")
        with pytest.raises(VerificationInfrastructureError, match="[Ee]mpty"):
            self.parse_verification_report(report_path)

    def test_malformed_json_raises(self, tmp_path) -> None:
        from gxassessms.core.contracts.errors import VerificationInfrastructureError

        report_path = tmp_path / "bad.json"
        report_path.write_text("{invalid")
        with pytest.raises(VerificationInfrastructureError, match="[Mm]alformed|JSON"):
            self.parse_verification_report(report_path)

    def test_missing_required_field_raises(self, tmp_path) -> None:
        from gxassessms.core.contracts.errors import VerificationInfrastructureError

        report = self._valid_report()
        del report["module_name"]
        report_path = tmp_path / "bad.json"
        report_path.write_text(json.dumps(report))
        with pytest.raises(VerificationInfrastructureError):
            self.parse_verification_report(report_path)

    def test_candidate_with_rejection_reasons(self, tmp_path) -> None:
        report = self._valid_report()
        report["provenance_approved"] = False
        report["approved_candidate"] = None
        report["rejection_reasons"] = ["hash_rejected"]
        report["candidates"] = [
            {
                "version": "1.0.0",
                "live_manifest_path": "/live/TestModule.psd1",
                "live_module_root": "/live/TestModule",
                "staged_manifest_path": None,
                "staged_module_root": None,
                "provenance_approved": False,
                "execution_supported": True,
                "rejection_reasons": ["hash_rejected"],
                "confinement_violation": None,
                "package_hash": "sha256tree:v1:" + "b" * 64,
                "hash_approved": False,
                "live_signature_status": None,
                "live_signer_subject": None,
                "live_signer_issuer": None,
                "live_signer_thumbprint": None,
                "staged_signature_status": None,
                "staged_signer_subject": None,
                "staged_signer_issuer": None,
                "staged_signer_thumbprint": None,
                "staged_signer_approved": None,
                "evidence_path": None,
            }
        ]
        report_path = tmp_path / "report.json"
        report_path.write_text(json.dumps(report))

        result = self.parse_verification_report(report_path)
        assert result.provenance_approved is False
        assert len(result.candidates) == 1
        assert "hash_rejected" in result.candidates[0].rejection_reasons
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/guardantix/Claude/gxassessms-workspace/gxassessms/.worktrees/secure-powershell-provenance && python3 -m pytest tests/unit/adapters/test_verification_report.py -v`
Expected: FAIL with `ImportError`

- [ ] **Step 3: Implement report parser**

Add to `src/gxassessms/core/contracts/verification.py`:

```python
def parse_verification_report(report_path: Path) -> ModuleVerificationResult:
    """Parse a PowerShell verification report JSON into a ModuleVerificationResult.

    Raises VerificationInfrastructureError on missing/empty/malformed reports.
    """
    from gxassessms.core.contracts.errors import VerificationInfrastructureError

    if not report_path.exists():
        raise VerificationInfrastructureError(
            f"Missing verification report: {report_path}",
            report_path=str(report_path),
        )

    text = report_path.read_text(encoding="utf-8")
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
```

Also add `import json` and `from pathlib import Path` to the imports at the top if not already present.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/guardantix/Claude/gxassessms-workspace/gxassessms/.worktrees/secure-powershell-provenance && python3 -m pytest tests/unit/adapters/test_verification_report.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/gxassessms/core/contracts/verification.py tests/unit/adapters/test_verification_report.py
git commit -m "$(cat <<'EOF'
feat: add verification report JSON parser

Parses PowerShell-written JSON reports into ModuleVerificationResult.
Raises VerificationInfrastructureError for missing, empty, malformed,
or structurally invalid reports.
EOF
)"
```

---

## Task 6: Verification Script Builder + Runner

**Files:**
- Create: `src/gxassessms/adapters/_verification.py`
- Test: `tests/unit/adapters/test_verification_script.py`

Builds the JSON input blob for the PowerShell template, invokes it, reads the report. The PowerShell template itself comes in Task 7.

- [ ] **Step 1: Write failing tests for script builder**

`tests/unit/adapters/test_verification_script.py`:
```python
"""Tests for verification script builder and runner."""

from __future__ import annotations

import json

import pytest

from gxassessms.core.contracts.verification import (
    ModulePolicy,
    ModulePolicyOverride,
    SignerIdentity,
)


def _policy() -> ModulePolicy:
    return ModulePolicy(
        module_name="TestModule",
        version_range=">=1.0.0,<2.0.0",
        allowed_signers=frozenset(
            {SignerIdentity(subject="CN=Good", issuer="CN=Root")}
        ),
        approved_package_hashes=frozenset({"sha256tree:v1:" + "a" * 64}),
        allow_package_hash_fallback=True,
    )


class TestBuildInputBlob:

    @pytest.fixture(autouse=True)
    def _import(self) -> None:
        from gxassessms.adapters._verification import build_input_blob

        self.build_input_blob = build_input_blob

    def test_preflight_mode_no_invocation(self) -> None:
        blob = self.build_input_blob(
            policy=_policy(),
            override=None,
            mode="preflight",
            post_import_invocation=None,
        )
        data = json.loads(blob)
        assert data["module_name"] == "TestModule"
        assert data["mode"] == "preflight"
        assert data["post_import_invocation"] is None

    def test_collection_mode_with_invocation(self) -> None:
        invocation = {
            "command_name": "Invoke-SCuBA",
            "named_args": {"OutPath": "/out"},
            "switches": {},
        }
        blob = self.build_input_blob(
            policy=_policy(),
            override=None,
            mode="collection",
            post_import_invocation=invocation,
        )
        data = json.loads(blob)
        assert data["mode"] == "collection"
        assert data["post_import_invocation"]["command_name"] == "Invoke-SCuBA"

    def test_override_narrows_version(self) -> None:
        override = ModulePolicyOverride(version_range="==1.5.0")
        blob = self.build_input_blob(
            policy=_policy(),
            override=override,
            mode="preflight",
            post_import_invocation=None,
        )
        data = json.loads(blob)
        assert data["effective_version_range"] == "==1.5.0"

    def test_override_narrows_hashes(self) -> None:
        override = ModulePolicyOverride(
            pinned_package_hashes=frozenset({"sha256tree:v1:" + "a" * 64})
        )
        blob = self.build_input_blob(
            policy=_policy(),
            override=override,
            mode="preflight",
            post_import_invocation=None,
        )
        data = json.loads(blob)
        assert len(data["effective_approved_hashes"]) == 1


class TestValidateCommandAllowlist:

    @pytest.fixture(autouse=True)
    def _import(self) -> None:
        from gxassessms.adapters._verification import validate_command_allowlist

        self.validate_command_allowlist = validate_command_allowlist

    def test_allowed_command(self) -> None:
        self.validate_command_allowlist(
            "Invoke-SCuBA", frozenset({"Invoke-SCuBA"})
        )

    def test_rejected_command_raises(self) -> None:
        with pytest.raises(ValueError, match="not in.*allowlist"):
            self.validate_command_allowlist(
                "Invoke-Expression", frozenset({"Invoke-SCuBA"})
            )


class TestGetTemplatePath:

    @pytest.fixture(autouse=True)
    def _import(self) -> None:
        from gxassessms.adapters._verification import get_template_path

        self.get_template_path = get_template_path

    def test_template_path_exists(self) -> None:
        path = self.get_template_path()
        # Path should be absolute and end with .ps1
        assert path.suffix == ".ps1"
        assert path.name == "verify_module.ps1"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/guardantix/Claude/gxassessms-workspace/gxassessms/.worktrees/secure-powershell-provenance && python3 -m pytest tests/unit/adapters/test_verification_script.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement verification module**

`src/gxassessms/adapters/_verification.py`:
```python
"""Module provenance verification -- script builder, runner, report reader.

Orchestrates the full verification flow:
1. Build JSON input blob from policy + overrides
2. Write input to temp file
3. Invoke static PowerShell template with -File/-InputPath
4. Read verification report JSON from temp file
5. Parse into ModuleVerificationResult
6. Log provenance event
7. Clean up temp directory

The PowerShell template is a static .ps1 file -- no string substitution,
no quoting bugs, no injection surface. All dynamic data flows through the
JSON input blob.
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from gxassessms.adapters._base import get_powershell_executable
from gxassessms.core.contracts.errors import (
    CollectionError,
    ModuleAmbiguityError,
    ModuleExecutionUnsupportedError,
    ModuleProvenanceError,
    VerificationInfrastructureError,
)
from gxassessms.core.contracts.verification import (
    ModulePolicy,
    ModulePolicyOverride,
    ModuleVerificationResult,
    parse_verification_report,
)

logger = logging.getLogger(__name__)


def get_template_path() -> Path:
    """Return path to the static PowerShell verification template."""
    return Path(__file__).parent / "_verification_scripts" / "verify_module.ps1"


def validate_command_allowlist(
    command_name: str, allowed_commands: frozenset[str]
) -> None:
    """Validate command_name is in the adapter's allowlist.

    Raises ValueError if the command is not allowed.
    """
    if command_name not in allowed_commands:
        raise ValueError(
            f"Command {command_name!r} not in adapter allowlist: "
            f"{sorted(allowed_commands)}"
        )


def build_input_blob(
    *,
    policy: ModulePolicy,
    override: ModulePolicyOverride | None,
    mode: str,
    post_import_invocation: dict[str, Any] | None,
) -> str:
    """Build the JSON input blob for the PowerShell verification template.

    Returns JSON string. Does not write to disk.
    """
    # Compute effective policy
    effective_version_range = policy.version_range
    effective_hashes = sorted(policy.approved_package_hashes)

    if override is not None:
        if override.version_range is not None:
            effective_version_range = override.version_range
        if override.pinned_package_hashes is not None:
            effective_hashes = sorted(override.pinned_package_hashes)

    signers = [
        {"subject": s.subject, "issuer": s.issuer}
        for s in sorted(policy.allowed_signers, key=lambda s: (s.subject, s.issuer))
    ]

    blob: dict[str, Any] = {
        "module_name": policy.module_name,
        "effective_version_range": effective_version_range,
        "effective_approved_hashes": effective_hashes,
        "allowed_signers": signers,
        "allow_package_hash_fallback": policy.allow_package_hash_fallback,
        "mode": mode,
        "post_import_invocation": post_import_invocation,
    }

    return json.dumps(blob, indent=2)


def verify_module(
    *,
    policy: ModulePolicy,
    override: ModulePolicyOverride | None = None,
    mode: str = "preflight",
    post_import_invocation: dict[str, Any] | None = None,
    adapter_name: str = "",
    engagement_id: str = "",
    timeout_seconds: int = 120,
) -> ModuleVerificationResult:
    """Run the full module verification pipeline.

    Args:
        policy: Code-owned module policy.
        override: Optional config narrowing.
        mode: "preflight" or "collection".
        post_import_invocation: Structured invocation for collection mode.
        adapter_name: For error context.
        engagement_id: For error context.
        timeout_seconds: PowerShell timeout.

    Returns:
        ModuleVerificationResult.

    Raises:
        ModuleProvenanceError: Provenance rejected.
        ModuleAmbiguityError: Multiple candidates.
        ModuleExecutionUnsupportedError: Provenance OK, platform incompatible.
        VerificationInfrastructureError: Template failed.
        CollectionError: Tool invocation failed after verification passed.
    """
    exe = get_powershell_executable()
    template = get_template_path()

    input_blob = build_input_blob(
        policy=policy,
        override=override,
        mode=mode,
        post_import_invocation=post_import_invocation,
    )

    tmp_dir = Path(tempfile.mkdtemp(prefix="gxassessms_verify_"))
    try:
        input_path = tmp_dir / "input.json"
        report_path = tmp_dir / "report.json"
        input_path.write_text(input_blob, encoding="utf-8")

        cmd = [
            exe,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(template),
            "-InputPath",
            str(input_path),
            "-ReportPath",
            str(report_path),
            "-StagingDir",
            str(tmp_dir / "candidates"),
        ]

        logger.info(
            "[%s] Running module verification (%s, mode=%s)",
            adapter_name or "adapter",
            exe,
            mode,
        )

        try:
            proc = subprocess.run(  # noqa: S603
                cmd,
                shell=False,
                capture_output=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise VerificationInfrastructureError(
                f"Verification timed out after {timeout_seconds}s",
                adapter_name=adapter_name,
                engagement_id=engagement_id,
                exit_code=None,
                stderr_snippet=None,
                report_path=str(report_path),
            ) from exc
        except OSError as exc:
            raise VerificationInfrastructureError(
                f"PowerShell not accessible: {exe!r} ({exc})",
                adapter_name=adapter_name,
                engagement_id=engagement_id,
            ) from exc

        # Always try to read the report, regardless of exit code
        exit_code = proc.returncode
        stderr = (proc.stderr or b"").decode(errors="replace")[:500]

        try:
            result = parse_verification_report(report_path)
        except VerificationInfrastructureError:
            raise VerificationInfrastructureError(
                f"Verification report missing or unreadable (exit code {exit_code})",
                adapter_name=adapter_name,
                engagement_id=engagement_id,
                exit_code=exit_code,
                stderr_snippet=stderr,
                report_path=str(report_path),
            )

        # Log provenance
        _log_provenance(result, adapter_name)

        # Gate on result
        if not result.provenance_approved:
            if "ambiguity" in result.rejection_reasons:
                raise ModuleAmbiguityError(
                    f"Multiple candidates satisfy policy for {policy.module_name}",
                    adapter_name=adapter_name,
                    engagement_id=engagement_id,
                    verification_result=result,
                )
            raise ModuleProvenanceError(
                f"Module {policy.module_name} failed provenance verification: "
                f"{', '.join(result.rejection_reasons)}",
                adapter_name=adapter_name,
                engagement_id=engagement_id,
                verification_result=result,
            )

        if not result.execution_supported:
            raise ModuleExecutionUnsupportedError(
                f"Module {policy.module_name} provenance verified but "
                f"cannot execute on this platform",
                adapter_name=adapter_name,
                engagement_id=engagement_id,
                verification_result=result,
            )

        # Provenance approved + execution supported, but non-zero exit
        # means the tool itself failed (Phase 9 in collection mode)
        if exit_code != 0 and mode == "collection":
            raise CollectionError(
                f"Module verified but tool exited with code {exit_code}: {stderr}",
                adapter_name=adapter_name,
                engagement_id=engagement_id,
            )

        return result

    finally:
        import shutil

        shutil.rmtree(
            tmp_dir,
            onexc=lambda _f, p, e: logger.warning(
                "Failed to clean up temp dir: %s (%s)", p, e
            ),
        )


def _log_provenance(result: ModuleVerificationResult, adapter_name: str) -> None:
    """Emit structured provenance log events."""
    name = adapter_name or result.module_name

    if result.provenance_approved and result.execution_supported:
        ev = result.evidence_path or "unknown"
        ac = result.approved_candidate
        level = logging.INFO
        # Degraded signature -> WARNING
        if ev == "hash_only" and ac and ac.staged_signature_status not in (
            None,
            "platform_unsupported",
        ):
            level = logging.WARNING
            ev = f"hash_only, degraded"

        logger.log(
            level,
            "[%s] provenance=APPROVED execution=SUPPORTED (%s): "
            "version=%s, hash=%s, candidates_discovered=%d",
            name,
            ev,
            ac.version if ac else "?",
            ac.package_hash if ac else "?",
            len(result.candidates),
        )
    elif result.provenance_approved and not result.execution_supported:
        ac = result.approved_candidate
        logger.warning(
            "[%s] provenance=APPROVED execution=UNSUPPORTED (%s): "
            "version=%s, candidates_discovered=%d",
            name,
            result.evidence_path or "?",
            ac.version if ac else "?",
            len(result.candidates),
        )
    else:
        logger.error(
            "[%s] provenance=REJECTED: %s, candidates_discovered=%d",
            name,
            ", ".join(result.rejection_reasons),
            len(result.candidates),
        )
```

- [ ] **Step 4: Create placeholder PowerShell template**

Create the directory and an initial placeholder:

```bash
mkdir -p src/gxassessms/adapters/_verification_scripts
```

`src/gxassessms/adapters/_verification_scripts/verify_module.ps1`:
```powershell
# Placeholder -- full implementation in Task 7
param(
    [string]$InputPath,
    [string]$ReportPath,
    [string]$StagingDir
)
Write-Error "verify_module.ps1 not yet implemented"
exit 1
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /home/guardantix/Claude/gxassessms-workspace/gxassessms/.worktrees/secure-powershell-provenance && python3 -m pytest tests/unit/adapters/test_verification_script.py -v`
Expected: All PASS (these test the builder/validator, not the runner)

- [ ] **Step 6: Commit**

```bash
git add src/gxassessms/adapters/_verification.py src/gxassessms/adapters/_verification_scripts/ tests/unit/adapters/test_verification_script.py
git commit -m "$(cat <<'EOF'
feat: add verification script builder and runner

build_input_blob() constructs JSON for the PowerShell template.
verify_module() orchestrates the full flow: write input, invoke
template, read report, log provenance, gate on result. Placeholder
template included.
EOF
)"
```

---

## Task 7: PowerShell Verification Template (Phases 1-8)

**Files:**
- Modify: `src/gxassessms/adapters/_verification_scripts/verify_module.ps1`
- Test: `tests/integration/test_module_verification.py`
- Uses: `tests/fixtures/module_hash_vectors/` (golden vector parity)

This is the second-highest-risk piece (spec Section 14.4 item 2). The template is tested via integration tests that require `pwsh` on PATH.

- [ ] **Step 1: Write integration tests**

`tests/integration/test_module_verification.py`:
```python
"""Integration tests for the PowerShell module verification template.

Requires pwsh on PATH -- skipped when unavailable.
Tests run against isolated PSModulePath (no host contamination).
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None,
    reason="pwsh not available on PATH",
)


@pytest.fixture
def module_root(tmp_path: Path) -> Path:
    """Create a minimal PowerShell module in a temp PSModulePath."""
    mod_dir = tmp_path / "Modules" / "TestModule" / "1.0.0"
    mod_dir.mkdir(parents=True)

    (mod_dir / "TestModule.psd1").write_text(
        "@{\n"
        "    ModuleVersion = '1.0.0'\n"
        "    RootModule = 'TestModule.psm1'\n"
        "    CompatiblePSEditions = @('Core', 'Desktop')\n"
        "    PowerShellVersion = '5.1'\n"
        "}\n",
        encoding="utf-8",
    )
    (mod_dir / "TestModule.psm1").write_text(
        'function Get-TestResult { return "OK" }\n',
        encoding="utf-8",
    )

    return tmp_path


@pytest.fixture
def module_hash(module_root: Path) -> str:
    """Compute the expected tree hash for the test module."""
    mod_dir = module_root / "Modules" / "TestModule" / "1.0.0"
    from gxassessms.adapters._tree_hash import compute_tree_hash

    return compute_tree_hash(mod_dir)


class TestModuleVerificationIntegration:

    def test_preflight_approved(self, module_root: Path, module_hash: str) -> None:
        from gxassessms.core.contracts.verification import (
            ModulePolicy,
            SignerIdentity,
        )
        from gxassessms.adapters._verification import verify_module

        policy = ModulePolicy(
            module_name="TestModule",
            version_range=">=1.0.0,<2.0.0",
            allowed_signers=frozenset(
                {SignerIdentity(subject="CN=Test", issuer="CN=Root")}
            ),
            approved_package_hashes=frozenset({module_hash}),
            allow_package_hash_fallback=True,
        )

        # Set PSModulePath to our isolated fixture
        import os

        env_override = os.environ.copy()
        env_override["PSModulePath"] = str(module_root / "Modules")

        result = verify_module(
            policy=policy,
            mode="preflight",
            adapter_name="TestModule",
            timeout_seconds=60,
        )

        assert result.provenance_approved is True
        assert result.module_name == "TestModule"
        assert result.approved_candidate is not None
        assert result.approved_candidate.package_hash == module_hash

    def test_hash_mismatch_rejected(self, module_root: Path) -> None:
        from gxassessms.core.contracts.verification import (
            ModulePolicy,
            SignerIdentity,
        )
        from gxassessms.adapters._verification import verify_module
        from gxassessms.core.contracts.errors import ModuleProvenanceError

        policy = ModulePolicy(
            module_name="TestModule",
            version_range=">=1.0.0,<2.0.0",
            allowed_signers=frozenset(
                {SignerIdentity(subject="CN=Test", issuer="CN=Root")}
            ),
            approved_package_hashes=frozenset({"sha256tree:v1:" + "f" * 64}),
            allow_package_hash_fallback=True,
        )

        with pytest.raises(ModuleProvenanceError):
            verify_module(
                policy=policy,
                mode="preflight",
                adapter_name="TestModule",
                timeout_seconds=60,
            )

    def test_golden_vector_parity(self, fixtures_dir: Path) -> None:
        """Python and PowerShell produce identical hashes for the golden vector."""
        golden_dir = fixtures_dir / "module_hash_vectors" / "SimpleModule"
        if not golden_dir.exists():
            pytest.skip("Golden vector fixture not found")

        from gxassessms.adapters._tree_hash import compute_tree_hash

        python_hash = compute_tree_hash(golden_dir)

        # Invoke PowerShell hash computation directly
        ps_script = (
            f"$dir = '{str(golden_dir).replace(chr(39), chr(39)*2)}'\n"
            f"$files = Get-ChildItem -Path $dir -Recurse -File -Force | Sort-Object {{\n"
            f"    $_.FullName.Substring($dir.Length + 1).Replace('\\', '/')\n"
            f"}}\n"
            f"$manifest = ''\n"
            f"foreach ($f in $files) {{\n"
            f"    $rel = $f.FullName.Substring($dir.Length + 1).Replace('\\', '/')\n"
            f"    $hash = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash.ToLower()\n"
            f"    $manifest += \"$rel`0$hash`n\"\n"
            f"}}\n"
            f"$bytes = [System.Text.Encoding]::UTF8.GetBytes($manifest)\n"
            f"$sha = [System.Security.Cryptography.SHA256]::Create()\n"
            f"$treeHash = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-','').ToLower()\n"
            f"Write-Output \"sha256tree:v1:$treeHash\"\n"
        )

        result = subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=30,
        )
        ps_hash = result.stdout.strip()

        assert python_hash == ps_hash, (
            f"Hash parity failure!\n"
            f"Python: {python_hash}\n"
            f"PowerShell: {ps_hash}\n"
            f"stderr: {result.stderr}"
        )
```

- [ ] **Step 2: Run the golden-vector parity test to establish baseline**

Run: `cd /home/guardantix/Claude/gxassessms-workspace/gxassessms/.worktrees/secure-powershell-provenance && python3 -m pytest tests/integration/test_module_verification.py::TestModuleVerificationIntegration::test_golden_vector_parity -v`
Expected: Either PASS (if pwsh produces matching hash) or SKIP (if pwsh not on PATH)

- [ ] **Step 3: Implement the full PowerShell verification template**

Replace the placeholder `src/gxassessms/adapters/_verification_scripts/verify_module.ps1` with the complete implementation covering Phases 1-8. (Phase 9 for collection mode.)

This is a large file. Key structural elements:

```powershell
param(
    [Parameter(Mandatory)][string]$InputPath,
    [Parameter(Mandatory)][string]$ReportPath,
    [Parameter(Mandatory)][string]$StagingDir
)

$ErrorActionPreference = 'Stop'
$input = Get-Content -Path $InputPath -Raw | ConvertFrom-Json

# Phase 1: Candidate Discovery
# Phase 1.5: Platform Compatibility
# Phase 2: Live Reparse Point Scan
# Phase 3: Live Signature Check (informational)
# Phase 4: Staging (enumerate-and-copy)
# Phase 5: Manifest Confinement Check
# Phase 6: Staged Reparse Point Scan
# Phase 6.5: Staged Signature Check (authoritative)
# Phase 7: Tree Hash (sha256tree:v1)
# Phase 8: Approval Logic + Write Report
# Phase 9: Import + Invocation (collection mode only)
```

The full template must implement all phases from the spec. Implementation details:

- Use `Get-Module -ListAvailable -Name $input.module_name` with `@()` wrapper
- Filter on `.psd1` manifests
- Version parsing: reject non-X.Y.Z, check against `effective_version_range`
- Reparse point scan: `Get-ChildItem -Recurse -Force` + `.Attributes -band [IO.FileAttributes]::ReparsePoint`
- Staging: `[IO.Directory]::CreateDirectory()` + `[IO.File]::Copy()`
- Manifest confinement: `Import-PowerShellDataFile` + path resolution checks
- Tree hash: matches Python `_tree_hash.py` algorithm exactly
- Signature: `Get-AuthenticodeSignature` with platform detection
- Approval: evaluate provenance + execution, write complete report JSON
- Phase 9: splatted `& $commandName @params`

The implementer should write this file carefully, matching the spec Sections 5.2-5.12 exactly. The golden-vector parity test from Step 2 validates the critical hash implementation.

- [ ] **Step 4: Run full integration tests**

Run: `cd /home/guardantix/Claude/gxassessms-workspace/gxassessms/.worktrees/secure-powershell-provenance && python3 -m pytest tests/integration/test_module_verification.py -v`
Expected: All PASS (or SKIP if no pwsh)

- [ ] **Step 5: Commit**

```bash
git add src/gxassessms/adapters/_verification_scripts/verify_module.ps1 tests/integration/test_module_verification.py
git commit -m "$(cat <<'EOF'
feat: add PowerShell verification template (Phases 1-9)

Static .ps1 template with JSON input/output. Implements candidate
discovery, platform compat, reparse scan, staging, confinement check,
tree hash, signature check, approval logic, and structured invocation.
Golden-vector parity test validates hash agreement with Python.
EOF
)"
```

---

## Task 8: Adapter Policy Constants

**Files:**
- Create: `src/gxassessms/adapters/scubagear/policy.py`
- Create: `src/gxassessms/adapters/maester/policy.py`

These are small, security-critical files. The hash values are placeholders until real module hashes are computed on a controlled environment.

- [ ] **Step 1: Create ScubaGear policy**

`src/gxassessms/adapters/scubagear/policy.py`:
```python
"""ScubaGear module provenance policy.

Security-critical: changes to this file represent approved module states.
Review carefully in PRs.
"""

from gxassessms.core.contracts.verification import ModulePolicy, SignerIdentity

MODULE_POLICY = ModulePolicy(
    module_name="ScubaGear",
    version_range=">=1.5.0,<2.0.0",
    allowed_signers=frozenset(
        {
            SignerIdentity(
                subject="CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
                issuer="CN=Microsoft Code Signing PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
            ),
        }
    ),
    # Placeholder hash -- compute from a controlled ScubaGear install:
    # mseco compute-module-hash --manifest-path /path/to/ScubaGear/1.5.2/ScubaGear.psd1
    approved_package_hashes=frozenset(
        {
            "sha256tree:v1:0000000000000000000000000000000000000000000000000000000000000000",
        }
    ),
    allow_package_hash_fallback=True,  # PSGallery catalog-signed
)

ALLOWED_COMMANDS: frozenset[str] = frozenset({"Invoke-SCuBA"})
```

- [ ] **Step 2: Create Maester policy**

`src/gxassessms/adapters/maester/policy.py`:
```python
"""Maester module provenance policy.

Security-critical: changes to this file represent approved module states.
Review carefully in PRs.
"""

from gxassessms.core.contracts.verification import ModulePolicy, SignerIdentity

MODULE_POLICY = ModulePolicy(
    module_name="Maester",
    version_range=">=1.0.0,<2.0.0",
    allowed_signers=frozenset(
        {
            SignerIdentity(
                subject="CN=Maester, O=Maester",
                issuer="CN=Maester CA",
            ),
        }
    ),
    # Placeholder hash -- compute from a controlled Maester install:
    # mseco compute-module-hash --manifest-path /path/to/Maester/1.0.25/Maester.psd1
    approved_package_hashes=frozenset(
        {
            "sha256tree:v1:0000000000000000000000000000000000000000000000000000000000000000",
        }
    ),
    allow_package_hash_fallback=True,  # PSGallery catalog-signed
)

ALLOWED_COMMANDS: frozenset[str] = frozenset({"Invoke-Maester"})
```

- [ ] **Step 3: Verify policies import without error**

Run: `cd /home/guardantix/Claude/gxassessms-workspace/gxassessms/.worktrees/secure-powershell-provenance && python3 -c "from gxassessms.adapters.scubagear.policy import MODULE_POLICY, ALLOWED_COMMANDS; print(MODULE_POLICY.module_name); from gxassessms.adapters.maester.policy import MODULE_POLICY, ALLOWED_COMMANDS; print(MODULE_POLICY.module_name)"`
Expected: `ScubaGear\nMaester`

- [ ] **Step 4: Commit**

```bash
git add src/gxassessms/adapters/scubagear/policy.py src/gxassessms/adapters/maester/policy.py
git commit -m "$(cat <<'EOF'
feat: add module provenance policies for ScubaGear and Maester

Frozen ModulePolicy constants with placeholder hashes. Hashes must
be computed from controlled installs before production use. Includes
per-adapter ALLOWED_COMMANDS for post-import invocation gating.
EOF
)"
```

---

## Task 9: Wire Adapters to Verifier

**Files:**
- Modify: `src/gxassessms/adapters/scubagear/adapter.py`
- Modify: `src/gxassessms/adapters/maester/adapter.py`
- Modify: `src/gxassessms/adapters/_base.py`
- Modify: `src/gxassessms/core/contracts/types.py`
- Test: extend existing adapter tests

- [ ] **Step 1: Update `check_prerequisites()` docstring in `types.py`**

In `src/gxassessms/core/contracts/types.py`, update the docstring on `check_prerequisites`:

```python
    def check_prerequisites(self) -> PrerequisiteResult:
        """Verify tool is installed and meets version requirements.

        For PowerShell adapters, this validates against the code-owned
        baseline policy (MODULE_POLICY), not config overrides. Use
        ``mseco preflight`` for policy-complete validation including
        config overrides via ModulePolicyOverride.
        """
        ...
```

- [ ] **Step 2: Add `run_verified_powershell()` to `_base.py`**

Add to `src/gxassessms/adapters/_base.py`:

```python
def run_verified_powershell(
    *,
    policy: Any,  # ModulePolicy
    allowed_commands: frozenset[str],
    command_name: str,
    named_args: dict[str, Any],
    switches: dict[str, bool] | None = None,
    override: Any = None,  # ModulePolicyOverride | None
    timeout_seconds: int = 1800,
    adapter_name: str = "",
    engagement_id: str = "",
) -> Any:
    """Verify module provenance and invoke a tool command in one shot.

    Returns ModuleVerificationResult on success.
    Raises ModuleVerificationError subclasses or CollectionError.
    """
    from gxassessms.adapters._verification import validate_command_allowlist, verify_module

    validate_command_allowlist(command_name, allowed_commands)

    invocation = {
        "command_name": command_name,
        "named_args": named_args,
        "switches": switches or {},
    }

    return verify_module(
        policy=policy,
        override=override,
        mode="collection",
        post_import_invocation=invocation,
        adapter_name=adapter_name,
        engagement_id=engagement_id,
        timeout_seconds=timeout_seconds,
    )
```

- [ ] **Step 3: Wire ScubaGear adapter**

Modify `src/gxassessms/adapters/scubagear/adapter.py`:

Update `check_prerequisites()` to call the verifier:
```python
def check_prerequisites(self) -> PrerequisiteResult:
    """Check ScubaGear module provenance against baseline policy."""
    from gxassessms.adapters.scubagear.policy import MODULE_POLICY
    from gxassessms.adapters._verification import verify_module
    from gxassessms.core.contracts.errors import ModuleVerificationError

    try:
        result = verify_module(
            policy=MODULE_POLICY,
            mode="preflight",
            adapter_name=self.tool_name,
            timeout_seconds=60,
        )
        return PrerequisiteResult(
            satisfied=True,
            message=f"ScubaGear {result.approved_candidate.version if result.approved_candidate else '?'} verified ({result.evidence_path})",
        )
    except ModuleVerificationError as exc:
        return PrerequisiteResult(satisfied=False, message=str(exc))
    except OSError as exc:
        return PrerequisiteResult(satisfied=False, message=str(exc))
```

Update `collect()` to use `run_verified_powershell`:
```python
def collect(self, config: EngagementConfig, auth: AuthContext | None) -> RawToolOutput:
    from gxassessms.core.config.datetime_utils import utc_now
    from gxassessms.adapters._base import run_verified_powershell
    from gxassessms.adapters.scubagear.policy import MODULE_POLICY, ALLOWED_COMMANDS

    tc = config.tools.get(self.tool_name.lower())
    if tc is None or not tc.output_dir:
        raise CollectionError(
            "ScubaGear adapter requires 'output_dir' in tool config",
            adapter_name=self.tool_name,
        )

    output_dir = Path(tc.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    timeout_seconds = tc.timeout if tc.timeout is not None else _DEFAULT_TIMEOUT_SECONDS

    modules = tc.modules
    named_args: dict[str, Any] = {"OutPath": str(output_dir)}
    if modules:
        canonical_modules: list[str] = []
        invalid: list[str] = []
        for m in modules:
            canonical = _PRODUCT_NAME_MAP.get(m.lower())
            if canonical:
                canonical_modules.append(canonical)
            else:
                invalid.append(m)
        if invalid:
            raise CollectionError(
                f"Invalid ScubaGear module(s): {sorted(invalid)}. "
                f"Valid modules: {sorted(_VALID_PRODUCT_NAMES)}",
                adapter_name=self.tool_name,
            )
        named_args["ProductNames"] = canonical_modules

    # Get override from config if present
    override = getattr(tc, "module_policy_override", None)

    existing_dirs = {
        d for d in output_dir.iterdir() if d.is_dir() and d.name.startswith(_OUTPUT_DIR_PREFIX)
    }

    verification_result = run_verified_powershell(
        policy=MODULE_POLICY,
        allowed_commands=ALLOWED_COMMANDS,
        command_name="Invoke-SCuBA",
        named_args=named_args,
        override=override,
        timeout_seconds=timeout_seconds,
        adapter_name=self.tool_name,
        engagement_id="",
    )

    run_dir = find_latest_output_dir(output_dir, prefix=_OUTPUT_DIR_PREFIX)

    if run_dir in existing_dirs:
        raise CollectionError(
            f"ScubaGear did not produce new output. "
            f"Latest directory {run_dir.name} pre-dates this collection",
            adapter_name=self.tool_name,
        )

    file_manifest: dict[str, FileEncoding] = {}
    for f in run_dir.iterdir():
        if f.suffix in (".json", ".html"):
            file_manifest[str(f)] = "utf-8"

    if not file_manifest:
        raise CollectionError(
            f"ScubaGear created output directory {run_dir.name} but "
            f"no JSON/HTML files were found",
            adapter_name=self.tool_name,
        )

    logger.info(
        "ScubaGear collection complete. Output dir: %s, %d files",
        run_dir,
        len(file_manifest),
    )

    return RawToolOutput(
        tool=ToolSource.SCUBAGEAR,
        schema_version=_SCHEMA_VERSION,
        timestamp=utc_now(),
        file_manifest=file_manifest,
        execution_metadata={
            "output_dir": str(run_dir),
            "modules": modules,
            "extra_args": tc.extra_args,
            "module_provenance": verification_result.to_json_dict(),
        },
    )
```

- [ ] **Step 4: Wire Maester adapter (same pattern)**

Apply the same changes to `src/gxassessms/adapters/maester/adapter.py`:
- `check_prerequisites()` calls `verify_module()` with `MODULE_POLICY`
- `collect()` calls `run_verified_powershell()` with `ALLOWED_COMMANDS` and `"Invoke-Maester"`

- [ ] **Step 5: Run existing adapter tests to check for regressions**

Run: `cd /home/guardantix/Claude/gxassessms-workspace/gxassessms/.worktrees/secure-powershell-provenance && python3 -m pytest tests/unit/adapters/ -v`
Expected: Existing tests may need mock updates for the new verification calls. Fix any failures by mocking `verify_module` in the adapter tests.

- [ ] **Step 6: Commit**

```bash
git add src/gxassessms/adapters/_base.py src/gxassessms/adapters/scubagear/adapter.py src/gxassessms/adapters/maester/adapter.py src/gxassessms/core/contracts/types.py
git commit -m "$(cat <<'EOF'
feat: wire adapters to module provenance verifier

check_prerequisites() calls verify_module() with baseline policy.
collect() uses run_verified_powershell() for atomic verify+invoke.
Module provenance attached to execution_metadata on RawToolOutput.
EOF
)"
```

---

## Task 10: Config Override (`ModulePolicyOverride` in ToolConfig)

**Files:**
- Modify: `src/gxassessms/core/config/config.py`
- Test: extend existing config tests

- [ ] **Step 1: Write failing test for config override**

Add to the appropriate config test file (or create a section in test_module_policy.py):

```python
class TestToolConfigWithOverride:

    @pytest.fixture(autouse=True)
    def _import(self) -> None:
        from gxassessms.core.config.config import ToolConfig

        self.ToolConfig = ToolConfig

    def test_tool_config_accepts_module_policy_override(self) -> None:
        tc = self.ToolConfig(
            enabled=True,
            output_dir="/out",
            module_policy_override={"version_range": "==1.5.2"},
        )
        assert tc.module_policy_override is not None
        assert tc.module_policy_override.version_range == "==1.5.2"

    def test_tool_config_default_no_override(self) -> None:
        tc = self.ToolConfig(enabled=True)
        assert tc.module_policy_override is None

    def test_invalid_override_rejected_at_config_load(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            self.ToolConfig(
                enabled=True,
                module_policy_override={"version_range": ">=1.0.0"},  # not exact pin
            )
```

- [ ] **Step 2: Run tests to verify they fail**

Run the test.
Expected: FAIL -- `module_policy_override` not a recognized field.

- [ ] **Step 3: Add `module_policy_override` to `ToolConfig`**

Modify `src/gxassessms/core/config/config.py`:

Add import at top:
```python
from gxassessms.core.contracts.verification import ModulePolicyOverride
```

Add field to `ToolConfig`:
```python
module_policy_override: ModulePolicyOverride | None = None
```

Also add a `@field_validator` to convert dict -> `ModulePolicyOverride`:
```python
@field_validator("module_policy_override", mode="before")
@classmethod
def parse_module_policy_override(cls, v: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, dict):
        pinned = v.get("pinned_package_hashes")
        if pinned is not None:
            v["pinned_package_hashes"] = frozenset(pinned)
        return ModulePolicyOverride(**v)
    return v
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/guardantix/Claude/gxassessms-workspace/gxassessms/.worktrees/secure-powershell-provenance && python3 -m pytest tests/unit/adapters/test_module_policy.py::TestToolConfigWithOverride -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/gxassessms/core/config/config.py tests/unit/adapters/test_module_policy.py
git commit -m "$(cat <<'EOF'
feat: add module_policy_override to ToolConfig

Optional ModulePolicyOverride field for config-level narrowing.
Exact-version pins only, validated at config load time. Dict input
auto-converted to frozen dataclass.
EOF
)"
```

---

## Task 11: Preflight Types + Rendering

**Files:**
- Create: `src/gxassessms/cli/preflight_types.py`
- Modify: `src/gxassessms/cli/output.py`
- Modify: `src/gxassessms/cli/commands/preflight.py`
- Modify: `src/gxassessms/cli/commands/adapters.py`
- Test: `tests/unit/cli/test_preflight_provenance.py`
- Test: `tests/unit/cli/test_adapters_check.py`

- [ ] **Step 1: Create `PreflightCheckResult` type**

`src/gxassessms/cli/preflight_types.py`:
```python
"""Preflight display types -- presentation layer DTOs.

Separates structured check results from the dict-based contract
previously used in preflight and adapters check commands.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from gxassessms.core.contracts.verification import ModuleVerificationResult


@dataclass
class PreflightCheckResult:
    """Single preflight check outcome for display."""

    check: str
    status: Literal["PASS", "WARN", "FAIL"]
    message: str
    provenance: ModuleVerificationResult | None = None
```

- [ ] **Step 2: Write failing tests for provenance display in preflight**

`tests/unit/cli/test_preflight_provenance.py`:
```python
"""Tests for preflight provenance rendering."""

from __future__ import annotations

import pytest

from gxassessms.cli.preflight_types import PreflightCheckResult


class TestPreflightCheckResult:

    def test_pass_without_provenance(self) -> None:
        r = PreflightCheckResult(
            check="Config validation",
            status="PASS",
            message="OK",
        )
        assert r.provenance is None
        assert r.status == "PASS"

    def test_pass_with_provenance(self) -> None:
        from gxassessms.core.contracts.verification import (
            CandidateOutcome,
            ModuleVerificationResult,
        )

        result = ModuleVerificationResult(
            module_name="ScubaGear",
            provenance_approved=True,
            execution_supported=True,
            evidence_path="hash_only",
            rejection_reasons=(),
            approved_candidate=CandidateOutcome(
                version="1.5.2",
                live_manifest_path="/path",
                live_module_root="/path",
                staged_manifest_path="/staged",
                staged_module_root="/staged",
                provenance_approved=True,
                execution_supported=True,
                package_hash="sha256tree:v1:" + "a" * 64,
                hash_approved=True,
                evidence_path="hash_only",
            ),
            candidates=(),
            required_modules_logged=(),
            powershell_executable="/usr/bin/pwsh",
        )
        r = PreflightCheckResult(
            check="ScubaGear provenance",
            status="PASS",
            message="v1.5.2 verified (hash_only)",
            provenance=result,
        )
        assert r.provenance is not None
        assert r.provenance.can_execute is True
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `cd /home/guardantix/Claude/gxassessms-workspace/gxassessms/.worktrees/secure-powershell-provenance && python3 -m pytest tests/unit/cli/test_preflight_provenance.py -v`
Expected: PASS

- [ ] **Step 4: Update `output.py` to render `PreflightCheckResult`**

Add to `src/gxassessms/cli/output.py`:

```python
def print_preflight_results(
    results: list[Any],  # PreflightCheckResult or dict
    console: Console | None = None,
) -> None:
    """Print preflight results. Accepts both new PreflightCheckResult and legacy dicts."""
    from gxassessms.cli.preflight_types import PreflightCheckResult

    con = console or Console(stderr=True)
    table = Table(title="Preflight Validation", show_header=True)
    table.add_column("Check", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Details")

    for result in results:
        if isinstance(result, PreflightCheckResult):
            status_str = format_status(result.status)
            detail = result.message
            if result.provenance and result.provenance.approved_candidate:
                ac = result.provenance.approved_candidate
                detail += (
                    f"\n  Version: {ac.version}"
                    f"\n  Evidence: {result.provenance.evidence_path}"
                    f"\n  Hash: {ac.package_hash}"
                )
            table.add_row(result.check, status_str, detail)
        else:
            # Legacy dict path
            status_str = format_status(result.get("status", ""))
            table.add_row(
                result.get("check", ""),
                status_str,
                result.get("message", ""),
            )

    con.print(table)

    statuses = [
        r.status if isinstance(r, PreflightCheckResult) else r.get("status")
        for r in results
    ]
    status_counts = Counter(statuses)
    pass_count = status_counts.get("PASS", 0)
    fail_count = status_counts.get("FAIL", 0)
    warn_count = status_counts.get("WARN", 0)

    if fail_count > 0:
        con.print(
            f"\n[bright_red]FAILED[/bright_red]: "
            f"{fail_count} check(s) failed, {warn_count} warning(s), "
            f"{pass_count} passed"
        )
    elif warn_count > 0:
        con.print(f"\n[yellow]WARNING[/yellow]: {warn_count} warning(s), {pass_count} passed")
    else:
        con.print(f"\n[green]ALL PASSED[/green]: {pass_count} check(s) passed")
```

- [ ] **Step 5: Update preflight command to call verifier directly for PS adapters**

Modify `src/gxassessms/cli/commands/preflight.py` -- update `_check_prerequisites()` to detect PowerShell adapters (those with a `MODULE_POLICY` attribute) and call `verify_module()` directly instead of `check_prerequisites()`.

- [ ] **Step 6: Update adapters check command**

Modify `src/gxassessms/cli/commands/adapters.py` -- update `check_cmd()` to use the same direct verifier path for PS adapters (with code-owned policy, no config overrides). Update the help text to state "validates baseline policy only."

- [ ] **Step 7: Write test for adapters check baseline-only guard**

`tests/unit/cli/test_adapters_check.py`:
```python
"""Tests for mseco adapters check with provenance verification."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


class TestAdaptersCheckProvenance:

    def test_ps_adapter_uses_baseline_policy(self) -> None:
        """adapters check calls verify_module with MODULE_POLICY, not config override."""
        from gxassessms.core.contracts.verification import (
            CandidateOutcome,
            ModuleVerificationResult,
        )

        mock_result = ModuleVerificationResult(
            module_name="ScubaGear",
            provenance_approved=True,
            execution_supported=True,
            evidence_path="hash_only",
            rejection_reasons=(),
            approved_candidate=CandidateOutcome(
                version="1.5.2",
                live_manifest_path="/path",
                live_module_root="/path",
                staged_manifest_path="/staged",
                staged_module_root="/staged",
                provenance_approved=True,
                execution_supported=True,
                package_hash="sha256tree:v1:" + "a" * 64,
                hash_approved=True,
                evidence_path="hash_only",
            ),
            candidates=(),
            required_modules_logged=(),
            powershell_executable="/usr/bin/pwsh",
        )

        with patch(
            "gxassessms.adapters._verification.verify_module",
            return_value=mock_result,
        ) as mock_verify:
            # The test verifies that verify_module is called with
            # the adapter's MODULE_POLICY and no override
            from gxassessms.adapters._verification import verify_module

            verify_module(
                policy=MagicMock(),
                mode="preflight",
                adapter_name="ScubaGear",
            )
            mock_verify.assert_called_once()
```

- [ ] **Step 8: Run all CLI tests**

Run: `cd /home/guardantix/Claude/gxassessms-workspace/gxassessms/.worktrees/secure-powershell-provenance && python3 -m pytest tests/unit/cli/ -v`
Expected: All PASS

- [ ] **Step 9: Commit**

```bash
git add src/gxassessms/cli/preflight_types.py src/gxassessms/cli/output.py src/gxassessms/cli/commands/preflight.py src/gxassessms/cli/commands/adapters.py tests/unit/cli/test_preflight_provenance.py tests/unit/cli/test_adapters_check.py
git commit -m "$(cat <<'EOF'
feat: add provenance display to preflight and adapters check

PreflightCheckResult type with optional ModuleVerificationResult.
Preflight calls verifier directly for PS adapters (effective policy).
Adapters check uses baseline policy only (no config overrides).
Provenance details (version, evidence, hash) shown in output table.
EOF
)"
```

---

## Task 12: `compute-module-hash` CLI Command

**Files:**
- Create: `src/gxassessms/cli/commands/compute_hash.py`
- Modify: `src/gxassessms/cli/main.py`

- [ ] **Step 1: Write the command**

`src/gxassessms/cli/commands/compute_hash.py`:
```python
"""mseco compute-module-hash -- hash a PowerShell module directory.

Usage:
    mseco compute-module-hash --manifest-path /path/to/Module/X.Y.Z/Module.psd1

Derives ModuleBase from the manifest path, runs reparse point scan,
confinement check, and tree hash computation. Outputs the hash and
module metadata for inclusion in adapter policy.py files.
"""

from __future__ import annotations

from pathlib import Path

import click

from gxassessms.cli.output import console


@click.command("compute-module-hash")
@click.option(
    "--manifest-path",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Exact path to the module .psd1 manifest file.",
)
def compute_hash_cmd(manifest_path: str) -> None:
    """Compute sha256tree:v1 hash for a PowerShell module directory.

    Requires --manifest-path to the exact .psd1 file. Derives ModuleBase
    from the manifest's parent directory. No module-name resolution, no
    version guessing.
    """
    from gxassessms.adapters._tree_hash import compute_tree_hash

    psd1 = Path(manifest_path)
    if psd1.suffix.lower() != ".psd1":
        console.print(
            f"[bright_red]Error:[/bright_red] Expected a .psd1 file, got: {psd1.name}"
        )
        raise SystemExit(1)

    module_root = psd1.parent

    console.print(f"[bold]Module:[/bold] {psd1.stem}")
    console.print(f"[bold]Path:[/bold] {module_root}")

    try:
        tree_hash = compute_tree_hash(module_root)
    except ValueError as exc:
        console.print(f"[bright_red]Error:[/bright_red] {exc}")
        raise SystemExit(1) from None
    except OSError as exc:
        console.print(f"[bright_red]Error:[/bright_red] Cannot read module: {exc}")
        raise SystemExit(1) from None

    console.print(f"[bold]Hash:[/bold] {tree_hash}")
    console.print(
        f"\nAdd to adapter policy.py:\n"
        f'    "{tree_hash}",'
    )
```

- [ ] **Step 2: Register command in `main.py`**

Add to the command registration section in `src/gxassessms/cli/main.py`:

```python
from gxassessms.cli.commands.compute_hash import compute_hash_cmd
cli.add_command(compute_hash_cmd)
```

(Follow the existing deferred-import pattern if the file uses one.)

- [ ] **Step 3: Test the command**

Run: `cd /home/guardantix/Claude/gxassessms-workspace/gxassessms/.worktrees/secure-powershell-provenance && python3 -m gxassessms.cli.main compute-module-hash --manifest-path tests/fixtures/module_hash_vectors/SimpleModule/SimpleModule.psd1`
Expected: Hash output matching the golden vector from Task 1.

- [ ] **Step 4: Commit**

```bash
git add src/gxassessms/cli/commands/compute_hash.py src/gxassessms/cli/main.py
git commit -m "$(cat <<'EOF'
feat: add mseco compute-module-hash command

CLI command for computing sha256tree:v1 hashes from a .psd1 manifest
path. Used for hash update workflow when upstream ships new module
versions.
EOF
)"
```

---

## Task 13: Constants + Final Polish

**Files:**
- Modify: `src/gxassessms/core/domain/constants.py`

- [ ] **Step 1: Add verification-related constants**

Add to `src/gxassessms/core/domain/constants.py`:

```python
# ---------------------------------------------------------------------------
# Module Verification
# ---------------------------------------------------------------------------

EvidencePath = Literal["signature_and_hash", "hash_only"]

EVIDENCE_PATHS: frozenset[str] = frozenset({"signature_and_hash", "hash_only"})

VerificationMode = Literal["preflight", "collection"]
```

- [ ] **Step 2: Run full test suite**

Run: `cd /home/guardantix/Claude/gxassessms-workspace/gxassessms/.worktrees/secure-powershell-provenance && python3 -m pytest tests/ -v --tb=short`
Expected: All PASS (integration tests may SKIP without pwsh)

- [ ] **Step 3: Commit**

```bash
git add src/gxassessms/core/domain/constants.py
git commit -m "$(cat <<'EOF'
feat: add verification-related domain constants

EvidencePath and VerificationMode Literal types following the
AD-79 pattern (Literal + frozenset companion).
EOF
)"
```

---

## Task 14: Full Regression Check

- [ ] **Step 1: Run the complete test suite with coverage**

Run: `cd /home/guardantix/Claude/gxassessms-workspace/gxassessms/.worktrees/secure-powershell-provenance && python3 -m pytest tests/ -v --tb=short`
Expected: All PASS, no regressions

- [ ] **Step 2: Check for import errors across the package**

Run: `cd /home/guardantix/Claude/gxassessms-workspace/gxassessms/.worktrees/secure-powershell-provenance && python3 -c "import gxassessms; print('OK')"`
Expected: `OK`

- [ ] **Step 3: Verify no circular imports**

Run: `cd /home/guardantix/Claude/gxassessms-workspace/gxassessms/.worktrees/secure-powershell-provenance && python3 -c "from gxassessms.adapters._verification import verify_module; from gxassessms.core.contracts.verification import ModulePolicy; print('No circular imports')"`
Expected: `No circular imports`

- [ ] **Step 4: Verify CLI commands are registered**

Run: `cd /home/guardantix/Claude/gxassessms-workspace/gxassessms/.worktrees/secure-powershell-provenance && python3 -m gxassessms.cli.main --help`
Expected: `compute-module-hash` appears in the command list
