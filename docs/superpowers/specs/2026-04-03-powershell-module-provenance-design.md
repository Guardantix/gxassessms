# PowerShell Module Provenance Verification

**Issue**: [#37](https://github.com/Guardantix/gxassessms/issues/37) -- Pin and verify
approved PowerShell modules before collection runs

**Threat model reference**: TM-001 (Compromised PowerShell Module), HIGH/HIGH

**Date**: 2026-04-03

**Status**: Design approved, pending implementation plan

---

## 1. Problem

The threat model (TM-001) identifies PowerShell module execution as a high-risk trust
boundary. Current controls verify command-shape safety (`shell=False`, argument allowlist,
timeouts) but do not prove that the resolved ScubaGear or Maester module is the approved
one.

On a shared host, weakly controlled workstation, or compromised package source, a replaced
or unexpected PowerShell module can execute with the analyst account and silently tamper
with findings or exfiltrate customer-sensitive data.

Current `check_prerequisites()` implementations in both adapters only verify module
presence via `Get-Module -ListAvailable`. No version, signature, publisher, path, or
integrity verification exists.

## 2. Scope

This control verifies the **top-level collector module** (ScubaGear, Maester) only.
Transitive dependencies declared via `RequiredModules` (e.g., `Microsoft.Graph.*`,
`Pester`) are logged for audit but not verified. Transitive module provenance is a
separate trust boundary -- a follow-up issue should be filed for it.

The control covers:

- Module identity: name, version, signer (when verifiable)
- Module integrity: tree hash of the entire module directory
- Module platform compatibility: `CompatiblePSEditions`, `PowerShellVersion`
- Enforcement: fail closed on policy violation, ambiguity, confinement escape
- Audit: structured logging of module provenance per run

## 3. Design Decisions

### 3.1 Version Policy: Semver Range

Module versions use semver ranges (e.g., `>=1.5.0,<2.0.0`). The verifier accepts X.Y.Z
versions only. If upstream ships a four-part System.Version (e.g., `1.5.2.0`), the
verifier rejects it. This is a deliberate product decision: it forces an explicit policy
update rather than silently accepting an unexpected version format. The rejection reason
is documented in preflight output so the operator knows why.

Config overrides are limited to exact-version pins (`==X.Y.Z`). No arbitrary subset
proofs required.

### 3.2 Trust Anchor: Tree Hash + Signature When Available

Signature on a `.psd1` file proves signer identity for that one file but does not attest
the full module tree. An attacker can replace `.psm1` or nested scripts while leaving the
signed `.psd1` intact.

Tree hash is always required for integrity. Signature is an additional identity layer:

- **signature_and_hash**: Authenticode signature verified on the staged `.psd1` AND tree
  hash matches an approved hash. Only claimable when signature verification succeeds on
  the staged artifact.
- **hash_only**: Tree hash matches an approved hash. Signature either unavailable
  (platform), unreliable on the staged copy (catalog-signed), or failed.

For PSGallery catalog-signed modules, the expected operational evidence path is
`hash_only`. Catalog signatures typically do not survive staging to a private copy.
`signature_and_hash` is available when modules carry embedded Authenticode signatures.
The control's primary strength comes from the tree hash against approved hashes, not
from signature verification. Signature is a bonus when available, not the load-bearing
element.

### 3.3 Staging Eliminates the TOCTOU Race

Verification and import must execute what was hashed. An attacker who can mutate files
concurrently can race hash/signature checks and `Import-Module` even within the same
PowerShell process. The design copies the approved module tree into a private temp
directory, verifies the staged copy, and imports the staged manifest path. We execute
what we hashed, not the live install tree.

### 3.4 Single-Invocation Atomic Verification

Verification, import, and execution happen in one PowerShell invocation. Python builds
the script, invokes it once, and parses the verification report afterward. No
re-resolution by module name after verification. The exact staged `.psd1` path is the
only import reference.

### 3.5 Dual-Axis Result: Provenance vs Execution

`provenance_approved` and `execution_supported` are independent axes:

- A module can be provenance-approved but platform-incompatible (ScubaGear on Linux)
- A module can be platform-compatible but provenance-rejected

Both must pass for collection to proceed. Preflight displays both axes independently.

### 3.6 Scope Split: adapters check vs preflight

- `mseco adapters check`: Validates against code-owned `MODULE_POLICY` only. No config
  overrides. Answers: "is this module installed and does it satisfy baseline policy?"
- `mseco preflight <config.yaml>`: Validates against effective policy (code defaults
  merged with `ModulePolicyOverride` from config). Policy-complete gate.
- `collect()`: Same effective policy as preflight. Enforcement gate.

The `check_prerequisites()` protocol method takes no config (backward compatibility
with non-PowerShell adapters). `adapters check` is honestly a subset and documents
this in its help text.

### 3.7 Transitive Dependencies

`RequiredModules` entries (e.g., `Microsoft.Graph.Authentication`, `Pester`) are logged
in the verification report for audit but not blocked or verified. This matches reality:
Maester declares `RequiredModules` for `Microsoft.Graph.Authentication` and `Pester`.
These are PowerShell-managed transitive dependencies outside the collector module's tree.
A follow-up issue should be filed for transitive module provenance.

## 4. Policy Schema

### 4.1 Code-Owned Policy

```python
@dataclass(frozen=True)
class SignerIdentity:
    """Structured signer identity -- full subject + issuer via certificate API."""
    subject: str    # Exact string from .SignerCertificate.Subject, trimmed
    issuer: str     # Exact string from .SignerCertificate.Issuer, trimmed

@dataclass(frozen=True)
class ModulePolicy:
    """Code-owned approved-module policy. Adapters define these as constants."""
    module_name: str                            # Exact PowerShell module name
    version_range: str                          # Semver constraint, X.Y.Z only
    allowed_signers: frozenset[SignerIdentity]   # Non-empty
    approved_package_hashes: frozenset[str]      # Non-empty, typed "sha256tree:v1:<hex>"
    allow_package_hash_fallback: bool            # True only when hashes are non-empty
```

Construction invariants (enforced at policy creation):

- `allowed_signers` must be non-empty
- `approved_package_hashes` must be non-empty
- All hashes must be prefixed `sha256tree:v1:`
- If `allow_package_hash_fallback` is True, `approved_package_hashes` must be non-empty
- If `allow_package_hash_fallback` is False, `approved_package_hashes` must be non-empty
  (hash is always required for integrity; the flag controls whether hash alone is
  sufficient or whether signature is also needed)
- `version_range` must parse as valid X.Y.Z semver constraints

### 4.2 Approval Logic

A candidate is approved when ALL of:

1. Module name matches exactly
2. Version is valid X.Y.Z and satisfies `version_range`
3. Platform compatibility satisfied (`CompatiblePSEditions`, `PowerShellVersion`)
4. Manifest confinement check passed (all referenced files under `ModuleBase`)
5. No reparse points (symlinks, junctions) in module tree
6. Tree hash of staged copy matches an entry in `approved_package_hashes`
7. **Either**:
   - (a) Valid Authenticode signature on the staged `.psd1`, AND signer (subject +
     issuer) matches an entry in `allowed_signers` -> evidence path: `signature_and_hash`
   - **OR**
   - (b) `allow_package_hash_fallback` is True -> evidence path: `hash_only`
8. Exactly one candidate passes all checks (ambiguity = always reject, hardcoded
   invariant)

### 4.3 Config Override

```python
class ModulePolicyOverride(BaseModel):
    """Optional config narrowing. Can restrict, never widen."""
    version_range: str | None = None
    pinned_package_hashes: frozenset[str] | None = None
```

Merge rules:

- `version_range`: limited to exact-version pins (`==X.Y.Z`). Validated at config load
  that the pinned version satisfies the code default range.
- `pinned_package_hashes`: every entry must exist in code-owned
  `approved_package_hashes`. Restricts which approved states are accepted. `None` = use
  code default. Empty set = validation error at config load.
- Override cannot touch `allowed_signers`, `allow_package_hash_fallback`, or
  `module_name`.

## 5. Verification Pipeline

### 5.1 Phase Overview

All phases execute within a single PowerShell invocation. Dynamic data is passed via a
JSON input file -- no string substitution in the template.

| Phase | Location | Purpose |
|-------|----------|---------|
| 1 | Live | Discover candidates (`Get-Module -ListAvailable`), filter to `.psd1` manifest modules, check version |
| 1.5 | Live | Platform compatibility check (`CompatiblePSEditions`, `PowerShellVersion`) |
| 2 | Live | Reparse point scan (all items, files AND directories, `-Force`) |
| 3 | Live | Signature check on `.psd1` (informational only, logged, not authoritative) |
| 4 | Live -> Staged | Pure PowerShell enumerate-and-copy to per-candidate staging directory |
| 5 | Staged | Manifest confinement check |
| 6 | Staged | Reparse point scan (defense in depth) |
| 6.5 | Staged | Signature check on staged `.psd1` (authoritative -- determines evidence path) |
| 7 | Staged | Tree hash computation (`sha256tree:v1`) |
| 8 | -- | Approval logic, write verification report JSON |
| 9 | Staged | `Import-Module` staged `.psd1`; structured tool invocation (collection mode only) |

### 5.2 Candidate Discovery (Phase 1)

```powershell
$candidates = @(Get-Module -ListAvailable -Name $moduleName)
```

The `@()` wrapper forces an array even for single results. Each candidate is filtered:

- Reject if `Path` does not end in `.psd1` (non-manifest modules are not candidates)
- Reject if `Version.ToString()` does not parse as X.Y.Z (logged, not an error -- reduces
  candidate set)
- Reject if version is outside the policy's `version_range`

Remaining candidates proceed to subsequent phases. All candidates (including rejected)
appear in the verification report with their rejection reasons.

### 5.3 Platform Compatibility (Phase 1.5)

Read `CompatiblePSEditions` and `PowerShellVersion` from each candidate's manifest. If
the current PowerShell edition/version doesn't satisfy those constraints, the candidate
is flagged as `platform_incompatible`. This is a separate rejection category from
provenance failure.

In preflight, provenance phases (5-7) still run for platform-incompatible candidates to
provide visibility. The operator sees both "won't run here" and "provenance status."

### 5.4 Live Reparse Point Scan (Phase 2)

Enumerate ALL items under `ModuleBase` using `Get-ChildItem -Recurse -Force`. Check
`.Attributes -band [IO.FileAttributes]::ReparsePoint` on every item (files AND
directories). Any reparse point -> reject candidate immediately.

### 5.5 Live Signature Check (Phase 3)

`Get-AuthenticodeSignature` on the live `.psd1`. This is **informational only** -- the
result is logged and included in the report but does not contribute to the evidence path
label. On Linux/macOS, `Get-AuthenticodeSignature` is unavailable; report
`signature_status = "platform_unsupported"`.

### 5.6 Staging (Phase 4)

Copy the entire `ModuleBase` directory to a per-candidate staging directory:

```
<temp_dir>/candidates/0/   # First candidate
<temp_dir>/candidates/1/   # Second candidate (if multiple version-matched)
```

The copy uses pure PowerShell/.NET enumerate-and-copy:

```powershell
# For each directory: [IO.Directory]::CreateDirectory($stagedPath)
# For each file: [IO.File]::Copy($sourcePath, $stagedPath, $false)
```

No `Copy-Item -Recurse` (follows junctions). No `robocopy` (non-standard exit codes,
external dependency). The reparse point rejection in Phase 2 ensures the tree is clean
before copying.

### 5.7 Manifest Confinement Check (Phase 5)

Parse the staged `.psd1` using `Import-PowerShellDataFile`. For each of the following
active load inputs:

| Manifest key | Value type | Rule |
|---|---|---|
| `RootModule` | File path (`.psm1`, `.dll`, `.cdxml`) | Must resolve under staged `ModuleBase` |
| `RootModule` | Bare name (no extension, no separator) | Reject |
| `NestedModules` | File path | Must resolve under staged `ModuleBase` |
| `NestedModules` | Bare module name | Reject |
| `NestedModules` | Module specification (`@{ModuleName=...}`) | Reject |
| `RequiredAssemblies` | File path (`.dll`) | Must resolve under staged `ModuleBase` |
| `RequiredAssemblies` | GAC assembly name | Reject |
| `ScriptsToProcess` | File path (`.ps1`) | Must resolve under staged `ModuleBase` |
| `RequiredModules` | Any | Logged for audit, not blocked |

Resolution rule: relative paths resolve against the staged module root. Absolute paths
must be under the staged module root. Any path that escapes via `..`, absolute path
outside the tree, or UNC path causes immediate rejection with a specific confinement
violation message naming the key and offending path.

Empty or `$null` values are ignored (not a violation).

### 5.8 Staged Reparse Point Scan (Phase 6)

Same check as Phase 2 but on the staged copy. Defense in depth -- should be clean, but
verified.

### 5.9 Staged Signature Check (Phase 6.5)

`Get-AuthenticodeSignature` on the staged `.psd1`. This is the **authoritative** check
that determines the evidence path label. If status is `Valid` and signer matches the
allowlist -> `signature_and_hash`. Otherwise -> `hash_only` (if hash fallback is allowed
by policy).

On Linux/macOS: `signature_status = "platform_unsupported"`, evidence path defaults to
`hash_only`.

### 5.10 Tree Hash (Phase 7)

Scheme: `sha256tree:v1`

1. `Get-ChildItem -Recurse -File -Force` on the staged directory
2. Reparse point check again (defense in depth)
3. Reject symlinks, junctions, reparse points, non-regular files (fail closed)
4. Sort by forward-slash-normalized relative path, lexicographic
5. Per-file: SHA-256 of raw bytes
6. Concatenate: `relative/path\0<sha256hex>\n` for each file
7. Final: `sha256tree:v1:` + SHA-256 of the concatenation

### 5.11 Approval and Report (Phase 8)

Apply the approval logic from Section 4.2. Write the full verification report JSON to
the Python-owned temp file. This write happens ALWAYS, whether approved or rejected.

### 5.12 Structured Post-Import Invocation (Phase 9, Collection Mode Only)

If approved, import the staged module and invoke the tool command. The tool command is
passed as structured data in the JSON input blob, not as a raw command string:

```json
{
  "post_import_invocation": {
    "command_name": "Invoke-SCuBA",
    "named_args": {
      "OutPath": "/path/to/output",
      "ProductNames": ["AAD", "EXO"]
    },
    "switches": {}
  }
}
```

The template invokes via splatting:

```powershell
$params = @{}
foreach ($key in $input.post_import_invocation.named_args.PSObject.Properties) {
    $params[$key.Name] = $key.Value
}
foreach ($key in $input.post_import_invocation.switches.PSObject.Properties) {
    if ($key.Value -eq $true) { $params[$key.Name] = $true }
}
& $input.post_import_invocation.command_name @params
```

Rules:

- `command_name` must be in the adapter's per-adapter allowlist (validated Python-side
  before writing the blob)
- `Invoke-Expression` is never used in the template
- `named_args` are key-value pairs (string or string-array values only)
- `switches` are explicit booleans
- The `&` call operator with splatting executes without string interpolation

Per-adapter allowed commands:

- ScubaGear: `frozenset({"Invoke-SCuBA"})`
- Maester: `frozenset({"Invoke-Maester"})`

### 5.13 Static Template + JSON Input

The PowerShell verification script is a static `.ps1` template. All dynamic data is
passed via a JSON input file:

```powershell
param([string]$InputPath)
$input = Get-Content -Path $InputPath -Raw | ConvertFrom-Json
```

Invoked as:

```python
cmd = [exe, "-NoProfile", "-NonInteractive", "-File", template_path,
       "-InputPath", str(input_path)]
```

No string substitution, no quoting bugs, no injection surface.

## 6. Python-Side Post-Invocation

Regardless of subprocess exit code, Python always:

1. Reads the verification report from the temp file
   - Missing report -> `VerificationInfrastructureError` (with exit code, stderr, path)
   - Empty report -> `VerificationInfrastructureError`
   - Malformed JSON -> `VerificationInfrastructureError`
   - Valid report with `can_execute=False` -> appropriate `ModuleVerificationError` subclass
   - Valid report with `can_execute=True` + non-zero exit -> `CollectionError` (tool failed)
   - Valid report with `can_execute=True` + zero exit -> success
2. Parses into `ModuleVerificationResult`
3. Logs provenance event (see Section 8)
4. Attaches `result.to_json_dict()` to `execution_metadata["module_provenance"]`
5. Cleans up temp directory (including staged module copy) in a `finally` block

## 7. Result Types

All verification DTOs live in `core/contracts/verification.py` (neutral location, no
cross-layer dependencies).

### 7.1 CandidateOutcome

```python
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
    rejection_category: Literal[
        "platform_incompatible",
        "version_mismatch",
        "confinement_violation",
        "hash_rejected",
        "signature_rejected",
        None,
    ]

    confinement_violation: str | None
    package_hash: str | None              # "sha256tree:v1:<hex>"
    hash_approved: bool

    live_signature_status: str | None
    live_signer_subject: str | None
    live_signer_issuer: str | None
    live_signer_thumbprint: str | None

    staged_signature_status: str | None
    staged_signer_subject: str | None
    staged_signer_issuer: str | None
    staged_signer_thumbprint: str | None
    staged_signer_approved: bool | None

    evidence_path: Literal["signature_and_hash", "hash_only"] | None
```

### 7.2 ModuleVerificationResult

```python
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
        ...
```

### 7.3 Preflight Display Type

```python
@dataclass
class PreflightCheckResult:
    """Single preflight check outcome for display."""
    check: str
    status: Literal["PASS", "WARN", "FAIL"]
    message: str
    provenance: ModuleVerificationResult | None = None
```

Replaces the current `list[dict[str, str]]` contract in `cli/output.py`.

## 8. Error Hierarchy

Additions to `core/contracts/errors.py`:

```python
class ModuleVerificationError(PrerequisiteError):
    """Module provenance verification failed."""
    def __init__(
        self,
        message: str,
        adapter_name: str = "",
        engagement_id: str = "",
        verification_result: ModuleVerificationResult | None = None,
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
        verification_result: ModuleVerificationResult | None = None,
        exit_code: int | None = None,
        stderr_snippet: str | None = None,
        report_path: str | None = None,
    ) -> None:
        self.exit_code = exit_code
        self.stderr_snippet = stderr_snippet
        self.report_path = report_path
        super().__init__(message, adapter_name, engagement_id, verification_result)
```

The `ModuleVerificationResult` on the exception is authoritative. Exception subclasses
are routing signals for control flow:

- `ModuleProvenanceError`: `provenance_approved=False`
- `ModuleExecutionUnsupportedError`: `execution_supported=False` AND
  `provenance_approved=True`
- `ModuleAmbiguityError`: multiple candidates passed (subcase of provenance failure)
- `VerificationInfrastructureError`: verification couldn't complete

When both axes fail, `ModuleProvenanceError` is raised (provenance is the security
concern). The `verification_result` shows both axes failed.

## 9. Logging

Every verification produces a structured log event before any import or execution.

**Approval (signature_and_hash) -- INFO**:
```
[ScubaGear] Module approved (signature_and_hash): version=1.5.2,
  live_path=/path/to/ScubaGear.psd1,
  staged_path=/tmp/.../candidates/0/ScubaGear.psd1,
  hash=sha256tree:v1:abc123...,
  signer=CN=..., thumbprint=ABC123...,
  pwsh=/usr/bin/pwsh, candidates_discovered=1
```

**Approval (hash_only, platform lacks signature support) -- INFO**:
```
[ScubaGear] Module approved (hash_only): version=1.5.2,
  live_path=..., staged_path=..., hash=sha256tree:v1:abc123...,
  signature_status=platform_unsupported,
  pwsh=/usr/bin/pwsh, candidates_discovered=1
```

**Approval (hash_only, signature available but failed) -- WARNING**:
```
[ScubaGear] Module approved (hash_only, degraded): version=1.5.2,
  live_path=..., staged_path=..., hash=sha256tree:v1:abc123...,
  signature_status=NotSigned,
  pwsh=/usr/bin/pwsh, candidates_discovered=1
```

WARNING only when signature verification should have worked but didn't. INFO when
hash-only is the policy-backed normal path on an unsupported platform.

**Rejection -- ERROR**:
```
[ScubaGear] Module REJECTED: <reason>,
  candidates_discovered=2, per-candidate details follow
```

Rejection always logs before raising the exception. If collection fails before
`RawToolOutput` is created, the log record still exists.

**In execution_metadata**: `result.to_json_dict()` is stored in
`execution_metadata["module_provenance"]`. Persists: live manifest path, live module
root, staged manifest path, staged module root, package hash, evidence path, live and
staged signature details, thumbprint, and PowerShell executable path.

## 10. Preflight Behavior

| Condition | Status | Display |
|-----------|--------|---------|
| `provenance_approved=True`, `execution_supported=True` | PASS | Version, evidence path, hash, signer (if available) |
| `provenance_approved=True`, `execution_supported=False`, tool enabled | FAIL | "Provenance approved, requires PowerShell Desktop 5.1" |
| `provenance_approved=False` | FAIL | Rejection reason, per-candidate details |
| Ambiguity (multiple approved candidates) | FAIL | Candidate count, per-candidate details |
| No candidates found | FAIL | "No installed versions match policy range" |
| Infrastructure failure | FAIL | Exit code, stderr snippet, report path |

Preflight calls the verifier directly (not via `check_prerequisites()`) for the full
`ModuleVerificationResult`. Single call, no duplication.

Non-PowerShell adapters continue to use `check_prerequisites()` as before.

## 11. Hash Update Workflow

When upstream ships a new module version:

1. Install the new version in a controlled environment
2. Run: `mseco compute-module-hash --manifest-path /path/to/Module/X.Y.Z/Module.psd1`
3. The command derives `ModuleBase` from the manifest path, runs reparse point scan,
   confinement check, and tree hash computation
4. Review the output: hash, module name, version, path, confinement results
5. Update the adapter's `policy.py` with the new hash and version range
6. PR review and merge

The command requires `--manifest-path` (exact `.psd1` path). No module-name resolution,
no version guessing. This prevents approving the wrong version when multiple are
installed.

Golden-vector tests ensure the Python hash utility and the PowerShell verifier produce
identical `sha256tree:v1` values for the same directory structure.

## 12. Tree Hash Specification

Scheme: `sha256tree:v1`

1. Enumerate all items in the module directory recursively (including hidden items)
2. Reject any item (file or directory) with the `ReparsePoint` attribute
3. Select only regular files
4. Sort by relative path (forward-slash normalized, lexicographic)
5. Per-file: SHA-256 of raw bytes
6. Concatenate entries: `relative/path\0<sha256hex>\n`
7. SHA-256 of the concatenation
8. Prefix: `sha256tree:v1:<hex>`

The scheme version (`v1`) means file-selection rules, path normalization, and hash
algorithm can be revised in a future version without silently invalidating existing
hashes.

## 13. Test Strategy

### 13.1 Unit: Policy Construction and Validation

`tests/unit/adapters/test_module_policy.py`

- `ModulePolicy` construction invariants: non-empty signers, non-empty hashes, hash
  prefix validation, fallback consistency
- `ModulePolicyOverride` validation: exact-version pin satisfies code default range,
  `pinned_package_hashes` subset of approved hashes, empty set rejected
- Policy merge logic: override narrows effective policy correctly
- Invalid policy construction raises at creation time

### 13.2 Unit: Verification Report Parsing

`tests/unit/adapters/test_verification_report.py`

- Valid report JSON parses into `ModuleVerificationResult`
- Missing report -> `VerificationInfrastructureError` (with exit code, stderr, path)
- Empty report -> `VerificationInfrastructureError`
- Malformed JSON -> `VerificationInfrastructureError`
- Missing required fields -> `VerificationInfrastructureError`
- Per-candidate outcome parsing: all rejection categories

### 13.3 Unit: Approval Logic

`tests/unit/adapters/test_approval_logic.py`

Parametric tests covering the decision matrix:

| Version | Hash | Staged sig | Fallback | Provenance | Execution | Evidence |
|---------|------|-----------|----------|------------|-----------|----------|
| match | approved | Valid+match | -- | approved | supported | sig+hash |
| match | approved | NotSigned | True | approved | supported | hash_only |
| match | approved | NotSigned | False | rejected | supported | -- |
| match | approved | unsupported | True | approved | supported | hash_only |
| match | approved | Valid+mismatch | True | approved | supported | hash_only |
| match | not approved | Valid+match | -- | rejected | supported | -- |
| match | not approved | NotSigned | True | rejected | supported | -- |
| mismatch | -- | -- | -- | rejected | -- | -- |
| no candidates | -- | -- | -- | rejected | -- | -- |
| 2 approved | -- | -- | -- | rejected (ambiguity) | -- | -- |
| match | approved | Valid+match | -- | approved | incompatible | sig+hash |

Additional cases:

- Non-X.Y.Z version -> candidate skipped
- Confinement violation (RootModule escapes ModuleBase) -> rejected
- Confinement violation (bare module name in NestedModules) -> rejected
- Both axes fail -> `ModuleProvenanceError` raised

### 13.4 Unit: Tree Hash

`tests/unit/adapters/test_tree_hash.py`

- Known directory structure produces expected hash
- File ordering is deterministic
- Symlink in tree -> rejection
- Reparse point directory -> rejection
- Empty directory -> valid hash
- Hash scheme prefix is `sha256tree:v1:`

### 13.5 Unit: Script Builder

`tests/unit/adapters/test_verification_script.py`

- Builds valid PowerShell for preflight mode (no import/execute)
- Builds valid PowerShell for collection mode (with import/execute)
- JSON input blob is well-formed
- `command_name` validated against adapter allowlist
- Rejected command name raises before script execution

### 13.6 Integration: End-to-End Verification

`tests/integration/test_module_verification.py`

Requires `pwsh` on PATH (skipped via `pytest.mark.skipif` when unavailable).

- `PSModulePath` set to a temp fixture root for isolation (no host contamination)
- Install a test PowerShell module (minimal `.psd1` + `.psm1`) to the fixture root
- Run full verification in preflight mode
- Verify report matches expected structure
- Test with tampered `.psm1` (hash mismatch)
- Test with multiple installed versions (ambiguity)
- Test with confinement-violating manifest
- Test with non-X.Y.Z version

### 13.7 Golden-Vector Hash Parity

`tests/fixtures/module_hash_vectors/`

A version-controlled fixture directory with known file structure and contents. Both the
Python `compute-module-hash` utility and the PowerShell verifier script compute the hash.
The test asserts identical `sha256tree:v1` values. If either implementation's path
normalization or hashing diverges, the test fails.

### 13.8 Adapter Tests

Extend existing `tests/unit/adapters/test_scubagear.py` and `test_maester.py`:

- `collect()` uses `run_verified_powershell()`
- `check_prerequisites()` calls the verifier
- Mock subprocess returns include verification report JSON
- Approved and rejected scenarios
- `execution_metadata["module_provenance"]` populated and JSON-serializable

### 13.9 Preflight Tests

Extend existing `tests/unit/cli/test_preflight.py`:

- Structured provenance details rendered (version, evidence path, signer, hash)
- `ModuleExecutionUnsupportedError` on enabled tool -> FAIL
- `ModuleProvenanceError` -> FAIL with rejection reason
- Disabled tools not verified
- New `PreflightCheckResult` type used throughout

## 14. File Layout

### 14.1 New Files

```
src/gxassessms/
  adapters/
    _verification.py                  # verify_module(), script builder, report parser
    _verification_scripts/
      verify_module.ps1               # Static PowerShell template (Phases 1-9)
    scubagear/
      policy.py                       # MODULE_POLICY, approved hashes, allowed commands
    maester/
      policy.py                       # MODULE_POLICY, approved hashes, allowed commands

  core/
    contracts/
      verification.py                 # DTOs: ModulePolicy, SignerIdentity,
                                      #   ModuleVerificationResult, CandidateOutcome,
                                      #   ModulePolicyOverride, PreflightCheckResult

  cli/
    commands/
      compute_hash.py                 # mseco compute-module-hash --manifest-path

  reporting/
    _semver.py                        # Extracted semver utilities (shared)

tests/
  unit/adapters/
    test_module_policy.py
    test_verification_report.py
    test_approval_logic.py
    test_tree_hash.py
    test_verification_script.py
  integration/
    test_module_verification.py
  fixtures/
    module_hash_vectors/
```

### 14.2 Modified Files

```
src/gxassessms/
  adapters/
    _base.py                          # Add run_verified_powershell()
    scubagear/adapter.py              # check_prerequisites() calls verifier,
                                      #   collect() uses run_verified_powershell(),
                                      #   MODULE_POLICY constant reference
    maester/adapter.py                # Same changes as ScubaGear

  core/
    contracts/errors.py               # Add ModuleVerificationError subtree
    config/config.py                  # Add ModulePolicyOverride to ToolConfig
    domain/constants.py               # Add verification Literal types

  cli/
    commands/preflight.py             # Call verifier directly, use PreflightCheckResult
    output.py                         # PreflightCheckResult rendering, provenance display

  reporting/
    renderer_registry.py              # Delegate to _semver.py
```

### 14.3 Size Targets

`_verification.py` is the largest new file. If it approaches 400 lines, split:
- `_verification_script.py`: script builder
- `_verification_report.py`: report parser

`policy.py` per adapter is intentionally small (policy constants, approved hashes).
Changes to these files represent security-relevant decisions and should be easy to
review in PRs.

## 15. Operational Notes

### 15.1 Signature Expectations

For PSGallery catalog-signed modules, the expected evidence path is `hash_only`.
`signature_and_hash` is available for modules with embedded Authenticode signatures.
Documentation and preflight output should not imply stronger publisher assurance than
the staged artifact check actually delivers.

### 15.2 ScubaGear Platform Constraint

ScubaGear declares `CompatiblePSEditions = 'Desktop'` and `PowerShellVersion = '5.1'`.
It is only executable on Windows PowerShell 5.1. On Linux/macOS with `pwsh` (PowerShell
Core), ScubaGear will be `provenance_approved=True, execution_supported=False`. This
is surfaced as a FAIL in preflight if the tool is enabled.

### 15.3 Maester Cross-Platform

Maester declares `CompatiblePSEditions = 'Core', 'Desktop'`. It works on both Windows
PowerShell and PowerShell Core (Linux/macOS).
