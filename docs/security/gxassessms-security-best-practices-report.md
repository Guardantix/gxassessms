# GxAssessMS Security Best Practices Assessment

## Executive Summary

This assessment reviewed the current `gxassessms` codebase against Python/JavaScript secure coding practices, the existing threat model in `docs/security/gxassessms-threat-model.md`, and external guidance available through the `context` MCP (OWASP Cheat Sheets, OWASP Testing Guide, CWE, and CIS Controls v8.1).

The strongest controls already in the repo are input-safe YAML parsing, parameterized SQL, explicit path-traversal checks inside artifact management, `tarfile.extractall(..., filter="data")` during restore, and PowerShell execution with `shell=False` plus an allowlist for extra arguments.

The highest-risk gaps are at local trust boundaries rather than HTTP-facing attack surface. The most important issues are:

1. Replay trusts persisted manifest file paths and can be redirected to out-of-scope files.
2. Entry-point plugins and renderers are trusted too broadly, and render execution ignores configured format/theme intent.
3. Sensitive artifacts and rendered reports rely on ambient filesystem permissions and a default `output/` directory in the current working directory.
4. Replay and rendering have no explicit size ceilings, so malformed or oversized artifacts can exhaust memory, disk, or render time.

No critical internet-facing vulnerability was identified because this repo is a local CLI/orchestration tool, not a network service. The main risks are integrity loss, local disclosure, and local code execution through trusted extension paths.

## Scope and Method

- Reviewed code under `src/gxassessms`, `report-renderers/basic`, and `docs/security/gxassessms-threat-model.md`.
- Prioritized collection, replay, persistence, plugin loading, rendering, and filesystem trust boundaries.
- Cross-checked findings against `context` MCP references:
  - `owasp-cheatsheets@1.0.0`: input validation, file handling, OS command injection, logging, cryptographic storage
  - `owasp-testing-guide@1.0.0`: directory traversal testing guidance
  - `cwe@1.0.0`: path traversal weaknesses
  - `cis-controls@v8.1`: software inventory and allowlisting safeguards
- Spot-checked existing tests around artifacts, replay, and rendering.

## High Severity Findings

### SBP-001: Replay accepts attacker-controlled file paths from persisted manifests

**Status: REMEDIATED** (PR #47, branch `security/replay-manifest`, 2026-04-03)

**Original impact:** A local attacker who can modify persisted raw-output manifests can cause replay to read JSON files outside the engagement root, leading to report integrity loss and limited local file disclosure under the analyst account.

**Why this matters**

OWASP secure code review guidance and CWE path-traversal guidance both call out unsafe file path construction and missing canonical path validation as a primary class of file handling vulnerability.

**Remediation implemented**

All three recommended mitigations are now in place:

1. **Relative paths only:** Manifests (`raw-output/manifests/<slug>.json`) store only canonical POSIX-relative paths. `RawToolOutput` field validators enforce this via `validate_canonical_posix_path()` in `src/gxassessms/core/domain/path_validation.py`. Absolute paths, backslashes, parent traversal, and Windows reserved names are all rejected.

2. **Path confinement at replay:** `confine_and_resolve()` in `src/gxassessms/pipeline/confinement.py` performs 9 sequential security checks before any adapter method runs: manifest version gate, three-way slug match (filename/field/adapter), canonical path format, tool-slug path prefix, strict resolve, tool-subtree containment (rejects cross-tool symlink escape), file type check, SHA-256 verification, and duplicate resolution detection. The artifacts root itself is checked for symlink redirection before any per-path checks.

3. **Content hash binding:** SHA-256 hashes are recorded at collection time in `ArtifactRecord.sha256`, verified at copy time during persistence, and re-verified at replay time by `confine_and_resolve()`. Shared hashing utility: `src/gxassessms/core/hashing.py::sha256_file`.

**Residual risk:** An attacker with write access who replaces both the manifest and the referenced artifact with matching SHA-256 hashes will not be detected. Detecting this requires an external trust root (signatures, HMAC, or separate digest store) -- tracked as a remaining gap in TM-003.

**Test coverage**

- `tests/unit/pipeline/test_confinement.py`: 335 lines covering all 9 confinement checks including symlink escape, hash mismatch, and cross-tool containment.
- `tests/unit/core/test_path_validation.py`: 151 lines covering canonical path validation including reserved names, illegal characters, and normalization.
- `tests/integration/test_replay_equivalence.py`: End-to-end live/replay equivalence test.

### SBP-002: Plugin and renderer trust is too broad, and render execution ignores configured report intent

**Impact:** Any malicious or compromised package exposing the expected entry points can execute inside the trusted assessment workflow; in the render path this code receives the full report payload plus the config snapshot, and every discovered renderer is executed whether or not the operator intended to use it.

**Why this matters**

CIS Controls v8.1 emphasizes software inventory, authorized software, library allowlisting, and script allowlisting. GxAssessMS currently discovers and executes plugins from Python entry points without an allowlist, provenance check, or "trusted plugins only" mode. The risk is amplified because render execution is broader than the config suggests.

**Evidence**

- Entry points are loaded directly with `ep.load()` in `src/gxassessms/registry.py:84-127`.
- Generic plugin helpers instantiate discovered classes with no allowlist or signature check:
  - `src/gxassessms/cli/_helpers.py:187-248`
  - `src/gxassessms/cli/_helpers.py:251-274`
- The normal `run` path passes all discovered renderers into the pipeline in `src/gxassessms/cli/commands/run.py:166-175`.
- The render stage invokes every renderer it receives in `src/gxassessms/pipeline/stages.py:323-345`.
- The config surface suggests operator intent can constrain reporting:
  - `report_formats` and `report_theme` exist in `src/gxassessms/core/config/config.py:67-70`
  - but they are not used to filter renderers before execution.
- The render payload includes `config_snapshot`, which is inserted into payload metadata in:
  - `src/gxassessms/pipeline/_runner.py:481-489`
  - `src/gxassessms/reporting/payload.py:88-100`
- Node renderers then receive that payload over the process boundary in `src/gxassessms/reporting/renderer_registry.py:201-233`.

**Behavioral confirmation**

- `tests/unit/cli/test_helpers.py:304-337` expects `discover_all_plugins()` to instantiate all discovered plugins.
- `tests/unit/pipeline/test_stages.py:428-478` expects `render()` to delegate to every renderer in the provided list.

**What is missing**

- An allowlist of approved adapter, policy, QA, and renderer packages.
- Verification of package provenance, version pinning, or package integrity.
- Runtime filtering that maps `report_formats` and `report_theme` to the renderer set actually executed.
- A safer default that refuses third-party renderers unless explicitly enabled.

**Recommended remediation**

- Add a "trusted plugins only" mode with explicit package and entry-point allowlists.
- Log plugin name, version, and filesystem path at startup, and fail closed on unexpected providers in production mode.
- Filter renderers by configured format/theme before any renderer is instantiated or executed.
- Consider isolating renderer execution in a dedicated low-privilege account or container.

### SBP-003: Sensitive artifacts depend on ambient filesystem permissions and default report output lands in the working directory

**Status: REMEDIATED** (branch `security/lifecycle-guardrails`)

**Original impact:** On shared hosts, permissive workspaces, or weak backup policies, customer-sensitive findings, reports, archives, and config snapshots can be exposed to other local users or processes.

**Why this matters**

OWASP cryptographic storage guidance stresses layered protection for data at rest. This repo stores sensitive assessment data locally but does not harden directory permissions, warn on broad access, or keep rendered output inside the main protected data root by default.

**Remediation implemented**

All four recommended mitigations are now in place:

1. **Restrictive directory permissions:** All directory creation now goes through `secure_mkdir()` in `src/gxassessms/core/security/permissions.py`, which enforces `0o700` on POSIX systems after creation. On Windows, NTFS ACL inheritance is relied upon. A convention test (`tests/conventions/test_mkdir_conventions.py`) bans bare `mkdir()` calls in source code.

2. **Engagement-rooted report output:** The default report output path changed from `Path("output")` (current working directory) to `<engagement_dir>/reports/`, which lives under the protected engagement data root. Operators can still override with an explicit `output_dir`.

3. **Permission warnings:** The CLI warns at runtime when the engagement data root or engagement directories have group- or world-accessible bits set. Warnings appear before archive, restore, purge, and export operations and during pipeline initialization.

4. **Lifecycle audit enrichment:** All lifecycle operations (archive, restore, purge) now write JSON audit manifests capturing hostname, OS user, PID, platform, and operator. Export operations log equivalent context. See `docs/security/shared-host-deployment.md` for deployment guidance.

**Test coverage:**
- `tests/unit/core/test_permissions.py`: Permission hardening and broad-access detection
- `tests/unit/core/test_audit_context.py`: Audit context generation with failure fallbacks
- `tests/unit/persistence/test_artifacts.py`: Lifecycle audit manifest creation and GDPR ordering
- `tests/conventions/test_mkdir_conventions.py`: Convention test banning bare mkdir() calls

<details>
<summary>Original analysis (now addressed)</summary>

**Evidence**

- Default storage root is `~/.gxassessms` in `src/gxassessms/persistence/database.py:24-45`.
- Data and engagement roots are created with default `mkdir()` behavior and no explicit mode hardening:
  - `src/gxassessms/persistence/database.py:75-80`
  - `src/gxassessms/cli/_helpers.py:37-40`
  - `src/gxassessms/cli/_helpers.py:63-71`
  - `src/gxassessms/persistence/artifacts.py:88-90`
  - `src/gxassessms/persistence/artifacts.py:229`
- Report rendering defaults to `Path("output")` in the current working directory in `src/gxassessms/pipeline/_runner.py:188-196`.
- Renderer output directories are then created without permission hardening in `src/gxassessms/reporting/renderer_registry.py:192-193`.

**What is missing**

- Explicit `0700` permissions for data, engagement, audit, and report directories.
- Warnings when the chosen storage root or output directory is group/world accessible.
- A secure default that keeps reports under the main data root unless the operator overrides it intentionally.

**Recommended remediation**

- Apply restrictive directory permissions at creation time and verify them during preflight.
- Default report output to an engagement-specific directory under the main data root rather than `./output`.
- Add a preflight warning when data roots or output paths resolve to shared mounts, workspace directories, or weakly permissioned locations.

</details>

## Medium Severity Findings

### SBP-004: Replay and rendering do not enforce artifact or payload size limits

**Impact:** Oversized raw artifacts or unusually large report payloads can exhaust memory, disk, or renderer time and delay or halt delivery.

**Why this matters**

OWASP input-validation and file-handling guidance recommends explicit size limits and early rejection of unexpectedly large inputs. In this repo, replay, JSON parsing, payload assembly, and document rendering all assume inputs are reasonably sized.

**Evidence**

- Raw JSON files are read fully into memory with `read_text()` and parsed with `json.loads()` in `src/gxassessms/adapters/_base.py:207-223`.
- Replay manifests are also read fully in `src/gxassessms/pipeline/replay.py:69-73`.
- The full report payload is serialized to JSON before render in `src/gxassessms/reporting/renderer_registry.py:201-205`.
- The Node renderer reads the entire payload JSON with `fs.readFileSync()` and renders the whole document into a single buffer with `Packer.toBuffer()` in `report-renderers/basic/render.js:48-58` and `report-renderers/basic/render.js:125-133`.

**What is missing**

- Maximum manifest size, result-file size, finding-count, or payload-size thresholds.
- Preflight checks for available disk space before rendering.
- Streaming or chunked parsing for large raw results where practical.

**Recommended remediation**

- Enforce explicit size ceilings for replay manifests, result JSON files, and report payloads.
- Reject or quarantine artifacts that exceed expected bounds before parsing.
- Log artifact sizes and render payload sizes so repeated threshold hits are visible operationally.

## Positive Controls Already Present

- YAML config is parsed with `yaml.safe_load` and then validated with Pydantic models that forbid extra keys in `src/gxassessms/core/config/config.py:20-29`, `src/gxassessms/core/config/config.py:46-61`, and `src/gxassessms/core/config/config.py:98-121`.
- PowerShell execution uses `shell=False`, a fixed executable, and an allowlist for extra arguments in `src/gxassessms/adapters/_base.py:25-27`, `src/gxassessms/adapters/_base.py:44-65`, and `src/gxassessms/adapters/_base.py:97-115`.
- Artifact management already performs canonical path checks with `resolve()` and `is_relative_to()` in `src/gxassessms/persistence/artifacts.py:41-53`.
- Archive restore uses `tar.extractall(..., filter="data")`, which is materially safer than raw extraction, in `src/gxassessms/persistence/artifacts.py:167-170`.
- SQL writes are parameterized throughout the repositories; the one formatted table name in `src/gxassessms/persistence/engagement_repo.py:149-162` iterates a fixed internal table list, not attacker input.

## Verification Notes

- I reviewed the existing threat model in `docs/security/gxassessms-threat-model.md` as the initial map, then re-validated each finding against current code rather than treating that document as authoritative.
- I attempted a targeted test run for security-relevant paths. Two environment issues affected automated verification:
  - the repo's default `pytest` options require the coverage plugin, which is not installed in this environment;
  - after overriding `addopts`, test collection still failed because `src/gxassessms/reporting/renderer_registry.py:122` currently contains invalid multi-exception syntax.
- That syntax issue is a correctness problem, not part of the security findings above, but it does reduce confidence in automated validation of the renderer path until fixed.

## Priority Order

1. ~~Fix replay path confinement and hash binding first.~~ **DONE** (PR #47, SBP-001 remediated)
2. ~~Pin approved PowerShell module versions and verify publisher or signature before collection runs.~~ **Addressed**: Module provenance verification implemented (version range pinning, sha256tree:v1 tree hash, Authenticode signature, TOCTOU-eliminating staging). See `src/gxassessms/adapters/_verification.py` and `docs/superpowers/specs/2026-04-03-powershell-module-provenance-design.md`. Remaining gap: transitive dependency verification (RequiredModules logged but not blocked).
3. Add plugin and renderer allowlisting plus config-based renderer filtering.
4. ~~Harden artifact/report directory permissions and move default report output under the protected data root.~~ **DONE** (branch `security/lifecycle-guardrails`, SBP-003 remediated)
5. Add artifact and payload size ceilings plus preflight checks.
