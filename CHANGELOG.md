# Changelog

All notable changes to this project will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed
- Manual DB-corruption recovery (runbook section 2, step 3) is now
  functional. `mseco replay` previously required an intact DB row; it
  now falls back to a filesystem-persisted `config_snapshot.json` mirror
  in the engagement directory. Engagements created before this release
  will not have the mirror file and must be rebuilt from the original
  engagement YAML after a DB wipe.

### Added
- `ArtifactManager.write_config_snapshot()` / `read_config_snapshot()`
  methods for atomic mirror write/read with 1 MB DoS ceiling.
- `pipeline/config_snapshot_mirror.py` module with
  `mirror_config_snapshot_from_db()` fail-open helper.
- `decode_config_snapshot()` helper in `persistence/engagement_repo.py`
  (consolidates three pre-existing inline decode sites).
- `ConfigSnapshotMirrorError` persistence exception (narrow subclass
  of `PersistenceError`, carries `engagement_id` attribute).
- Concrete type annotations on `cli/_helpers.py::get_engagement_repo()`
  and `get_artifact_manager()` (previously returned `Any`).
- **Shared HTTP adapter infrastructure** (`adapters/_http`): `check_python_packages`,
  `validate_auth_context`, and `fetch_paginated_json` for code reuse across API-based
  adapters. Includes SSRF-safe pagination origin validation and cycle detection.
- `subscription_id` config field (optional, `client` section): Azure subscription UUID
  for adapters targeting Azure resources (Prowler, Azure Advisor, SecureScore).
- `controls_dir` and `script_dir` tool config fields (optional): adapter-specific
  directories for control mappings or custom check scripts.
- `from_epoch()` datetime utility: converts Unix epoch seconds to UTC datetime for
  Azure token expiry handling.
- `SEVERITY_IDENTITY_MAP` constant: identity map for adapters that pre-compute
  domain-level severity in the parser (SecureScore, Azure Advisor).
- `native_category` field on `ToolObservation`: optional passthrough for tool-native
  category values (e.g., SecureScore `controlCategory`).
- `validate_config` now warns when `device_code` or `interactive` auth methods are
  configured with `client_secret_env` or `certificate_path` (which are ignored).
- Execution metadata allowlist entries for 5 new adapter slugs: monkey365,
  m365-assess, prowler, azure-advisor, secure-score.
- **Module provenance verification**: PowerShell modules (ScubaGear, Maester) are
  verified for version, integrity (sha256tree:v1 tree hash), and Authenticode signature
  before execution. Modules are staged to a private temp directory to eliminate TOCTOU
  races. Verification is fail-closed. (Addresses TM-001)
- `mseco compute-module-hash --manifest-path <path>`: Compute the sha256tree:v1 hash
  for a PowerShell module directory, for inclusion in adapter policy files.
- `module_policy_override` config option: Narrow module provenance policy per-tool
  (exact version pin, pinned hash subset). Cannot widen code-owned policy.
- Provenance details displayed in `mseco preflight` and `mseco adapters check` output.
- `ModuleVerificationError` exception hierarchy for granular provenance failure handling.

### Fixed
- Duplicate adapter `storage_slug` values in `confine_and_resolve()` now raise
  `ManifestConfinementError` (`adapter_slug_unique`) instead of silently dropping
  all but the last adapter.

### Changed
- `mseco replay` emits a `[yellow]Note:[/yellow] Replayed from filesystem
  config_snapshot (DB row was missing or unreadable).` DR-mode indicator
  on successful filesystem-fallback replays.
- `mseco engagement export` now uses the shared `decode_config_snapshot`
  helper (identical behavior; centralized error handling).
- Refactored `confine_and_resolve()` into focused validators for independent
  testability (no public API change).
- `mseco preflight` now runs module provenance verification for PowerShell adapters
  (using effective policy with config overrides).
- `mseco adapters check` now runs baseline provenance verification for PowerShell
  adapters (code-owned policy only, no config overrides).
- ScubaGear and Maester `collect()` now use `run_verified_powershell()` instead of
  `run_powershell()`.

### Security
- `mseco replay` validates `engagement_id` against `^[a-zA-Z0-9_-]+$`
  before any filesystem or DB access (CWE-22 path traversal, CWE-117
  log injection).
- `decode_config_snapshot` and `ArtifactManager.read_config_snapshot`
  enforce a 1 MB size ceiling on parse inputs (CWE-400 uncontrolled
  resource consumption).
- `_load_config_for_replay` sanitizes Pydantic `ValidationError` output
  to log only error count and field locations, preventing leakage of
  `tenant_id`, `client_id`, and `certificate_path` into operator logs
  (CWE-209 information exposure through error message).
- `ArtifactManager.write_config_snapshot` uses `os.open` with
  `O_CREAT | O_EXCL | mode=0o600` to close the write-then-chmod race
  window (CWE-732) and prevent silent overwrite of attacker-planted
  temp files (CWE-377).
