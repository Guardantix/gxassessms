# Changelog

All notable changes to this project will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
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

### Changed
- `mseco preflight` now runs module provenance verification for PowerShell adapters
  (using effective policy with config overrides).
- `mseco adapters check` now runs baseline provenance verification for PowerShell
  adapters (code-owned policy only, no config overrides).
- ScubaGear and Maester `collect()` now use `run_verified_powershell()` instead of
  `run_powershell()`.
