# Changelog

All notable changes to this project will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
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
