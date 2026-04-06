"""Prowler adapter module provenance policy.

Security-critical: changes to this file represent approved invocation states.
Review carefully in PRs.

Prowler provenance model
------------------------
Prowler is a pip-installed Python binary invoked as an external subprocess.
Unlike PowerShell module adapters (ScubaGear, Maester), there is no
cryptographic signing or catalog verification available for pip packages.

Provenance is verified by:
  1. Binary existence: shutil.which("prowler") at collect() time
  2. Version check: prowler --version in check_prerequisites()
  3. Invocation constraint: only the named binary on PATH is invoked,
     with shell=False and no PATH manipulation

Operator responsibility: ensure the Python environment where GxAssessMS
runs has a known-good Prowler installation. Pin Prowler to a specific
version in the deployment requirements file.

Version constraint
------------------
Prowler requires Python >= 3.10, <= 3.12 (separate venv from GxAssessMS).
Prowler >= 4.0 is required for OCSF Detection Finding JSON output
(-M json-ocsf flag).

See also: adapters/prowler/adapter.py::_SCHEMA_VERSION for the expected
OCSF metadata.version value.
"""

# Prowler does not use PowerShell modules or signed packages, so
# ModulePolicy / SignerIdentity do not apply here.
# This file documents provenance constraints in prose.

#: Minimum supported Prowler major version for OCSF output.
MINIMUM_PROWLER_MAJOR_VERSION: int = 4

#: Expected OCSF schema version in Prowler output metadata.
EXPECTED_OCSF_SCHEMA_VERSION: str = "1.4.0"

#: Allowed Prowler CLI auth flags. Kept in sync with adapter._PROWLER_ALLOWED_FLAGS.
ALLOWED_AUTH_FLAGS: frozenset[str] = frozenset(
    {
        "--az-cli-auth",
        "--sp-env-auth",
        "--browser-auth",
        "--managed-identity-auth",
    }
)
