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
