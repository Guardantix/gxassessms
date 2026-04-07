"""Monkey365 module provenance policy.

Security-critical: changes to this file represent approved module states.
Review carefully in PRs.
"""

from gxassessms.core.contracts.verification import ModulePolicy, SignerIdentity

MODULE_POLICY = ModulePolicy(
    module_name="monkey365",
    version_range=">=1.0.0,<2.0.0",
    allowed_signers=frozenset(
        {
            SignerIdentity(
                subject="CN=monkey365",  # Placeholder -- update with real signer
                issuer="CN=monkey365 CA",
            ),
        }
    ),
    # Placeholder hash -- compute from a controlled monkey365 install:
    # mseco compute-module-hash --manifest-path /path/to/monkey365/1.x.x/monkey365.psd1
    approved_package_hashes=frozenset(
        {
            "sha256tree:v1:0000000000000000000000000000000000000000000000000000000000000000",
        }
    ),
    allow_package_hash_fallback=True,
)

ALLOWED_COMMANDS: frozenset[str] = frozenset({"Invoke-Monkey365"})
