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
                subject=(
                    "CN=Microsoft Corporation, O=Microsoft Corporation,"
                    " L=Redmond, S=Washington, C=US"
                ),
                issuer=(
                    "CN=Microsoft Code Signing PCA 2011, O=Microsoft Corporation,"
                    " L=Redmond, S=Washington, C=US"
                ),
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
