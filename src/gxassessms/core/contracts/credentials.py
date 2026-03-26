"""CredentialProvider Protocol and default EnvVarProvider.

Credentials are never stored in config files or engagement directories.
The CredentialProvider resolves key references to actual values at runtime.
"""

import os
from typing import Protocol, runtime_checkable


@runtime_checkable
class CredentialProvider(Protocol):
    """Protocol for resolving credential references to actual values."""

    def get_credential(self, key: str) -> str:
        """Resolve a credential key to its value. Raises KeyError if not found."""
        ...

    def has_credential(self, key: str) -> bool:
        """Check whether a credential key can be resolved."""
        ...


class EnvVarProvider:
    """Reads credentials from environment variables. Default provider."""

    def get_credential(self, key: str) -> str:
        """Read credential from environment variable. Raises KeyError if unset."""
        value = os.environ.get(key)
        if value is None:
            raise KeyError(f"Environment variable not set: {key}")
        return value

    def has_credential(self, key: str) -> bool:
        """Check whether the environment variable is set."""
        return key in os.environ
