"""Shared Azure token acquisition for REST API adapters (Advisor, Secure Score, etc.)."""

from __future__ import annotations

import logging
import os

from pydantic import SecretStr

from gxassessms.core.config.config import EngagementConfig
from gxassessms.core.config.datetime_utils import from_epoch
from gxassessms.core.contracts.errors import CollectionError
from gxassessms.core.domain.models import AuthContext

logger = logging.getLogger(__name__)


def acquire_azure_token(
    config: EngagementConfig,
    *,
    scope: str,
    adapter_name: str,
) -> AuthContext:
    """Acquire an Azure token via azure-identity credential dispatch.

    Dispatches on ``config.auth.method``:

    - ``client_credential`` -- ClientSecretCredential (secret) or
      CertificateCredential (cert), sub-dispatched by field presence.
    - ``device_code`` -- DeviceCodeCredential (interactive device flow).
    - ``interactive`` -- InteractiveBrowserCredential (browser flow).

    Args:
        config: Engagement configuration (only ``config.auth`` is accessed).
        scope: OAuth scope URL (e.g. ``https://graph.microsoft.com/.default``).
        adapter_name: Name for log and error messages.

    Raises:
        CollectionError: If token acquisition fails, method is unsupported,
            or azure-identity is not installed.
    """
    try:
        from azure.core.exceptions import (  # pyright: ignore[reportMissingImports]
            AzureError,  # pyright: ignore[reportUnknownVariableType]
        )
        from azure.identity import (  # pyright: ignore[reportMissingImports]
            CertificateCredential,  # pyright: ignore[reportUnknownVariableType]
            ClientSecretCredential,  # pyright: ignore[reportUnknownVariableType]
            DeviceCodeCredential,  # pyright: ignore[reportUnknownVariableType]
            InteractiveBrowserCredential,  # pyright: ignore[reportUnknownVariableType]
        )
    except ImportError as exc:
        raise CollectionError(
            f"azure-identity is required for {adapter_name} authentication: {exc}. "
            f"Install with: pip install azure-identity",
            adapter_name=adapter_name,
        ) from exc

    client_id = config.auth.client_id
    client_secret_env = config.auth.client_secret_env
    auth_method = config.auth.method

    try:
        match auth_method:
            case "client_credential":
                if client_secret_env:
                    client_secret = os.environ.get(client_secret_env, "")
                    if not client_secret:
                        raise CollectionError(
                            f"Environment variable '{client_secret_env}' is not set "
                            f"or empty. Required for service principal authentication.",
                            adapter_name=adapter_name,
                        )
                    logger.info(  # nosemgrep  # client_id is not a secret
                        "Authenticating %s via ClientSecretCredential (SP: %s)",
                        adapter_name,
                        client_id,
                    )
                    credential = ClientSecretCredential(  # pyright: ignore[reportUnknownVariableType]
                        tenant_id=config.auth.tenant_id,
                        client_id=client_id,
                        client_secret=client_secret,
                    )
                elif config.auth.certificate_path:
                    logger.info(  # nosemgrep  # client_id is not a secret
                        "Authenticating %s via CertificateCredential (SP: %s)",
                        adapter_name,
                        client_id,
                    )
                    credential = CertificateCredential(  # pyright: ignore[reportUnknownVariableType]
                        tenant_id=config.auth.tenant_id,
                        client_id=client_id,
                        certificate_path=config.auth.certificate_path,
                    )
                else:
                    raise CollectionError(
                        "client_credential auth requires client_secret_env or certificate_path",
                        adapter_name=adapter_name,
                    )
            case "device_code":
                logger.info(  # nosemgrep  # client_id is not a secret
                    "Authenticating %s via DeviceCodeCredential (client: %s)",
                    adapter_name,
                    client_id,
                )
                credential = DeviceCodeCredential(  # pyright: ignore[reportUnknownVariableType]
                    client_id=client_id,
                    tenant_id=config.auth.tenant_id,
                )
            case "interactive":
                logger.info(  # nosemgrep  # client_id is not a secret
                    "Authenticating %s via InteractiveBrowserCredential (client: %s)",
                    adapter_name,
                    client_id,
                )
                credential = InteractiveBrowserCredential(  # pyright: ignore[reportUnknownVariableType]
                    tenant_id=config.auth.tenant_id,
                    client_id=client_id,
                )
            case _:
                raise CollectionError(
                    f"Unsupported auth method: {auth_method!r}",
                    adapter_name=adapter_name,
                )

        token = credential.get_token(scope)  # pyright: ignore[reportUnknownVariableType,reportUnknownMemberType]
    except CollectionError:
        raise
    except (AzureError, ValueError, OSError) as exc:  # pyright: ignore[reportUnknownVariableType,reportPossiblyUnboundVariable]
        raise CollectionError(
            f"Azure token acquisition failed for {adapter_name}: {exc}",
            adapter_name=adapter_name,
        ) from exc

    return AuthContext(
        token=SecretStr(token.token),  # pyright: ignore[reportUnknownMemberType,reportUnknownArgumentType]
        extra={"scope": scope},
        expires_at=from_epoch(token.expires_on),  # pyright: ignore[reportUnknownMemberType,reportUnknownArgumentType]
    )
