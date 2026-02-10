# External 2FA Provider Support
# This module provides dependency-inverted interfaces for external 2FA providers
# like Telnyx Verify and Twilio Verify.

from .base import (
    DeliveryStatus,
    External2FAProvider,
    External2FAResult,
    VerificationMethod,
    VerificationStatus,
    WebhookEvent,
    WebhookEventType,
)
from .signals import (
    verification_delivered,
    verification_delivery_failed,
    verification_webhook_received,
)
from .telnyx import TelnyxVerifyProvider
from .testing import FakeVerifyProvider


def get_external_2fa_provider():
    """
    Get the configured external 2FA provider instance.

    Returns:
        External2FAProvider instance or None if not configured
    """
    from jwt_drf_passwordless.conf import settings

    external_2fa_config = getattr(settings, "EXTERNAL_2FA", None)
    if not external_2fa_config:
        return None

    provider_class = external_2fa_config.get("provider")
    if not provider_class:
        return None

    # Import the provider class if it's a string
    if isinstance(provider_class, str):
        from django.utils.module_loading import import_string

        provider_class = import_string(provider_class)

    # Get configuration for the provider
    api_key = external_2fa_config.get("api_key", "")
    verify_profile_id = external_2fa_config.get("verify_profile_id", "")
    webhook_public_key = external_2fa_config.get("webhook_public_key", "")

    return provider_class(
        api_key=api_key,
        verify_profile_id=verify_profile_id,
        webhook_public_key=webhook_public_key,
    )


__all__ = [
    # Base types
    "External2FAProvider",
    "External2FAResult",
    "VerificationStatus",
    "VerificationMethod",
    # Webhook types
    "WebhookEvent",
    "WebhookEventType",
    "DeliveryStatus",
    # Signals
    "verification_webhook_received",
    "verification_delivered",
    "verification_delivery_failed",
    # Providers
    "TelnyxVerifyProvider",
    "FakeVerifyProvider",
    # Utilities
    "get_external_2fa_provider",
]
