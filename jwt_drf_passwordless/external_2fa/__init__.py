# External 2FA Provider Support
# This module provides dependency-inverted interfaces for external 2FA providers
# like Telnyx Verify and Twilio Verify.

from .base import (DeliveryStatus, External2FAProvider, External2FAResult,
                   VerificationMethod, VerificationStatus, WebhookEvent,
                   WebhookEventType)
from .signals import (verification_delivered, verification_delivery_failed,
                      verification_webhook_received)
from .telnyx import TelnyxVerifyProvider

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
]
