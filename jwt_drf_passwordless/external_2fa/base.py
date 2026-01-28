"""
Abstract base class for external 2FA providers.

This module defines the interface that all external 2FA providers must implement,
following the Dependency Inversion Principle. The application depends on this
abstraction, not on concrete implementations like Telnyx or Twilio.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class VerificationStatus(Enum):
    """Status of a verification attempt."""
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    EXPIRED = "expired"
    ERROR = "error"


class VerificationMethod(Enum):
    """Method used for verification delivery."""
    SMS = "sms"
    CALL = "call"
    FLASHCALL = "flashcall"


class WebhookEventType(Enum):
    """Types of webhook events from 2FA providers."""
    # Delivery status events
    SENT = "sent"  # Verification dispatched to upstream provider
    DELIVERED = "delivered"  # Provider confirms message arrival
    FAILED = "failed"  # Delivery attempt unsuccessful

    # Verification result events (provider-specific)
    VERIFIED = "verified"  # User successfully verified
    EXPIRED = "expired"  # Verification timed out


class DeliveryStatus(Enum):
    """Delivery status values from providers."""
    SENT = "sent"
    DELIVERED = "delivered"
    SENDING_FAILED = "sending_failed"
    DELIVERY_FAILED = "delivery_failed"
    DELIVERY_UNCONFIRMED = "delivery_unconfirmed"


@dataclass
class External2FAResult:
    """
    Result of an external 2FA operation.

    Attributes:
        success: Whether the operation succeeded
        status: The verification status
        verification_id: Provider's verification ID (for tracking)
        message: Human-readable message
        error_code: Provider-specific error code if failed
    """
    success: bool
    status: VerificationStatus
    verification_id: Optional[str] = None
    message: Optional[str] = None
    error_code: Optional[str] = None


@dataclass
class WebhookEvent:
    """
    Parsed webhook event from an external 2FA provider.

    Attributes:
        event_type: Type of webhook event (sent, delivered, failed, etc.)
        event_id: Unique identifier for this event
        phone_number: Phone number associated with the verification
        verification_id: Provider's verification ID
        delivery_status: Current delivery status
        occurred_at: ISO timestamp of when the event occurred
        raw_payload: Original webhook payload for debugging
        provider: Name of the provider (e.g., "telnyx", "twilio")
    """
    event_type: WebhookEventType
    event_id: str
    phone_number: str
    verification_id: Optional[str] = None
    delivery_status: Optional[DeliveryStatus] = None
    occurred_at: Optional[str] = None
    raw_payload: Optional[dict] = None
    provider: Optional[str] = None


class External2FAProvider(ABC):
    """
    Abstract base class for external 2FA verification providers.

    Implement this interface to add support for any external 2FA service
    (Telnyx, Twilio, Vonage, etc.). The application code depends on this
    abstraction, allowing providers to be swapped without changing business logic.

    Example usage:
        provider = TelnyxVerifyProvider(api_key="...", profile_id="...")

        # Request verification
        result = provider.send_verification("+13035551234", VerificationMethod.SMS)
        if result.success:
            # Store result.verification_id for later verification
            ...

        # Verify code submitted by user
        result = provider.verify_code("+13035551234", "123456")
        if result.success and result.status == VerificationStatus.ACCEPTED:
            # User verified successfully
            ...
    """

    @abstractmethod
    def send_verification(
        self,
        phone_number: str,
        method: VerificationMethod = VerificationMethod.SMS,
    ) -> External2FAResult:
        """
        Send a verification code to the specified phone number.

        Args:
            phone_number: Phone number in E.164 format (e.g., "+13035551234")
            method: Delivery method (SMS, call, or flashcall)

        Returns:
            External2FAResult with success status and verification_id
        """
        pass

    @abstractmethod
    def verify_code(
        self,
        phone_number: str,
        code: str,
    ) -> External2FAResult:
        """
        Verify a code submitted by the user.

        Args:
            phone_number: Phone number in E.164 format
            code: The verification code entered by the user

        Returns:
            External2FAResult with verification status (ACCEPTED/REJECTED)
        """
        pass

    @abstractmethod
    def cancel_verification(
        self,
        phone_number: str,
    ) -> External2FAResult:
        """
        Cancel any pending verification for the phone number.

        Args:
            phone_number: Phone number in E.164 format

        Returns:
            External2FAResult indicating cancellation success
        """
        pass

    def is_configured(self) -> bool:
        """
        Check if the provider is properly configured.

        Returns:
            True if the provider has all required configuration
        """
        return True

    def parse_webhook(self, payload: dict, headers: Optional[dict] = None) -> WebhookEvent:
        """
        Parse a webhook payload from the provider.

        Args:
            payload: The webhook JSON payload
            headers: HTTP headers (for signature verification)

        Returns:
            WebhookEvent with parsed event data

        Raises:
            ValueError: If the payload is invalid or signature verification fails
        """
        raise NotImplementedError(
            "Webhook parsing not implemented for this provider"
        )

    def verify_webhook_signature(
        self,
        payload: bytes,
        signature: str,
        timestamp: Optional[str] = None,
    ) -> bool:
        """
        Verify the webhook signature for security.

        Args:
            payload: Raw request body bytes
            signature: Signature from webhook headers
            timestamp: Timestamp from webhook headers (if applicable)

        Returns:
            True if signature is valid, False otherwise
        """
        # Default implementation: no signature verification
        return True
