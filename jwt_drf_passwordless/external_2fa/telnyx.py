"""
Telnyx Verify provider implementation.

This module implements the External2FAProvider interface for Telnyx's
Verify API. It handles sending verification codes via SMS/call and
verifying codes submitted by users.

Telnyx API Reference: https://developers.telnyx.com/docs/identity/verify

Configuration:
    Set the following in your Django settings under JWT_DRF_PASSWORDLESS:

    JWT_DRF_PASSWORDLESS = {
        "EXTERNAL_2FA": {
            "provider": "jwt_drf_passwordless.external_2fa.TelnyxVerifyProvider",
            "api_key": "YOUR_TELNYX_API_KEY",
            "verify_profile_id": "YOUR_VERIFY_PROFILE_ID",
            # Optional: webhook signature verification (get from Mission Control Portal)
            "webhook_public_key": "YOUR_TELNYX_PUBLIC_KEY",
        }
    }

Webhook Security:
    Telnyx signs webhooks using Ed25519. The signature is sent in the
    `telnyx-signature-ed25519` header, and the timestamp in `telnyx-timestamp`.
    Get your public key from: https://portal.telnyx.com/#/api-keys/public-key
"""

import base64
import logging
from typing import Optional

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .base import (DeliveryStatus, External2FAProvider, External2FAResult,
                   VerificationMethod, VerificationStatus, WebhookEvent,
                   WebhookEventType)

logger = logging.getLogger(__name__)


class TelnyxVerifyProvider(External2FAProvider):
    """
    Telnyx Verify API implementation.

    This provider uses Telnyx's Verify API to send and verify 2FA codes.
    The provider handles all code generation and storage - we just need
    to relay requests and responses.
    """

    BASE_URL = "https://api.telnyx.com/v2"

    def __init__(
        self,
        api_key: str,
        verify_profile_id: str,
        timeout: int = 30,
        webhook_public_key: Optional[str] = None,
    ):
        """
        Initialize the Telnyx Verify provider.

        Args:
            api_key: Telnyx API key (Bearer token)
            verify_profile_id: UUID of the Verify Profile to use
            timeout: Request timeout in seconds
            webhook_public_key: Ed25519 public key for webhook signature
                verification. Get from Mission Control Portal.
        """
        self.api_key = api_key
        self.verify_profile_id = verify_profile_id
        self.timeout = timeout
        self.webhook_public_key = webhook_public_key

    def _get_headers(self) -> dict:
        """Get HTTP headers for Telnyx API requests."""
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _method_to_endpoint(self, method: VerificationMethod) -> str:
        """Map verification method to Telnyx API endpoint."""
        mapping = {
            VerificationMethod.SMS: "sms",
            VerificationMethod.CALL: "call",
            VerificationMethod.FLASHCALL: "flashcall",
        }
        return mapping.get(method, "sms")

    def send_verification(
        self,
        phone_number: str,
        method: VerificationMethod = VerificationMethod.SMS,
    ) -> External2FAResult:
        """
        Send a verification code via Telnyx Verify.

        Args:
            phone_number: Phone number in E.164 format
            method: Delivery method (SMS, call, or flashcall)

        Returns:
            External2FAResult with verification_id on success
        """
        endpoint = self._method_to_endpoint(method)
        url = f"{self.BASE_URL}/verifications/{endpoint}"

        payload = {
            "phone_number": phone_number,
            "verify_profile_id": self.verify_profile_id,
        }

        try:
            response = requests.post(
                url,
                json=payload,
                headers=self._get_headers(),
                timeout=self.timeout,
            )

            if response.status_code in (200, 201):
                data = response.json().get("data", {})
                return External2FAResult(
                    success=True,
                    status=VerificationStatus.PENDING,
                    verification_id=data.get("id"),
                    message=f"Verification sent via {method.value}",
                )
            else:
                error_data = response.json()
                errors = error_data.get("errors", [{}])
                error_detail = errors[0].get("detail", "Unknown error") if errors else "Unknown error"
                error_code = errors[0].get("code", "unknown") if errors else "unknown"

                logger.error(
                    "Telnyx verification send failed: %s (code: %s)",
                    error_detail,
                    error_code,
                )

                return External2FAResult(
                    success=False,
                    status=VerificationStatus.ERROR,
                    message=error_detail,
                    error_code=error_code,
                )

        except requests.RequestException as e:
            logger.exception("Telnyx API request failed")
            return External2FAResult(
                success=False,
                status=VerificationStatus.ERROR,
                message=str(e),
                error_code="request_error",
            )

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
            External2FAResult with ACCEPTED status on success
        """
        # URL encode the phone number for the path
        encoded_phone = requests.utils.quote(phone_number, safe="")
        url = f"{self.BASE_URL}/verifications/by_phone_number/{encoded_phone}/actions/verify"

        payload = {
            "code": code,
            "verify_profile_id": self.verify_profile_id,
        }

        try:
            response = requests.post(
                url,
                json=payload,
                headers=self._get_headers(),
                timeout=self.timeout,
            )

            if response.status_code == 200:
                data = response.json().get("data", {})
                response_code = data.get("response_code", "")

                if response_code == "accepted":
                    return External2FAResult(
                        success=True,
                        status=VerificationStatus.ACCEPTED,
                        message="Verification successful",
                    )
                else:
                    return External2FAResult(
                        success=False,
                        status=VerificationStatus.REJECTED,
                        message=f"Verification rejected: {response_code}",
                        error_code=response_code,
                    )
            else:
                error_data = response.json()
                errors = error_data.get("errors", [{}])
                error_detail = errors[0].get("detail", "Unknown error") if errors else "Unknown error"
                error_code = errors[0].get("code", "unknown") if errors else "unknown"

                # Check for specific error codes
                status = VerificationStatus.ERROR
                if error_code in ("verification_expired", "timeout"):
                    status = VerificationStatus.EXPIRED
                elif error_code in ("verification_not_found", "invalid_code"):
                    status = VerificationStatus.REJECTED

                logger.error(
                    "Telnyx verification failed: %s (code: %s)",
                    error_detail,
                    error_code,
                )

                return External2FAResult(
                    success=False,
                    status=status,
                    message=error_detail,
                    error_code=error_code,
                )

        except requests.RequestException as e:
            logger.exception("Telnyx API request failed")
            return External2FAResult(
                success=False,
                status=VerificationStatus.ERROR,
                message=str(e),
                error_code="request_error",
            )

    def cancel_verification(
        self,
        phone_number: str,
    ) -> External2FAResult:
        """
        Cancel any pending verification for the phone number.

        Note: Telnyx doesn't have a direct cancel endpoint. Verifications
        expire based on the profile's timeout settings. This method returns
        success as the practical effect is the same.

        Args:
            phone_number: Phone number in E.164 format

        Returns:
            External2FAResult indicating success
        """
        # Telnyx verifications expire automatically based on profile settings
        # There's no explicit cancel endpoint, so we just acknowledge the request
        logger.info("Verification cancellation requested for %s (will expire automatically)", phone_number)

        return External2FAResult(
            success=True,
            status=VerificationStatus.EXPIRED,
            message="Verification will expire automatically",
        )

    def is_configured(self) -> bool:
        """Check if the provider has required configuration."""
        return bool(self.api_key and self.verify_profile_id)

    def parse_webhook(
        self,
        payload: dict,
        headers: Optional[dict] = None,
    ) -> WebhookEvent:
        """
        Parse a Telnyx Verify webhook payload.

        Telnyx sends webhooks for verification delivery events:
        - verify.sent: Verification dispatched to upstream provider
        - verify.delivered: Provider confirms message arrival
        - verify.failed: Delivery attempt unsuccessful

        Args:
            payload: The webhook JSON payload
            headers: HTTP headers (for signature verification)

        Returns:
            WebhookEvent with parsed event data

        Raises:
            ValueError: If the payload is invalid
        """
        try:
            # Validate required structure
            if "data" not in payload:
                raise ValueError("Missing 'data' key in webhook payload")

            data = payload["data"]
            if not isinstance(data, dict):
                raise ValueError("'data' must be a dictionary")

            # Validate required fields
            if "event_type" not in data:
                raise ValueError("Missing 'event_type' in webhook data")

            event_type_str = data["event_type"]
            event_payload = data.get("payload", {})

            # Validate event_type is a Telnyx verify event
            if not event_type_str.startswith("verify."):
                raise ValueError(f"Unexpected event type: {event_type_str}")

            # Map Telnyx event types to our enum
            event_type = self._map_event_type(event_type_str)

            # Extract phone number from payload
            phone_number = event_payload.get("phone_number", "")

            # Map delivery status
            delivery_status_str = event_payload.get("status", "")
            delivery_status = self._map_delivery_status(delivery_status_str)

            return WebhookEvent(
                event_type=event_type,
                event_id=data.get("id", ""),
                phone_number=phone_number,
                verification_id=event_payload.get("id"),
                delivery_status=delivery_status,
                occurred_at=data.get("occurred_at"),
                raw_payload=payload,
                provider="telnyx",
            )

        except (KeyError, TypeError) as e:
            raise ValueError(f"Invalid Telnyx webhook payload: {e}") from e

    def _map_event_type(self, event_type_str: str) -> WebhookEventType:
        """Map Telnyx event type string to WebhookEventType enum."""
        mapping = {
            "verify.sent": WebhookEventType.SENT,
            "verify.delivered": WebhookEventType.DELIVERED,
            "verify.failed": WebhookEventType.FAILED,
        }
        return mapping.get(event_type_str, WebhookEventType.SENT)

    def _map_delivery_status(self, status_str: str) -> Optional[DeliveryStatus]:
        """Map Telnyx delivery status string to DeliveryStatus enum."""
        mapping = {
            "sent": DeliveryStatus.SENT,
            "delivered": DeliveryStatus.DELIVERED,
            "sending_failed": DeliveryStatus.SENDING_FAILED,
            "delivery_failed": DeliveryStatus.DELIVERY_FAILED,
            "delivery_unconfirmed": DeliveryStatus.DELIVERY_UNCONFIRMED,
        }
        return mapping.get(status_str)

    def verify_webhook_signature(
        self,
        payload: bytes,
        signature: str,
        timestamp: Optional[str] = None,
    ) -> bool:
        """
        Verify the webhook signature using Ed25519.

        Telnyx signs webhooks with Ed25519. The signature is computed over
        the string: "{timestamp}|{payload}".

        Args:
            payload: Raw request body bytes
            signature: Base64-encoded signature from `telnyx-signature-ed25519` header
            timestamp: Unix timestamp from `telnyx-timestamp` header

        Returns:
            True if signature is valid, False otherwise

        Note:
            If webhook_public_key is not configured, this method returns True
            (signature verification is optional but recommended).
        """
        if not self.webhook_public_key:
            logger.warning(
                "Webhook signature verification skipped - no public key configured. "
                "Get your public key from https://portal.telnyx.com/#/api-keys/public-key"
            )
            return True

        if not signature or not timestamp:
            logger.warning("Missing signature or timestamp headers")
            return False

        try:
            # Build the signed payload: "{timestamp}|{payload}"
            if isinstance(payload, bytes):
                payload_str = payload.decode("utf-8")
            else:
                payload_str = str(payload)

            signed_payload = f"{timestamp}|{payload_str}"

            # Decode the signature and public key from base64
            signature_bytes = base64.b64decode(signature)
            public_key_bytes = base64.b64decode(self.webhook_public_key)

            # Load the public key and verify
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            public_key.verify(signature_bytes, signed_payload.encode("utf-8"))

            return True

        except (InvalidSignature, ValueError, TypeError) as e:
            logger.warning("Webhook signature verification failed: %s", e)
            return False
