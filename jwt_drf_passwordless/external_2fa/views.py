"""
Webhook view for external 2FA providers.

Receives delivery status updates from providers like Telnyx and fires
Django signals so the application can react (e.g., logging, alerting).
"""

import json
import logging

from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from . import get_external_2fa_provider, signals as webhook_signals
from .base import WebhookEventType

logger = logging.getLogger(__name__)


class External2FAWebhookView(APIView):
    """
    Receive webhooks from external 2FA providers.

    POST /passwordless/external/webhook/

    This endpoint receives delivery status updates from providers like Telnyx.
    Events are parsed and Django signals are fired for application-level handling.

    Telnyx Webhook Events:
    - verify.sent: Verification dispatched to upstream provider
    - verify.delivered: Provider confirms message arrival
    - verify.failed: Delivery attempt unsuccessful

    Network Configuration:
    - For Telnyx, whitelist: 192.76.120.192/27

    Example webhook payload (Telnyx):
    {
        "data": {
            "event_type": "verify.delivered",
            "id": "event-uuid",
            "occurred_at": "2024-01-01T00:00:00Z",
            "payload": {
                "phone_number": "+13035551234",
                "status": "delivered",
                "id": "verification-uuid"
            }
        }
    }
    """

    # Webhooks are unauthenticated - security via signature verification
    permission_classes = (AllowAny,)
    authentication_classes = []  # No auth required for webhooks

    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        # Get the external 2FA provider
        provider = get_external_2fa_provider()
        if not provider:
            logger.warning("Webhook received but no provider configured")
            # Return 200 to prevent retries from provider
            return Response({"detail": "OK"}, status=status.HTTP_200_OK)

        try:
            # Get the raw body for signature verification
            raw_body = request.body

            # Verify webhook signature (Telnyx uses Ed25519)
            signature = request.headers.get("Telnyx-Signature-Ed25519", "")
            timestamp = request.headers.get("Telnyx-Timestamp", "")

            if not provider.verify_webhook_signature(
                payload=raw_body,
                signature=signature,
                timestamp=timestamp,
            ):
                logger.warning("Webhook signature verification failed")
                return Response(
                    {"detail": "Invalid signature"},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            # Parse the JSON payload
            if isinstance(request.data, dict):
                payload = request.data
            else:
                payload = json.loads(raw_body)

            # Parse the webhook event
            event = provider.parse_webhook(
                payload=payload,
                headers=dict(request.headers),
            )

            logger.info(
                "Received 2FA webhook: type=%s phone=%s provider=%s",
                event.event_type.value,
                event.phone_number,
                event.provider,
            )

            # Fire the general webhook signal
            webhook_signals.verification_webhook_received.send(
                sender=self.__class__,
                event=event,
                provider=event.provider,
            )

            # Fire specific signals based on event type
            if event.event_type == WebhookEventType.DELIVERED:
                webhook_signals.verification_delivered.send(
                    sender=self.__class__,
                    event=event,
                    phone_number=event.phone_number,
                )
            elif event.event_type == WebhookEventType.FAILED:
                webhook_signals.verification_delivery_failed.send(
                    sender=self.__class__,
                    event=event,
                    phone_number=event.phone_number,
                    error=(
                        event.delivery_status.value
                        if event.delivery_status
                        else "unknown"
                    ),
                )

            return Response({"detail": "OK"}, status=status.HTTP_200_OK)

        except json.JSONDecodeError as e:
            logger.error("Invalid JSON in webhook: %s", e)
            return Response(
                {"detail": "Invalid JSON"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except ValueError as e:
            logger.error("Invalid webhook payload: %s", e)
            return Response(
                {"detail": str(e)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            logger.exception("Unexpected error processing webhook")
            # Return 200 to prevent infinite retries
            return Response({"detail": "OK"}, status=status.HTTP_200_OK)
