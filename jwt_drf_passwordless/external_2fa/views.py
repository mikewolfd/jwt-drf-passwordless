"""
Views for external 2FA verification.

These views handle the request/verify flow when using an external 2FA provider
like Telnyx or Twilio. Unlike the internal token flow, the external provider
generates and stores the verification code.

Flow:
1. User requests verification → We call provider.send_verification()
2. Provider sends code to user's phone
3. User submits code → We call provider.verify_code()
4. If accepted, we issue JWT tokens

Webhook Flow:
1. Provider sends webhook to /passwordless/external/webhook/
2. We parse the webhook and fire Django signals
3. Application can react to delivery status events
"""

import json
import logging

from django.contrib.auth import get_user_model
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from jwt_drf_passwordless import signals as app_signals
from jwt_drf_passwordless.conf import settings
from jwt_drf_passwordless.constants import Messages

from . import signals as webhook_signals
from .base import VerificationStatus, WebhookEventType
from .serializers import (External2FARequestSerializer,
                          External2FAVerifySerializer)

logger = logging.getLogger(__name__)

User = get_user_model()


def get_external_2fa_provider():
    """
    Get the configured external 2FA provider instance.

    Returns:
        External2FAProvider instance or None if not configured
    """
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

    return provider_class(
        api_key=api_key,
        verify_profile_id=verify_profile_id,
    )


class External2FARequestView(APIView):
    """
    Request a 2FA verification code via external provider.

    POST /passwordless/external/request/
    {
        "phone_number": "+13035551234"
    }

    Response:
    {
        "detail": "Verification code sent."
    }
    """

    permission_classes = (AllowAny,)
    serializer_class = External2FARequestSerializer

    @method_decorator(settings.DECORATORS.token_request_rate_limit_decorator)
    def post(self, request, *args, **kwargs):
        # Check if MOBILE is allowed
        if "MOBILE" not in settings.ALLOWED_PASSWORDLESS_METHODS:
            return Response(status=status.HTTP_404_NOT_FOUND)

        serializer = self.serializer_class(
            data=request.data,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data.get("user")
        phone_number = str(serializer.validated_data["phone_number"])

        # Check admin restriction
        if not settings.ALLOW_ADMIN_AUTHENTICATION:
            if getattr(user, "is_staff", None) or getattr(user, "is_superuser", None):
                return Response(
                    {"detail": Messages.CANNOT_SEND_TOKEN},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        # Get the external 2FA provider
        provider = get_external_2fa_provider()
        if not provider or not provider.is_configured():
            return Response(
                {"detail": "External 2FA provider not configured."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        # Send verification via provider
        result = provider.send_verification(phone_number)

        if result.success:
            return Response(
                {"detail": Messages.TOKEN_SENT},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"detail": result.message or Messages.CANNOT_SEND_TOKEN},
                status=status.HTTP_400_BAD_REQUEST,
            )


class External2FAVerifyView(APIView):
    """
    Verify a 2FA code and exchange for JWT tokens.

    POST /passwordless/external/verify/
    {
        "phone_number": "+13035551234",
        "code": "123456"
    }

    Response (on success):
    {
        "access": "...",
        "refresh": "..."
    }
    """

    permission_classes = (AllowAny,)
    serializer_class = External2FAVerifySerializer

    @method_decorator(settings.DECORATORS.token_redeem_rate_limit_decorator)
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(
            data=request.data,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]
        phone_number = str(serializer.validated_data["phone_number"])
        code = serializer.validated_data["code"]

        # Get the external 2FA provider
        provider = get_external_2fa_provider()
        if not provider or not provider.is_configured():
            return Response(
                {"detail": "External 2FA provider not configured."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        # Verify the code with the provider
        result = provider.verify_code(phone_number, code)

        if result.success and result.status == VerificationStatus.ACCEPTED:
            # Activate user if needed
            if not user.is_active:
                user.is_active = True
                user.save()
                app_signals.user_activated.send(
                    sender=self.__class__,
                    user=user,
                    request=request,
                )

            # Generate JWT tokens
            tokens = serializer.generate_auth_token(user)
            return Response(data=tokens, status=status.HTTP_200_OK)

        elif result.status == VerificationStatus.EXPIRED:
            return Response(
                {"detail": "Verification code has expired."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        else:
            return Response(
                {"detail": Messages.INVALID_CREDENTIALS_ERROR},
                status=status.HTTP_400_BAD_REQUEST,
            )


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
                    error=event.delivery_status.value if event.delivery_status else "unknown",
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
