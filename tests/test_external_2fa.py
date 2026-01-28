"""
Tests for external 2FA provider functionality.

These tests verify the external 2FA flow using mocked providers
to avoid making actual API calls during testing.
"""

from unittest.mock import Mock, patch

import pytest
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APIClient

from jwt_drf_passwordless.external_2fa.base import (External2FAProvider,
                                                    External2FAResult,
                                                    VerificationMethod,
                                                    VerificationStatus)
from jwt_drf_passwordless.external_2fa.telnyx import TelnyxVerifyProvider

User = get_user_model()


# ============================================================================
# Base Provider Tests
# ============================================================================


class TestExternal2FAResult:
    """Tests for External2FAResult dataclass."""

    def test_success_result(self):
        result = External2FAResult(
            success=True,
            status=VerificationStatus.PENDING,
            verification_id="abc123",
            message="Code sent",
        )
        assert result.success is True
        assert result.status == VerificationStatus.PENDING
        assert result.verification_id == "abc123"
        assert result.message == "Code sent"
        assert result.error_code is None

    def test_failure_result(self):
        result = External2FAResult(
            success=False,
            status=VerificationStatus.ERROR,
            message="API error",
            error_code="rate_limited",
        )
        assert result.success is False
        assert result.status == VerificationStatus.ERROR
        assert result.error_code == "rate_limited"


class TestVerificationEnums:
    """Tests for verification enums."""

    def test_verification_status_values(self):
        assert VerificationStatus.PENDING.value == "pending"
        assert VerificationStatus.ACCEPTED.value == "accepted"
        assert VerificationStatus.REJECTED.value == "rejected"
        assert VerificationStatus.EXPIRED.value == "expired"
        assert VerificationStatus.ERROR.value == "error"

    def test_verification_method_values(self):
        assert VerificationMethod.SMS.value == "sms"
        assert VerificationMethod.CALL.value == "call"
        assert VerificationMethod.FLASHCALL.value == "flashcall"


# ============================================================================
# Telnyx Provider Tests
# ============================================================================


class TestTelnyxVerifyProvider:
    """Tests for TelnyxVerifyProvider implementation."""

    def test_initialization(self):
        provider = TelnyxVerifyProvider(
            api_key="test_key",
            verify_profile_id="test_profile",
        )
        assert provider.api_key == "test_key"
        assert provider.verify_profile_id == "test_profile"
        assert provider.timeout == 30

    def test_is_configured_valid(self):
        provider = TelnyxVerifyProvider(
            api_key="test_key",
            verify_profile_id="test_profile",
        )
        assert provider.is_configured() is True

    def test_is_configured_missing_key(self):
        provider = TelnyxVerifyProvider(
            api_key="",
            verify_profile_id="test_profile",
        )
        assert provider.is_configured() is False

    def test_is_configured_missing_profile(self):
        provider = TelnyxVerifyProvider(
            api_key="test_key",
            verify_profile_id="",
        )
        assert provider.is_configured() is False

    @patch("jwt_drf_passwordless.external_2fa.telnyx.requests.post")
    def test_send_verification_success(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "id": "verification-123",
                "status": "pending",
            }
        }
        mock_post.return_value = mock_response

        provider = TelnyxVerifyProvider(
            api_key="test_key",
            verify_profile_id="test_profile",
        )
        result = provider.send_verification("+13035551234")

        assert result.success is True
        assert result.status == VerificationStatus.PENDING
        assert result.verification_id == "verification-123"

        # Verify the API was called correctly
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert "verifications/sms" in call_args[0][0]
        assert call_args[1]["json"]["phone_number"] == "+13035551234"
        assert call_args[1]["json"]["verify_profile_id"] == "test_profile"

    @patch("jwt_drf_passwordless.external_2fa.telnyx.requests.post")
    def test_send_verification_with_call_method(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"id": "verification-456"}}
        mock_post.return_value = mock_response

        provider = TelnyxVerifyProvider(
            api_key="test_key",
            verify_profile_id="test_profile",
        )
        result = provider.send_verification("+13035551234", VerificationMethod.CALL)

        assert result.success is True
        call_args = mock_post.call_args
        assert "verifications/call" in call_args[0][0]

    @patch("jwt_drf_passwordless.external_2fa.telnyx.requests.post")
    def test_send_verification_api_error(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            "errors": [
                {
                    "code": "invalid_phone_number",
                    "detail": "Invalid phone number format",
                }
            ]
        }
        mock_post.return_value = mock_response

        provider = TelnyxVerifyProvider(
            api_key="test_key",
            verify_profile_id="test_profile",
        )
        result = provider.send_verification("+invalid")

        assert result.success is False
        assert result.status == VerificationStatus.ERROR
        assert result.error_code == "invalid_phone_number"
        assert "Invalid phone number" in result.message

    @patch("jwt_drf_passwordless.external_2fa.telnyx.requests.post")
    def test_send_verification_network_error(self, mock_post):
        import requests
        mock_post.side_effect = requests.RequestException("Connection failed")

        provider = TelnyxVerifyProvider(
            api_key="test_key",
            verify_profile_id="test_profile",
        )
        result = provider.send_verification("+13035551234")

        assert result.success is False
        assert result.status == VerificationStatus.ERROR
        assert result.error_code == "request_error"

    @patch("jwt_drf_passwordless.external_2fa.telnyx.requests.post")
    def test_verify_code_accepted(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "phone_number": "+13035551234",
                "response_code": "accepted",
            }
        }
        mock_post.return_value = mock_response

        provider = TelnyxVerifyProvider(
            api_key="test_key",
            verify_profile_id="test_profile",
        )
        result = provider.verify_code("+13035551234", "123456")

        assert result.success is True
        assert result.status == VerificationStatus.ACCEPTED
        assert "successful" in result.message.lower()

    @patch("jwt_drf_passwordless.external_2fa.telnyx.requests.post")
    def test_verify_code_rejected(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "phone_number": "+13035551234",
                "response_code": "rejected",
            }
        }
        mock_post.return_value = mock_response

        provider = TelnyxVerifyProvider(
            api_key="test_key",
            verify_profile_id="test_profile",
        )
        result = provider.verify_code("+13035551234", "000000")

        assert result.success is False
        assert result.status == VerificationStatus.REJECTED

    @patch("jwt_drf_passwordless.external_2fa.telnyx.requests.post")
    def test_verify_code_expired(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {
            "errors": [
                {
                    "code": "verification_expired",
                    "detail": "Verification has expired",
                }
            ]
        }
        mock_post.return_value = mock_response

        provider = TelnyxVerifyProvider(
            api_key="test_key",
            verify_profile_id="test_profile",
        )
        result = provider.verify_code("+13035551234", "123456")

        assert result.success is False
        assert result.status == VerificationStatus.EXPIRED

    def test_cancel_verification(self):
        """Telnyx doesn't have explicit cancel, returns success."""
        provider = TelnyxVerifyProvider(
            api_key="test_key",
            verify_profile_id="test_profile",
        )
        result = provider.cancel_verification("+13035551234")

        assert result.success is True
        assert result.status == VerificationStatus.EXPIRED


# ============================================================================
# Mock Provider for View Tests
# ============================================================================


class MockExternal2FAProvider(External2FAProvider):
    """Mock provider for testing views."""

    def __init__(self, **kwargs):
        self.send_result = External2FAResult(
            success=True,
            status=VerificationStatus.PENDING,
            verification_id="mock-123",
        )
        self.verify_result = External2FAResult(
            success=True,
            status=VerificationStatus.ACCEPTED,
        )

    def send_verification(self, phone_number, method=VerificationMethod.SMS):
        return self.send_result

    def verify_code(self, phone_number, code):
        return self.verify_result

    def cancel_verification(self, phone_number):
        return External2FAResult(success=True, status=VerificationStatus.EXPIRED)


# ============================================================================
# View Integration Tests
# ============================================================================


@pytest.mark.django_db
class TestExternal2FAViews:
    """Integration tests for external 2FA views."""

    @pytest.fixture
    def api_client(self):
        return APIClient()

    @pytest.fixture
    def user_with_phone(self):
        return User.objects.create(
            username="testuser",
            email="test@example.com",
            phone_number="+13035551234",
        )

    @pytest.fixture
    def mock_provider(self):
        return MockExternal2FAProvider()

    @pytest.fixture
    def external_2fa_settings(self, settings, mock_provider):
        """Configure external 2FA settings for testing."""
        settings.JWT_DRF_PASSWORDLESS = {
            "ALLOWED_PASSWORDLESS_METHODS": ["EMAIL", "MOBILE"],
            "REGISTER_NONEXISTENT_USERS": False,
            "EXTERNAL_2FA": {
                "provider": "tests.test_external_2fa.MockExternal2FAProvider",
                "api_key": "test_key",
                "verify_profile_id": "test_profile",
            },
        }
        return settings

    @patch("jwt_drf_passwordless.external_2fa.views.get_external_2fa_provider")
    def test_request_verification_success(
        self, mock_get_provider, api_client, user_with_phone
    ):
        mock_provider = MockExternal2FAProvider()
        mock_get_provider.return_value = mock_provider

        response = api_client.post(
            "/passwordless/external/request/",
            {"phone_number": "+13035551234"},
            format="json",
        )

        assert response.status_code == status.HTTP_200_OK
        assert "detail" in response.data

    @patch("jwt_drf_passwordless.external_2fa.views.get_external_2fa_provider")
    def test_request_verification_user_not_found(
        self, mock_get_provider, api_client
    ):
        mock_provider = MockExternal2FAProvider()
        mock_get_provider.return_value = mock_provider

        response = api_client.post(
            "/passwordless/external/request/",
            {"phone_number": "+19995551234"},  # Non-existent user
            format="json",
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @patch("jwt_drf_passwordless.external_2fa.views.get_external_2fa_provider")
    def test_request_verification_provider_not_configured(
        self, mock_get_provider, api_client, user_with_phone
    ):
        mock_get_provider.return_value = None

        response = api_client.post(
            "/passwordless/external/request/",
            {"phone_number": "+13035551234"},
            format="json",
        )

        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE

    @patch("jwt_drf_passwordless.external_2fa.views.get_external_2fa_provider")
    def test_verify_code_success(
        self, mock_get_provider, api_client, user_with_phone
    ):
        mock_provider = MockExternal2FAProvider()
        mock_get_provider.return_value = mock_provider

        response = api_client.post(
            "/passwordless/external/verify/",
            {"phone_number": "+13035551234", "code": "123456"},
            format="json",
        )

        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data
        assert "refresh" in response.data

    @patch("jwt_drf_passwordless.external_2fa.views.get_external_2fa_provider")
    def test_verify_code_rejected(
        self, mock_get_provider, api_client, user_with_phone
    ):
        mock_provider = MockExternal2FAProvider()
        mock_provider.verify_result = External2FAResult(
            success=False,
            status=VerificationStatus.REJECTED,
        )
        mock_get_provider.return_value = mock_provider

        response = api_client.post(
            "/passwordless/external/verify/",
            {"phone_number": "+13035551234", "code": "000000"},
            format="json",
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @patch("jwt_drf_passwordless.external_2fa.views.get_external_2fa_provider")
    def test_verify_code_expired(
        self, mock_get_provider, api_client, user_with_phone
    ):
        mock_provider = MockExternal2FAProvider()
        mock_provider.verify_result = External2FAResult(
            success=False,
            status=VerificationStatus.EXPIRED,
        )
        mock_get_provider.return_value = mock_provider

        response = api_client.post(
            "/passwordless/external/verify/",
            {"phone_number": "+13035551234", "code": "123456"},
            format="json",
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "expired" in response.data["detail"].lower()

    @patch("jwt_drf_passwordless.external_2fa.views.get_external_2fa_provider")
    def test_verify_activates_inactive_user(
        self, mock_get_provider, api_client, user_with_phone
    ):
        user_with_phone.is_active = False
        user_with_phone.save()

        mock_provider = MockExternal2FAProvider()
        mock_get_provider.return_value = mock_provider

        response = api_client.post(
            "/passwordless/external/verify/",
            {"phone_number": "+13035551234", "code": "123456"},
            format="json",
        )

        assert response.status_code == status.HTTP_200_OK

        user_with_phone.refresh_from_db()
        assert user_with_phone.is_active is True


# ============================================================================
# Serializer Tests
# ============================================================================


@pytest.mark.django_db
class TestExternal2FASerializers:
    """Tests for external 2FA serializers."""

    @pytest.fixture
    def user_with_phone(self):
        return User.objects.create(
            username="testuser",
            email="test@example.com",
            phone_number="+13035551234",
        )

    def test_request_serializer_valid(self, user_with_phone):
        from jwt_drf_passwordless.external_2fa.serializers import \
            External2FARequestSerializer

        serializer = External2FARequestSerializer(
            data={"phone_number": "+13035551234"}
        )
        assert serializer.is_valid()
        assert serializer.validated_data["user"] == user_with_phone

    def test_request_serializer_invalid_phone(self):
        from jwt_drf_passwordless.external_2fa.serializers import \
            External2FARequestSerializer

        serializer = External2FARequestSerializer(
            data={"phone_number": "invalid"}
        )
        assert not serializer.is_valid()

    def test_verify_serializer_valid(self, user_with_phone):
        from jwt_drf_passwordless.external_2fa.serializers import \
            External2FAVerifySerializer

        serializer = External2FAVerifySerializer(
            data={"phone_number": "+13035551234", "code": "123456"}
        )
        assert serializer.is_valid()
        assert serializer.validated_data["user"] == user_with_phone

    def test_verify_serializer_user_not_found(self):
        from jwt_drf_passwordless.external_2fa.serializers import \
            External2FAVerifySerializer

        serializer = External2FAVerifySerializer(
            data={"phone_number": "+19995551234", "code": "123456"}
        )
        assert not serializer.is_valid()


# ============================================================================
# Webhook Tests
# ============================================================================


class TestWebhookEventEnums:
    """Tests for webhook-related enums."""

    def test_webhook_event_type_values(self):
        from jwt_drf_passwordless.external_2fa.base import WebhookEventType

        assert WebhookEventType.SENT.value == "sent"
        assert WebhookEventType.DELIVERED.value == "delivered"
        assert WebhookEventType.FAILED.value == "failed"
        assert WebhookEventType.VERIFIED.value == "verified"
        assert WebhookEventType.EXPIRED.value == "expired"

    def test_delivery_status_values(self):
        from jwt_drf_passwordless.external_2fa.base import DeliveryStatus

        assert DeliveryStatus.SENT.value == "sent"
        assert DeliveryStatus.DELIVERED.value == "delivered"
        assert DeliveryStatus.SENDING_FAILED.value == "sending_failed"
        assert DeliveryStatus.DELIVERY_FAILED.value == "delivery_failed"
        assert DeliveryStatus.DELIVERY_UNCONFIRMED.value == "delivery_unconfirmed"


class TestWebhookEvent:
    """Tests for WebhookEvent dataclass."""

    def test_webhook_event_creation(self):
        from jwt_drf_passwordless.external_2fa.base import (DeliveryStatus,
                                                            WebhookEvent,
                                                            WebhookEventType)

        event = WebhookEvent(
            event_type=WebhookEventType.DELIVERED,
            event_id="event-123",
            phone_number="+13035551234",
            verification_id="verification-456",
            delivery_status=DeliveryStatus.DELIVERED,
            occurred_at="2024-01-01T00:00:00Z",
            provider="telnyx",
        )

        assert event.event_type == WebhookEventType.DELIVERED
        assert event.event_id == "event-123"
        assert event.phone_number == "+13035551234"
        assert event.verification_id == "verification-456"
        assert event.delivery_status == DeliveryStatus.DELIVERED
        assert event.provider == "telnyx"


class TestTelnyxWebhookParsing:
    """Tests for Telnyx webhook parsing."""

    @pytest.fixture
    def provider(self):
        return TelnyxVerifyProvider(
            api_key="test_key",
            verify_profile_id="test_profile",
        )

    def test_parse_verify_sent_webhook(self, provider):
        from jwt_drf_passwordless.external_2fa.base import (DeliveryStatus,
                                                            WebhookEventType)

        payload = {
            "data": {
                "event_type": "verify.sent",
                "id": "event-uuid-123",
                "occurred_at": "2024-01-01T12:00:00Z",
                "payload": {
                    "phone_number": "+13035551234",
                    "status": "sent",
                    "id": "verification-uuid",
                },
            }
        }

        event = provider.parse_webhook(payload)

        assert event.event_type == WebhookEventType.SENT
        assert event.event_id == "event-uuid-123"
        assert event.phone_number == "+13035551234"
        assert event.verification_id == "verification-uuid"
        assert event.delivery_status == DeliveryStatus.SENT
        assert event.provider == "telnyx"

    def test_parse_verify_delivered_webhook(self, provider):
        from jwt_drf_passwordless.external_2fa.base import (DeliveryStatus,
                                                            WebhookEventType)

        payload = {
            "data": {
                "event_type": "verify.delivered",
                "id": "event-uuid-456",
                "occurred_at": "2024-01-01T12:01:00Z",
                "payload": {
                    "phone_number": "+13035551234",
                    "status": "delivered",
                    "id": "verification-uuid",
                },
            }
        }

        event = provider.parse_webhook(payload)

        assert event.event_type == WebhookEventType.DELIVERED
        assert event.delivery_status == DeliveryStatus.DELIVERED

    def test_parse_verify_failed_webhook(self, provider):
        from jwt_drf_passwordless.external_2fa.base import (DeliveryStatus,
                                                            WebhookEventType)

        payload = {
            "data": {
                "event_type": "verify.failed",
                "id": "event-uuid-789",
                "occurred_at": "2024-01-01T12:02:00Z",
                "payload": {
                    "phone_number": "+13035551234",
                    "status": "delivery_failed",
                    "id": "verification-uuid",
                },
            }
        }

        event = provider.parse_webhook(payload)

        assert event.event_type == WebhookEventType.FAILED
        assert event.delivery_status == DeliveryStatus.DELIVERY_FAILED

    def test_parse_webhook_invalid_payload(self, provider):
        with pytest.raises(ValueError):
            provider.parse_webhook({"invalid": "payload"})

    def test_parse_webhook_preserves_raw_payload(self, provider):
        payload = {
            "data": {
                "event_type": "verify.sent",
                "id": "event-uuid",
                "payload": {
                    "phone_number": "+13035551234",
                    "status": "sent",
                },
            }
        }

        event = provider.parse_webhook(payload)

        assert event.raw_payload == payload


@pytest.mark.django_db
class TestWebhookView:
    """Integration tests for the webhook endpoint."""

    @pytest.fixture
    def api_client(self):
        return APIClient()

    @patch("jwt_drf_passwordless.external_2fa.views.get_external_2fa_provider")
    def test_webhook_delivered_event(self, mock_get_provider, api_client):
        from jwt_drf_passwordless.external_2fa.base import (DeliveryStatus,
                                                            WebhookEvent,
                                                            WebhookEventType)

        mock_provider = Mock()
        mock_provider.parse_webhook.return_value = WebhookEvent(
            event_type=WebhookEventType.DELIVERED,
            event_id="event-123",
            phone_number="+13035551234",
            delivery_status=DeliveryStatus.DELIVERED,
            provider="telnyx",
        )
        mock_get_provider.return_value = mock_provider

        payload = {
            "data": {
                "event_type": "verify.delivered",
                "id": "event-123",
                "payload": {"phone_number": "+13035551234"},
            }
        }

        response = api_client.post(
            "/passwordless/external/webhook/",
            payload,
            format="json",
        )

        assert response.status_code == status.HTTP_200_OK
        assert response.data["detail"] == "OK"

    @patch("jwt_drf_passwordless.external_2fa.views.get_external_2fa_provider")
    def test_webhook_failed_event(self, mock_get_provider, api_client):
        from jwt_drf_passwordless.external_2fa.base import (DeliveryStatus,
                                                            WebhookEvent,
                                                            WebhookEventType)

        mock_provider = Mock()
        mock_provider.parse_webhook.return_value = WebhookEvent(
            event_type=WebhookEventType.FAILED,
            event_id="event-456",
            phone_number="+13035551234",
            delivery_status=DeliveryStatus.DELIVERY_FAILED,
            provider="telnyx",
        )
        mock_get_provider.return_value = mock_provider

        payload = {
            "data": {
                "event_type": "verify.failed",
                "id": "event-456",
                "payload": {"phone_number": "+13035551234"},
            }
        }

        response = api_client.post(
            "/passwordless/external/webhook/",
            payload,
            format="json",
        )

        assert response.status_code == status.HTTP_200_OK

    @patch("jwt_drf_passwordless.external_2fa.views.get_external_2fa_provider")
    def test_webhook_no_provider_configured(self, mock_get_provider, api_client):
        mock_get_provider.return_value = None

        response = api_client.post(
            "/passwordless/external/webhook/",
            {"data": {}},
            format="json",
        )

        # Should return 200 to prevent retries
        assert response.status_code == status.HTTP_200_OK

    @patch("jwt_drf_passwordless.external_2fa.views.get_external_2fa_provider")
    def test_webhook_invalid_payload(self, mock_get_provider, api_client):
        mock_provider = Mock()
        mock_provider.parse_webhook.side_effect = ValueError("Invalid payload")
        mock_get_provider.return_value = mock_provider

        response = api_client.post(
            "/passwordless/external/webhook/",
            {"invalid": "data"},
            format="json",
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @patch("jwt_drf_passwordless.external_2fa.views.get_external_2fa_provider")
    def test_webhook_fires_signals(self, mock_get_provider, api_client):
        from jwt_drf_passwordless.external_2fa.base import (DeliveryStatus,
                                                            WebhookEvent,
                                                            WebhookEventType)
        from jwt_drf_passwordless.external_2fa.signals import (
            verification_delivered, verification_webhook_received)

        mock_provider = Mock()
        mock_provider.parse_webhook.return_value = WebhookEvent(
            event_type=WebhookEventType.DELIVERED,
            event_id="event-789",
            phone_number="+13035551234",
            delivery_status=DeliveryStatus.DELIVERED,
            provider="telnyx",
        )
        mock_get_provider.return_value = mock_provider

        # Track signal calls
        received_signals = []

        def on_webhook_received(sender, event, provider, **kwargs):
            received_signals.append(("webhook_received", event, provider))

        def on_delivered(sender, event, phone_number, **kwargs):
            received_signals.append(("delivered", event, phone_number))

        verification_webhook_received.connect(on_webhook_received)
        verification_delivered.connect(on_delivered)

        try:
            payload = {
                "data": {
                    "event_type": "verify.delivered",
                    "id": "event-789",
                    "payload": {"phone_number": "+13035551234"},
                }
            }

            api_client.post(
                "/passwordless/external/webhook/",
                payload,
                format="json",
            )

            # Verify signals were fired
            assert len(received_signals) == 2
            assert received_signals[0][0] == "webhook_received"
            assert received_signals[0][2] == "telnyx"
            assert received_signals[1][0] == "delivered"
            assert received_signals[1][2] == "+13035551234"

        finally:
            verification_webhook_received.disconnect(on_webhook_received)
            verification_delivered.disconnect(on_delivered)
