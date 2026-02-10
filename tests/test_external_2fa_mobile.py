"""
Tests for external 2FA via the standard mobile endpoints.

When EXTERNAL_2FA is configured, /request/mobile/ and /exchange/mobile/
transparently delegate to the external provider. The API contract
(field names, response shape) is unchanged.
"""

from unittest.mock import Mock, patch

import pytest
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APIClient

from jwt_drf_passwordless.external_2fa.base import (
    External2FAProvider,
    External2FAResult,
    VerificationMethod,
    VerificationStatus,
)

User = get_user_model()


# ---------------------------------------------------------------------------
# Mock provider reused across tests
# ---------------------------------------------------------------------------


class MockProvider(External2FAProvider):
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


class CustomTokenResponse:
    @classmethod
    def generate_auth_token(cls, user):
        return {"access": "custom-access", "refresh": "custom-refresh", "custom": True}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

EXTERNAL_2FA_SETTINGS = {
    "ALLOWED_PASSWORDLESS_METHODS": ["EMAIL", "MOBILE"],
    "REGISTER_NONEXISTENT_USERS": False,
    "EXTERNAL_2FA": {
        "provider": "tests.test_external_2fa_mobile.MockProvider",
        "api_key": "test",
        "verify_profile_id": "test",
    },
}


# ============================================================================
# No EXTERNAL_2FA — internal mobile flow unchanged (no regressions)
# ============================================================================


@pytest.mark.django_db
class TestInternalFlow:
    """When EXTERNAL_2FA is not configured, the standard
    mobile flow should work exactly as before."""

    @pytest.fixture
    def api_client(self):
        return APIClient()

    @pytest.fixture
    def user(self):
        return User.objects.create_user(
            username="alice",
            email="alice@example.com",
            phone_number="+13035551234",
        )

    def test_request_mobile_uses_internal_flow(self, api_client, user, settings):
        settings.JWT_DRF_PASSWORDLESS = {
            "ALLOWED_PASSWORDLESS_METHODS": ["EMAIL", "MOBILE"],
        }

        response = api_client.post(
            "/passwordless/request/mobile/",
            {"phone_number": "+13035551234"},
            format="json",
        )
        # Internal flow sends SMS via django-sms (console backend in tests).
        assert response.status_code == status.HTTP_200_OK
        assert "detail" in response.data

    def test_exchange_mobile_uses_internal_flow(self, api_client, user, settings):
        from jwt_drf_passwordless.services import PasswordlessTokenService

        settings.JWT_DRF_PASSWORDLESS = {
            "ALLOWED_PASSWORDLESS_METHODS": ["EMAIL", "MOBILE"],
        }

        token = PasswordlessTokenService.create_token(user, "phone_number")

        response = api_client.post(
            "/passwordless/exchange/mobile/",
            {"phone_number": "+13035551234", "token": token.short_token},
            format="json",
        )

        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data
        assert "refresh" in response.data


# ============================================================================
# EXTERNAL_2FA configured — request endpoint delegates to external provider
# ============================================================================


@pytest.mark.django_db
class TestExternalRequest:
    """When EXTERNAL_2FA is configured, /request/mobile/ should
    delegate to the external provider."""

    @pytest.fixture
    def api_client(self):
        return APIClient()

    @pytest.fixture
    def user(self):
        return User.objects.create_user(
            username="bob",
            email="bob@example.com",
            phone_number="+13035559999",
        )

    @patch("jwt_drf_passwordless.external_2fa.get_external_2fa_provider")
    def test_request_calls_provider(
        self, mock_get_provider, api_client, user, settings
    ):
        settings.JWT_DRF_PASSWORDLESS = EXTERNAL_2FA_SETTINGS

        mock_provider = MockProvider()
        mock_get_provider.return_value = mock_provider

        response = api_client.post(
            "/passwordless/request/mobile/",
            {"phone_number": "+13035559999"},
            format="json",
        )

        assert response.status_code == status.HTTP_200_OK
        assert "detail" in response.data

    @patch("jwt_drf_passwordless.external_2fa.get_external_2fa_provider")
    def test_request_no_db_token_created(
        self, mock_get_provider, api_client, user, settings
    ):
        """External flow should NOT create a PasswordlessChallengeToken."""
        from jwt_drf_passwordless.models import PasswordlessChallengeToken

        settings.JWT_DRF_PASSWORDLESS = EXTERNAL_2FA_SETTINGS

        mock_provider = MockProvider()
        mock_get_provider.return_value = mock_provider

        initial_count = PasswordlessChallengeToken.objects.count()

        api_client.post(
            "/passwordless/request/mobile/",
            {"phone_number": "+13035559999"},
            format="json",
        )

        assert PasswordlessChallengeToken.objects.count() == initial_count

    @patch("jwt_drf_passwordless.external_2fa.get_external_2fa_provider")
    def test_request_admin_check(self, mock_get_provider, api_client, settings):
        User.objects.create_user(
            username="admin",
            email="admin@example.com",
            phone_number="+13035558888",
            is_staff=True,
        )
        settings.JWT_DRF_PASSWORDLESS = {
            **EXTERNAL_2FA_SETTINGS,
            "ALLOW_ADMIN_AUTHENTICATION": False,
        }

        mock_provider = MockProvider()
        mock_get_provider.return_value = mock_provider

        response = api_client.post(
            "/passwordless/request/mobile/",
            {"phone_number": "+13035558888"},
            format="json",
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @patch("jwt_drf_passwordless.external_2fa.get_external_2fa_provider")
    def test_request_registers_new_user(self, mock_get_provider, api_client, settings):
        settings.JWT_DRF_PASSWORDLESS = {
            **EXTERNAL_2FA_SETTINGS,
            "REGISTER_NONEXISTENT_USERS": True,
        }

        mock_provider = MockProvider()
        mock_get_provider.return_value = mock_provider

        phone = "+12025550177"
        assert not User.objects.filter(phone_number=phone).exists()

        response = api_client.post(
            "/passwordless/request/mobile/",
            {"phone_number": phone},
            format="json",
        )

        assert response.status_code == status.HTTP_200_OK
        assert User.objects.filter(phone_number=phone).exists()

    @patch("jwt_drf_passwordless.external_2fa.get_external_2fa_provider")
    def test_request_provider_failure(
        self, mock_get_provider, api_client, user, settings
    ):
        settings.JWT_DRF_PASSWORDLESS = EXTERNAL_2FA_SETTINGS

        mock_provider = MockProvider()
        mock_provider.send_result = External2FAResult(
            success=False,
            status=VerificationStatus.ERROR,
            message="Rate limited",
        )
        mock_get_provider.return_value = mock_provider

        response = api_client.post(
            "/passwordless/request/mobile/",
            {"phone_number": "+13035559999"},
            format="json",
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST


# ============================================================================
# EXTERNAL_2FA configured — exchange endpoint delegates to external provider
# ============================================================================


@pytest.mark.django_db
class TestExternalExchange:
    """When EXTERNAL_2FA is configured, /exchange/mobile/ should
    verify via the external provider and return JWT tokens."""

    @pytest.fixture
    def api_client(self):
        return APIClient()

    @pytest.fixture
    def user(self):
        return User.objects.create_user(
            username="carol",
            email="carol@example.com",
            phone_number="+13035557777",
        )

    @patch("jwt_drf_passwordless.external_2fa.get_external_2fa_provider")
    def test_exchange_returns_jwt(self, mock_get_provider, api_client, user, settings):
        settings.JWT_DRF_PASSWORDLESS = EXTERNAL_2FA_SETTINGS

        mock_provider = MockProvider()
        mock_get_provider.return_value = mock_provider

        response = api_client.post(
            "/passwordless/exchange/mobile/",
            {"phone_number": "+13035557777", "token": "123456"},
            format="json",
        )

        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data
        assert "refresh" in response.data

    @patch("jwt_drf_passwordless.external_2fa.get_external_2fa_provider")
    def test_exchange_activates_inactive_user(
        self, mock_get_provider, api_client, user, settings
    ):
        user.is_active = False
        user.save()

        settings.JWT_DRF_PASSWORDLESS = EXTERNAL_2FA_SETTINGS

        mock_provider = MockProvider()
        mock_get_provider.return_value = mock_provider

        response = api_client.post(
            "/passwordless/exchange/mobile/",
            {"phone_number": "+13035557777", "token": "123456"},
            format="json",
        )

        assert response.status_code == status.HTTP_200_OK
        user.refresh_from_db()
        assert user.is_active is True

    @patch("jwt_drf_passwordless.external_2fa.get_external_2fa_provider")
    def test_exchange_fires_callback(
        self, mock_get_provider, api_client, user, settings
    ):
        callback = Mock()
        settings.JWT_DRF_PASSWORDLESS = {
            **EXTERNAL_2FA_SETTINGS,
            "CALLBACKS": {"on_verification_accepted": callback},
        }

        mock_provider = MockProvider()
        mock_get_provider.return_value = mock_provider

        response = api_client.post(
            "/passwordless/exchange/mobile/",
            {"phone_number": "+13035557777", "token": "123456"},
            format="json",
        )

        assert response.status_code == status.HTTP_200_OK
        callback.assert_called_once()
        call_kwargs = callback.call_args[1]
        assert call_kwargs["user"] == user
        assert call_kwargs["phone_number"] == "+13035557777"
        assert "request" in call_kwargs

    @patch("jwt_drf_passwordless.external_2fa.get_external_2fa_provider")
    def test_exchange_honors_custom_token_response_class(
        self, mock_get_provider, api_client, user, settings
    ):
        settings.JWT_DRF_PASSWORDLESS = {
            **EXTERNAL_2FA_SETTINGS,
            "SERIALIZERS": {
                "passwordless_token_response_class": "tests.test_external_2fa_mobile.CustomTokenResponse",
            },
        }

        mock_provider = MockProvider()
        mock_get_provider.return_value = mock_provider

        response = api_client.post(
            "/passwordless/exchange/mobile/",
            {"phone_number": "+13035557777", "token": "123456"},
            format="json",
        )

        assert response.status_code == status.HTTP_200_OK
        assert response.data["access"] == "custom-access"
        assert response.data["refresh"] == "custom-refresh"
        assert response.data["custom"] is True

    @patch("jwt_drf_passwordless.external_2fa.get_external_2fa_provider")
    def test_exchange_rejected(self, mock_get_provider, api_client, user, settings):
        settings.JWT_DRF_PASSWORDLESS = EXTERNAL_2FA_SETTINGS

        mock_provider = MockProvider()
        mock_provider.verify_result = External2FAResult(
            success=False,
            status=VerificationStatus.REJECTED,
        )
        mock_get_provider.return_value = mock_provider

        response = api_client.post(
            "/passwordless/exchange/mobile/",
            {"phone_number": "+13035557777", "token": "000000"},
            format="json",
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @patch("jwt_drf_passwordless.external_2fa.get_external_2fa_provider")
    def test_exchange_expired(self, mock_get_provider, api_client, user, settings):
        settings.JWT_DRF_PASSWORDLESS = EXTERNAL_2FA_SETTINGS

        mock_provider = MockProvider()
        mock_provider.verify_result = External2FAResult(
            success=False,
            status=VerificationStatus.EXPIRED,
        )
        mock_get_provider.return_value = mock_provider

        response = api_client.post(
            "/passwordless/exchange/mobile/",
            {"phone_number": "+13035557777", "token": "123456"},
            format="json",
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "expired" in response.data["detail"].lower()

    @patch("jwt_drf_passwordless.external_2fa.get_external_2fa_provider")
    def test_exchange_nonexistent_user(self, mock_get_provider, api_client, settings):
        settings.JWT_DRF_PASSWORDLESS = EXTERNAL_2FA_SETTINGS

        mock_provider = MockProvider()
        mock_get_provider.return_value = mock_provider

        response = api_client.post(
            "/passwordless/exchange/mobile/",
            {"phone_number": "+19995550000", "token": "123456"},
            format="json",
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST


# ============================================================================
# Edge cases
# ============================================================================


@pytest.mark.django_db
class TestEdgeCases:

    @pytest.fixture
    def api_client(self):
        return APIClient()

    @pytest.fixture
    def user(self):
        return User.objects.create_user(
            username="dave",
            email="dave@example.com",
            phone_number="+13035556666",
        )

    @patch("jwt_drf_passwordless.external_2fa.get_external_2fa_provider")
    def test_request_provider_not_configured_returns_503(
        self, mock_get_provider, api_client, user, settings
    ):
        settings.JWT_DRF_PASSWORDLESS = EXTERNAL_2FA_SETTINGS
        mock_get_provider.return_value = None

        response = api_client.post(
            "/passwordless/request/mobile/",
            {"phone_number": "+13035556666"},
            format="json",
        )

        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE

    @patch("jwt_drf_passwordless.external_2fa.get_external_2fa_provider")
    def test_exchange_provider_not_configured_returns_503(
        self, mock_get_provider, api_client, user, settings
    ):
        settings.JWT_DRF_PASSWORDLESS = EXTERNAL_2FA_SETTINGS
        mock_get_provider.return_value = None

        response = api_client.post(
            "/passwordless/exchange/mobile/",
            {"phone_number": "+13035556666", "token": "123456"},
            format="json",
        )

        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
