"""
Built-in fake 2FA provider for testing and local development.

Usage in Django settings::

    JWT_DRF_PASSWORDLESS = {
        "EXTERNAL_2FA": {
            "provider": "jwt_drf_passwordless.external_2fa.FakeVerifyProvider",
            "api_key": "ignored",
            "verify_profile_id": "ignored",
        },
    }

The default verification code is ``"12345"``. Override via constructor::

    FakeVerifyProvider(code="99999")
"""

from .base import (
    External2FAProvider,
    External2FAResult,
    VerificationMethod,
    VerificationStatus,
)


class FakeVerifyProvider(External2FAProvider):
    """
    In-memory 2FA provider that accepts a fixed code.

    Useful for:
    - Automated test suites (no network calls)
    - Local development without external API keys
    - CI pipelines
    """

    def __init__(self, code="12345", **kwargs):
        self.code = str(code)

    def is_configured(self):
        return True

    def send_verification(self, phone_number, method=VerificationMethod.SMS):
        return External2FAResult(
            success=True,
            status=VerificationStatus.PENDING,
            verification_id="fake-verification-id",
            message="Fake verification sent",
        )

    def verify_code(self, phone_number, code):
        if str(code) == self.code:
            return External2FAResult(
                success=True,
                status=VerificationStatus.ACCEPTED,
                message="Verification successful",
            )
        return External2FAResult(
            success=False,
            status=VerificationStatus.REJECTED,
            message="Invalid code",
        )

    def cancel_verification(self, phone_number):
        return External2FAResult(
            success=True,
            status=VerificationStatus.EXPIRED,
            message="Verification cancelled",
        )
