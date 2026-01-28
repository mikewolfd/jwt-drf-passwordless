from django.urls import re_path

from . import views
from .external_2fa import views as external_2fa_views

urlpatterns = [
    re_path(
        r"^request/email/$",
        views.PasswordlessEmailTokenRequestView.as_view(),
        name="passwordless_email_signup_request",
    ),
    re_path(
        r"^request/mobile/$",
        views.PasswordlessMobileTokenRequestView.as_view(),
        name="passwordless_mobile_signup_request",
    ),
    re_path(
        r"^exchange/mobile/$",
        views.MobileExchangePasswordlessTokenForAuthTokenView.as_view(),
        name="mobile_passwordless_token_exchange",
    ),
    re_path(
        r"^exchange/email/$",
        views.EmailExchangePasswordlessTokenForAuthTokenView.as_view(),
        name="email_passwordless_token_exchange",
    ),
    # External 2FA provider endpoints (Telnyx, Twilio, etc.)
    re_path(
        r"^external/request/$",
        external_2fa_views.External2FARequestView.as_view(),
        name="external_2fa_request",
    ),
    re_path(
        r"^external/verify/$",
        external_2fa_views.External2FAVerifyView.as_view(),
        name="external_2fa_verify",
    ),
    re_path(
        r"^external/webhook/$",
        external_2fa_views.External2FAWebhookView.as_view(),
        name="external_2fa_webhook",
    ),
]
