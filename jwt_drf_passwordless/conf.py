from django.conf import settings as django_settings
from django.test.signals import setting_changed
from django.utils.functional import LazyObject
from django.utils.module_loading import import_string

JWT_DRF_PASSWORDLESS_SETTINGS_NAMESPACE = "JWT_DRF_PASSWORDLESS"


class ObjDict(dict):
    def __getattribute__(self, item):
        try:
            val = self[item]
            if isinstance(val, str):
                val = import_string(val)
            elif isinstance(val, (list, tuple)):
                val = [import_string(v) if isinstance(v, str) else v for v in val]
            self[item] = val
        except KeyError:
            val = super().__getattribute__(item)
        return val


default_settings = {
    "SHORT_TOKEN_LENGTH": 6,
    "LONG_TOKEN_LENGTH": 64,
    "SHORT_TOKEN_CHARS": "0123456789",
    "LONG_TOKEN_CHARS": "abcdefghijklmnopqrstuvwxyz0123456789",
    "TOKEN_LIFETIME": 600,
    "TOKEN_REQUEST_THROTTLE_SECONDS": 60,
    "ALLOW_ADMIN_AUTHENTICATION": False,
    "REGISTER_NONEXISTENT_USERS": False,
    "REGISTRATION_SETS_UNUSABLE_PASSWORD": True,
    "EMAIL_FIELD_NAME": "email",
    "MOBILE_FIELD_NAME": "phone_number",
    # If true, an attempt to redeem a token with the wrong token type
    # will count for the times a token has been used
    "INCORRECT_SHORT_TOKEN_REDEEMS_TOKEN": False,
    "ALLOWED_PASSWORDLESS_METHODS": ["EMAIL"],  # ["EMAIL", "MOBILE"]
    "PASSWORDLESS_EMAIL_LOGIN_URL": None,
    "MAX_TOKEN_USES": 1,
    "EMAIL": ObjDict(
        {
            "passwordless_request": "jwt_drf_passwordless.email.PasswordlessRequestEmail",
        }
    ),
    "SERIALIZERS": ObjDict(
        {
            "passwordless_token_response_class": None,
            "passwordless_email_token_request": "jwt_drf_passwordless.serializers.PasswordlessEmailTokenRequestSerializer",
            "passwordless_mobile_token_request": "jwt_drf_passwordless.serializers.PasswordlessMobileTokenRequestSerializer",
            "passwordless_email_token_exchange": "jwt_drf_passwordless.serializers.PasswordlessEmailTokenExchangeSerializer",
            "passwordless_mobile_token_exchange": "jwt_drf_passwordless.serializers.PasswordlessMobileTokenExchangeSerializer",
        }
    ),
    "PERMISSIONS": ObjDict(
        {
            "passwordless_token_exchange": ["rest_framework.permissions.AllowAny"],
            "passwordless_token_request": ["rest_framework.permissions.AllowAny"],
        }
    ),
    "DECORATORS": ObjDict(
        {
            "token_request_rate_limit_decorator": "jwt_drf_passwordless.utils.token_request_limiter",
            "token_redeem_rate_limit_decorator": "jwt_drf_passwordless.utils.token_redeem_limiter",
        }
    ),
    "SMS_SENDERS": ObjDict(
        {
            "passwordless_request": "jwt_drf_passwordless.sms.PasswordlessRequestSMS",
        }
    ),
    "CONSTANTS": ObjDict({"messages": "jwt_drf_passwordless.constants.Messages"}),
    # External 2FA provider configuration (e.g., Telnyx, Twilio)
    # Set to None to use internal token generation
    "EXTERNAL_2FA": None,
    # Example configuration for Telnyx:
    # "EXTERNAL_2FA": {
    #     "provider": "jwt_drf_passwordless.external_2fa.TelnyxVerifyProvider",
    #     "api_key": "YOUR_TELNYX_API_KEY",
    #     "verify_profile_id": "YOUR_VERIFY_PROFILE_ID",
    #     # Optional: webhook signature verification (recommended for production)
    #     # Get from: https://portal.telnyx.com/#/api-keys/public-key
    #     "webhook_public_key": "YOUR_TELNYX_PUBLIC_KEY",
    # },
}


SETTINGS_TO_IMPORT = []


class Settings:
    def __init__(self, default_settings, explicit_overriden_settings: dict = None):
        if explicit_overriden_settings is None:
            explicit_overriden_settings = {}

        overriden_settings = (getattr(django_settings, JWT_DRF_PASSWORDLESS_SETTINGS_NAMESPACE, {}) or explicit_overriden_settings)

        self._load_default_settings()
        self._override_settings(overriden_settings)
        self._init_settings_to_import()

    def _load_default_settings(self):
        for setting_name, setting_value in default_settings.items():
            if setting_name.isupper():
                setattr(self, setting_name, setting_value)

    def _override_settings(self, overriden_settings: dict):
        for setting_name, setting_value in overriden_settings.items():
            value = setting_value
            if isinstance(setting_value, dict):
                current_value = getattr(self, setting_name, None)
                if not isinstance(current_value, dict):
                    current_value = {}
                value = ObjDict(current_value)
                value.update(ObjDict(setting_value))
            setattr(self, setting_name, value)

    def _init_settings_to_import(self):
        for setting_name in SETTINGS_TO_IMPORT:
            value = getattr(self, setting_name)
            if isinstance(value, str):
                setattr(self, setting_name, import_string(value))


class LazySettings(LazyObject):
    def _setup(self, explicit_overriden_settings=None):
        self._wrapped = Settings(default_settings, explicit_overriden_settings)


settings = LazySettings()


def reload_settings(*args, **kwargs):
    global settings
    setting, value = kwargs["setting"], kwargs["value"]
    if setting == JWT_DRF_PASSWORDLESS_SETTINGS_NAMESPACE:
        settings._setup(explicit_overriden_settings=value)


setting_changed.connect(reload_settings)
