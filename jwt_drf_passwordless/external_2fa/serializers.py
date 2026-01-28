"""
Serializers for external 2FA verification.

These serializers handle validation for the external 2FA flow where
an external provider (Telnyx, Twilio) manages the verification codes.
"""

from django.contrib.auth import get_user_model
from django.contrib.auth.models import update_last_login
from phonenumber_field.serializerfields import PhoneNumberField
from rest_framework import serializers
from rest_framework_simplejwt import settings as jwt_settings
from rest_framework_simplejwt import tokens

from jwt_drf_passwordless.conf import settings
from jwt_drf_passwordless.constants import Messages

User = get_user_model()


class External2FARequestSerializer(serializers.Serializer):
    """
    Serializer for requesting external 2FA verification.

    Validates the phone number and optionally creates a new user
    if REGISTER_NONEXISTENT_USERS is enabled.
    """

    phone_number = PhoneNumberField(required=True)

    def validate(self, data):
        validated_data = super().validate(data)
        phone_number = validated_data["phone_number"]

        # Look up user by phone number
        mobile_field = settings.MOBILE_FIELD_NAME
        try:
            user = User.objects.get(**{mobile_field: phone_number})
        except User.DoesNotExist:
            user = None

        # Check if we should register new users
        if not settings.REGISTER_NONEXISTENT_USERS and not user:
            raise serializers.ValidationError(Messages.CANNOT_SEND_TOKEN)

        validated_data["user"] = user
        return validated_data

    def create(self, validated_data):
        """Create a new user if allowed and user doesn't exist."""
        user = validated_data.get("user")
        phone_number = validated_data["phone_number"]

        if settings.REGISTER_NONEXISTENT_USERS and not user:
            mobile_field = settings.MOBILE_FIELD_NAME
            user = User.objects.create(**{mobile_field: phone_number})
            if settings.REGISTRATION_SETS_UNUSABLE_PASSWORD:
                user.set_unusable_password()
            user.save()
            validated_data["user"] = user

        return user


class External2FAVerifySerializer(serializers.Serializer):
    """
    Serializer for verifying external 2FA code.

    Validates that the phone number exists and the user is valid.
    The actual code verification is done by the external provider.
    """

    phone_number = PhoneNumberField(required=True)
    code = serializers.CharField(required=True, max_length=10)

    # Token generation class (can be overridden via settings)
    @property
    def token_serializer_class(self):
        custom_class = settings.SERIALIZERS.passwordless_token_response_class
        if custom_class is not None:
            return custom_class
        return DefaultJwtTokenGenerator

    def validate(self, data):
        validated_data = super().validate(data)
        phone_number = validated_data["phone_number"]

        # Look up user by phone number
        mobile_field = settings.MOBILE_FIELD_NAME
        try:
            user = User.objects.get(**{mobile_field: phone_number})
        except User.DoesNotExist:
            raise serializers.ValidationError(Messages.INVALID_CREDENTIALS_ERROR)

        validated_data["user"] = user
        return validated_data

    @classmethod
    def generate_auth_token(cls, user):
        """Generate JWT tokens for the authenticated user."""
        return DefaultJwtTokenGenerator.generate_auth_token(user)


class DefaultJwtTokenGenerator:
    """Default JWT token generator using simplejwt."""

    token_class = tokens.RefreshToken

    @classmethod
    def get_token(cls, user):
        return cls.token_class.for_user(user)

    @classmethod
    def generate_auth_token(cls, user):
        refresh = cls.get_token(user)
        data = {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        }
        if jwt_settings.api_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, user)
        return data
