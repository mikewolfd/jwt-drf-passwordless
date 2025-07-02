from phonenumber_field.serializerfields import PhoneNumberField
from rest_framework import serializers
from jwt_drf_passwordless.constants import Messages
from django.contrib.auth import get_user_model
from .services import PasswordlessTokenService
from django.contrib.auth.models import update_last_login
from jwt_drf_passwordless.conf import settings
from rest_framework_simplejwt import tokens, settings as jwt_settings
import secrets

User = get_user_model()


class AbstractPasswordlessTokenRequestSerializer(serializers.Serializer):
    @property
    def token_request_identifier_field(self):
        return NotImplementedError(
            "Passwordless request needs to define at least one field to request a token with."
        )

    def find_user_by_identifier(self, identifier_value):
        try:
            return User.objects.get(
                **{self.token_request_identifier_field: identifier_value}
            )
        except User.DoesNotExist:
            return None

    def validate(self, data):
        validated_data = super().validate(data)
        identifier_value = validated_data[self.token_request_identifier_field]
        user = self.find_user_by_identifier(identifier_value)
        if not settings.REGISTER_NONEXISTENT_USERS and not user:
            raise serializers.ValidationError(Messages.CANNOT_SEND_TOKEN)
        validated_data["user"] = user
        return validated_data

    def create(self, validated_data):
        identifier_value = validated_data[self.token_request_identifier_field]
        user = validated_data["user"]
        if settings.REGISTER_NONEXISTENT_USERS is True and not user:
            attributes = {
                self.token_request_identifier_field: identifier_value,
            }

            # For mobile users, ensure email is provided since StandardUserManager requires it
            if self.token_request_identifier_field == settings.MOBILE_FIELD_NAME:
                if "email" not in attributes:
                    attributes["email"] = None

            user = User.objects.create_user(**attributes)

            # Handle password setting based on configuration
            if settings.REGISTRATION_SETS_UNUSABLE_PASSWORD:
                user.set_unusable_password()
            else:
                # Set a usable password when unusable passwords are disabled
                # Use a random password since this is passwordless authentication
                random_password = secrets.token_urlsafe(32)
                user.set_password(random_password)

            user.save()
        return user


class PasswordlessEmailTokenRequestSerializerMixin(object):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields[settings.EMAIL_FIELD_NAME] = serializers.EmailField(required=True)

    @property
    def token_request_identifier_field(self):
        return settings.EMAIL_FIELD_NAME


class PasswordlessMobileTokenRequestSerializerMixin(object):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields[settings.MOBILE_FIELD_NAME] = PhoneNumberField(required=True)

    @property
    def token_request_identifier_field(self):
        return settings.MOBILE_FIELD_NAME


class PasswordlessEmailTokenRequestSerializer(
    PasswordlessEmailTokenRequestSerializerMixin,
    AbstractPasswordlessTokenRequestSerializer,
):
    pass


class PasswordlessMobileTokenRequestSerializer(
    PasswordlessMobileTokenRequestSerializerMixin,
    AbstractPasswordlessTokenRequestSerializer,
):
    pass


class PasswordlessJwtRefreshTokenResponse:
    token_class = tokens.RefreshToken

    @classmethod
    def get_token(cls, user):
        return cls.token_class.for_user(user)  # type: ignore

    @classmethod
    def generate_auth_token(cls, user):
        refresh = cls.get_token(user)
        data = {}
        data["refresh"] = str(refresh)
        data["access"] = str(refresh.access_token)
        if jwt_settings.api_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, user)
        return data


class AbstractPasswordlessTokenExchangeSerializer(serializers.Serializer):
    token_serializer_class = (
        settings.SERIALIZERS.passwordless_token_response_class
        if settings.SERIALIZERS.passwordless_token_response_class is not None
        else PasswordlessJwtRefreshTokenResponse
    )

    @property
    def token_request_identifier_field(self):
        return None

    default_error_messages = {
        "invalid_credentials": settings.CONSTANTS.messages.INVALID_CREDENTIALS_ERROR
    }
    token = serializers.CharField(required=True)

    @classmethod
    def generate_auth_token(cls, user):
        return cls.token_serializer_class.generate_auth_token(user)  # type: ignore

    def validate(self, attrs):
        super().validate(attrs)
        valid_token = PasswordlessTokenService.check_token(
            attrs.get("token", None),
            self.token_request_identifier_field,
            attrs.get(self.token_request_identifier_field, None),
        )
        if valid_token:
            self.user = valid_token.user
            return self.generate_auth_token(self.user)
        self.fail("invalid_credentials")


class PasswordlessEmailTokenExchangeSerializer(
    PasswordlessEmailTokenRequestSerializerMixin,
    AbstractPasswordlessTokenExchangeSerializer,
):
    pass


class PasswordlessMobileTokenExchangeSerializer(
    PasswordlessMobileTokenRequestSerializerMixin,
    AbstractPasswordlessTokenExchangeSerializer,
):
    pass
