from django.contrib.auth import get_user_model
from djet import assertions
from rest_framework import status
from rest_framework.reverse import reverse
from rest_framework.test import APITestCase
from .common import create_user
from django.conf import settings
from django.test.utils import override_settings

User = get_user_model()


class TestPasswordlessMobileTokenRequest(
    APITestCase, assertions.StatusCodeAssertionsMixin
):
    url = reverse("passwordless_mobile_signup_request")

    def test_post_gibberish_will_return_validation_errors(self):
        data = {"phone_number": "Totally a phone number"}
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_400_BAD_REQUEST)

    @override_settings(
        JWT_DRF_PASSWORDLESS=dict(
            settings.JWT_DRF_PASSWORDLESS, **{"REGISTER_NONEXISTENT_USERS": False}
        )
    )
    def test_post_with_non_existing_user_should_return_400_if_registration_disabled(
        self,
    ):
        data = {"phone_number": "+358 414111111"}
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_400_BAD_REQUEST)

    @override_settings(
        JWT_DRF_PASSWORDLESS=dict(
            settings.JWT_DRF_PASSWORDLESS, **{"REGISTER_NONEXISTENT_USERS": True}
        )
    )
    def test_post_request_with_new_user_successful_with_registration_enabled(self):
        data = {"phone_number": "+358 414111111"}
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_200_OK)
        user = User.objects.get(phone_number="+358414111111")
        self.assertIsNotNone(user)

    def test_post_request_with_existing_user_successful(self):
        user = create_user(phone_number="+358414111111")
        data = {"phone_number": "+358414111111"}
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_200_OK)
        user.jwt_drf_passwordless_tokens.count() == 1

    @override_settings(
        JWT_DRF_PASSWORDLESS=dict(
            settings.JWT_DRF_PASSWORDLESS, **{"TOKEN_REQUEST_THROTTLE_SECONDS": None}
        )
    )
    def test_post_request_user_should_not_have_more_than_one_active_token(self):
        user = create_user(phone_number="+358414111111")
        data = {"phone_number": "+358414111111"}
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_200_OK)
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_200_OK)
        user.jwt_drf_passwordless_tokens.count() == 1

    @override_settings(
        JWT_DRF_PASSWORDLESS=dict(
            settings.JWT_DRF_PASSWORDLESS, **{"TOKEN_REQUEST_THROTTLE_SECONDS": None}
        )
    )
    def test_normalize_phone_number_do_not_create_multiple(self):
        user = create_user(phone_number="+358414111111")
        data = {"phone_number": "+358 0414111111"}
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_200_OK)
        data = {"phone_number": "+358  414111111"}
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_200_OK)

        user.jwt_drf_passwordless_tokens.count() == 1

    def test_throttle_token_requests_independently_of_phone_format(self):
        user = create_user(phone_number="+358414111111")
        data = {"phone_number": "+358 0414111111"}
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_200_OK)
        data = {"phone_number": "+358 414111111"}
        response = self.client.post(self.url, data=data)
        self.assert_status_equal(response, status.HTTP_429_TOO_MANY_REQUESTS)
        user.jwt_drf_passwordless_tokens.count() == 1
