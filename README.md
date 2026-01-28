# **⛔️ ALPHA -- WORK IN PROGRESS**

# jwt drf passwordless
A Passwordless login add-on for Django Rest Framework authentication. Built with `django-sms`, `django-phonenumber-field` and `djangorestframework-simplejwt` with complete statelessness in mind.

## Great Thanks
This project is a fork of Sergioisidoro's [`djoser-passwordless`](https://github.com/sergioisidoro/djoser-passwordless) project, I have mostly just modified and customized this to be more in line with my own needs and preferences. Which include statelessness, independence of other authentication packages, and a more flexible and configurable approach to the token generation and validation.

## 🔑 Before you start!
Please consider your risk and threat landscape before adopting this library.

Authentication is always a trade-off of usability and security. This library has been built to give you the power to adjust those trade-offs as much as possible, and made an attempt to give you a reasonable set of defaults, but it's up to you to make those decisions. Please consider the following risks bellow.

## TODO
* [ ] recaptcha verification
* [ ] webauthn support
* [ ] better documentation

## Installation 
```.sh
pip install jwt_drf_passwordless
```

`settings.py`
```.py
INSTALLED_APPS = (
    ...
    "jwt_drf_passwordless",
    ...
)
...
jwt_drf_passwordless = {
    "ALLOWED_PASSWORDLESS_METHODS": ["EMAIL", "MOBILE"]
}
```
**Remember to set the settings for `django-sms` and `django-phonenumber-field`** if you are using mobile token requests

```
urlpatterns = (
    ...
    re_path(r"^passwordless/", include("jwt_drf_passwordless.urls")),
    ...
)
```

## 🕵️ Risks 
### Brute force
Although token requests are throttled by default, and token lifetime is limited, if you know a user email/phone it is possible to continuously request tokens (the default throttle is 1 minute), and try to brute force that token during the token lifetime (10 minutes).

#### Mitigations
* Set `INCORRECT_SHORT_TOKEN_REDEEMS_TOKEN` to `True`, so that any attempts at redeeming a token from an account will count as a user (`MAX_TOKEN_USES` is default set to 1) - **Tradeoff** is that if a user is being a victim of brute force attack, they will not be able to login with passwordless tokens, since it's likely the attacker will exhaust the token uses with failed attempts 

* Set `DECORATORS.token_redeem_rate_limit_decorator` or `DECORATORS.token_request_rate_limit_decorator` with your choice of request throttling library. - **Tradeoff** is that if there is an attacker hitting your service, you might prevent **any** user from logging in because someone is hitting this endpoint, so beware how you implement it. Note that because request limiting usually requires a key value db like redis, it is explicitly left out of this project to reduce it's dependencies and configuration needs.

* **Use External 2FA Providers** - Services like Telnyx Verify and Twilio Verify handle rate limiting, code generation, and delivery tracking. They also provide carrier-level fraud detection. - **Tradeoff** is vendor dependency and per-verification costs, but significantly improved security posture.

### Webhook Security

When using external 2FA providers, always enable webhook signature verification to prevent spoofed delivery events. For Telnyx, configure `webhook_public_key` in your settings to enable Ed25519 signature verification.

## Features
* International phone number validation and standardization (expects db phone numbers to be in same format)
* Basic throttling
* Stateless JWT tokens by default
* Short (for SMS) and long tokens for magic links
* Configurable serializers, permissions and decorators
* **External 2FA provider support** (Telnyx, Twilio, etc.) - delegate code generation to trusted providers

## URLs and Examples:

#### Available URLS

**Internal Token Flow** (tokens generated and stored locally):
* `request/email/` - Request token via email
* `request/mobile/` - Request token via SMS
* `exchange/email/` - Exchange email token for JWT
* `exchange/mobile/` - Exchange mobile token for JWT

**External 2FA Flow** (tokens managed by external provider):
* `external/request/` - Request verification via external provider
* `external/verify/` - Verify code and get JWT tokens
* `external/webhook/` - Receive delivery status webhooks

**Requesting a token**
```.sh
curl --request POST \
  --url http://localhost:8000/passwordless/request/email/ \
  --data '{
	"email": "sergioisidoro@example.com"
}'
```
Response
```.json
{
	"detail": "A token has been sent to you"
}
```

**Exchanging a one time token for a auth token**
```.sh
curl --request POST \
  --url http://localhost:8000/passwordless/exchange/ \
  --data '{
	"email": "sergioisidoro@example.com"
	"token": "902488"
}'
```
```.json
{
	"refresh": "3b8e6a2aed0435f95495e728b0fb41d0367a872d",
  "access": "3b8e6a2aed0435f95495e728b0fb41d0367a872d"
}
```

### External 2FA Provider Flow

When using an external provider like Telnyx Verify, the provider handles code generation and delivery.

**Requesting verification via external provider**
```.sh
curl --request POST \
  --url http://localhost:8000/passwordless/external/request/ \
  --header 'Content-Type: application/json' \
  --data '{
	"phone_number": "+13035551234"
}'
```
Response
```.json
{
	"detail": "A token has been sent to you"
}
```

**Verifying code and getting JWT tokens**
```.sh
curl --request POST \
  --url http://localhost:8000/passwordless/external/verify/ \
  --header 'Content-Type: application/json' \
  --data '{
	"phone_number": "+13035551234",
	"code": "123456"
}'
```
```.json
{
	"refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
	"access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

## Config

#### Basic configuration

* `ALLOWED_PASSWORDLESS_METHODS` (default=["email"]) - Which methods can be used to request a token? (Valid - `["email", "mobile"]`)
* `EMAIL_FIELD_NAME` (default="email") - Name of the user field that holds the email info
* `MOBILE_FIELD_NAME` (default="phone_number") - Name of the user field that holds phone number info
* `SHORT_TOKEN_LENGTH` (default=6) - The length of the short tokens
* `LONG_TOKEN_LENGTH` (default=64) - The length of the tokens that can redeemed standalone (without the original request data)
* `SHORT_TOKEN_CHARS` (default="0123456789") - The characters to be used when generating the short token
* `LONG_TOKEN_CHARS` (default="abcdefghijklmnopqrstuvwxyz0123456789") - Tokens used to generate the long token
* `TOKEN_LIFETIME` (default=600) - Number of seconds the token is valid
* `MAX_TOKEN_USES` (default=1) - How many times a token can be used - This can be adjusted because some email clients try to follow links, and might accidentally use tokens.
* `TOKEN_REQUEST_THROTTLE_SECONDS` - (default=60) - How many seconds to wait before allowing a new token to be issued for a particular user
* `ALLOW_ADMIN_AUTHENTICATION` (default=False) - Allow admin users to login without password (checks `is_admin` and `is_staff` from Django `AbstractUser`)
* `REGISTER_NONEXISTENT_USERS` (default=False) - Register users who do not have an account and request a passwordless login token?
* `REGISTRATION_SETS_UNUSABLE_PASSWORD` (Default=True) - When unusable password is set, users cannot reset passwords via the normal Django flows. This means users registered via passwordless cannot login through password.
* `INCORRECT_SHORT_TOKEN_REDEEMS_TOKEN` (default=False) - Should incorrect short token auth attempts count to the uses of a token? When set to true, together with `MAX_TOKEN_USES` to 1, this means a token has only one shot at being used.
* `PASSWORDLESS_EMAIL_LOGIN_URL` (default=None) - URL template for the link redeeming the standalone link: eg `my-app://page/{token}`
  
#### Advanced configuration

##### External 2FA Provider

To use an external 2FA provider like Telnyx or Twilio instead of internal token generation:

```.py
JWT_DRF_PASSWORDLESS = {
    "ALLOWED_PASSWORDLESS_METHODS": ["MOBILE"],
    "EXTERNAL_2FA": {
        "provider": "jwt_drf_passwordless.external_2fa.TelnyxVerifyProvider",
        "api_key": "YOUR_TELNYX_API_KEY",
        "verify_profile_id": "YOUR_TELNYX_VERIFY_PROFILE_ID",
        "webhook_public_key": "YOUR_TELNYX_PUBLIC_KEY",  # For webhook signature verification
    },
}
```

**Supported Providers:**
* `jwt_drf_passwordless.external_2fa.TelnyxVerifyProvider` - Telnyx Verify API

**Creating a Custom Provider:**

Implement the `External2FAProvider` abstract class:

```.py
from jwt_drf_passwordless.external_2fa import External2FAProvider, External2FAResult, VerificationStatus

class MyProvider(External2FAProvider):
    def send_verification(self, phone_number, method=VerificationMethod.SMS):
        # Send code via your provider
        return External2FAResult(success=True, status=VerificationStatus.PENDING)

    def verify_code(self, phone_number, code):
        # Verify code with your provider
        return External2FAResult(success=True, status=VerificationStatus.ACCEPTED)

    def cancel_verification(self, phone_number):
        return External2FAResult(success=True, status=VerificationStatus.EXPIRED)
```

##### Webhook Configuration

External providers send delivery status updates via webhooks. Configure your provider to send webhooks to:

```
POST https://your-domain.com/passwordless/external/webhook/
```

**Telnyx Webhook Setup:**
1. In Telnyx Mission Control, configure your Verify Profile webhook URL
2. Set `webhook_public_key` in your config for Ed25519 signature verification
3. Whitelist Telnyx IPs: `192.76.120.192/27`

**Listening to Webhook Events:**

```.py
from django.dispatch import receiver
from jwt_drf_passwordless.external_2fa.signals import (
    verification_delivered,
    verification_delivery_failed,
)

@receiver(verification_delivered)
def on_delivered(sender, event, phone_number, **kwargs):
    # Log successful delivery
    pass

@receiver(verification_delivery_failed)
def on_failed(sender, event, phone_number, error, **kwargs):
    # Alert on delivery failure
    pass
```

## Credits
This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

* Aaronn's `django-rest-framework-passwordless` project https://github.com/aaronn/django-rest-framework-passwordless
* Cookiecutter: https://github.com/audreyr/cookiecutter
* `audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage

## License
* Free software: MIT license
* Do no harm
