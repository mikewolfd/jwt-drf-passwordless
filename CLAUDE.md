# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`jwt-drf-passwordless` is a Django app providing stateless passwordless authentication via email or SMS. It generates short numeric tokens (for SMS) and long alphanumeric tokens (for magic links), exchangeable for JWT access/refresh tokens. Built on `djangorestframework-simplejwt`, `django-sms`, and `django-phonenumber-field`.

**Status**: Alpha - Work in Progress

## Common Commands

```bash
# Install dependencies
make install          # or: poetry install

# Run tests
make test             # Quick test with default Python
make test-all         # Tox multi-version testing (3.10, 3.11, 3.12)
./runtests.py         # Direct pytest execution

# Run a single test
pytest tests/test_token_exchange.py::test_exchange_short_token_with_email -v

# Linting
make lint             # Black format check
flake8 jwt_drf_passwordless tests --ignore=E501

# Build package
poetry build          # Creates dist/
make dist             # Clean build
```

## Architecture

### Authentication Flow (2-Step Process)

1. **Token Request**: User submits email/phone → System generates short (6-digit) + long (64-char) tokens → Stores in `PasswordlessChallengeToken` → Sends via email/SMS

2. **Token Exchange**: User submits token + identifier → `PasswordlessTokenService.check_token()` validates → Returns JWT access/refresh tokens

### Key Components

| Component | Purpose |
|-----------|---------|
| `services.py` | `PasswordlessTokenService` - Token creation, validation, throttling |
| `views.py` | Abstract base views + 4 concrete views for email/mobile request/exchange |
| `serializers.py` | Mixin-based serializers with dynamic field injection |
| `conf.py` | Lazy-loading settings with dynamic class import via `ObjDict` |
| `models.py` | `PasswordlessChallengeToken` with custom manager for cleanup |

### API Endpoints

```
POST /passwordless/request/email/   → {"email": "..."}
POST /passwordless/request/mobile/  → {"phone_number": "..."}
POST /passwordless/exchange/email/  → {"token": "...", "email": "..."}
POST /passwordless/exchange/mobile/ → {"token": "...", "phone_number": "..."}
```

### Configuration System

Settings in `conf.py` use lazy loading with `LazySettings` wrapper. Configure via Django settings:

```python
JWT_DRF_PASSWORDLESS = {
    "SHORT_TOKEN_LENGTH": 6,
    "LONG_TOKEN_LENGTH": 64,
    "TOKEN_LIFETIME": 600,  # seconds
    "MAX_TOKEN_USES": 1,
    "ALLOWED_PASSWORDLESS_METHODS": ["EMAIL", "MOBILE"],
    # ... see conf.py for full list
}
```

### Extensibility Points

- **Rate limiting**: Override `DECORATORS.token_request_rate_limit_decorator` (default is no-op)
- **User activation**: Listen to `user_activated` signal in `signals.py`
- **Serializers**: Override via `SERIALIZERS` config for custom validation
- **Permissions**: Override via `PERMISSIONS` config for custom auth requirements

## Testing

Tests use pytest-django with:
- In-memory SQLite database
- Console email backend
- Local memory SMS backend
- Two test user models: `StandardUser` (AbstractUser) and `CustomUser` (custom fields)

Test helpers in `tests/common.py`: `create_user()`, `create_token()`
