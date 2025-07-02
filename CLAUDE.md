# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview
This is `jwt-drf-passwordless`, a Django Rest Framework addon that provides passwordless authentication using JWT tokens. Users can authenticate via email or SMS by receiving and redeeming short-lived tokens.

## Development Commands

### Testing
- `./runtests.py` - Run all tests with pytest
- `./runtests.py --fast` - Run tests quickly without linting
- `./runtests.py TestClassName` - Run specific test class
- `./runtests.py test_function_name` - Run specific test function
- `./runtests.py --lintonly` - Run only linting checks
- `poetry run pytest` - Alternative test runner
- `poetry run tox` - Run tests across multiple Python versions

### Code Quality
- `make lint` or `make lint/black` - Check code formatting with black
- `black --check jwt_drf_passwordless tests` - Direct black check
- `flake8 jwt_drf_passwordless tests` - Lint with flake8

### Package Management
- `poetry install` - Install dependencies
- `poetry build` - Build package for distribution
- `make clean` - Clean build artifacts

### Documentation
- `make docs` - Generate Sphinx documentation
- `make servedocs` - Watch and rebuild docs on changes

## Architecture Overview

### Core Components
1. **Views** (`views.py`): API endpoints for token request and exchange
   - `PasswordlessEmailTokenRequestView` - Request token via email
   - `PasswordlessMobileTokenRequestView` - Request token via SMS
   - `EmailExchangePasswordlessTokenForAuthTokenView` - Exchange email token for JWT
   - `MobileExchangePasswordlessTokenForAuthTokenView` - Exchange mobile token for JWT

2. **Models** (`models.py`): Token storage and management
   - `PasswordlessChallengeToken` - Stores both long and short tokens with usage tracking

3. **Services** (`services.py`): Business logic for token operations
   - `PasswordlessTokenService` - Creates, validates, and manages tokens

4. **Serializers** (`serializers.py`): Request/response validation and JWT generation
   - Request serializers handle token requests
   - Exchange serializers validate tokens and return JWTs

### Security Model
- **Dual Token System**: Long tokens for magic links, short tokens for SMS/manual entry
- **Throttling**: Built-in rate limiting for token requests
- **Token Lifecycle**: Automatic expiration and usage limits
- **Admin Protection**: Optional blocking of admin user passwordless auth

### Key Settings
Configuration is handled through Django settings under `jwt_drf_passwordless` key. Important settings include:
- `ALLOWED_PASSWORDLESS_METHODS` - Enable email/mobile auth
- `TOKEN_LIFETIME` - Token expiration time
- `MAX_TOKEN_USES` - How many times a token can be redeemed
- `TOKEN_REQUEST_THROTTLE_SECONDS` - Rate limiting interval

## File Structure
- `/jwt_drf_passwordless/` - Main package
- `/tests/` - Test suite with pytest
- `/docs/` - Sphinx documentation
- `pyproject.toml` - Poetry configuration and dependencies
- `Makefile` - Development commands
- `tox.ini` - Multi-version testing configuration

## Dependencies
- Django 5.x with DRF for web framework
- `djangorestframework-simplejwt` for JWT token generation
- `django-sms` for SMS functionality
- `django-phonenumber-field` for phone number validation
- `django-templated-mail-2` for email templates

## Testing Strategy
Uses pytest with Django integration. Tests cover:
- Token request flows for email/mobile
- Token exchange and validation
- Security scenarios and edge cases
- Configuration variations