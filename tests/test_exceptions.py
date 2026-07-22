"""Tests for structured Opower exceptions."""

import datetime

from opower import (
    ApiException,
    AuthenticationError,
    CannotConnect,
    FailureCategory,
    FailureDetails,
    FailureStage,
    InvalidAuth,
    InvalidCredentials,
    MfaChallenge,
    MfaCodeRejected,
    OpowerError,
    PasswordExpired,
    ProtocolError,
    RateLimited,
    RetryDisposition,
    TemporaryAuthenticationError,
)


class _MfaHandler:
    """Minimal MFA handler used to verify compatibility."""



def test_failure_details_as_dict() -> None:
    """Failure details should serialize to safe primitive values."""
    retry_at = datetime.datetime(
        2026,
        7,
        22,
        18,
        45,
        tzinfo=datetime.UTC,
    )
    details = FailureDetails(
        category=FailureCategory.RATE_LIMITED,
        stage=FailureStage.LOGIN,
        retry=RetryDisposition.RETRY_AFTER,
        message_key="rate_limited",
        http_status=429,
        provider_code="TOO_MANY_ATTEMPTS",
        retry_at=retry_at,
        attempt_id="53d9c42c-fd03-44e6-bcb5-dc9b5662d100",
        operation_id="cb63af11-d13d-4856-9869-77dd84d2233a",
    )

    assert details.as_dict() == {
        "category": "rate_limited",
        "stage": "login",
        "retry": "retry_after",
        "message_key": "rate_limited",
        "http_status": 429,
        "provider_code": "TOO_MANY_ATTEMPTS",
        "provider_message": None,
        "retry_at": "2026-07-22T18:45:00+00:00",
        "attempt_id": "53d9c42c-fd03-44e6-bcb5-dc9b5662d100",
        "operation_id": "cb63af11-d13d-4856-9869-77dd84d2233a",
        "response_content_type": None,
        "response_schema": None,
        "server_request_id": None,
        "diagnostics": None,
    }


def test_legacy_exception_hierarchy_is_preserved() -> None:
    """New specific failures should remain compatible with legacy catches."""
    invalid_credentials = InvalidCredentials("credentials rejected")
    password_expired = PasswordExpired("password expired")
    temporary_failure = TemporaryAuthenticationError("provider unavailable")
    rate_limited = RateLimited("retry later")
    protocol_error = ProtocolError("unexpected response")

    assert isinstance(invalid_credentials, InvalidAuth)
    assert isinstance(invalid_credentials, AuthenticationError)
    assert isinstance(invalid_credentials, OpowerError)
    assert isinstance(password_expired, InvalidAuth)
    assert isinstance(temporary_failure, CannotConnect)
    assert isinstance(rate_limited, CannotConnect)
    assert isinstance(protocol_error, OpowerError)


def test_opower_error_exposes_optional_details() -> None:
    """Structured details should be available without changing the message."""
    details = FailureDetails(
        category=FailureCategory.PROTOCOL,
        stage=FailureStage.TOKEN_EXCHANGE,
        retry=RetryDisposition.RETRY_WITH_BACKOFF,
        message_key="token_response_invalid",
    )
    error = ProtocolError("Unexpected token response", details=details)

    assert str(error) == "Unexpected token response"
    assert error.details is details


def test_mfa_challenge_constructor_remains_compatible() -> None:
    """The existing positional MFA handler contract should remain intact."""
    handler = _MfaHandler()
    error = MfaChallenge("MFA required", handler)  # type: ignore[arg-type]

    assert str(error) == "MFA required"
    assert error.handler is handler
    assert error.details is None


def test_mfa_code_rejected_is_not_legacy_invalid_auth() -> None:
    """A rejected MFA transaction is not automatically invalid credentials."""
    error = MfaCodeRejected("MFA transaction rejected")

    assert isinstance(error, AuthenticationError)
    assert not isinstance(error, InvalidAuth)


def test_api_exception_constructor_and_rendering_remain_compatible() -> None:
    """The existing ApiException contract should not change in this PR."""
    error = ApiException(
        "HTTP Error: 500",
        url="https://example.invalid/endpoint",
        status=500,
        response_text="temporary provider failure",
    )

    assert error.url == "https://example.invalid/endpoint"
    assert error.status == 500
    assert error.response_text == "temporary provider failure"
    assert str(error) == (
        "HTTP Error: 500\n"
        "URL: https://example.invalid/endpoint\n"
        "Status: 500\n"
        "Response: temporary provider failure"
    )
