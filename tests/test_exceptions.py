"""Tests for structured Opower exceptions."""

import datetime
import typing

import opower.utilities.base
from opower import (
    ApiException,
    AuthenticationAttemptSuperseded,
    AuthenticationError,
    AuthenticationTimeout,
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
    SafeHttpMetadata,
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
        provider_code="TOO_MANY_ATTEMPTS",
        retry_at=retry_at,
        attempt_id="53d9c42c-fd03-44e6-bcb5-dc9b5662d100",
        operation_id="cb63af11-d13d-4856-9869-77dd84d2233a",
        http=SafeHttpMetadata(
            status=429,
            content_type="application/json",
            schema=("code",),
            request_id="request-123",
            retry_at=retry_at,
        ),
    )

    assert details.as_dict() == {
        "category": "rate_limited",
        "stage": "login",
        "retry": "retry_after",
        "message_key": "rate_limited",
        "provider_code": "TOO_MANY_ATTEMPTS",
        "retry_at": "2026-07-22T18:45:00+00:00",
        "attempt_id": "53d9c42c-fd03-44e6-bcb5-dc9b5662d100",
        "operation_id": "cb63af11-d13d-4856-9869-77dd84d2233a",
        "http": {
            "status": 429,
            "content_type": "application/json",
            "schema": ("code",),
            "request_id": "request-123",
            "retry_at": "2026-07-22T18:45:00+00:00",
        },
    }


def test_legacy_exception_hierarchy_is_preserved() -> None:
    """New specific failures should remain compatible with legacy catches."""
    invalid_credentials = InvalidCredentials("credentials rejected")
    password_expired = PasswordExpired("password expired")
    temporary_failure = TemporaryAuthenticationError("provider unavailable")
    rate_limited = RateLimited("retry later")
    protocol_error = ProtocolError("unexpected response")
    mfa_rejected = MfaCodeRejected("MFA transaction rejected")
    superseded = AuthenticationAttemptSuperseded("attempt replaced")
    timeout = AuthenticationTimeout("attempt timed out")

    assert isinstance(invalid_credentials, InvalidAuth)
    assert isinstance(invalid_credentials, AuthenticationError)
    assert isinstance(invalid_credentials, OpowerError)
    assert isinstance(password_expired, InvalidAuth)
    assert isinstance(temporary_failure, CannotConnect)
    assert isinstance(rate_limited, CannotConnect)
    assert isinstance(protocol_error, OpowerError)
    assert isinstance(protocol_error, CannotConnect)
    assert isinstance(mfa_rejected, CannotConnect)
    assert isinstance(superseded, CannotConnect)
    assert isinstance(timeout, CannotConnect)


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
    assert error.handler is typing.cast("opower.utilities.base.MfaHandlerBase", handler)
    assert error.details is None


def test_mfa_code_rejected_is_not_legacy_invalid_auth() -> None:
    """A rejected MFA transaction is not automatically invalid credentials."""
    error = MfaCodeRejected("MFA transaction rejected")

    assert isinstance(error, AuthenticationError)
    assert isinstance(error, CannotConnect)
    assert not isinstance(error, InvalidAuth)


def test_api_exception_constructor_and_rendering_remain_compatible() -> None:
    """The existing ApiException contract should not change in this PR."""
    error = ApiException(
        "HTTP Error: 500",
        url="https://example.invalid/endpoint",
        status=500,
        response_text="temporary provider failure",
        response_summary=SafeHttpMetadata(status=500),
    )

    assert error.url == "https://example.invalid/endpoint"
    assert error.status == 500
    assert error.response_text == "temporary provider failure"
    assert error.response_summary == SafeHttpMetadata(status=500)
    assert (
        str(error)
        == "HTTP Error: 500\nURL: https://example.invalid/endpoint\nStatus: 500\nResponse: temporary provider failure"
    )
