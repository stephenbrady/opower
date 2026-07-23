"""Tests for ConEd response validation and failure classification."""

import datetime
from unittest.mock import Mock

import pytest

from opower.exceptions import (
    FailureCategory,
    FailureStage,
    MfaCodeRejected,
    PasswordExpired,
    ProtocolError,
    RateLimited,
    TemporaryAuthenticationError,
)
from opower.utilities.coned import _raise_for_http_failure
from opower.utilities.coned_models import (
    parse_factor_response,
    parse_login_response,
    raise_for_factor_rejection,
    raise_for_login_rejection,
)


def test_unexplained_login_rejection_is_temporary() -> None:
    """A bare false login flag does not prove the saved password is wrong."""
    response = parse_login_response({"login": False})

    with pytest.raises(TemporaryAuthenticationError) as error:
        raise_for_login_rejection(response)

    assert error.value.details is not None
    assert error.value.details.category is FailureCategory.PROVIDER_UNAVAILABLE


def test_observed_login_fields_are_strictly_parsed() -> None:
    """Observed ConEd fields retain safe booleans and timing metadata."""
    response = parse_login_response(
        {
            "login": True,
            "expiredPassword": False,
            "waitingTime": 180000,
            "newDevice": True,
            "noMfa": False,
            "enableResendMfaCode": False,
            "isNumeric": True,
        }
    )

    assert response.waiting_time == datetime.timedelta(minutes=3)
    assert response.new_device
    assert response.is_numeric
    assert not response.enable_resend_mfa_code


def test_observed_expired_password_is_user_action_required() -> None:
    """The observed password-expiration field is sufficient provider evidence."""
    response = parse_login_response({"login": False, "expiredPassword": True})

    with pytest.raises(PasswordExpired) as error:
        raise_for_login_rejection(response)

    assert error.value.details is not None
    assert error.value.details.category is FailureCategory.PASSWORD_EXPIRED


def test_coned_http_rate_limit_retains_retry_after() -> None:
    """Authentication HTTP failures preserve a provider retry deadline."""
    response = Mock()
    response.ok = False
    response.status = 429
    response.content_type = "application/json"
    response.headers = {"Retry-After": "Thu, 23 Jul 2026 12:01:00 GMT"}

    with pytest.raises(RateLimited) as error:
        _raise_for_http_failure(response, FailureStage.LOGIN)

    assert error.value.details is not None
    assert error.value.details.retry_at == datetime.datetime(
        2026,
        7,
        23,
        12,
        1,
        tzinfo=datetime.UTC,
    )


def test_mfa_rejection_is_not_relabelled_as_invalid_credentials() -> None:
    """A rejected MFA transaction must wait for a fresh factor window."""
    response = parse_factor_response({"code": False})

    with pytest.raises(MfaCodeRejected) as error:
        raise_for_factor_rejection(response)

    assert error.value.details is not None
    assert error.value.details.category is FailureCategory.MFA_CODE_REJECTED


@pytest.mark.parametrize(
    ("parser", "payload"),
    [
        (parse_login_response, {"login": "true"}),
        (parse_factor_response, {"code": "false"}),
        (parse_login_response, []),
        (parse_login_response, {"login": True, "waitingTime": -1}),
        (parse_login_response, {"login": True, "expiredPassword": "false"}),
    ],
)
def test_malformed_coned_responses_are_protocol_errors(
    parser: object,
    payload: object,
) -> None:
    """Unexpected response shapes are explicit protocol errors, never KeyError."""
    with pytest.raises(ProtocolError):
        parser(payload)  # type: ignore[operator]
