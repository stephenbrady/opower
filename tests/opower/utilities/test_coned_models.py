"""Tests for ConEd response validation and failure classification."""

import pytest

from opower.exceptions import (
    FailureCategory,
    InvalidCredentials,
    MfaCodeRejected,
    ProtocolError,
    TemporaryAuthenticationError,
)
from opower.utilities.coned_models import (
    parse_factor_response,
    parse_login_response,
    raise_for_factor_rejection,
    raise_for_login_rejection,
)


def test_explicit_invalid_credential_code_is_invalid_auth() -> None:
    """A recognized credential code remains a compatibility-safe invalid-auth error."""
    response = parse_login_response({"login": False, "code": "INVALID_PASSWORD"})

    with pytest.raises(InvalidCredentials) as error:
        raise_for_login_rejection(response)

    assert error.value.details is not None
    assert error.value.details.category is FailureCategory.INVALID_CREDENTIALS


def test_unexplained_login_rejection_is_temporary() -> None:
    """A bare false login flag does not prove the saved password is wrong."""
    response = parse_login_response({"login": False})

    with pytest.raises(TemporaryAuthenticationError) as error:
        raise_for_login_rejection(response)

    assert error.value.details is not None
    assert error.value.details.category is FailureCategory.PROVIDER_UNAVAILABLE


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
    ],
)
def test_malformed_coned_responses_are_protocol_errors(
    parser: object,
    payload: object,
) -> None:
    """Unexpected response shapes are explicit protocol errors, never KeyError."""
    with pytest.raises(ProtocolError):
        parser(payload)  # type: ignore[operator]
