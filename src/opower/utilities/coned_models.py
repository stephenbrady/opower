"""Validated, non-secret ConEd login response models."""

import dataclasses
import datetime
from collections.abc import Mapping
from typing import Any

from ..exceptions import (
    FailureCategory,
    FailureDetails,
    FailureStage,
    MfaCodeRejected,
    PasswordExpired,
    ProtocolError,
    RetryDisposition,
    TemporaryAuthenticationError,
)


@dataclasses.dataclass(frozen=True, slots=True)
class ConEdLoginResponse:
    """Validated result returned by the ConEd ``Login`` endpoint."""

    accepted: bool
    auth_redirect_url: str | None
    expired_password: bool
    waiting_time: datetime.timedelta | None
    new_device: bool
    no_mfa: bool
    enable_resend_mfa_code: bool
    is_numeric: bool


@dataclasses.dataclass(frozen=True, slots=True)
class ConEdFactorResponse:
    """Validated result returned by the ConEd ``VerifyFactor`` endpoint."""

    accepted: bool
    auth_redirect_url: str | None
    is_password_expired: bool


def parse_login_response(payload: object) -> ConEdLoginResponse:
    """Validate a login payload without exposing provider response values."""
    data = _require_mapping(payload, "login")
    accepted = _require_bool(data, "login", "login")
    return ConEdLoginResponse(
        accepted=accepted,
        auth_redirect_url=_optional_string(data, "authRedirectUrl", "login"),
        expired_password=_optional_bool(data, "expiredPassword", False, "login"),
        waiting_time=_optional_milliseconds(data, "waitingTime", "login"),
        new_device=_optional_bool(data, "newDevice", False, "login"),
        no_mfa=_optional_bool(data, "noMfa", False, "login"),
        enable_resend_mfa_code=_optional_bool(data, "enableResendMfaCode", False, "login"),
        is_numeric=_optional_bool(data, "isNumeric", False, "login"),
    )


def parse_factor_response(payload: object) -> ConEdFactorResponse:
    """Validate a factor-verification payload without exposing response values."""
    data = _require_mapping(payload, "MFA verification")
    accepted = _require_bool(data, "code", "MFA verification")
    return ConEdFactorResponse(
        accepted=accepted,
        auth_redirect_url=_optional_string(data, "authRedirectUrl", "MFA verification"),
        is_password_expired=_optional_bool(data, "isPasswordExpired", False, "MFA verification"),
    )


def raise_for_login_rejection(response: ConEdLoginResponse) -> None:
    """Raise only evidence-backed credential errors for a rejected login."""
    if response.expired_password:
        raise PasswordExpired(
            "ConEd requires a password change",
            details=FailureDetails(
                category=FailureCategory.PASSWORD_EXPIRED,
                stage=FailureStage.LOGIN,
                retry=RetryDisposition.USER_ACTION_REQUIRED,
                message_key="coned_password_expired",
            ),
        )
    if not response.accepted:
        raise TemporaryAuthenticationError(
            "ConEd rejected the login transaction without evidence of invalid credentials",
            details=FailureDetails(
                category=FailureCategory.PROVIDER_UNAVAILABLE,
                stage=FailureStage.LOGIN,
                retry=RetryDisposition.RETRY_WITH_BACKOFF,
                message_key="coned_login_rejected",
            ),
        )


def raise_for_factor_rejection(
    response: ConEdFactorResponse,
    *,
    retry_at: datetime.datetime | None = None,
) -> None:
    """Treat a factor rejection as retryable unless ConEd proves a configuration error."""
    if response.is_password_expired:
        raise PasswordExpired(
            "ConEd requires a password change",
            details=FailureDetails(
                category=FailureCategory.PASSWORD_EXPIRED,
                stage=FailureStage.MFA_VERIFICATION,
                retry=RetryDisposition.USER_ACTION_REQUIRED,
                message_key="coned_password_expired",
            ),
        )
    if response.accepted:
        return
    details = FailureDetails(
        category=FailureCategory.MFA_CODE_REJECTED,
        stage=FailureStage.MFA_VERIFICATION,
        retry=RetryDisposition.RETRY_AFTER_TOTP_ROLLOVER,
        message_key="coned_mfa_transaction_rejected",
        retry_at=retry_at,
    )
    raise MfaCodeRejected("ConEd rejected the MFA transaction; retry with a fresh TOTP window", details=details)


def _require_mapping(payload: object, stage: str) -> Mapping[str, Any]:
    """Require a JSON object while excluding its values from the error."""
    if not isinstance(payload, Mapping):
        raise ProtocolError(f"ConEd {stage} response was not a JSON object", details=_protocol_details(stage))
    return payload


def _require_bool(data: Mapping[str, Any], key: str, stage: str) -> bool:
    """Require a boolean field without accidentally accepting truthy values."""
    value = data.get(key)
    if not isinstance(value, bool):
        raise ProtocolError(f"ConEd {stage} response field {key!r} was not a boolean", details=_protocol_details(stage))
    return value


def _optional_bool(data: Mapping[str, Any], key: str, default: bool, stage: str) -> bool:
    """Read an optional boolean field with strict type validation."""
    if key not in data:
        return default
    return _require_bool(data, key, stage)


def _optional_string(data: Mapping[str, Any], key: str, stage: str) -> str | None:
    """Read an optional string field with strict type validation."""
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ProtocolError(
            f"ConEd {stage} response field {key!r} was not a non-empty string",
            details=_protocol_details(stage),
        )
    return value


def _optional_milliseconds(
    data: Mapping[str, Any],
    key: str,
    stage: str,
) -> datetime.timedelta | None:
    """Read an optional non-negative millisecond duration."""
    value = data.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ProtocolError(
            f"ConEd {stage} response field {key!r} was not non-negative milliseconds",
            details=_protocol_details(stage),
        )
    return datetime.timedelta(milliseconds=value)


def _protocol_details(stage: str) -> FailureDetails:
    """Build a safe protocol failure without retaining payload content."""
    failure_stage = FailureStage.LOGIN if stage == "login" else FailureStage.MFA_VERIFICATION
    return FailureDetails(
        category=FailureCategory.PROTOCOL,
        stage=failure_stage,
        retry=RetryDisposition.DO_NOT_RETRY,
        message_key="coned_response_schema_invalid",
    )
