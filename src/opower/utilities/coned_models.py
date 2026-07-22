"""Validated, non-secret ConEd login response models."""

import dataclasses
from collections.abc import Mapping
from typing import Any

from ..exceptions import (
    FailureCategory,
    FailureDetails,
    FailureStage,
    InvalidAuth,
    InvalidCredentials,
    MfaCodeRejected,
    PasswordExpired,
    ProtocolError,
    RateLimited,
    RetryDisposition,
    TemporaryAuthenticationError,
)

_INVALID_CREDENTIAL_CODES = frozenset({"INVALID_CREDENTIALS", "INVALID_PASSWORD", "INVALID_USERNAME"})
_PASSWORD_EXPIRED_CODES = frozenset({"PASSWORD_EXPIRED", "PASSWORD_RESET_REQUIRED"})
_RATE_LIMITED_CODES = frozenset({"RATE_LIMITED", "TOO_MANY_ATTEMPTS", "TOO_MANY_REQUESTS"})


@dataclasses.dataclass(frozen=True, slots=True)
class ConEdLoginResponse:
    """Validated result returned by the ConEd ``Login`` endpoint."""

    accepted: bool
    auth_redirect_url: str | None
    new_device: bool
    no_mfa: bool
    provider_code: str | None


@dataclasses.dataclass(frozen=True, slots=True)
class ConEdFactorResponse:
    """Validated result returned by the ConEd ``VerifyFactor`` endpoint."""

    accepted: bool
    auth_redirect_url: str | None
    provider_code: str | None


def parse_login_response(payload: object) -> ConEdLoginResponse:
    """Validate a login payload without exposing provider response values."""
    data = _require_mapping(payload, "login")
    accepted = _require_bool(data, "login", "login")
    return ConEdLoginResponse(
        accepted=accepted,
        auth_redirect_url=_optional_string(data, "authRedirectUrl", "login"),
        new_device=_optional_bool(data, "newDevice", False, "login"),
        no_mfa=_optional_bool(data, "noMfa", False, "login"),
        provider_code=_safe_provider_code(data.get("code")),
    )


def parse_factor_response(payload: object) -> ConEdFactorResponse:
    """Validate a factor-verification payload without exposing response values."""
    data = _require_mapping(payload, "MFA verification")
    accepted = _require_bool(data, "code", "MFA verification")
    return ConEdFactorResponse(
        accepted=accepted,
        auth_redirect_url=_optional_string(data, "authRedirectUrl", "MFA verification"),
        provider_code=_safe_provider_code(data.get("status") or data.get("errorCode")),
    )


def raise_for_login_rejection(response: ConEdLoginResponse) -> None:
    """Raise only evidence-backed credential errors for a rejected login."""
    if response.accepted:
        return
    details = _failure_details(response.provider_code, FailureStage.LOGIN)
    if response.provider_code in _INVALID_CREDENTIAL_CODES:
        raise InvalidCredentials("ConEd rejected the username or password", details=details)
    if response.provider_code in _PASSWORD_EXPIRED_CODES:
        raise PasswordExpired("ConEd requires a password change", details=details)
    if response.provider_code in _RATE_LIMITED_CODES:
        raise RateLimited("ConEd temporarily limited login attempts", details=details)
    raise TemporaryAuthenticationError("ConEd rejected the login transaction without a credential error code", details=details)


def raise_for_factor_rejection(response: ConEdFactorResponse) -> None:
    """Treat a factor rejection as retryable unless ConEd proves a configuration error."""
    if response.accepted:
        return
    details = FailureDetails(
        category=FailureCategory.MFA_CODE_REJECTED,
        stage=FailureStage.MFA_VERIFICATION,
        retry=RetryDisposition.RETRY_AFTER_TOTP_ROLLOVER,
        message_key="coned_mfa_transaction_rejected",
        provider_code=response.provider_code,
    )
    raise MfaCodeRejected("ConEd rejected the MFA transaction; retry with a fresh TOTP window", details=details)


def _failure_details(provider_code: str | None, stage: FailureStage) -> FailureDetails:
    """Return details based solely on safe, recognized provider codes."""
    category = FailureCategory.PROVIDER_UNAVAILABLE
    retry = RetryDisposition.RETRY_WITH_BACKOFF
    message_key = "coned_login_rejected"
    if provider_code in _INVALID_CREDENTIAL_CODES:
        category = FailureCategory.INVALID_CREDENTIALS
        retry = RetryDisposition.USER_ACTION_REQUIRED
        message_key = "coned_invalid_credentials"
    elif provider_code in _PASSWORD_EXPIRED_CODES:
        category = FailureCategory.PASSWORD_EXPIRED
        retry = RetryDisposition.USER_ACTION_REQUIRED
        message_key = "coned_password_expired"
    elif provider_code in _RATE_LIMITED_CODES:
        category = FailureCategory.RATE_LIMITED
        retry = RetryDisposition.RETRY_WITH_BACKOFF
        message_key = "coned_rate_limited"
    return FailureDetails(
        category=category,
        stage=stage,
        retry=retry,
        message_key=message_key,
        provider_code=provider_code,
    )


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
        raise ProtocolError(f"ConEd {stage} response field {key!r} was not a non-empty string", details=_protocol_details(stage))
    return value


def _safe_provider_code(value: object) -> str | None:
    """Retain only known, non-secret provider codes."""
    if not isinstance(value, str):
        return None
    normalized = value.strip().upper()
    known_codes = _INVALID_CREDENTIAL_CODES | _PASSWORD_EXPIRED_CODES | _RATE_LIMITED_CODES
    return normalized if normalized in known_codes else None


def _protocol_details(stage: str) -> FailureDetails:
    """Build a safe protocol failure without retaining payload content."""
    failure_stage = FailureStage.LOGIN if stage == "login" else FailureStage.MFA_VERIFICATION
    return FailureDetails(
        category=FailureCategory.PROTOCOL,
        stage=failure_stage,
        retry=RetryDisposition.DO_NOT_RETRY,
        message_key="coned_response_schema_invalid",
    )
