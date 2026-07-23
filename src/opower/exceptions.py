"""Exceptions."""

from dataclasses import asdict, dataclass
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .utilities.base import MfaHandlerBase


class FailureCategory(StrEnum):
    """Broad machine-readable category for an Opower failure."""

    INVALID_CREDENTIALS = "invalid_credentials"
    PASSWORD_EXPIRED = "password_expired"  # noqa: S105
    MFA_REQUIRED = "mfa_required"
    MFA_CODE_REJECTED = "mfa_code_rejected"
    MFA_REPLAY_PREVENTED = "mfa_replay_prevented"
    RATE_LIMITED = "rate_limited"
    SESSION_EXPIRED = "session_expired"
    AUTHENTICATION_RESET = "authentication_reset"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    TRANSPORT = "transport"
    PROTOCOL = "protocol"
    TOKEN_EXCHANGE = "token_exchange"  # noqa: S105
    AUTHORIZATION = "authorization"
    API = "api"
    UNKNOWN = "unknown"


class FailureStage(StrEnum):
    """Stage where an Opower failure occurred."""

    LOGIN = "login"
    MFA_GENERATION = "mfa_generation"
    MFA_VERIFICATION = "mfa_verification"
    AUTH_REDIRECT = "auth_redirect"
    TOKEN_EXCHANGE = "token_exchange"  # noqa: S105
    CUSTOMERS = "customers"
    ACCOUNTS = "accounts"
    FORECAST = "forecast"
    COST_READS = "cost_reads"
    USAGE_READS = "usage_reads"
    REALTIME_READS = "realtime_reads"
    GRAPHQL = "graphql"
    UNKNOWN = "unknown"


class RetryDisposition(StrEnum):
    """Recommended retry behavior for an Opower failure."""

    DO_NOT_RETRY = "do_not_retry"
    RETRY_WITH_BACKOFF = "retry_with_backoff"
    RETRY_AFTER = "retry_after"
    RETRY_AFTER_TOTP_ROLLOVER = "retry_after_totp_rollover"
    REAUTHENTICATE_ONCE = "reauthenticate_once"
    USER_ACTION_REQUIRED = "user_action_required"


@dataclass(frozen=True, slots=True)
class SafeHttpMetadata:
    """Non-secret metadata describing an HTTP response."""

    status: int
    content_type: str | None = None
    schema: tuple[str, ...] | None = None
    request_id: str | None = None
    retry_at: datetime | None = None

    def as_dict(self) -> dict[str, Any]:
        """Return JSON-serializable safe response metadata."""
        return {
            "status": self.status,
            "content_type": self.content_type,
            "schema": self.schema,
            "request_id": self.request_id,
            "retry_at": self.retry_at.isoformat() if self.retry_at else None,
        }


@dataclass(frozen=True, slots=True)
class FailureDetails:
    """Safe, machine-readable details attached to an Opower failure."""

    category: FailureCategory
    stage: FailureStage
    retry: RetryDisposition
    message_key: str
    provider_code: str | None = None
    retry_at: datetime | None = None
    attempt_id: str | None = None
    operation_id: str | None = None
    http: SafeHttpMetadata | None = None

    def as_dict(self) -> dict[str, Any]:
        """Return JSON-serializable failure details."""
        result = asdict(self)
        result["category"] = self.category.value
        result["stage"] = self.stage.value
        result["retry"] = self.retry.value
        result["retry_at"] = self.retry_at.isoformat() if self.retry_at else None
        result["http"] = self.http.as_dict() if self.http else None
        return result


class OpowerError(Exception):
    """Base class for Opower failures."""

    def __init__(
        self,
        message: object = "",
        *,
        details: FailureDetails | None = None,
    ) -> None:
        """Initialize an Opower failure."""
        super().__init__(message)
        self.details = details


class AuthenticationError(OpowerError):
    """Base class for authentication-related failures."""


class CannotConnect(OpowerError):
    """Error to indicate we cannot connect or should retry later."""


class InvalidAuth(AuthenticationError):
    """Error to indicate user-provided authentication data is invalid."""


class InvalidCredentials(InvalidAuth):
    """The provider explicitly rejected the username or password."""


class PasswordExpired(InvalidAuth):
    """The provider reports that the password has expired."""


class TemporaryAuthenticationError(CannotConnect, AuthenticationError):
    """Authentication failed for a temporary or ambiguous reason."""


class MfaCodeRejected(TemporaryAuthenticationError):
    """The provider rejected an MFA transaction without proving bad credentials."""


class AuthenticationAttemptSuperseded(TemporaryAuthenticationError):
    """The shared authentication attempt was explicitly replaced."""


class AuthenticationTimeout(TemporaryAuthenticationError):
    """The shared authentication transaction exceeded its deadline."""


class RateLimited(CannotConnect):
    """The provider requires waiting before another attempt."""


class ProtocolError(CannotConnect):
    """The provider response did not match the expected protocol."""


class MfaChallenge(AuthenticationError):
    """Raised when MFA is required and user interaction is needed."""

    def __init__(
        self,
        message: str,
        handler: "MfaHandlerBase",
        *,
        details: FailureDetails | None = None,
    ) -> None:
        """Initialize the exception."""
        super().__init__(message, details=details)
        self.handler = handler


class ApiException(OpowerError):
    """Raised during problems talking to the API."""

    def __init__(
        self,
        message: str,
        url: str,
        status: int | None = None,
        response_text: str | None = None,
        *,
        details: FailureDetails | None = None,
        response_summary: SafeHttpMetadata | None = None,
    ) -> None:
        """Initialize the exception."""
        super().__init__(message, details=details)
        self.url = url
        self.status = status
        # Deprecated compatibility attribute. Internal code must not store raw
        # provider bodies here.
        self.response_text = response_text
        self.response_summary = response_summary

    def __str__(self) -> str:
        """Return a string representation of the exception."""
        parts = [super().__str__()]
        parts.append(f"URL: {self.url}")
        if self.status is not None:
            parts.append(f"Status: {self.status}")
        if self.response_text is not None:
            parts.append(f"Response: {self.response_text}")
        return "\n".join(parts)
