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
class FailureDetails:
    """Safe, machine-readable details attached to an Opower failure."""

    category: FailureCategory
    stage: FailureStage
    retry: RetryDisposition
    message_key: str
    http_status: int | None = None
    provider_code: str | None = None
    provider_message: str | None = None
    retry_at: datetime | None = None
    attempt_id: str | None = None
    operation_id: str | None = None
    response_content_type: str | None = None
    response_schema: tuple[str, ...] | None = None
    server_request_id: str | None = None
    diagnostics: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        """Return JSON-serializable failure details."""
        result = asdict(self)
        result["category"] = self.category.value
        result["stage"] = self.stage.value
        result["retry"] = self.retry.value
        result["retry_at"] = self.retry_at.isoformat() if self.retry_at else None
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


class MfaCodeRejected(AuthenticationError):
    """The provider rejected an MFA transaction without proving bad credentials."""


class TemporaryAuthenticationError(CannotConnect, AuthenticationError):
    """Authentication failed for a temporary or ambiguous reason."""


class RateLimited(CannotConnect):
    """The provider requires waiting before another attempt."""


class ProtocolError(OpowerError):
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
    ) -> None:
        """Initialize the exception."""
        super().__init__(message, details=details)
        self.url = url
        self.status = status
        self.response_text = response_text

    def __str__(self) -> str:
        """Return a string representation of the exception."""
        parts = [super().__str__()]
        parts.append(f"URL: {self.url}")
        if self.status is not None:
            parts.append(f"Status: {self.status}")
        if self.response_text is not None:
            parts.append(f"Response: {self.response_text}")
        return "\n".join(parts)
