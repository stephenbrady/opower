"""Safe HTTP response metadata and failure classification."""

import dataclasses
import datetime
import email.utils
import enum
import uuid
from collections.abc import Mapping
from typing import Any

import aiohttp

from .exceptions import FailureCategory, FailureDetails, FailureStage, RetryDisposition, SafeHttpMetadata


class RequestPurpose(enum.StrEnum):
    """Logical purpose of an Opower HTTP operation."""

    LOGIN = "login"
    CUSTOMERS = "customers"
    USER_ACCOUNTS = "user_accounts"
    SERVICE_AGREEMENTS = "service_agreements"
    FORECAST_GRAPHQL = "forecast_graphql"
    DATA_BROWSER = "data_browser"
    BILL_HISTORY = "bill_history"
    METERS = "meters"
    REALTIME_USAGE = "realtime_usage"
    GENERIC_API = "generic_api"


class AuthenticationExpectation(enum.StrEnum):
    """Whether an HTTP 401 is sufficient evidence to replace authentication."""

    REAUTHENTICATE_ON_401 = "reauthenticate_on_401"
    NO_AUTOMATIC_REAUTHENTICATION = "no_automatic_reauthentication"


@dataclasses.dataclass(frozen=True, slots=True)
class RequestContext:
    """Classification context for one logical HTTP operation."""

    purpose: RequestPurpose
    stage: FailureStage
    authentication: AuthenticationExpectation


@dataclasses.dataclass(frozen=True, slots=True)
class ResponseSummary:
    """Non-secret metadata describing an HTTP response."""

    status: int
    content_type: str | None
    schema: tuple[str, ...] | None
    request_id: str | None
    retry_at: datetime.datetime | None

    def as_diagnostics(self) -> dict[str, Any]:
        """Return safe values suitable for diagnostics and debug logs."""
        return {
            "status": self.status,
            "content_type": self.content_type,
            "schema": self.schema,
            "request_id": self.request_id,
            "retry_at": self.retry_at.isoformat() if self.retry_at else None,
        }

    def as_safe_metadata(self) -> SafeHttpMetadata:
        """Return the public safe metadata representation."""
        return SafeHttpMetadata(
            status=self.status,
            content_type=self.content_type,
            schema=self.schema,
            request_id=self.request_id,
            retry_at=self.retry_at,
        )


def new_correlation_id() -> str:
    """Return an opaque correlation ID without embedding user data."""
    return str(uuid.uuid4())


def summarize_response(
    response: aiohttp.ClientResponse,
    payload: object | None = None,
    *,
    now: datetime.datetime | None = None,
) -> ResponseSummary:
    """Extract safe response metadata without retaining response content."""
    response_date = _parse_http_date(response.headers.get("Date"))
    retry_at = _parse_retry_after(response.headers.get("Retry-After"), response_date, now)
    schema = tuple(sorted(str(key) for key in payload)) if isinstance(payload, Mapping) else None
    request_id = next(
        (
            response.headers[header]
            for header in ("X-Request-ID", "X-Correlation-ID", "X-Amzn-RequestId", "Traceparent")
            if response.headers.get(header)
        ),
        None,
    )
    return ResponseSummary(
        status=response.status,
        content_type=response.content_type or None,
        schema=schema,
        request_id=request_id,
        retry_at=retry_at,
    )


def classify_http_failure(
    summary: ResponseSummary,
    context: RequestContext,
    *,
    operation_id: str | None = None,
    attempt_id: str | None = None,
    provider_session_expired: bool = False,
) -> FailureDetails:
    """Classify HTTP status without assuming credentials caused the failure."""
    category = FailureCategory.API
    retry = RetryDisposition.RETRY_WITH_BACKOFF
    message_key = "http_error"
    if summary.status == 429:
        category = FailureCategory.RATE_LIMITED
        retry = RetryDisposition.RETRY_AFTER if summary.retry_at else RetryDisposition.RETRY_WITH_BACKOFF
        message_key = "rate_limited"
    elif provider_session_expired or (
        summary.status == 401 and context.authentication is AuthenticationExpectation.REAUTHENTICATE_ON_401
    ):
        category = FailureCategory.SESSION_EXPIRED
        retry = RetryDisposition.REAUTHENTICATE_ONCE
        message_key = "session_expired"
    elif summary.status in (401, 403):
        category = FailureCategory.AUTHORIZATION
        retry = RetryDisposition.DO_NOT_RETRY
        message_key = "request_not_authorized"
    elif summary.status >= 500:
        category = FailureCategory.PROVIDER_UNAVAILABLE
        message_key = "provider_unavailable"
    elif summary.status >= 400:
        category = FailureCategory.PROTOCOL
        retry = RetryDisposition.DO_NOT_RETRY
        message_key = "unexpected_http_response"
    return FailureDetails(
        category=category,
        stage=context.stage,
        retry=retry,
        message_key=message_key,
        retry_at=summary.retry_at,
        attempt_id=attempt_id,
        operation_id=operation_id,
        http=summary.as_safe_metadata(),
    )


def _parse_http_date(value: str | None) -> datetime.datetime | None:
    """Parse a provider HTTP date as UTC."""
    if not value:
        return None
    try:
        return email.utils.parsedate_to_datetime(value).astimezone(datetime.UTC)
    except (TypeError, ValueError):
        return None


def _parse_retry_after(
    value: str | None,
    response_date: datetime.datetime | None,
    now: datetime.datetime | None,
) -> datetime.datetime | None:
    """Parse either delta-seconds or an HTTP date from ``Retry-After``."""
    if not value:
        return None
    if value.isdigit():
        return (response_date or now or datetime.datetime.now(datetime.UTC)) + datetime.timedelta(seconds=int(value))
    return _parse_http_date(value)
