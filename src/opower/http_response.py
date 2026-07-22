"""Safe HTTP response metadata and failure classification."""

import dataclasses
import datetime
import email.utils
import uuid
from collections.abc import Mapping
from typing import Any

import aiohttp

from .exceptions import FailureCategory, FailureDetails, FailureStage, RetryDisposition


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
    stage: FailureStage,
    *,
    operation_id: str | None = None,
    attempt_id: str | None = None,
) -> FailureDetails:
    """Classify HTTP status without assuming credentials caused the failure."""
    category = FailureCategory.API
    retry = RetryDisposition.RETRY_WITH_BACKOFF
    message_key = "http_error"
    if summary.status == 429:
        category = FailureCategory.RATE_LIMITED
        retry = RetryDisposition.RETRY_AFTER if summary.retry_at else RetryDisposition.RETRY_WITH_BACKOFF
        message_key = "rate_limited"
    elif summary.status in (401, 403):
        category = FailureCategory.SESSION_EXPIRED
        retry = RetryDisposition.REAUTHENTICATE_ONCE
        message_key = "session_not_authorized"
    elif summary.status >= 500:
        category = FailureCategory.PROVIDER_UNAVAILABLE
        message_key = "provider_unavailable"
    elif summary.status >= 400:
        category = FailureCategory.PROTOCOL
        retry = RetryDisposition.DO_NOT_RETRY
        message_key = "unexpected_http_response"
    return FailureDetails(
        category=category,
        stage=stage,
        retry=retry,
        message_key=message_key,
        http_status=summary.status,
        retry_at=summary.retry_at,
        attempt_id=attempt_id,
        operation_id=operation_id,
        response_content_type=summary.content_type,
        response_schema=summary.schema,
        server_request_id=summary.request_id,
        diagnostics=summary.as_diagnostics(),
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
