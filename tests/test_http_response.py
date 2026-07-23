"""Tests for safe HTTP response metadata and classification."""

import datetime
from unittest.mock import Mock

from opower.exceptions import FailureCategory, FailureStage, RetryDisposition
from opower.http_response import (
    AuthenticationExpectation,
    RequestContext,
    RequestPurpose,
    classify_http_failure,
    summarize_response,
)

_AUTHENTICATED_COST_REQUEST = RequestContext(
    purpose=RequestPurpose.DATA_BROWSER,
    stage=FailureStage.COST_READS,
    authentication=AuthenticationExpectation.REAUTHENTICATE_ON_401,
)


def test_response_summary_excludes_payload_values() -> None:
    """A response summary retains schema but never body values."""
    response = Mock()
    response.status = 429
    response.content_type = "application/json"
    response.headers = {
        "Date": "Wed, 22 Jul 2026 20:00:00 GMT",
        "Retry-After": "60",
        "X-Request-ID": "provider-request-123",
    }

    summary = summarize_response(response, {"error": "secret response text", "code": "RATE_LIMIT"})

    assert summary.status == 429
    assert summary.schema == ("code", "error")
    assert summary.request_id == "provider-request-123"
    assert summary.retry_at == datetime.datetime(2026, 7, 22, 20, 1, tzinfo=datetime.UTC)
    assert "secret response text" not in str(summary.as_diagnostics())


def test_rate_limit_is_retryable_at_provider_time() -> None:
    """A rate limit carries a retry deadline without invalidating authentication."""
    response = Mock()
    response.status = 429
    response.content_type = "application/json"
    response.headers = {"Retry-After": "Wed, 22 Jul 2026 20:01:00 GMT"}

    details = classify_http_failure(
        summarize_response(response),
        RequestContext(
            purpose=RequestPurpose.LOGIN,
            stage=FailureStage.LOGIN,
            authentication=AuthenticationExpectation.NO_AUTOMATIC_REAUTHENTICATION,
        ),
        operation_id="operation-123",
    )

    assert details.category is FailureCategory.RATE_LIMITED
    assert details.retry is RetryDisposition.RETRY_AFTER
    assert details.operation_id == "operation-123"


def test_401_on_authenticated_api_request_allows_one_reauthentication() -> None:
    """A bearer-protected API 401 is evidence that its session needs replacement."""
    response = Mock()
    response.status = 401
    response.content_type = "text/html"
    response.headers = {}

    details = classify_http_failure(summarize_response(response), _AUTHENTICATED_COST_REQUEST)

    assert details.category is FailureCategory.SESSION_EXPIRED
    assert details.retry is RetryDisposition.REAUTHENTICATE_ONCE


def test_generic_403_is_authorization_failure_without_reauthentication() -> None:
    """A generic 403 never starts a replacement login."""
    response = Mock()
    response.status = 403
    response.content_type = "application/json"
    response.headers = {}

    details = classify_http_failure(summarize_response(response), _AUTHENTICATED_COST_REQUEST)

    assert details.category is FailureCategory.AUTHORIZATION
    assert details.retry is RetryDisposition.DO_NOT_RETRY
