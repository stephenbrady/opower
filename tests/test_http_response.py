"""Tests for safe HTTP response metadata and classification."""

import datetime
from unittest.mock import Mock

from opower.exceptions import FailureCategory, FailureStage, RetryDisposition
from opower.http_response import classify_http_failure, summarize_response


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

    details = classify_http_failure(summarize_response(response), FailureStage.LOGIN, operation_id="operation-123")

    assert details.category is FailureCategory.RATE_LIMITED
    assert details.retry is RetryDisposition.RETRY_AFTER
    assert details.operation_id == "operation-123"


def test_unauthorized_response_does_not_prove_bad_credentials() -> None:
    """A generic 401/403 requires one reauthentication, not a credential reset."""
    response = Mock()
    response.status = 403
    response.content_type = "text/html"
    response.headers = {}

    details = classify_http_failure(summarize_response(response), FailureStage.COST_READS)

    assert details.category is FailureCategory.SESSION_EXPIRED
    assert details.retry is RetryDisposition.REAUTHENTICATE_ONCE
