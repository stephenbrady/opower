"""Integration-style tests for authenticated request reconstruction and replay."""

import asyncio
import json
from collections.abc import Mapping
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest

from opower import Account, AggregateType, MeterType, Opower, ReadResolution
from opower.exceptions import (
    ApiException,
    FailureCategory,
    FailureDetails,
    FailureStage,
    RetryDisposition,
)
from opower.http_response import (
    AuthenticationExpectation,
    RequestContext,
    RequestPurpose,
)


class _Response:
    """Minimal asynchronous response context."""

    def __init__(
        self,
        status: int,
        payload: object,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.status = status
        self.ok = status < 400
        self._payload = payload
        self.headers = dict(headers or {})
        self.content_type = "application/json"

    async def __aenter__(self) -> "_Response":
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    async def json(self) -> object:
        return self._payload


class _Session:
    """Scripted session that records every reconstructed request."""

    def __init__(
        self,
        *,
        get_responses: list[_Response] | None = None,
        post_responses: list[_Response] | None = None,
    ) -> None:
        self._get_responses = list(get_responses or [])
        self._post_responses = list(post_responses or [])
        self.get_requests: list[dict[str, Any]] = []
        self.post_requests: list[dict[str, Any]] = []

    def get(
        self,
        url: str,
        *,
        params: dict[str, str],
        headers: dict[str, str],
    ) -> _Response:
        """Return the next scripted GET response."""
        self.get_requests.append({"url": url, "params": params, "headers": headers})
        return self._get_responses.pop(0)

    def post(
        self,
        url: str,
        *,
        headers: dict[str, str],
        json: dict[str, str],
    ) -> _Response:
        """Return the next scripted POST response."""
        self.post_requests.append({"url": url, "json": json, "headers": headers})
        return self._post_responses.pop(0)


_DATA_BROWSER_CONTEXT = RequestContext(
    purpose=RequestPurpose.DATA_BROWSER,
    stage=FailureStage.COST_READS,
    authentication=AuthenticationExpectation.REAUTHENTICATE_ON_401,
)


def _new_opower(session: _Session, utility: str) -> Opower:
    """Return an Opower instance with deterministic replacement tokens."""
    opower = Opower(session, utility, "username", "password")  # type: ignore[arg-type]
    opower.utility.async_login = AsyncMock(side_effect=["old-token", "new-token"])  # type: ignore[method-assign]
    return opower


@pytest.mark.asyncio
async def test_customer_scope_and_token_are_rebuilt_after_401() -> None:
    """Replay preserves customer scope while replacing the bearer token."""
    session = _Session(
        get_responses=[
            _Response(401, {}),
            _Response(200, {"ok": True}),
        ]
    )
    opower = _new_opower(session, "Pacific Gas and Electric Company (PG&E)")
    factory_calls = 0

    def url_factory() -> str:
        nonlocal factory_calls
        factory_calls += 1
        return "https://example.invalid/customer"

    result = await opower._async_get_request(
        url_factory,
        lambda: {"fresh": "true"},
        "customer-uuid",
        _DATA_BROWSER_CONTEXT,
    )

    assert result == {"ok": True}
    assert factory_calls == 2
    assert opower.utility.async_login.await_count == 2  # type: ignore[attr-defined]
    first_headers = session.get_requests[0]["headers"]
    second_headers = session.get_requests[1]["headers"]
    assert first_headers["authorization"] == "Bearer old-token"
    assert second_headers["authorization"] == "Bearer new-token"
    assert first_headers["Opower-Selected-Entities"] == second_headers["Opower-Selected-Entities"]
    assert "customer-uuid" in first_headers["Opower-Selected-Entities"]


@pytest.mark.asyncio
async def test_dss_selected_entities_are_rebuilt_after_401() -> None:
    """DSS replay retains account, provider, and customer claims."""
    session = _Session(
        get_responses=[
            _Response(401, {}),
            _Response(200, {"ok": True}),
        ]
    )
    opower = _new_opower(session, "City of Austin Utilities")
    opower.user_accounts = [{"accountId": "account-123", "premises": ["premise"]}]

    await opower._async_get_request(
        lambda: "https://example.invalid/dss",
        lambda: {},
        "customer-uuid",
        _DATA_BROWSER_CONTEXT,
    )

    for request in session.get_requests:
        selected_entities = json.loads(request["headers"]["Opower-Selected-Entities"])
        assert "urn:session:account:account-123" in selected_entities
        assert "urn:session:account:provider:dsst" in selected_entities
        assert "urn:opower:customer:uuid:customer-uuid" in selected_entities
    assert session.get_requests[1]["headers"]["authorization"] == "Bearer new-token"


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [403, 500])
async def test_non_session_failures_do_not_reauthenticate(status: int) -> None:
    """Authorization and downstream provider failures do not start fresh login."""
    session = _Session(get_responses=[_Response(status, {})])
    opower = _new_opower(session, "Pacific Gas and Electric Company (PG&E)")

    with pytest.raises(ApiException):
        await opower._async_get_request(
            lambda: "https://example.invalid/failure",
            lambda: {},
            None,
            _DATA_BROWSER_CONTEXT,
        )

    assert opower.utility.async_login.await_count == 1  # type: ignore[attr-defined]
    assert len(session.get_requests) == 1


@pytest.mark.asyncio
async def test_graphql_post_rebuilds_request_after_401() -> None:
    """GraphQL POST uses the same one-time recovery as authenticated GET."""
    session = _Session(
        post_responses=[
            _Response(401, {}),
            _Response(200, {"data": {}}),
        ]
    )
    opower = _new_opower(session, "Pacific Gas and Electric Company (PG&E)")

    result = await opower._async_post_graphql("query { test }", "customer-uuid")

    assert result == {"data": {}}
    assert opower.utility.async_login.await_count == 2  # type: ignore[attr-defined]
    assert session.post_requests[0]["headers"]["authorization"] == "Bearer old-token"
    assert session.post_requests[1]["headers"]["authorization"] == "Bearer new-token"
    assert "customer-uuid" in session.post_requests[1]["headers"]["Opower-Selected-Entities"]


@pytest.mark.asyncio
async def test_second_401_stops_without_looping() -> None:
    """A replacement session receives no third request or login attempt."""
    session = _Session(
        get_responses=[
            _Response(401, {}),
            _Response(401, {}),
        ]
    )
    opower = _new_opower(session, "Pacific Gas and Electric Company (PG&E)")

    with pytest.raises(ApiException):
        await opower._async_get_request(
            lambda: "https://example.invalid/repeated-401",
            lambda: {},
            None,
            _DATA_BROWSER_CONTEXT,
        )

    assert opower.utility.async_login.await_count == 2  # type: ignore[attr-defined]
    assert len(session.get_requests) == 2


@pytest.mark.asyncio
async def test_expected_dss_403_falls_back_without_reauthentication() -> None:
    """DSS DataBrowser denial immediately uses bill history with one login."""
    session = _Session(
        get_responses=[
            _Response(403, {}),
            _Response(
                200,
                {
                    "bills": [
                        {"billDate": "2026-02-28", "cost": 20.0},
                        {"billDate": "2026-01-31", "cost": 10.0},
                    ]
                },
            ),
        ]
    )
    opower = _new_opower(session, "City of Austin Utilities")
    opower.user_accounts = [{"accountId": "account-123", "premises": ["premise"]}]
    account = Account(
        customer=Mock(uuid="customer-uuid"),
        uuid="service-agreement",
        utility_account_id="account-123",
        id="service-agreement",
        meter_type=MeterType.ELEC,
        read_resolution=ReadResolution.DAY,
    )

    reads = await opower._async_fetch(
        account,
        AggregateType.BILL,
        usage_only=False,
    )

    assert len(reads) == 1
    assert opower.utility.async_login.await_count == 1  # type: ignore[attr-defined]
    assert len(session.get_requests) == 2


@pytest.mark.asyncio
async def test_concurrent_401_responses_share_one_replacement_login() -> None:
    """Generation-aware invalidation converges concurrent callers on one login."""
    session = _Session()
    opower = _new_opower(session, "Pacific Gas and Electric Company (PG&E)")
    await opower.async_login()
    first_attempts = 0
    both_failed = asyncio.Event()

    def request_factory() -> Any:
        request_attempt = 0

        async def request() -> dict[str, bool]:
            nonlocal first_attempts, request_attempt
            request_attempt += 1
            if request_attempt == 1:
                first_attempts += 1
                if first_attempts == 2:
                    both_failed.set()
                else:
                    await both_failed.wait()
                raise ApiException(
                    "HTTP Error: 401",
                    url="https://example.invalid/concurrent",
                    status=401,
                    details=FailureDetails(
                        category=FailureCategory.SESSION_EXPIRED,
                        stage=FailureStage.COST_READS,
                        retry=RetryDisposition.REAUTHENTICATE_ONCE,
                        message_key="session_expired",
                    ),
                )
            return {"ok": True}

        return request

    first_request = request_factory()
    second_request = request_factory()
    first, second = await asyncio.gather(
        opower._async_authenticated_request(
            first_request,
            context=_DATA_BROWSER_CONTEXT,
        ),
        opower._async_authenticated_request(
            second_request,
            context=_DATA_BROWSER_CONTEXT,
        ),
    )

    assert first == {"ok": True}
    assert second == {"ok": True}
    assert opower.utility.async_login.await_count == 2  # type: ignore[attr-defined]
