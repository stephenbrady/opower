"""Deterministic integration tests for the ConEd authentication transaction."""

from typing import Any
from unittest.mock import Mock

import pytest

from opower import FailureStage, Opower


class _Response:
    """Minimal ConEd response context."""

    def __init__(self, payload: object) -> None:
        self.status = 200
        self.ok = True
        self.content_type = "application/json"
        self.headers: dict[str, str] = {}
        self._payload = payload

    async def __aenter__(self) -> "_Response":
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    async def json(self) -> object:
        return self._payload


class _ConEdSession:
    """Script the observed successful ConEd request sequence."""

    def __init__(self) -> None:
        self.cookie_jar = Mock()
        self.requests: list[dict[str, Any]] = []

    def post(self, url: str, **kwargs: Any) -> _Response:
        """Return the observed login or factor response."""
        self.requests.append({"method": "POST", "url": url, **kwargs})
        if url.endswith("/Login"):
            return _Response(
                {
                    "login": True,
                    "expiredPassword": False,
                    "waitingTime": 180000,
                    "newDevice": True,
                    "noMfa": False,
                    "enableResendMfaCode": False,
                    "isNumeric": True,
                }
            )
        assert url.endswith("/VerifyFactor")
        return _Response(
            {
                "code": True,
                "isPasswordExpired": False,
                "authRedirectUrl": "https://example.invalid/auth-redirect",
            }
        )

    def get(self, url: str, **kwargs: Any) -> _Response:
        """Return redirect completion or the final Opower token."""
        self.requests.append({"method": "GET", "url": url, **kwargs})
        if url == "https://example.invalid/auth-redirect":
            return _Response({})
        assert url.endswith("/GetOPowerToken")
        return _Response("opower-token")


@pytest.mark.asyncio
async def test_successful_coned_login_publishes_complete_progress() -> None:
    """A successful observed response sequence reaches token exchange."""
    session = _ConEdSession()
    opower = Opower(
        session,  # type: ignore[arg-type]
        "Consolidated Edison (ConEd)",
        "username",
        "password",
        "JBSWY3DPEHPK3PXP",
    )

    await opower.async_login()
    progress = await opower.async_authentication_progress()

    assert progress.authenticated
    assert progress.stage is FailureStage.TOKEN_EXCHANGE
    assert progress.message_key == "authentication_complete"
    assert opower.access_token == "opower-token"  # noqa: S105
    assert [request["method"] for request in session.requests] == [
        "POST",
        "POST",
        "GET",
        "GET",
    ]
    assert session.requests[0]["timeout"].total == 30
    assert session.requests[2]["timeout"].total == 45
