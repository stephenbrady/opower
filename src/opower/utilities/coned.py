"""Consolidated Edison (ConEd)."""

from typing import Any

import aiohttp
import pyotp

from ..const import USER_AGENT
from ..exceptions import FailureCategory, FailureDetails, FailureStage, InvalidAuth, ProtocolError, RetryDisposition
from .base import UtilityBase
from .coned_models import (
    parse_factor_response,
    parse_login_response,
    raise_for_factor_rejection,
    raise_for_login_rejection,
)

RETURN_URL = "/en/accounts-billing/my-account/energy-use"


class ConEd(UtilityBase):
    """Consolidated Edison (ConEd)."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Consolidated Edison (ConEd)"

    def subdomain(self) -> str:
        """Return the opower.com subdomain for this utility."""
        return "cned"

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/New_York"

    @staticmethod
    def accepts_totp_secret() -> bool:
        """Check if Utility accepts TOTP secret."""
        return True

    @staticmethod
    def hostname() -> str:
        """Return the hostname for login. Allows overriding it for oru.com."""
        return "coned.com"

    @staticmethod
    def supports_realtime_usage() -> bool:
        """Check if Utility supports realtime usage reads."""
        return True

    async def async_login(
        self,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        login_data: dict[str, Any],
    ) -> str:
        """Login to the utility website."""
        hostname = self.hostname()
        login_base = "https://www." + hostname + "/sitecore/api/ssc/ConEdWeb-Foundation-Login-Areas-LoginAPI/User/0"
        login_headers = {
            "User-Agent": USER_AGENT,
            "Referer": "https://www." + hostname + "/",
        }

        # Double-logins are somewhat broken if cookies stay around.
        # Let's clear everything except device tokens (which allow skipping 2FA)
        session.cookie_jar.clear(lambda cookie: cookie["domain"] == "www." + hostname and cookie.key != "CE_DEVICE_ID")

        async with session.post(
            login_base + "/Login",
            json={
                "LoginEmail": username,
                "LoginPassword": password,
                "LoginRememberMe": False,
                "ReturnUrl": RETURN_URL,
                "OpenIdRelayState": "",
            },
            headers=login_headers,
            raise_for_status=True,
        ) as resp:
            login_response = parse_login_response(await resp.json())
            raise_for_login_rejection(login_response)

            redirect_url = login_response.auth_redirect_url
            if redirect_url is None and login_response.new_device and not login_response.no_mfa:
                if not self._totp_secret:
                    raise InvalidAuth(
                        "A TOTP secret is required for this ConEd account",
                        details=FailureDetails(
                            category=FailureCategory.MFA_REQUIRED,
                            stage=FailureStage.MFA_GENERATION,
                            retry=RetryDisposition.USER_ACTION_REQUIRED,
                            message_key="coned_totp_secret_required",
                        ),
                    )

                mfa_code = pyotp.TOTP(self._totp_secret).now()

                async with session.post(
                    login_base + "/VerifyFactor",
                    headers=login_headers,
                    json={
                        "MFACode": mfa_code,
                        "ReturnUrl": RETURN_URL,
                        "OpenIdRelayState": "",
                    },
                    raise_for_status=True,
                ) as resp:  # noqa: PLW2901
                    factor_response = parse_factor_response(await resp.json())
                    raise_for_factor_rejection(factor_response)
                    redirect_url = factor_response.auth_redirect_url

            if redirect_url is None:
                raise ProtocolError(
                    "ConEd login succeeded without an authorization redirect",
                    details=FailureDetails(
                        category=FailureCategory.PROTOCOL,
                        stage=FailureStage.AUTH_REDIRECT,
                        retry=RetryDisposition.DO_NOT_RETRY,
                        message_key="coned_auth_redirect_missing",
                    ),
                )
            async with session.get(
                redirect_url,
                headers={
                    "User-Agent": USER_AGENT,
                },
                allow_redirects=True,
                raise_for_status=True,
            ) as resp:  # noqa: PLW2901
                pass

        async with session.get(
            "https://www."
            + hostname
            + "/sitecore/api/ssc/ConEd-Cms-Services-Controllers-Opower/OpowerService/0/GetOPowerToken",
            headers=login_headers,
            raise_for_status=True,
        ) as resp:
            return str(await resp.json())
