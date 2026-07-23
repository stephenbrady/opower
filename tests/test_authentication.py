"""Tests for resettable single-flight authentication."""

import asyncio
import datetime

import pytest

from opower.authentication import (
    AuthenticationAttemptContext,
    AuthenticationGate,
    AuthenticationResetReason,
)
from opower.exceptions import (
    AuthenticationAttemptSuperseded,
    AuthenticationTimeout,
    FailureCategory,
    FailureDetails,
    FailureStage,
    MfaCodeRejected,
    RetryDisposition,
)


@pytest.mark.asyncio
async def test_concurrent_callers_join_one_authentication_attempt() -> None:
    """Concurrent callers await one task rather than starting duplicate login."""
    gate = AuthenticationGate()
    started = asyncio.Event()
    release = asyncio.Event()
    calls = 0

    async def authenticate(context: AuthenticationAttemptContext) -> None:
        nonlocal calls
        calls += 1
        await context.async_update_progress(
            FailureStage.AUTH_REDIRECT,
            message_key="following_redirect",
        )
        started.set()
        await release.wait()

    first = asyncio.create_task(gate.async_ensure_authenticated(authenticate))
    await started.wait()
    second = asyncio.create_task(gate.async_ensure_authenticated(authenticate))

    progress = await gate.async_progress()
    assert progress.stage is FailureStage.AUTH_REDIRECT
    assert progress.message_key == "following_redirect"

    release.set()
    first_progress, second_progress = await asyncio.gather(first, second)

    assert calls == 1
    assert first_progress.authenticated
    assert second_progress.authenticated


@pytest.mark.asyncio
async def test_reset_translates_internal_cancellation_for_joined_waiter() -> None:
    """Reset callers receive a domain failure rather than task cancellation."""
    gate = AuthenticationGate()
    started = asyncio.Event()
    cancelled = asyncio.Event()

    async def stall(context: AuthenticationAttemptContext) -> None:
        del context
        started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise

    waiting = asyncio.create_task(gate.async_ensure_authenticated(stall))
    await started.wait()
    progress = await gate.async_reset(AuthenticationResetReason.MANUAL)

    with pytest.raises(AuthenticationAttemptSuperseded):
        await waiting
    await cancelled.wait()
    assert not progress.authenticated
    assert not progress.reset_available


@pytest.mark.asyncio
async def test_cancelled_waiter_does_not_cancel_shared_authentication() -> None:
    """Caller cancellation remains CancelledError and leaves shared login running."""
    gate = AuthenticationGate()
    started = asyncio.Event()
    release = asyncio.Event()

    async def authenticate(context: AuthenticationAttemptContext) -> None:
        del context
        started.set()
        await release.wait()

    waiting = asyncio.create_task(gate.async_ensure_authenticated(authenticate))
    await started.wait()
    waiting.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiting

    release.set()
    progress = await gate.async_ensure_authenticated(authenticate)
    assert progress.authenticated


@pytest.mark.asyncio
async def test_timeout_is_structured_and_clears_session() -> None:
    """A bounded transaction timeout is retryable and invalidates session state."""
    invalidations = 0

    def invalidate() -> None:
        nonlocal invalidations
        invalidations += 1

    gate = AuthenticationGate(
        timeout=datetime.timedelta(milliseconds=10),
        invalidate_session=invalidate,
    )

    async def stall(context: AuthenticationAttemptContext) -> None:
        del context
        await asyncio.Event().wait()

    with pytest.raises(AuthenticationTimeout) as error:
        await gate.async_ensure_authenticated(stall)

    assert invalidations == 1
    assert error.value.details is not None
    assert error.value.details.message_key == "authentication_timeout"


@pytest.mark.asyncio
async def test_same_totp_counter_waits_inside_manager() -> None:
    """A repeated counter waits for rollover instead of being submitted twice."""
    current_time = [datetime.datetime(2026, 7, 23, 12, 0, tzinfo=datetime.UTC)]
    sleeps: list[float] = []
    submitted: list[int] = []
    calls = 0

    async def fake_sleep(delay: float) -> None:
        sleeps.append(delay)
        current_time[0] += datetime.timedelta(seconds=delay)

    gate = AuthenticationGate(
        clock=lambda: current_time[0],
        sleep=fake_sleep,
    )

    async def authenticate(context: AuthenticationAttemptContext) -> None:
        nonlocal calls
        calls += 1
        await context.async_prepare_totp(
            100,
            current_time[0] + datetime.timedelta(seconds=30),
        )
        submitted_counter = 100 if calls == 1 else 101
        await context.async_mark_totp_submitted(submitted_counter)
        submitted.append(submitted_counter)

    first = await gate.async_ensure_authenticated(authenticate)
    await gate.async_invalidate(
        AuthenticationResetReason.SESSION_EXPIRED,
        expected_generation=first.generation,
    )
    await gate.async_ensure_authenticated(authenticate)

    assert submitted == [100, 101]
    assert sleeps == [30.0]


@pytest.mark.asyncio
async def test_mfa_rejection_gets_one_managed_rollover_retry() -> None:
    """All callers remain attached while one fresh TOTP retry is performed."""
    current_time = [datetime.datetime(2026, 7, 23, 12, 0, tzinfo=datetime.UTC)]
    calls = 0
    sleeps: list[float] = []

    async def fake_sleep(delay: float) -> None:
        sleeps.append(delay)
        current_time[0] += datetime.timedelta(seconds=delay)

    gate = AuthenticationGate(
        clock=lambda: current_time[0],
        sleep=fake_sleep,
    )

    async def authenticate(context: AuthenticationAttemptContext) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise MfaCodeRejected(
                "MFA transaction rejected",
                details=FailureDetails(
                    category=FailureCategory.MFA_CODE_REJECTED,
                    stage=FailureStage.MFA_VERIFICATION,
                    retry=RetryDisposition.RETRY_AFTER_TOTP_ROLLOVER,
                    message_key="coned_mfa_transaction_rejected",
                    retry_at=current_time[0] + datetime.timedelta(seconds=30),
                ),
            )
        await context.async_update_progress(
            FailureStage.TOKEN_EXCHANGE,
            message_key="requesting_token",
        )

    progress = await gate.async_ensure_authenticated(authenticate)

    assert calls == 2
    assert sleeps == [30.0]
    assert progress.authenticated
    assert progress.stage is FailureStage.TOKEN_EXCHANGE
