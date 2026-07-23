"""Resettable single-flight authentication coordination."""

import asyncio
import contextlib
import dataclasses
import datetime
import enum
from collections.abc import Awaitable, Callable

from .exceptions import (
    AuthenticationAttemptSuperseded,
    AuthenticationTimeout,
    FailureCategory,
    FailureDetails,
    FailureStage,
    MfaCodeRejected,
    RetryDisposition,
)
from .http_response import new_correlation_id

DEFAULT_AUTHENTICATION_TIMEOUT = datetime.timedelta(seconds=120)


class AuthenticationResetReason(enum.StrEnum):
    """Reason an authentication generation was explicitly reset."""

    MANUAL = "manual"
    SESSION_EXPIRED = "session_expired"
    UNLOAD = "unload"
    TIMEOUT = "timeout"


@dataclasses.dataclass(frozen=True, slots=True)
class AuthenticationProgress:
    """Safe state suitable for user feedback and diagnostics."""

    authenticated: bool
    attempt_id: str | None
    generation: int
    stage: FailureStage
    started_at: datetime.datetime | None
    deadline: datetime.datetime | None
    retry_at: datetime.datetime | None
    message_key: str | None
    last_failure: FailureDetails | None
    reset_available: bool


class AuthenticationAttemptContext:
    """Progress and one-time-code coordination for one authentication generation."""

    def __init__(self, gate: "AuthenticationGate", generation: int, attempt_id: str) -> None:
        """Initialize an attempt-bound context."""
        self._gate = gate
        self._generation = generation
        self.attempt_id = attempt_id

    async def async_update_progress(
        self,
        stage: FailureStage,
        *,
        retry_at: datetime.datetime | None = None,
        message_key: str | None = None,
    ) -> None:
        """Publish safe progress if this is still the active generation."""
        await self._gate._async_update_progress(
            self._generation,
            stage,
            retry_at=retry_at,
            message_key=message_key,
        )

    async def async_prepare_totp(
        self,
        counter: int,
        retry_at: datetime.datetime,
    ) -> None:
        """Wait when this manager has already submitted the current TOTP counter."""
        await self._gate._async_prepare_totp(self._generation, counter, retry_at)

    async def async_mark_totp_submitted(self, counter: int) -> None:
        """Record the counter immediately before its provider submission."""
        await self._gate._async_mark_totp_submitted(self._generation, counter)


class AuthenticationGate:
    """Share one bounded authentication attempt among callers of one Opower instance."""

    def __init__(
        self,
        *,
        timeout: datetime.timedelta = DEFAULT_AUTHENTICATION_TIMEOUT,
        invalidate_session: Callable[[], None] | None = None,
        clock: Callable[[], datetime.datetime] | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        """Initialize an unauthenticated gate with bounded transaction state."""
        self._timeout = timeout
        self._invalidate_session = invalidate_session or (lambda: None)
        self._clock = clock or (lambda: datetime.datetime.now(datetime.UTC))
        self._sleep = sleep
        self._state_lock = asyncio.Lock()
        self._task: asyncio.Task[None] | None = None
        self._generation = 0
        self._authenticated = False
        self._attempt_id: str | None = None
        self._started_at: datetime.datetime | None = None
        self._stage = FailureStage.LOGIN
        self._retry_at: datetime.datetime | None = None
        self._message_key: str | None = None
        self._last_failure: FailureDetails | None = None
        self._last_totp_counter: int | None = None

    async def async_ensure_authenticated(
        self,
        authenticate: Callable[[AuthenticationAttemptContext], Awaitable[None]],
    ) -> AuthenticationProgress:
        """Return after the shared authentication attempt has completed."""
        async with self._state_lock:
            if self._authenticated:
                return self._progress_locked()
            task = self._task
            if task is None or task.done():
                self._generation += 1
                generation = self._generation
                attempt_id = new_correlation_id()
                self._attempt_id = attempt_id
                self._started_at = self._clock()
                self._stage = FailureStage.LOGIN
                self._retry_at = None
                self._message_key = "authentication_started"
                context = AuthenticationAttemptContext(self, generation, attempt_id)
                self._task = asyncio.create_task(
                    self._async_run(generation, context, authenticate)
                )
                task = self._task
            generation = self._generation
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as error:
            current_task = asyncio.current_task()
            if current_task is not None and current_task.cancelling():
                raise
            async with self._state_lock:
                if generation == self._generation:
                    raise
                details = self._superseded_details_locked()
            raise AuthenticationAttemptSuperseded(
                "Authentication attempt was replaced",
                details=details,
            ) from error
        async with self._state_lock:
            if generation != self._generation:
                raise AuthenticationAttemptSuperseded(
                    "Authentication attempt was replaced",
                    details=self._superseded_details_locked(),
                )
            return self._progress_locked()

    async def async_invalidate(
        self,
        reason: AuthenticationResetReason,
        *,
        expected_generation: int | None = None,
    ) -> AuthenticationProgress:
        """Invalidate one observed authentication generation coherently."""
        async with self._state_lock:
            if expected_generation is not None and expected_generation != self._generation:
                return self._progress_locked()
            self._invalidate_session()
            self._authenticated = False
            self._last_failure = FailureDetails(
                category=FailureCategory.SESSION_EXPIRED,
                stage=FailureStage.AUTH_REDIRECT,
                retry=RetryDisposition.REAUTHENTICATE_ONCE,
                message_key=f"authentication_invalidated_{reason.value}",
                attempt_id=self._attempt_id,
            )
            return self._progress_locked()

    async def async_reset(
        self,
        reason: AuthenticationResetReason = AuthenticationResetReason.MANUAL,
    ) -> AuthenticationProgress:
        """Cancel and detach a stale attempt while translating joined waiters."""
        async with self._state_lock:
            stale_task = self._task
            self._generation += 1
            self._task = None
            self._invalidate_session()
            self._authenticated = False
            self._attempt_id = None
            self._started_at = None
            self._stage = FailureStage.LOGIN
            self._retry_at = None
            self._message_key = f"authentication_reset_{reason.value}"
            self._last_failure = FailureDetails(
                category=FailureCategory.AUTHENTICATION_RESET,
                stage=FailureStage.LOGIN,
                retry=RetryDisposition.RETRY_WITH_BACKOFF,
                message_key=self._message_key,
            )
            progress = self._progress_locked()
        if stale_task and not stale_task.done():
            stale_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, TimeoutError):
                async with asyncio.timeout(5):
                    await asyncio.shield(stale_task)
        return progress

    async def async_progress(self) -> AuthenticationProgress:
        """Return the current safe authentication state."""
        async with self._state_lock:
            return self._progress_locked()

    async def _async_run(
        self,
        generation: int,
        context: AuthenticationAttemptContext,
        authenticate: Callable[[AuthenticationAttemptContext], Awaitable[None]],
    ) -> None:
        """Run one bounded authentication transaction with one MFA rollover retry."""
        try:
            async with asyncio.timeout(self._timeout.total_seconds()):
                rollover_retries = 0
                while True:
                    try:
                        await authenticate(context)
                    except MfaCodeRejected as error:
                        details = error.details
                        if (
                            rollover_retries
                            or details is None
                            or details.retry is not RetryDisposition.RETRY_AFTER_TOTP_ROLLOVER
                            or details.retry_at is None
                        ):
                            raise
                        rollover_retries += 1
                        await self._async_wait_until(
                            generation,
                            details.retry_at,
                            FailureStage.MFA_GENERATION,
                            "waiting_for_fresh_totp_window",
                        )
                        self._invalidate_session()
                        continue
                    break
        except TimeoutError as error:
            details = FailureDetails(
                category=FailureCategory.PROVIDER_UNAVAILABLE,
                stage=self._stage,
                retry=RetryDisposition.RETRY_WITH_BACKOFF,
                message_key="authentication_timeout",
                attempt_id=self._attempt_id,
            )
            self._invalidate_session()
            await self._async_record_failure(generation, details)
            raise AuthenticationTimeout(
                "Authentication transaction timed out",
                details=details,
            ) from error
        except asyncio.CancelledError:
            raise
        except Exception as error:
            error_details = getattr(error, "details", None)
            if isinstance(error_details, FailureDetails):
                await self._async_record_failure(generation, error_details)
            raise
        else:
            async with self._state_lock:
                if generation == self._generation:
                    self._authenticated = True
                    self._retry_at = None
                    self._message_key = "authentication_complete"
                    self._last_failure = None
        finally:
            async with self._state_lock:
                if generation == self._generation and self._task is asyncio.current_task():
                    self._task = None

    async def _async_prepare_totp(
        self,
        generation: int,
        counter: int,
        retry_at: datetime.datetime,
    ) -> None:
        """Wait until rollover only when the current counter was already submitted."""
        async with self._state_lock:
            already_submitted = (
                generation == self._generation and counter == self._last_totp_counter
            )
        if already_submitted:
            await self._async_wait_until(
                generation,
                retry_at,
                FailureStage.MFA_GENERATION,
                "waiting_for_fresh_totp_window",
            )

    async def _async_mark_totp_submitted(self, generation: int, counter: int) -> None:
        """Retain a submitted counter only for the active generation."""
        async with self._state_lock:
            self._raise_if_superseded_locked(generation)
            self._last_totp_counter = counter

    async def _async_wait_until(
        self,
        generation: int,
        retry_at: datetime.datetime,
        stage: FailureStage,
        message_key: str,
    ) -> None:
        """Publish a wait deadline and sleep outside the state lock."""
        await self._async_update_progress(
            generation,
            stage,
            retry_at=retry_at,
            message_key=message_key,
        )
        delay = max(0.0, (retry_at - self._clock()).total_seconds())
        await self._sleep(delay)
        async with self._state_lock:
            self._raise_if_superseded_locked(generation)
            self._retry_at = None

    async def _async_update_progress(
        self,
        generation: int,
        stage: FailureStage,
        *,
        retry_at: datetime.datetime | None,
        message_key: str | None,
    ) -> None:
        """Update progress only for the active generation."""
        async with self._state_lock:
            self._raise_if_superseded_locked(generation)
            self._stage = stage
            self._retry_at = retry_at
            self._message_key = message_key

    async def _async_record_failure(
        self,
        generation: int,
        details: FailureDetails,
    ) -> None:
        """Retain a failure only when it belongs to the active generation."""
        async with self._state_lock:
            if generation == self._generation:
                self._authenticated = False
                self._stage = details.stage
                self._retry_at = details.retry_at
                self._message_key = details.message_key
                self._last_failure = details

    def _raise_if_superseded_locked(self, generation: int) -> None:
        """Raise a domain failure when an attempt no longer owns the generation."""
        if generation != self._generation:
            raise AuthenticationAttemptSuperseded(
                "Authentication attempt was replaced",
                details=self._superseded_details_locked(),
            )

    def _superseded_details_locked(self) -> FailureDetails:
        """Build safe details for a replaced authentication attempt."""
        return FailureDetails(
            category=FailureCategory.AUTHENTICATION_RESET,
            stage=self._stage,
            retry=RetryDisposition.RETRY_WITH_BACKOFF,
            message_key="authentication_attempt_superseded",
            attempt_id=self._attempt_id,
        )

    def _progress_locked(self) -> AuthenticationProgress:
        """Build progress while the caller holds the state lock."""
        deadline = self._started_at + self._timeout if self._started_at else None
        return AuthenticationProgress(
            authenticated=self._authenticated,
            attempt_id=self._attempt_id,
            generation=self._generation,
            stage=self._stage,
            started_at=self._started_at,
            deadline=deadline,
            retry_at=self._retry_at,
            message_key=self._message_key,
            last_failure=self._last_failure,
            reset_available=self._task is not None and not self._task.done(),
        )
