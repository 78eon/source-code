"""Offline session lifecycle and deterministic resource-accounting foundations."""

from dataclasses import dataclass, replace
from datetime import datetime
from threading import Lock

from rlredteam.knowledge import validation as v

from .models import ObservationSession, SessionStatus
from .protocols import LiveObservationDisabledError, ObservationMode


def create_session(*, scope, authorization=None, **kwargs):
    if kwargs.get("mode") == ObservationMode.LIVE_LAB:
        raise LiveObservationDisabledError("Phase 4A has no live observation execution path")
    if authorization is not None:
        authorization.validate(scope, at=kwargs["created_at"])
    requested = kwargs.get("requested_capabilities", ())
    if any(not scope.is_capability_permitted(item) for item in requested):
        raise v.ModelError("session requests an unapproved capability")
    if scope.expires_at and datetime.fromisoformat(
        v.timestamp(kwargs["created_at"])
    ) >= datetime.fromisoformat(scope.expires_at):
        raise v.ModelError("scope has expired")
    return ObservationSession(
        scope_id=scope.scope_id,
        permitted_capabilities=tuple(requested),
        authorization_id=authorization.authorization_id if authorization else None,
        **kwargs,
    )


def start_session(session, *, at):
    if session.mode == ObservationMode.LIVE_LAB:
        raise LiveObservationDisabledError("live execution disabled")
    if session.status != SessionStatus.CREATED:
        raise v.ModelError("session can start only once")
    return replace(session, status=SessionStatus.RUNNING, started_at=at)


def complete_session(session, *, at, evidence_count):
    if session.status != SessionStatus.RUNNING:
        raise v.ModelError("only running sessions may complete")
    return replace(
        session, status=SessionStatus.COMPLETED, completed_at=at, evidence_count=evidence_count
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class BudgetLimits:
    max_targets: int = 16
    max_operations: int = 128
    max_duration_seconds: int = 60
    per_asset_requests: int = 8
    concurrency_limit: int = 1

    def __post_init__(self):
        v.validate_fields(self)
        for value in (
            self.max_targets,
            self.max_operations,
            self.max_duration_seconds,
            self.per_asset_requests,
            self.concurrency_limit,
        ):
            if value <= 0:
                raise v.ModelError("budget limits must be positive")


class BudgetExhaustedError(v.ModelError):
    pass


class Budget:
    """Caller-supplied elapsed time for mocked work; no live scheduler is provided."""

    def __init__(self, limits=None):
        self.limits = limits or BudgetLimits()
        self._counts, self._active = {}, set()
        self._operations, self._last_elapsed = 0, 0.0
        self._lock = Lock()

    def reserve(self, target, *, elapsed_seconds):
        v.stable_id(target)
        if type(elapsed_seconds) not in (int, float) or not 0 <= elapsed_seconds < float("inf"):
            raise v.ModelError("invalid elapsed time")
        with self._lock:
            if elapsed_seconds < self._last_elapsed:
                raise v.ModelError("elapsed time cannot move backwards")
            self._last_elapsed = elapsed_seconds
            limits = self.limits
            if (
                elapsed_seconds >= limits.max_duration_seconds
                or self._operations >= limits.max_operations
                or len(self._active) >= limits.concurrency_limit
                or self._counts.get(target, 0) >= limits.per_asset_requests
                or (target not in self._counts and len(self._counts) >= limits.max_targets)
            ):
                raise BudgetExhaustedError("observation budget exhausted")
            self._operations += 1
            self._counts[target] = self._counts.get(target, 0) + 1
            token = self._operations
            self._active.add(token)
            return token

    def release(self, token):
        with self._lock:
            if token not in self._active:
                raise v.ModelError("invalid or already released budget token")
            self._active.remove(token)

    @property
    def operations(self):
        return self._operations
