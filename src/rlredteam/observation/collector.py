"""Offline acceptance of supplied observations, NOT live acquisition."""

from rlredteam.knowledge.validation import ModelError

from .audit import AuditKind, AuditTrail
from .models import SessionStatus
from .session import Budget, BudgetLimits
from .transport import FixtureObservationTransport, MockObservationTransport
from .validation import validate_observation


class ObservationCollector:
    def __init__(self, session, scope, transport, *, limits=None):
        if type(transport) not in (MockObservationTransport, FixtureObservationTransport):
            raise ModelError("only native offline transports are permitted")
        if session.scope_id != scope.scope_id or session.status != SessionStatus.RUNNING:
            raise ModelError("collector requires a running, scope-bound offline session")
        self.session, self.scope, self.transport = session, scope, transport
        proposed = limits or BudgetLimits()
        self.budget = Budget(
            BudgetLimits(
                max_targets=min(proposed.max_targets, scope.max_hosts),
                max_operations=proposed.max_operations,
                max_duration_seconds=min(proposed.max_duration_seconds, scope.max_duration_seconds),
                per_asset_requests=min(proposed.per_asset_requests, scope.max_requests_per_asset),
                concurrency_limit=proposed.concurrency_limit,
            )
        )
        self.audit = AuditTrail(session_id=session.session_id).append(
            AuditKind.SESSION_CREATED,
            session.created_at,
            mode=session.mode.value,
            scope_id=scope.scope_id,
        )
        self._accepted = {}

    def accept(self, observation_id, *, at, elapsed_seconds=0):
        try:
            raw = self.transport.read_metadata(observation_id)
            validate_observation(raw, self.session, self.scope)
            self.scope.validate_target(raw.subject_hint, raw.capability, at=at)
            if observation_id in self._accepted:
                raise ModelError("duplicate observation ID")
            token = self.budget.reserve(raw.subject_hint, elapsed_seconds=elapsed_seconds)
            try:
                audit = self.audit.append(
                    AuditKind.SCOPE_VALIDATED,
                    at,
                    observation_id=observation_id,
                    capability=raw.capability.value,
                )
                audit = audit.append(
                    AuditKind.OBSERVATION_ACCEPTED,
                    at,
                    observation_id=observation_id,
                    input_digest=raw.provenance.input_digest,
                )
                self._accepted[observation_id] = raw
                self.audit = audit
            finally:
                self.budget.release(token)
            return raw
        except (ValueError, KeyError) as exc:
            self.audit = self.audit.append(
                AuditKind.OBSERVATION_REJECTED,
                at,
                observation_id=observation_id,
                reason_type=type(exc).__name__,
            )
            raise

    @property
    def observations(self):
        return tuple(self._accepted[key] for key in sorted(self._accepted))
