from dataclasses import replace

import pytest

from rlredteam.knowledge.validation import ModelError
from rlredteam.observation.audit import AuditKind as K
from rlredteam.observation.audit import AuditTrail
from rlredteam.observation.collector import ObservationCollector
from rlredteam.observation.serialization import dumps, loads
from rlredteam.observation.session import start_session
from rlredteam.observation.transport import FixtureObservationTransport
from tests.observation_fixtures import TIME, raw, scope, session


def test_audit_is_immutable_hashable_and_rejects_tampering_and_reordering():
    empty = AuditTrail(session_id="session:test")
    first = empty.append(K.SESSION_CREATED, TIME, scope_id="scope:test")
    second = first.append(K.SCOPE_VALIDATED, TIME, target="asset:web")
    assert not empty.events and len(first.events) == 1
    assert loads(dumps(second)) == second
    with pytest.raises(ModelError, match="digest"):
        replace(second.events[0], details={"tampered": True})
    with pytest.raises(ModelError, match="chain"):
        replace(second, events=tuple(reversed(second.events)))


def test_rejected_duplicate_is_structured_and_does_not_replace_accepted_record():
    collector = ObservationCollector(
        start_session(session(), at=TIME), scope(), FixtureObservationTransport((raw(),))
    )
    collector.accept("raw:address", at=TIME)
    with pytest.raises(ModelError):
        collector.accept("raw:address", at=TIME)
    assert collector.audit.events[-1].kind == K.OBSERVATION_REJECTED
    assert collector.observations == (raw(),)
    assert collector.budget.operations == 1
