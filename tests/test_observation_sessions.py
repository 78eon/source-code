from dataclasses import replace

import pytest

from rlredteam.knowledge.validation import ModelError
from rlredteam.observation.protocols import LiveObservationDisabledError, ObservationMode
from rlredteam.observation.provenance import AuthorizationRecord
from rlredteam.observation.session import (
    Budget,
    BudgetExhaustedError,
    BudgetLimits,
    complete_session,
    start_session,
)
from tests.observation_fixtures import TIME, scope, session


@pytest.mark.parametrize(
    "mode", [ObservationMode.FIXTURE, ObservationMode.OFFLINE_IMPORT, ObservationMode.MANUAL]
)
def test_offline_session_lifecycle_needs_no_authorization(mode):
    value = session(mode=mode)
    assert value.authorization_id is None
    running = start_session(value, at=TIME)
    completed = complete_session(running, at=TIME, evidence_count=3)
    assert completed.evidence_count == 3
    assert value.started_at is None
    with pytest.raises(ModelError):
        start_session(running, at=TIME)


def test_live_creation_and_direct_model_construction_denied():
    with pytest.raises(LiveObservationDisabledError):
        session(mode=ObservationMode.LIVE_LAB)
    with pytest.raises(LiveObservationDisabledError):
        replace(session(), mode=ObservationMode.LIVE_LAB)


def test_live_scope_configuration_still_cannot_enable_execution():
    from rlredteam.observation.session import create_session
    from tests.observation_fixtures import provenance

    enabled = scope(live_enabled=True, authorization_reference="approved:fixture")
    with pytest.raises(LiveObservationDisabledError):
        create_session(
            scope=enabled,
            mode=ObservationMode.LIVE_LAB,
            session_id="session:live",
            created_at=TIME,
            collector_version="test",
            host_identity="supplied",
            provenance=provenance({}),
        )


def test_authorization_expiry_and_binding():
    auth = AuthorizationRecord(
        authorization_id="auth:test",
        scope_id="scope:fixture",
        owner="fixture owner",
        authorized_by="fixture reviewer",
        valid_from="2026-10-01T00:00:00Z",
        valid_until="2026-10-02T00:00:00Z",
        permitted_purpose="offline test",
        authorization_reference="manual:fixture",
    )
    with pytest.raises(ModelError, match="expired"):
        auth.validate(scope(authorization_reference="manual:fixture"), at=TIME)
    with pytest.raises(ModelError, match="scope/reference"):
        auth.validate(scope(), at="2026-10-01T12:00:00Z")
    auth.validate(scope(authorization_reference="manual:fixture"), at="2026-10-01T12:00:00Z")
    with pytest.raises(ModelError, match="digest"):
        replace(auth, owner="tampered")


@pytest.mark.parametrize(
    "limit",
    [
        "max_targets",
        "max_operations",
        "per_asset_requests",
        "concurrency_limit",
        "max_duration_seconds",
    ],
)
def test_each_budget_dimension_exhausts_without_live_work(limit):
    budget = Budget(BudgetLimits(**{limit: 1}))
    first = budget.reserve("asset:a", elapsed_seconds=0)
    if limit != "concurrency_limit":
        budget.release(first)
    with pytest.raises(BudgetExhaustedError):
        budget.reserve(
            "asset:b" if limit == "max_targets" else "asset:a",
            elapsed_seconds=1 if limit == "max_duration_seconds" else 0,
        )
