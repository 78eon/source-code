import pytest

from rlredteam.evidence.models import AssetIdentifier
from rlredteam.evidence.models import IdentifierType as I
from rlredteam.knowledge.validation import ModelError
from rlredteam.observation.identity import ConflictDecisionState as S
from rlredteam.observation.identity import (
    ConflictResolutionDecision,
    InMemoryAssetIdentityStore,
    fixture_asset_id,
)
from tests.observation_fixtures import TIME


def identifier(kind=I.USER_DEFINED, value="stable-key"):
    return AssetIdentifier(identifier_type=kind, value=value)


def test_fixture_ids_are_namespaced_strong_and_order_independent():
    identifiers = (identifier(), identifier(I.CLOUD_RESOURCE, "cloud:immutable"))
    assert fixture_asset_id("fixture:a", identifiers) == fixture_asset_id(
        "fixture:a", reversed(identifiers)
    )
    assert fixture_asset_id("fixture:a", identifiers) != fixture_asset_id("fixture:b", identifiers)
    for item in (
        identifier(I.IPV4, "192.0.2.1"),
        identifier(I.HOSTNAME, "host.test"),
        identifier(I.MAC, "00:11:22:33:44:55"),
    ):
        with pytest.raises(ModelError):
            fixture_asset_id("fixture:a", (item,))


def test_generated_identity_stays_stable_when_identifiers_change_and_matches_are_candidates():
    store = InMemoryAssetIdentityStore()
    a = store.register_asset((identifier(),), evidence_ids=("raw:a",))
    b = store.register_asset((identifier(),), evidence_ids=("raw:b",))
    assert a != b
    store.link_identifier(a, identifier(I.IPV4, "192.0.2.10"), evidence_id="raw:c")
    store.link_identifier(a, identifier(I.HOSTNAME, "renamed.test"), evidence_id="raw:d")
    assert store.history(a)["versions"][-1].asset_id == a
    assert store.resolve_identifiers((identifier(),)) == tuple(sorted((a, b)))
    assert len(store.history(a)["versions"]) == 3


@pytest.mark.parametrize("state", list(S))
def test_conflict_decisions_are_recorded_never_automatically_applied(state):
    store = InMemoryAssetIdentityStore()
    a, b = store.register_asset((identifier(),)), store.register_asset((identifier(),))
    decision = ConflictResolutionDecision(
        decision_id="decision:test",
        asset_ids=(a, b),
        evidence_ids=("raw:a", "raw:b"),
        state=state,
        reason="manual fixture proposal",
        created_at=TIME,
    )
    store.record_conflict(decision)
    assert store.history(a)["conflicts"] == (decision,)
    assert len(store.resolve_identifiers((identifier(),))) == 2
