import pytest

from rlredteam.evidence.models import (
    ApplicabilityStatus,
    ObservedAsset,
    ObservedIdentity,
    ObservedRelationship,
    ObservedService,
)
from rlredteam.evidence.serialization import dumps as evidence_dumps
from rlredteam.knowledge.validation import ModelError
from rlredteam.observation.normalization import asset_assignments, normalize
from rlredteam.observation.protocols import Capability as C
from rlredteam.observation.serialization import dumps, import_bundle
from tests.observation_fixtures import bundle, raw


def test_normalization_is_deterministic_and_preserves_every_raw_origin():
    source = bundle()
    first = normalize(source)
    assert evidence_dumps(first.bundle) == evidence_dumps(normalize(source).bundle)
    assert evidence_dumps(import_bundle(dumps(source)).bundle) == evidence_dumps(first.bundle)
    ids = {item.observation_id for item in source.observations}
    for item in (*first.bundle.records, *first.bundle.findings):
        assert item.provenance.attributes["raw_observation_id"] in ids
        assert item.provenance.attributes["bundle_digest"] == source.digest
        assert item.provenance.attributes["input_digest"]
    assert any(isinstance(item, ObservedAsset) for item in first.bundle.records)
    assert any(isinstance(item, ObservedIdentity) for item in first.bundle.records)
    assert any(
        isinstance(item, ObservedService) and item.port == 443 for item in first.bundle.records
    )
    assert any(isinstance(item, ObservedRelationship) for item in first.bundle.records)
    assert first.bundle.findings[0].applicability_status == ApplicabilityStatus.POSSIBLE


def test_conflicting_hostnames_both_survive():
    evidence = normalize(bundle()).bundle
    names = {
        identifier.value
        for item in evidence.records
        if isinstance(item, ObservedAsset)
        for identifier in item.identifiers
        if identifier.identifier_type.value == "HOSTNAME"
    }
    assert names == {"web01.test", "db01.test"}


def test_address_or_mac_or_hostname_is_not_a_durable_asset_key():
    for key, value in (
        ("address", "192.0.2.10"),
        ("mac", "00:11:22:33:44:55"),
        ("hostname", "web01.test"),
    ):
        observation = raw(fields={"asset_key": value, key: value})
        with pytest.raises(ModelError):
            normalize(bundle(observations=(observation,)))


def test_generated_asset_ids_do_not_change_when_addresses_or_names_change():
    a = bundle(observations=(raw(fields={"address": "192.0.2.10", "hostname": "old.test"}),))
    b = bundle(observations=(raw(fields={"address": "192.0.2.20", "hostname": "new.test"}),))
    assert asset_assignments(a) == asset_assignments(b)


def test_nested_out_of_scope_target_and_missing_target_evidence_are_rejected():
    with pytest.raises(ModelError):
        bundle(observations=(raw(fields={"address": "8.8.8.8"}),))
    with pytest.raises(ModelError, match="no supplied asset"):
        normalize(
            bundle(
                observations=(
                    raw(capability=C.ROUTE_INVENTORY, fields={"target_asset": "asset:db"}),
                )
            )
        )


@pytest.mark.parametrize("capability", list(C))
def test_all_capability_declarations_can_retain_offline_input(capability):
    evidence = normalize(bundle(observations=(raw(capability=capability),))).bundle
    assert any(item.observation_type == "raw_input" for item in evidence.records)
    assert all(
        item.provenance.attributes["raw_observation_id"] == "raw:address"
        for item in evidence.records
    )
