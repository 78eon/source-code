from dataclasses import replace

import pytest

from rlredteam.digital_twin.builder import DigitalTwinBuilder
from rlredteam.digital_twin.models import FactStatus, TwinRelationType, VersionStatus, ZoneType
from rlredteam.digital_twin.policy import ReconstructionPolicy
from rlredteam.evidence.models import ApplicabilityStatus, ObservedSoftware
from rlredteam.evidence.registry import EvidenceRegistry
from rlredteam.knowledge.validation import ModelError
from tests.digital_twin_fixtures import build, evidence, host
from tests.knowledge_evidence_fixtures import record, registry


def test_reconstructs_chain_components_and_identity_without_attack_claims():
    twin = build()
    assert len(twin.assets) == 4 and len(twin.services) == 1 and len(twin.software) == 1
    assert len(twin.identities) == 1 and len(twin.findings) == 1
    web = next(asset for asset in twin.assets if "asset:web" in asset.subject_ids)
    assert len(web.evidence_ids) == 2 and web.entry_point
    assert twin.services[0].port == 443 and twin.services[0].protocol == "tcp"
    assert twin.software[0].version_status == VersionStatus.EXACT
    assert all(edge.evidence_ids and edge.provenance.rules for edge in twin.relationships)
    assert all(item.status == FactStatus.SYNTHETIC for item in twin.assets)
    assert twin.findings[0].applicability_status == ApplicabilityStatus.POSSIBLE


def test_enrichment_is_separate_from_observation_and_explainable():
    twin = build()
    service = twin.services[0]
    explanation = twin.explain_entity(service.stable_id)
    assert service.knowledge_ids == ("product:a",)
    assert explanation["knowledge_enrichment"][0].stable_id == "product:a"
    assert explanation["knowledge_source_ids"] == ("source:test",)
    assert not any(record.observation_type == "knowledge" for record in twin.evidence.records)
    edge = twin.relationships[0]
    assert twin.explain_relation(edge.stable_id)["evidence_ids"] == edge.evidence_ids
    resolution = twin.resolutions[0]
    assert (
        twin.explain_resolution(resolution.stable_id)["confidence_calculation"]["score"]
        == resolution.confidence
    )
    with pytest.raises(KeyError):
        twin.explain_entity("missing")


@pytest.mark.parametrize("applicability", list(ApplicabilityStatus))
def test_finding_applicability_never_upgraded(applicability):
    source = evidence()
    bundle = source.bundle
    original = replace(bundle.findings[0], applicability_status=applicability)
    source = EvidenceRegistry(
        bundle_id=bundle.bundle_id,
        created_at=bundle.created_at,
        sources=bundle.sources,
        records=bundle.records,
        findings=(original,),
    )
    result = DigitalTwinBuilder(registry(), source).build()
    assert result.findings[0].original == original
    assert result.findings[0].applicability_status == applicability


@pytest.mark.parametrize(
    "kind,version,state",
    [
        ("exact", "1.0", VersionStatus.EXACT),
        ("range", ">=1,<2", VersionStatus.RANGE),
        ("unknown", "maybe 1", VersionStatus.UNKNOWN),
    ],
)
def test_explicit_software_precision_only(kind, version, state):
    extra = record(
        "evidence:other-software",
        ObservedSoftware,
        subject_id="software:other",
        asset_id="asset:app",
        version=version,
        attributes={"version_kind": kind},
    )
    twin = build(extras=(extra,))
    software = next(item for item in twin.software if item.subject_ids == ("software:other",))
    assert software.version_status == state
    assert software.attributes["reported_versions"] == (version,)


def test_subnet_is_not_trust_and_explicit_segmentation_and_route_are_supported():
    extra = host(
        "extra",
        10,
        value={
            "subnet": "192.0.1.0/24",
            "network_segment": "test-net",
            "trust_zone": "restricted",
            "gateway_asset_id": "asset:web",
        },
    )
    twin = build(extras=(extra,))
    assert len([zone for zone in twin.zones if zone.zone_type == ZoneType.TRUST_ZONE]) == 1
    subnet = next(zone for zone in twin.zones if zone.name == "192.0.1.0/24")
    assert subnet.zone_type == ZoneType.NETWORK_SEGMENT
    assert any(
        "explicit-gateway-asset-id-v1" in edge.provenance.rules for edge in twin.relationships
    )
    disabled = build(policy=ReconstructionPolicy(allow_subnet_zone_inference=False))
    assert not disabled.zones
    assert not any(
        edge.relation_type == TwinRelationType.LOCATED_IN for edge in disabled.relationships
    )


def test_unknown_enrichment_and_unknown_route_fail_closed():
    for value in ({"gateway_asset_id": "missing"}, {"subnet": "not-a-subnet"}):
        with pytest.raises(ModelError):
            build(extras=(host("extra", 10, value=value),))
    with pytest.raises(ModelError, match="knowledge"):
        build(extras=(host("extra", 10, attributes={"knowledge_ids": ["missing"]}),))


def test_inference_threshold_does_not_fabricate_edges():
    twin = build(policy=ReconstructionPolicy(relationship_inference_threshold=0.9))
    assert not any(edge.relation_type == TwinRelationType.LOCATED_IN for edge in twin.relationships)
    assert any(edge.relation_type == TwinRelationType.HOSTS for edge in twin.relationships)
