from dataclasses import replace

import pytest

from rlredteam.evidence.models import AssetIdentifier, EvidenceStatus, IdentifierType
from rlredteam.evidence.registry import EvidenceRegistry
from rlredteam.knowledge.validation import ModelError
from tests.knowledge_evidence_fixtures import TIME, asset, evidence_source, record
from tests.test_evidence_models import finding


def registry():
    return EvidenceRegistry(
        bundle_id="bundle:test", created_at=TIME, sources=(evidence_source(),), records=(asset(),)
    )


def test_conflicting_observations_remain_separate_and_queryable():
    value = registry()
    value.add(record("evidence:a", value={"os": "linux"}, status=EvidenceStatus.OBSERVED))
    value.add(record("evidence:b", value={"os": "windows"}, status=EvidenceStatus.INFERRED))
    assert len(value.for_subject("asset:opaque-1")) == 3
    assert len(value.by_status(EvidenceStatus.OBSERVED)) == 1
    assert len(value.by_source("source:test")) == 3
    assert value.get("evidence:a").value != value.get("evidence:b").value
    value.add(finding())
    assert value.findings_for_asset("asset:opaque-1") == (finding(),)
    assert value.relationships_for_asset("asset:opaque-1") == ()


def test_two_ips_can_describe_one_canonical_asset_without_automatic_resolution():
    value = registry()
    second = asset(
        "evidence:other-ip",
        identifiers=(AssetIdentifier(identifier_type=IdentifierType.IPV4, value="192.0.2.99"),),
    )
    value.add(second)
    records = value.for_subject("asset:opaque-1")
    assert len(records) == 2
    assert {item.asset_id for item in records} == {"asset:opaque-1"}
    assert len({item.identifiers[0].value for item in records}) == 2


def test_duplicate_rejection_is_atomic():
    value = registry()
    before = value.bundle
    with pytest.raises(ModelError, match="duplicate"):
        value.add(asset())
    assert value.bundle is before
    value.add(finding())
    with pytest.raises(ModelError, match="duplicate"):
        value.add(finding())


def test_dangling_sources_assets_and_evidence_are_rejected():
    value = registry()
    with pytest.raises(ModelError):
        value.add(finding(asset_id="asset:missing"))
    with pytest.raises(ModelError):
        value.add(finding(evidence_ids=("missing",)))
    provenance = replace(record().provenance, source_ids=("source:missing",))
    with pytest.raises(ModelError):
        value.add(record(source_id="source:missing", provenance=provenance))
    assert len(value.bundle.records) == 1 and not value.bundle.findings


def test_relationship_queries_and_missing_endpoints():
    from rlredteam.evidence.models import ObservedRelationship
    from rlredteam.knowledge.relations import RelationType

    value = registry()
    value.add(asset("evidence:asset2", subject_id="asset:two"))
    edge = record(
        "evidence:edge",
        ObservedRelationship,
        source_asset_id="asset:opaque-1",
        target_asset_id="asset:two",
        relation_type=RelationType.CONNECTS_TO,
    )
    value.add(edge)
    assert value.relationships_for_asset("asset:two") == (edge,)
    assert value.relationships_for_asset("asset:opaque-1") == (edge,)
    with pytest.raises(ModelError, match="endpoints"):
        value.add(replace(edge, evidence_id="evidence:bad", target_asset_id="asset:missing"))


def test_conflicting_service_owners_are_preserved_not_silently_resolved():
    from rlredteam.evidence.models import ObservedService

    value = registry()
    value.add(asset("evidence:asset2", subject_id="asset:two"))
    value.add(
        record(
            "evidence:s1", ObservedService, subject_id="service:shared", asset_id="asset:opaque-1"
        )
    )
    value.add(
        record("evidence:s2", ObservedService, subject_id="service:shared", asset_id="asset:two")
    )
    assert len(value.for_subject("service:shared")) == 2
    with pytest.raises(ModelError, match="ambiguous"):
        value.add(finding(service_id="service:shared"))
