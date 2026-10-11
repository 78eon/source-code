from dataclasses import replace

import pytest

from rlredteam.evidence.models import (
    ApplicabilityStatus,
    AssetIdentifier,
    EvidenceBundle,
    EvidenceStatus,
    Finding,
    IdentifierType,
    IdentityStatus,
    ObservedIdentity,
    ObservedRelationship,
    ObservedService,
    ObservedSoftware,
)
from rlredteam.evidence.serialization import dumps, loads
from rlredteam.knowledge.relations import RelationType
from rlredteam.knowledge.validation import ModelError
from rlredteam.research_boundaries import ResearchBoundary
from tests.knowledge_evidence_fixtures import TIME, asset, evidence_source, record


@pytest.mark.parametrize("score", [-1, 1.1, True, "0.5", float("nan"), float("inf")])
def test_confidence_is_explicit_finite_and_bounded(score):
    with pytest.raises(ModelError):
        record(confidence=score)


@pytest.mark.parametrize("status", list(EvidenceStatus))
def test_status_is_preserved_not_inferred(status):
    value = record(status=status)
    assert loads(dumps(value)) == value
    assert loads(dumps(value)).status is status


def test_all_identifiers_and_identity_states_are_supported_without_ip_canonical_id():
    identifiers = tuple(
        AssetIdentifier(identifier_type=kind, value=value)
        for kind, value in (
            (IdentifierType.IPV4, "192.0.2.1"),
            (IdentifierType.IPV6, "2001:db8::1"),
            (IdentifierType.HOSTNAME, "Example.TEST."),
            (IdentifierType.MAC, "00-11-22-33-44-55"),
            (IdentifierType.CLOUD_RESOURCE, "cloud:resource:123"),
            (IdentifierType.USER_DEFINED, "lab-a"),
        )
    )
    value = asset(identifiers=identifiers)
    assert len(value.identifiers) == 6
    assert loads(dumps(value)) == value
    assert value.asset_id == "asset:opaque-1"
    for status in IdentityStatus:
        candidate = replace(
            value,
            identity_status=status,
            candidate_asset_ids=("asset:candidate",) if status == IdentityStatus.CANDIDATE else (),
        )
        assert loads(dumps(candidate)) == candidate
    with pytest.raises(ModelError, match="must not be an IP"):
        asset(subject_id="192.0.2.1")


@pytest.mark.parametrize(
    "kind,value",
    [
        (IdentifierType.IPV4, "999.1.2.3"),
        (IdentifierType.IPV6, "192.0.2.1"),
        (IdentifierType.MAC, "bad"),
        (IdentifierType.HOSTNAME, "bad name"),
    ],
)
def test_invalid_identifiers_fail(kind, value):
    with pytest.raises(ModelError):
        AssetIdentifier(identifier_type=kind, value=value)


def finding(**kwargs):
    values = dict(
        finding_id="finding:1",
        asset_id="asset:opaque-1",
        status=EvidenceStatus.INFERRED,
        confidence=0.4,
        applicability_status=ApplicabilityStatus.POSSIBLE,
        evidence_ids=("evidence:asset",),
        first_observed_at=TIME,
        last_observed_at=TIME,
        provenance=record().provenance,
        vulnerability_id="CVE-2021-42013",
        cvss_base=9.8,
    )
    values.update(kwargs)
    return Finding(**values)


@pytest.mark.parametrize("applicability", list(ApplicabilityStatus))
def test_findings_preserve_explicit_applicability(applicability):
    value = finding(applicability_status=applicability)
    assert loads(dumps(value)) == value
    assert finding().applicability_status is ApplicabilityStatus.POSSIBLE


@pytest.mark.parametrize(
    "kwargs",
    [
        {"applicability_status": "CONFIRMED"},
        {"confidence": -1},
        {"cvss_base": 11},
        {"cvss_base": True},
        {"evidence_ids": ()},
        {"severity": "bad"},
        {"last_observed_at": "2025-01-01T00:00:00Z"},
    ],
)
def test_invalid_findings_fail(kwargs):
    with pytest.raises(ModelError):
        finding(**kwargs)


def test_specialized_records_and_bundle_round_trip():
    records = (
        asset(),
        record("evidence:identity", ObservedIdentity, identity_type="service_account"),
        record(
            "evidence:service",
            ObservedService,
            subject_id="service:1",
            asset_id="asset:opaque-1",
            port=443,
            protocol="tcp",
        ),
        record(
            "evidence:software",
            ObservedSoftware,
            subject_id="software:1",
            asset_id="asset:opaque-1",
            product_id="product:a",
            version="2.4.50",
        ),
        record(
            "evidence:relationship",
            ObservedRelationship,
            source_asset_id="asset:opaque-1",
            target_asset_id="asset:opaque-1",
            relation_type=RelationType.USES,
        ),
    )
    bundle = EvidenceBundle(
        bundle_id="bundle:test",
        created_at=TIME,
        sources=(evidence_source(),),
        records=records,
        findings=(finding(service_id="service:1"),),
    )
    assert loads(dumps(bundle)) == bundle
    assert dumps(replace(bundle, records=tuple(reversed(records)))) == dumps(bundle)
    for item in records:
        assert loads(dumps(item)) == item


def test_live_lab_or_registered_study_ingestion_is_disabled():
    for boundary in (ResearchBoundary.LIVE_LAB_EXTENSION, ResearchBoundary.GENERALISATION_RESEARCH):
        with pytest.raises(ModelError):
            replace(evidence_source(), boundary=boundary)
        with pytest.raises(ModelError):
            EvidenceBundle(
                bundle_id="bundle:test", created_at=TIME, sources=(), records=(), boundary=boundary
            )


def test_record_value_is_deeply_immutable():
    original = {"list": [1, 2]}
    value = record(value=original)
    original["list"].append(3)
    assert value.value["list"] == (1, 2)
    with pytest.raises(TypeError):
        value.value["mutate"] = 1
