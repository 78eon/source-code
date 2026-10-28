"""Synthetic local chain; no simulator construction, collection or database access."""

from dataclasses import replace

from rlredteam.digital_twin.builder import DigitalTwinBuilder
from rlredteam.evidence.models import (
    AssetIdentifier,
    IdentifierType,
    ObservedIdentity,
    ObservedRelationship,
    ObservedService,
    ObservedSoftware,
)
from rlredteam.evidence.registry import EvidenceRegistry
from rlredteam.knowledge.relations import RelationType
from tests.knowledge_evidence_fixtures import TIME, asset, evidence_source, record, registry
from tests.test_evidence_models import finding


def host(name, index, **kwargs):
    values = dict(
        subject_id="asset:" + name,
        confidence=0.9,
        identifiers=(
            AssetIdentifier(
                identifier_type=IdentifierType.MAC, value=f"02:00:00:00:00:{index:02x}"
            ),
            AssetIdentifier(identifier_type=IdentifierType.HOSTNAME, value=name + ".test"),
        ),
        value={
            "os": "linux",
            "entry_point": name == "web",
            "crown_jewel_candidate": name == "crown",
            "subnet": f"192.0.{index}.0/24",
        },
    )
    values.update(kwargs)
    return asset("evidence:" + name, **values)


def evidence(*, extras=(), with_components=True, with_finding=True):
    records = [host(name, index) for index, name in enumerate(("web", "app", "db", "crown"), 1)]
    records.append(replace(records[0], evidence_id="evidence:web-duplicate"))
    for index, (left, right) in enumerate((("web", "app"), ("app", "db"), ("db", "crown"))):
        records.append(
            record(
                f"evidence:edge-{index}",
                ObservedRelationship,
                subject_id=f"edge:{index}",
                source_asset_id="asset:" + left,
                target_asset_id="asset:" + right,
                relation_type=RelationType.CONNECTS_TO,
                confidence=0.9,
            )
        )
    if with_components:
        records.extend(
            (
                record(
                    "evidence:https",
                    ObservedService,
                    subject_id="service:https",
                    asset_id="asset:web",
                    port=443,
                    protocol="tcp",
                    confidence=0.9,
                    attributes={"knowledge_ids": ["product:a"]},
                ),
                record(
                    "evidence:software",
                    ObservedSoftware,
                    subject_id="software:web",
                    asset_id="asset:web",
                    product_id="product:a",
                    version="2.4.50",
                    confidence=0.9,
                    attributes={"version_kind": "exact", "service_id": "service:https"},
                ),
                record(
                    "evidence:identity",
                    ObservedIdentity,
                    subject_id="identity:app",
                    identity_type="service_account",
                    asset_id="asset:app",
                    confidence=0.9,
                ),
            )
        )
    records.extend(extras)
    findings = (
        (
            finding(
                asset_id="asset:web",
                evidence_ids=("evidence:web",),
                service_id="service:https",
                software_id="software:web",
            ),
        )
        if with_finding and with_components
        else ()
    )
    return EvidenceRegistry(
        bundle_id="bundle:twin-fixture",
        created_at=TIME,
        sources=(evidence_source(),),
        records=records,
        findings=findings,
    )


def build(*, policy=None, created_at=None, **kwargs):
    return DigitalTwinBuilder(registry(), evidence(**kwargs), policy).build(created_at=created_at)
