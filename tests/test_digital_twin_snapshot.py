from dataclasses import replace

import pytest

from rlredteam.digital_twin.builder import DigitalTwinBuilder
from rlredteam.digital_twin.serialization import dumps
from rlredteam.digital_twin.snapshot import freeze
from rlredteam.evidence.registry import EvidenceRegistry
from rlredteam.knowledge.validation import ModelError
from tests.digital_twin_fixtures import build, evidence
from tests.knowledge_evidence_fixtures import registry
from tests.test_knowledge_importers import protected_hashes


def test_created_at_does_not_change_logical_hash():
    first = build(created_at="2026-10-09T00:00:00Z")
    second = build(created_at="2026-10-10T00:00:00Z")
    assert first.snapshot.twin_digest == second.snapshot.twin_digest
    assert first.snapshot.created_at != second.snapshot.created_at
    assert first.snapshot.policy_digest == second.snapshot.policy_digest
    assert first.snapshot.evidence_bundle_digest == second.snapshot.evidence_bundle_digest


def test_order_independent_reconstruction_and_hash():
    source = evidence().bundle
    reverse = EvidenceRegistry(
        bundle_id=source.bundle_id,
        created_at=source.created_at,
        sources=reversed(source.sources),
        records=reversed(source.records),
        findings=reversed(source.findings),
    )
    assert dumps(DigitalTwinBuilder(registry(), reverse).build()) == dumps(build())


def test_bundle_and_knowledge_snapshot_creation_time_is_not_logical_content():
    source = evidence().bundle
    later = EvidenceRegistry(
        bundle_id=source.bundle_id,
        created_at="2026-10-10T00:00:00Z",
        sources=source.sources,
        records=source.records,
        findings=source.findings,
    )
    first = build()
    second = DigitalTwinBuilder(registry(), later).build()
    assert first.snapshot.twin_digest == second.snapshot.twin_digest
    assert first.snapshot.evidence_bundle_digest == second.snapshot.evidence_bundle_digest
    # Phase 2 provenance is not rewritten to make a logical-hash comparison.
    assert first.snapshot.knowledge_snapshot_digest != second.snapshot.knowledge_snapshot_digest


@pytest.mark.parametrize(
    "field,value",
    [
        ("twin_digest", "0" * 64),
        ("policy_digest", "0" * 64),
        ("evidence_bundle_digest", "0" * 64),
        ("asset_count", 100),
        ("schema_version", "bad"),
    ],
)
def test_snapshot_tampering_rejected(field, value):
    twin = build()
    with pytest.raises(ModelError):
        replace(twin, snapshot=replace(twin.snapshot, **{field: value}))


def test_logical_content_change_changes_digest():
    twin = build()
    changed = freeze(replace(twin, snapshot=None, attributes={"review_note": "changed"}))
    assert changed.snapshot.twin_digest != twin.snapshot.twin_digest


def test_asset_creation_update_timestamps_do_not_change_logical_digest():
    twin = build()
    changed = freeze(
        replace(
            twin,
            snapshot=None,
            assets=tuple(
                replace(asset, created_at="2026-10-09T00:00:00Z", updated_at="2026-10-10T00:00:00Z")
                for asset in twin.assets
            ),
        )
    )
    assert changed.snapshot.twin_digest == twin.snapshot.twin_digest


def test_mismatched_supplied_knowledge_snapshot_rejected():
    from rlredteam.knowledge.registry import KnowledgeRegistry
    from rlredteam.knowledge.snapshot import KnowledgeSnapshot
    from tests.knowledge_evidence_fixtures import TIME

    empty = KnowledgeSnapshot.create(KnowledgeRegistry(), created_at=TIME)
    with pytest.raises(ModelError, match="does not match registry"):
        DigitalTwinBuilder(registry(), evidence()).build(knowledge_snapshot=empty)


def test_build_does_not_write_frozen_catalogues_or_use_network(monkeypatch):
    import socket

    before = protected_hashes()

    def forbidden(*args, **kwargs):
        raise AssertionError("network forbidden")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    build()
    assert protected_hashes() == before
