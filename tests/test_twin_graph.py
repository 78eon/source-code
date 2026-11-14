"""Generated inventory graph contracts over real persisted Twin snapshots."""

from dataclasses import replace
from uuid import uuid4

import pytest

from rlredteam.digital_twin.graph import dumps, loads, project_snapshot
from rlredteam.digital_twin.projection import TwinStateSnapshot
from rlredteam.evidence.models import ObservedService, ObservedSoftware
from rlredteam.knowledge.serialization import digest
from rlredteam.knowledge.validation import ModelError
from tests import test_persistent_twin as fixtures

db = fixtures.db
prepared = fixtures.prepared


@pytest.fixture
def snapshot(prepared):
    return fixtures.project(prepared)


def test_projection_is_deterministic_and_roundtrippable(prepared, snapshot):
    store = prepared[0]
    first = project_snapshot(store.load(snapshot.snapshot_id))
    second = project_snapshot(store.load(snapshot.snapshot_id))
    assert first == second
    assert dumps(first) == dumps(second)
    assert loads(dumps(first)) == first
    assert first.graph_id == digest(first.payload())


def test_node_and_relationship_types_are_inventory_only(snapshot):
    graph = project_snapshot(snapshot)
    assert {n.node_type for n in graph.nodes} == {"asset", "service", "software", "identity"}
    assert {e.relationship_type for e in graph.edges} == {"HOSTS", "ASSOCIATED_WITH", "DEPENDS_ON"}
    assert all(e.rule for e in graph.edges)
    assert len({n.node_id for n in graph.nodes}) == len(graph.nodes)


def test_persistent_asset_identity_survives_snapshot_change(prepared, snapshot):
    store, bundles, decision, _ = prepared
    newer = store.refresh(
        snapshot.projection_key, [b.bundle_id for b in bundles], as_of=fixtures.now()
    )
    for value in (snapshot, newer):
        assert [n.node_id for n in project_snapshot(value).nodes if n.node_type == "asset"] == [
            decision["entity_id"]
        ]


def test_edges_and_nodes_retain_evidence_and_snapshot_provenance(snapshot):
    graph = project_snapshot(snapshot)
    ids = {e["support_id"] for e in graph.evidence}
    assert graph.snapshot_id == snapshot.snapshot_id
    assert graph.decision_ids == snapshot.decision_ids
    assert all(
        set(item.evidence_ids) <= ids and item.evidence_ids for item in (*graph.nodes, *graph.edges)
    )
    assert all(e["bundle_id"] in snapshot.bundle_digests for e in graph.evidence)
    assert graph.conflicts_json
    assert any(n.metadata["conflict_ids"] for n in graph.nodes)


def test_multiple_services_and_software_are_not_merged_by_product(prepared):
    store, bundles, decision, _ = prepared
    previous = bundles[-1]
    service = next(r for r in previous.records if isinstance(r, ObservedService))
    software = next(r for r in previous.records if isinstance(r, ObservedSoftware))
    # A second endpoint on the same reconciled asset, with the same product.
    other_port = service.port % 65535 + 1
    extra_service = replace(
        service,
        evidence_id="evidence:" + uuid4().hex,
        subject_id="subject:" + uuid4().hex,
        port=other_port,
    )
    extra_software = replace(
        software,
        evidence_id="evidence:" + uuid4().hex,
        subject_id="subject:" + uuid4().hex,
        attributes={**software.attributes, "service_id": extra_service.subject_id},
    )
    bundle = replace(
        previous,
        bundle_id="bundle:" + uuid4().hex,
        records=(*previous.records, extra_service, extra_software),
    )
    store.entities.evidence.save(bundle)
    store.entities.reconcile(
        (fixtures.asset_ref(bundle),), entity_id=decision["entity_id"], created_at=fixtures.now()
    )
    snapshot = store.refresh("projection:" + uuid4().hex, (bundle.bundle_id,), as_of=fixtures.now())
    graph = project_snapshot(snapshot)
    assert len([n for n in graph.nodes if n.node_type == "service"]) == 2
    assert len([n for n in graph.nodes if n.node_type == "software"]) == 2
    assert len([e for e in graph.edges if e.rule == "explicit-service-software-link-v1"]) == 2


def test_unresolved_evidence_does_not_create_graph_assets(prepared):
    from tests.test_entity_reconciliation import make_bundle

    store = prepared[0]
    bundle = make_bundle()
    store.entities.evidence.save(bundle)
    snapshot = store.refresh("projection:" + uuid4().hex, (bundle.bundle_id,), as_of=fixtures.now())
    graph = project_snapshot(snapshot)
    assert graph.nodes == graph.edges == ()
    assert graph.unprojected == snapshot.unprojected


def test_software_owner_link_must_be_valid(snapshot):
    broken = replace(snapshot.software[0], attributes={"service_id": "service:" + uuid4().hex})
    payload = {**snapshot.payload(), "software": (broken,)}
    changed = TwinStateSnapshot(snapshot_id=digest(payload), **payload)
    with pytest.raises(ModelError, match="absent or differently owned"):
        project_snapshot(changed)


def test_unsupported_input_is_rejected():
    with pytest.raises(ModelError, match="TwinStateSnapshot"):
        project_snapshot({})
