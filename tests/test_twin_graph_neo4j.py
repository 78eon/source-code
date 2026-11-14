"""Real disposable Neo4j inventory rebuilds; no research-service access."""

import os
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest

from rlredteam.digital_twin.graph import project_snapshot
from rlredteam.digital_twin.projection import dumps as snapshot_dumps
from rlredteam.evidence.serialization import dumps as evidence_dumps
from rlredteam.knowledge.validation import ModelError
from rlredteam.storage.neo4j_projection import Neo4jSettings
from rlredteam.storage.twin_graph_store import TwinInventoryGraphStore
from tests import test_persistent_twin as fixtures

db = fixtures.db
prepared = fixtures.prepared


@pytest.fixture
def neo():
    if os.environ.get("RLRT_TWIN_GRAPH_TEST_ONLY") != "1":
        pytest.skip("requires explicitly isolated disposable Neo4j")
    store = TwinInventoryGraphStore.connect(Neo4jSettings.from_env(), wait_seconds=0)
    with store.driver.session(database=store.database) as session:
        before = {
            r["id"] for r in session.run("MATCH(g:TwinInventoryProjection) RETURN g.graph_id AS id")
        }
    try:
        yield store
    finally:
        with store.driver.session(database=store.database) as session:
            ids = [
                r["id"]
                for r in session.run("MATCH(g:TwinInventoryProjection) RETURN g.graph_id AS id")
            ]
        for graph_id in set(ids) - before:
            store.delete(graph_id)
        store.close()


def test_real_rebuild_is_idempotent_and_loadable(prepared, neo):
    twin_store = prepared[0]
    snapshot = fixtures.project(prepared)
    graph = neo.rebuild_from_snapshot(twin_store, snapshot.snapshot_id)
    assert neo.load(graph.graph_id) == graph
    neo.rebuild_from_snapshot(twin_store, snapshot.snapshot_id)
    assert neo.load(graph.graph_id) == graph


def test_delete_then_rebuild_preserves_all_canonical_inputs(prepared, neo):
    twin_store, bundles, _, _ = prepared
    snapshot = fixtures.project(prepared)
    evidence_before = [
        evidence_dumps(twin_store.entities.evidence.load(b.bundle_id)) for b in bundles
    ]
    twin_before = snapshot_dumps(twin_store.load(snapshot.snapshot_id))
    graph = neo.rebuild_from_snapshot(twin_store, snapshot.snapshot_id)
    neo.delete(graph.graph_id)
    with pytest.raises(KeyError):
        neo.load(graph.graph_id)
    rebuilt = neo.rebuild_from_snapshot(twin_store, snapshot.snapshot_id)
    assert rebuilt == graph
    assert snapshot_dumps(twin_store.load(snapshot.snapshot_id)) == twin_before
    assert [
        evidence_dumps(twin_store.entities.evidence.load(b.bundle_id)) for b in bundles
    ] == evidence_before


def test_inventory_delete_cannot_delete_research_namespace(prepared, neo):
    graph = project_snapshot(fixtures.project(prepared))
    marker = uuid4().hex
    with neo.driver.session(database=neo.database) as session:
        session.run(
            "CREATE(n:CausalNode {graph_id:$id,marker:$marker})", id=graph.graph_id, marker=marker
        ).consume()
    try:
        neo.rebuild(graph)
        neo.delete(graph.graph_id)
        with neo.driver.session(database=neo.database) as session:
            assert (
                session.run(
                    "MATCH(n:CausalNode {marker:$marker}) RETURN count(n) AS count", marker=marker
                ).single()["count"]
                == 1
            )
    finally:
        with neo.driver.session(database=neo.database) as session:
            session.run("MATCH(n:CausalNode {marker:$marker}) DELETE n", marker=marker).consume()


def test_snapshot_scoped_nodes_keep_stable_logical_asset_id(prepared, neo):
    twin_store, bundles, _, _ = prepared
    first = fixtures.project(prepared)
    second = twin_store.refresh(
        first.projection_key, [b.bundle_id for b in bundles], as_of=fixtures.now()
    )
    old = neo.rebuild_from_snapshot(twin_store, first.snapshot_id)
    new = neo.rebuild_from_snapshot(twin_store, second.snapshot_id)
    assert old.graph_id != new.graph_id
    assert [n.node_id for n in old.nodes if n.node_type == "asset"] == [
        n.node_id for n in new.nodes if n.node_type == "asset"
    ]
    neo.delete(old.graph_id)
    assert neo.load(new.graph_id) == new


def test_property_tampering_is_detected_and_rebuild_repairs_derived_state(prepared, neo):
    twin_store = prepared[0]
    snapshot = fixtures.project(prepared)
    graph = neo.rebuild_from_snapshot(twin_store, snapshot.snapshot_id)
    with neo.driver.session(database=neo.database) as session:
        session.run(
            "MATCH(n:TwinInventoryNode {graph_id:$id}) SET n.node_type=$value",
            id=graph.graph_id,
            value=uuid4().hex,
        ).consume()
    with pytest.raises(ModelError, match="projection mismatch"):
        neo.load(graph.graph_id)
    neo.rebuild_from_snapshot(twin_store, snapshot.snapshot_id)
    assert neo.load(graph.graph_id) == graph


def test_concurrent_rebuilds_do_not_duplicate_nodes_or_edges(prepared, neo):
    graph = project_snapshot(fixtures.project(prepared))
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(neo.rebuild, (graph, graph)))
    assert neo.load(graph.graph_id) == graph


def test_foreign_relationships_are_not_detached_by_inventory_deletion(prepared, neo):
    graph = project_snapshot(fixtures.project(prepared))
    neo.rebuild(graph)
    marker = uuid4().hex
    with neo.driver.session(database=neo.database) as session:
        session.run(
            """MATCH(a:TwinInventoryNode {graph_id:$id,node_id:$node})
            CREATE (n:CausalNode {marker:$marker}) CREATE(a)-[:INVENTORY_TEST_FOREIGN]->(n)""",
            id=graph.graph_id,
            node=graph.nodes[0].node_id,
            marker=marker,
        ).consume()
    try:
        with pytest.raises(ModelError, match="foreign relationships"):
            neo.delete(graph.graph_id)
        assert neo.load(graph.graph_id) == graph
    finally:
        with neo.driver.session(database=neo.database) as session:
            session.run(
                """MATCH (:TwinInventoryNode {graph_id:$id})
                -[r:INVENTORY_TEST_FOREIGN]->(n:CausalNode {marker:$marker}) DELETE r,n""",
                id=graph.graph_id,
                marker=marker,
            ).consume()
