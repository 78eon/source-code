"""Disposable Neo4j inventory namespace, isolated from Causal* research graphs."""

from rlredteam.digital_twin.graph import dumps, loads, project_snapshot
from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import canonical_json, digest, encode

from .neo4j_projection import Neo4jProjectionStore

CONSTRAINTS = (
    "CREATE CONSTRAINT twin_inventory_graph_id IF NOT EXISTS "
    "FOR (g:TwinInventoryProjection) REQUIRE g.graph_id IS UNIQUE",
    "CREATE CONSTRAINT twin_inventory_node_key IF NOT EXISTS "
    "FOR (n:TwinInventoryNode) REQUIRE n.projection_key IS UNIQUE",
)


def _rows(graph):
    # Neo4j properties use primitive strings/lists; full tagged metadata stays JSON.
    nodes = [
        {
            "projection_key": digest((graph.graph_id, n.node_id)),
            "node_id": n.node_id,
            "graph_id": graph.graph_id,
            "node_type": n.node_type,
            "snapshot_id": graph.snapshot_id,
            "decision_ids": list(graph.decision_ids),
            "evidence_json": canonical_json(
                encode(tuple(e for e in graph.evidence if e["support_id"] in n.evidence_ids))
            ),
            "metadata_json": canonical_json(encode(n.metadata)),
        }
        for n in graph.nodes
    ]
    edges = [
        {
            "edge_id": e.edge_id,
            "graph_id": graph.graph_id,
            "source": e.source,
            "target": e.target,
            "relationship_type": e.relationship_type,
            "snapshot_id": graph.snapshot_id,
            "rule": e.rule,
            "decision_ids": list(graph.decision_ids),
            "evidence_json": canonical_json(
                encode(tuple(ref for ref in graph.evidence if ref["support_id"] in e.evidence_ids))
            ),
        }
        for e in graph.edges
    ]
    return nodes, edges


def _delete(tx, graph_id):
    # Labels and relationship type are fixed; input never becomes Cypher syntax.
    # Refuse cross-namespace connections rather than DETACH-delete unrelated links.
    foreign = tx.run(
        """MATCH (n:TwinInventoryNode {graph_id:$id})-[r]-(other)
        WHERE type(r)<>'TWIN_INVENTORY_LINK'
           OR NOT other:TwinInventoryNode OR other.graph_id<>$id
        RETURN count(r) AS count""",
        id=graph_id,
    ).single()["count"]
    if foreign:
        raise v.ModelError("inventory graph has foreign relationships; refusing deletion")
    tx.run(
        """MATCH (:TwinInventoryNode {graph_id:$id})-[r:TWIN_INVENTORY_LINK]-()
        DELETE r""",
        id=graph_id,
    ).consume()
    tx.run("MATCH (n:TwinInventoryNode {graph_id:$id}) DELETE n", id=graph_id).consume()
    tx.run("MATCH (g:TwinInventoryProjection {graph_id:$id}) DELETE g", id=graph_id).consume()


class TwinInventoryGraphStore:
    def __init__(self, driver, database):
        self.driver, self.database = driver, database

    @classmethod
    def connect(cls, settings=None, *, wait_seconds=0):
        existing = Neo4jProjectionStore.connect(settings, wait_seconds=wait_seconds)
        return cls(existing.driver, existing.database)

    def close(self):
        self.driver.close()

    def rebuild_from_snapshot(self, twin_store, snapshot_id):
        graph = project_snapshot(twin_store.load(snapshot_id))
        self.rebuild(graph)
        return graph

    def rebuild(self, graph):
        graph = loads(dumps(graph))
        nodes, edges = _rows(graph)
        with self.driver.session(database=self.database) as session:
            for constraint in CONSTRAINTS:
                session.run(constraint).consume()

            def replace(tx):
                # Serialize concurrent rebuilds of this graph by locking its root.
                tx.run(
                    """MERGE (g:TwinInventoryProjection {graph_id:$id})
                    SET g.lock_version=coalesce(g.lock_version,0)+1""",
                    id=graph.graph_id,
                ).consume()
                _delete(tx, graph.graph_id)
                tx.run(
                    """CREATE (g:TwinInventoryProjection {graph_id:$id,
                    snapshot_id:$snapshot, document:$document, schema_version:$schema})""",
                    id=graph.graph_id,
                    snapshot=graph.snapshot_id,
                    document=dumps(graph),
                    schema=graph.schema_version,
                ).consume()
                tx.run(
                    "UNWIND $rows AS row CREATE (n:TwinInventoryNode) SET n=row", rows=nodes
                ).consume()
                tx.run(
                    """UNWIND $rows AS row
                    MATCH (a:TwinInventoryNode {graph_id:$id,node_id:row.source})
                    MATCH (b:TwinInventoryNode {graph_id:$id,node_id:row.target})
                    CREATE (a)-[r:TWIN_INVENTORY_LINK]->(b) SET r=row""",
                    rows=edges,
                    id=graph.graph_id,
                ).consume()

            session.execute_write(replace)
        if self.load(graph.graph_id) != graph:
            raise v.ModelError("inventory rebuild verification failed")

    def delete(self, graph_id):
        v.digest_string(graph_id)
        with self.driver.session(database=self.database) as session:

            def remove(tx):
                tx.run(
                    """MATCH(g:TwinInventoryProjection {graph_id:$id})
                    SET g.lock_version=coalesce(g.lock_version,0)+1""",
                    id=graph_id,
                ).consume()
                _delete(tx, graph_id)

            session.execute_write(remove)

    def load(self, graph_id):
        v.digest_string(graph_id)
        with self.driver.session(database=self.database, default_access_mode="READ") as session:

            def read(tx):
                row = tx.run(
                    "MATCH (g:TwinInventoryProjection {graph_id:$id}) RETURN g", id=graph_id
                ).single()
                if row is None:
                    raise KeyError(graph_id)
                root = dict(row["g"])
                graph = loads(root["document"])
                if (
                    graph.graph_id != graph_id
                    or root["snapshot_id"] != graph.snapshot_id
                    or root["schema_version"] != graph.schema_version
                ):
                    raise v.ModelError("inventory graph header mismatch")
                nodes = [
                    dict(row["n"])
                    for row in tx.run(
                        "MATCH(n:TwinInventoryNode {graph_id:$id}) RETURN n ORDER BY n.node_id",
                        id=graph_id,
                    )
                ]
                edges = []
                for row in tx.run(
                    "MATCH (a:TwinInventoryNode {graph_id:$id})-[r:TWIN_INVENTORY_LINK]->(b) "
                    "RETURN r,a.node_id AS source,b.node_id AS target,b.graph_id AS target_graph,"
                    "labels(b) AS target_labels ORDER BY r.edge_id",
                    id=graph_id,
                ):
                    edge = dict(row["r"])
                    if (
                        edge["source"] != row["source"]
                        or edge["target"] != row["target"]
                        or row["target_graph"] != graph_id
                        or "TwinInventoryNode" not in row["target_labels"]
                    ):
                        raise v.ModelError("inventory edge endpoint mismatch")
                    edges.append(edge)
                expected_nodes, expected_edges = _rows(graph)
                if nodes != expected_nodes or edges != expected_edges:
                    raise v.ModelError("inventory graph projection mismatch")
                return graph

            return session.execute_read(read)
