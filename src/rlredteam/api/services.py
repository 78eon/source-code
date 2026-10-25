"""Read projections only. No topology generation, file evidence crawling or writes."""

import os

import psycopg

from rlredteam.application.data.repository import Repository
from rlredteam.storage.neo4j_projection import Neo4jProjectionStore, Neo4jSettings

from .models import GraphDTO, GraphEdge, GraphNode


class ReadOnlyRepository(Repository):
    def _connect(self):
        if not self.settings.complete:
            raise RuntimeError("PostgreSQL not configured")
        return psycopg.connect(
            host=self.settings.host,
            port=self.settings.port,
            user=self.settings.user,
            password=self.settings.password,
            dbname=self.settings.dbname,
            connect_timeout=4,
            options="-c default_transaction_read_only=on -c statement_timeout=5000",
        )


class AnalystService:
    def __init__(self, repository=None):
        self.repository = repository or ReadOnlyRepository()

    def reports(self):
        return self.repository.attack_path_reports(limit=50)

    def paths(self):
        # Stored, evidence-backed graphs, not newly computed omniscient paths.
        return self.repository.causal_attack_graphs(limit=50)

    def assets(self):
        values = []
        for graph in self.paths():
            for node in graph.get("nodes", []):
                values.append(
                    {
                        **node,
                        "id": graph["graph_id"] + ":" + node["node_id"],
                        "graph_id": graph["graph_id"],
                    }
                )
        return values

    def findings(self):
        # Preserve recorded vulnerability identifiers; do not assert applicability.
        return [
            {
                "id": a["id"] + ":" + str(v),
                "asset_id": a["id"],
                "vulnerability_id": v,
                "applicability": "UNKNOWN",
                "cvss": None,
                "evidence_refs": a.get("evidence_ids", []),
            }
            for a in self.assets()
            for v in a.get("discovered_vulnerabilities", [])
        ]

    def graph(self, graph_id=None):
        if not os.environ.get("NEO4J_URI"):
            raise RuntimeError("Neo4j not configured")
        store = Neo4jProjectionStore.connect(Neo4jSettings.from_env(), wait_seconds=0)
        try:
            with store.driver.session(database=store.database, default_access_mode="READ") as s:

                def read(tx):
                    nonlocal graph_id
                    if graph_id is None:
                        row = tx.run(
                            "MATCH (g:CausalProjection) RETURN g.graph_id AS id ORDER BY id LIMIT 1"
                        ).single()
                        if row is None:
                            return GraphDTO()
                        graph_id = row["id"]
                    nodes = [
                        dict(r["n"])
                        for r in tx.run(
                            "MATCH (n:CausalNode {graph_id:$id}) "
                            "RETURN n ORDER BY n.node_id LIMIT 2001",
                            id=graph_id,
                        )
                    ]
                    edges = [
                        dict(r["e"])
                        for r in tx.run(
                            "MATCH (e:CausalEdgeFact {graph_id:$id}) "
                            "RETURN e ORDER BY e.edge_id LIMIT 5001",
                            id=graph_id,
                        )
                    ]
                    if len(nodes) > 2000 or len(edges) > 5000:
                        raise ValueError("Projection exceeds display limit")
                    ids = {n["node_id"] for n in nodes}
                    if any(
                        not e.get("evidence_ids")
                        or e["source_node"] not in ids
                        or e["target_node"] not in ids
                        for e in edges
                    ):
                        raise ValueError("Projection contains unsupported relationships")
                    return GraphDTO(
                        graph_id=graph_id,
                        nodes=[
                            GraphNode(
                                id=n["node_id"],
                                type=n["node_type"],
                                label=n["node_id"],
                                metadata=n,
                                provenance=n.get("evidence_ids", []),
                            )
                            for n in nodes
                        ],
                        edges=[
                            GraphEdge(
                                id=e["edge_id"],
                                source=e["source_node"],
                                target=e["target_node"],
                                type=e["relationship_type"],
                                metadata=e,
                                evidence_refs=e["evidence_ids"],
                            )
                            for e in edges
                        ],
                    )

                return s.execute_read(read)
        finally:
            store.close()
