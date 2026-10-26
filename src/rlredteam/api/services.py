"""Read projections only. No topology generation, file evidence crawling or writes."""

import os

import psycopg

from rlredteam.application.analyst_readers import SnapshotReader, simulation_replays
from rlredteam.application.data.repository import Repository
from rlredteam.storage.neo4j_projection import Neo4jProjectionStore, Neo4jSettings

from .models import GraphDTO, GraphEdge, GraphNode

# Only properties emitted by the existing projection schema can reach the UI.
NODE_FIELDS = frozenset(
    """node_id node_type first_discovery_step discovered_by discovered_services_json
    discovered_vulnerabilities current_access_level credentials mitre_techniques
    incoming_relationships outgoing_relationships evidence_ids graph_id""".split()
)
EDGE_FIELDS = frozenset(
    """edge_id graph_id source_node target_node relationship_type simulator_action
    discovery_method service port protocol product version vulnerability_id cve_id
    credential_id identity access_before access_after success episode_id step evidence_steps
    evidence_ids new_information explanation categories mitre_technique_ids mitre_tactic_ids
    mitre_mappings_json""".split()
)
PROJECTION_FIELDS = frozenset(
    """graph_id report_id source_graph_sha256 projection_hash schema_version hidden_topology_used
    node_count edge_count evidence_count technique_count""".split()
)


def presentation_properties(row, allowed):
    return {key: value for key, value in row.items() if key in allowed}


def selected_report_ids():
    return {
        value.strip()
        for value in os.environ.get("SECURITY_RL_ANALYST_REPORT_IDS", "").split(",")
        if value.strip()
    }


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
    def __init__(self, repository=None, snapshot_reader=None):
        self.repository = repository or ReadOnlyRepository()
        self.snapshot_reader = snapshot_reader or SnapshotReader()

    def twin_summary(self):
        return self.snapshot_reader.summary()

    def twin_entities(self):
        return self.snapshot_reader.entities()

    def simulations(self):
        allowed = selected_report_ids()
        if not allowed:
            return {
                "status": "UNAVAILABLE",
                "detail": "No analyst simulation reports selected",
                "items": [],
            }
        items = simulation_replays(self.reports(), allowed)
        paths = self.paths()
        for item in items:
            item["paths"] = [
                {
                    **p,
                    "edges": [
                        e for e in p.get("edges", []) if e.get("episode_id") == item["episode_id"]
                    ],
                }
                for p in paths
                if p.get("report_id") == item["report_id"]
            ]
            item["path_available"] = any(p["edges"] for p in item["paths"])
        return {"status": "AVAILABLE", "items": items}

    def reports(self):
        allowed = selected_report_ids()
        if not allowed:
            return []
        return self.repository.attack_path_reports(limit=50, report_ids=allowed)

    def paths(self):
        # Stored, evidence-backed graphs, not newly computed omniscient paths.
        allowed = selected_report_ids()
        if not allowed:
            return []
        graphs = self.repository.causal_attack_graphs(limit=50, report_ids=allowed)
        return [
            {
                **g,
                "edges": sorted(
                    g.get("edges", []), key=lambda e: (e["episode_id"], e["step"], e["edge_id"])
                ),
            }
            for g in graphs
        ]

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

    def graph(self, graph_id=None, node_type=None, relationship_type=None, search=None, limit=2000):
        if not os.environ.get("NEO4J_URI"):
            raise RuntimeError("Neo4j not configured")
        allowed = sorted(selected_report_ids())
        if not allowed:
            return GraphDTO(metadata={"detail": "No analyst reports selected"})
        store = Neo4jProjectionStore.connect(Neo4jSettings.from_env(), wait_seconds=0)
        try:
            with store.driver.session(database=store.database, default_access_mode="READ") as s:

                def read(tx):
                    nonlocal graph_id
                    if graph_id is None:
                        row = tx.run(
                            "MATCH (g:CausalProjection) WHERE g.report_id IN $reports "
                            "RETURN g.graph_id AS id ORDER BY id LIMIT 1",
                            reports=allowed,
                        ).single()
                        if row is None:
                            return GraphDTO()
                        graph_id = row["id"]
                    projection = tx.run(
                        "MATCH (g:CausalProjection {graph_id:$id}) "
                        "WHERE g.report_id IN $reports RETURN g",
                        id=graph_id,
                        reports=allowed,
                    ).single()
                    if projection is None:
                        return GraphDTO(graph_id=graph_id)
                    projection = dict(projection["g"])
                    if (
                        projection.get("hidden_topology_used") is not False
                        or projection.get("schema_version") != "security-rl-neo4j-projection-v1"
                    ):
                        raise ValueError("Unverified projection provenance")
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
                    evidence = {
                        r["id"]
                        for r in tx.run(
                            "MATCH (e:CausalEvidence {graph_id:$id}) RETURN e.evidence_id AS id",
                            id=graph_id,
                        )
                    }
                    if any(
                        not e.get("evidence_ids")
                        or not set(e["evidence_ids"]) <= evidence
                        or e["source_node"] not in ids
                        or e["target_node"] not in ids
                        for e in edges
                    ):
                        raise ValueError("Projection contains unsupported relationships")
                    total_nodes, total_edges = len(nodes), len(edges)
                    nodes = [
                        n
                        for n in nodes
                        if (not node_type or n["node_type"] == node_type)
                        and (not search or search.casefold() in n["node_id"].casefold())
                    ][:limit]
                    ids = {n["node_id"] for n in nodes}
                    edges = [
                        e
                        for e in edges
                        if e["source_node"] in ids
                        and e["target_node"] in ids
                        and (not relationship_type or e["relationship_type"] == relationship_type)
                    ]
                    return GraphDTO(
                        graph_id=graph_id,
                        metadata={
                            "projection": presentation_properties(projection, PROJECTION_FIELDS),
                            "total_nodes": total_nodes,
                            "total_edges": total_edges,
                            "displayed_nodes": len(nodes),
                            "displayed_edges": len(edges),
                        },
                        nodes=[
                            GraphNode(
                                id=n["node_id"],
                                type=n["node_type"],
                                label=n["node_id"],
                                metadata=presentation_properties(n, NODE_FIELDS),
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
                                metadata=presentation_properties(e, EDGE_FIELDS),
                                evidence_refs=e["evidence_ids"],
                            )
                            for e in edges
                        ],
                    )

                return s.execute_read(read)
        finally:
            store.close()
