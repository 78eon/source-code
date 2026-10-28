"""Opt-in disposable desktop databases, never campaign services.

Run with SECURITY_RL_DESKTOP_INTEGRATION=1 in a network-disabled Podman
namespace containing only fresh desktop_fixture PostgreSQL and Neo4j instances.
"""

import os

import psycopg
import pytest
from fastapi.testclient import TestClient

from rlredteam.api.app import create_app
from rlredteam.api.services import AnalystService, ReadOnlyRepository
from rlredteam.application.analyst_readers import SnapshotReader
from rlredteam.attack_path_report import build_report
from rlredteam.causal_graph import build_causal_graph
from rlredteam.digital_twin.serialization import dumps
from rlredteam.storage.causal_store import CausalGraphStore
from rlredteam.storage.neo4j_projection import Neo4jProjectionStore, build_projection_plan
from rlredteam.storage.report_store import ReportStore
from tests.digital_twin_fixtures import build
from tests.test_causal_graph import causal_document

pytestmark = pytest.mark.skipif(
    os.environ.get("SECURITY_RL_DESKTOP_INTEGRATION") != "1",
    reason="requires disposable desktop databases",
)


def test_populated_desktop_sources(tmp_path, monkeypatch):
    assert os.environ["POSTGRES_DB"] == "desktop_fixture"
    assert os.environ["POSTGRES_HOST"] == "127.0.0.1"
    assert os.environ["NEO4J_URI"] == "bolt://127.0.0.1:7687"
    document = causal_document()
    report = build_report(
        document,
        source_trajectory_hash="a" * 64,
        mode="simulation_report",
        experiment_id="causal-test",
    )
    graph = build_causal_graph(report.to_dict(), document)
    with psycopg.connect(
        host="127.0.0.1",
        port=5432,
        user="desktop_fixture",
        password=os.environ["POSTGRES_PASSWORD"],
        dbname="desktop_fixture",
    ) as conn:
        ReportStore(conn).save(report)
        CausalGraphStore(conn).save(graph)
    store = Neo4jProjectionStore.connect(wait_seconds=30)
    try:
        projected = store.rebuild(build_projection_plan(graph))
        assert projected["counts"]["nodes"] == len(graph.nodes)
        with store.driver.session() as session:
            labels = sorted(
                {
                    label
                    for r in session.run("MATCH (n) RETURN labels(n) AS labels")
                    for label in r["labels"]
                }
            )
            relationships = sorted(
                r["type"] for r in session.run("MATCH ()-[r]->() RETURN DISTINCT type(r) AS type")
            )
        monkeypatch.setenv("SECURITY_RL_API_TOKEN", "desktop-integration-fixture-token-0001")
        monkeypatch.setenv("SECURITY_RL_ANALYST_REPORT_IDS", report.report_id)
        path = tmp_path / "twin.json"
        path.write_text(dumps(build()))
        service = AnalystService(snapshot_reader=SnapshotReader(path))
        client = TestClient(create_app(service))
        client.headers["Authorization"] = "Bearer desktop-integration-fixture-token-0001"
        dto = client.get("/api/graph/topology").json()
        assert len(dto["nodes"]) == len(graph.nodes)
        assert len(dto["edges"]) == len(graph.edges)
        assert dto["metadata"]["projection"]["hidden_topology_used"] is False
        assert all(e["evidence_refs"] for e in dto["edges"])
        with store.driver.session() as session:
            session.run("MATCH (n:CausalNode) SET n.true_topology = 'must-not-leak'").consume()
        assert "must-not-leak" not in client.get("/api/graph/topology").text
        filtered = client.get("/api/graph/topology?node_type=service&limit=1").json()
        assert len(filtered["nodes"]) == 1 and not filtered["edges"]
        assert client.get("/api/assets").json()
        assert client.get("/api/findings").status_code == 200
        assert client.get("/api/attack-paths/" + graph.graph_id).json()["edges"]
        assert client.get("/api/reports").json()[0]["report_id"] == report.report_id
        assert client.get("/api/digital-twin/summary").json()["counts"]["assets"] == 4
        replay = client.get("/api/simulations").json()["items"][0]
        assert client.get("/api/simulations/" + replay["id"]).json()["path_available"]
        with ReadOnlyRepository()._connect() as conn:
            with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
                conn.execute("CREATE TABLE forbidden_write (id integer)")
        print(
            {
                "development_fixture_only": True,
                **projected,
                "labels": labels,
                "relationship_types": relationships,
                "graph_endpoint": 200,
                "postgresql_read_only": True,
                "persisted_twin": True,
                "simulation_replay": True,
            }
        )
        with store.driver.session() as session:
            session.run("MATCH (g:CausalProjection) SET g.hidden_topology_used = true").consume()
        assert client.get("/api/graph/topology").status_code == 503
        store.rebuild(build_projection_plan(graph))
        with store.driver.session() as session:
            session.run(
                "MATCH (e:CausalEdgeFact) SET e.evidence_ids = ['missing-evidence']"
            ).consume()
        assert client.get("/api/graph/topology").status_code == 503
        store.rebuild(build_projection_plan(graph))
        monkeypatch.setenv("SECURITY_RL_ANALYST_REPORT_IDS", "unselected-report")
        assert client.get("/api/graph/topology").json()["nodes"] == []
        assert client.get("/api/reports").json() == []
        assert client.get("/api/attack-paths").json() == []
    finally:
        store.close()
