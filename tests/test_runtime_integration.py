"""Disposable services -> approved fixture -> API/desktop state, plus restore."""

import json
import os
from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient

from rlredteam.api.app import create_app
from rlredteam.api.services import AnalystService
from rlredteam.application.analytical_fixture import fixture_bundle
from rlredteam.application.data.repository import Repository
from rlredteam.application.runtime_readiness import inspect_stores
from rlredteam.storage.analytical_identity import digest
from rlredteam.storage.analytical_lineage import rebuild_report
from rlredteam.storage.analytical_store import AnalyticalStore
from rlredteam.storage.neo4j_projection import Neo4jProjectionStore, Neo4jSettings
from tests.test_analytical_database import db as phase5_db

pytestmark = pytest.mark.postgres


@pytest.fixture
def db():
    yield from phase5_db.__wrapped__()


@pytest.fixture
def neo():
    store = Neo4jProjectionStore.connect(
        Neo4jSettings("bolt://127.0.0.1:7687", "neo4j", "disposable-phase5-only"), wait_seconds=0
    )
    yield store
    store.close()


def ingest(db):
    source, report, graph, lineage = fixture_bundle()
    before = digest(source)
    AnalyticalStore(db).ingest(
        report,
        graph,
        lineage,
        source_sha256=before,
        protocol_sha256=digest({"fixture": "not_registered"}),
    )
    assert digest(source) == before
    return report, graph


def test_empty_and_schema_mismatch(db, neo, monkeypatch):
    result = inspect_stores(db, neo, [], True)
    assert result["state"] == "DATABASE_EMPTY"
    assert result["neo4j"] == "NEO4J_READY_EMPTY"
    assert result["overall"] == "EMPTY"
    monkeypatch.setenv("SECURITY_RL_API_TOKEN", "e" * 32)
    service = AnalystService()
    service.readiness = lambda: inspect_stores(db, neo, [], True)
    with TestClient(create_app(service)) as client:
        response = client.get("/api/readiness", headers={"Authorization": "Bearer " + "e" * 32})
        assert response.status_code == 200 and response.json()["state"] == "DATABASE_EMPTY"
    assert db.execute("SELECT count(*) FROM attack_path_reports").fetchone()[0] == 0
    db.execute("UPDATE analytical_schema_migrations SET checksum='wrong'")
    assert inspect_stores(db, neo)["state"] == "DATABASE_SCHEMA_MISMATCH"


def test_prerequisites_approvals_projection_and_live_api(db, neo, monkeypatch):
    report, graph = ingest(db)
    selected = [report.report_id]
    assert inspect_stores(db, neo, selected)["state"] == "REPORTS_AVAILABLE_NONE_APPROVED"
    AnalyticalStore(db).approve(
        report.report_id,
        approver_label="test-only reviewer",
        reason="explicit engineering fixture validation",
    )
    assert inspect_stores(db, neo, selected)["state"] == "NEO4J_PROJECTION_MISSING"
    assert inspect_stores(db, None, selected)["state"] == "NEO4J_UNAVAILABLE"
    assert inspect_stores(db, neo, ["f" * 64])["state"] == "APPROVED_REPORT_MISSING"
    rebuild_report(db, neo, report.report_id)
    try:
        assert inspect_stores(db, neo, selected)["state"] == "EVIDENCE_READY"

        class TestRepository(Repository):
            @contextmanager
            def _connect(self):
                yield db

        monkeypatch.setenv("SECURITY_RL_API_TOKEN", "phase6-test-token-" + "a" * 32)
        monkeypatch.setenv("SECURITY_RL_ANALYST_REPORT_IDS", report.report_id)
        monkeypatch.setenv("SECURITY_RL_REQUIRE_REPORT_APPROVAL", "1")
        service = AnalystService(repository=TestRepository())
        # Default readiness opens its own real Neo4j READ session; only the
        # repository connection is scoped to this isolated PostgreSQL schema.
        before = db.execute("SELECT count(*) FROM attack_path_reports").fetchone()[0]
        with TestClient(create_app(service)) as client:
            client.headers["Authorization"] = "Bearer " + os.environ["SECURITY_RL_API_TOKEN"]
            assert client.get("/api/health").json()["read_only"] is True
            assert client.get("/api/readiness").json()["state"] == "EVIDENCE_READY"
            assert client.get("/api/reports").json()[0]["report_id"] == report.report_id
            assert client.get("/api/attack-paths").json()[0]["graph_id"] == graph.graph_id
            payload = client.get("/api/graph/topology").json()
            assert payload["graph_id"] == graph.graph_id and payload["nodes"] and payload["edges"]
            assert client.post("/api/reports").status_code == 405
        assert db.execute("SELECT count(*) FROM attack_path_reports").fetchone()[0] == before
        with neo.driver.session(database=neo.database) as s:
            s.run(
                "MATCH(g:CausalProjection {graph_id:$id}) SET g.source_graph_sha256=$sha",
                id=graph.graph_id,
                sha="f" * 64,
            ).consume()
        assert inspect_stores(db, neo, selected)["state"] == "PROJECTION_STALE"
        rebuild_report(db, neo, report.report_id)
        with neo.driver.session(database=neo.database) as s:
            s.run(
                "MATCH(g:CausalProjection {graph_id:$id}) SET g.node_count=999", id=graph.graph_id
            ).consume()
        assert inspect_stores(db, neo, selected)["state"] == "PROJECTION_INCONSISTENT"
        print(
            "PHASE6_E2E",
            json.dumps(
                {
                    "report_id": report.report_id,
                    "graph_id": graph.graph_id,
                    "source_hash": digest(fixture_bundle()[0]),
                    "api": "PASS",
                    "desktop_state": "EVIDENCE_READY",
                }
            ),
        )
    finally:
        with neo.driver.session(database=neo.database) as s:
            s.run("MATCH(n {graph_id:$id}) DETACH DELETE n", id=graph.graph_id).consume()


def test_report_without_graph(db, neo):
    from rlredteam.storage.report_store import ReportStore

    _, report, _, _ = fixture_bundle()
    ReportStore(db).save(report)
    AnalyticalStore(db).approve(report.report_id, approver_label="test", reason="explicit fixture")
    assert inspect_stores(db, neo, [report.report_id])["state"] == "CAUSAL_GRAPH_MISSING"


def test_heldout_bootstrap_is_rejected_before_write(db):
    from rlredteam.causal_graph import build_causal_graph
    from rlredteam.storage.analytical_identity import build_analytical_report

    source, _, _, _ = fixture_bundle()
    source[0]["topology_seed"] = 16001
    report, prepared, lineage = build_analytical_report(source, experiment_id="blocked-fixture")
    graph = build_causal_graph(report.to_dict(), prepared)
    with pytest.raises(ValueError, match="held-out"):
        AnalyticalStore(db).ingest(
            report,
            graph,
            lineage,
            source_sha256=digest(source),
            protocol_sha256=digest({"fixture": True}),
        )
    assert db.execute("SELECT count(*) FROM attack_path_reports").fetchone()[0] == 0


def test_database_unavailable_is_sanitized():
    class FailedConnection:
        def execute(self, *args):
            raise RuntimeError("password=not-for-display")

    result = inspect_stores(FailedConnection(), None)
    assert result["state"] == "DATABASE_UNAVAILABLE"
    assert "not-for-display" not in json.dumps(result)


def test_starting_database_state():
    from psycopg.errors import CannotConnectNow

    class StartingConnection:
        def execute(self, *args):
            raise CannotConnectNow("test-only starting")

    assert inspect_stores(StartingConnection(), None)["state"] == "DATABASE_STARTING"


def test_actual_unavailable_local_services_and_invalid_selection(db):
    import psycopg

    from rlredteam.application.runtime_readiness import service_readiness

    class UnavailableRepository:
        def _connect(self):
            return psycopg.connect(
                host="127.0.0.1", port=1, dbname="rlrt_phase5_test", connect_timeout=1
            )

    assert service_readiness(UnavailableRepository(), [])["state"] == "DATABASE_UNAVAILABLE"
    from neo4j.exceptions import ServiceUnavailable

    with pytest.raises(ServiceUnavailable):
        Neo4jProjectionStore.connect(
            Neo4jSettings("bolt://127.0.0.1:1", "neo4j", "disposable-phase5-only"), wait_seconds=0
        )
    with pytest.raises(ValueError):
        inspect_stores(db, None, ["not-a-report-hash"])
