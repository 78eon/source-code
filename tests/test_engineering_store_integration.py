"""Explicit disposable-schema canonical publication and fixture command checks."""

import json
import os
import subprocess
import sys
import pytest
from rlredteam.application.runtime_readiness import inspect_stores
from rlredteam.storage.analytical_store import AnalyticalStore
from rlredteam.storage.analytical_identity import digest
from rlredteam.storage.analytical_lineage import rebuild_report
from rlredteam.storage.neo4j_projection import Neo4jProjectionStore, Neo4jSettings
from rlredteam.application.analytical_fixture import fixture_bundle
from tests.test_analytical_database import db as database_fixture
from tests.test_engineering_simulation import specification
from rlredteam.application.engineering_simulation.service import SimulationService

pytestmark = pytest.mark.postgres


@pytest.fixture
def db():
    yield from database_fixture.__wrapped__()


@pytest.fixture
def stores(db, monkeypatch):
    if os.environ.get("RLRT_ENGINEERING_TEST_ONLY") != "1":
        pytest.skip("explicit disposable engineering stores only")
    # The fixture provides an isolated schema. New canonical connections use it too.
    schema = db.execute("SELECT current_schema()").fetchone()[0]
    monkeypatch.setenv("PGOPTIONS", "-c search_path=" + schema)
    for k, v in {
        "POSTGRES_HOST": "127.0.0.1",
        "POSTGRES_PORT": "5432",
        "POSTGRES_USER": "phase5_test",
        "POSTGRES_DB": "rlrt_phase5_test",
        "POSTGRES_PASSWORD": "disposable-phase5-only",
        "NEO4J_URI": "bolt://127.0.0.1:7687",
        "NEO4J_USER": "neo4j",
        "NEO4J_PASSWORD": "disposable-phase5-only",
    }.items():
        monkeypatch.setenv(k, v)
    neo = Neo4jProjectionStore.connect(Neo4jSettings.from_env(), wait_seconds=45)
    try:
        yield db, neo
    finally:
        # Delete only graph IDs created in this disposable schema, so later
        # readiness tests do not inherit our engineering projections.
        ids = [r[0] for r in db.execute("SELECT graph_id FROM causal_attack_graphs").fetchall()]
        with neo.driver.session(database=neo.database) as session:
            for identifier in ids:
                session.run("MATCH(n {graph_id:$id}) DETACH DELETE n", id=identifier).consume()
        neo.close()


def test_fixture_readiness_transitions_and_canonical_rebuild(stores):
    db, neo = stores
    source, report, graph, lineage = fixture_bundle()
    selected = [report.report_id]
    assert inspect_stores(db, neo, selected)["state"] == "DATABASE_EMPTY"
    store = AnalyticalStore(db)
    store.ingest(
        report,
        graph,
        lineage,
        source_sha256=digest(source),
        protocol_sha256=digest({"fixture": "not_registered"}),
    )
    assert inspect_stores(db, neo, selected)["state"] == "REPORTS_AVAILABLE_NONE_APPROVED"
    store.approve(
        report.report_id,
        approver_label="disposable engineering test",
        reason="explicit engineering fixture",
        source="engineering_fixture",
    )
    # Clear only this disposable Neo4j projection to exercise the missing state.
    with neo.driver.session(database=neo.database) as session:
        session.run("MATCH (n {graph_id:$id}) DETACH DELETE n", id=graph.graph_id).consume()
    assert inspect_stores(db, neo, selected)["state"] == "NEO4J_PROJECTION_MISSING"
    rebuild_report(db, neo, report.report_id)
    assert inspect_stores(db, neo, selected)["state"] == "EVIDENCE_READY"


def test_development_fixture_command_is_explicit_and_idempotent(stores):
    db, neo = stores
    command = [sys.executable, "-B", "scripts/analytical_runtime.py", "development-fixture"]
    first = subprocess.run(command, capture_output=True, text=True, timeout=45)
    assert first.returncode == 0, first.stdout
    result = json.loads(first.stdout)
    assert result["status"] == "EVIDENCE_READY" and result["research_status"] == "not_registered"
    approvals = db.execute("SELECT count(*) FROM report_approvals").fetchone()[0]
    second = subprocess.run(command, capture_output=True, text=True, timeout=45)
    assert second.returncode == 0
    assert json.loads(second.stdout)["report_id"] == result["report_id"]
    assert db.execute("SELECT count(*) FROM report_approvals").fetchone()[0] == approvals
    bad = subprocess.run(command + ["--source", "/does-not-exist"], capture_output=True, text=True)
    assert bad.returncode != 0


def test_generated_run_publishes_through_canonical_layers(stores, tmp_path):
    db, neo = stores
    service = SimulationService(tmp_path / "engineering-simulations")
    record = service.create(specification())
    identifier = record["simulation_id"]
    result = service.run(identifier)
    assert db.execute("SELECT count(*) FROM attack_path_reports").fetchone()[0] == 0
    publication = service.publish(identifier)
    assert publication["state"] == "EVIDENCE_READY"
    assert publication["report_id"] == result["report_id"]
    assert inspect_stores(db, neo, [result["report_id"]])["state"] == "EVIDENCE_READY"
    assert service.publish(identifier) == publication
    assert db.execute("SELECT count(*) FROM report_approvals").fetchone()[0] == 1
    with neo.driver.session(database=neo.database, default_access_mode="READ") as session:
        assert session.run(
            "MATCH(n:CausalNode {graph_id:$id}) RETURN count(n) AS n", id=result["graph_id"]
        ).single()["n"] == len(result["graph"]["nodes"])
