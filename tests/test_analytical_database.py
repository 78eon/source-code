"""Disposable Podman DB tests only; refuses ambient research DB configuration."""

import os
import uuid

import psycopg
import pytest
from psycopg import sql

from rlredteam.storage.analytical_migrations import migrate
from rlredteam.storage.analytical_store import AnalyticalStore
from rlredteam.storage.causal_store import CausalGraphStore
from rlredteam.storage.postgres_logger import ensure_schema
from rlredteam.storage.report_store import ReportStore
from tests.test_analytical_lineage import bundle

pytestmark = pytest.mark.postgres


@pytest.fixture
def db():
    if os.environ.get("RLRT_PHASE5_TEST_ONLY") != "1":
        pytest.skip("requires explicit disposable Phase5 Podman test environment")
    # Do not consume POSTGRES_* from the host. Fixed test identity, isolated namespace.
    connection = psycopg.connect(
        host="127.0.0.1",
        port=5432,
        user="phase5_test",
        password="disposable-phase5-only",
        dbname="rlrt_phase5_test",
        autocommit=True,
        connect_timeout=4,
    )
    if connection.execute("SELECT current_database()").fetchone()[0] != "rlrt_phase5_test":
        raise RuntimeError("refusing non-test database")
    schema = "phase5_" + uuid.uuid4().hex
    connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    connection.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
    ensure_schema(connection)
    migrate(connection)
    try:
        yield connection
    finally:
        connection.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))
        connection.close()


def ingest(db):
    report, graph, episodes = bundle()
    AnalyticalStore(db).ingest(
        report, graph, episodes, source_sha256="a" * 64, protocol_sha256="b" * 64
    )
    return report, graph, episodes


def test_fresh_and_repeated_migration_history(db):
    migrate(db)
    assert db.execute("SELECT count(*) FROM analytical_schema_migrations").fetchone()[0] == 1
    assert db.execute("SELECT count(*) FROM report_approvals").fetchone()[0] == 0
    constraints = {
        r[0]
        for r in db.execute(
            "SELECT conname FROM pg_constraint WHERE connamespace=current_schema()::regnamespace"
        )
    }
    assert {"causal_report_fk", "causal_source_fk", "causal_target_fk"} <= constraints
    indexes = {
        r[0]
        for r in db.execute("SELECT indexname FROM pg_indexes WHERE schemaname=current_schema()")
    }
    assert {"one_active_report_approval", "one_active_graph_projection"} <= indexes


def test_populated_previous_schema_upgrade_preserves_legacy(db):
    from rlredteam.attack_path_report import build_report
    from tests.test_causal_graph import causal_document

    schema = "phase5_upgrade_" + uuid.uuid4().hex
    prior = db.execute("SELECT current_schema()").fetchone()[0]
    db.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    try:
        db.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        ensure_schema(db)
        legacy = build_report(
            causal_document(),
            source_trajectory_hash="a" * 64,
            mode="simulation_report",
            experiment_id="legacy",
        )
        ReportStore(db).save(legacy)
        migrate(db)
        migrate(db)
        assert ReportStore(db).load(legacy.report_id) == legacy.to_dict()
        assert db.execute("SELECT count(*) FROM analytical_schema_migrations").fetchone()[0] == 1
    finally:
        db.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(prior)))
        db.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


def test_migration_checksum_tampering_rejected(db):
    db.execute("UPDATE analytical_schema_migrations SET checksum='wrong'")
    with pytest.raises(ValueError, match="checksum"):
        migrate(db)


def test_duplicate_migration_history_rejected(db):
    with pytest.raises(psycopg.errors.UniqueViolation):
        db.execute("""INSERT INTO analytical_schema_migrations(version,checksum)
            SELECT version,checksum FROM analytical_schema_migrations""")


def test_ingest_roundtrip_and_duplicate_idempotence(db):
    report, graph, episodes = ingest(db)
    ingest(db)
    assert ReportStore(db).load(report.report_id) == report.to_dict()
    assert CausalGraphStore(db).load(graph.graph_id).to_dict() == graph.to_dict()
    assert db.execute("SELECT count(*) FROM analytical_episode_lineage").fetchone()[0] == 2
    assert db.execute("SELECT count(*) FROM analytical_report_episodes").fetchone()[0] == 2


def test_changed_source_lineage_rollback(db):
    report, graph, episodes = ingest(db)
    with pytest.raises(ValueError, match="collision"):
        AnalyticalStore(db).ingest(
            report, graph, episodes, source_sha256="c" * 64, protocol_sha256="b" * 64
        )
    assert db.execute("SELECT count(*) FROM analytical_episode_lineage").fetchone()[0] == 2


def test_selection_is_not_approval_and_revoke_preserves_report(db):
    report, graph, episodes = ingest(db)
    service = AnalyticalStore(db)
    assert not service.is_approved(report.report_id)
    approval = service.approve(
        report.report_id, approver_label="test reviewer", reason="fixture review"
    )
    assert service.is_approved(report.report_id)
    assert service.revoke(approval)
    assert not service.is_approved(report.report_id)
    assert ReportStore(db).load(report.report_id) == report.to_dict()


def test_orphan_approval_rejected(db):
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        AnalyticalStore(db).approve("f" * 64, approver_label="reviewer", reason="orphan")


def test_duplicate_active_approval_rejected(db):
    report, _, _ = ingest(db)
    service = AnalyticalStore(db)
    service.approve(report.report_id, approver_label="first", reason="first")
    with pytest.raises(psycopg.errors.UniqueViolation):
        service.approve(report.report_id, approver_label="second", reason="second")


def test_orphan_graph_rejected(db):
    _, graph, _ = bundle()
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        CausalGraphStore(db).save(graph)
    assert db.execute("SELECT count(*) FROM causal_attack_graphs").fetchone()[0] == 0


def test_orphan_endpoint_rejected(db):
    _, graph, _ = ingest(db)
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        db.execute(
            "UPDATE causal_edge_facts SET source_node='nonexistent' WHERE graph_id=%s",
            (graph.graph_id,),
        )


def test_duplicate_active_projection_rejected(db):
    from rlredteam.storage.neo4j_projection import build_projection_plan

    _, graph, _ = ingest(db)
    plan = build_projection_plan(graph)
    AnalyticalStore(db).record_projection(plan)
    with pytest.raises(psycopg.errors.UniqueViolation):
        db.execute(
            """INSERT INTO analytical_projections
            SELECT %s,graph_id,report_id,source_graph_sha256,projection_hash,
                   schema_version,builder_version,projected_at,status,is_active
            FROM analytical_projections""",
            ("f" * 64,),
        )


def test_graph_tamper_detected_on_load(db):
    from psycopg.types.json import Jsonb

    _, graph, _ = ingest(db)
    node = dict(db.execute("SELECT node_data FROM causal_node_facts LIMIT 1").fetchone()[0])
    node["node_type"] = "tampered"
    db.execute(
        "UPDATE causal_node_facts SET node_data=%s WHERE node_id=%s", (Jsonb(node), node["node_id"])
    )
    with pytest.raises(ValueError, match="identity"):
        CausalGraphStore(db).load(graph.graph_id)


def test_report_insert_rollback_with_autocommit(db):
    report, _, _ = bundle()
    db.execute("""CREATE FUNCTION fail_report_fact() RETURNS trigger LANGUAGE plpgsql AS
        $$ BEGIN RAISE EXCEPTION 'injected test failure'; END $$""")
    db.execute("""CREATE TRIGGER injected_failure BEFORE INSERT ON attack_path_report_facts
        FOR EACH ROW EXECUTE FUNCTION fail_report_fact()""")
    with pytest.raises(psycopg.Error):
        ReportStore(db).save(report)
    assert db.execute("SELECT count(*) FROM attack_path_reports").fetchone()[0] == 0


def test_graph_insert_rollback_with_autocommit(db):
    report, graph, _ = bundle()
    ReportStore(db).save(report)
    db.execute("""CREATE FUNCTION fail_graph_fact() RETURNS trigger LANGUAGE plpgsql AS
        $$ BEGIN RAISE EXCEPTION 'injected test failure'; END $$""")
    db.execute("""CREATE TRIGGER injected_failure BEFORE INSERT ON causal_node_facts
        FOR EACH ROW EXECUTE FUNCTION fail_graph_fact()""")
    with pytest.raises(psycopg.Error):
        CausalGraphStore(db).save(graph)
    assert db.execute("SELECT count(*) FROM causal_attack_graphs").fetchone()[0] == 0
    assert db.execute("SELECT count(*) FROM causal_knowledge_evidence").fetchone()[0] == 0
    assert ReportStore(db).load(report.report_id) is not None


def test_ingestion_coordinator_rolls_back_all_dependent_records(db):
    report, graph, episodes = bundle()
    db.execute("""CREATE FUNCTION fail_lineage() RETURNS trigger LANGUAGE plpgsql AS
        $$ BEGIN RAISE EXCEPTION 'injected lineage failure'; END $$""")
    db.execute("""CREATE TRIGGER injected_failure BEFORE INSERT ON analytical_episode_lineage
        FOR EACH ROW EXECUTE FUNCTION fail_lineage()""")
    with pytest.raises(psycopg.Error):
        AnalyticalStore(db).ingest(
            report, graph, episodes, source_sha256="a" * 64, protocol_sha256="b" * 64
        )
    assert db.execute("SELECT count(*) FROM attack_path_reports").fetchone()[0] == 0
    assert db.execute("SELECT count(*) FROM causal_attack_graphs").fetchone()[0] == 0
    assert db.execute("SELECT count(*) FROM analytical_episode_lineage").fetchone()[0] == 0


def test_rebuild_failure_preserves_canonical_pg(db):
    from rlredteam.storage.analytical_lineage import rebuild_report

    report, graph, _ = ingest(db)

    class FailedNeo:
        def rebuild(self, plan):
            raise RuntimeError("injected Neo4j outage")

    with pytest.raises(RuntimeError):
        rebuild_report(db, FailedNeo(), report.report_id)
    assert CausalGraphStore(db).load(graph.graph_id).to_dict() == graph.to_dict()
    assert db.execute("SELECT status FROM analytical_projections").fetchone()[0] == "INCONSISTENT"


def test_live_rebuild_idempotence_and_cross_store(db):
    from rlredteam.storage.analytical_lineage import (
        read_live_snapshot,
        rebuild_report,
        verify_snapshot,
    )
    from rlredteam.storage.neo4j_projection import Neo4jProjectionStore, Neo4jSettings

    report, graph, _ = ingest(db)
    neo = Neo4jProjectionStore.connect(
        Neo4jSettings("bolt://127.0.0.1:7687", "neo4j", "disposable-phase5-only"), wait_seconds=0
    )
    try:
        first = rebuild_report(db, neo, report.report_id)
        second = rebuild_report(db, neo, report.report_id)
        assert first == second
        result = verify_snapshot(read_live_snapshot(db, neo))
        assert result["exit_code"] == 0
        print("LIVE_LINEAGE", result["status"], "Neo4j", first["neo4j_version"])
    finally:
        with neo.driver.session(database=neo.database) as session:
            session.run("MATCH(n {graph_id:$id}) DETACH DELETE n", id=graph.graph_id).consume()
        neo.close()


def test_frozen_seed42_reconstruction(db):
    import json
    from pathlib import Path

    from rlredteam.storage.frozen_reconstruction import PROTOCOL, reconstruct_validation

    directory = Path(
        "docs/research_evidence/MASTER_PROJECT_AUDIT/01_REGISTERED_CAMPAIGN/"
        "onprem-generalisation-registered/seed-42/validation"
    )
    report, graph, episodes, before = reconstruct_validation(directory)
    AnalyticalStore(db).ingest(
        report,
        graph,
        episodes,
        source_sha256=before["trajectories.jsonl"],
        protocol_sha256=PROTOCOL,
    )
    assert CausalGraphStore(db).load(graph.graph_id).to_dict() == graph.to_dict()
    after = reconstruct_validation(directory)[3]
    assert before == after
    assert len(episodes) == 20
    assert db.execute("SELECT count(*) FROM analytical_episode_lineage").fetchone()[0] == 20
    print(
        "FROZEN_RECONSTRUCTION",
        json.dumps(
            {
                "report_id": report.report_id,
                "graph_id": graph.graph_id,
                "episode_count": len(episodes),
                "source_hashes_before": before,
                "source_hashes_after": after,
                "node_count": len(graph.nodes),
                "edge_count": len(graph.edges),
                "fact_count": len(report.facts),
                "first_episode_uid": episodes[0]["episode_uid"],
                "last_episode_uid": episodes[-1]["episode_uid"],
                "no_training_or_evaluation": True,
            },
            sort_keys=True,
        ),
    )
