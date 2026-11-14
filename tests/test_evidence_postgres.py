"""Disposable Podman PostgreSQL only; never accepts an ambient research DB."""

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql
from psycopg.types.json import Jsonb

from rlredteam.evidence.models import EvidenceBundle, ObservedAsset
from rlredteam.evidence.repository import EvidenceBundleConflictError, InMemoryEvidenceRepository
from rlredteam.evidence.serialization import dumps
from rlredteam.knowledge.serialization import digest
from rlredteam.knowledge.validation import ModelError
from rlredteam.storage import evidence_migrations
from rlredteam.storage.evidence_migrations import migrate
from rlredteam.storage.evidence_store import (
    EvidenceStorageIntegrityError,
    PostgresEvidenceRepository,
)
from rlredteam.storage.postgres_logger import connection_string, ensure_schema
from tests.digital_twin_fixtures import evidence
from tests.knowledge_evidence_fixtures import asset

pytestmark = pytest.mark.postgres


@pytest.fixture
def db():
    if os.environ.get("RLRT_EVIDENCE_TEST_ONLY") != "1":
        pytest.skip("requires explicit disposable evidence Podman environment")
    if os.environ.get("POSTGRES_HOST") != "127.0.0.1" or (
        os.environ.get("POSTGRES_DB") != "rlrt_evidence_test"
    ):
        pytest.fail("refusing non-disposable evidence database configuration")
    # Fresh database for every test: no application database migrations/cleanup.
    name = "rlrt_evidence_test_" + uuid4().hex
    with psycopg.connect(connection_string(), autocommit=True) as admin:
        assert admin.execute("SELECT current_database()").fetchone()[0] == "rlrt_evidence_test"
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        try:
            with psycopg.connect(connection_string(), dbname=name, autocommit=True) as conn:
                yield conn
        finally:
            admin.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(name)))


@pytest.fixture
def ready(db):
    migrate(db)
    return db


@pytest.fixture
def bundle():
    return evidence(extras=(asset("evidence:ip", subject_id="asset:web"),)).bundle


def count(db, table):
    return db.execute(
        sql.SQL("SELECT count(*) FROM normalized_evidence.{}").format(sql.Identifier(table))
    ).fetchone()[0]


def test_explicit_migration_and_repeat(db):
    PostgresEvidenceRepository(db)
    assert db.execute("SELECT to_regnamespace('normalized_evidence')").fetchone()[0] is None
    migrate(db)
    migrate(db)
    assert count(db, "evidence_schema_migrations") == 1
    assert db.execute(
        """SELECT checksum FROM normalized_evidence.evidence_schema_migrations"""
    ).fetchone()[0] == digest(evidence_migrations.MIGRATION_PATH.read_text())
    assert count(db, "evidence_bundle") == 0


def test_altered_migration_checksum_fails(ready, monkeypatch):
    class ChangedSource:
        def read_text(self):
            return "-- altered migration"

    monkeypatch.setattr(evidence_migrations, "MIGRATION_PATH", ChangedSource())
    with pytest.raises(ValueError, match="evidence migration checksum mismatch"):
        migrate(ready)
    assert count(ready, "evidence_schema_migrations") == 1


def test_migration_failure_rolls_back_schema(db, monkeypatch):
    class BadSource:
        def read_text(self):
            return "CREATE TABLE normalized_evidence.partial(id int); SELECT missing_function();"

    monkeypatch.setattr(evidence_migrations, "MIGRATION_PATH", BadSource())
    with pytest.raises(psycopg.Error):
        migrate(db)
    assert db.execute("SELECT to_regnamespace('normalized_evidence')").fetchone()[0] is None


def test_minimal_bundle_roundtrip(ready):
    bundle = EvidenceBundle(
        bundle_id="bundle:minimal", created_at="2026-11-11T12:00:00Z", sources=(), records=()
    )
    repo = PostgresEvidenceRepository(ready)
    repo.save(bundle)
    assert repo.load(bundle.bundle_id) == bundle
    assert count(ready, "evidence_source") == 0


@pytest.mark.parametrize(
    "table,typename",
    [
        ("observed_asset", "ObservedAsset"),
        ("observed_identity", "ObservedIdentity"),
        ("observed_service", "ObservedService"),
        ("observed_software", "ObservedSoftware"),
        ("observed_relationship", "ObservedRelationship"),
    ],
)
def test_subtype_roundtrip_and_projection(ready, bundle, table, typename):
    repo = PostgresEvidenceRepository(ready)
    repo.save(bundle)
    restored = repo.load(bundle.bundle_id)
    expected = [r for r in bundle.records if type(r).__name__ == typename]
    assert expected
    assert [r for r in restored.records if type(r).__name__ == typename] == expected
    assert count(ready, table) == len(expected)


def test_findings_and_provenance_roundtrip(ready, bundle):
    repo = PostgresEvidenceRepository(ready)
    repo.save(bundle)
    restored = repo.load(bundle.bundle_id)
    assert dumps(restored) == dumps(bundle)
    assert restored.findings == bundle.findings
    assert count(ready, "finding") == len(bundle.findings) > 0
    assert count(ready, "record_source_reference") == sum(
        len(r.provenance.source_ids) for r in bundle.records
    )
    assert count(ready, "finding_evidence_reference") == sum(
        len(f.evidence_ids) + len(f.provenance.evidence_ids) for f in bundle.findings
    )


def test_queryable_projection_values(ready, bundle):
    PostgresEvidenceRepository(ready).save(bundle)
    assert ready.execute(
        """SELECT asset_id,port,protocol FROM normalized_evidence.observed_service"""
    ).fetchall() == [("asset:web", 443, "tcp")]
    assert ready.execute(
        """SELECT asset_id,product_id,version FROM normalized_evidence.observed_software"""
    ).fetchall() == [("asset:web", "product:a", "2.4.50")]
    assert ready.execute(
        """SELECT asset_id,identity_type FROM normalized_evidence.observed_identity"""
    ).fetchall() == [("asset:app", "service_account")]
    for raw in bundle.records:
        row = ready.execute(
            """SELECT record_type,subject_id,observation_type,status,confidence,source_id
            FROM normalized_evidence.evidence_record WHERE bundle_id=%s AND evidence_id=%s""",
            (bundle.bundle_id, raw.evidence_id),
        ).fetchone()
        assert row == (
            type(raw).__name__,
            raw.subject_id,
            raw.observation_type,
            raw.status.value,
            raw.confidence,
            raw.source_id,
        )
    for f in bundle.findings:
        row = ready.execute(
            """SELECT asset_id,status,confidence,applicability_status,service_id,
            software_id,vulnerability_id,weakness_id,severity,cvss_base,"references"
            FROM normalized_evidence.finding WHERE bundle_id=%s AND finding_id=%s""",
            (bundle.bundle_id, f.finding_id),
        ).fetchone()
        assert row == (
            f.asset_id,
            f.status.value,
            f.confidence,
            f.applicability_status.value,
            f.service_id,
            f.software_id,
            f.vulnerability_id,
            f.weakness_id,
            f.severity,
            f.cvss_base,
            list(f.references),
        )


def test_multiple_sources_and_forward_evidence_references(ready, bundle):
    source = replace(bundle.sources[0], source_id="source:second")
    first = bundle.records[0]
    target = bundle.records[-1]
    changed = replace(
        first,
        provenance=replace(
            first.provenance,
            source_ids=(bundle.sources[0].source_id, source.source_id),
            evidence_ids=(target.evidence_id,),
        ),
    )
    bundle = replace(
        bundle, sources=(*bundle.sources, source), records=(changed, *bundle.records[1:])
    )
    repo = PostgresEvidenceRepository(ready)
    repo.save(bundle)
    assert repo.load(bundle.bundle_id) == bundle
    assert count(ready, "record_evidence_reference") == 1
    assert count(ready, "record_source_reference") == len(bundle.records) + 1


def test_digest_and_identical_save_are_stable(ready, bundle):
    repo = PostgresEvidenceRepository(ready)
    repo.save(bundle)
    before = ready.execute(
        "SELECT canonical_digest,stored_at FROM normalized_evidence.evidence_bundle"
    ).fetchone()
    repo.save(bundle)
    after = ready.execute(
        "SELECT canonical_digest,stored_at FROM normalized_evidence.evidence_bundle"
    ).fetchone()
    assert before == after
    assert after[0] == digest(dumps(bundle))
    assert count(ready, "evidence_bundle") == 1
    assert count(ready, "evidence_record") == len(bundle.records)


def test_conflict_preserves_original(ready, bundle):
    repo = PostgresEvidenceRepository(ready)
    repo.save(bundle)
    with pytest.raises(EvidenceBundleConflictError, match="already exists"):
        repo.save(replace(bundle, created_at="2026-11-11T12:00:00Z"))
    assert repo.load(bundle.bundle_id) == bundle


def test_exists_missing_and_sorted_contract(ready, bundle):
    repo = PostgresEvidenceRepository(ready)
    memory = InMemoryEvidenceRepository()
    assert not repo.exists(bundle.bundle_id)
    with pytest.raises(KeyError):
        repo.load(bundle.bundle_id)
    for key in ("bundle:z", "bundle:a", "bundle:m"):
        value = replace(bundle, bundle_id=key)
        repo.save(value)
        memory.save(value)
        assert repo.exists(key)
        assert repo.load(key) == memory.load(key)
    assert repo.list() == memory.list() == ("bundle:a", "bundle:m", "bundle:z")


def test_repeated_identifiers_endpoints_and_cves_do_not_merge(ready, bundle):
    repo = PostgresEvidenceRepository(ready)
    second = replace(bundle, bundle_id="bundle:second")
    repo.save(bundle)
    repo.save(second)
    assert repo.load(bundle.bundle_id) == bundle
    assert repo.load(second.bundle_id) == second
    assert count(ready, "evidence_record") == 2 * len(bundle.records)
    for table in (
        "observed_asset",
        "observed_identity",
        "observed_service",
        "observed_software",
        "finding",
    ):
        assert count(ready, table) >= 2
    assert (
        ready.execute("""SELECT count(DISTINCT bundle_id) FROM normalized_evidence.observed_asset
        WHERE identifiers @> '[{"identifier_type":"IPV4","value":"192.0.2.10"}]'""").fetchone()[0]
        == 2
    )
    assert (
        ready.execute(
            "SELECT count(DISTINCT bundle_id) FROM normalized_evidence.finding "
            "WHERE vulnerability_id=%s",
            (bundle.findings[0].vulnerability_id,),
        ).fetchone()[0]
        == 2
    )
    assert (
        ready.execute("""SELECT count(DISTINCT bundle_id) FROM normalized_evidence.observed_asset
        WHERE identifiers @> '[{"identifier_type":"HOSTNAME","value":"web.test"}]'""").fetchone()[0]
        == 2
    )
    assert (
        ready.execute("""SELECT count(DISTINCT bundle_id) FROM normalized_evidence.observed_service
        WHERE asset_id='asset:web' AND protocol='tcp' AND port=443""").fetchone()[0]
        == 2
    )


def test_shared_asset_id_keeps_multiple_records(ready, bundle):
    repo = PostgresEvidenceRepository(ready)
    repo.save(bundle)
    expected = sum(
        isinstance(r, ObservedAsset) and r.asset_id == "asset:web" for r in bundle.records
    )
    assert expected > 1
    assert (
        ready.execute(
            "SELECT count(*) FROM normalized_evidence.observed_asset WHERE asset_id='asset:web'"
        ).fetchone()[0]
        == expected
    )


def test_projection_failure_rolls_back_every_insert(ready, bundle):
    ready.execute("""CREATE FUNCTION normalized_evidence.fail_projection()
        RETURNS trigger LANGUAGE plpgsql
        AS $$ BEGIN RAISE EXCEPTION 'injected evidence projection failure'; END $$""")
    ready.execute("""CREATE TRIGGER fail_projection BEFORE INSERT ON normalized_evidence.finding
        FOR EACH ROW EXECUTE FUNCTION normalized_evidence.fail_projection()""")
    with pytest.raises(psycopg.Error, match="injected evidence projection failure"):
        PostgresEvidenceRepository(ready).save(bundle)
    for table in (
        "evidence_bundle",
        "evidence_source",
        "evidence_subject",
        "evidence_record",
        "observed_asset",
    ):
        assert count(ready, table) == 0


@pytest.mark.parametrize("mutation", ["digest", "document", "bundle_id", "schema", "created_at"])
def test_corruption_detected_without_repair(ready, bundle, mutation):
    repo = PostgresEvidenceRepository(ready)
    repo.save(bundle)
    if mutation == "digest":
        ready.execute(
            "UPDATE normalized_evidence.evidence_bundle SET canonical_digest=%s", ("0" * 64,)
        )
    elif mutation in {"document", "bundle_id"}:
        changed = replace(
            bundle,
            **(
                {"created_at": "2026-11-11T12:00:00Z"}
                if mutation == "document"
                else {"bundle_id": "bundle:tampered"}
            ),
        )
        import json

        ready.execute(
            "UPDATE normalized_evidence.evidence_bundle SET document=%s",
            (Jsonb(json.loads(dumps(changed))),),
        )
    elif mutation == "schema":
        ready.execute("UPDATE normalized_evidence.evidence_bundle SET schema_version='bad'")
    else:
        ready.execute(
            "UPDATE normalized_evidence.evidence_bundle SET created_at='2020-01-01T00:00:00Z'"
        )
    before = ready.execute(
        "SELECT to_jsonb(b) FROM normalized_evidence.evidence_bundle b"
    ).fetchone()[0]
    with pytest.raises(EvidenceStorageIntegrityError, match="mismatch"):
        repo.load(bundle.bundle_id)
    assert (
        ready.execute("SELECT to_jsonb(b) FROM normalized_evidence.evidence_bundle b").fetchone()[0]
        == before
    )


def test_existing_research_schema_and_rows_unchanged(db, bundle):
    # This is the disposable per-test DB, not an existing application database.
    ensure_schema(db)
    db.execute("""INSERT INTO experiments(name,reward_mode,config_hash,topology_config_hash,
        cve_manifest_sha256,seed_set) VALUES('sentinel','sparse','a','b','c',ARRAY[42])""")

    def snapshot():
        definitions = db.execute("""SELECT c.relname,a.attname,format_type(a.atttypid,a.atttypmod)
            FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            JOIN pg_attribute a ON a.attrelid=c.oid
            WHERE n.nspname='public' AND a.attnum>0 ORDER BY c.relname,a.attnum""").fetchall()
        names = db.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename"
        ).fetchall()
        rows = [
            (
                name,
                db.execute(
                    sql.SQL(
                        "SELECT to_jsonb(t) FROM public.{} t ORDER BY to_jsonb(t)::text"
                    ).format(sql.Identifier(name))
                ).fetchall(),
            )
            for (name,) in names
        ]
        return definitions, rows

    before = snapshot()
    migrate(db)
    PostgresEvidenceRepository(db).save(bundle)
    assert snapshot() == before


def test_no_cross_schema_foreign_keys_or_cascades(ready):
    assert (
        ready.execute("""SELECT count(*) FROM pg_constraint c
        JOIN pg_class r ON r.oid=c.confrelid JOIN pg_namespace n ON n.oid=r.relnamespace
        WHERE c.connamespace='normalized_evidence'::regnamespace AND c.contype='f'
        AND (n.nspname<>'normalized_evidence' OR c.confdeltype='c')""").fetchone()[0]
        == 0
    )


def test_same_bundle_foreign_keys_reject_orphans(ready, bundle):
    PostgresEvidenceRepository(ready).save(bundle)
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        ready.execute(
            """INSERT INTO normalized_evidence.record_evidence_reference
            VALUES(%s,%s,'missing')""",
            (bundle.bundle_id, bundle.records[0].evidence_id),
        )


def test_origins_are_optional_append_only_and_validated(ready, bundle):
    repo = PostgresEvidenceRepository(ready)
    origin = dict(
        raw_bundle_id="raw-bundle:test",
        raw_bundle_digest="a" * 64,
        session_id="session:test",
        acquisition_mode="OFFLINE_IMPORT",
        normalization_version="native-observation-normalization-v1",
    )
    repo.save(bundle)
    assert count(ready, "evidence_origin") == 0
    repo.save(bundle, origins=(origin,))
    repo.save(bundle, origins=(origin,))
    assert count(ready, "evidence_origin") == 1
    with pytest.raises(EvidenceBundleConflictError, match="origin conflict"):
        repo.save(bundle, origins=({**origin, "raw_bundle_digest": "b" * 64},))
    with pytest.raises(ModelError, match="live-lab"):
        repo.save(bundle, origins=({**origin, "acquisition_mode": "LIVE_LAB"},))
    assert repo.load(bundle.bundle_id) == bundle


def test_outer_transaction_is_not_committed(ready, bundle):
    with ready.transaction(force_rollback=True):
        PostgresEvidenceRepository(ready).save(bundle)
        assert count(ready, "evidence_bundle") == 1
    assert count(ready, "evidence_bundle") == 0


def test_concurrent_migrations_are_serialized(db):
    def apply(_):
        with psycopg.connect(db.info.dsn, autocommit=True) as connection:
            migrate(connection)

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(apply, range(2)))
    assert count(db, "evidence_schema_migrations") == 1


@pytest.mark.parametrize("conflict", [False, True])
def test_concurrent_saves_preserve_idempotency_or_report_conflict(ready, bundle, conflict):
    def save(value):
        with psycopg.connect(ready.info.dsn, autocommit=True) as connection:
            try:
                PostgresEvidenceRepository(connection).save(value)
                return "saved"
            except EvidenceBundleConflictError:
                return "conflict"

    other = replace(bundle, created_at="2026-11-11T12:00:00Z") if conflict else bundle
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(save, (bundle, other)))
    assert sorted(results) == (["conflict", "saved"] if conflict else ["saved", "saved"])
    assert count(ready, "evidence_bundle") == 1
    assert PostgresEvidenceRepository(ready).load(bundle.bundle_id) in (bundle, other)


def test_invalid_input_has_no_side_effects(ready):
    with pytest.raises(ModelError, match="expected EvidenceBundle"):
        PostgresEvidenceRepository(ready).save(evidence())
    assert count(ready, "evidence_bundle") == 0
