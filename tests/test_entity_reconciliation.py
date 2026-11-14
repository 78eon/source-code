"""Generated identity fixtures over disposable PostgreSQL; no live acquisition."""

import ipaddress
import secrets
from concurrent.futures import ThreadPoolExecutor
from dataclasses import fields, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import psycopg
import pytest

from rlredteam.digital_twin.reconciliation import EvidenceReference, assess
from rlredteam.evidence.models import (
    AssetIdentifier,
    EvidenceBundle,
    EvidenceRecord,
    EvidenceSource,
    EvidenceStatus,
    IdentifierType,
    IdentityStatus,
    ObservedAsset,
    Provenance,
)
from rlredteam.evidence.serialization import dumps
from rlredteam.knowledge.models import SourceType
from rlredteam.knowledge.validation import ModelError
from rlredteam.storage import entity_migrations
from rlredteam.storage.entity_migrations import migrate
from rlredteam.storage.entity_store import EntityReconciliationStore
from rlredteam.storage.evidence_migrations import migrate as migrate_evidence
from tests import test_evidence_postgres

db = test_evidence_postgres.db


def identifier(kind):
    if kind == IdentifierType.IPV4:
        value = str(ipaddress.IPv4Address(secrets.randbits(32)))
    elif kind == IdentifierType.HOSTNAME:
        value = secrets.token_hex(8) + "." + secrets.token_hex(8)
    elif kind == IdentifierType.MAC:
        value = ":".join(f"{octet:02x}" for octet in secrets.token_bytes(6))
    else:
        value = uuid4().hex
    return AssetIdentifier(identifier_type=kind, value=value)


def make_bundle(identifiers=(), *, record_id=None, subject_id=None, value=None):
    at = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    source_id = "source:" + uuid4().hex
    record = ObservedAsset(
        evidence_id=record_id or "evidence:" + uuid4().hex,
        subject_id=subject_id or "subject:" + uuid4().hex,
        observation_type="asset_hint",
        value=value or {},
        status=EvidenceStatus.OBSERVED,
        confidence=(secrets.randbelow(99) + 1) / 100,
        source_id=source_id,
        observed_at=at,
        imported_at=at,
        provenance=Provenance(source_ids=(source_id,), activity="generated-fixture", version="1"),
        identifiers=tuple(identifiers),
        identity_status=IdentityStatus.EXACT,
    )
    bundle = EvidenceBundle(
        bundle_id="bundle:" + uuid4().hex,
        created_at=at,
        sources=(
            EvidenceSource(
                source_id=source_id,
                source_type=SourceType.INTERNAL,
                title=uuid4().hex,
                publisher=uuid4().hex,
                imported_at=at,
            ),
        ),
        records=(record,),
    )
    return bundle


def ref(bundle):
    return EvidenceReference(bundle_id=bundle.bundle_id, evidence_id=bundle.records[0].evidence_id)


@pytest.fixture
def store(db):
    migrate_evidence(db)
    migrate(db)
    return EntityReconciliationStore(db)


def save(store, *bundles):
    for bundle in bundles:
        store.evidence.save(bundle)


def reconcile(store, bundles, **kwargs):
    return store.reconcile(
        tuple(ref(bundle) for bundle in bundles), created_at=datetime.now(UTC).isoformat(), **kwargs
    )


@pytest.mark.parametrize(
    "kind", [IdentifierType.IPV4, IdentifierType.HOSTNAME, IdentifierType.USER_DEFINED]
)
def test_weak_overlap_never_establishes_identity(store, kind):
    shared = identifier(kind)
    bundles = (make_bundle((shared,)), make_bundle((shared,)))
    save(store, *bundles)
    decision = reconcile(store, bundles)
    assert decision["state"] in {"POSSIBLE_MATCH", "UNRESOLVED"}
    assert decision["entity_id"] is None
    assert store.asset_ids(bundles[0].bundle_id) == {}


@pytest.mark.parametrize("kind", [IdentifierType.MAC, IdentifierType.CLOUD_RESOURCE])
def test_strong_identity_spans_bundles_and_survives_reload(store, kind):
    shared = identifier(kind)
    bundles = (make_bundle((shared,)), make_bundle((shared,)))
    save(store, *bundles)
    before = [dumps(store.evidence.load(bundle.bundle_id)) for bundle in bundles]
    result = reconcile(store, bundles)
    assert result["state"] == "MATCH"
    assert UUID(result["entity_id"].removeprefix("asset:")).version == 4
    assert result["entity_id"] not in {r.subject_id for b in bundles for r in b.records}
    assert store.load_decision(result["decision_id"]) == result
    assert len(store.members(result["entity_id"])) == 2
    assert [dumps(store.evidence.load(b.bundle_id)) for b in bundles] == before
    assert all(
        store.asset_ids(b.bundle_id) == {b.records[0].subject_id: result["entity_id"]}
        for b in bundles
    )


def test_one_bundle_can_remain_unresolved(store):
    bundle = make_bundle()
    save(store, bundle)
    result = reconcile(store, (bundle,))
    assert result["state"] == "UNRESOLVED"
    assert result["entity_id"] is None
    assert (
        store.load_decision(result["decision_id"])["evidence"][0]["bundle_id"] == bundle.bundle_id
    )


def test_identical_local_subject_ids_are_not_global_identity(store):
    subject, record_id = "subject:" + uuid4().hex, "evidence:" + uuid4().hex
    bundles = (
        make_bundle(subject_id=subject, record_id=record_id),
        make_bundle(subject_id=subject, record_id=record_id),
    )
    save(store, *bundles)
    result = reconcile(store, bundles)
    assert result["entity_id"] is None
    assert len(result["evidence"]) == 2


def test_conflicting_strong_identifiers_block_assignment(store):
    shared = identifier(IdentifierType.MAC)
    bundles = tuple(
        make_bundle((shared, identifier(IdentifierType.CLOUD_RESOURCE))) for _ in range(2)
    )
    save(store, *bundles)
    result = reconcile(store, bundles)
    assert result["state"] == "CONFLICT"
    assert result["entity_id"] is None


def test_conflicting_observed_fields_are_preserved_and_explained(store):
    shared = identifier(IdentifierType.CLOUD_RESOURCE)
    bundles = tuple(make_bundle((shared,), value={"os": uuid4().hex}) for _ in range(2))
    save(store, *bundles)
    result = reconcile(store, bundles)
    assert result["state"] == "MATCH"
    assert result["comparisons"][0]["conflicting_fields"] == ["os"]
    assert all(store.evidence.load(b.bundle_id) == b for b in bundles)


def test_extension_reuses_entity_and_checks_all_previous_evidence(store):
    shared = identifier(IdentifierType.CLOUD_RESOURCE)
    bundles = tuple(make_bundle((shared,)) for _ in range(3))
    save(store, *bundles)
    first = reconcile(store, bundles[:2])
    extended = reconcile(store, bundles[2:], entity_id=first["entity_id"])
    assert extended["entity_id"] == first["entity_id"]
    assert len(extended["evidence"]) == 3
    assert store.load_decision(first["decision_id"]) == first


def test_transitive_conflict_cannot_join_existing_entity(store):
    shared, cloud = identifier(IdentifierType.MAC), identifier(IdentifierType.CLOUD_RESOURCE)
    bundles = (make_bundle((shared, cloud)), make_bundle((shared,)))
    save(store, *bundles)
    first = reconcile(store, bundles)
    contradicting = make_bundle((shared, identifier(IdentifierType.CLOUD_RESOURCE)))
    save(store, contradicting)
    denied = reconcile(store, (contradicting,), entity_id=first["entity_id"])
    assert denied["state"] == "CONFLICT"
    assert denied["entity_id"] is None
    assert len(store.members(first["entity_id"])) == 2


def test_unrelated_assets_stay_separate(store):
    bundles = tuple(make_bundle((identifier(IdentifierType.CLOUD_RESOURCE),)) for _ in range(2))
    save(store, *bundles)
    assert reconcile(store, bundles)["state"] == "NO_MATCH"


def test_unknown_and_non_asset_references_rejected(store):
    missing = EvidenceReference(
        bundle_id="bundle:" + uuid4().hex, evidence_id="evidence:" + uuid4().hex
    )
    with pytest.raises(KeyError):
        store.reconcile((missing,), created_at=datetime.now(UTC).isoformat())
    bundle = make_bundle()
    generic = EvidenceRecord(
        **{f.name: getattr(bundle.records[0], f.name) for f in fields(EvidenceRecord)}
    )
    bundle = replace(bundle, records=(generic,))
    save(store, bundle)
    with pytest.raises(ModelError, match="persisted ObservedAsset"):
        reconcile(store, (bundle,))


def test_duplicate_references_rejected(store):
    bundle = make_bundle()
    save(store, bundle)
    with pytest.raises(ModelError, match="duplicate"):
        reconcile(store, (bundle, bundle))


def test_pure_assessment_is_deterministic_and_immutable():
    shared = identifier(IdentifierType.MAC)
    bundles = (make_bundle((shared,)), make_bundle((shared,)))
    values = tuple((ref(b), b.records[0]) for b in bundles)
    at = datetime.now(UTC).isoformat()
    before = tuple(dumps(b) for b in bundles)
    assert assess(values, created_at=at) == assess(tuple(reversed(values)), created_at=at)
    assert tuple(dumps(b) for b in bundles) == before


def test_migrations_explicit_idempotent_and_checksum_checked(db, monkeypatch):
    EntityReconciliationStore(db)
    with pytest.raises(ValueError, match="canonical evidence migration"):
        migrate(db)
    migrate_evidence(db)
    migrate(db)
    migrate(db)

    class Changed:
        def read_text(self):
            return uuid4().hex

    monkeypatch.setattr(entity_migrations, "MIGRATION_PATH", Changed())
    with pytest.raises(ValueError, match="checksum mismatch"):
        migrate(db)


def test_decision_failure_rolls_back_entity_and_members(store):
    shared = identifier(IdentifierType.MAC)
    bundles = (make_bundle((shared,)), make_bundle((shared,)))
    save(store, *bundles)
    store.connection.execute("""CREATE FUNCTION entity_reconciliation.fail() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected decision failure'; END $$""")
    store.connection.execute("""CREATE TRIGGER injected
        BEFORE INSERT ON entity_reconciliation.decision
        FOR EACH ROW EXECUTE FUNCTION entity_reconciliation.fail()""")
    with pytest.raises(psycopg.Error, match="injected decision failure"):
        reconcile(store, bundles)
    assert (
        store.connection.execute("SELECT count(*) FROM entity_reconciliation.asset").fetchone()[0]
        == 0
    )
    assert all(store.evidence.load(b.bundle_id) == b for b in bundles)


def test_concurrent_assignment_cannot_split_identity(store):
    shared = identifier(IdentifierType.MAC)
    bundles = (make_bundle((shared,)), make_bundle((shared,)))
    save(store, *bundles)

    def assign(_):
        with psycopg.connect(store.connection.info.dsn, autocommit=True) as conn:
            return reconcile(EntityReconciliationStore(conn), bundles)["entity_id"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        ids = list(pool.map(assign, range(2)))
    assert len(set(ids)) == 1


def test_rule_and_support_metadata_are_persistent(store):
    shared = identifier(IdentifierType.MAC)
    bundles = (make_bundle((shared,)), make_bundle((shared,)))
    save(store, *bundles)
    result = reconcile(store, bundles)
    restored = store.load_decision(result["decision_id"])
    assert restored["rule_version"]
    assert restored["policy_version"]
    assert 0 <= restored["confidence"] <= 1
    assert restored["comparisons"][0]["rules"]
    assert all(len(item["bundle_digest"]) == 64 for item in restored["evidence"])


def test_no_graph_or_research_tables_created(store):
    tables = store.connection.execute(
        "SELECT schemaname,tablename FROM pg_tables "
        "WHERE schemaname IN ('public','entity_reconciliation')"
    ).fetchall()
    assert not any(schema == "public" for schema, _ in tables)
    assert {table for _, table in tables} == {
        "asset",
        "decision",
        "evidence_reference",
        "asset_evidence",
        "schema_migrations",
    }


def test_every_persisted_evidence_projection_remains_immutable(store):
    from psycopg import sql

    shared = identifier(IdentifierType.MAC)
    bundles = (make_bundle((shared,)), make_bundle((shared,)))
    save(store, *bundles)
    tables = store.connection.execute(
        "SELECT tablename FROM pg_tables WHERE schemaname='normalized_evidence' ORDER BY tablename"
    ).fetchall()

    def snapshot():
        return [
            store.connection.execute(
                sql.SQL(
                    "SELECT to_jsonb(t) FROM normalized_evidence.{} t ORDER BY to_jsonb(t)::text"
                ).format(sql.Identifier(name))
            ).fetchall()
            for (name,) in tables
        ]

    before = snapshot()
    reconcile(store, bundles)
    assert snapshot() == before


def test_existing_entities_cannot_be_merged_implicitly(store):
    groups = []
    for _ in range(2):
        shared = identifier(IdentifierType.MAC)
        bundles = (make_bundle((shared,)), make_bundle((shared,)))
        save(store, *bundles)
        reconcile(store, bundles)
        groups.append(bundles)
    with pytest.raises(ModelError, match="automatic merging"):
        reconcile(store, (groups[0][0], groups[1][0]))


def test_decision_integrity_is_checked(store):
    bundle = make_bundle()
    save(store, bundle)
    result = reconcile(store, (bundle,))
    store.connection.execute(
        "UPDATE entity_reconciliation.decision SET rule_version=%s WHERE decision_id=%s",
        (uuid4().hex, result["decision_id"]),
    )
    with pytest.raises(ModelError, match="integrity mismatch"):
        store.load_decision(result["decision_id"])
