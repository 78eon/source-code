"""Generated inventory state over disposable canonical evidence/reconciliation."""

import secrets
from dataclasses import fields, replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql

from rlredteam.digital_twin.projection import dumps, loads
from rlredteam.digital_twin.reconciliation import EvidenceReference
from rlredteam.evidence.models import (
    EvidenceRecord,
    IdentifierType,
    ObservedAsset,
    ObservedIdentity,
    ObservedRelationship,
    ObservedService,
    ObservedSoftware,
)
from rlredteam.evidence.serialization import dumps as evidence_dumps
from rlredteam.knowledge.relations import RelationType
from rlredteam.knowledge.validation import ModelError
from rlredteam.storage import twin_migrations
from rlredteam.storage.entity_migrations import migrate as migrate_entities
from rlredteam.storage.entity_store import EntityReconciliationStore
from rlredteam.storage.evidence_migrations import migrate as migrate_evidence
from rlredteam.storage.twin_migrations import migrate
from rlredteam.storage.twin_store import PersistentTwinStore
from tests import test_entity_reconciliation as fixtures

db = fixtures.db


def now():
    return datetime.now(UTC).isoformat()


def asset_record(bundle):
    return next(r for r in bundle.records if isinstance(r, ObservedAsset))


def asset_ref(bundle):
    return EvidenceReference(
        bundle_id=bundle.bundle_id, evidence_id=asset_record(bundle).evidence_id
    )


def inventory(shared, port, product, version, *, relationship=RelationType.DEPENDS_ON):
    bundle = fixtures.make_bundle((shared,), value={"os": uuid4().hex})
    asset = bundle.records[0]
    base = {f.name: getattr(asset, f.name) for f in fields(EvidenceRecord)}

    def component(cls, **kwargs):
        return cls(
            **{
                **base,
                "evidence_id": "evidence:" + uuid4().hex,
                "subject_id": "subject:" + uuid4().hex,
                **kwargs,
            }
        )

    service = component(ObservedService, asset_id=asset.asset_id, port=port, protocol="tcp")
    software = component(
        ObservedSoftware,
        asset_id=asset.asset_id,
        product_id=product,
        version=version,
        attributes={"service_id": service.subject_id, "version_kind": "exact"},
    )
    identity = component(ObservedIdentity, asset_id=asset.asset_id, identity_type=uuid4().hex)
    relation = component(
        ObservedRelationship,
        source_asset_id=asset.asset_id,
        target_asset_id=asset.asset_id,
        relation_type=relationship,
    )
    return replace(bundle, records=(*bundle.records, service, software, identity, relation))


@pytest.fixture
def prepared(db):
    migrate_evidence(db)
    migrate_entities(db)
    migrate(db)
    entities = EntityReconciliationStore(db)
    shared = fixtures.identifier(IdentifierType.CLOUD_RESOURCE)
    port, product = secrets.randbelow(65535) + 1, "product:" + uuid4().hex
    versions = (uuid4().hex, uuid4().hex)
    bundles = tuple(inventory(shared, port, product, version) for version in versions)
    for bundle in bundles:
        entities.evidence.save(bundle)
    decision = entities.reconcile(tuple(asset_ref(b) for b in bundles), created_at=now())
    return PersistentTwinStore(db), bundles, decision, versions


def project(prepared, *, key=None, as_of=None):
    store, bundles, _, _ = prepared
    return store.refresh(
        key or "projection:" + uuid4().hex,
        tuple(b.bundle_id for b in bundles),
        as_of=as_of or now(),
    )


def test_multi_bundle_asset_identity_and_history_links(prepared):
    store, bundles, decision, versions = prepared
    snapshot = project(prepared)
    assert len(snapshot.assets) == 1
    assert snapshot.assets[0].stable_id == decision["entity_id"]
    assert len(snapshot.services) == len(snapshot.software) == 1
    assert snapshot.software[0].versions == (versions[-1],)
    assert snapshot.software[0].attributes["reported_versions"] == tuple(sorted(versions))
    assert snapshot.software[0].attributes["service_id"] == snapshot.services[0].stable_id
    assert snapshot.identities
    assert snapshot.relationships
    assert all(r.relation_type.value == "depends_on" for r in snapshot.relationships)
    assert {ref["bundle_id"] for ref in snapshot.evidence} == {b.bundle_id for b in bundles}
    assert decision["decision_id"] in snapshot.decision_ids
    assert store.load(snapshot.snapshot_id) == snapshot
    assert loads(dumps(snapshot)) == snapshot


def test_current_state_moves_but_identity_and_history_remain(prepared):
    store, bundles, decision, _ = prepared
    first = project(prepared)
    second = store.refresh(first.projection_key, [b.bundle_id for b in bundles], as_of=now())
    assert second.assets[0].stable_id == first.assets[0].stable_id == decision["entity_id"]
    assert store.current(first.projection_key) == second
    assert store.load(first.snapshot_id) == first
    assert store.history(first.projection_key) == (first.snapshot_id, second.snapshot_id)


def test_latest_snapshot_does_not_rewrite_previous_software_state(prepared):
    store, bundles, _, versions = prepared
    first = store.refresh("projection:" + uuid4().hex, (bundles[0].bundle_id,), as_of=now())
    second = store.refresh(first.projection_key, [b.bundle_id for b in bundles], as_of=now())
    assert first.software[0].versions == (versions[0],)
    assert second.software[0].versions == (versions[1],)
    assert store.load(first.snapshot_id).software[0].versions == (versions[0],)


def test_unresolved_evidence_is_not_assigned_an_asset(prepared):
    store, _, _, _ = prepared
    unresolved = fixtures.make_bundle((fixtures.identifier(IdentifierType.IPV4),))
    store.entities.evidence.save(unresolved)
    snapshot = store.refresh("projection:" + uuid4().hex, (unresolved.bundle_id,), as_of=now())
    assert snapshot.assets == snapshot.services == ()
    assert snapshot.unprojected[0]["evidence_id"] == unresolved.records[0].evidence_id
    assert store.load(snapshot.snapshot_id) == snapshot


def test_conflicting_observations_are_traceable(prepared):
    store, bundles, _, _ = prepared
    snapshot = project(prepared)
    assert {c.field_name for c in snapshot.conflicts} >= {"os", "version"}
    assert snapshot.assets[0].os == asset_record(bundles[-1]).value["os"]
    assert all(c.evidence_ids for c in snapshot.conflicts)
    assert all(store.entities.evidence.load(b.bundle_id) == b for b in bundles)


def test_idempotent_snapshot_persistence(prepared):
    store, bundles, _, _ = prepared
    snapshot = project(prepared)
    repeated = store.refresh(
        snapshot.projection_key, [b.bundle_id for b in reversed(bundles)], as_of=snapshot.as_of
    )
    assert repeated == snapshot
    assert store.history(snapshot.projection_key) == (snapshot.snapshot_id,)


def test_old_current_state_cannot_overwrite_newer_pointer(prepared):
    store, bundles, _, _ = prepared
    current = project(prepared)
    older = (
        datetime.fromisoformat(current.as_of.replace("Z", "+00:00")) - timedelta(days=1)
    ).isoformat()
    with pytest.raises(ModelError):
        store.refresh(current.projection_key, [b.bundle_id for b in bundles], as_of=older)
    assert store.current(current.projection_key) == current


def test_persisted_evidence_tables_are_unchanged(prepared):
    store, bundles, _, _ = prepared
    names = store.connection.execute(
        "SELECT tablename FROM pg_tables WHERE schemaname='normalized_evidence' ORDER BY tablename"
    ).fetchall()

    def state():
        return [
            store.connection.execute(
                sql.SQL(
                    "SELECT to_jsonb(t) FROM normalized_evidence.{} t ORDER BY to_jsonb(t)::text"
                ).format(sql.Identifier(name))
            ).fetchall()
            for (name,) in names
        ]

    before = state()
    project(prepared)
    assert state() == before
    assert all(
        evidence_dumps(store.entities.evidence.load(b.bundle_id)) == evidence_dumps(b)
        for b in bundles
    )


def test_explicit_migration_and_checksum(db, monkeypatch):
    PersistentTwinStore(db)
    assert db.execute("SELECT to_regnamespace('digital_twin_state')").fetchone()[0] is None
    with pytest.raises(ValueError, match="reconciliation migration"):
        migrate(db)
    migrate_evidence(db)
    migrate_entities(db)
    migrate(db)
    migrate(db)

    class Changed:
        def read_text(self):
            return uuid4().hex

    monkeypatch.setattr(twin_migrations, "MIGRATION_PATH", Changed())
    with pytest.raises(ValueError, match="checksum"):
        migrate(db)


def test_projection_failure_rolls_back_snapshot_and_pointer(prepared):
    store, bundles, _, _ = prepared
    current = project(prepared)
    store.connection.execute("""CREATE FUNCTION digital_twin_state.fail() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected Twin failure'; END $$""")
    store.connection.execute("""CREATE TRIGGER injected
        BEFORE INSERT ON digital_twin_state.component_state
        FOR EACH ROW EXECUTE FUNCTION digital_twin_state.fail()""")
    with pytest.raises(psycopg.Error, match="injected Twin failure"):
        store.refresh(current.projection_key, [b.bundle_id for b in bundles], as_of=now())
    assert store.current(current.projection_key) == current
    assert store.history(current.projection_key) == (current.snapshot_id,)


def test_no_attack_relationships_or_graph_tables(prepared):
    store, bundles, _, _ = prepared
    changed = replace(
        bundles[0],
        bundle_id="bundle:" + uuid4().hex,
        records=tuple(
            replace(r, relation_type=RelationType.CONNECTS_TO)
            if isinstance(r, ObservedRelationship)
            else r
            for r in bundles[0].records
        ),
    )
    store.entities.evidence.save(changed)
    store.entities.reconcile(
        (asset_ref(changed),), entity_id=prepared[2]["entity_id"], created_at=now()
    )
    snapshot = store.refresh("projection:" + uuid4().hex, (changed.bundle_id,), as_of=now())
    assert not snapshot.relationships
    assert any(r["reason"].startswith("unresolved endpoint") for r in snapshot.unprojected)
    assert not store.connection.execute(
        "SELECT tablename FROM pg_tables WHERE schemaname='public'"
    ).fetchall()


@pytest.mark.parametrize(
    "table,column", [("asset_state", "entity_id"), ("component_state", "component_id")]
)
def test_projection_corruption_is_detected(prepared, table, column):
    store, _, _, _ = prepared
    snapshot = project(prepared)
    store.connection.execute(
        sql.SQL("UPDATE digital_twin_state.{} SET document='{{}}'::jsonb").format(
            sql.Identifier(table)
        )
    )
    with pytest.raises(ModelError, match="projection mismatch"):
        store.load(snapshot.snapshot_id)


def test_component_identity_stays_stable_across_snapshots(prepared):
    store, bundles, _, _ = prepared
    first = project(prepared)
    second = store.refresh(first.projection_key, [b.bundle_id for b in bundles], as_of=now())
    assert first.services[0].stable_id == second.services[0].stable_id
    assert first.software[0].stable_id == second.software[0].stable_id


def test_simultaneous_version_conflict_does_not_choose_arbitrarily(prepared):
    store, bundles, decision, _ = prepared
    at = now()
    changed = []
    for bundle in bundles:
        candidate = replace(
            bundle,
            bundle_id="bundle:" + uuid4().hex,
            records=tuple(replace(r, observed_at=at, imported_at=at) for r in bundle.records),
        )
        store.entities.evidence.save(candidate)
        changed.append(candidate)
    store.entities.reconcile(
        tuple(asset_ref(b) for b in changed), entity_id=decision["entity_id"], created_at=now()
    )
    snapshot = store.refresh(
        "projection:" + uuid4().hex, [b.bundle_id for b in changed], as_of=now()
    )
    assert snapshot.software[0].versions == ()
    assert any(c.field_name == "version" for c in snapshot.conflicts)


def test_latest_unknown_software_version_is_not_filled_from_history(prepared):
    store, bundles, decision, _ = prepared
    at = now()
    candidate = replace(
        bundles[-1],
        bundle_id="bundle:" + uuid4().hex,
        records=tuple(
            replace(
                r,
                observed_at=at,
                imported_at=at,
                **({"version": None} if isinstance(r, ObservedSoftware) else {}),
            )
            for r in bundles[-1].records
        ),
    )
    store.entities.evidence.save(candidate)
    store.entities.reconcile(
        (asset_ref(candidate),), entity_id=decision["entity_id"], created_at=now()
    )
    snapshot = store.refresh(
        "projection:" + uuid4().hex, [b.bundle_id for b in (*bundles, candidate)], as_of=now()
    )
    assert snapshot.software[0].versions == ()
    assert snapshot.software[0].attributes["reported_versions"]


def test_projection_keys_have_independent_current_pointers(prepared):
    store, _, _, _ = prepared
    first, second = project(prepared), project(prepared)
    assert first.projection_key != second.projection_key
    assert store.current(first.projection_key) == first
    assert store.current(second.projection_key) == second


def test_link_corruption_is_detected(prepared):
    store, _, _, _ = prepared
    snapshot = project(prepared)
    store.connection.execute(
        "UPDATE digital_twin_state.snapshot_evidence SET bundle_digest=%s WHERE snapshot_id=%s",
        (secrets.token_hex(32), snapshot.snapshot_id),
    )
    with pytest.raises(ModelError, match="evidence linkage mismatch"):
        store.load(snapshot.snapshot_id)
