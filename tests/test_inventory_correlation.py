"""Generated inventory/knowledge over disposable PostgreSQL; no acquisition."""

import secrets
from dataclasses import fields, replace
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql

from rlredteam.digital_twin.graph import dumps as graph_dumps
from rlredteam.digital_twin.graph import project_snapshot
from rlredteam.digital_twin.projection import dumps as twin_dumps
from rlredteam.evidence.models import ApplicabilityStatus as S
from rlredteam.evidence.models import EvidenceRecord, IdentifierType, ObservedSoftware, Provenance
from rlredteam.evidence.serialization import dumps as evidence_dumps
from rlredteam.knowledge.models import KnowledgeSource, SourceType
from rlredteam.knowledge.serialization import digest
from rlredteam.knowledge.validation import ModelError
from rlredteam.knowledge.vulnerabilities.constraints import VersionConstraint, VersionOperator
from rlredteam.knowledge.vulnerabilities.models import (
    AffectedProduct,
    DefaultStatus,
    KnowledgeKind,
    VulnerabilityKnowledgeEntry,
    product_id,
)
from rlredteam.knowledge.vulnerabilities.registry import VulnerabilityKnowledgeRegistry
from rlredteam.knowledge.vulnerabilities.snapshot import freeze
from rlredteam.storage import correlation_migrations
from rlredteam.storage.correlation_migrations import migrate
from rlredteam.storage.correlation_store import InventoryCorrelationStore
from rlredteam.storage.entity_migrations import migrate as migrate_entities
from rlredteam.storage.evidence_migrations import migrate as migrate_evidence
from rlredteam.storage.twin_migrations import migrate as migrate_twins
from rlredteam.vulnerability.correlation import dumps, loads
from rlredteam.vulnerability.cpe import literal_cpe
from rlredteam.vulnerability.models import ConfirmationEvidence, ConfirmationType, TrustLevel
from tests import test_persistent_twin as fixtures

db = fixtures.db


def release():
    return ".".join(str(secrets.randbelow(1000) + 1) for _ in range(3))


def knowledge(vendor, product, version, *, count=1):
    source_id = "source:" + uuid4().hex
    provenance = Provenance(source_ids=(source_id,), activity="generated-test", version="1")
    constraint = VersionConstraint(
        constraint_id="constraint:" + uuid4().hex,
        operator=VersionOperator.EXACT,
        version=version,
        provenance=provenance,
    )
    affected = AffectedProduct(
        product_id=product_id(vendor, product),
        vendor=vendor,
        product=product,
        version_constraints=(constraint,),
        default_status=DefaultStatus.NOT_AFFECTED,
        provenance=provenance,
    )
    entries = tuple(
        VulnerabilityKnowledgeEntry(
            vulnerability_id="SYNTH-VULN-" + uuid4().hex,
            knowledge_kind=KnowledgeKind.SYNTHETIC_TEST,
            affected_products=(affected,),
            source_ids=(source_id,),
            source_version="1",
            source_revision="1",
            provenance=provenance,
        )
        for _ in range(count)
    )
    source = KnowledgeSource(
        source_id=source_id,
        source_type=SourceType.INTERNAL,
        title=uuid4().hex,
        publisher=uuid4().hex,
        imported_at=fixtures.now(),
        content_hash=secrets.token_hex(32),
        upstream_version="1",
        upstream_revision="1",
    )
    return freeze(
        VulnerabilityKnowledgeRegistry(entries=entries, sources=(source,)),
        created_at=fixtures.now(),
    )


@pytest.fixture
def ready(db):
    migrate_evidence(db)
    migrate_entities(db)
    migrate_twins(db)
    migrate(db)
    return InventoryCorrelationStore(db)


def inventory(
    store,
    *,
    vendor=None,
    product=None,
    version=None,
    cpe=False,
    confirmation=False,
    assets=1,
    missing_version=False,
    missing_vendor=False,
    service_only=False,
    transform_software=None,
):
    vendor, product, version = vendor or uuid4().hex, product or uuid4().hex, version or release()
    bundles, confirmations = [], []
    for _ in range(assets):
        shared = fixtures.fixtures.identifier(IdentifierType.CLOUD_RESOURCE)
        port = secrets.randbelow(65535) + 1
        members = []
        for _ in range(2):
            bundle = fixtures.inventory(shared, port, product, version)
            software = next(r for r in bundle.records if isinstance(r, ObservedSoftware))
            value = dict(product=product, version=None if missing_version else version)
            if not missing_vendor:
                value["vendor"] = vendor
            if cpe:
                value["cpes"] = (f"cpe:/a:{vendor}:{product}:{version}",)
            software = replace(software, value=value, version=None if missing_version else version)
            if transform_software:
                software = transform_software(software)
            records = tuple(
                software if isinstance(r, ObservedSoftware) else r for r in bundle.records
            )
            if service_only:
                from rlredteam.evidence.models import ObservedService

                records = tuple(
                    replace(r, value=value) if isinstance(r, ObservedService) else r
                    for r in records
                    if not isinstance(r, ObservedSoftware)
                )
            if confirmation:
                identifier = "evidence:" + uuid4().hex
                kind = ConfirmationType.AUTHENTICATED_INVENTORY
                record = EvidenceRecord(
                    **{
                        **{f.name: getattr(software, f.name) for f in fields(EvidenceRecord)},
                        "evidence_id": identifier,
                        "observation_type": kind.value,
                        "value": dict(
                            software_evidence_id=software.evidence_id,
                            asset_id=software.asset_id,
                            product_id=software.product_id,
                            version=software.version,
                            software_evidence_hash=digest(software),
                        ),
                        "attributes": {"trust_level": TrustLevel.AUTHORITATIVE.value},
                    }
                )
                records = (*records, record)
                confirmations.append(
                    (
                        bundle.bundle_id,
                        ConfirmationEvidence(
                            evidence_id=identifier,
                            evidence_type=kind,
                            subject_id=software.subject_id,
                            source=record.source_id,
                            trust_level=TrustLevel.AUTHORITATIVE,
                            provenance=Provenance(
                                source_ids=(record.source_id,),
                                evidence_ids=(identifier,),
                                activity="generated-test",
                                version="1",
                            ),
                        ),
                    )
                )
            bundle = replace(bundle, records=records)
            store.twins.entities.evidence.save(bundle)
            bundles.append(bundle)
            members.append(bundle)
        store.twins.entities.reconcile(
            tuple(fixtures.asset_ref(b) for b in members), created_at=fixtures.now()
        )
    snapshot = store.twins.refresh(
        "projection:" + uuid4().hex, [b.bundle_id for b in bundles], as_of=fixtures.now()
    )
    return snapshot, bundles, tuple(confirmations), knowledge(vendor, product, version)


def build(store, snapshot, knowledge, **kwargs):
    return store.build(snapshot.snapshot_id, knowledge, **kwargs)


def test_exact_observation_is_likely_not_confirmed(ready):
    snapshot, _, _, known = inventory(ready)
    result = build(ready, snapshot, known)
    assert len(result.assessments) == 1
    assert result.assessments[0].applicability_status == S.LIKELY
    assert loads(dumps(result)) == result


def test_confirmed_requires_recorded_inventory_and_explicit_trust(ready):
    snapshot, _, confirmations, known = inventory(ready, confirmation=True)
    assert (
        build(ready, snapshot, known, confirmations=confirmations)
        .assessments[0]
        .applicability_status
        == S.LIKELY
    )
    trusted = tuple((b, c.source) for b, c in confirmations)
    result = build(
        ready, snapshot, known, confirmations=confirmations, trusted_inventory_sources=trusted
    )
    assessment = result.assessments[0]
    assert assessment.applicability_status == S.CONFIRMED
    assert assessment.rule_ids == ("confirmation-v1",)
    assert assessment.provenance.attributes["confirmation_ids"]
    ready.save(result)
    assert ready.rebuild(result.correlation_id) == result


@pytest.mark.parametrize("changes", [dict(missing_version=True), dict(missing_vendor=True)])
def test_insufficient_evidence_stays_unknown(ready, changes):
    snapshot, _, _, known = inventory(ready, **changes)
    result = build(ready, snapshot, known)
    assert result.assessments
    assert all(a.applicability_status == S.UNKNOWN for a in result.assessments)
    assert not any(a.conflicting_evidence_ids for a in result.assessments)


def test_version_mismatch_does_not_match(ready):
    snapshot, _, _, known = inventory(ready)
    affected = known.entries[0].affected_products[0]
    other = release()
    while other == snapshot.software[0].versions[0]:
        other = release()
    different = knowledge(affected.vendor, affected.product, other)
    assert build(ready, snapshot, different).assessments[0].applicability_status == S.NOT_APPLICABLE


def test_multiple_vulnerabilities_and_separate_assets(ready):
    snapshot, _, _, known = inventory(ready, assets=2)
    p = known.entries[0].affected_products[0]
    known = knowledge(p.vendor, p.product, snapshot.software[0].versions[0], count=3)
    result = build(ready, snapshot, known)
    assert len(result.assessments) == 6
    assert {a.asset_id for a in result.assessments} == {a.stable_id for a in snapshot.assets}
    assert all(a.applicability_status == S.LIKELY for a in result.assessments)
    assert len({a.vulnerability_id for a in result.assessments}) == 3


@pytest.mark.parametrize("service_only", [False, True])
def test_literal_cpe_and_service_input(ready, service_only):
    snapshot, _, _, known = inventory(ready, cpe=True, service_only=service_only)
    result = build(ready, snapshot, known)
    assert result.assessments[0].applicability_status == S.LIKELY
    assert bool(result.assessments[0].software_id) != service_only


def test_provenance_and_deterministic_rebuild_leave_inputs_immutable(ready):
    snapshot, bundles, _, known = inventory(ready)
    graph = project_snapshot(snapshot)
    before = (twin_dumps(snapshot), graph_dumps(graph), tuple(evidence_dumps(b) for b in bundles))
    result = build(ready, snapshot, known, graph=graph)
    assert result == build(ready, snapshot, known, graph=graph)
    ready.save(result)
    ready.save(result)
    restarted = InventoryCorrelationStore(ready.connection)
    assert (
        restarted.load(result.correlation_id) == restarted.rebuild(result.correlation_id) == result
    )
    assessment = result.assessments[0]
    assert assessment.provenance.attributes["twin_snapshot_id"] == snapshot.snapshot_id
    assert assessment.provenance.attributes["graph_node_id"] in {n.node_id for n in graph.nodes}
    assert result.decision_ids == snapshot.decision_ids
    assert set(assessment.supporting_evidence_ids) <= {r["support_id"] for r in result.evidence}
    assert all(
        r["bundle_digest"] == snapshot.bundle_digests[r["bundle_id"]] for r in result.evidence
    )
    assert (
        twin_dumps(ready.twins.load(snapshot.snapshot_id)),
        graph_dumps(graph),
        tuple(evidence_dumps(ready.twins.entities.evidence.load(b.bundle_id)) for b in bundles),
    ) == before
    assert not ready.connection.execute(
        "SELECT tablename FROM pg_tables WHERE schemaname='public'"
    ).fetchall()


def test_unmatched_catalogue_is_unresolved_without_invented_vulnerability(ready):
    snapshot, _, _, _ = inventory(ready)
    result = build(ready, snapshot, knowledge(uuid4().hex, uuid4().hex, release()))
    assert not result.assessments
    assert result.unresolved[0]["status"] == S.UNKNOWN


def test_graph_from_different_snapshot_rejected(ready):
    first, _, _, known = inventory(ready)
    second, _, _, _ = inventory(ready)
    with pytest.raises(ModelError, match="graph does not match"):
        build(ready, first, known, graph=project_snapshot(second))


@pytest.mark.parametrize("mode", ["unsupported_cpe", "cpe_version_conflict", "partial_version"])
def test_weak_or_contradictory_identification_remains_unknown(ready, mode):
    def change(record):
        raw = dict(record.value)
        if mode == "unsupported_cpe":
            raw["cpes"] = ("cpe:/a:*:*:*",)
        elif mode == "cpe_version_conflict":
            different = record.version + "." + str(secrets.randbelow(1000) + 1)
            raw["cpes"] = (f'cpe:/a:{raw["vendor"]}:{raw["product"]}:{different}',)
        else:
            return replace(record, version=record.version.rsplit(".", 1)[0])
        return replace(record, value=raw)

    snapshot, _, _, known = inventory(ready, transform_software=change)
    assert build(ready, snapshot, known).assessments[0].applicability_status == S.UNKNOWN


def test_conflicting_versions_remain_traceable_and_never_confirm(ready):
    versions = iter((release(), release()))
    snapshot, bundles, confirmations, known = inventory(
        ready, confirmation=True, transform_software=lambda r: replace(r, version=next(versions))
    )
    assert snapshot.conflicts
    result = build(
        ready,
        snapshot,
        known,
        confirmations=confirmations,
        trusted_inventory_sources=tuple((b, c.source) for b, c in confirmations),
    )
    assert result.assessments[0].applicability_status == S.UNKNOWN
    assert result.assessments[0].conflicting_evidence_ids
    assert len({r["bundle_id"] for r in result.evidence}) == len(bundles)
    ready.save(result)
    assert ready.load(result.correlation_id) == result


def test_disagreeing_knowledge_sources_remain_unknown(ready):
    snapshot, _, _, first = inventory(ready)
    p = first.entries[0].affected_products[0]
    second = knowledge(p.vendor, p.product, snapshot.software[0].versions[0] + ".1")
    sources = (*first.sources, *second.sources)
    source_ids = tuple(sorted(s.source_id for s in sources))
    provenance = replace(p.provenance, source_ids=source_ids)
    product = replace(
        p,
        provenance=provenance,
        version_constraints=(
            *p.version_constraints,
            *second.entries[0].affected_products[0].version_constraints,
        ),
    )
    entry = replace(
        first.entries[0], source_ids=source_ids, provenance=provenance, affected_products=(product,)
    )
    combined = freeze(
        VulnerabilityKnowledgeRegistry(entries=(entry,), sources=sources), created_at=fixtures.now()
    )
    assessment = build(ready, snapshot, combined).assessments[0]
    assert assessment.applicability_status == S.UNKNOWN
    assert assessment.provenance.attributes["knowledge_conflicts"]


def test_confirmation_binding_mismatch_is_rejected(ready):
    snapshot, _, confirmations, known = inventory(ready, confirmation=True)
    bundle, original = confirmations[-1]
    changed = replace(original, trust_level=TrustLevel.UNVERIFIED)
    with pytest.raises(ModelError, match="trust differs"):
        build(ready, snapshot, known, confirmations=((bundle, changed),))


def test_reconciliation_links_are_asset_specific(ready):
    snapshot, _, _, known = inventory(ready, assets=2)
    batch = build(ready, snapshot, known)
    decision_sets = []
    for assessment in batch.assessments:
        identifiers = assessment.provenance.attributes["reconciliation_decision_ids"]
        assert identifiers
        assert all(
            ready.twins.entities.load_decision(key)["entity_id"] == assessment.asset_id
            for key in identifiers
        )
        decision_sets.append(set(identifiers))
    assert not decision_sets[0] & decision_sets[1]


def test_unresolved_assets_create_no_applicability(ready):
    bundle = fixtures.fixtures.make_bundle((fixtures.fixtures.identifier(IdentifierType.IPV4),))
    ready.twins.entities.evidence.save(bundle)
    snapshot = ready.twins.refresh(
        "projection:" + uuid4().hex, (bundle.bundle_id,), as_of=fixtures.now()
    )
    known = knowledge(uuid4().hex, uuid4().hex, release())
    batch = build(ready, snapshot, known)
    assert not batch.assessments
    assert not project_snapshot(snapshot).nodes
    assert snapshot.unprojected


def test_cpe_23_literal_and_qualified_bindings():
    vendor, product, version = uuid4().hex, uuid4().hex, release()
    assert literal_cpe(f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*") == (
        vendor,
        product,
        version,
    )
    assert literal_cpe(f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:{uuid4().hex}:*:*:*") is None


@pytest.mark.parametrize("table", ["assessment", "evidence_reference", "decision_reference"])
def test_derived_projection_tampering_is_detected(ready, table):
    snapshot, _, _, known = inventory(ready)
    batch = build(ready, snapshot, known)
    ready.save(batch)
    ready.connection.execute(
        sql.SQL("DELETE FROM vulnerability_correlation.{}").format(sql.Identifier(table))
    )
    with pytest.raises(ModelError, match="projection mismatch"):
        ready.load(batch.correlation_id)


def test_explicit_migration_and_checksum(db, monkeypatch):
    InventoryCorrelationStore(db)
    assert db.execute("SELECT to_regnamespace('vulnerability_correlation')").fetchone()[0] is None
    with pytest.raises(ValueError, match="Twin migration"):
        migrate(db)
    migrate_evidence(db)
    migrate_entities(db)
    migrate_twins(db)
    migrate(db)
    migrate(db)

    class Changed:
        def read_text(self):
            return uuid4().hex

    monkeypatch.setattr(correlation_migrations, "MIGRATION_PATH", Changed())
    with pytest.raises(ValueError, match="checksum"):
        migrate(db)


def test_transaction_rolls_back_failed_projection(ready):
    snapshot, _, _, known = inventory(ready)
    batch = build(ready, snapshot, known)
    ready.connection.execute("""CREATE FUNCTION vulnerability_correlation.fail() RETURNS trigger
        LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected correlation failure'; END $$""")
    ready.connection.execute("""CREATE TRIGGER injected BEFORE INSERT ON
        vulnerability_correlation.assessment FOR EACH ROW
        EXECUTE FUNCTION vulnerability_correlation.fail()""")
    with pytest.raises(psycopg.Error, match="injected correlation failure"):
        ready.save(batch)
    assert not ready.connection.execute("SELECT 1 FROM vulnerability_correlation.batch").fetchall()


@pytest.mark.parametrize("suffix", ["*", "-", "escaped\\name", "%encoded"])
def test_unsupported_cpe_identity_is_not_guessed(suffix):
    vendor = uuid4().hex
    assert literal_cpe(f"cpe:/a:{vendor}:{suffix}:{release()}") is None


def test_no_execution_or_attack_path_imports():
    import ast
    from pathlib import Path

    from rlredteam.vulnerability import correlation

    tree = ast.parse(Path(correlation.__file__).read_text())
    imports = [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    assert not any(
        any(word in module for word in ("attack_path", "causal", "mitre", "enterprise.live"))
        for module in imports
    )
