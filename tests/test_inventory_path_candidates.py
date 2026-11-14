"""Generated candidates from disposable persisted inventory, never live targets."""

import ast
from dataclasses import replace
from pathlib import Path

import pytest
from psycopg import sql

from rlredteam.digital_twin.graph import dumps as graph_dumps
from rlredteam.digital_twin.graph import project_snapshot
from rlredteam.digital_twin.path_candidates import dumps, generate_candidates, loads, rebuild
from rlredteam.evidence.models import ApplicabilityStatus as S
from rlredteam.knowledge.serialization import digest
from rlredteam.knowledge.validation import ModelError
from rlredteam.storage.path_candidates import load_candidate_paths
from tests import test_inventory_correlation as fixtures

db = fixtures.db
ready = fixtures.ready


def prepared(store, **kwargs):
    snapshot, bundles, confirmations, knowledge = fixtures.inventory(store, **kwargs)
    graph = project_snapshot(snapshot)
    correlation = store.build(
        snapshot.snapshot_id,
        knowledge,
        confirmations=confirmations,
        trusted_inventory_sources=tuple((b, c.source) for b, c in confirmations),
    )
    store.save(correlation)
    return snapshot, graph, correlation


def candidates(snapshot, graph, correlation, **kwargs):
    return generate_candidates(
        graph, correlation, source_ids=(snapshot.assets[0].stable_id,), **kwargs
    )


def test_deterministic_rebuild_and_serialization(ready):
    snapshot, graph, correlation = prepared(ready)
    value = candidates(snapshot, graph, correlation)
    assert value == candidates(snapshot, graph, correlation)
    assert value == rebuild(value) == loads(dumps(value))
    assert value == load_candidate_paths(
        ready, correlation.correlation_id, source_ids=(snapshot.assets[0].stable_id,)
    )
    assert value.candidates


def test_multiple_directed_inventory_paths_are_distinct(ready):
    snapshot, graph, correlation = prepared(ready)
    paths = candidates(snapshot, graph, correlation).candidates
    assert len(paths) == 2
    assert len({p.candidate_id for p in paths}) == 2
    assert {len(p.steps) for p in paths} == {1, 2}
    assert all(p.node_ids[-1] == snapshot.software[0].stable_id for p in paths)


def test_paths_cannot_cross_missing_relationships_or_reverse_edges(ready):
    snapshot, graph, correlation = prepared(ready, assets=2)
    source = snapshot.assets[0].stable_id
    other = next(s for s in snapshot.software if s.asset_id != source)
    result = generate_candidates(
        graph, correlation, source_ids=(source,), target_ids=(other.stable_id,)
    )
    assert result.candidates == ()
    result = generate_candidates(
        graph, correlation, source_ids=(other.stable_id,), target_ids=(source,)
    )
    assert result.candidates == ()


@pytest.mark.parametrize("missing", ["missing_vendor", "missing_version"])
def test_unknown_remains_uncertain(ready, missing):
    snapshot, graph, correlation = prepared(ready, **{missing: True})
    result = candidates(snapshot, graph, correlation)
    assert result.candidates
    assert all(
        p.applicability == S.UNKNOWN and p.feasibility == "UNCERTAIN" for p in result.candidates
    )


def test_confirmed_applicability_does_not_prove_reachability_or_access(ready, monkeypatch):
    from rlredteam.evidence.models import ObservedAsset, ObservedService

    original = fixtures.fixtures.inventory

    def consistent_inventory(*args, **kwargs):
        bundle = original(*args, **kwargs)
        return replace(
            bundle,
            records=tuple(
                replace(r, value={}) if isinstance(r, ObservedAsset | ObservedService) else r
                for r in bundle.records
            ),
        )

    monkeypatch.setattr(fixtures.fixtures, "inventory", consistent_inventory)
    snapshot, graph, correlation = prepared(ready, confirmation=True)
    result = candidates(snapshot, graph, correlation)
    assert all(
        p.applicability == S.CONFIRMED and p.feasibility == "APPLICABILITY_SUPPORTED"
        for p in result.candidates
    )
    assert all(
        set(p.unverified_prerequisites)
        >= {"network reachability", "required access", "exploitability", "authorization"}
        for p in result.candidates
    )


def test_conflicting_evidence_remains_visible(ready):
    versions = iter((fixtures.release(), fixtures.release()))
    snapshot, graph, correlation = prepared(
        ready, transform_software=lambda r: replace(r, version=next(versions))
    )
    paths = candidates(snapshot, graph, correlation).candidates
    assert paths
    assert all(
        p.feasibility == "UNCERTAIN" and p.conflict_ids and p.conflicting_evidence_ids
        for p in paths
    )


def test_every_step_has_exact_graph_evidence_and_correlation_provenance(ready):
    snapshot, graph, correlation = prepared(ready)
    value = candidates(snapshot, graph, correlation)
    edges = {e.edge_id: e for e in graph.edges}
    assessments = {a.assessment_id: a for a in correlation.assessments}
    refs = {r["support_id"] for r in correlation.evidence}
    for path in value.candidates:
        terminal = assessments[path.terminal_assessment_id]
        assert terminal.provenance.attributes["graph_node_id"] == path.node_ids[-1]
        assert terminal.provenance.attributes["reconciliation_decision_ids"]
        for index, step in enumerate(path.steps):
            assert step.correlation_id == correlation.correlation_id
            edge = edges[step.graph_edge_id]
            assert (
                (step.source, step.target)
                == (edge.source, edge.target)
                == path.node_ids[index : index + 2]
            )
            assert step.relationship_type == edge.relationship_type
            assert set(edge.evidence_ids) <= set(step.graph_evidence_ids) <= refs
            assert set(step.assessment_ids) <= assessments.keys()
    assert value.graph_json == graph_dumps(graph)


def test_all_input_schemas_unchanged(ready):
    snapshot, graph, correlation = prepared(ready)
    conn = ready.connection
    schemas = (
        "normalized_evidence",
        "entity_reconciliation",
        "digital_twin_state",
        "vulnerability_correlation",
    )
    tables = conn.execute(
        "SELECT schemaname,tablename FROM pg_tables "
        "WHERE schemaname=ANY(%s) ORDER BY schemaname,tablename",
        (list(schemas),),
    ).fetchall()

    def fingerprint():
        return [
            conn.execute(
                sql.SQL("SELECT to_jsonb(t) FROM {}.{} t ORDER BY to_jsonb(t)::text").format(
                    sql.Identifier(s), sql.Identifier(t)
                )
            ).fetchall()
            for s, t in tables
        ]

    before = fingerprint()
    value = load_candidate_paths(
        ready, correlation.correlation_id, source_ids=(snapshot.assets[0].stable_id,)
    )
    assert rebuild(value) == value
    assert fingerprint() == before
    assert ready.load(correlation.correlation_id) == correlation
    assert project_snapshot(ready.twins.load(snapshot.snapshot_id)) == graph


@pytest.mark.parametrize(
    "limits",
    [
        dict(max_paths=1),
        dict(max_expansions=1),
        dict(max_hops=0),
        dict(max_hops=True),
        dict(max_paths=10001),
    ],
)
def test_bounded_search_fails_without_partial_outputs(ready, limits):
    snapshot, graph, correlation = prepared(ready)
    with pytest.raises(ModelError, match="bound|budget"):
        candidates(snapshot, graph, correlation, **limits)


def test_unknown_source_is_not_resolved_by_address_or_name(ready):
    snapshot, graph, correlation = prepared(ready)
    with pytest.raises(ModelError):
        generate_candidates(graph, correlation, source_ids=("unresolved:" + digest(snapshot),))


def test_mismatched_graph_and_correlation_rejected(ready):
    first, graph, _ = prepared(ready)
    _, _, other = prepared(ready)
    with pytest.raises(ModelError, match="exact inventory graph"):
        candidates(first, graph, other)


def test_not_applicable_is_not_a_vulnerability_candidate(ready):
    snapshot, _, _, knowledge = fixtures.inventory(ready)
    product = knowledge.entries[0].affected_products[0]
    # Add another numeric component: the exact affected release must differ.
    different = snapshot.software[0].versions[0] + "." + str(len(snapshot.software))
    known = fixtures.knowledge(product.vendor, product.product, different)
    correlation = ready.build(snapshot.snapshot_id, known)
    assert all(a.applicability_status == S.NOT_APPLICABLE for a in correlation.assessments)
    assert not candidates(snapshot, project_snapshot(snapshot), correlation).candidates


def test_multiple_vulnerabilities_keep_separate_candidate_identities(ready):
    snapshot, _, _, knowledge = fixtures.inventory(ready)
    product = knowledge.entries[0].affected_products[0]
    known = fixtures.knowledge(
        product.vendor, product.product, snapshot.software[0].versions[0], count=3
    )
    graph = project_snapshot(snapshot)
    correlation = ready.build(snapshot.snapshot_id, known)
    value = candidates(snapshot, graph, correlation)
    assert len(value.candidates) == 6
    assert len({p.candidate_id for p in value.candidates}) == 6
    assert len({p.terminal_assessment_id for p in value.candidates}) == 3


def test_source_order_has_no_semantic_effect(ready):
    snapshot, graph, correlation = prepared(ready, assets=2)
    sources = tuple(a.stable_id for a in snapshot.assets)
    assert generate_candidates(graph, correlation, source_ids=sources) == generate_candidates(
        graph, correlation, source_ids=tuple(reversed(sources))
    )


def test_generator_performs_no_network_or_process_activity(ready, monkeypatch):
    import socket
    import subprocess

    snapshot, graph, correlation = prepared(ready)

    def denied(*args, **kwargs):
        raise AssertionError("candidate generation must be offline and non-executing")

    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    assert candidates(snapshot, graph, correlation).candidates


def test_no_execution_imports_or_command_fields():
    from rlredteam.digital_twin import path_candidates

    tree = ast.parse(Path(path_candidates.__file__).read_text())
    forbidden = {"subprocess", "socket", "requests", "os", "torch", "nasim", "stable_baselines3"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not {n.name.split(".")[0] for n in node.names} & forbidden
        if isinstance(node, ast.ImportFrom):
            assert not set((node.module or "").split(".")) & forbidden
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {"exec", "eval", "compile", "__import__"}
    assert not any(
        word in path_candidates.CandidateStep.__dataclass_fields__
        for word in ("command", "payload", "execute", "action")
    )
