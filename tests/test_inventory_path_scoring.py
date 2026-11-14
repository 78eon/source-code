"""Generated evidence only; deterministic ranking is not an execution interface."""

import ast
import secrets
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

import pytest
from psycopg import sql

from rlredteam.digital_twin.path_candidates import dumps as candidate_dumps
from rlredteam.digital_twin.path_candidates import generate_candidates
from rlredteam.digital_twin.path_scoring import (
    PathScoringConfig,
    dumps,
    loads,
    replay,
    score_candidates,
)
from rlredteam.knowledge.validation import ModelError
from rlredteam.knowledge.vulnerabilities.registry import VulnerabilityKnowledgeRegistry
from rlredteam.knowledge.vulnerabilities.snapshot import freeze
from tests import test_inventory_path_candidates as fixtures

db = fixtures.db
ready = fixtures.ready


def setup(store, *, cvss=True, **kwargs):
    snapshot, _, confirmations, knowledge = fixtures.fixtures.inventory(store, **kwargs)
    entries = tuple(
        replace(e, cvss_base=(secrets.randbelow(99) + 1) / 10 if cvss else None)
        for e in knowledge.entries
    )
    known = freeze(
        VulnerabilityKnowledgeRegistry(entries=entries, sources=knowledge.sources),
        created_at=knowledge.created_at,
    )
    graph = fixtures.project_snapshot(snapshot)
    correlation = store.build(
        snapshot.snapshot_id,
        known,
        confirmations=confirmations,
        trusted_inventory_sources=tuple((b, c.source) for b, c in confirmations),
    )
    store.save(correlation)
    paths = generate_candidates(graph, correlation, source_ids=(snapshot.assets[0].stable_id,))
    return paths, correlation


def test_deterministic_scores_and_replay(ready):
    paths, _ = setup(ready)
    ranked = score_candidates(paths)
    assert ranked == score_candidates(paths) == replay(ranked) == loads(dumps(ranked))
    assert ranked.scores


def test_scale_change_is_predictable_and_provenanced(ready):
    paths, _ = setup(ready)
    config = PathScoringConfig(decimal_places=10)
    first = score_candidates(paths, config)
    second = score_candidates(paths, replace(config, scale=config.scale * 2))
    by_id = {s.candidate_id: s for s in second.scores}
    for score in first.scores:
        assert float(by_id[score.candidate_id].total) == pytest.approx(float(score.total) * 2)
        assert (
            by_id[score.candidate_id].provenance["config_digest"]
            != score.provenance["config_digest"]
        )


@pytest.mark.parametrize("missing", ["missing_vendor", "missing_version"])
def test_unknown_does_not_get_confirmed_treatment(ready, missing):
    paths, _ = setup(ready, **{missing: True})
    ranked = score_candidates(paths)
    assert all(
        s.total == "0.000000"
        and s.components["applicability_factor"] == "0.0"
        and s.explanation["terminal_applicability"] == "UNKNOWN"
        for s in ranked.scores
    )


def test_confirmed_is_not_compromise_probability(ready):
    paths, _ = setup(ready, confirmation=True)
    assert all(
        s.components["applicability_factor"] == "1.0" for s in score_candidates(paths).scores
    )
    assert all(s.explanation["unverified_prerequisites"] for s in score_candidates(paths).scores)


def test_conflict_penalty_is_explicit_and_configurable(ready):
    paths, _ = setup(ready)
    # Generated asset OS observations conflict; no evidence is edited to remove it.
    lower = score_candidates(paths, PathScoringConfig(conflict_multiplier=0.25))
    higher = score_candidates(paths, PathScoringConfig(conflict_multiplier=0.5))
    by_id = {s.candidate_id: s for s in higher.scores}
    for s in lower.scores:
        assert s.explanation["has_conflicts"] and s.explanation["conflict_ids"]
        assert s.components["conflict_multiplier"] == "0.25"
        assert float(by_id[s.candidate_id].total) == pytest.approx(float(s.total) * 2, abs=0.000002)


def test_longer_path_never_earns_more_for_repeated_support(ready):
    paths, _ = setup(ready)
    assert len(paths.candidates) == 2
    config = PathScoringConfig(hop_decay=0)
    scores = score_candidates(paths, config).scores
    # The extra HOSTS step repeats supporting evidence, not additional impact.
    assert len({s.total for s in scores}) == 1
    ranked = score_candidates(paths, replace(config, hop_decay=0.5))
    by_candidate = {p.candidate_id: p for p in paths.candidates}
    short, long = sorted(ranked.scores, key=lambda s: len(by_candidate[s.candidate_id].steps))
    assert Decimal(long.total) <= Decimal(short.total)


def test_ties_use_candidate_id_and_have_no_hidden_priority(ready):
    paths, _ = setup(ready)
    ranking = score_candidates(paths, PathScoringConfig(hop_decay=0))
    assert len({s.total for s in ranking.scores}) == 1
    assert tuple(s.candidate_id for s in ranking.scores) == tuple(
        sorted(p.candidate_id for p in paths.candidates)
    )


def test_duplicate_evidence_references_are_rejected_before_scoring(ready):
    paths, _ = setup(ready)
    step = next(s for p in paths.candidates for s in p.steps)
    with pytest.raises(ModelError, match="duplicate graph_evidence_ids"):
        replace(step, graph_evidence_ids=(*step.graph_evidence_ids, *step.graph_evidence_ids))


def test_replay_is_independent_of_ambient_decimal_context(ready):
    from decimal import ROUND_DOWN, Inexact, Rounded, localcontext

    paths, _ = setup(ready)
    expected = score_candidates(paths)
    with localcontext() as context:
        context.prec = 7
        context.rounding = ROUND_DOWN
        context.traps[Inexact] = context.traps[Rounded] = True
        assert score_candidates(paths) == expected


def test_missing_cvss_remains_unknown_and_uses_explicit_fallback(ready):
    paths, _ = setup(ready, cvss=False)
    first = score_candidates(paths, PathScoringConfig(severity_weight=1, confidence_weight=0))
    assert all(
        s.explanation["cvss_missing"]
        and s.explanation["cvss_base"] is None
        and Decimal(s.total) == 0
        for s in first.scores
    )
    second = score_candidates(paths, replace(first.config, missing_cvss_normalized=0.5))
    assert all(Decimal(s.total) > 0 and s.explanation["cvss_missing"] for s in second.scores)


def test_components_and_exact_provenance_are_visible(ready):
    paths, correlation = setup(ready)
    ranked = score_candidates(paths)
    for score in ranked.scores:
        assert set(score.components) == {
            "severity_normalized",
            "confidence",
            "severity_contribution",
            "confidence_contribution",
            "applicability_factor",
            "conflict_multiplier",
            "length_multiplier",
            "scale",
        }
        assert score.provenance["candidate_set_id"] == paths.candidate_set_id
        assert score.provenance["correlation_id"] == correlation.correlation_id
        assert score.provenance["twin_snapshot_id"] == correlation.snapshot_id
        assert score.provenance["reconciliation_decision_ids"]
        assert score.provenance["evidence_references"]


def test_scoring_does_not_mutate_candidates_or_persistent_inputs(ready):
    paths, correlation = setup(ready)
    before = candidate_dumps(paths)
    conn = ready.connection
    names = conn.execute(
        "SELECT schemaname,tablename FROM pg_tables WHERE schemaname=ANY(%s) "
        "ORDER BY schemaname,tablename",
        (
            [
                "normalized_evidence",
                "entity_reconciliation",
                "digital_twin_state",
                "vulnerability_correlation",
            ],
        ),
    ).fetchall()

    def fingerprint():
        return [
            conn.execute(
                sql.SQL("SELECT to_jsonb(t) FROM {}.{} t ORDER BY to_jsonb(t)::text").format(
                    sql.Identifier(s), sql.Identifier(t)
                )
            ).fetchall()
            for s, t in names
        ]

    state = fingerprint()
    score_candidates(paths)
    assert before == candidate_dumps(paths)
    assert state == fingerprint()
    assert ready.load(correlation.correlation_id) == correlation


@pytest.mark.parametrize(
    "changes",
    [
        dict(severity_weight=-1),
        dict(scale=float("nan")),
        dict(conflict_multiplier=2),
        dict(decimal_places=True),
        dict(severity_weight=0, confidence_weight=0),
        dict(applicability_factors={"UNKNOWN": 1}),
    ],
)
def test_invalid_config_fails_closed(changes):
    with pytest.raises(ModelError):
        PathScoringConfig(**changes)


def test_config_cannot_relabel_unknown_as_confirmed():
    config = PathScoringConfig()
    with pytest.raises(ModelError, match="uncertainty ordering"):
        replace(config, applicability_factors={**config.applicability_factors, "UNKNOWN": 1.0})


def test_no_ppo_execution_or_network_capability(ready, monkeypatch):
    import socket
    import subprocess

    from rlredteam.digital_twin import path_scoring

    paths, _ = setup(ready)

    def denied(*args, **kwargs):
        raise AssertionError("scoring must not acquire data or execute")

    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    assert score_candidates(paths).scores
    forbidden = {
        "torch",
        "stable_baselines3",
        "reward",
        "nasim",
        "simulator_adapter",
        "subprocess",
        "socket",
        "requests",
        "frameworks",
        "enterprise",
    }
    tree = ast.parse(Path(path_scoring.__file__).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert not set((node.module or "").split(".")) & forbidden
        if isinstance(node, ast.Import):
            assert not {n.name.split(".")[0] for n in node.names} & forbidden
