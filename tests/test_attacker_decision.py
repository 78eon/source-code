import pytest

from rlredteam.enterprise.attack_path_reasoner import (
    CandidateAttackPath,
)
from rlredteam.enterprise.attacker_decision import (
    DecisionKind,
    progress_candidate,
    rank_decision_candidates,
    recon_candidate,
)
from rlredteam.enterprise.attacker_graph import (
    AttackerGraphEdge,
)
from rlredteam.enterprise.information_value import (
    InformationValueScore,
)


def test_progress_candidate_targets_next_node():
    edge = AttackerGraphEdge(
        source="entry",
        relationship="connects",
        target="web",
        confidence=0.8,
    )

    path = CandidateAttackPath(
        nodes=("entry", "web"),
        edges=(edge,),
        confidence=0.8,
    )

    candidate = progress_candidate(
        path
    )

    assert candidate.kind == DecisionKind.PROGRESS
    assert candidate.target_id == "web"
    assert candidate.score == pytest.approx(
        0.8
    )


def test_recon_candidate_uses_information_score():
    information = InformationValueScore(
        subject_id="app",
        predicate="service",
        value="https",
        uncertainty=0.7,
        contradiction_bonus=1.0,
        score=1.2,
    )

    candidate = recon_candidate(
        information
    )

    assert candidate.kind == DecisionKind.RECON
    assert candidate.target_id == "app"
    assert candidate.score == pytest.approx(
        1.2
    )


def test_candidates_are_ranked_together():
    edge = AttackerGraphEdge(
        source="entry",
        relationship="connects",
        target="web",
        confidence=0.6,
    )

    path = CandidateAttackPath(
        nodes=("entry", "web"),
        edges=(edge,),
        confidence=0.6,
    )

    information = InformationValueScore(
        subject_id="app",
        predicate="service",
        value="https",
        uncertainty=0.8,
        contradiction_bonus=0.0,
        score=0.8,
    )

    ranked = rank_decision_candidates(
        paths=(path,),
        information_targets=(
            information,
        ),
    )

    assert ranked[0].kind == DecisionKind.RECON
    assert ranked[1].kind == DecisionKind.PROGRESS


def test_progress_requires_next_node():
    path = CandidateAttackPath(
        nodes=("entry",),
        edges=(),
        confidence=1.0,
    )

    with pytest.raises(ValueError):
        progress_candidate(
            path
        )


def test_empty_inputs_return_empty_candidates():
    assert rank_decision_candidates() == ()