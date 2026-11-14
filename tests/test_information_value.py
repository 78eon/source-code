import pytest

from rlredteam.enterprise.belief import (
    AttackerBeliefState,
    BeliefFact,
    BeliefStatus,
)
from rlredteam.enterprise.information_value import (
    belief_uncertainty,
    contradiction_bonus,
    rank_information_targets,
    score_belief_information_value,
)


def test_uncertainty_is_inverse_confidence():
    fact = BeliefFact(
        subject_id="host-a",
        predicate="reachable",
        value="true",
        confidence=0.25,
        status=BeliefStatus.INFERRED,
    )

    assert belief_uncertainty(
        fact
    ) == pytest.approx(
        0.75
    )


def test_confirmed_fact_has_zero_uncertainty():
    fact = BeliefFact(
        subject_id="host-a",
        predicate="reachable",
        value="true",
        confidence=1.0,
        status=BeliefStatus.OBSERVED,
    )

    assert belief_uncertainty(
        fact
    ) == 0.0


def test_contradiction_bonus_is_present():
    fact = BeliefFact(
        subject_id="host-a",
        predicate="service",
        value="ssh",
        confidence=0.8,
        status=BeliefStatus.INFERRED,
        contradictory_evidence_ids=(
            "evidence-x",
        ),
    )

    assert contradiction_bonus(
        fact
    ) == 1.0


def test_information_score_combines_uncertainty_and_conflict():
    fact = BeliefFact(
        subject_id="host-a",
        predicate="service",
        value="ssh",
        confidence=0.4,
        status=BeliefStatus.INFERRED,
        contradictory_evidence_ids=(
            "evidence-x",
        ),
    )

    result = score_belief_information_value(
        fact,
        contradiction_weight=0.5,
    )

    assert result.uncertainty == pytest.approx(
        0.6
    )

    assert result.contradiction_bonus == 1.0

    assert result.score == pytest.approx(
        1.1
    )


def test_information_targets_are_ranked():
    beliefs = AttackerBeliefState()

    beliefs.learn(
        BeliefFact(
            subject_id="low-value",
            predicate="reachable",
            value="true",
            confidence=0.9,
            status=BeliefStatus.INFERRED,
        )
    )

    beliefs.learn(
        BeliefFact(
            subject_id="high-value",
            predicate="reachable",
            value="true",
            confidence=0.2,
            status=BeliefStatus.INFERRED,
        )
    )

    ranked = rank_information_targets(
        beliefs
    )

    assert ranked[0].subject_id == (
        "high-value"
    )


def test_contradiction_can_raise_priority():
    beliefs = AttackerBeliefState()

    beliefs.learn(
        BeliefFact(
            subject_id="a",
            predicate="service",
            value="ssh",
            confidence=0.5,
            status=BeliefStatus.INFERRED,
        )
    )

    beliefs.learn(
        BeliefFact(
            subject_id="b",
            predicate="service",
            value="https",
            confidence=0.6,
            status=BeliefStatus.INFERRED,
            contradictory_evidence_ids=(
                "conflict",
            ),
        )
    )

    ranked = rank_information_targets(
        beliefs
    )

    assert ranked[0].subject_id == "b"


def test_negative_contradiction_weight_is_rejected():
    fact = BeliefFact(
        subject_id="host-a",
        predicate="reachable",
        value="true",
        confidence=0.5,
        status=BeliefStatus.INFERRED,
    )

    with pytest.raises(ValueError):
        score_belief_information_value(
            fact,
            contradiction_weight=-0.1,
        )
def test_path_component_prioritizes_relevant_uncertainty_without_changing_default():
    from rlredteam.enterprise.attacker_graph import AttackerKnowledgeGraph
    from rlredteam.enterprise.attack_path_reasoner import find_candidate_paths
    b = AttackerBeliefState()
    for subject in ("on-path", "off-path"):
        b.learn(BeliefFact(subject, "service", "ssh", 0.5, BeliefStatus.INFERRED))
    b.learn(BeliefFact("on-path", "edge:connects", "goal", 0.8, BeliefStatus.INFERRED))
    b.learn(BeliefFact("on-path", "edge:connects", "dead-end", 0.5, BeliefStatus.INFERRED))
    paths = find_candidate_paths(AttackerKnowledgeGraph.from_beliefs(b), "on-path", "goal")
    base = rank_information_targets(b)
    default = rank_information_targets(b, paths=paths)
    assert [x.score for x in base] == [x.score for x in default]
    ranked = rank_information_targets(b, paths=paths, path_weight=2.0)
    result = next(x for x in ranked if x.subject_id == "on-path" and x.predicate == "service")
    assert result.path_relevance == 0.8
    assert result.path_component == pytest.approx(0.8)
    assert result.score == pytest.approx(result.uncertainty + result.contradiction_component + result.path_component)
    assert ranked[0] == result
    assert next(x for x in ranked if x.value == "dead-end").path_component == 0
    assert rank_information_targets(b, paths=tuple(reversed(paths)), path_weight=2.0) == ranked


@pytest.mark.parametrize("weight", [-1, float("nan"), float("inf")])
def test_invalid_path_weights_rejected_even_without_facts(weight):
    with pytest.raises(ValueError):
        rank_information_targets(AttackerBeliefState(), path_weight=weight)

