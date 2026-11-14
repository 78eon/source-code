import pytest

from rlredteam.enterprise.attacker_graph import (
    AttackerKnowledgeGraph,
)
from rlredteam.enterprise.belief import (
    AttackerBeliefState,
    BeliefFact,
    BeliefStatus,
)
from rlredteam.enterprise.belief_observation import (
    BeliefObservation,
)


def test_empty_observation_has_expected_size():
    beliefs = AttackerBeliefState()
    graph = AttackerKnowledgeGraph()

    observation = BeliefObservation.from_beliefs(
        beliefs,
        graph,
        max_nodes=2,
        step=0,
        max_steps=100,
    )

    assert len(observation.values) == (
        2 * BeliefObservation.feature_count()
        + 2 * 2
        + 1
    )


def test_observation_encodes_confidence():
    beliefs = AttackerBeliefState()

    beliefs.learn(
        BeliefFact(
            subject_id="host-a",
            predicate="reachable",
            value="true",
            confidence=0.8,
            status=BeliefStatus.INFERRED,
        )
    )

    graph = AttackerKnowledgeGraph.from_beliefs(
        beliefs
    )

    observation = BeliefObservation.from_beliefs(
        beliefs,
        graph,
        max_nodes=1,
        step=0,
        max_steps=100,
    )

    assert observation.values[0] == 1.0
    assert observation.values[1] == pytest.approx(
        0.8
    )


def test_observation_encodes_contradiction():
    beliefs = AttackerBeliefState()

    beliefs.learn(
        BeliefFact(
            subject_id="host-a",
            predicate="reachable",
            value="true",
            confidence=0.7,
            status=BeliefStatus.INFERRED,
            contradictory_evidence_ids=(
                "conflict-a",
            ),
        )
    )

    graph = AttackerKnowledgeGraph.from_beliefs(
        beliefs
    )

    observation = BeliefObservation.from_beliefs(
        beliefs,
        graph,
        max_nodes=1,
        step=0,
        max_steps=100,
    )

    assert observation.values[2] == 1.0


def test_weighted_adjacency_uses_edge_confidence():
    beliefs = AttackerBeliefState()

    beliefs.learn(
        BeliefFact(
            subject_id="host-a",
            predicate="edge:connects",
            value="host-b",
            confidence=0.65,
            status=BeliefStatus.INFERRED,
        )
    )

    graph = AttackerKnowledgeGraph.from_beliefs(
        beliefs
    )

    observation = BeliefObservation.from_beliefs(
        beliefs,
        graph,
        max_nodes=2,
        step=0,
        max_steps=100,
    )

    adjacency_start = (
        2 * BeliefObservation.feature_count()
    )

    assert observation.values[
        adjacency_start + 1
    ] == pytest.approx(
        0.65
    )


def test_step_is_normalized():
    observation = BeliefObservation.from_beliefs(
        AttackerBeliefState(),
        AttackerKnowledgeGraph(),
        max_nodes=1,
        step=50,
        max_steps=100,
    )

    assert observation.values[-1] == pytest.approx(
        0.5
    )


def test_capacity_is_enforced():
    beliefs = AttackerBeliefState()

    beliefs.learn(
        BeliefFact(
            subject_id="a",
            predicate="edge:connects",
            value="b",
            confidence=1.0,
            status=BeliefStatus.OBSERVED,
        )
    )

    graph = AttackerKnowledgeGraph.from_beliefs(
        beliefs
    )

    with pytest.raises(ValueError):
        BeliefObservation.from_beliefs(
            beliefs,
            graph,
            max_nodes=1,
            step=0,
            max_steps=100,
        )


def test_invalid_limits_are_rejected():
    with pytest.raises(ValueError):
        BeliefObservation.from_beliefs(
            AttackerBeliefState(),
            AttackerKnowledgeGraph(),
            max_nodes=0,
            step=0,
            max_steps=100,
        )

    with pytest.raises(ValueError):
        BeliefObservation.from_beliefs(
            AttackerBeliefState(),
            AttackerKnowledgeGraph(),
            max_nodes=1,
            step=0,
            max_steps=0,
        )
def test_semantic_features_are_fixed_deterministic_and_confidence_weighted():
    facts = [BeliefFact("host-a", p, v, 0.7, BeliefStatus.INFERRED)
             for p, v in [("node_type", "host"), ("service", "ssh"),
                          ("access", "user"), ("reachable", "true"),
                          ("native_vulnerability", "native-1")]]
    observations = []
    for ordered in (facts, list(reversed(facts))):
        b = AttackerBeliefState()
        for f in ordered:
            b.learn(f)
        observations.append(BeliefObservation.from_beliefs(
            b, AttackerKnowledgeGraph.from_beliefs(b), max_nodes=2, step=0, max_steps=10))
    assert observations[0] == observations[1]
    features = dict(zip(BeliefObservation.FEATURE_NAMES, observations[0].values))
    for name in ("type:host", "service_present", "access_user", "reachable",
                 "native_vulnerability_present"):
        assert features[name] == 0.7
    assert features["access_root"] == features["vulnerability_present"] == 0
    width = BeliefObservation.feature_count()
    assert len(observations[0].values) == 2 * width + 4 + 1
    assert observations[0].values[width:2*width] == (0.0,) * width


def test_unknown_node_type_has_explicit_channel():
    b = AttackerBeliefState()
    b.learn(BeliefFact("a", "node_type", "future-type", 1.0, BeliefStatus.OBSERVED))
    o = BeliefObservation.from_beliefs(b, AttackerKnowledgeGraph.from_beliefs(b),
                                    max_nodes=1, step=0, max_steps=1)
    assert o.values[BeliefObservation.FEATURE_NAMES.index("type:other")] == 1.0

