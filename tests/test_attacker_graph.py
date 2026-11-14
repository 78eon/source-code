import pytest

from rlredteam.enterprise.attacker_graph import (
    AttackerKnowledgeGraph,
)
from rlredteam.enterprise.belief import (
    AttackerBeliefState,
    BeliefFact,
    BeliefStatus,
)


def test_graph_is_built_from_belief_relationships():
    beliefs = AttackerBeliefState()

    beliefs.learn(
        BeliefFact(
            subject_id="host-a",
            predicate="edge:connects",
            value="host-b",
            confidence=1.0,
            status=BeliefStatus.OBSERVED,
        )
    )

    graph = AttackerKnowledgeGraph.from_beliefs(
        beliefs
    )

    assert graph.nodes == {
        "host-a",
        "host-b",
    }

    assert len(graph.edges) == 1

    edge = graph.edges[0]

    assert edge.source == "host-a"
    assert edge.relationship == "connects"
    assert edge.target == "host-b"


def test_non_edge_fact_does_not_create_relationship():
    beliefs = AttackerBeliefState()

    beliefs.learn(
        BeliefFact(
            subject_id="host-a",
            predicate="service",
            value="ssh",
            confidence=0.8,
            status=BeliefStatus.INFERRED,
        )
    )

    graph = AttackerKnowledgeGraph.from_beliefs(
        beliefs
    )

    assert graph.nodes == {"host-a"}
    assert graph.edges == []


def test_confidence_filtering():
    beliefs = AttackerBeliefState()

    beliefs.learn(
        BeliefFact(
            subject_id="entry",
            predicate="edge:connects",
            value="high",
            confidence=0.9,
            status=BeliefStatus.INFERRED,
        )
    )

    beliefs.learn(
        BeliefFact(
            subject_id="entry",
            predicate="edge:connects",
            value="low",
            confidence=0.3,
            status=BeliefStatus.INFERRED,
        )
    )

    graph = AttackerKnowledgeGraph.from_beliefs(
        beliefs
    )

    assert graph.neighbors(
        "entry",
        minimum_confidence=0.5,
    ) == ("high",)


def test_graph_preserves_provenance():
    beliefs = AttackerBeliefState()

    beliefs.learn(
        BeliefFact(
            subject_id="host-a",
            predicate="edge:pivots_to",
            value="host-b",
            confidence=0.7,
            status=BeliefStatus.INFERRED,
            evidence_ids=("evidence-a",),
            contradictory_evidence_ids=(
                "evidence-b",
            ),
        )
    )

    graph = AttackerKnowledgeGraph.from_beliefs(
        beliefs
    )

    edge = graph.edges[0]

    assert edge.evidence_ids == (
        "evidence-a",
    )

    assert edge.contradictory_evidence_ids == (
        "evidence-b",
    )


def test_invalid_confidence_threshold_is_rejected():
    graph = AttackerKnowledgeGraph()

    with pytest.raises(ValueError):
        graph.neighbors(
            "host-a",
            minimum_confidence=1.1,
        )
def test_semantic_attributes_preserve_provenance_without_edges():
    from rlredteam.enterprise.belief import AttackerBeliefState, BeliefFact, BeliefStatus
    from rlredteam.enterprise.attacker_graph import AttackerKnowledgeGraph
    predicates = ("node_type", "property", "service", "vulnerability",
                  "native_vulnerability", "access", "reachable", "credential_owned")
    facts = [BeliefFact("host-a", p, "known-value", 0.7, BeliefStatus.INFERRED,
                       evidence_ids=("e1",), source_ids=("s1",),
                       contradictory_evidence_ids=("c1",)) for p in predicates]
    a, b = AttackerBeliefState(), AttackerBeliefState()
    for f in facts:
        a.learn(f)
    for f in reversed(facts):
        b.learn(f)
    first, second = map(AttackerKnowledgeGraph.from_beliefs, (a, b))
    assert first == second
    assert first.edges == []
    assert first.nodes == {"host-a"}
    assert first.attributes("host-a", "property") == (facts[1],)
    assert first.attributes("hidden") == ()
    a.revise(BeliefFact("host-a", "property", "known-value", 0.9, BeliefStatus.OBSERVED))
    assert first.attributes("host-a", "property") == (facts[1],)

