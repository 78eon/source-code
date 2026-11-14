"""Unified attacker knowledge graph for RLRedTeam V2."""

from __future__ import annotations

from dataclasses import dataclass, field

from rlredteam.enterprise.belief import (
    AttackerBeliefState,
    BeliefFact,
)


@dataclass(frozen=True, slots=True)
class AttackerGraphEdge:
    source: str
    relationship: str
    target: str
    confidence: float
    evidence_ids: tuple[str, ...] = ()
    contradictory_evidence_ids: tuple[str, ...] = ()


@dataclass(slots=True)
class AttackerKnowledgeGraph:
    nodes: set[str] = field(default_factory=set)
    edges: list[AttackerGraphEdge] = field(
        default_factory=list
    )
    node_facts: dict[str, tuple[BeliefFact, ...]] = field(default_factory=dict)

    def attributes(self, node_id: str, predicate: str | None = None) -> tuple[BeliefFact, ...]:
        """Immutable semantic facts; unknown nodes/predicates return no facts.

        Conflicting values coexist, with their original provenance and confidence.
        Edge beliefs remain edges, not node attributes.
        """
        return tuple(f for f in self.node_facts.get(node_id, ())
                     if predicate is None or f.predicate == predicate)

    @classmethod
    def from_beliefs(
        cls,
        beliefs: AttackerBeliefState,
    ) -> "AttackerKnowledgeGraph":
        graph = cls()

        for fact in sorted(beliefs.facts.values(), key=AttackerBeliefState.key):
            graph.nodes.add(fact.subject_id)

            if not fact.predicate.startswith("edge:"):
                graph.node_facts[fact.subject_id] = (
                    *graph.node_facts.get(fact.subject_id, ()), fact
                )
                continue

            target = fact.value
            relationship = fact.predicate.removeprefix(
                "edge:"
            )

            graph.nodes.add(target)

            graph.edges.append(
                AttackerGraphEdge(
                    source=fact.subject_id,
                    relationship=relationship,
                    target=target,
                    confidence=fact.confidence,
                    evidence_ids=fact.evidence_ids,
                    contradictory_evidence_ids=(
                        fact.contradictory_evidence_ids
                    ),
                )
            )

        graph.edges.sort(
            key=lambda edge: (
                edge.source,
                edge.relationship,
                edge.target,
            )
        )

        return graph

    def outgoing(
        self,
        node_id: str,
    ) -> tuple[AttackerGraphEdge, ...]:
        return tuple(
            edge
            for edge in self.edges
            if edge.source == node_id
        )

    def neighbors(
        self,
        node_id: str,
        *,
        minimum_confidence: float = 0.0,
    ) -> tuple[str, ...]:
        if not 0.0 <= minimum_confidence <= 1.0:
            raise ValueError(
                "minimum_confidence must be between 0 and 1"
            )

        return tuple(
            sorted(
                {
                    edge.target
                    for edge in self.outgoing(node_id)
                    if edge.confidence
                    >= minimum_confidence
                }
            )
        )
