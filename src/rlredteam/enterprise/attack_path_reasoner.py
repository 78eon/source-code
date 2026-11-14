"""Candidate attack-path reasoning over attacker-visible knowledge."""

from __future__ import annotations

from dataclasses import dataclass

from rlredteam.enterprise.attacker_graph import (
    AttackerGraphEdge,
    AttackerKnowledgeGraph,
)


@dataclass(frozen=True, slots=True)
class CandidateAttackPath:
    nodes: tuple[str, ...]
    edges: tuple[AttackerGraphEdge, ...]
    confidence: float

    @property
    def hops(self) -> int:
        return len(self.edges)


def _path_confidence(
    edges: tuple[AttackerGraphEdge, ...],
) -> float:
    """Combine edge confidence conservatively.

    Multiplication means every uncertain edge reduces confidence
    in the complete candidate path.
    """

    confidence = 1.0

    for edge in edges:
        confidence *= edge.confidence

    return confidence


def find_candidate_paths(
    graph: AttackerKnowledgeGraph,
    source: str,
    target: str,
    *,
    max_hops: int = 8,
    minimum_edge_confidence: float = 0.0,
) -> tuple[CandidateAttackPath, ...]:
    """Return simple attacker-visible paths ranked by plausibility."""

    if max_hops <= 0:
        raise ValueError(
            "max_hops must be positive"
        )

    if not 0.0 <= minimum_edge_confidence <= 1.0:
        raise ValueError(
            "minimum_edge_confidence must be between 0 and 1"
        )

    if source not in graph.nodes:
        return ()

    if target not in graph.nodes:
        return ()

    if source == target:
        return (
            CandidateAttackPath(
                nodes=(source,),
                edges=(),
                confidence=1.0,
            ),
        )

    results: list[CandidateAttackPath] = []

    stack: list[
        tuple[
            str,
            tuple[str, ...],
            tuple[AttackerGraphEdge, ...],
        ]
    ] = [
        (
            source,
            (source,),
            (),
        )
    ]

    while stack:
        current, path_nodes, path_edges = stack.pop()

        if len(path_edges) >= max_hops:
            continue

        for edge in graph.outgoing(current):
            if edge.confidence < minimum_edge_confidence:
                continue

            if edge.target in path_nodes:
                continue

            next_nodes = path_nodes + (
                edge.target,
            )

            next_edges = path_edges + (
                edge,
            )

            if edge.target == target:
                results.append(
                    CandidateAttackPath(
                        nodes=next_nodes,
                        edges=next_edges,
                        confidence=_path_confidence(
                            next_edges
                        ),
                    )
                )
                continue

            stack.append(
                (
                    edge.target,
                    next_nodes,
                    next_edges,
                )
            )

    return tuple(
        sorted(
            results,
            key=lambda path: (
                -path.confidence,
                path.hops,
                path.nodes,
            ),
        )
    )