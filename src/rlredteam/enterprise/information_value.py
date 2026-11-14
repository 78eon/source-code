"""Information-value scoring for uncertainty-aware attacker reasoning."""

from __future__ import annotations

from dataclasses import dataclass
import math
from rlredteam.enterprise.attack_path_reasoner import CandidateAttackPath

from rlredteam.enterprise.belief import (
    AttackerBeliefState,
    BeliefFact,
)


@dataclass(frozen=True, slots=True)
class InformationValueScore:
    subject_id: str
    predicate: str
    value: str
    uncertainty: float
    contradiction_bonus: float
    score: float
    contradiction_component: float = 0.0
    path_relevance: float = 0.0
    path_component: float = 0.0


def belief_uncertainty(
    fact: BeliefFact,
) -> float:
    """Return deterministic uncertainty from belief confidence."""

    return 1.0 - fact.confidence


def contradiction_bonus(
    fact: BeliefFact,
) -> float:
    """Flag beliefs with contradictory evidence."""

    return float(
        bool(
            fact.contradictory_evidence_ids
        )
    )


def score_belief_information_value(
    fact: BeliefFact,
    *,
    contradiction_weight: float = 0.5,
    path_relevance: float = 0.0,
    path_weight: float = 0.0,
) -> InformationValueScore:
    """Score how useful it may be to investigate a belief further."""

    if not math.isfinite(contradiction_weight) or contradiction_weight < 0.0:
        raise ValueError(
            "contradiction_weight must not be negative"
        )
    if not math.isfinite(path_weight) or path_weight < 0:
        raise ValueError("path_weight must be finite and nonnegative")
    if not math.isfinite(path_relevance) or not 0 <= path_relevance <= 1:
        raise ValueError("path_relevance must be finite and between zero and one")

    uncertainty = belief_uncertainty(
        fact
    )

    conflict = contradiction_bonus(
        fact
    )

    score = (
        uncertainty
        + contradiction_weight * conflict
        + path_weight * path_relevance * uncertainty
    )

    return InformationValueScore(
        subject_id=fact.subject_id,
        predicate=fact.predicate,
        value=fact.value,
        uncertainty=uncertainty,
        contradiction_bonus=conflict,
        score=score,
        contradiction_component=contradiction_weight * conflict,
        path_relevance=path_relevance,
        path_component=path_weight * path_relevance * uncertainty,
    )


def rank_information_targets(
    beliefs: AttackerBeliefState,
    *,
    contradiction_weight: float = 0.5,
    paths: tuple[CandidateAttackPath, ...] = (),
    path_weight: float = 0.0,
) -> tuple[InformationValueScore, ...]:
    """Rank known facts; path relevance is opt-in (path_weight defaults to zero).

    Relevance is the maximum plausibility among supplied candidate paths that
    contain the fact's subject (or exact edge for edge beliefs). It is a heuristic,
    not a calibrated probability. Path component = weight * relevance * uncertainty.
    Only caller-supplied attacker-visible paths are considered; no paths means zero.
    """

    if not math.isfinite(path_weight) or path_weight < 0:
        raise ValueError("path_weight must be finite and nonnegative")
    if not math.isfinite(contradiction_weight) or contradiction_weight < 0:
        raise ValueError("contradiction_weight must be finite and nonnegative")

    def relevance(fact):
        def supports(path):
            if fact.predicate.startswith("edge:"):
                return any((edge.source, edge.relationship, edge.target) ==
                           (fact.subject_id, fact.predicate[5:], fact.value)
                           for edge in path.edges)
            return fact.subject_id in path.nodes
        return max((path.confidence for path in paths if supports(path)), default=0.0)

    scores = [
        score_belief_information_value(
            fact,
            contradiction_weight=contradiction_weight,
            path_relevance=relevance(fact),
            path_weight=path_weight,
        )
        for fact in beliefs.facts.values()
    ]

    return tuple(
        sorted(
            scores,
            key=lambda item: (
                -item.score,
                item.subject_id,
                item.predicate,
                item.value,
            ),
        )
    )
