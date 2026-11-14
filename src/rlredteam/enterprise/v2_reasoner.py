"""End-to-end V2 attacker reasoning over visible knowledge only."""

from __future__ import annotations

from dataclasses import dataclass

from rlredteam.enterprise.attack_path_reasoner import (
    CandidateAttackPath,
    find_candidate_paths,
)
from rlredteam.enterprise.attacker_decision import (
    AttackerDecisionCandidate,
    rank_decision_candidates,
)
from rlredteam.enterprise.attacker_graph import (
    AttackerKnowledgeGraph,
)
from rlredteam.enterprise.belief import (
    AttackerBeliefState,
    BeliefFact,
    beliefs_from_agent_knowledge,
)
from rlredteam.enterprise.information_value import (
    InformationValueScore,
    rank_information_targets,
)
from rlredteam.enterprise.v2_execution import (
    V2ExecutionPlan,
    plan_v2_execution,
)


@dataclass(frozen=True, slots=True)
class V2DecisionExplanation:
    """Immutable selection-time evidence, not a claim of calibrated causality.

    Empty evidence/source IDs mean unavailable provenance, never fabricated IDs.
    Decision retains progress path or recon score decomposition; the plan retains
    the existing mapped enterprise action. Rank counts non-executable candidates.
    """

    decision: AttackerDecisionCandidate
    execution_plan: V2ExecutionPlan
    selection_rank: int
    motivating_paths: tuple[CandidateAttackPath, ...]
    supporting_facts: tuple[BeliefFact, ...]
    evidence_ids: tuple[str, ...]
    source_ids: tuple[str, ...]
    contradictory_evidence_ids: tuple[str, ...]
    selection_rule: str = "first executable candidate in deterministic ranked order"


def explain_decision(beliefs, decision, plan, *, selection_rank, paths=()):
    """Snapshot visible target context plus the exact motivating path/fact."""
    keys = set()
    motivating_paths = (decision.path,) if decision.path else ()
    if decision.information and decision.information.path_component > 0:
        info = decision.information
        def supports(path):
            if info.predicate.startswith("edge:"):
                return any((e.source, "edge:" + e.relationship, e.target) ==
                           (info.subject_id, info.predicate, info.value) for e in path.edges)
            return info.subject_id in path.nodes
        motivating_paths = tuple(sorted(
            (p for p in paths if supports(p) and p.confidence == info.path_relevance),
            key=lambda p: (p.nodes, tuple((e.source, e.relationship, e.target) for e in p.edges)),
        ))
    for path in motivating_paths:
        keys.update((e.source, "edge:" + e.relationship, e.target)
                    for e in path.edges)
    if decision.information:
        i = decision.information
        keys.add((i.subject_id, i.predicate, i.value))
    facts = tuple(sorted((f for f in beliefs.facts.values()
                          if AttackerBeliefState.key(f) in keys
                          or f.subject_id in {decision.target_id, plan.action.target}),
                         key=AttackerBeliefState.key))
    return V2DecisionExplanation(
        decision=decision, execution_plan=plan, selection_rank=selection_rank,
        motivating_paths=motivating_paths,
        supporting_facts=facts,
        evidence_ids=tuple(sorted({e for f in facts for e in f.evidence_ids})),
        source_ids=tuple(sorted({s for f in facts for s in f.source_ids})),
        contradictory_evidence_ids=tuple(sorted(
            {e for f in facts for e in f.contradictory_evidence_ids})),
    )


@dataclass(frozen=True, slots=True)
class V2ReasoningResult:
    beliefs: AttackerBeliefState
    graph: AttackerKnowledgeGraph
    paths: tuple[CandidateAttackPath, ...]
    information_targets: tuple[
        InformationValueScore,
        ...
    ]
    decisions: tuple[
        AttackerDecisionCandidate,
        ...
    ]
    selected_decision: (
        AttackerDecisionCandidate | None
    )
    execution_plan: V2ExecutionPlan | None
    explanation: V2DecisionExplanation | None = None


def reason_next_action(
    env,
    *,
    goal_id: str,
    max_hops: int = 8,
    minimum_edge_confidence: float = 0.0,
    contradiction_weight: float = 0.5,
    path_weight: float = 0.0,
) -> V2ReasoningResult:
    """Build one V2 reasoning cycle from attacker-visible state."""

    beliefs = beliefs_from_agent_knowledge(
        env.knowledge
    )

    graph = AttackerKnowledgeGraph.from_beliefs(
        beliefs
    )

    paths: tuple[
        CandidateAttackPath,
        ...
    ] = ()

    if goal_id in graph.nodes:
        source_nodes = tuple(
            sorted(
                env.knowledge.access
                or env.knowledge.discovered
            )
        )

        collected_paths: list[
            CandidateAttackPath
        ] = []

        for source in source_nodes:
            collected_paths.extend(
                find_candidate_paths(
                    graph,
                    source,
                    goal_id,
                    max_hops=max_hops,
                    minimum_edge_confidence=(
                        minimum_edge_confidence
                    ),
                )
            )

        paths = tuple(
            sorted(
                collected_paths,
                key=lambda path: (
                    -path.confidence,
                    path.hops,
                    path.nodes,
                ),
            )
        )

    information_targets = rank_information_targets(
        beliefs,
        paths=paths,
        path_weight=path_weight,
        contradiction_weight=(
            contradiction_weight
        ),
    )

    decisions = rank_decision_candidates(
        paths=paths,
        information_targets=(
            information_targets
        ),
    )

    selected_decision = None
    execution_plan = None
    explanation = None

    for rank, candidate in enumerate(decisions, start=1):
        plan = plan_v2_execution(
            env,
            candidate,
        )

        if plan is None:
            continue

        selected_decision = candidate
        execution_plan = plan
        explanation = explain_decision(beliefs, candidate, plan, selection_rank=rank, paths=paths)
        break

    return V2ReasoningResult(
        beliefs=beliefs,
        graph=graph,
        paths=paths,
        information_targets=(
            information_targets
        ),
        decisions=decisions,
        selected_decision=(
            selected_decision
        ),
        execution_plan=execution_plan,
        explanation=explanation,
    )
