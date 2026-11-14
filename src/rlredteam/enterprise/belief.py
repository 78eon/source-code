"""Evidence-grounded attacker belief state for RLRedTeam V2.

This module contains no reference to TrueTopology. Beliefs may only be created
from information supplied by the caller, such as AgentKnowledge or validated
evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import StrEnum


class BeliefStatus(StrEnum):
    OBSERVED = "observed"
    INFERRED = "inferred"


@dataclass(frozen=True, slots=True)
class BeliefFact:
    """One attacker-visible proposition with explicit uncertainty."""

    subject_id: str
    predicate: str
    value: str
    confidence: float
    status: BeliefStatus
    evidence_ids: tuple[str, ...] = ()
    source_ids: tuple[str, ...] = ()
    contradictory_evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.subject_id:
            raise ValueError("belief subject_id must not be empty")

        if not self.predicate:
            raise ValueError("belief predicate must not be empty")

        if not self.value:
            raise ValueError("belief value must not be empty")

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "belief confidence must be between 0 and 1"
            )

        if len(set(self.evidence_ids)) != len(
            self.evidence_ids
        ):
            raise ValueError(
                "belief evidence_ids must be unique"
            )

        if len(set(self.source_ids)) != len(
            self.source_ids
        ):
            raise ValueError(
                "belief source_ids must be unique"
            )

        if len(
            set(self.contradictory_evidence_ids)
        ) != len(self.contradictory_evidence_ids):
            raise ValueError(
                "contradictory evidence IDs must be unique"
            )


@dataclass(slots=True)
class AttackerBeliefState:
    """Agent-visible uncertain knowledge.

    This is deliberately separate from the simulator's ground truth.
    """

    facts: dict[
        tuple[str, str, str],
        BeliefFact,
    ] = field(default_factory=dict)

    @staticmethod
    def key(
        fact: BeliefFact,
    ) -> tuple[str, str, str]:
        return (
            fact.subject_id,
            fact.predicate,
            fact.value,
        )

    def learn(
        self,
        fact: BeliefFact,
    ) -> None:
        key = self.key(fact)
        existing = self.facts.get(key)

        if existing is None:
            self.facts[key] = fact
            return

        if existing == fact:
            return

        raise ValueError(
            "belief fact already exists with different metadata"
        )
    def revise(
        self,
        fact: BeliefFact,
    ) -> None:
        """Explicitly revise an existing belief.

        Provenance is accumulated rather than overwritten.
        Observed status cannot be downgraded back to inferred.
        """

        key = self.key(fact)
        existing = self.facts.get(key)

        if existing is None:
            raise KeyError(
                "cannot revise a belief that does not exist"
            )

        status = (
            BeliefStatus.OBSERVED
            if (
                existing.status == BeliefStatus.OBSERVED
                or fact.status == BeliefStatus.OBSERVED
            )
            else BeliefStatus.INFERRED
        )

        self.facts[key] = BeliefFact(
            subject_id=existing.subject_id,
            predicate=existing.predicate,
            value=existing.value,
            confidence=fact.confidence,
            status=status,
            evidence_ids=tuple(
                sorted(
                    set(existing.evidence_ids)
                    | set(fact.evidence_ids)
                )
            ),
            source_ids=tuple(
                sorted(
                    set(existing.source_ids)
                    | set(fact.source_ids)
                )
            ),
            contradictory_evidence_ids=tuple(
                sorted(
                    set(
                        existing.contradictory_evidence_ids
                    )
                    | set(
                        fact.contradictory_evidence_ids
                    )
                )
            ),
        )

    def record_contradiction(
        self,
        subject_id: str,
        predicate: str,
        value: str,
        evidence_id: str,
    ) -> None:
        """Attach contradictory evidence to an existing belief."""

        key = (
            subject_id,
            predicate,
            value,
        )

        existing = self.facts.get(key)

        if existing is None:
            raise KeyError(
                "cannot contradict a belief that does not exist"
            )

        if not evidence_id:
            raise ValueError(
                "contradictory evidence ID must not be empty"
            )

        contradictions = tuple(
            sorted(
                set(
                    existing.contradictory_evidence_ids
                )
                | {evidence_id}
            )
        )

        self.facts[key] = replace(
            existing,
            contradictory_evidence_ids=contradictions,
        )

    def get(
        self,
        subject_id: str,
        predicate: str,
        value: str,
    ) -> BeliefFact | None:
        return self.facts.get(
            (
                subject_id,
                predicate,
                value,
            )
        )

    def for_subject(
        self,
        subject_id: str,
    ) -> tuple[BeliefFact, ...]:
        return tuple(
            sorted(
                (
                    fact
                    for fact in self.facts.values()
                    if fact.subject_id == subject_id
                ),
                key=lambda item: (
                    item.predicate,
                    item.value,
                ),
            )
        )

    def snapshot(self) -> tuple:
        """Deterministic research/debug representation."""

        return tuple(
            sorted(
                (
                    fact.subject_id,
                    fact.predicate,
                    fact.value,
                    fact.confidence,
                    fact.status.value,
                    fact.evidence_ids,
                    fact.source_ids,
                    fact.contradictory_evidence_ids,
                )
                for fact in self.facts.values()
            )
        )
def beliefs_from_agent_knowledge(
    knowledge,
) -> AttackerBeliefState:
    """Create beliefs only from facts already visible to the agent."""

    beliefs = AttackerBeliefState()

    for node_id in knowledge.discovery_order:
        node_type = knowledge.known_node_types[node_id]

        beliefs.learn(
            BeliefFact(
                subject_id=node_id,
                predicate="discovered",
                value="true",
                confidence=1.0,
                status=BeliefStatus.OBSERVED,
            )
        )

        beliefs.learn(
            BeliefFact(
                subject_id=node_id,
                predicate="node_type",
                value=node_type.value,
                confidence=1.0,
                status=BeliefStatus.OBSERVED,
            )
        )

    for node_id in knowledge.enumerated:
        beliefs.learn(
            BeliefFact(
                subject_id=node_id,
                predicate="enumerated",
                value="true",
                confidence=1.0,
                status=BeliefStatus.OBSERVED,
            )
        )

    for node_id in knowledge.assessed:
        beliefs.learn(
            BeliefFact(
                subject_id=node_id,
                predicate="assessed",
                value="true",
                confidence=1.0,
                status=BeliefStatus.OBSERVED,
            )
        )

    for node_id in knowledge.reachable:
        beliefs.learn(
            BeliefFact(
                subject_id=node_id,
                predicate="reachable",
                value="true",
                confidence=1.0,
                status=BeliefStatus.OBSERVED,
            )
        )

    for node_id, privilege in knowledge.access.items():
        beliefs.learn(
            BeliefFact(
                subject_id=node_id,
                predicate="access",
                value=privilege,
                confidence=1.0,
                status=BeliefStatus.OBSERVED,
            )
        )

    for vulnerability_id in knowledge.vulnerability_order:
        target = knowledge.vulnerability_targets[vulnerability_id]

        beliefs.learn(
            BeliefFact(
                subject_id=target,
                predicate="vulnerability",
                value=vulnerability_id,
                confidence=1.0,
                status=BeliefStatus.OBSERVED,
            )
        )

    for source, target, edge_type in knowledge.known_edges:
        beliefs.learn(
            BeliefFact(
                subject_id=source,
                predicate=f"edge:{edge_type.value}",
                value=target,
                confidence=1.0,
                status=BeliefStatus.OBSERVED,
            )
        )

    for credential_id in knowledge.credentials:
        beliefs.learn(
            BeliefFact(
                subject_id=credential_id,
                predicate="credential_owned",
                value="true",
                confidence=1.0,
                status=BeliefStatus.OBSERVED,
            )
        )

    for node_id, properties in knowledge.known_properties.items():
        for property_name in sorted(properties):
            beliefs.learn(
                BeliefFact(
                    subject_id=node_id,
                    predicate="property",
                    value=property_name,
                    confidence=1.0,
                    status=BeliefStatus.OBSERVED,
                )
            )

    for node_id, services in knowledge.known_services.items():
        for service_name in sorted(services):
            beliefs.learn(
                BeliefFact(
                    subject_id=node_id,
                    predicate="service",
                    value=service_name,
                    confidence=1.0,
                    status=BeliefStatus.OBSERVED,
                )
            )

    for (
        node_id,
        vulnerabilities,
    ) in knowledge.known_native_vulnerabilities.items():
        for vulnerability_id in sorted(vulnerabilities):
            beliefs.learn(
                BeliefFact(
                    subject_id=node_id,
                    predicate="native_vulnerability",
                    value=vulnerability_id,
                    confidence=1.0,
                    status=BeliefStatus.OBSERVED,
                )
            )

    return beliefs
