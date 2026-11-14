"""Confidence-aware RL observation derived from attacker beliefs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

import numpy as np

from rlredteam.enterprise.attacker_graph import (
    AttackerKnowledgeGraph,
)
from rlredteam.enterprise.belief import (
    AttackerBeliefState,
)


@dataclass(frozen=True, slots=True)
class BeliefObservation:
    """RL-ready representation of attacker-visible uncertain knowledge."""

    values: tuple[float, ...]
    # Versioned V2-only encoding. Never used by the baseline Observation.
    SCHEMA_VERSION: ClassVar[str] = "belief-observation-v2.15"
    NODE_TYPES: ClassVar[tuple[str, ...]] = (
        "entry_point", "network_segment", "network_device", "security_control",
        "host", "service", "application", "api", "identity", "database",
        "cloud_resource", "cloud_account", "cloud_network", "cloud_workload",
        "iam_role", "storage", "legacy_host", "identity_provider", "asset",
    )
    FEATURE_NAMES: ClassVar[tuple[str, ...]] = (
        "present", "mean_confidence", "contradiction", "inferred_fraction",
        "reachable", "access_known", "access_user", "access_root",
        "service_present", "vulnerability_present", "native_vulnerability_present",
        "property_present", "credential_owned",
    ) + tuple("type:" + name for name in NODE_TYPES) + ("type:other",)

    @staticmethod
    def feature_count() -> int:
        return len(BeliefObservation.FEATURE_NAMES)

    @classmethod
    def from_beliefs(
        cls,
        beliefs: AttackerBeliefState,
        graph: AttackerKnowledgeGraph,
        *,
        max_nodes: int,
        step: int,
        max_steps: int,
    ) -> "BeliefObservation":
        if max_nodes <= 0:
            raise ValueError(
                "max_nodes must be positive"
            )

        if max_steps <= 0:
            raise ValueError(
                "max_steps must be positive"
            )
        if step < 0:
            raise ValueError("step must not be negative")

        node_ids = sorted(graph.nodes)

        if len(node_ids) > max_nodes:
            raise ValueError(
                "attacker graph exceeds observation node capacity"
            )

        values: list[float] = []

        for index in range(max_nodes):
            if index >= len(node_ids):
                values.extend(
                    [0.0] * cls.feature_count()
                )
                continue

            node_id = node_ids[index]

            facts = beliefs.for_subject(
                node_id
            )

            if facts:
                mean_confidence = (
                    sum(
                        fact.confidence
                        for fact in facts
                    )
                    / len(facts)
                )
            else:
                mean_confidence = 0.0

            has_contradiction = float(
                any(
                    fact.contradictory_evidence_ids
                    for fact in facts
                )
            )

            inferred_fraction = (
                sum(
                    fact.status.value == "inferred"
                    for fact in facts
                )
                / len(facts)
                if facts
                else 0.0
            )

            values.extend(
                [
                    1.0,
                    mean_confidence,
                    has_contradiction,
                    inferred_fraction,
                ]
            )

            # Max supporting confidence per semantic channel; absence is zero,
            # not proof of a negative fact. Conflicts remain visible separately.
            semantic = graph.attributes(node_id)
            def confidence(predicate, value=None):
                return max((f.confidence for f in semantic
                            if f.predicate == predicate and
                            (value is None or f.value == value)), default=0.0)
            values.extend([
                confidence("reachable", "true"), confidence("access"),
                confidence("access", "user"), confidence("access", "root"),
                confidence("service"), confidence("vulnerability"),
                confidence("native_vulnerability"), confidence("property"),
                confidence("credential_owned", "true"),
            ])
            values.extend(confidence("node_type", name) for name in cls.NODE_TYPES)
            values.append(max((f.confidence for f in semantic
                               if f.predicate == "node_type" and f.value not in cls.NODE_TYPES),
                              default=0.0))

        slot_by_node = {
            node_id: index
            for index, node_id in enumerate(
                node_ids
            )
        }

        adjacency = [
            0.0
        ] * (
            max_nodes * max_nodes
        )

        for edge in graph.edges:
            source_slot = slot_by_node[
                edge.source
            ]

            target_slot = slot_by_node[
                edge.target
            ]

            adjacency[
                source_slot * max_nodes
                + target_slot
            ] = max(
                adjacency[
                    source_slot * max_nodes
                    + target_slot
                ],
                edge.confidence,
            )

        values.extend(
            adjacency
        )

        values.append(
            min(step / max_steps, 1.0)
        )

        return cls(
            tuple(values)
        )

    def as_array(
        self,
    ) -> np.ndarray:
        return np.asarray(
            self.values,
            dtype=np.float32,
        )
