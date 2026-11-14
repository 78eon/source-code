"""Map V2 attacker decisions onto existing enterprise actions."""

from __future__ import annotations

from rlredteam.enterprise.attacker_decision import (
    AttackerDecisionCandidate,
    DecisionKind,
)
from rlredteam.enterprise.environment import (
    EnterpriseAction,
    EnterpriseActionType,
)
from rlredteam.enterprise.model import (
    EdgeType,
    NodeType,
)
from rlredteam.enterprise.state import (
    AgentKnowledge,
)

_HOST_TYPES = {
    NodeType.HOST,
    NodeType.LEGACY_HOST,
    NodeType.CLOUD_WORKLOAD,
}

_APPLICATION_TYPES = {
    NodeType.APPLICATION,
    NodeType.API,
    NodeType.DATABASE,
    NodeType.CLOUD_RESOURCE,
    NodeType.CLOUD_ACCOUNT,
    NodeType.STORAGE,
}


def _known_edge_exists(
    knowledge: AgentKnowledge,
    edge_type: EdgeType,
    target: str,
    *,
    require_source_access: bool = False,
    require_source_credential: bool = False,
) -> bool:
    for source, edge_target, known_type in knowledge.known_edges:
        if known_type != edge_type:
            continue

        if edge_target != target:
            continue

        if require_source_access and source not in knowledge.access:
            continue

        if require_source_credential and source not in knowledge.credentials:
            continue

        return True

    return False


def _map_recon(
    target: str,
    knowledge: AgentKnowledge,
) -> EnterpriseAction | None:
    if target not in knowledge.discovered:
        return None

    if target not in knowledge.reachable and target not in knowledge.access:
        return None

    node_type = knowledge.known_node_types[target]

    if target not in knowledge.enumerated:
        if node_type in {
            NodeType.NETWORK_SEGMENT,
            NodeType.CLOUD_NETWORK,
        }:
            return EnterpriseAction(
                EnterpriseActionType.DISCOVER_NETWORK,
                target,
            )

        if node_type in _HOST_TYPES:
            return EnterpriseAction(
                EnterpriseActionType.ENUMERATE_HOST,
                target,
            )

        if node_type == NodeType.SERVICE:
            return EnterpriseAction(
                EnterpriseActionType.ENUMERATE_SERVICE,
                target,
            )

        if node_type in _APPLICATION_TYPES:
            return EnterpriseAction(
                EnterpriseActionType.ENUMERATE_APPLICATION,
                target,
            )

    if target not in knowledge.assessed:
        return EnterpriseAction(
            EnterpriseActionType.ASSESS_VULNERABILITY,
            target,
        )

    return None


def _known_exploit_for_target(
    target: str,
    knowledge: AgentKnowledge,
) -> str | None:
    if target in knowledge.access:
        return None

    for vulnerability_id in knowledge.vulnerability_order:
        if vulnerability_id not in knowledge.known_vulnerabilities:
            continue
        source = knowledge.vulnerability_targets[vulnerability_id]
        if source not in knowledge.reachable and source not in knowledge.access:
            continue
        if knowledge.vulnerability_grants_access[vulnerability_id] == target:
            return vulnerability_id

    return None


def _has_root_escalation(
    target: str,
    knowledge: AgentKnowledge,
) -> bool:
    if knowledge.access_level(target) != 1:
        return False

    return any(
        knowledge.vulnerability_targets[vulnerability_id] == target
        and knowledge.vulnerability_grants_access[vulnerability_id] == target
        and knowledge.vulnerability_privileges[vulnerability_id] == "root"
        for vulnerability_id in knowledge.known_vulnerabilities
    )


def _map_progress(
    candidate: AttackerDecisionCandidate,
    knowledge: AgentKnowledge,
) -> EnterpriseAction | None:
    target = candidate.target_id

    if target not in knowledge.discovered:
        return None

    relationship = None

    if candidate.path is not None and candidate.path.edges:
        relationship = candidate.path.edges[0].relationship

    if relationship == EdgeType.YIELDS_CREDENTIAL.value:
        if _known_edge_exists(
            knowledge,
            EdgeType.YIELDS_CREDENTIAL,
            target,
            require_source_access=True,
        ):
            return EnterpriseAction(
                EnterpriseActionType.OBTAIN_CREDENTIAL,
                target,
            )

    if relationship == EdgeType.HAS_ACCESS.value:
        if _known_edge_exists(
            knowledge,
            EdgeType.HAS_ACCESS,
            target,
            require_source_credential=True,
        ):
            return EnterpriseAction(
                EnterpriseActionType.AUTHENTICATE,
                target,
            )

    if relationship == EdgeType.PIVOTS_TO.value:
        if _known_edge_exists(
            knowledge,
            EdgeType.PIVOTS_TO,
            target,
            require_source_access=True,
        ):
            return EnterpriseAction(
                EnterpriseActionType.PIVOT,
                target,
            )

    if relationship == EdgeType.CONTAINS.value:
        if _known_edge_exists(
            knowledge,
            EdgeType.CONTAINS,
            target,
            require_source_access=True,
        ):
            return EnterpriseAction(
                EnterpriseActionType.ACCESS_ASSET,
                target,
            )

    if _has_root_escalation(
        target,
        knowledge,
    ):
        return EnterpriseAction(
            EnterpriseActionType.ESCALATE_PRIVILEGE,
            target,
        )

    vulnerability_id = _known_exploit_for_target(
        target,
        knowledge,
    )

    if vulnerability_id is not None:
        return EnterpriseAction(
            EnterpriseActionType.EXPLOIT,
            vulnerability_id,
        )

    return None


def map_decision_to_action(
    candidate: AttackerDecisionCandidate,
    knowledge: AgentKnowledge,
) -> EnterpriseAction | None:
    """Map one abstract V2 decision to an existing action.

    Only attacker-visible AgentKnowledge is consulted.
    """

    if candidate.kind == DecisionKind.RECON:
        return _map_recon(
            candidate.target_id,
            knowledge,
        )

    if candidate.kind == DecisionKind.PROGRESS:
        return _map_progress(
            candidate,
            knowledge,
        )

    return None
