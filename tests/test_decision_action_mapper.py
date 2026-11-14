from rlredteam.enterprise.attack_path_reasoner import (
    CandidateAttackPath,
)
from rlredteam.enterprise.attacker_decision import (
    AttackerDecisionCandidate,
    DecisionKind,
)
from rlredteam.enterprise.attacker_graph import (
    AttackerGraphEdge,
)
from rlredteam.enterprise.belief import (
    BeliefStatus,
)
from rlredteam.enterprise.environment import (
    EnterpriseActionType,
)
from rlredteam.enterprise.decision_action_mapper import (
    map_decision_to_action,
)
from rlredteam.enterprise.information_value import (
    InformationValueScore,
)
from rlredteam.enterprise.model import (
    EdgeType,
    NodeType,
)
from rlredteam.enterprise.state import (
    AgentKnowledge,
)


def make_recon_candidate(
    target: str,
) -> AttackerDecisionCandidate:
    return AttackerDecisionCandidate(
        kind=DecisionKind.RECON,
        target_id=target,
        score=1.0,
        information=InformationValueScore(
            subject_id=target,
            predicate="reachable",
            value="true",
            uncertainty=1.0,
            contradiction_bonus=0.0,
            score=1.0,
        ),
    )


def make_progress_candidate(
    source: str,
    target: str,
    relationship: EdgeType,
) -> AttackerDecisionCandidate:
    edge = AttackerGraphEdge(
        source=source,
        relationship=relationship.value,
        target=target,
        confidence=1.0,
    )

    path = CandidateAttackPath(
        nodes=(source, target),
        edges=(edge,),
        confidence=1.0,
    )

    return AttackerDecisionCandidate(
        kind=DecisionKind.PROGRESS,
        target_id=target,
        score=1.0,
        path=path,
    )


def test_recon_host_maps_to_enumerate_host():
    knowledge = AgentKnowledge()

    knowledge.discover(
        "host-a",
        NodeType.HOST,
        reachable=True,
    )

    action = map_decision_to_action(
        make_recon_candidate("host-a"),
        knowledge,
    )

    assert action is not None
    assert action.type == (
        EnterpriseActionType.ENUMERATE_HOST
    )
    assert action.target == "host-a"


def test_enumerated_target_maps_to_assessment():
    knowledge = AgentKnowledge()

    knowledge.discover(
        "host-a",
        NodeType.HOST,
        reachable=True,
    )
    knowledge.enumerated.add("host-a")

    action = map_decision_to_action(
        make_recon_candidate("host-a"),
        knowledge,
    )

    assert action is not None
    assert action.type == (
        EnterpriseActionType.ASSESS_VULNERABILITY
    )


def test_progress_pivot_uses_existing_pivot_action():
    knowledge = AgentKnowledge()

    knowledge.discover(
        "source",
        NodeType.HOST,
    )
    knowledge.discover(
        "target",
        NodeType.HOST,
    )

    knowledge.access["source"] = "user"

    knowledge.learn_edge(
        "source",
        "target",
        EdgeType.PIVOTS_TO,
    )

    action = map_decision_to_action(
        make_progress_candidate(
            "source",
            "target",
            EdgeType.PIVOTS_TO,
        ),
        knowledge,
    )

    assert action is not None
    assert action.type == EnterpriseActionType.PIVOT
    assert action.target == "target"


def test_progress_authenticate_requires_owned_credential():
    knowledge = AgentKnowledge()

    knowledge.discover(
        "credential-a",
        NodeType.IDENTITY,
    )
    knowledge.discover(
        "host-a",
        NodeType.HOST,
    )

    knowledge.credentials.add(
        "credential-a"
    )

    knowledge.learn_edge(
        "credential-a",
        "host-a",
        EdgeType.HAS_ACCESS,
    )

    action = map_decision_to_action(
        make_progress_candidate(
            "credential-a",
            "host-a",
            EdgeType.HAS_ACCESS,
        ),
        knowledge,
    )

    assert action is not None
    assert action.type == (
        EnterpriseActionType.AUTHENTICATE
    )


def test_known_vulnerability_can_map_to_exploit():
    knowledge = AgentKnowledge()

    knowledge.discover(
        "service-a",
        NodeType.SERVICE,
        reachable=True,
    )
    knowledge.discover(
        "host-a",
        NodeType.HOST,
    )

    knowledge.learn_vulnerability(
        "CVE-TEST-0001",
        "service-a",
        grants_access_to="host-a",
        privilege="user",
    )

    candidate = AttackerDecisionCandidate(
        kind=DecisionKind.PROGRESS,
        target_id="host-a",
        score=0.8,
    )

    action = map_decision_to_action(
        candidate,
        knowledge,
    )

    assert action is not None
    assert action.type == EnterpriseActionType.EXPLOIT
    assert action.target == "CVE-TEST-0001"


def test_unknown_target_is_not_mapped():
    knowledge = AgentKnowledge()

    action = map_decision_to_action(
        make_recon_candidate("hidden-host"),
        knowledge,
    )

    assert action is None


def test_mapper_does_not_modify_agentknowledge():
    knowledge = AgentKnowledge()

    knowledge.discover(
        "host-a",
        NodeType.HOST,
    )

    before = knowledge.snapshot()

    map_decision_to_action(
        make_recon_candidate("host-a"),
        knowledge,
    )

    assert knowledge.snapshot() == before
