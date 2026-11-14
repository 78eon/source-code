import pytest

from rlredteam.enterprise.attacker_decision import (
    DecisionKind,
)
from rlredteam.enterprise.environment import (
    EnterpriseCyberEnv,
    EnterpriseActionType,
)
from rlredteam.enterprise.model import (
    EnterpriseEdge,
    EnterpriseNode,
    EdgeType,
    NodeType,
    TrueTopology,
)
from rlredteam.enterprise.v2_reasoner import (
    reason_next_action,
)


@pytest.fixture
def reasoning_env() -> EnterpriseCyberEnv:
    graph = TrueTopology(
        name="v2-reasoner-test",
        nodes={
            "entry-host": EnterpriseNode(
                id="entry-host",
                type=NodeType.HOST,
                name="Entry Host",
            ),
            "asset-a": EnterpriseNode(
                id="asset-a",
                type=NodeType.ASSET,
                name="Asset A",
            ),
        },
        edges=[
            EnterpriseEdge(
                source="entry-host",
                target="asset-a",
                type=EdgeType.CONTAINS,
            ),
        ],
        vulnerabilities={},
        entry_points=("entry-host",),
        crown_jewels=("asset-a",),
    )

    env = EnterpriseCyberEnv(
        graph,
        max_steps=10,
        max_nodes=4,
        max_vulnerabilities=1,
    )

    env.reset()

    return env


def test_reasoner_builds_beliefs_and_graph(
    reasoning_env,
):
    result = reason_next_action(
        reasoning_env,
        goal_id="asset-a",
    )

    assert result.beliefs is not None
    assert result.graph is not None

    assert "entry-host" in result.graph.nodes


def test_reasoner_does_not_modify_knowledge(
    reasoning_env,
):
    before = reasoning_env.knowledge.snapshot()

    reason_next_action(
        reasoning_env,
        goal_id="asset-a",
    )

    assert reasoning_env.knowledge.snapshot() == before


def test_reasoner_can_select_valid_recon_action(
    reasoning_env,
):
    result = reason_next_action(
        reasoning_env,
        goal_id="asset-a",
    )

    assert result.selected_decision is not None
    assert result.execution_plan is not None

    assert result.selected_decision.kind in {
        DecisionKind.RECON,
        DecisionKind.PROGRESS,
    }

    assert reasoning_env.action_masks()[
        result.execution_plan.action_index
    ]


def test_reasoner_execution_plan_matches_environment_index(
    reasoning_env,
):
    result = reason_next_action(
        reasoning_env,
        goal_id="asset-a",
    )

    assert result.execution_plan is not None

    action = result.execution_plan.action

    expected_index = reasoning_env.action_index(
        action.type,
        action.target,
    )

    assert result.execution_plan.action_index == (
        expected_index
    )


def test_reasoner_does_not_require_goal_to_be_known(
    reasoning_env,
):
    result = reason_next_action(
        reasoning_env,
        goal_id="unknown-goal",
    )

    assert result.paths == ()

    assert result.selected_decision is not None


def test_reasoner_does_not_execute_environment_step(
    reasoning_env,
):
    before_step = reasoning_env._step

    result = reason_next_action(
        reasoning_env,
        goal_id="asset-a",
    )

    assert reasoning_env._step == before_step
    assert result.execution_plan is not None


def test_reasoner_uses_existing_action_type(
    reasoning_env,
):
    result = reason_next_action(
        reasoning_env,
        goal_id="asset-a",
    )

    assert result.execution_plan is not None

    assert isinstance(
        result.execution_plan.action.type,
        EnterpriseActionType,
    )
def test_selected_action_has_immutable_deterministic_explanation(reasoning_env):
    from dataclasses import FrozenInstanceError
    first = reason_next_action(reasoning_env, goal_id="asset-a")
    second = reason_next_action(reasoning_env, goal_id="asset-a")
    explanation = first.explanation
    assert explanation == second.explanation
    assert explanation.decision == first.selected_decision
    assert explanation.execution_plan == first.execution_plan
    assert explanation.supporting_facts
    assert explanation.evidence_ids == ()  # bridge does not invent provenance
    assert explanation.source_ids == ()
    with pytest.raises(FrozenInstanceError):
        explanation.selection_rank = 10
    first.beliefs.facts.clear()
    assert explanation.supporting_facts


def test_explanation_preserves_path_fact_provenance():
    from rlredteam.enterprise.belief import AttackerBeliefState, BeliefFact, BeliefStatus
    from rlredteam.enterprise.attacker_graph import AttackerKnowledgeGraph
    from rlredteam.enterprise.attack_path_reasoner import find_candidate_paths
    from rlredteam.enterprise.attacker_decision import progress_candidate
    from rlredteam.enterprise.environment import EnterpriseAction
    from rlredteam.enterprise.v2_execution import V2ExecutionPlan
    from rlredteam.enterprise.v2_reasoner import explain_decision
    b = AttackerBeliefState()
    fact = BeliefFact("a", "edge:connects", "b", 0.5, BeliefStatus.INFERRED,
                      evidence_ids=("e1",), source_ids=("sensor1",),
                      contradictory_evidence_ids=("conflict1",))
    b.learn(fact)
    path = find_candidate_paths(AttackerKnowledgeGraph.from_beliefs(b), "a", "b")[0]
    decision = progress_candidate(path)
    plan = V2ExecutionPlan(EnterpriseAction(EnterpriseActionType.ENUMERATE_HOST, "b"), 0)
    explanation = explain_decision(b, decision, plan, selection_rank=2)
    assert explanation.supporting_facts == (fact,)
    assert explanation.evidence_ids == ("e1",)
    assert explanation.source_ids == ("sensor1",)
    assert explanation.contradictory_evidence_ids == ("conflict1",)
    assert explanation.decision.path == path
    assert explanation.motivating_paths == (path,)

    from rlredteam.enterprise.information_value import rank_information_targets
    from rlredteam.enterprise.attacker_decision import recon_candidate
    information = rank_information_targets(b, paths=(path,), path_weight=1.0)[0]
    recon = explain_decision(b, recon_candidate(information), plan,
                             selection_rank=1, paths=(path,))
    assert recon.motivating_paths == (path,)
    assert recon.evidence_ids == ("e1",)
    assert recon.decision.information.path_component > 0


def test_reasoner_cannot_access_hidden_topology_or_execute(reasoning_env):
    class VisiblePort:
        knowledge = reasoning_env.knowledge
        action_index = reasoning_env.action_index
        action_masks = reasoning_env.action_masks
        def __getattr__(self, name):
            raise AssertionError("Forbidden environment access: " + name)
    result = reason_next_action(VisiblePort(), goal_id="unknown-goal")
    assert result.execution_plan is not None
    assert result.explanation is not None

