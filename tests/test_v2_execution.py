import pytest

from rlredteam.enterprise.attacker_decision import (
    AttackerDecisionCandidate,
    DecisionKind,
)
from rlredteam.enterprise.environment import (
    EnterpriseCyberEnv,
)
from rlredteam.enterprise.information_value import (
    InformationValueScore,
)
from rlredteam.enterprise.model import (
    EnterpriseNode,
    NodeType,
    TrueTopology,
)
from rlredteam.enterprise.v2_execution import (
    execute_v2_decision,
    plan_v2_execution,
)


@pytest.fixture
def enterprise_env() -> EnterpriseCyberEnv:
    graph = TrueTopology(
        name="v2-execution-test",
        nodes={
            "entry-host": EnterpriseNode(
                id="entry-host",
                type=NodeType.HOST,
                name="Entry Host",
            ),
            "crown-jewel": EnterpriseNode(
                id="crown-jewel",
                type=NodeType.ASSET,
                name="Crown Jewel",
            ),
        },
        edges=[],
        vulnerabilities={},
        entry_points=("entry-host",),
        crown_jewels=("crown-jewel",),
    )

    return EnterpriseCyberEnv(
        graph,
        max_steps=10,
        max_nodes=4,
        max_vulnerabilities=1,
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


def test_unknown_target_returns_no_plan(
    enterprise_env,
):
    env = enterprise_env
    env.reset()

    plan = plan_v2_execution(
        env,
        make_recon_candidate(
            "hidden-target"
        ),
    )

    assert plan is None


def test_plan_uses_existing_action_index(
    enterprise_env,
):
    env = enterprise_env
    env.reset()

    candidate = make_recon_candidate(
        "entry-host"
    )

    plan = plan_v2_execution(
        env,
        candidate,
    )

    assert plan is not None

    assert plan.action_index == env.action_index(
        plan.action.type,
        plan.action.target,
    )

    assert env.action_masks()[
        plan.action_index
    ]


def test_planning_does_not_modify_knowledge(
    enterprise_env,
):
    env = enterprise_env
    env.reset()

    before = env.knowledge.snapshot()

    plan_v2_execution(
        env,
        make_recon_candidate(
            "entry-host"
        ),
    )

    assert env.knowledge.snapshot() == before


def test_unmappable_execution_is_rejected(
    enterprise_env,
):
    env = enterprise_env
    env.reset()

    with pytest.raises(ValueError):
        execute_v2_decision(
            env,
            make_recon_candidate(
                "hidden-target"
            ),
        )