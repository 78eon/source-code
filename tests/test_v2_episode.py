import pytest

from rlredteam.enterprise.environment import (
    EnterpriseCyberEnv,
)
from rlredteam.enterprise.model import (
    EnterpriseEdge,
    EnterpriseNode,
    EdgeType,
    NodeType,
    TrueTopology,
)
from rlredteam.enterprise.v2_episode import (
    run_v2_episode,
)


@pytest.fixture
def episode_env() -> EnterpriseCyberEnv:
    graph = TrueTopology(
        name="v2-episode-test",
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


def test_episode_runs_at_least_one_reasoning_step(
    episode_env,
):
    result = run_v2_episode(
        episode_env,
        goal_id="asset-a",
        max_reasoning_steps=3,
    )

    assert len(result.steps) >= 1


def test_episode_respects_reasoning_step_limit(
    episode_env,
):
    result = run_v2_episode(
        episode_env,
        goal_id="asset-a",
        max_reasoning_steps=1,
    )

    assert len(result.steps) <= 1


def test_episode_records_environment_actions(
    episode_env,
):
    result = run_v2_episode(
        episode_env,
        goal_id="asset-a",
        max_reasoning_steps=3,
    )

    assert all(
        step.action is not None
        for step in result.steps
    )


def test_episode_changes_visible_knowledge(
    episode_env,
):
    before = episode_env.knowledge.snapshot()

    result = run_v2_episode(
        episode_env,
        goal_id="asset-a",
        max_reasoning_steps=3,
    )

    assert (
        result.final_knowledge_snapshot
        != before
    )


def test_invalid_reasoning_limit_is_rejected(
    episode_env,
):
    with pytest.raises(ValueError):
        run_v2_episode(
            episode_env,
            goal_id="asset-a",
            max_reasoning_steps=0,
        )