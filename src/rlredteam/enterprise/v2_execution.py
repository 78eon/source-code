"""Safe execution bridge from V2 decisions to the existing environment."""

from __future__ import annotations

from dataclasses import dataclass

from rlredteam.enterprise.attacker_decision import (
    AttackerDecisionCandidate,
)
from rlredteam.enterprise.decision_action_mapper import (
    map_decision_to_action,
)
from rlredteam.enterprise.environment import (
    EnterpriseAction,
    EnterpriseCyberEnv,
)


@dataclass(frozen=True, slots=True)
class V2ExecutionPlan:
    action: EnterpriseAction
    action_index: int


def plan_v2_execution(
    env: EnterpriseCyberEnv,
    candidate: AttackerDecisionCandidate,
) -> V2ExecutionPlan | None:
    """Map one V2 decision into a currently valid environment action."""

    action = map_decision_to_action(
        candidate,
        env.knowledge,
    )

    if action is None:
        return None

    try:
        action_index = env.action_index(
            action.type,
            action.target,
        )
    except KeyError:
        return None

    mask = env.action_masks()

    if not bool(mask[action_index]):
        return None

    return V2ExecutionPlan(
        action=action,
        action_index=action_index,
    )


def execute_v2_decision(
    env: EnterpriseCyberEnv,
    candidate: AttackerDecisionCandidate,
):
    """Execute only through the environment's existing step interface."""

    plan = plan_v2_execution(
        env,
        candidate,
    )

    if plan is None:
        raise ValueError(
            "V2 decision cannot be mapped to a valid action"
        )

    return env.step(
        plan.action_index
    )