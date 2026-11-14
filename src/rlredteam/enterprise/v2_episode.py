"""Repeated V2 attacker reasoning and execution loop."""

from __future__ import annotations

from dataclasses import dataclass

from rlredteam.enterprise.environment import (
    EnterpriseAction,
    EnterpriseCyberEnv,
)
from rlredteam.enterprise.v2_execution import (
    execute_v2_decision,
)
from rlredteam.enterprise.v2_reasoner import (
    V2ReasoningResult,
    reason_next_action,
)


@dataclass(frozen=True, slots=True)
class V2EpisodeStep:
    reasoning: V2ReasoningResult
    action: EnterpriseAction
    reward: float
    terminated: bool
    truncated: bool


@dataclass(frozen=True, slots=True)
class V2EpisodeResult:
    steps: tuple[V2EpisodeStep, ...]
    terminated: bool
    truncated: bool
    goal_reached: bool
    stopped_without_plan: bool
    final_knowledge_snapshot: tuple


def run_v2_episode(
    env: EnterpriseCyberEnv,
    *,
    goal_id: str,
    max_reasoning_steps: int = 100,
) -> V2EpisodeResult:
    """Run repeated V2 reasoning through the existing environment."""

    if max_reasoning_steps <= 0:
        raise ValueError(
            "max_reasoning_steps must be positive"
        )

    steps: list[V2EpisodeStep] = []
    terminated = False
    truncated = False
    stopped_without_plan = False

    for _ in range(max_reasoning_steps):
        reasoning = reason_next_action(
            env,
            goal_id=goal_id,
        )

        if (
            reasoning.selected_decision is None
            or reasoning.execution_plan is None
        ):
            stopped_without_plan = True
            break

        action = reasoning.execution_plan.action

        (
            _observation,
            reward,
            terminated,
            truncated,
            info,
        ) = execute_v2_decision(
            env,
            reasoning.selected_decision,
        )

        steps.append(
            V2EpisodeStep(
                reasoning=reasoning,
                action=action,
                reward=float(reward),
                terminated=terminated,
                truncated=truncated,
            )
        )

        if terminated or truncated:
            break

    goal_reached = bool(
        env.knowledge.accessed_assets
        and goal_id in env.knowledge.accessed_assets
    )

    return V2EpisodeResult(
        steps=tuple(steps),
        terminated=terminated,
        truncated=truncated,
        goal_reached=goal_reached,
        stopped_without_plan=stopped_without_plan,
        final_knowledge_snapshot=(
            env.knowledge.snapshot()
        ),
    )