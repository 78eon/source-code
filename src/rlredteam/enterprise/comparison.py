"""Planned comparison contracts and guards only; no algorithm/learner implementation."""

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Protocol

import gymnasium as gym
import numpy as np
import yaml

ENVIRONMENT_CONTRACT = "enterprise-comparison-env-v1"
DEAD_END_CONTRACT = "knowledge-dead-end-v1"
ALGORITHMS = {"PPO", "DQN", "A3C"}
PROTECTED_TEST = set(range(16001, 16021))


def canonical_hash(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def derive_seed(run_seed, domain, index=0):
    if type(run_seed) is not int or run_seed < 0 or type(index) is not int or index < 0:
        raise ValueError("seeds/indices must be nonnegative integers")
    if not isinstance(domain, str) or not domain:
        raise ValueError("seed domain required")
    return int(canonical_hash(["rq1-seed-v1", run_seed, domain, index])[:8], 16)


def seed_pool(value):
    if not isinstance(value, dict) or set(value) != {"start", "stop"}:
        raise ValueError("seed range requires inclusive start and exclusive stop")
    start, stop = value["start"], value["stop"]
    if (
        type(start) is not int
        or type(stop) is not int
        or not 0 <= start < stop
        or stop - start > 10000
    ):
        raise ValueError("invalid bounded seed range")
    result = set(range(start, stop))
    if result & PROTECTED_TEST:
        raise ValueError("registered held-out seeds forbidden")
    return result


def validate_manifest(manifest, arms):
    """Validate planned inputs only. Passing is NOT registration/launch authority."""
    if (
        manifest.get("schema_version") != "rq1-comparison-plan-v1"
        or manifest.get("status") != "planned"
    ):
        raise ValueError("planned comparison schema required")
    if any(
        manifest.get(key) is not False
        for key in ("registered", "training_authorized", "held_out_authorized")
    ):
        raise ValueError("Phase10 cannot authorize execution")
    if manifest.get("final_test_rules") != {
        "locked": True,
        "execution_authorized": False,
        "source_freeze_required": True,
        "development_access": False,
    }:
        raise ValueError("final-test rules must remain locked")
    if (
        manifest.get("algorithms") != ["PPO", "DQN", "A3C"]
        or {arm.get("algorithm") for arm in arms} != ALGORITHMS
        or len(arms) != 3
    ):
        raise ValueError("exactly PPO/DQN/A3C required; A2C is not A3C")
    common = manifest["common"]
    required = {
        "environment_contract",
        "observation_version",
        "action_schema_version",
        "reward_version",
        "reward_config_sha256",
        "dead_end_contract",
        "max_nodes",
        "max_vulnerabilities",
        "max_steps",
        "training_budget",
        "network_scales",
        "topology_split",
        "run_seeds",
        "validation_episode_seeds",
        "final_episode_seeds_locked",
        "validation",
    }
    if set(common) != required:
        raise ValueError("missing or unknown common fields")
    expected = {
        "environment_contract": ENVIRONMENT_CONTRACT,
        "observation_version": "enterprise-observation-v1.1",
        "action_schema_version": "enterprise-discovery-slots-v1",
        "reward_version": "enterprise-config-exclusive-v2",
        "dead_end_contract": DEAD_END_CONTRACT,
    }
    if any(common.get(key) != value for key, value in expected.items()):
        raise ValueError("inconsistent common scientific contract")
    for name in ("max_nodes", "max_vulnerabilities", "max_steps", "training_budget"):
        if type(common.get(name)) is not int or common[name] <= 0:
            raise ValueError("positive integer common budgets/capacities required")
    if common["network_scales"] != [10, 30, 60] or common["max_nodes"] < 60:
        raise ValueError("three prespecified network scales required")
    split = common["topology_split"]
    pools = [seed_pool(split[key]) for key in ("train", "validation", "test_locked")]
    if any(pools[i] & pools[j] for i in range(3) for j in range(i)):
        raise ValueError("overlapping topology splits")
    for field in ("run_seeds", "validation_episode_seeds", "final_episode_seeds_locked"):
        values = common[field]
        if (
            not values
            or any(type(v) is not int or v < 0 for v in values)
            or len(set(values)) != len(values)
        ):
            raise ValueError("nonempty unique integer seed sets required")
        if set(values) & PROTECTED_TEST:
            raise ValueError("reserved seed IDs forbidden in this comparison plan")
    if any(
        set(common[a]) & set(common[b])
        for a, b in (
            ("run_seeds", "validation_episode_seeds"),
            ("run_seeds", "final_episode_seeds_locked"),
            ("validation_episode_seeds", "final_episode_seeds_locked"),
        )
    ):
        raise ValueError("run/evaluation seeds must be separated")
    if common["validation"] != {
        "deterministic": True,
        "policy_updates": False,
        "checkpoint": "terminal_budget",
    }:
        raise ValueError("frozen deterministic terminal-checkpoint validation required")
    for arm in arms:
        if (
            arm.get("status") != "planned"
            or arm.get("experiment_id") != manifest["experiment_id"]
            or arm.get("common_sha256") != canonical_hash(common)
        ):
            raise ValueError("arm/common identity mismatch")
        if arm.get("common") != common:
            raise ValueError("unfair arm changes common contract")
        if arm.get("hyperparameter_status") != "provisional_not_registered":
            raise ValueError("do not label provisional parameters final")
        if (
            arm["algorithm"] == "A3C"
            and arm["algorithm_specific"].get("implementation")
            != "true_asynchronous_A3C_design_not_A2C"
        ):
            raise ValueError("A2C cannot be substituted for A3C")
    return canonical_hash(manifest)


def load_plan(root):
    root = Path(root)
    manifest = json.loads(
        (root / "docs/experiments/RQ1_COMPARISON_MANIFEST_TEMPLATE.json").read_text()
    )
    if manifest["arm_config_files"] != [
        "configs/comparison/ppo_comparison.yaml",
        "configs/comparison/dqn.yaml",
        "configs/comparison/a3c.yaml",
    ]:
        raise ValueError("unexpected arm config paths")
    arms = [yaml.safe_load((root / path).read_text()) for path in manifest["arm_config_files"]]
    validate_manifest(manifest, arms)
    return manifest, arms


def masked_argmax(values, mask):
    values, mask = np.asarray(values), np.asarray(mask)
    if values.ndim != 1 or values.shape != mask.shape or mask.dtype != np.bool_:
        raise ValueError("one-dimensional scores and boolean mask must match")
    if not np.isfinite(values).all() or not mask.any():
        raise ValueError("finite scores and eligible action required; handle terminal frame first")
    return int(np.argmax(np.where(mask, values, -np.inf)))


@dataclass(frozen=True)
class DecisionFrame:
    observation: np.ndarray
    action_mask: np.ndarray
    reward: float
    terminated: bool
    truncated: bool
    success: bool
    terminal_reason: str | None
    transitions: int

    @property
    def done(self):
        return self.terminated or self.truncated


class ComparisonEnvironment:
    """Framework-neutral, common prospective wrapper; not installed into old runners."""

    def __init__(self, environment):
        self._env = environment
        self._closed = True
        self.transitions = 0

    def _frame(self, obs, reward, terminated, truncated, info):
        self._last_info = deepcopy(info)
        mask = np.asarray(self._env.action_masks())
        if (
            mask.shape != (self._env.action_space.n,)
            or not np.isfinite(mask).all()
            or not np.isin(mask, [0, 1]).all()
        ):
            raise ValueError("invalid common action mask")
        if type(info.get("goal_reached")) is not bool or (terminated and truncated):
            raise ValueError("explicit boolean outcome and exclusive flags required")
        success = info["goal_reached"]
        reason = (
            "objective"
            if success
            else "budget_exhaustion"
            if truncated
            else "environment_terminal"
            if terminated
            else None
        )
        if not terminated and not truncated and not mask.any():
            terminated, reason = True, "dead_end"
        self._last_info.update(
            {
                "comparison_contract": ENVIRONMENT_CONTRACT,
                "comparison_terminal_reason": reason,
                "comparison_terminated": bool(terminated),
                "comparison_truncated": bool(truncated),
                "comparison_success": success,
                "comparison_transitions": self.transitions,
            }
        )
        self._closed = bool(terminated or truncated)
        observation = np.array(obs, dtype=np.float32, copy=True)
        if observation.ndim != 1 or not np.isfinite(observation).all() or not np.isfinite(reward):
            raise ValueError("finite flat observation and reward required")
        mask = np.array(mask, dtype=bool, copy=True)
        observation.setflags(write=False)
        mask.setflags(write=False)
        return DecisionFrame(
            observation,
            mask,
            float(reward),
            bool(terminated),
            bool(truncated),
            success,
            reason,
            self.transitions,
        )

    @property
    def evidence_info(self):
        """Detached recorder-only metadata, never passed to AlgorithmAdapter.act."""
        return deepcopy(self._last_info)

    def reset(self, *, seed=None, options=None):
        self.transitions = 0
        obs, info = self._env.reset(seed=seed, options=options)
        return self._frame(obs, 0.0, False, False, info)

    def step(self, action):
        if self._closed:
            raise gym.error.ResetNeeded("comparison episode ended; reset required")
        obs, reward, terminated, truncated, info = self._env.step(action)
        self.transitions += 1
        return self._frame(obs, reward, terminated, truncated, info)


class TransitionBudget:
    """Thread-safe data accounting guard, not a rollout/training loop."""

    def __init__(self, limit):
        if type(limit) is not int or limit <= 0:
            raise ValueError("positive transition limit required")
        self.limit, self.completed = limit, 0
        self._pending, self._next, self._lock = {}, 0, Lock()

    def reserve(self, worker):
        with self._lock:
            if self.completed + len(self._pending) >= self.limit:
                return None
            token = self._next
            self._next += 1
            self._pending[token] = worker
            return token

    def finish(self, token, worker, *, executed=True):
        if type(executed) is not bool:
            raise ValueError("executed flag must be boolean")
        with self._lock:
            if token not in self._pending or self._pending[token] != worker:
                raise ValueError("unknown ticket or wrong worker")
            del self._pending[token]
            self.completed += int(executed)


class AlgorithmAdapter(Protocol):
    """Future experiment-facing methods; internals/optimizers remain algorithm-specific."""

    algorithm: str
    algorithm_version: str

    def act(
        self, observation: np.ndarray, action_mask: np.ndarray, *, deterministic: bool
    ) -> int: ...
    def train(self, context) -> None: ...
    def save(self, path: Path) -> dict: ...
    def load(self, path: Path, metadata: dict) -> None: ...
    def evaluate(self, context) -> dict: ...


def validate_status_change(current, proposed, *, exclusion_rule=None, declared_rules=()):
    allowed = {
        "CONFIGURED": {"RUNNING", "FAILED"},
        "RUNNING": {"TRAINING_COMPLETE", "FAILED"},
        "TRAINING_COMPLETE": {"VALIDATION_COMPLETE", "FAILED"},
        "VALIDATION_COMPLETE": {"TECHNICALLY_VALID", "FAILED"},
        "FAILED": {"EXCLUDED_ONLY_BY_PREDEFINED_RULE"},
    }
    if proposed not in allowed.get(current, set()):
        raise ValueError("invalid run-status transition")
    if proposed == "EXCLUDED_ONLY_BY_PREDEFINED_RULE" and (
        not exclusion_rule or exclusion_rule not in declared_rules
    ):
        raise ValueError("predeclared exclusion rule required; poor reward is not a rule")
    return proposed
