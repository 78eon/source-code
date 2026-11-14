"""Phase10 contracts only: synthetic transitions and accounting, no learners/models."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import gymnasium as gym
import numpy as np
import pytest

from rlredteam.enterprise.comparison import (
    ComparisonEnvironment,
    TransitionBudget,
    canonical_hash,
    derive_seed,
    load_plan,
    masked_argmax,
    seed_pool,
    validate_manifest,
    validate_status_change,
)
from rlredteam.enterprise.environment import EnterpriseActionType as A
from rlredteam.enterprise.environment import EnterpriseCyberEnv
from rlredteam.enterprise.model import EnterpriseNode, TrueTopology
from rlredteam.enterprise.model import NodeType as N
from rlredteam.enterprise.reward_config import EnterpriseRewardConfig
from tests.test_phase7_environment_contract import TRACE, environment, world

pytestmark = pytest.mark.environment
ROOT = Path(__file__).resolve().parents[1]


def test_plan_common_contracts_and_prospective_identities():
    manifest, arms = load_plan(ROOT)
    assert validate_manifest(manifest, arms)
    for arm in arms:
        assert arm["common"] == manifest["common"]
        assert arm["common_sha256"] == canonical_hash(manifest["common"])
    assert manifest["common"]["reward_config_sha256"] == EnterpriseRewardConfig.from_yaml().digest()
    assert not manifest["registered"] and not manifest["training_authorized"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("observation_version", "belief-observation-v2.15"),
        ("reward_version", "other"),
        ("action_schema_version", "other"),
        ("environment_contract", "other"),
        ("training_budget", 123),
        ("max_nodes", 16),
        ("max_steps", 10),
        ("dead_end_contract", "free_noop"),
        ("network_scales", [10]),
        (
            "topology_split",
            {
                "id": "wrong",
                "train": {"start": 1, "stop": 2},
                "validation": {"start": 3, "stop": 4},
                "test_locked": {"start": 5, "stop": 6},
            },
        ),
        ("reward_config_sha256", "0" * 64),
        ("validation_episode_seeds", [999]),
    ],
)
def test_inconsistent_arm_rejected(field, value):
    manifest, arms = load_plan(ROOT)
    arms[1]["common"][field] = value
    arms[1]["common_sha256"] = canonical_hash(arms[1]["common"])
    with pytest.raises(ValueError):
        validate_manifest(manifest, arms)


@pytest.mark.parametrize("flag", ["registered", "training_authorized", "held_out_authorized"])
def test_template_cannot_authorize_execution(flag):
    manifest, arms = load_plan(ROOT)
    manifest[flag] = True
    with pytest.raises(ValueError, match="authorize"):
        validate_manifest(manifest, arms)


@pytest.mark.parametrize("pool", ["train", "validation", "test_locked"])
def test_registered_heldout_never_enters_comparison(pool):
    manifest, arms = load_plan(ROOT)
    manifest["common"]["topology_split"][pool] = {"start": 16001, "stop": 16021}
    with pytest.raises(ValueError, match="held-out"):
        validate_manifest(manifest, arms)


def test_overlapping_and_missing_inputs_fail_closed():
    manifest, arms = load_plan(ROOT)
    manifest["common"]["topology_split"]["validation"] = manifest["common"]["topology_split"][
        "train"
    ]
    with pytest.raises(ValueError, match="overlapping"):
        validate_manifest(manifest, arms)
    manifest, arms = load_plan(ROOT)
    del manifest["common"]["training_budget"]
    with pytest.raises(ValueError, match="common fields"):
        validate_manifest(manifest, arms)


def test_a2c_not_substituted_or_historical_ppo_reused():
    manifest, arms = load_plan(ROOT)
    arms[2]["algorithm_specific"]["implementation"] = "A2C"
    with pytest.raises(ValueError, match="A2C"):
        validate_manifest(manifest, arms)
    assert manifest["source_commit"] is None
    assert manifest["experiment_id"] != "onprem-generalisation-registered-v1"


def test_seed_derivation_stable_domains_worker_independence():
    workers = [derive_seed(52001, "worker-policy", i) for i in range(4)]
    assert len(set(workers)) == 4
    assert workers == [4241290040, 3157146455, 3927327683, 2223174237]
    for run_seed in range(52001, 52011):
        assert len({derive_seed(run_seed, "worker-policy", index) for index in range(4)}) == 4
    assert workers == [derive_seed(52001, "worker-policy", i) for i in range(4)]
    assert derive_seed(52001, "topology", 0) != derive_seed(52001, "environment", 0)
    assert derive_seed(52001, "initialization", 0) != derive_seed(52002, "initialization", 0)


@pytest.mark.parametrize("args", [(True, "x", 0), (-1, "x", 0), (1, "", 0), (1, "x", -1)])
def test_invalid_seed_input_rejected(args):
    with pytest.raises(ValueError):
        derive_seed(*args)


def test_dqn_shape_feasibility_same_flattening_and_masks():
    manifest, _ = load_plan(ROOT)
    common = manifest["common"]
    m, v = common["max_nodes"], common["max_vulnerabilities"]
    assert 27 * m + m * m + 1 == 11809
    assert 10 * m + v == 968
    q = np.arange(968, dtype=float)
    mask = np.zeros(968, dtype=bool)
    mask[[2, 10, 33]] = True
    assert masked_argmax(q, mask) == 33
    assert masked_argmax(np.ones(968), mask) == 2
    with pytest.raises(ValueError):
        masked_argmax(q, np.zeros(968, dtype=bool))


def test_dead_end_after_real_transition_no_extra_reward_or_data():
    graph = TrueTopology(
        "dead-end-synthetic",
        {
            "entry": EnterpriseNode("entry", N.ENTRY_POINT, "entry"),
            "goal": EnterpriseNode("goal", N.ASSET, "goal"),
        },
        [],
        {},
        ("entry",),
        ("goal",),
    )
    base = EnterpriseCyberEnv(graph, max_nodes=4)
    wrapped = ComparisonEnvironment(base)
    first = wrapped.reset(seed=7)
    assert not first.done
    frame = wrapped.step(base.action_index(A.ASSESS_VULNERABILITY, "entry"))
    assert frame.done and frame.terminated and not frame.truncated and not frame.success
    assert frame.terminal_reason == "dead_end" and not frame.action_mask.any()
    assert frame.transitions == 1 and len(base.events) == 1
    assert frame.reward == base.events[-1].reward == base.episode_return
    assert wrapped.evidence_info["comparison_terminal_reason"] == "dead_end"
    with pytest.raises(gym.error.ResetNeeded):
        wrapped.step(0)
    assert len(base.events) == 1
    assert not wrapped.reset(seed=7).done


def test_initial_dead_end_is_zero_transition_failure():
    class Empty:
        action_space = gym.spaces.Discrete(2)

        def reset(self, **kwargs):
            return np.zeros(3), {"goal_reached": False}

        def action_masks(self):
            return np.zeros(2, dtype=bool)

        def step(self, action):
            raise AssertionError("initial dead end must not fabricate a step")

    frame = ComparisonEnvironment(Empty()).reset(seed=7)
    assert frame.terminal_reason == "dead_end" and frame.terminated
    assert frame.reward == 0 and frame.transitions == 0 and not frame.success


@pytest.mark.parametrize("limit,outcome", [(13, "objective"), (12, "budget_exhaustion")])
def test_goal_budget_precedence_unchanged(limit, outcome):
    base = EnterpriseCyberEnv(world(), max_steps=limit, max_nodes=16, max_vulnerabilities=4)
    wrapper = ComparisonEnvironment(base)
    wrapper.reset(seed=7)
    for kind, target in TRACE[:limit]:
        frame = wrapper.step(base.action_index(kind, target))
    assert frame.terminal_reason == outcome
    assert frame.success == (outcome == "objective")
    assert frame.truncated == (outcome == "budget_exhaustion")
    assert not (frame.terminated and frame.truncated)


def test_wrapper_inputs_copies_and_worker_worlds_independent():
    left, right = environment(), environment()
    a, b = ComparisonEnvironment(left), ComparisonEnvironment(right)
    first, second = a.reset(seed=7), b.reset(seed=7)
    assert not first.observation.flags.writeable and not first.action_mask.flags.writeable
    assert not np.shares_memory(first.observation, second.observation)
    a.step(left.action_index(A.DISCOVER_NETWORK, "net"))
    assert "host" not in right.knowledge.discovered
    info = a.evidence_info
    info["action_mask"][:] = 0
    assert a.evidence_info["action_mask"].any()


def test_worker_transition_budget_global_not_n_times_data():
    budget = TransitionBudget(101)

    def worker(index):
        count = 0
        while True:
            ticket = budget.reserve(index)
            if ticket is None:
                return count
            budget.finish(ticket, index)
            count += 1

    with ThreadPoolExecutor(max_workers=4) as pool:
        counts = list(pool.map(worker, range(4)))
    assert sum(counts) == budget.completed == 101
    assert budget.reserve(0) is None


def test_budget_cancel_and_wrong_worker_are_safe():
    budget = TransitionBudget(1)
    token = budget.reserve(0)
    with pytest.raises(ValueError):
        budget.finish(token, 1)
    budget.finish(token, 0, executed=False)
    assert budget.completed == 0
    next_token = budget.reserve(1)
    assert next_token != token
    budget.finish(next_token, 1)
    assert budget.completed == 1


def test_status_model_no_skipping_evidence_or_discarding_bad_seeds():
    status = "CONFIGURED"
    for next_status in ("RUNNING", "TRAINING_COMPLETE", "VALIDATION_COMPLETE", "TECHNICALLY_VALID"):
        status = validate_status_change(status, next_status)
    with pytest.raises(ValueError):
        validate_status_change("RUNNING", "TECHNICALLY_VALID")
    with pytest.raises(ValueError):
        validate_status_change(
            "FAILED", "EXCLUDED_ONLY_BY_PREDEFINED_RULE", exclusion_rule="poor_reward"
        )


def test_declared_fresh_pools_only_no_topology_generated():
    manifest, _ = load_plan(ROOT)
    split = manifest["common"]["topology_split"]
    assert seed_pool(split["train"]) == set(range(20001, 20061))
    assert seed_pool(split["validation"]) == set(range(21001, 21021))
    assert seed_pool(split["test_locked"]) == set(range(22001, 22021))
