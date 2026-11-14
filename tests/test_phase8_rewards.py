"""Synthetic active/registered reward checks; no training or held-out execution."""

import hashlib
import importlib.util
import json
import pickle
import sys
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import gymnasium as gym
import numpy as np
import pytest
import yaml

from rlredteam.enterprise.environment import EnterpriseActionType as A
from rlredteam.enterprise.environment import EnterpriseCyberEnv
from rlredteam.enterprise.model import EdgeType, EnterpriseEdge, EnterpriseNode, NodeType
from rlredteam.enterprise.reward_attribution import REWARD_VERSION, implementation_sha256
from rlredteam.enterprise.reward_config import EnterpriseRewardConfig
from tests.test_phase7_environment_contract import TRACE, act, environment, prefix, world

pytestmark = pytest.mark.environment
PROTECTED_SHA = "a7dfcefea42f05824c1e44b8377dae9a4ea2a0c7f68d46a266a7f38b55fca123"


@pytest.fixture(scope="module")
def reference():
    # This exact protected source file is mounted RO by the bounded runner.
    path = Path("/reference/environment.py")
    assert hashlib.sha256(path.read_bytes()).hexdigest() == PROTECTED_SHA
    name = "phase8_protected_reference"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    yield module
    del sys.modules[name]
    assert hashlib.sha256(path.read_bytes()).hexdigest() == PROTECTED_SHA


BRANCHES = [
    (0, A.DISCOVER_NETWORK, "net", "information_state_change", 1),
    (1, A.ENUMERATE_HOST, "host", "information_state_change", 1),
    (2, A.ENUMERATE_SERVICE, "service", "information_state_change", 1),
    (3, A.ENUMERATE_APPLICATION, "app", "information_state_change", 1),
    (4, A.ASSESS_VULNERABILITY, "service", "information_state_change", 1),
    (5, A.EXPLOIT, "native-entry", "exploit", 1),
    (7, A.ESCALATE_PRIVILEGE, "host", "escalate_privilege", 4),
    (8, A.OBTAIN_CREDENTIAL, "identity", "obtain_credential", 2),
    (9, A.AUTHENTICATE, "db", "authenticate", 3),
    (10, A.PIVOT, "pivot", "pivot", 3),
    (12, A.ACCESS_ASSET, "asset", "objective", 100),
]


@pytest.mark.parametrize("count,kind,target,branch,expected", BRANCHES)
def test_each_active_primary_branch(count, kind, target, branch, expected):
    env = environment()
    prefix(env, count)
    _, reward, _, _, info = act(env, kind, target)
    attribution = info["reward_attribution"]
    assert reward == expected == info["event"].reward == attribution.reward_total
    assert attribution.reward_component == branch
    assert attribution.success and attribution.state_change
    assert attribution.cvss_used == (5 if branch == "exploit" else None)
    assert attribution.reward_version == REWARD_VERSION
    assert attribution.reward_config_sha256 == env.reward_config.digest()
    assert attribution.reward_implementation_sha256 == implementation_sha256()
    assert env.episode_return == sum(event.reward for event in env.events)


@pytest.mark.parametrize("count,kind,target,branch,expected", BRANCHES)
def test_protected_branches_read_only(reference, count, kind, target, branch, expected):
    env = reference.EnterpriseCyberEnv(world(), max_nodes=16, max_steps=30)
    env.reset(seed=7)
    for action_kind, action_target in TRACE[:count]:
        env.step(env.action_index(reference.EnterpriseActionType(action_kind.value), action_target))
    result = env.step(env.action_index(reference.EnterpriseActionType(kind.value), target))
    assert result[1] == expected == result[-1]["event"].reward


@pytest.mark.parametrize(
    "mode", ["invalid_exploit", "missing_prerequisite", "exploit_failure", "escalation_failure"]
)
def test_failure_has_one_penalty_and_no_success_mutation(mode):
    env = environment(
        probability=0 if mode == "exploit_failure" else 1,
        root_probability=0 if mode == "escalation_failure" else 1,
    )
    prefix(env, 7 if mode == "escalation_failure" else 5 if mode == "exploit_failure" else 2)
    before = env.agent_knowledge.snapshot()
    if mode == "invalid_exploit":
        index = next(i for i, a in enumerate(env.actions) if a.type == A.EXPLOIT)
    else:
        kind, target = (
            (A.EXPLOIT, "native-entry")
            if mode == "exploit_failure"
            else (A.ESCALATE_PRIVILEGE, "host")
            if mode == "escalation_failure"
            else (A.OBTAIN_CREDENTIAL, "identity")
        )
        index = env.action_index(kind, target)
    _, reward, _, _, info = env.step(index)
    assert reward == -5  # Not -5 plus no-change or a success component.
    assert env.agent_knowledge.snapshot() == before
    attribution = info["reward_attribution"]
    assert not attribution.success and not attribution.state_change
    assert attribution.reward_component == (
        "stochastic_failure" if mode.endswith("failure") else "invalid_action"
    )
    assert attribution.cvss_used is None


def test_protected_invalid_and_stochastic_failure(reference):
    env = reference.EnterpriseCyberEnv(world(probability=0), max_nodes=16)
    env.reset(seed=7)
    invalid = env.action_index(reference.EnterpriseActionType.ACCESS_ASSET, "net")
    assert env.step(invalid)[1] == -5
    invalid_exploit = next(
        index
        for index, action in enumerate(env.actions)
        if action.type == reference.EnterpriseActionType.EXPLOIT
    )
    assert env.step(invalid_exploit)[1] == -5
    for kind, target in TRACE[:5]:
        env.step(env.action_index(reference.EnterpriseActionType(kind.value), target))
    before = env.knowledge.snapshot()
    result = env.step(env.action_index(reference.EnterpriseActionType.EXPLOIT, "native-entry"))
    assert result[1] == -5 and not result[-1]["event"].success
    assert env.knowledge.snapshot() == before


@pytest.mark.parametrize("implementation", ["active", "protected"])
def test_defensive_no_change_and_other_change(reference, implementation):
    if implementation == "active":
        env = environment()
        kind = A
    else:
        env = reference.EnterpriseCyberEnv(world(), max_nodes=16)
        kind = reference.EnterpriseActionType
    env.reset(seed=7)
    assert env._reward(kind.EXPLOIT, "native-entry", False) == -1
    # Other branch is a genuinely accessed non-objective asset, not a new action.
    env.true_topology.nodes["other"] = EnterpriseNode("other", NodeType.ASSET, "other")
    env.true_topology.edges.append(EnterpriseEdge("db", "other", EdgeType.CONTAINS))
    for action_kind, target in TRACE[:12]:
        env.step(env.action_index(kind(action_kind.value), target))
    result = env.step(env.action_index(kind.ACCESS_ASSET, "other"))
    assert result[1] == 0 and not result[2] and result[-1]["event"].state_changed
    if implementation == "active":
        assert result[-1]["reward_attribution"].reward_component == "other_state_change"


def test_successful_no_change_attribution_is_distinct_from_invalid(monkeypatch):
    # Defensive valid/no-delta branch is normally unreachable: actual repeated
    # enumeration fails prerequisites. Inject only this transition result.
    env = environment()
    env.reset(seed=7)
    monkeypatch.setattr(
        env,
        "_execute",
        lambda action: (True, False, env._reward(action.type, action.target, False), (), (), ""),
    )
    result = act(env, A.DISCOVER_NETWORK, "net")
    assert result[1] == -1
    assert result[-1]["reward_attribution"].reward_component == "no_state_change"
    assert result[-1]["event"].success and not result[-1]["event"].state_changed


def test_repeat_is_invalid_not_successful_no_op():
    env = environment()
    prefix(env, 1)
    result = act(env, A.DISCOVER_NETWORK, "net")
    assert result[1] == -5 and not result[-1]["event"].success
    assert result[-1]["reward_attribution"].reward_component == "invalid_action"


@pytest.mark.parametrize("cvss", [0, 0.1, 2.3, 5, 9.8, 10])
def test_cvss_formula_both_implementations(reference, cvss):
    for cls in (EnterpriseCyberEnv, reference.EnterpriseCyberEnv):
        graph = world()
        graph.vulnerabilities["native-entry"] = replace(
            graph.vulnerabilities["native-entry"], cvss=cvss
        )
        env = cls(graph, max_nodes=16)
        env.reset(seed=7)
        # The actual protected class uses its own semantic enum; string enums compare by value.
        for kind, target in TRACE[:5]:
            env.step(env.action_index(kind, target))
        reward = act(env, A.EXPLOIT, "native-entry")[1]
        assert reward == pytest.approx(0.5 + cvss / 10)
        assert 0.5 <= reward <= 1.5


@pytest.mark.parametrize("cvss", [-1, 11, float("nan"), float("inf"), None, "9.8", True])
def test_malformed_or_missing_cvss_rejected(cvss):
    with pytest.raises(ValueError):
        replace(world().vulnerabilities["native-entry"], cvss=cvss)


@pytest.mark.parametrize("mode", ["goal_at_budget", "truncation", "invalid", "failure"])
def test_episode_accounting_and_reset(mode):
    env = EnterpriseCyberEnv(
        world(probability=0 if mode == "failure" else 1),
        max_nodes=16,
        max_steps=13 if mode == "goal_at_budget" else 6,
    )
    env.reset(seed=7)
    total = 0.0
    sequence = (
        TRACE
        if mode == "goal_at_budget"
        else TRACE[:6]
        if mode == "failure"
        else [(A.ACCESS_ASSET, "net")] * 6
    )
    for kind, target in sequence:
        _, reward, terminated, truncated, info = act(env, kind, target)
        total += reward
        assert env.episode_return == total == sum(event.reward for event in env.events)
        assert info["reward_attribution"].episode_return == total
    if mode == "goal_at_budget":
        assert terminated and not truncated
        assert reward == 100 and info["reward_attribution"].reward_component == "objective"
    else:
        assert truncated and not terminated
    with pytest.raises(gym.error.ResetNeeded):
        env.step(0)
    assert env.episode_return == total
    env.reset(seed=7)
    assert env.episode_return == 0 and not env.events


def test_reward_replay_includes_reward_and_attribution():
    traces = []
    for _ in range(2):
        env = environment()
        env.reset(seed=7)
        rows = []
        for kind, target in TRACE:
            _, reward, terminated, truncated, info = act(env, kind, target)
            rows.append(
                {
                    "reward": reward,
                    "attribution": info["reward_attribution"].as_row(),
                    "terminated": terminated,
                    "truncated": truncated,
                }
            )
        traces.append(hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest())
    assert traces[0] == traces[1]


@pytest.mark.parametrize(
    "field",
    ["invalid_action", "no_state_change", "crown_jewel", "exploit_base", "exploit_cvss_scale"],
)
@pytest.mark.parametrize("value", [float("nan"), float("inf"), None, "5", True])
def test_direct_config_rejects_malformed_numeric(field, value):
    with pytest.raises(ValueError, match="finite numeric"):
        replace(EnterpriseRewardConfig.from_yaml(), **{field: value})


def test_action_values_immutable_validated_and_hash_canonical():
    config = EnterpriseRewardConfig.from_yaml()
    assert deepcopy(config).digest() == config.digest()
    assert pickle.loads(pickle.dumps(config)).digest() == config.digest()
    huge = replace(config, action_rewards={**config.action_rewards, "pivot": 1e308})
    with pytest.raises(ValueError, match="episode return budget"):
        EnterpriseCyberEnv(world(), reward_config=huge)
    original = dict(config.action_rewards)
    config2 = replace(config, action_rewards=original)
    original["pivot"] = 999
    assert config2.action_rewards["pivot"] == 3
    with pytest.raises(TypeError):
        config2.action_rewards["pivot"] = 999
    with pytest.raises(ValueError):
        replace(config, action_rewards={**config.action_rewards, "pivot": float("nan")})
    assert (
        config.digest()
        == replace(
            config, action_rewards=dict(reversed(list(config.action_rewards.items())))
        ).digest()
    )


@pytest.mark.parametrize(
    "defect",
    [
        "root_unknown",
        "unknown",
        "exploit_unknown",
        "missing",
        "duplicate",
        "alias",
        "version",
        "malformed",
        "action_missing",
        "action_unknown",
        "positive_failure",
        "overflow",
    ],
)
def test_yaml_config_boundary(tmp_path, defect):
    payload = yaml.safe_load(Path("configs/enterprise_reward.yaml").read_text())
    reward = payload["enterprise_reward"]
    if defect == "root_unknown":
        payload["unknown"] = 1
    elif defect == "unknown":
        reward["unknown"] = 1
    elif defect == "exploit_unknown":
        reward["exploit"]["unknown"] = 1
    elif defect == "missing":
        del reward["crown_jewel"]
    elif defect == "version":
        reward["schema_version"] = "future"
    elif defect == "malformed":
        reward["crown_jewel"] = "100"
    elif defect == "action_missing":
        del reward["actions"]["pivot"]
    elif defect == "action_unknown":
        reward["actions"]["invented"] = 1
    elif defect == "positive_failure":
        reward["invalid_action"] = 1
    elif defect == "overflow":
        reward["exploit"]["cvss_scale"] = 1e308
    text = yaml.safe_dump(payload)
    if defect == "duplicate":
        text += "enterprise_reward: {}\n"
    elif defect == "alias":
        text = "enterprise_reward: &reward {}\nother: *reward\n"
    path = tmp_path / "bad.yaml"
    path.write_text(text)
    with pytest.raises(ValueError):
        EnterpriseRewardConfig.from_yaml(path)


def test_hidden_cvss_reward_potential_not_in_policy_observation():
    environments = []
    for cvss in (0, 10):
        graph = world()
        graph.vulnerabilities["native-entry"] = replace(
            graph.vulnerabilities["native-entry"], cvss=cvss
        )
        env = EnterpriseCyberEnv(graph, max_nodes=16)
        prefix(env, 5)
        environments.append(env)
    left, right = environments
    assert np.array_equal(left._observation(), right._observation())
    assert np.array_equal(left.action_masks(), right.action_masks())
    assert left.agent_knowledge.snapshot() == right.agent_knowledge.snapshot()
    assert act(left, A.EXPLOIT, "native-entry")[1] == 0.5
    assert act(right, A.EXPLOIT, "native-entry")[1] == 1.5


def test_reward_identity_and_purity():
    env = environment()
    prefix(env, 5)
    before = env.agent_knowledge.snapshot()
    rng = deepcopy(env.np_random.bit_generator.state)
    assert env._reward(A.EXPLOIT, "native-entry", True) == 1
    assert env.agent_knowledge.snapshot() == before
    assert env.np_random.bit_generator.state == rng
    assert len(implementation_sha256()) == 64


def test_converted_reward_uses_frozen_world_not_live_evidence():
    from rlredteam.digital_twin.conversion_result import convert_draft_to_true_topology
    from tests.simulation_conversion_fixtures import executable

    draft = executable(approved=True)
    result = convert_draft_to_true_topology(draft, draft.policy)
    graph = result.true_topology
    vulnerability = next(iter(graph.vulnerabilities.values()))
    env = EnterpriseCyberEnv(graph, max_nodes=96)
    env.reset(seed=7)
    assert not env.knowledge.known_vulnerabilities
    assert not hasattr(env.knowledge, "cvss")
    graph.vulnerabilities[vulnerability.id] = replace(vulnerability, cvss=0)
    act(env, A.ENUMERATE_HOST, graph.entry_points[0])
    act(env, A.ASSESS_VULNERABILITY, vulnerability.target)
    info = act(env, A.EXPLOIT, vulnerability.id)[-1]
    assert info["reward_attribution"].cvss_used == vulnerability.cvss
    assert info["event"].reward == pytest.approx(0.5 + vulnerability.cvss * 0.1)


@pytest.mark.parametrize("cvss", range(11))
def test_bounded_reward_properties(cvss):
    graph = world()
    graph.vulnerabilities["native-entry"] = replace(
        graph.vulnerabilities["native-entry"], cvss=cvss
    )
    env = EnterpriseCyberEnv(graph, max_nodes=16)
    env.reset(seed=7)
    invalid = act(env, A.ACCESS_ASSET, "net")
    assert invalid[1] <= 0 and np.isfinite(invalid[1])
    prefix(env, 5)
    result = act(env, A.EXPLOIT, "native-entry")
    assert 0.5 <= result[1] <= 1.5
    assert result[-1]["reward_attribution"].reward_component == "exploit"
    assert result[1] == env.events[-1].reward


def test_historical_diagnostic_read_only_matches_recorded_classifications():
    from scripts.diagnose_registered_reward_rise import diagnose

    rows = diagnose()
    assert [row["seed"] for row in rows] == list(range(42, 52))
    assert all(not row["passed"] for row in rows)
    assert all(row["training_objective_success_frequency"] is None for row in rows)
    assert all(row["validation_successes"] == row["validation_episodes"] == 20 for row in rows)


def test_historical_diagnostic_rejects_changed_hash(monkeypatch):
    from scripts import diagnose_registered_reward_rise as diagnostic

    monkeypatch.setattr(diagnostic, "sha", lambda path: "wrong")
    with pytest.raises(ValueError, match="hash mismatch"):
        diagnostic.diagnose()
