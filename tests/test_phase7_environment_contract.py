"""Bounded synthetic correctness fixtures. Never loads a policy or campaign evidence."""

import hashlib
import json
import os
import random
import subprocess
import sys
from copy import deepcopy
from dataclasses import asdict, fields, replace

import gymnasium as gym
import numpy as np
import pytest

from rlredteam.enterprise.attacker_graph import AttackerKnowledgeGraph
from rlredteam.enterprise.belief import beliefs_from_agent_knowledge
from rlredteam.enterprise.belief_observation import BeliefObservation
from rlredteam.enterprise.environment import EnterpriseActionType as A
from rlredteam.enterprise.environment import EnterpriseCyberEnv
from rlredteam.enterprise.model import (
    EdgeType as E,
)
from rlredteam.enterprise.model import (
    EnterpriseEdge,
    EnterpriseNode,
    TrueTopology,
    Vulnerability,
)
from rlredteam.enterprise.model import (
    NodeType as N,
)
from rlredteam.enterprise.onprem import (
    OnPremCurriculumEnv,
    generate_onprem_topology,
    topology_digest,
)
from rlredteam.enterprise.state import Observation
from rlredteam.enterprise.v2_reasoner import reason_next_action

pytestmark = [pytest.mark.environment, pytest.mark.observation, pytest.mark.seed]


def world(probability=1.0, root_probability=1.0):
    kinds = {
        "entry": N.HOST,
        "net": N.NETWORK_SEGMENT,
        "host": N.HOST,
        "service": N.SERVICE,
        "app": N.APPLICATION,
        "db": N.DATABASE,
        "identity": N.IDENTITY,
        "pivot": N.HOST,
        "asset": N.ASSET,
    }
    nodes = {
        key: EnterpriseNode(key, kind, key, {"product": "synthetic", "version": "1"})
        for key, kind in kinds.items()
    }
    edges = [
        EnterpriseEdge(source, target, kind)
        for source, target, kind in (
            ("entry", "net", E.CONNECTS),
            ("host", "net", E.LOCATED_IN),
            ("host", "service", E.HOSTS),
            ("service", "app", E.EXPOSES),
            ("app", "db", E.CALLS),
            ("host", "identity", E.YIELDS_CREDENTIAL),
            ("identity", "db", E.HAS_ACCESS),
            ("host", "pivot", E.PIVOTS_TO),
            ("db", "asset", E.CONTAINS),
        )
    ]
    vulnerabilities = {
        "native-entry": Vulnerability(
            "native-entry", "service", 5, probability, "host", "synthetic", ("1",)
        ),
        "native-root": Vulnerability(
            "native-root", "host", 5, root_probability, "host", "synthetic", ("1",), "root"
        ),
    }
    return TrueTopology(
        "phase7-synthetic-v1", nodes, edges, vulnerabilities, ("entry",), ("asset",)
    )


TRACE = (
    (A.DISCOVER_NETWORK, "net"),
    (A.ENUMERATE_HOST, "host"),
    (A.ENUMERATE_SERVICE, "service"),
    (A.ENUMERATE_APPLICATION, "app"),
    (A.ASSESS_VULNERABILITY, "service"),
    (A.EXPLOIT, "native-entry"),
    (A.ASSESS_VULNERABILITY, "host"),
    (A.ESCALATE_PRIVILEGE, "host"),
    (A.OBTAIN_CREDENTIAL, "identity"),
    (A.AUTHENTICATE, "db"),
    (A.PIVOT, "pivot"),
    (A.ENUMERATE_APPLICATION, "db"),
    (A.ACCESS_ASSET, "asset"),
)


def environment(**kwargs):
    return EnterpriseCyberEnv(world(**kwargs), max_nodes=16, max_vulnerabilities=4, max_steps=30)


def act(env, kind, target):
    return env.step(env.action_index(kind, target))


def prefix(env, count, seed=7):
    env.reset(seed=seed)
    for kind, target in TRACE[:count]:
        act(env, kind, target)


def digest(value):
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), default=lambda item: sorted(item)
        ).encode()
    ).hexdigest()


def replay(seed=7):
    env = environment()
    obs, _ = env.reset(seed=seed)
    rows = [
        {
            "observation": hashlib.sha256(obs.tobytes()).hexdigest(),
            "knowledge": digest(asdict(env.agent_knowledge)),
        }
    ]
    for kind, target in TRACE:
        obs, reward, terminated, truncated, info = act(env, kind, target)
        rows.append(
            {
                "observation": hashlib.sha256(obs.tobytes()).hexdigest(),
                "knowledge": digest(asdict(env.agent_knowledge)),
                "event": digest(
                    {key: value for key, value in asdict(info["event"]).items() if key != "reward"}
                ),
                "terminated": terminated,
                "truncated": truncated,
            }
        )
        assert reward == info["event"].reward
    return rows


def test_replay_fixture():
    from tests.phase7_replay_fixture import EXPECTED, RESET_SEED, TOPOLOGY_SHA

    assert topology_digest(world()) == TOPOLOGY_SHA
    assert replay(RESET_SEED) == EXPECTED
    assert replay(RESET_SEED) == EXPECTED


@pytest.mark.parametrize("count", [0, 1, 2, 6, 8, 9, 13])
def test_reset_clears_every_episode_field(count):
    env = environment()
    original = topology_digest(env.true_topology)
    initial, _ = env.reset(seed=7)
    baseline = asdict(env.agent_knowledge)
    prefix(env, count)
    restored, _ = env.reset(seed=7)
    assert np.array_equal(initial, restored)
    assert asdict(env.agent_knowledge) == baseline
    assert env.events == [] and env._step == 0
    assert topology_digest(env.true_topology) == original
    for _ in range(3):
        assert np.array_equal(env.reset(seed=7)[0], initial)


@pytest.mark.parametrize("mode", ["failure", "invalid", "truncated"])
def test_reset_after_non_success(mode):
    env = environment(probability=0)
    baseline, _ = env.reset(seed=7)
    if mode == "failure":
        prefix(env, 5)
        assert not act(env, A.EXPLOIT, "native-entry")[-1]["event"].success
    elif mode == "invalid":
        assert not act(env, A.ACCESS_ASSET, "net")[-1]["event"].success
    else:
        for _ in range(30):
            result = act(env, A.ACCESS_ASSET, "net")
        assert result[3] and not result[2]
    assert np.array_equal(env.reset(seed=7)[0], baseline)
    assert not env.events and env._step == 0


def test_every_supported_action_has_causal_delta_and_monotone_state():
    env = environment()
    env.reset(seed=7)
    expected = [
        ("discovered", "host"),
        ("discovered", "service"),
        ("discovered", "app"),
        ("discovered", "db"),
        ("known_vulnerabilities", "native-entry"),
        ("access", "host"),
        ("known_vulnerabilities", "native-root"),
        ("access", "host"),
        ("credentials", "identity"),
        ("access", "db"),
        ("access", "pivot"),
        ("discovered", "asset"),
        ("accessed_assets", "asset"),
    ]
    allowed = {
        A.DISCOVER_NETWORK: {
            "enumerated",
            "discovered",
            "discovery_order",
            "known_node_types",
            "reachable",
            "known_edges",
        },
        A.ENUMERATE_HOST: {
            "enumerated",
            "discovered",
            "discovery_order",
            "known_node_types",
            "reachable",
            "known_edges",
        },
        A.ENUMERATE_SERVICE: {
            "enumerated",
            "discovered",
            "discovery_order",
            "known_node_types",
            "reachable",
            "known_edges",
        },
        A.ENUMERATE_APPLICATION: {
            "enumerated",
            "discovered",
            "discovery_order",
            "known_node_types",
            "reachable",
            "known_edges",
        },
        A.ASSESS_VULNERABILITY: {
            "assessed",
            "known_vulnerabilities",
            "vulnerability_order",
            "vulnerability_targets",
            "vulnerability_grants_access",
            "vulnerability_privileges",
        },
        A.EXPLOIT: {"access"},
        A.ESCALATE_PRIVILEGE: {"access"},
        A.OBTAIN_CREDENTIAL: {"credentials", "known_edges", "reachable"},
        A.AUTHENTICATE: {"access"},
        A.PIVOT: {"access"},
        A.ACCESS_ASSET: {"accessed_assets"},
    }
    assert set(kind for kind, _ in TRACE) == set(A)
    for (kind, target), (field, member) in zip(TRACE, expected, strict=True):
        before = env.agent_knowledge
        result = act(env, kind, target)
        after = env.agent_knowledge
        assert result[-1]["event"].success and result[-1]["event"].state_changed
        assert member in getattr(after, field)
        changed = {
            item.name
            for item in fields(before)
            if getattr(before, item.name) != getattr(after, item.name)
        }
        assert changed <= allowed[kind]
        assert before.discovered <= after.discovered
        assert before.credentials <= after.credentials
        assert before.reachable <= after.reachable
        assert all(after.access_level(node) >= before.access_level(node) for node in before.access)
    assert env.knowledge.access["host"] == "root"
    assert result[2] and not result[3]


@pytest.mark.parametrize("kind", list(A))
def test_each_action_rejects_unavailable_target_without_knowledge_mutation(kind):
    env = environment()
    env.reset(seed=7)
    before = env.agent_knowledge.snapshot()
    # Empty slots remain addressable integers but cannot resolve to hidden entities.
    index = next(
        index
        for index, item in enumerate(env.actions)
        if item.type == kind and item.target.endswith("_3")
    )
    result = env.step(index)
    assert env.agent_knowledge.snapshot() == before
    assert not result[-1]["event"].success
    assert not result[2] and not result[3]


@pytest.mark.parametrize(
    "kind,target,count",
    [
        (A.OBTAIN_CREDENTIAL, "identity", 2),
        (A.AUTHENTICATE, "db", 4),
        (A.PIVOT, "pivot", 2),
        (A.ESCALATE_PRIVILEGE, "host", 5),
        (A.ACCESS_ASSET, "asset", 0),
    ],
)
def test_preconditions_authoritative_even_with_bad_mask(monkeypatch, kind, target, count):
    env = environment()
    prefix(env, count)
    if target == "asset":  # Legitimate discovery does not itself grant containing-system access.
        prefix(env, 4)
        act(env, A.ENUMERATE_APPLICATION, "db")
    before = env.agent_knowledge.snapshot()
    monkeypatch.setattr(
        env, "valid_action_mask", lambda: np.ones(env.action_space.n, dtype=np.int8)
    )
    result = act(env, kind, target)
    assert not result[-1]["event"].success
    assert env.agent_knowledge.snapshot() == before


@pytest.mark.parametrize(
    "kind,target",
    [
        (A.DISCOVER_NETWORK, "net"),
        (A.ENUMERATE_HOST, "host"),
        (A.ENUMERATE_SERVICE, "service"),
        (A.ENUMERATE_APPLICATION, "app"),
        (A.ASSESS_VULNERABILITY, "service"),
        (A.EXPLOIT, "native-entry"),
    ],
)
def test_unreachable_target_cannot_be_used(kind, target):
    env = environment()
    prefix(env, 5)
    env.knowledge.enumerated.clear()  # Privileged test setup, not policy-facing mutation.
    env.knowledge.assessed.clear()
    env.knowledge.reachable.clear()
    before = env.agent_knowledge.snapshot()
    assert not act(env, kind, target)[-1]["event"].success
    assert env.agent_knowledge.snapshot() == before


def trial(probability, seed):
    env = environment(probability=probability)
    prefix(env, 5, seed=seed)
    before = env.agent_knowledge.snapshot()
    result = act(env, A.EXPLOIT, "native-entry")
    assert not result[2] and not result[3]
    if not result[-1]["event"].success:
        assert env.agent_knowledge.snapshot() == before
    return result[-1]["event"].success


@pytest.mark.parametrize("probability,expected", [(0.0, False), (1.0, True)])
def test_probability_endpoints(probability, expected):
    for seed in range(12):
        assert trial(probability, seed) == expected


def test_zero_random_draw_does_not_make_zero_probability_succeed():
    env = environment(probability=0)
    prefix(env, 5)

    class ZeroRng:
        def random(self):
            return 0.0

    env._np_random = ZeroRng()
    assert not act(env, A.EXPLOIT, "native-entry")[-1]["event"].success


@pytest.mark.parametrize("probability", [-0.1, 1.1, float("nan"), float("inf"), -float("inf")])
def test_malformed_probability_rejected(probability):
    with pytest.raises(ValueError, match="exploit_probability"):
        world(probability=probability)


def test_stochastic_replay_variation_and_bounded_frequency():
    first = [trial(0.5, seed) for seed in range(200)]
    assert first == [trial(0.5, seed) for seed in range(200)]
    assert set(first) == {False, True}
    # Synthetic implementation sanity check only: +/-40 is >5 binomial SD at n=200,p=.5.
    assert 60 <= sum(first) <= 140
    env = environment(probability=0.5)
    for seed in range(10):
        repeated = []
        for _ in range(2):
            prefix(env, 5, seed=seed)
            repeated.append(asdict(act(env, A.EXPLOIT, "native-entry")[-1]["event"]))
        assert repeated[0] == repeated[1]


@pytest.mark.parametrize("probability,success", [(0, False), (1, True)])
def test_escalation_respects_probability_without_downgrade(probability, success):
    env = environment(root_probability=probability)
    prefix(env, 7)
    before = env.agent_knowledge.snapshot()
    result = act(env, A.ESCALATE_PRIVILEGE, "host")
    assert result[-1]["event"].success == success
    assert env.knowledge.access["host"] == ("root" if success else "user")
    if not success:
        assert env.agent_knowledge.snapshot() == before
    else:
        before = env.agent_knowledge.snapshot()
        assert not act(env, A.ESCALATE_PRIVILEGE, "host")[-1]["event"].success
        assert env.agent_knowledge.snapshot() == before


def test_topology_rng_and_episode_rng_are_separate_from_globals():
    first = generate_onprem_topology(1).to_dict()
    random.seed(999)
    np.random.seed(999)
    assert generate_onprem_topology(1).to_dict() == first
    contents = []
    for seed in range(1, 9):
        content = generate_onprem_topology(seed).to_dict()
        content.pop("name")
        contents.append(digest(content))
    assert len(set(contents)) > 1  # Not just different seed-labelled world names.
    assert len({topology_digest(generate_onprem_topology(seed)) for seed in range(1, 9)}) == 8
    env = environment(probability=0.5)
    original = topology_digest(env.true_topology)
    for episode_seed in range(10):
        env.reset(seed=episode_seed)
        assert topology_digest(env.true_topology) == original
    np.random.seed(42)  # A policy/training global RNG must not override explicit eval reset.
    left = trial(0.5, 19001)
    np.random.seed(51)
    random.seed(51)
    assert trial(0.5, 19001) == left


def test_curriculum_explicit_topology_pin_and_episode_seed_replay():
    env = OnPremCurriculumEnv((1, 2, 3))
    first, info = env.reset(seed=17, options={"topology_seed": 2})
    second, again = env.reset(seed=18, options={"topology_seed": 2})
    assert info["topology_hash"] == again["topology_hash"]
    assert np.array_equal(first, second)
    env.reset(seed=17)
    selected = env.topology_seed
    env.reset(seed=17)
    assert env.topology_seed == selected
    with pytest.raises(ValueError, match="outside this split"):
        env.reset(seed=17, options={"topology_seed": 999})


def test_hidden_world_changes_do_not_leak_into_policy_or_v2():
    left = environment()
    alternate = world()
    alternate.vulnerabilities.clear()
    alternate.nodes["hidden"] = EnterpriseNode("hidden", N.SERVICE, "hidden")
    right = EnterpriseCyberEnv(alternate, max_nodes=16, max_vulnerabilities=4, max_steps=30)
    for env in (left, right):
        prefix(env, 4)
    assert left.agent_knowledge.snapshot() == right.agent_knowledge.snapshot()
    assert np.array_equal(left._observation(), right._observation())
    assert np.array_equal(left.action_masks(), right.action_masks())
    assert left.actions == right.actions
    assert reason_next_action(left, goal_id="unknown") == reason_next_action(
        right, goal_id="unknown"
    )
    for env in (left, right):
        act(env, A.ASSESS_VULNERABILITY, "service")
    assert not np.array_equal(left._observation(), right._observation())
    assert not np.array_equal(left.action_masks(), right.action_masks())


def test_v2_and_policy_encoding_never_read_latent_topology():
    env = environment()
    prefix(env, 5)
    observation = env._observation()
    mask = env.action_masks()
    reasoning = reason_next_action(env, goal_id="unknown")

    class Forbidden:
        def __getattr__(self, name):
            raise AssertionError("hidden read: " + name)

    env.true_topology = Forbidden()
    assert np.array_equal(env._observation(), observation)
    assert np.array_equal(env.action_masks(), mask)
    assert reason_next_action(env, goal_id="unknown") == reasoning


def test_assessment_discloses_effect_reference_not_full_destination_state():
    topology = world()
    topology.vulnerabilities["native-entry"] = replace(
        topology.vulnerabilities["native-entry"], grants_access_to="asset"
    )
    env = EnterpriseCyberEnv(topology, max_nodes=16)
    prefix(env, 4)
    act(env, A.ASSESS_VULNERABILITY, "service")
    assert "asset" not in env.knowledge.discovered
    assert "asset" in env.knowledge.vulnerability_grants_access.values()
    assert "asset" not in env.knowledge.known_node_types
    assert "asset" not in env.knowledge.access


def test_returned_observations_info_and_knowledge_are_copy_safe():
    env = environment()
    observation, info = env.reset(seed=7)
    before = env.agent_knowledge.snapshot()
    knowledge = env.agent_knowledge
    knowledge.discovered.clear()
    knowledge.access["asset"] = "root"
    observation[:] = 999
    info["action_mask"][:] = 0
    info["credentials"].append("fabricated")
    assert env.agent_knowledge.snapshot() == before
    assert env.observation_space.contains(env._observation())
    assert env.action_masks().any()
    caller_world = world()
    owned = EnterpriseCyberEnv(caller_world)
    caller_world.nodes["entry"].attributes["product"] = "changed"
    caller_world.edges.clear()
    assert owned.true_topology.nodes["entry"].attributes["product"] == "synthetic"
    assert owned.true_topology.edges


def test_v1_v2_schema_ranges_aliases_and_deterministic_ordering():
    env = environment()
    prefix(env, 9)
    knowledge = env.agent_knowledge
    v1 = Observation.from_knowledge(knowledge, max_nodes=16, step=9, max_steps=30)
    beliefs = beliefs_from_agent_knowledge(knowledge)
    graph = AttackerKnowledgeGraph.from_beliefs(beliefs)
    v2 = BeliefObservation.from_beliefs(beliefs, graph, max_nodes=16, step=9, max_steps=30)
    assert len(v1.values) == 16 * 27 + 16 * 16 + 1
    assert len(v2.values) == 16 * 33 + 16 * 16 + 1
    assert len(Observation.FEATURE_NAMES) == 27
    assert Observation.SCHEMA_VERSION == "enterprise-observation-v1.1"
    assert BeliefObservation.SCHEMA_VERSION == "belief-observation-v2.15"
    for encoded in (v1, v2):
        a, b = encoded.as_array(), encoded.as_array()
        assert a.dtype == np.float32 and np.isfinite(a).all()
        assert ((a >= 0) & (a <= 1)).all()
        a[:] = 999
        assert not np.shares_memory(a, b)
        assert np.array_equal(encoded.as_array(), b)
    reversed_beliefs = deepcopy(beliefs)
    reversed_beliefs.facts = dict(reversed(list(beliefs.facts.items())))
    reversed_graph = AttackerKnowledgeGraph.from_beliefs(reversed_beliefs)
    assert v2 == BeliefObservation.from_beliefs(
        reversed_beliefs, reversed_graph, max_nodes=16, step=9, max_steps=30
    )
    # Unfilled slots are entirely zero; absent facts mean unknown, not known-negative.
    assert not any(v1.values[len(knowledge.discovery_order) * 27 : 16 * 27])


@pytest.mark.parametrize("limit,expected", [(13, (True, False)), (12, (False, True))])
def test_goal_budget_precedence_and_post_episode_guard(limit, expected):
    env = EnterpriseCyberEnv(world(), max_nodes=16, max_steps=limit)
    env.reset(seed=7)
    for kind, target in TRACE[:limit]:
        result = act(env, kind, target)
    assert result[2:4] == expected
    before = env.agent_knowledge.snapshot()
    events = tuple(env.events)
    with pytest.raises(gym.error.ResetNeeded):
        env.step(0)
    assert env.agent_knowledge.snapshot() == before
    assert tuple(env.events) == events
    env.reset(seed=7)
    assert not env.knowledge.accessed_assets


def test_step_requires_initial_reset_and_invalid_indices_are_atomic():
    env = environment()
    with pytest.raises(gym.error.ResetNeeded):
        env.step(0)
    env.reset(seed=7)
    before = env.agent_knowledge.snapshot()
    for invalid in (-1, 999999, 1.5):
        with pytest.raises(ValueError):
            env.step(invalid)
    assert env.agent_knowledge.snapshot() == before
    assert not env.events and env._step == 0


@pytest.mark.parametrize("seed", range(1, 9))
def test_generated_topology_integrity(seed):
    graph = generate_onprem_topology(seed)
    graph.validate()
    assert len(graph.nodes) == len({node.id for node in graph.nodes.values()})
    for edge in graph.edges:
        assert edge.source in graph.nodes and edge.target in graph.nodes
        if edge.type == E.LOCATED_IN:
            assert graph.nodes[edge.target].type == N.NETWORK_SEGMENT
        if edge.type == E.HOSTS:
            assert graph.nodes[edge.source].type == N.HOST
        if edge.type == E.HAS_ACCESS:
            assert graph.nodes[edge.source].type == N.IDENTITY
    assert all(node in graph.nodes for node in (*graph.entry_points, *graph.crown_jewels))
    for vulnerability in graph.vulnerabilities.values():
        assert vulnerability.target in graph.nodes
        assert vulnerability.grants_access_to in graph.nodes
        assert vulnerability.applies_to(graph.nodes[vulnerability.target])


@pytest.mark.parametrize(
    "defect", ["dangling_edge", "vulnerability", "objective", "node_id", "product"]
)
def test_malformed_topologies_rejected(defect):
    graph = world()
    if defect == "dangling_edge":
        graph.edges.append(EnterpriseEdge("absent", "host", E.HOSTS))
    elif defect == "vulnerability":
        graph.vulnerabilities["native-entry"] = replace(
            graph.vulnerabilities["native-entry"], target="absent"
        )
    elif defect == "objective":
        graph.crown_jewels = ("absent",)
    elif defect == "node_id":
        graph.nodes["host"] = EnterpriseNode("other", N.HOST, "other")
    else:
        graph.nodes["service"].attributes["version"] = "invalid"
    with pytest.raises(ValueError):
        graph.validate()


@pytest.mark.parametrize("seed", range(5))
def test_bounded_invalid_action_properties(seed):
    env = environment()
    env.reset(seed=seed)
    rng = random.Random(seed)
    for _ in range(20):
        invalid = np.flatnonzero(~env.action_masks())
        index = int(rng.choice(invalid))
        before = env.agent_knowledge.snapshot()
        obs, _, terminated, truncated, info = env.step(index)
        assert not info["event"].success and not terminated and not truncated
        assert env.agent_knowledge.snapshot() == before
        assert env.observation_space.contains(obs) and np.isfinite(obs).all()


def test_reward_call_is_read_only(monkeypatch):
    env = environment()
    original = env._reward

    def checked_reward(*args):
        state = env.agent_knowledge.snapshot()
        topology = topology_digest(env.true_topology)
        result = original(*args)
        assert env.agent_knowledge.snapshot() == state
        assert topology_digest(env.true_topology) == topology
        return result

    monkeypatch.setattr(env, "_reward", checked_reward)
    prefix(env, len(TRACE))


def test_replay_is_independent_of_process_hash_seed():
    outputs = []
    for hash_seed in (1, 123):
        result = subprocess.run(
            [
                sys.executable,
                "-B",
                "-c",
                "from tests.test_phase7_environment_contract import replay; print(repr(replay()))",
            ],
            env={**os.environ, "PYTHONHASHSEED": str(hash_seed)},
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        outputs.append(result.stdout)
    assert outputs[0] == outputs[1]


def test_fanout_discovery_and_causal_prerequisites_are_sorted():
    graph = world()
    for node in ("z-child", "a-child"):
        graph.nodes[node] = EnterpriseNode(node, N.APPLICATION, node)
        graph.edges.append(EnterpriseEdge("service", node, E.EXPOSES))
    env = EnterpriseCyberEnv(graph, max_nodes=16)
    prefix(env, 2)
    result = act(env, A.ENUMERATE_SERVICE, "service")
    assert result[-1]["event"].outcomes == (
        "discovered:a-child",
        "discovered:app",
        "discovered:z-child",
    )
    assert env.knowledge.discovery_order[-3:] == ["a-child", "app", "z-child"]


@pytest.mark.parametrize("field", ["max_steps", "max_nodes", "max_vulnerabilities"])
@pytest.mark.parametrize("value", [0, -1, 1.5, True])
def test_capacity_must_be_positive_integer(field, value):
    with pytest.raises(ValueError, match=field):
        EnterpriseCyberEnv(world(), **{field: value})


@pytest.mark.parametrize("step,max_steps,max_nodes", [(-1, 10, 16), (0, 0, 16), (0, 10, 0)])
def test_v1_invalid_observation_bounds_rejected(step, max_steps, max_nodes):
    env = environment()
    env.reset(seed=7)
    with pytest.raises(ValueError):
        Observation.from_knowledge(
            env.agent_knowledge, max_nodes=max_nodes, step=step, max_steps=max_steps
        )
