import numpy as np

from rlredteam.digital_twin.conversion_result import convert_draft_to_true_topology
from rlredteam.enterprise.environment import EnterpriseActionType as A
from rlredteam.enterprise.environment import EnterpriseCyberEnv
from tests.digital_twin_fixtures import build, host
from tests.simulation_conversion_fixtures import draft, executable


def test_converted_fixture_smoke_knowledge_changes_only_through_consequences():
    value = executable(approved=True)
    result = convert_draft_to_true_topology(value, value.policy)
    env = EnterpriseCyberEnv(
        result.true_topology,
        max_nodes=value.policy.max_nodes,
        max_vulnerabilities=value.policy.max_vulnerabilities,
    )
    observation, info = env.reset(seed=42)
    crown = result.true_topology.crown_jewels[0]
    assert crown not in env.knowledge.discovered
    assert not env.knowledge.known_vulnerabilities
    assert not env.knowledge.access
    assert set(info) == {
        "action_mask",
        "known_nodes",
        "known_vulnerabilities",
        "compromised_nodes",
        "credentials",
        "goal_reached",
    }
    entry = result.true_topology.entry_points[0]
    env.step(env.action_index(A.ENUMERATE_HOST, entry))
    vulnerability = next(iter(result.true_topology.vulnerabilities.values()))
    env.step(env.action_index(A.ASSESS_VULNERABILITY, vulnerability.target))
    assert vulnerability.id in env.knowledge.known_vulnerabilities
    env.step(env.action_index(A.EXPLOIT, vulnerability.id))
    env.step(env.action_index(A.ENUMERATE_APPLICATION, vulnerability.grants_access_to))
    _, _, terminated, _, _ = env.step(env.action_index(A.ACCESS_ASSET, crown))
    assert terminated
    assert observation.dtype == np.float32
    assert not any(
        hasattr(env.knowledge, name)
        for name in ("evidence", "assumptions", "twin", "conversion_policy")
    )


def test_hidden_sizes_metadata_and_feasibility_do_not_change_initial_policy_inputs():
    a = draft()
    b = draft(build(extras=(host("hidden-extra", 20),)))
    environments = []
    for value in (a, b):
        result = convert_draft_to_true_topology(value, value.policy)
        environments.append(
            EnterpriseCyberEnv(result.true_topology, max_nodes=96, max_vulnerabilities=16)
        )
    left, right = environments
    obs_a, info_a = left.reset(seed=42)
    obs_b, info_b = right.reset(seed=42)
    assert np.array_equal(obs_a, obs_b)
    assert np.array_equal(info_a["action_mask"], info_b["action_mask"])
    assert left.actions == right.actions
    assert left.action_space == right.action_space
    assert len(left.true_topology.nodes) != len(right.true_topology.nodes)
    assert all("192.0." not in node.id for node in left.true_topology.nodes.values())
    assert all(
        set(node.attributes) <= {"os", "port", "protocol", "product", "version"}
        for node in left.true_topology.nodes.values()
    )


def test_policy_observation_and_mask_do_not_read_converted_ground_truth():
    value = executable(approved=True)
    result = convert_draft_to_true_topology(value, value.policy)
    env = EnterpriseCyberEnv(result.true_topology, max_nodes=96, max_vulnerabilities=16)
    before, info = env.reset(seed=42)

    class Forbidden:
        def __getattr__(self, name):
            raise AssertionError("policy input accessed hidden topology: " + name)

    env.true_topology = Forbidden()
    assert np.array_equal(env._observation(), before)
    assert np.array_equal(env.action_masks(), info["action_mask"])
