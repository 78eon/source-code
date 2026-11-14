"""Bounded action/mask/candidate tests; no training or held-out environments."""

import hashlib
import json
from copy import deepcopy
from dataclasses import asdict, replace

import numpy as np
import pytest

from rlredteam.enterprise.attack_path_reasoner import CandidateAttackPath, find_candidate_paths
from rlredteam.enterprise.attacker_decision import (
    AttackerDecisionCandidate,
    DecisionKind,
    rank_decision_candidates,
)
from rlredteam.enterprise.attacker_graph import AttackerKnowledgeGraph
from rlredteam.enterprise.belief import AttackerBeliefState, BeliefFact, BeliefStatus
from rlredteam.enterprise.decision_action_mapper import map_decision_to_action
from rlredteam.enterprise.environment import EnterpriseAction, EnterpriseCyberEnv
from rlredteam.enterprise.environment import EnterpriseActionType as A
from rlredteam.enterprise.information_value import InformationValueScore, rank_information_targets
from rlredteam.enterprise.model import EdgeType as E
from rlredteam.enterprise.model import EnterpriseEdge, EnterpriseNode
from rlredteam.enterprise.model import NodeType as N
from rlredteam.enterprise.v2_episode import run_v2_episode
from rlredteam.enterprise.v2_execution import execute_v2_decision, plan_v2_execution
from rlredteam.enterprise.v2_reasoner import reason_next_action
from tests.test_phase7_environment_contract import TRACE, act, environment, prefix, world

pytestmark = [pytest.mark.action, pytest.mark.mask, pytest.mark.candidate]


def recon(target):
    return AttackerDecisionCandidate(DecisionKind.RECON, target, 1)


def progress(target):
    return AttackerDecisionCandidate(DecisionKind.PROGRESS, target, 1)


def decision_digest(env):
    reasoning = reason_next_action(env, goal_id="asset")
    payload = {
        "schema": env.metadata["action_schema_version"],
        "mask": env.action_masks().astype(int).tolist(),
        "decisions": [asdict(item) for item in reasoning.decisions],
        "candidate_order": [item.candidate_id for item in reasoning.decisions],
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


@pytest.mark.parametrize(
    "difference",
    [
        "host",
        "service",
        "vulnerability",
        "credential",
        "privilege",
        "objective",
        "connectivity",
        "cvss",
        "probability",
    ],
)
def test_hidden_differences_preserve_mask_candidates_and_order(difference):
    baseline = world()
    alternate = deepcopy(baseline)
    if difference in {"host", "service", "credential"}:
        kind = {"host": N.HOST, "service": N.SERVICE, "credential": N.IDENTITY}[difference]
        alternate.nodes["secret"] = EnterpriseNode("secret", kind, "secret")
        if difference == "credential":
            alternate.edges.append(EnterpriseEdge("host", "secret", E.YIELDS_CREDENTIAL))
    elif difference == "vulnerability":
        alternate.vulnerabilities.clear()
    elif difference == "objective":
        alternate.crown_jewels = ("pivot",)
    elif difference == "connectivity":
        alternate.edges.append(EnterpriseEdge("host", "pivot", E.CONNECTS))
    else:
        change = {
            "privilege": {"privilege": "root"},
            "cvss": {"cvss": 10},
            "probability": {"exploit_probability": 0},
        }[difference]
        alternate.vulnerabilities["native-entry"] = replace(
            alternate.vulnerabilities["native-entry"], **change
        )
    left = EnterpriseCyberEnv(baseline, max_nodes=16, max_steps=30, max_vulnerabilities=4)
    right = EnterpriseCyberEnv(alternate, max_nodes=16, max_steps=30, max_vulnerabilities=4)
    for env in (left, right):
        env.reset(seed=7)
    assert left.agent_knowledge.snapshot() == right.agent_knowledge.snapshot()
    assert decision_digest(left) == decision_digest(right)
    assert reason_next_action(left, goal_id="asset") == reason_next_action(right, goal_id="asset")
    if difference in {"cvss", "probability"}:
        for env in (left, right):
            prefix(env, 5)
        assert decision_digest(left) == decision_digest(right)


def test_legitimate_discovery_allows_candidate_divergence():
    left, right = environment(), environment()
    right.true_topology.vulnerabilities.clear()
    prefix(left, 5)
    prefix(right, 5)
    assert not np.array_equal(left.action_masks(), right.action_masks())


def test_v2_full_pipeline_forbids_all_latent_and_info_access():
    env = environment()
    prefix(env, 9)
    expected = reason_next_action(env, goal_id="asset")

    class VisiblePort:
        knowledge = env.agent_knowledge
        action_index = env.action_index
        action_masks = env.action_masks

        def __getattr__(self, name):
            raise AssertionError("forbidden reasoning access: " + name)

    assert reason_next_action(VisiblePort(), goal_id="asset") == expected


@pytest.mark.parametrize("position", range(len(TRACE)))
def test_mask_and_authoritative_step_consistent_at_each_trace_state(position):
    env = environment()
    prefix(env, position)
    mask = env.action_masks()
    assert mask.dtype == np.bool_ and np.isfinite(mask).all()
    for index, allowed in enumerate(mask):
        candidate = env._resolve_action(env.actions[index])
        assert bool(allowed) == env._can_execute(candidate)[0]
        clone = deepcopy(env)
        before = clone.agent_knowledge.snapshot()
        result = clone.step(index)
        if allowed:
            assert result[-1]["event"].success  # p=1 fixtures: no stochastic discrepancy.
        else:
            assert not result[-1]["event"].success
            assert clone.agent_knowledge.snapshot() == before
            assert result[1] <= 0
    kind, target = TRACE[position]
    assert mask[env.action_index(kind, target)]


@pytest.mark.parametrize(
    "case",
    [
        "unreachable",
        "unknown_credential",
        "insufficient_access",
        "nonexistent_service",
        "invalid_vulnerability",
        "impossible_pivot",
        "wrong_credential_scope",
    ],
)
def test_forged_mask_cannot_authorize_impossible_action(monkeypatch, case):
    env = environment()
    prefix(env, 5)
    selection = {
        "unreachable": (A.ENUMERATE_HOST, "host"),
        "unknown_credential": (A.AUTHENTICATE, "db"),
        "insufficient_access": (A.ESCALATE_PRIVILEGE, "host"),
        "nonexistent_service": (A.ENUMERATE_SERVICE, "absent"),
        "invalid_vulnerability": (A.EXPLOIT, "absent"),
        "impossible_pivot": (A.PIVOT, "pivot"),
        "wrong_credential_scope": (A.AUTHENTICATE, "pivot"),
    }
    if case == "unreachable":
        env.knowledge.enumerated.discard("host")
        env.knowledge.reachable.discard("host")
    if case == "wrong_credential_scope":
        prefix(env, 9)
    action = EnterpriseAction(*selection[case])
    before = env.agent_knowledge.snapshot()
    monkeypatch.setattr(
        env, "valid_action_mask", lambda: np.ones(env.action_space.n, dtype=np.int8)
    )
    monkeypatch.setattr(env, "_resolve_action", lambda slot: action)
    result = env.step(0)
    assert not result[-1]["event"].success
    assert result[1] == -5 and env.agent_knowledge.snapshot() == before


def test_stochastic_eligibility_is_not_guaranteed_success():
    env = environment(probability=0)
    prefix(env, 5)
    index = env.action_index(A.EXPLOIT, "native-entry")
    assert env.action_masks()[index]
    assert not env.step(index)[-1]["event"].success  # EXPECTED_STOCHASTIC_FAILURE


def test_credentials_unlock_only_their_recorded_target_then_reset():
    env = environment()
    prefix(env, 8)
    authenticate = env.action_index(A.AUTHENTICATE, "db")
    assert not env.action_masks()[authenticate]
    act(env, A.OBTAIN_CREDENTIAL, "identity")
    assert env.action_masks()[authenticate]
    assert not env.action_masks()[env.action_index(A.AUTHENTICATE, "pivot")]
    act(env, A.AUTHENTICATE, "db")
    assert not env.action_masks()[authenticate]
    env.reset(seed=7)
    assert not env.knowledge.credentials and not env.knowledge.access
    assert not env.action_masks()[authenticate]


@pytest.mark.parametrize("probability", [0, 1])
def test_privilege_is_host_scoped_and_failure_does_not_unlock(probability):
    env = environment(root_probability=probability)
    prefix(env, 7)
    before = env.action_masks()
    index = env.action_index(A.ESCALATE_PRIVILEGE, "host")
    result = env.step(index)
    assert env.knowledge.access.get("pivot") is None
    assert not env.action_masks()[env.action_index(A.ESCALATE_PRIVILEGE, "pivot")]
    if probability == 0:
        assert not result[-1]["event"].success
        assert np.array_equal(before, env.action_masks())
    else:
        assert env.knowledge.access["host"] == "root"
        assert not env.action_masks()[index]


def test_discovery_is_not_reachability_and_pivot_changes_local_eligibility():
    env = environment()
    env.reset(seed=7)
    # Explicit known-but-unreachable initial test fact, not a latent read.
    env.knowledge.discover("pivot", N.HOST)
    assert not env.action_masks()[env.action_index(A.ENUMERATE_HOST, "pivot")]
    prefix(env, 8)
    # In this model host enumeration reveals pivot endpoint as reachable, while
    # gaining access still requires a compromised pivot source.
    assert env.action_masks()[env.action_index(A.PIVOT, "pivot")]
    act(env, A.PIVOT, "pivot")
    assert env.knowledge.access["pivot"] == "user"
    assert not env.action_masks()[env.action_index(A.PIVOT, "pivot")]


def test_belief_credential_and_route_cannot_be_promoted_into_prerequisites():
    env = environment()
    prefix(env, 4)
    for confidence in (0.2, 1.0):
        beliefs = AttackerBeliefState()
        beliefs.learn(
            BeliefFact("identity", "credential_owned", "true", confidence, BeliefStatus.INFERRED)
        )
        beliefs.learn(
            BeliefFact("identity", "edge:has_access", "db", confidence, BeliefStatus.INFERRED)
        )
        graph = AttackerKnowledgeGraph.from_beliefs(beliefs)
        paths = find_candidate_paths(graph, "identity", "db")
        decisions = rank_decision_candidates(
            paths=paths, information_targets=rank_information_targets(beliefs)
        )
        before = env.agent_knowledge.snapshot()
        assert all(plan_v2_execution(env, item) is None for item in decisions)
        assert env.agent_knowledge.snapshot() == before
        assert "identity" not in env.knowledge.credentials


def test_mapper_skips_unreachable_first_vulnerability_without_false_negative():
    env = environment()
    prefix(env, 5)
    env.knowledge.discover("offline", N.SERVICE)
    env.knowledge.learn_vulnerability(
        "offline-vuln", "offline", grants_access_to="host", privilege="user"
    )
    env.knowledge.vulnerability_order = ["offline-vuln", "native-entry"]
    mapped = map_decision_to_action(progress("host"), env.agent_knowledge)
    assert mapped == EnterpriseAction(A.EXPLOIT, "native-entry")


def test_candidates_are_unique_and_input_order_invariant():
    first = InformationValueScore("entry", "node_type", "host", 1, 0, 1)
    other = replace(first, predicate="reachable", value="true")
    left = rank_decision_candidates(information_targets=(first, other, first))
    right = rank_decision_candidates(information_targets=(other, first))
    assert left == right and len(left) == 2
    assert len({item.candidate_id for item in left}) == 2


def test_zero_hop_goal_path_is_not_an_actionable_progress_candidate():
    path = CandidateAttackPath(("asset",), (), 1)
    assert rank_decision_candidates(paths=(path,)) == ()


def test_known_goal_without_access_does_not_crash_or_authorize_goal_action():
    env = environment()
    env.reset(seed=7)
    env.knowledge.discover("asset", N.ASSET, reachable=True)  # Explicit visible test state.
    result = reason_next_action(env, goal_id="asset")
    assert all(item.path is None or item.path.hops > 0 for item in result.decisions)
    assert not env.action_masks()[env.action_index(A.ACCESS_ASSET, "asset")]


def test_incorrect_false_mask_has_no_side_effect_or_execution(monkeypatch):
    env = environment()
    prefix(env, 5)
    before = env.agent_knowledge.snapshot()
    index = env.action_index(A.EXPLOIT, "native-entry")
    monkeypatch.setattr(env, "action_masks", lambda: np.zeros(env.action_space.n, dtype=bool))
    assert plan_v2_execution(env, progress("host")) is None
    with pytest.raises(ValueError, match="cannot be mapped"):
        execute_v2_decision(env, progress("host"))
    assert env.agent_knowledge.snapshot() == before and env._step == 5
    assert env.step(index)[-1]["event"].success  # Environment validity independent of false mask.


def test_root_mapping_requires_matching_grant_host():
    env = environment()
    prefix(env, 7)
    env.knowledge.vulnerability_grants_access["native-root"] = "pivot"
    assert map_decision_to_action(progress("host"), env.agent_knowledge) is None


@pytest.mark.parametrize("score", [float("nan"), float("inf"), None, True, "1"])
def test_malformed_candidate_scores_rejected(score):
    with pytest.raises(ValueError):
        AttackerDecisionCandidate(DecisionKind.RECON, "host", score)


@pytest.mark.parametrize("kind", list(A))
def test_action_codec_roundtrip_preserves_exact_id(kind):
    action = EnterpriseAction(kind, "sim:host/service:opaque-id")
    assert EnterpriseAction.from_dict(json.loads(json.dumps(action.to_dict()))) == action


@pytest.mark.parametrize(
    "payload",
    [
        None,
        {},
        {"type": "invented", "target": "host", "schema_version": "enterprise-action-v1"},
        {"type": "exploit", "target": None, "schema_version": "enterprise-action-v1"},
        {"type": "exploit", "target": "x", "schema_version": "future"},
        {
            "type": "exploit",
            "target": "x",
            "service": "wrong-pair",
            "schema_version": "enterprise-action-v1",
        },
    ],
)
def test_malformed_codec_fails_closed(payload):
    with pytest.raises(ValueError):
        EnterpriseAction.from_dict(payload)


@pytest.mark.parametrize(
    "invalid", [-1, 10**20, None, float("nan"), True, np.bool_(False), [], "1", 1.5]
)
def test_malformed_indices_are_atomic(invalid):
    env = environment()
    env.reset(seed=7)
    before = env.agent_knowledge.snapshot()
    with pytest.raises(ValueError):
        env.step(invalid)
    assert env.agent_knowledge.snapshot() == before and not env.events and env._step == 0


@pytest.mark.parametrize("target", [None, "", " \t", "a\n", "x" * 4097, float("nan")])
def test_malformed_targets_rejected_before_transition(target):
    with pytest.raises(ValueError):
        EnterpriseAction(A.EXPLOIT, target)


@pytest.mark.parametrize(
    "slot", ["node_slot_-1", "node_slot_1.2", "garbage", "node_slot_١", "node_slot_01"]
)
def test_malformed_slot_never_addresses_last_or_wrong_node(slot):
    env = environment()
    env.reset(seed=7)
    with pytest.raises(ValueError, match="slot"):
        env._resolve_action(EnterpriseAction(A.ENUMERATE_HOST, slot))


def test_mask_copy_and_dynamic_slot_reset():
    for extras in (0, 5):
        graph = world()
        for index in range(extras):
            key = f"extra-{index}"
            graph.nodes[key] = EnterpriseNode(key, N.HOST, key)
            graph.edges.append(EnterpriseEdge(key, "net", E.LOCATED_IN))
        env = EnterpriseCyberEnv(graph, max_nodes=16, max_vulnerabilities=4)
        before, info = env.reset(seed=7)
        assert env.action_space.n == 164
        mask = env.action_masks()
        pristine = mask.copy()
        mask[:] = True
        info["action_mask"][:] = True
        assert np.array_equal(env.action_masks(), pristine)
        act(env, A.DISCOVER_NETWORK, "net")
        for slot in range(len(env.knowledge.discovery_order), 16):
            assert not any(
                env.action_masks()[i]
                for i, action in enumerate(env.actions)
                if action.target == f"node_slot_{slot}"
            )
        host_slot = env.knowledge.node_slot("host")
        env.reset(seed=7)
        assert "host" not in env.knowledge.discovered
        assert not any(
            env.action_masks()[i]
            for i, action in enumerate(env.actions)
            if action.target == f"node_slot_{host_slot}"
        )


def test_empty_eligibility_and_finished_episode_stop_without_sampling():
    env = environment()
    env.reset(seed=7)
    env.knowledge.enumerated.update(env.knowledge.discovered)
    env.knowledge.assessed.update(env.knowledge.discovered)
    assert not env.action_masks().any()
    result = run_v2_episode(env, goal_id="unknown", max_reasoning_steps=2)
    assert not result.steps and result.stopped_without_plan
    assert not env.events
    prefix(env, len(TRACE))
    assert not env.action_masks().any()
    assert plan_v2_execution(env, recon("entry")) is None


def test_fixed_mask_candidate_regression_digest():
    from tests.phase9_action_fixture import EXPECTED

    env = environment()
    actual = []
    for count in (0, 2, 5, 8, 9, 12):
        prefix(env, count)
        actual.append(decision_digest(env))
    assert actual == EXPECTED


def test_imported_inventory_does_not_enable_hidden_actions():
    from rlredteam.digital_twin.conversion_result import convert_draft_to_true_topology
    from tests.simulation_conversion_fixtures import executable

    draft = executable(approved=True)
    result = convert_draft_to_true_topology(draft, draft.policy)
    env = EnterpriseCyberEnv(result.true_topology, max_nodes=96)
    env.reset(seed=7)
    assert not env.knowledge.known_vulnerabilities and not env.knowledge.credentials
    for index, slot in enumerate(env.actions):
        if slot.type in {
            A.EXPLOIT,
            A.AUTHENTICATE,
            A.OBTAIN_CREDENTIAL,
            A.PIVOT,
            A.ESCALATE_PRIVILEGE,
            A.ACCESS_ASSET,
        }:
            assert not env.action_masks()[index]
