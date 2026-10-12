"""No registered training or final-test policy evaluation is executed here."""

import copy
import csv
import json
from dataclasses import replace

import numpy as np
import pytest

from rlredteam.enterprise.environment import EnterpriseActionType as A
from rlredteam.enterprise.environment import EnterpriseCyberEnv
from rlredteam.enterprise.generator import generate_enterprise
from rlredteam.enterprise.onprem import OnPremTopologyConfig
from rlredteam.enterprise.onprem_protocol import (
    CONFIG,
    ROOT,
    artifact_inventory,
    choose_test_seeds,
    load_protocol,
    protocol_digest,
    split_manifest,
    validate_design,
)
from rlredteam.enterprise.registered_onprem import AuditedTrainingEnv, convergence_diagnostics


def test_draft_is_not_registration_and_budget_is_exact():
    protocol = load_protocol(ROOT / CONFIG)
    validate_design(protocol)
    assert protocol["status"] == "draft" and not protocol["registered"]
    assert protocol["total_timesteps"] // (256 * protocol["n_envs"]) == 3907
    assert protocol["total_timesteps"] % (256 * protocol["n_envs"]) == 0
    assert protocol["historical_pilot"].endswith("onprem_generalisation.yaml")


def test_protocol_digest_is_stable_and_mutation_is_detected():
    protocol = load_protocol(ROOT / CONFIG)
    changed = copy.deepcopy(protocol)
    changed["registration_timestamp"] = "2026-10-12T00:00:00Z"
    assert protocol_digest(changed) == protocol_digest(protocol)
    changed["protocol_sha256"] = protocol_digest(changed)
    changed["ppo"]["gamma"] = 0.9
    with pytest.raises(ValueError, match="digest"):
        validate_design(changed)


@pytest.mark.parametrize(
    "field,value",
    [
        ("total_timesteps", 1000000),
        ("n_envs", 3),
        ("training_seeds", [42]),
        ("authorized_start_seeds", [42, 43]),
    ],
)
def test_invalid_registered_design_rejected(field, value):
    protocol = load_protocol(ROOT / CONFIG)
    protocol[field] = value
    with pytest.raises(ValueError):
        validate_design(protocol)


def test_hash_only_split_reconstruction_is_disjoint_and_deterministic():
    protocol = load_protocol(ROOT / CONFIG)
    first = split_manifest(protocol)
    assert first == split_manifest(protocol)
    hashes = [row["structural_hash"] for group in first.values() for row in group.values()]
    assert len(hashes) == len(set(hashes)) == 100
    protocol["splits"]["test"][0] = 1
    with pytest.raises(ValueError, match="overlapping"):
        split_manifest(protocol)


def test_local_inventory_includes_csv_and_nested_seed_fields(tmp_path):
    (tmp_path / "runs").mkdir()
    (tmp_path / "results").mkdir()
    (tmp_path / "runs/a.json").write_text(json.dumps({"nested": {"test_topology_seeds": [2001]}}))
    (tmp_path / "results/b.csv").write_text("topology_seed,total_reward\n3001,1\n")
    inventory = artifact_inventory(tmp_path)
    assert inventory["used_topology_seeds"] == [2001, 3001]
    assert choose_test_seeds(inventory) == list(range(4001, 4021))
    (tmp_path / "results/bad.json").write_text("{broken")
    with pytest.raises(ValueError, match="cannot audit"):
        artifact_inventory(tmp_path)


def test_reward_contract_exact_sequence_and_failure():
    graph = generate_enterprise(42)
    vid = "CVE-2021-42013"
    graph.vulnerabilities[vid] = replace(graph.vulnerabilities[vid], exploit_probability=1)
    env = EnterpriseCyberEnv(graph, max_steps=100)
    env.reset(seed=42)
    sequence = [
        (A.DISCOVER_NETWORK, "seg_dmz", 1),
        (A.ENUMERATE_HOST, "web_host", 1),
        (A.ENUMERATE_SERVICE, "http", 1),
        (A.ENUMERATE_APPLICATION, "portal", 1),
        (A.ASSESS_VULNERABILITY, "http", 1),
        (A.EXPLOIT, vid, 0.5 + graph.vulnerabilities[vid].cvss / 10),
        (A.OBTAIN_CREDENTIAL, "svc_orders", 2),
        (A.AUTHENTICATE, "app_host", 3),
        (A.ENUMERATE_HOST, "app_host", 1),
        (A.PIVOT, "db_host", 3),
        (A.ENUMERATE_HOST, "db_host", 1),
        (A.ENUMERATE_APPLICATION, "customer_db", 1),
        (A.AUTHENTICATE, "customer_db", 3),
        (A.ACCESS_ASSET, "customer_records", 100),
    ]
    for kind, target, expected in sequence:
        _, reward, terminated, _, _ = env.step(env.action_index(kind, target))
        assert reward == pytest.approx(expected)
    assert terminated
    assert env._reward(A.ESCALATE_PRIVILEGE, "web_host", True) == 4
    assert env._reward(A.ENUMERATE_HOST, "web_host", False) == -1
    _, reward, _, _, _ = env.step(env.action_index(A.DISCOVER_NETWORK, "seg_dmz"))
    assert reward == -5


def test_discovery_is_set_based_not_boolean_map_counting():
    env = EnterpriseCyberEnv(generate_enterprise(42))
    env.reset(seed=42)
    index = env.action_index(A.DISCOVER_NETWORK, "seg_dmz")
    env.step(index)
    discovered = set(env.knowledge.discovered)
    count = len(discovered)
    _, reward, _, _, info = env.step(index)
    assert len(env.knowledge.discovered) == count
    assert env.knowledge.discovered == discovered
    assert reward == -5 and not info["event"].state_changed


def test_information_reward_is_not_a_new_node_count():
    env = EnterpriseCyberEnv(generate_enterprise(42))
    env.reset(seed=42)
    env.step(env.action_index(A.DISCOVER_NETWORK, "seg_dmz"))
    # An empty first assessment changes assessed-state, not the discovery set.
    before = set(env.knowledge.discovered)
    _, reward, _, _, _ = env.step(env.action_index(A.ASSESS_VULNERABILITY, "seg_dmz"))
    assert env.knowledge.discovered == before
    assert reward == 1
    assert (
        "not new-node count"
        in load_protocol(ROOT / CONFIG)["reward"]["components"]["information_state_change"][
            "novelty"
        ]
    )


def test_no_success_summary_is_null(tmp_path):
    from rlredteam.enterprise.generalisation import write_evaluation_package

    episode = {
        "topology_seed": 1001,
        "evaluation_seed": 19001,
        "goal_reached": False,
        "steps_to_goal": None,
        "total_reward": -5,
        "discovery_coverage": 0.1,
        "invalid_mask_selections": 0,
    }
    write_evaluation_package(tmp_path, episodes=[episode], steps=[], metadata={})
    assert json.loads((tmp_path / "summary.json").read_text())["mean_steps_to_goal"] is None


def test_training_sampling_audit_deterministic_and_outside_policy_inputs(tmp_path):
    outputs = []
    for index in range(2):
        path = tmp_path / f"audit-{index}.csv"
        env = AuditedTrainingEnv(
            (1, 2, 3),
            config=replace(OnPremTopologyConfig(), max_steps=1),
            training_seed=42,
            audit_path=path,
        )
        for _ in range(5):
            observation, info = env.reset()
            assert env.observation_space.contains(observation)
            assert not isinstance(observation, dict)
            env.step(int(np.flatnonzero(env.action_masks())[0]))
        env.close()
        with path.open() as handle:
            rows = list(csv.DictReader(handle))
        assert {int(x["topology_seed"]) for x in rows} <= {1, 2, 3}
        assert {int(x["training_seed"]) for x in rows} == {42}
        assert all(x["topology_hash"] and x["training_episode_seed"] for x in rows)
        outputs.append(rows)
    assert outputs[0] == outputs[1]


def test_seed42_runner_refuses_draft_before_outputs_or_learning(monkeypatch, tmp_path):
    from rlredteam.enterprise import registered_onprem as runner

    monkeypatch.setattr(
        runner,
        "verify_protocol",
        lambda *a: {"allowed_to_train": False, "blockers": ["source checkpoint commit required"]},
    )
    with pytest.raises(ValueError, match="checkpoint"):
        runner.train_registered_seed42(load_protocol(ROOT / CONFIG), root=tmp_path)
    assert not list(tmp_path.iterdir())


def test_convergence_rule_is_descriptive_and_rejects_collapse_or_nonfinite():
    row = {
        "train/" + key: 0.1
        for key in (
            "approx_kl",
            "clip_fraction",
            "explained_variance",
            "entropy_loss",
            "policy_gradient_loss",
            "value_loss",
        )
    }
    assert convergence_diagnostics([0] * 300 + [10] * 300, [row])["passed"]
    assert not convergence_diagnostics([0] * 100 + [20] * 400 + [0] * 100, [row])["passed"]
    row["train/approx_kl"] = float("nan")
    assert not convergence_diagnostics([0] * 300 + [10] * 300, [row])["passed"]


def test_preflight_cannot_be_bypassed_by_claiming_registered(monkeypatch, tmp_path):
    from rlredteam.enterprise import onprem_protocol as module

    protocol = load_protocol(ROOT / CONFIG)
    protocol.update(
        status="registered",
        registered=True,
        implementation_ready=True,
        registration_timestamp="2026-10-12T00:00:00Z",
    )
    protocol["protocol_sha256"] = protocol_digest(protocol)
    monkeypatch.setattr(
        module,
        "artifact_inventory",
        lambda root: {
            "used_topology_seeds": [],
            "inventory_sha256": protocol["freshness"]["inventory_sha256"],
        },
    )
    monkeypatch.setattr(module, "split_manifest", lambda p: {})
    monkeypatch.setattr(
        module,
        "source_provenance",
        lambda root: {
            "git_dirty": True,
            "git_commit": "a" * 40,
            "source_hashes": {"runtime.py": "b" * 64},
        },
    )
    report = module.verify_protocol(protocol, tmp_path)
    assert not report["allowed_to_train"]
    assert any("checkpoint commit" in reason for reason in report["blockers"])
    assert "immutable registered manifest absent" in report["blockers"]


def test_registered_runner_wiring_with_fake_learner_only(monkeypatch, tmp_path):
    import sb3_contrib
    import torch

    from rlredteam.enterprise import registered_onprem as runner

    protocol = load_protocol(ROOT / CONFIG)
    protocol["topology"]["max_steps"] = 1
    report = {
        "allowed_to_train": True,
        "protocol_sha256": "test-protocol",
        "topology_config_sha256": "test-topology",
        "reward_definition_sha256": "test-reward",
        "provenance": {"source_hashes": {}, "dependency_definition_sha256": "test-deps"},
    }
    monkeypatch.setattr(runner, "verify_protocol", lambda *a: report)
    monkeypatch.setenv("RLREDTEAM_IMAGE_DIGEST", protocol["container_image_id"])

    class FakeLearner:
        def __init__(self, policy, env, **kwargs):
            assert kwargs["seed"] == 42 and kwargs["n_steps"] == 256
            assert env.topology_seeds == tuple(range(1, 61))
            self.env, self.policy = env, torch.nn.Linear(1, 1)

        def set_logger(self, logger):
            self.logger = logger

        def learn(self, *, total_timesteps):
            # Wiring test only: no PPO optimization, training campaign or research output.
            assert total_timesteps == 1000192
            self.env.reset(seed=42)
            self.env.step(int(np.flatnonzero(self.env.action_masks())[0]))
            self.num_timesteps = total_timesteps
            for key in protocol["convergence"]["required_diagnostics"]:
                self.logger.record("train/" + key, 0.1)

        def save(self, path):
            path.write_bytes(b"FAKE UNIT TEST CHECKPOINT; NOT A POLICY")

    monkeypatch.setattr(sb3_contrib, "MaskablePPO", FakeLearner)
    result = runner.train_registered_seed42(protocol, root=tmp_path)
    assert result["training_seed"] == 42
    assert result["final_test_evaluated"] is False
    assert result["completed_episodes"] == 1
    assert result["checkpoint_sha256"]
    assert not (tmp_path / "runs/onprem-generalisation-registered/seed-43").exists()
