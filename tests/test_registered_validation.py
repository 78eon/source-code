"""Synthetic unit evidence only; never train or evaluate a held-out final policy."""

import copy
import json

import pytest
import torch

from rlredteam.enterprise import registered_validation as module
from rlredteam.enterprise.generalisation import GeneralisationError, policy_digest
from rlredteam.enterprise.onprem import OnPremTopologyConfig
from rlredteam.enterprise.onprem_protocol import CONFIG, ROOT, load_protocol
from rlredteam.enterprise.registered_onprem import AuditedTrainingEnv, convergence_diagnostics


class Policy:
    def __init__(self):
        self.policy = torch.nn.Linear(1, 1)
        self.policy.optimizer = torch.optim.SGD(self.policy.parameters(), lr=0.1)
        self.calls = 0

    def learn(self):
        self.calls += 1

    def train(self):
        self.calls += 1


def episodes(protocol, success=False):
    return [
        {
            "topology_seed": t,
            "topology_hash": "UNIT-TEST-HASH",
            "evaluation_seed": e,
            "goal_reached": success,
            "steps_to_goal": 7 if success else None,
            "episode_length": 7,
            "total_reward": -4.0,
            "failed_actions": 2,
            "terminal_reason": "goal" if success else "step_limit",
        }
        for t in protocol["splits"]["validation"]
        for e in protocol["evaluation"]["evaluation_episode_seeds"]
    ]


def run_validation(tmp_path, monkeypatch, evaluator=None):
    p = load_protocol(ROOT / CONFIG)
    model = Policy()
    checkpoint = tmp_path / "unit-checkpoint"
    checkpoint.write_bytes(b"UNIT TEST ONLY")
    monkeypatch.setattr(module, "evaluate_policy", evaluator or (lambda *a, **k: (episodes(p), [])))
    result = module.validate_registered_checkpoint(
        model, p, training_seed=42, checkpoint=checkpoint, output=tmp_path / "validation"
    )
    return p, model, result


def test_validation_exact_population_schedule_and_distinct_seed_fields(tmp_path, monkeypatch):
    p = load_protocol(ROOT / CONFIG)

    def evaluator(model, **kwargs):
        assert kwargs == {
            "topology_seeds": tuple(range(1001, 1021)),
            "evaluation_episode_seeds": (19001,),
            "deterministic": True,
        }
        assert not torch.is_grad_enabled()
        return episodes(p), []

    _, model, summary = run_validation(tmp_path, monkeypatch, evaluator)
    rows = json.loads((tmp_path / "validation/episodes.json").read_text())
    assert len(rows) == summary["episode_count"] == 20
    assert all((r["training_seed"], r["evaluation_episode_seed"]) == (42, 19001) for r in rows)
    assert {r["topology_seed"] for r in rows} == set(range(1001, 1021))
    assert all("seed" not in r and "evaluation_seed" not in r for r in rows)
    assert all(r["steps_to_success"] is None for r in rows)
    assert summary["mean_steps_to_success"] is summary["median_steps_to_success"] is None
    assert summary["failed_episodes"] == 20
    assert summary["policy_sha256_before"] == summary["policy_sha256_after"] == policy_digest(model)
    assert model.calls == 0 and not summary["final_test_evaluated"]


def test_success_summary_uses_only_successful_steps(tmp_path, monkeypatch):
    p = load_protocol(ROOT / CONFIG)
    rows = episodes(p)
    rows[0].update(goal_reached=True, steps_to_goal=3, terminal_reason="goal")
    _, _, summary = run_validation(tmp_path, monkeypatch, lambda *a, **k: (rows, []))
    assert summary["success_rate"] == 1 / 20
    assert summary["mean_steps_to_success"] == summary["median_steps_to_success"] == 3
    assert summary["per_topology_success_rate"]["1001"] == 1
    assert summary["mean_environment_return"] == -4
    assert summary["mean_failed_actions"] == 2


@pytest.mark.parametrize("method", ["learn", "train", "optimizer"])
def test_updates_are_blocked_not_just_detected_afterwards(tmp_path, monkeypatch, method):
    def evaluator(model, **kwargs):
        if method == "optimizer":
            model.policy.optimizer.step()
        else:
            getattr(model, method)()
        raise AssertionError("update guard failed")

    with pytest.raises(GeneralisationError, match="update attempted"):
        run_validation(tmp_path, monkeypatch, evaluator)
    assert not (tmp_path / "validation").exists()


def test_weight_mutation_fails_before_output(tmp_path, monkeypatch):
    def evaluator(model, **kwargs):
        model.policy.weight.add_(1)
        return episodes(load_protocol(ROOT / CONFIG)), []

    with pytest.raises(GeneralisationError, match="policy changed"):
        run_validation(tmp_path, monkeypatch, evaluator)
    assert not (tmp_path / "validation").exists()


@pytest.mark.parametrize("kind", ["missing", "duplicate", "test", "trajectory"])
def test_invalid_or_final_test_population_is_rejected(tmp_path, monkeypatch, kind):
    p = load_protocol(ROOT / CONFIG)
    rows, steps = episodes(p), []
    if kind == "missing":
        rows.pop()
    elif kind == "duplicate":
        rows[-1] = copy.deepcopy(rows[0])
    elif kind == "test":
        rows[-1]["topology_seed"] = 16001
    else:
        steps = [{"topology_seed": 16001, "evaluation_seed": 19001}]
    with pytest.raises(GeneralisationError, match="population"):
        run_validation(tmp_path, monkeypatch, lambda *a, **k: (rows, steps))
    assert not (tmp_path / "validation").exists()


def test_training_env_rejects_final_test_pool_before_audit_creation(tmp_path):
    with pytest.raises(ValueError, match="1..60"):
        AuditedTrainingEnv(
            (1, 16001),
            config=OnPremTopologyConfig(),
            training_seed=42,
            audit_path=tmp_path / "audit.csv",
        )
    assert not (tmp_path / "audit.csv").exists()


def test_training_reset_cannot_override_split(tmp_path):
    env = AuditedTrainingEnv(
        (1,), config=OnPremTopologyConfig(), training_seed=42, audit_path=tmp_path / "audit.csv"
    )
    try:
        with pytest.raises(ValueError, match="outside this split"):
            env.reset(options={"topology_seed": 16001})
    finally:
        env.close()


def test_convergence_has_no_topology_or_evaluator_access(monkeypatch):
    monkeypatch.setattr(module, "evaluate_policy", lambda *a, **k: pytest.fail("test access"))
    import inspect

    assert list(inspect.signature(convergence_diagnostics).parameters) == [
        "returns",
        "diagnostic_rows",
    ]
    assert not convergence_diagnostics([], [])["passed"]


def test_real_untrained_ppo_validation_is_frozen(tmp_path, monkeypatch):
    from dataclasses import replace

    import numpy as np
    from sb3_contrib import MaskablePPO

    from rlredteam.enterprise import generalisation
    from rlredteam.enterprise.onprem import OnPremCurriculumEnv

    class BoundedEnv(OnPremCurriculumEnv):
        def __init__(self, seeds, *, config):
            super().__init__(seeds, config=replace(config, max_steps=2))

    monkeypatch.setattr(generalisation, "OnPremCurriculumEnv", BoundedEnv)
    p = load_protocol(ROOT / CONFIG)
    env = BoundedEnv((1,), config=OnPremTopologyConfig())
    model = MaskablePPO(
        "MlpPolicy",
        env,
        seed=0,
        n_steps=8,
        batch_size=8,
        policy_kwargs={"net_arch": [8]},
        device="cpu",
    )
    checkpoint = tmp_path / "untrained.zip"
    model.save(checkpoint)
    before = policy_digest(model)
    summary = module.validate_registered_checkpoint(
        model, p, training_seed=42, checkpoint=checkpoint, output=tmp_path / "validation"
    )
    assert summary["policy_sha256_before"] == summary["policy_sha256_after"] == before
    assert model.num_timesteps == 0 and summary["episode_count"] == 20
    assert np.isfinite(summary["mean_environment_return"])
    env.close()
