"""Phase 3 mask-aware training/evaluation and provenance invariants."""

from __future__ import annotations

import json

import numpy as np
import pytest
import torch

from rlredteam.enterprise.generalisation import (
    GeneralisationError,
    OnPremExperimentConfig,
    distribution_manifest,
    evaluate_policy,
    policy_digest,
    reconstruct_attack_path,
    write_evaluation_package,
)
from rlredteam.enterprise.onprem import (
    OnPremCurriculumEnv,
    OnPremGeneralisationSplit,
    OnPremTopologyConfig,
)


class HighestValidPolicy:
    """Test policy: observes only the public observation/mask boundary."""

    def __init__(self) -> None:
        self.policy = torch.nn.Linear(1, 1, bias=False)

    def set_random_seed(self, seed: int) -> None:
        self.seed = seed

    def predict(self, observation, *, action_masks, deterministic: bool):
        del observation, deterministic
        return int(np.flatnonzero(action_masks)[-1]), None


def test_action_masks_are_boolean_and_do_not_read_true_topology() -> None:
    env = OnPremCurriculumEnv((1,))
    env.reset(seed=77, options={"topology_seed": 1})
    expected = env.action_masks().copy()

    class ForbiddenTruth:
        def __getattribute__(self, name):
            raise AssertionError(f"action mask read ground truth: {name}")

    env._env.true_topology = ForbiddenTruth()
    actual = env.action_masks()
    assert actual.dtype == np.bool_
    assert np.array_equal(actual, expected)


def test_experiment_configuration_is_complete_and_hashed() -> None:
    config = OnPremExperimentConfig.from_yaml()
    assert config.total_timesteps > 0
    assert len(config.digest()) == 64
    assert config.evaluation_episode_seeds == (9001,)


def test_distribution_manifest_covers_every_disjoint_seed() -> None:
    split = OnPremGeneralisationSplit()
    manifest = distribution_manifest(split, OnPremTopologyConfig.from_yaml())
    assert set(map(int, manifest["train"])) == set(split.train)
    assert set(map(int, manifest["validation"])) == set(split.validation)
    assert set(map(int, manifest["test"])) == set(split.test)
    assert all(len(value) == 64 for group in manifest.values() for value in group.values())


@pytest.mark.parametrize("seeds", [(1,), (60,), (1001, 42), (2001, 60)])
def test_evaluation_refuses_training_topology_overlap(seeds) -> None:
    with pytest.raises(GeneralisationError, match="overlap"):
        evaluate_policy(
            HighestValidPolicy(),
            topology_seeds=seeds,
            evaluation_episode_seeds=(9001,),
        )


def test_unseen_evaluation_is_masked_frozen_and_reconstructable() -> None:
    model = HighestValidPolicy()
    before = model.policy.weight.detach().clone()
    episodes, steps = evaluate_policy(
        model,
        topology_seeds=(1001,),
        evaluation_episode_seeds=(9001,),
    )
    assert len(episodes) == 1
    assert episodes[0]["goal_reached"]
    assert episodes[0]["invalid_mask_selections"] == 0
    assert steps[-1]["goal_reached"]
    assert all(step["target_entity"] for step in steps)
    assert any(step["prerequisites"] for step in steps)
    assert any(step["outcomes"] for step in steps)
    causal = reconstruct_attack_path(steps)
    assert causal[-1]["action_kind"] == "access_asset"
    assert any(step["action_kind"] == "exploit" for step in causal)
    assert len(causal) < len(steps)
    assert torch.equal(before, model.policy.weight)


def test_policy_inputs_stay_knowledge_only_after_discovery() -> None:
    from rlredteam.enterprise.environment import EnterpriseActionType

    env = OnPremCurriculumEnv((1001,))
    env.reset(seed=9001, options={"topology_seed": 1001})
    action = env.action_index(EnterpriseActionType.DISCOVER_NETWORK, "segment_edge")
    env.step(action)
    expected_observation = env._env._observation().copy()
    expected_mask = env.action_masks().copy()

    class ForbiddenTruth:
        def __getattribute__(self, name):
            raise AssertionError(f"policy input read hidden topology: {name}")

    env._env.true_topology = ForbiddenTruth()
    assert np.array_equal(env._env._observation(), expected_observation)
    assert np.array_equal(env.action_masks(), expected_mask)
    env.close()


def test_real_maskable_ppo_evaluation_has_no_updates_and_separate_seeds(monkeypatch):
    """Untrained weights, four bounded steps per episode; never calls learn."""
    from dataclasses import replace

    from sb3_contrib import MaskablePPO

    config = replace(OnPremTopologyConfig.from_yaml(), max_steps=4)
    monkeypatch.setattr(OnPremTopologyConfig, "from_yaml", classmethod(lambda cls: config))
    env = OnPremCurriculumEnv((1001,), config=config)
    model = MaskablePPO("MlpPolicy", env, seed=42, n_steps=8, batch_size=8,
                        policy_kwargs={"net_arch": [8]}, device="cpu")

    def forbidden(*args, **kwargs):
        raise AssertionError("evaluation attempted a training update")

    monkeypatch.setattr(model, "learn", forbidden)
    monkeypatch.setattr(model, "train", forbidden)
    monkeypatch.setattr(model.policy.optimizer, "step", forbidden)
    before = policy_digest(model)
    episodes, steps = evaluate_policy(
        model, topology_seeds=(1001, 2001), evaluation_episode_seeds=(42, 9001)
    )
    assert policy_digest(model) == before
    assert model.num_timesteps == 0
    assert {(row["topology_seed"], row["evaluation_seed"]) for row in episodes} == {
        (1001, 42), (1001, 9001), (2001, 42), (2001, 9001)
    }
    assert len(steps) <= 16
    assert all(row["invalid_mask_selections"] == 0 for row in episodes)
    env.close()


def test_frozen_evaluation_rejects_policy_weight_mutation():
    class MutatingPolicy(HighestValidPolicy):
        def predict(self, *args, **kwargs):
            with torch.no_grad():
                self.policy.weight.add_(1)
            return super().predict(*args, **kwargs)

    with pytest.raises(GeneralisationError, match="parameters changed"):
        evaluate_policy(MutatingPolicy(), topology_seeds=(1001,),
                        evaluation_episode_seeds=(9001,))


def test_evaluation_package_contains_raw_trajectory_and_summary(tmp_path) -> None:
    episodes, steps = evaluate_policy(
        HighestValidPolicy(),
        topology_seeds=(1002,),
        evaluation_episode_seeds=(9002,),
    )
    write_evaluation_package(
        tmp_path,
        episodes=episodes,
        steps=steps,
        metadata={"gradient_updates": False},
    )
    assert (tmp_path / "episodes.csv").is_file()
    assert (tmp_path / "attack_paths.json").is_file()
    assert len((tmp_path / "trajectories.jsonl").read_text().splitlines()) == len(steps)
    summary = json.loads((tmp_path / "summary.json").read_text())
    assert summary["success_rate"] == 1.0
    assert summary["invalid_mask_selections"] == 0
