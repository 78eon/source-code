"""Generated evidence and untrained temporary PPO policies; no learning or live targets."""

import hashlib
import secrets
from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4

import gymnasium as gym
import numpy as np
import pytest
from gymnasium import spaces
from psycopg import sql
from stable_baselines3 import PPO

from rlredteam.digital_twin.path_scoring import dumps as ranking_dumps
from rlredteam.digital_twin.path_scoring import score_candidates
from rlredteam.digital_twin.planner_adapter import (
    FEATURES,
    CandidatePolicyContract,
    PolicyCompatibilityError,
    ReviewedPolicyBinding,
    advisory_predict,
    encode_ranked_paths,
    policy_digest,
)
from tests import test_inventory_path_scoring as fixtures

db = fixtures.db
ready = fixtures.ready


def state_for(store, *, padding=0):
    paths, correlation = fixtures.setup(store)
    ranking = score_candidates(paths)
    contract = CandidatePolicyContract(capacity=len(ranking.scores) + padding)
    return encode_ranked_paths(ranking, contract), ranking, correlation


def model_for(state):
    class NoInteractionEnv(gym.Env):
        observation_space = spaces.Box(
            -np.inf, np.inf, state.contract.observation_shape, dtype=np.float32
        )
        action_space = spaces.Discrete(state.contract.capacity)

        def reset(self, **kwargs):
            raise AssertionError("no environment interaction authorized")

        def step(self, action):
            raise AssertionError("no environment execution authorized")

    return PPO(
        "MlpPolicy",
        NoInteractionEnv(),
        n_steps=2,
        batch_size=2,
        device="cpu",
        seed=secrets.randbelow(100000),
        policy_kwargs={"net_arch": [4]},
    )


def binding_for(state, model):
    return ReviewedPolicyBinding(
        contract_id=state.contract.contract_id,
        policy_sha256=policy_digest(model),
        evidence_id="generated-review:" + uuid4().hex,
    )


def test_deterministic_encoding_and_reversible_mapping(ready):
    state, ranking, _ = state_for(ready)
    assert state == encode_ranked_paths(ranking, state.contract)
    assert state.ranking_json == ranking_dumps(ranking)
    assert len(state.observation) == state.contract.capacity * len(FEATURES)
    for item in state.preferences:
        assert state.candidate_for_index(item.index) == item.candidate_id
        assert state.index_for_candidate(item.candidate_id) == item.index
        assert ranking.scores[item.heuristic_rank - 1].candidate_id == item.candidate_id


def test_capacity_does_not_silently_truncate(ready):
    _, ranking, _ = state_for(ready)
    with pytest.raises(PolicyCompatibilityError, match="truncation"):
        encode_ranked_paths(ranking, CandidatePolicyContract(capacity=len(ranking.scores) - 1))


def test_padding_is_explicit_and_cannot_be_selected(ready):
    state, _, _ = state_for(ready, padding=1)
    assert not state.available_mask[-1]
    assert state.observation[-len(FEATURES) :] == (0.0,) * len(FEATURES)
    with pytest.raises(PolicyCompatibilityError, match="padded"):
        state.candidate_for_index(state.contract.capacity - 1)


def test_real_ppo_inference_is_advisory_and_policy_immutable(ready, monkeypatch):
    import torch

    state, _, _ = state_for(ready)
    model = model_for(state)
    binding = binding_for(state, model)

    def denied(*args, **kwargs):
        raise AssertionError("training/save is forbidden")

    monkeypatch.setattr(model, "learn", denied)
    monkeypatch.setattr(model, "save", denied)
    before, mode = policy_digest(model), model.policy.training
    first = advisory_predict(state, model, binding)
    second = advisory_predict(state, model, binding)
    assert first == second and first.advisory_only
    assert (
        first.provenance["policy_sha256_before"]
        == first.provenance["policy_sha256_after"]
        == before
    )
    assert model.num_timesteps == 0 and model._n_updates == 0
    assert model.policy.training == mode
    assert all(p.grad is None for p in model.policy.parameters())
    assert not model.policy.optimizer.state
    assert torch.is_grad_enabled()
    assert sum(p.planner_preference == 1 for p in first.preferences) == 1


def test_same_shape_historical_policy_is_rejected_without_semantic_binding(ready, monkeypatch):
    state, _, _ = state_for(ready)
    model = model_for(state)

    def denied(*args, **kwargs):
        raise AssertionError("unbound policy must not receive evidence")

    monkeypatch.setattr(model, "predict", denied)
    with pytest.raises(PolicyCompatibilityError, match="historical/unbound"):
        advisory_predict(state, model)


@pytest.mark.parametrize("mismatch", ["shape", "dtype", "bounds", "actions", "dict"])
def test_incompatible_model_spaces_fail_before_predict(ready, mismatch):
    state, _, _ = state_for(ready)
    shape = state.contract.observation_shape
    observation = spaces.Box(-np.inf, np.inf, shape, dtype=np.float32)
    actions = spaces.Discrete(state.contract.capacity)
    if mismatch == "shape":
        observation = spaces.Box(-np.inf, np.inf, (shape[0] + 1,), dtype=np.float32)
    elif mismatch == "dtype":
        observation = spaces.Box(-np.inf, np.inf, shape, dtype=np.float64)
    elif mismatch == "bounds":
        observation = spaces.Box(-1, -0.5, shape, dtype=np.float32)
    elif mismatch == "actions":
        actions = spaces.Discrete(state.contract.capacity + 1)
    else:
        observation = spaces.Dict({"unsupported": observation})
    model = SimpleNamespace(observation_space=observation, action_space=actions)
    binding = ReviewedPolicyBinding(
        contract_id=state.contract.contract_id,
        policy_sha256=secrets.token_hex(32),
        evidence_id="review:" + uuid4().hex,
    )
    with pytest.raises(PolicyCompatibilityError, match="incompatible PPO"):
        advisory_predict(state, model, binding)


def test_wrong_policy_or_encoder_binding_rejected(ready):
    state, _, _ = state_for(ready)
    model = model_for(state)
    binding = binding_for(state, model)
    with pytest.raises(PolicyCompatibilityError, match="encoder contract"):
        advisory_predict(state, model, replace(binding, contract_id=secrets.token_hex(32)))
    with pytest.raises(PolicyCompatibilityError, match="weights"):
        advisory_predict(state, model, replace(binding, policy_sha256=secrets.token_hex(32)))


def test_heuristic_rank_and_policy_preference_stay_distinct(ready, monkeypatch):
    state, _, _ = state_for(ready)
    model = model_for(state)
    selected = max(state.preferences, key=lambda p: p.heuristic_rank)
    monkeypatch.setattr(
        model, "predict", lambda obs, deterministic: (np.array(selected.index), None)
    )
    advice = advisory_predict(state, model, binding_for(state, model))
    preferred = next(p for p in advice.preferences if p.planner_preference == 1)
    assert preferred.heuristic_rank == selected.heuristic_rank > 1
    assert "not-heuristic-rank" in advice.method
    assert all(p.planner_preference is None for p in advice.preferences if p != preferred)


def test_generated_checkpoint_is_not_rewritten(ready, tmp_path):
    state, _, _ = state_for(ready)
    model = model_for(state)
    checkpoint = tmp_path / (uuid4().hex + ".zip")
    model.save(checkpoint)
    before = hashlib.sha256(checkpoint.read_bytes()).hexdigest()
    advisory_predict(state, model, binding_for(state, model))
    with pytest.raises(PolicyCompatibilityError):
        advisory_predict(state, model)
    assert hashlib.sha256(checkpoint.read_bytes()).hexdigest() == before


@pytest.mark.parametrize("output", ["padding", "vector", "float", "negative", "recurrent"])
def test_invalid_policy_output_never_becomes_an_action(ready, monkeypatch, output):
    state, _, _ = state_for(ready, padding=1)
    model = model_for(state)
    result, recurrent = np.array(0), None
    if output == "padding":
        result = np.array(state.contract.capacity - 1)
    elif output == "vector":
        result = np.array([0])
    elif output == "float":
        result = np.array(0.0)
    elif output == "negative":
        result = np.array(-1)
    else:
        recurrent = np.zeros((1,))
    monkeypatch.setattr(model, "predict", lambda obs, deterministic: (result, recurrent))
    with pytest.raises(PolicyCompatibilityError):
        advisory_predict(state, model, binding_for(state, model))


def test_policy_hash_uses_existing_frozen_evaluation_convention(ready):
    from rlredteam.evaluation import policy_digest as research_digest

    state, _, _ = state_for(ready)
    model = model_for(state)
    assert policy_digest(model) == research_digest(model)


def test_all_persisted_inputs_and_ranking_remain_unchanged(ready):
    state, ranking, correlation = state_for(ready)
    conn = ready.connection
    tables = conn.execute(
        "SELECT schemaname,tablename FROM pg_tables WHERE schemaname=ANY(%s) "
        "ORDER BY schemaname,tablename",
        (
            [
                "normalized_evidence",
                "entity_reconciliation",
                "digital_twin_state",
                "vulnerability_correlation",
            ],
        ),
    ).fetchall()

    def snapshot():
        return [
            conn.execute(
                sql.SQL("SELECT to_jsonb(t) FROM {}.{} t ORDER BY to_jsonb(t)::text").format(
                    sql.Identifier(s), sql.Identifier(t)
                )
            ).fetchall()
            for s, t in tables
        ]

    before = snapshot()
    model = model_for(state)
    advisory_predict(state, model, binding_for(state, model))
    assert snapshot() == before
    assert ranking_dumps(ranking) == state.ranking_json
    assert ready.load(correlation.correlation_id) == correlation


def test_no_network_calls_or_executable_preferences(ready, monkeypatch):
    import socket
    import subprocess

    state, _, _ = state_for(ready)
    model = model_for(state)

    def denied(*args, **kwargs):
        raise AssertionError("network/process activity forbidden")

    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(subprocess, "Popen", denied)
    advice = advisory_predict(state, model, binding_for(state, model))
    assert advice.advisory_only
    assert not any(
        hasattr(preference, name)
        for preference in advice.preferences
        for name in ("execute", "payload", "command", "step")
    )
