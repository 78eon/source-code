"""Read-only candidate-preference interface, deliberately not a NASim action adapter.

No environment, reward, training or checkpoint loader is imported. A trusted caller
may supply an already-loaded compatible policy. Shape equality alone never proves
semantic compatibility: a policy-specific reviewed binding is also mandatory.
"""

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from numbers import Integral

import numpy as np
from gymnasium import spaces

from rlredteam.knowledge import validation as v
from rlredteam.knowledge.serialization import digest

from .path_scoring import dumps as ranking_dumps
from .path_scoring import loads as ranking_loads

SCHEMA = "ranked-candidate-observation-v1"
ACTION_SEMANTICS = "advisory-candidate-preference-not-simulator-action-v1"
FEATURES = (
    "present",
    "heuristic_score",
    "confidence",
    "applicability_factor",
    "cvss_known",
    "unknown_applicability",
    "has_conflicts",
    "unique_edge_count",
    "unverified_prerequisites",
    "severity_normalized",
)


class PolicyCompatibilityError(ValueError):
    """No silent resizing, flattening of simulator state or action reinterpretation."""


@dataclass(frozen=True, slots=True, kw_only=True)
class CandidatePolicyContract:
    capacity: int
    schema: str = SCHEMA
    action_semantics: str = ACTION_SEMANTICS

    def __post_init__(self):
        v.validate_fields(self)
        if type(self.capacity) is not int or not 1 <= self.capacity <= 1024:
            raise PolicyCompatibilityError("candidate capacity must be an integer in 1..1024")
        if self.schema != SCHEMA or self.action_semantics != ACTION_SEMANTICS:
            raise PolicyCompatibilityError("unsupported candidate observation/action contract")

    @property
    def observation_shape(self):
        return (self.capacity * len(FEATURES),)

    @property
    def contract_id(self):
        return digest((self, FEATURES, "float32", "candidate-id-order", "explicit-zero-padding"))


@dataclass(frozen=True, slots=True, kw_only=True)
class CandidatePreference:
    index: int
    candidate_id: str
    heuristic_rank: int
    score_id: str

    def __post_init__(self):
        v.validate_fields(self)
        v.digest_string(self.candidate_id)
        v.digest_string(self.score_id)
        if type(self.index) is not int or self.index < 0 or self.heuristic_rank < 1:
            raise PolicyCompatibilityError("invalid preference catalogue index/rank")


@dataclass(frozen=True, slots=True, kw_only=True)
class CandidatePolicyState:
    state_id: str
    contract: CandidatePolicyContract
    observation: tuple[float, ...]
    preferences: tuple[CandidatePreference, ...]
    available_mask: tuple[bool, ...]
    ranking_json: str

    def __post_init__(self):
        v.validate_fields(self)
        v.unique(self.preferences, "candidate_id")
        if (
            len(self.observation) != self.contract.observation_shape[0]
            or len(self.available_mask) != self.contract.capacity
            or not np.isfinite(self.observation).all()
        ):
            raise PolicyCompatibilityError("candidate observation dimensions/values invalid")
        expected = tuple(i < len(self.preferences) for i in range(self.contract.capacity))
        if self.available_mask != expected or tuple(p.index for p in self.preferences) != tuple(
            range(len(self.preferences))
        ):
            raise PolicyCompatibilityError("invalid candidate preference catalogue/mask")
        if self.state_id != digest(
            (
                self.contract,
                self.observation,
                self.preferences,
                self.available_mask,
                self.ranking_json,
            )
        ):
            raise PolicyCompatibilityError("candidate policy state integrity mismatch")

    def candidate_for_index(self, index):
        if (
            isinstance(index, bool)
            or not isinstance(index, Integral)
            or not 0 <= index < len(self.preferences)
        ):
            raise PolicyCompatibilityError("policy preference is invalid or selects a padded slot")
        return self.preferences[int(index)].candidate_id

    def index_for_candidate(self, candidate_id):
        for item in self.preferences:
            if item.candidate_id == candidate_id:
                return item.index
        raise PolicyCompatibilityError("candidate not present in this state")


def encode_ranked_paths(ranking, contract):
    if not isinstance(contract, CandidatePolicyContract):
        raise PolicyCompatibilityError("explicit candidate policy contract required")
    ranking = ranking_loads(ranking_dumps(ranking))
    if len(ranking.scores) > contract.capacity:
        raise PolicyCompatibilityError("candidate capacity exceeded; truncation is forbidden")
    ranks = {s.candidate_id: rank for rank, s in enumerate(ranking.scores, 1)}
    preferences, rows = [], []
    for index, score in enumerate(sorted(ranking.scores, key=lambda s: s.candidate_id)):
        explanation, components = score.explanation, score.components
        rows.append(
            (
                1.0,
                float(score.total),
                float(components["confidence"]),
                float(components["applicability_factor"]),
                float(not explanation["cvss_missing"]),
                float(explanation["terminal_applicability"] == "UNKNOWN"),
                float(explanation["has_conflicts"]),
                float(explanation["unique_edge_count"]),
                float(bool(explanation["unverified_prerequisites"])),
                float(components["severity_normalized"]),
            )
        )
        preferences.append(
            CandidatePreference(
                index=index,
                candidate_id=score.candidate_id,
                heuristic_rank=ranks[score.candidate_id],
                score_id=score.score_id,
            )
        )
    rows.extend([(0.0,) * len(FEATURES)] * (contract.capacity - len(rows)))
    # Float32 conversion is part of this NEW contract, never an old-model coercion.
    observation = tuple(float(x) for x in np.asarray(rows, dtype=np.float32).reshape(-1))
    preferences = tuple(preferences)
    mask = tuple(i < len(preferences) for i in range(contract.capacity))
    document = ranking_dumps(ranking)
    identifier = digest((contract, observation, preferences, mask, document))
    return CandidatePolicyState(
        state_id=identifier,
        contract=contract,
        observation=observation,
        preferences=preferences,
        available_mask=mask,
        ranking_json=document,
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class ReviewedPolicyBinding:
    """Caller-supplied compatibility attestation, not inferred from matching shapes.

    evidence_id must refer to the operator's semantic-compatibility review. This
    interface cannot prove that an attestation is scientifically valid. Historical
    NASim action semantics do not satisfy this contract without a separate study.
    """

    contract_id: str
    policy_sha256: str
    evidence_id: str
    action_semantics: str = ACTION_SEMANTICS

    def __post_init__(self):
        v.validate_fields(self)
        v.digest_string(self.contract_id)
        v.digest_string(self.policy_sha256)
        v.stable_id(self.evidence_id)
        if self.action_semantics != ACTION_SEMANTICS:
            raise PolicyCompatibilityError(
                "native simulator actions cannot mean candidate preferences"
            )


def policy_digest(model):
    """Same state-dict hashing convention as frozen evaluation, without its imports."""
    value = hashlib.sha256()
    for name, tensor in sorted(model.policy.state_dict().items()):
        value.update(name.encode())
        value.update(tensor.detach().cpu().contiguous().numpy().tobytes())
    return value.hexdigest()


@dataclass(frozen=True, slots=True, kw_only=True)
class AdvisoryPreference:
    """Only one preference is reported by PPO.predict; other ranks stay unknown."""

    candidate_id: str
    heuristic_rank: int
    planner_preference: int | None

    def __post_init__(self):
        v.validate_fields(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class PolicyAdvice:
    state_id: str
    method: str
    preferences: tuple[AdvisoryPreference, ...]
    provenance: Mapping[str, object]
    advisory_only: bool = True

    def __post_init__(self):
        v.validate_fields(self)
        v.attributes(self, "provenance")
        if not self.advisory_only:
            raise PolicyCompatibilityError("planner advice can never authorize execution")


def advisory_predict(state, model, binding=None):
    """Deterministic inference only; no learn/load/save/environment.step calls.

    Standard PPO cannot use this padding mask automatically. If it prefers an
    unavailable slot we reject the output, never substitute a heuristic action.
    Recurrent, Dict, MultiDiscrete and native NASim contracts are unsupported.
    """
    if not isinstance(state, CandidatePolicyState):
        raise PolicyCompatibilityError("typed candidate policy state required")
    if encode_ranked_paths(ranking_loads(state.ranking_json), state.contract) != state:
        raise PolicyCompatibilityError("state does not match its retained ranking")
    if not isinstance(binding, ReviewedPolicyBinding):
        raise PolicyCompatibilityError(
            "historical/unbound policy rejected: reviewed candidate contract required"
        )
    if binding.contract_id != state.contract.contract_id:
        raise PolicyCompatibilityError("policy encoder contract mismatch")
    observation_space, action_space = model.observation_space, model.action_space
    observation = np.array(state.observation, dtype=np.float32)
    if (
        not isinstance(observation_space, spaces.Box)
        or observation_space.shape != state.contract.observation_shape
        or observation_space.dtype != np.dtype("float32")
        or not observation_space.contains(observation)
    ):
        raise PolicyCompatibilityError("incompatible PPO observation shape/dtype/bounds")
    if (
        not isinstance(action_space, spaces.Discrete)
        or action_space.start != 0
        or action_space.n != state.contract.capacity
    ):
        raise PolicyCompatibilityError("incompatible PPO candidate action space")
    if not state.preferences:
        raise PolicyCompatibilityError("no candidates available for advisory inference")
    before = policy_digest(model)
    if before != binding.policy_sha256:
        raise PolicyCompatibilityError("policy weights do not match reviewed binding")
    import torch

    # Preserve the module's mode, and never enable gradients or update an optimizer.
    training = model.policy.training
    try:
        model.policy.set_training_mode(False)
        with torch.no_grad():
            action, recurrent = model.predict(observation.copy(), deterministic=True)
    finally:
        model.policy.set_training_mode(training)
        if policy_digest(model) != before:
            raise PolicyCompatibilityError("policy parameters changed during advisory inference")
    if recurrent is not None:
        raise PolicyCompatibilityError("recurrent policy output is not supported by this contract")
    result = np.asarray(action)
    if result.shape != () or result.dtype.kind not in ("i", "u"):
        raise PolicyCompatibilityError("policy must return one discrete candidate preference")
    selected = state.candidate_for_index(result.item())
    ranking = ranking_loads(state.ranking_json)
    return PolicyAdvice(
        state_id=state.state_id,
        method="deterministic-policy-advice-not-heuristic-rank",
        preferences=tuple(
            AdvisoryPreference(
                candidate_id=p.candidate_id,
                heuristic_rank=p.heuristic_rank,
                planner_preference=1 if p.candidate_id == selected else None,
            )
            for p in state.preferences
        ),
        provenance=dict(
            ranking_id=ranking.ranking_id,
            contract_id=state.contract.contract_id,
            compatibility_evidence_id=binding.evidence_id,
            policy_sha256_before=before,
            policy_sha256_after=policy_digest(model),
            gradient_updates=False,
            deterministic=True,
            action_semantics=ACTION_SEMANTICS,
        ),
    )
