"""Registered per-policy aggregation contract for the frozen on-prem study.

The frozen validation runner defines the per-policy reporting calculations but
is intentionally bound to the validation split. This adapter applies those same
calculations to a supplied, already verified population without generating or
evaluating environments.
"""

from __future__ import annotations

from collections import defaultdict
from statistics import mean, median


class AggregationBlocked(RuntimeError):
    """Raised when rows or metric definitions diverge from the registered contract."""


# SHA256 of canonical JSON for protocol_manifest.json#/canonical_protocol/outcomes.
REGISTERED_OUTCOMES_SHA256 = "2360b7479f8182054046ad491c61ac4c91203c77232080818bf589059adc635a"


def _canonical_sha(value: object) -> str:
    import hashlib
    import json

    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode()).hexdigest()


def _validate_contract(outcomes: dict) -> None:
    if not isinstance(outcomes, dict) or _canonical_sha(outcomes) != REGISTERED_OUTCOMES_SHA256:
        raise AggregationBlocked("registered metric/outcome definition mismatch")


def _value(row: dict, normalized: str, raw: str):
    if normalized in row:
        return row[normalized]
    if raw in row:
        return row[raw]
    raise AggregationBlocked(f"episode field missing: {normalized}")


def _normalized_row(row: dict) -> dict:
    success = _value(row, "success", "goal_reached")
    if type(success) is not bool:
        raise AggregationBlocked("success outcome must be boolean")
    steps = _value(row, "steps_to_success", "steps_to_goal")
    if not success and steps is not None:
        raise AggregationBlocked("unsuccessful episode has steps_to_success")
    if success and (type(steps) is not int or steps < 0):
        raise AggregationBlocked("successful episode lacks valid steps_to_success")
    result = {
        **{k: v for k, v in row.items() if k not in {
            "goal_reached", "steps_to_goal", "total_reward", "terminal_reason",
            "evaluation_seed",
        }},
        "topology_seed": row["topology_seed"],
        "topology_hash": row.get("topology_hash"),
        "evaluation_episode_seed": row.get("evaluation_episode_seed", row.get("evaluation_seed")),
        "success": success,
        "steps_to_success": steps if success else None,
        "episode_length": row["episode_length"],
        "environment_return": _value(row, "environment_return", "total_reward"),
        "failed_actions": row["failed_actions"],
        "terminal_outcome": _value(row, "terminal_outcome", "terminal_reason"),
        "objective_reached": row.get("objective_reached", success),
    }
    if type(result["topology_seed"]) is not int or type(result["evaluation_episode_seed"]) is not int:
        raise AggregationBlocked("episode seed identifiers must be integers")
    if not isinstance(result["topology_hash"], str) or not result["topology_hash"]:
        raise AggregationBlocked("topology hash missing from episode provenance")
    if type(result["episode_length"]) is not int or result["episode_length"] < 0:
        raise AggregationBlocked("episode_length must be a nonnegative integer")
    if result["objective_reached"] is not success:
        raise AggregationBlocked("objective_reached disagrees with registered success outcome")
    return result


def aggregate_registered_results(
    episodes: list[dict],
    *,
    training_seeds: tuple[int, ...],
    topology_seeds: tuple[int, ...],
    evaluation_episode_seeds: tuple[int, ...],
    outcomes: dict,
    phase: str,
    deterministic: bool,
) -> tuple[dict, list[dict]]:
    """Validate the full policy × topology × episode population and report per policy.

    The campaign outcome is a collection of policy-level summaries. Metrics are
    never pooled across policies: the registered unit of aggregation is topology
    episodes within each training seed.
    """
    _validate_contract(outcomes)
    if not training_seeds or len(set(training_seeds)) != len(training_seeds):
        raise AggregationBlocked("duplicate or empty registered policy population")
    if not topology_seeds or len(set(topology_seeds)) != len(topology_seeds):
        raise AggregationBlocked("duplicate or empty registered topology population")
    if len(training_seeds) != 10:
        raise AggregationBlocked("registered campaign requires all ten policies")
    if len(topology_seeds) != 20:
        raise AggregationBlocked("registered policy population requires twenty topology IDs")
    if not evaluation_episode_seeds or len(set(evaluation_episode_seeds)) != len(evaluation_episode_seeds):
        raise AggregationBlocked("duplicate or empty registered evaluation seed population")
    if type(deterministic) is not bool or phase not in {"validation", "heldout"}:
        raise AggregationBlocked("evaluation phase/determinism contract mismatch")

    expected = {
        (policy, topology, episode_seed)
        for policy in training_seeds
        for topology in topology_seeds
        for episode_seed in evaluation_episode_seeds
    }
    grouped: dict[int, list[dict]] = defaultdict(list)
    observed: set[tuple[int, int, int]] = set()
    rows = []
    for raw in episodes:
        if type(raw.get("training_seed")) is not int:
            raise AggregationBlocked("episode training_seed missing or invalid")
        row = _normalized_row(raw)
        key = (raw["training_seed"], row["topology_seed"], row["evaluation_episode_seed"])
        if key not in expected:
            raise AggregationBlocked("unexpected policy/topology/evaluation-seed tuple")
        if key in observed:
            raise AggregationBlocked("duplicate policy/topology/evaluation-seed tuple")
        observed.add(key)
        grouped[key[0]].append(row)
        rows.append(row)
    if observed != expected:
        missing_policies = set(training_seeds) - set(grouped)
        if missing_policies:
            raise AggregationBlocked("missing registered policy")
        raise AggregationBlocked("registered topology/evaluation population incomplete")

    policy_summaries = {}
    for policy in training_seeds:
        policy_rows = grouped[policy]
        if len(policy_rows) != len(topology_seeds) * len(evaluation_episode_seeds):
            raise AggregationBlocked("policy episode count does not match registered population")
        provenance_keys = (
            "protocol_sha256", "training_seed", "checkpoint_sha256",
            "policy_sha256_before", "policy_sha256_after", "phase",
        )
        for key in provenance_keys:
            values = {row[key] for row in policy_rows if key in row}
            if len(values) > 1:
                raise AggregationBlocked(f"policy provenance differs across episodes: {key}")
        if "policy_sha256_before" in policy_rows[0] and "policy_sha256_after" in policy_rows[0]:
            if policy_rows[0]["policy_sha256_before"] != policy_rows[0]["policy_sha256_after"]:
                raise AggregationBlocked("policy changed during frozen evaluation")
        successful_steps = [r["steps_to_success"] for r in policy_rows if r["success"]]
        # Preserve provenance fields already attached to each raw episode. These
        # fields are identity metadata, not additional outcome metrics.
        provenance = {k: policy_rows[0][k] for k in provenance_keys if k in policy_rows[0]}
        summary = {
            **provenance,
            "episode_count": len(policy_rows),
            "successful_episodes": len(successful_steps),
            "failed_episodes": len(policy_rows) - len(successful_steps),
            "success_rate": len(successful_steps) / len(policy_rows),
            "per_topology_success_rate": {
                str(topology): mean(
                    r["success"] for r in policy_rows if r["topology_seed"] == topology
                )
                for topology in topology_seeds
            },
            "mean_steps_to_success": mean(successful_steps) if successful_steps else None,
            "median_steps_to_success": median(successful_steps) if successful_steps else None,
            "mean_environment_return": mean(r["environment_return"] for r in policy_rows),
            "mean_failed_actions": mean(r["failed_actions"] for r in policy_rows),
            "mean_episode_length": mean(r["episode_length"] for r in policy_rows),
            ("validation_topology_seeds" if phase == "validation" else "topology_seeds"): list(topology_seeds),
            "evaluation_episode_seeds": list(evaluation_episode_seeds),
            "deterministic": deterministic,
            "gradient_updates": False,
            "final_test_evaluated": phase == "heldout",
        }
        policy_summaries[str(policy)] = summary

    campaign = {
        "phase": phase,
        "complete": True,
        "episode_count": len(rows),
        "policy_count": len(policy_summaries),
        "training_seeds": list(training_seeds),
        "topology_seeds": list(topology_seeds),
        "evaluation_episode_seeds": list(evaluation_episode_seeds),
        "deterministic": deterministic,
        "gradient_updates": False,
        "final_test_evaluated": phase == "heldout",
        "policy_summaries": policy_summaries,
    }
    return campaign, rows
