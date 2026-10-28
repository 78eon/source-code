"""Validation-only terminal-checkpoint evaluation; never selects a final test split."""

from __future__ import annotations

import csv
import json
from contextlib import ExitStack
from pathlib import Path
from statistics import mean, median
from unittest.mock import patch

import torch

from .generalisation import GeneralisationError, evaluate_policy, policy_digest
from .onprem_protocol import file_hash, protocol_digest, validate_design


def validate_registered_checkpoint(model, protocol, *, training_seed, checkpoint, output):
    """Evaluate exactly the registered validation population without policy updates."""
    validate_design(protocol)
    if training_seed not in protocol["training_seeds"]:
        raise GeneralisationError("unregistered training_seed")
    seeds = tuple(protocol["splits"]["validation"])
    if set(seeds) & set(protocol["splits"]["test"]):
        raise GeneralisationError("validation overlaps final test")
    if protocol["evaluation"]["policy_updates"] is not False:
        raise GeneralisationError("validation policy updates forbidden")
    episode_seeds = tuple(protocol["evaluation"]["evaluation_episode_seeds"])
    checkpoint = Path(checkpoint)
    checkpoint_hash = file_hash(checkpoint)
    before = policy_digest(model)

    def forbidden(*args, **kwargs):
        raise GeneralisationError("policy update attempted during registered validation")

    with ExitStack() as guards, torch.no_grad():
        for owner, name in (
            (model, "learn"),
            (model, "train"),
            (getattr(model.policy, "optimizer", None), "step"),
            (getattr(model, "replay_buffer", None), "add"),
        ):
            if owner is not None and callable(getattr(owner, name, None)):
                guards.enter_context(patch.object(owner, name, forbidden))
        episodes, steps = evaluate_policy(
            model,
            topology_seeds=seeds,
            evaluation_episode_seeds=episode_seeds,
            deterministic=protocol["evaluation"]["deterministic"],
        )
    after = policy_digest(model)
    if before != after or file_hash(checkpoint) != checkpoint_hash:
        raise GeneralisationError("checkpoint/policy changed during registered validation")
    expected = {(t, e) for t in seeds for e in episode_seeds}
    observed = {(r["topology_seed"], r["evaluation_seed"]) for r in episodes}
    if observed != expected or len(episodes) != len(expected):
        raise GeneralisationError("validation episode population mismatch")
    if any((r["topology_seed"], r["evaluation_seed"]) not in expected for r in steps):
        raise GeneralisationError("trajectory outside validation population")
    metadata = {
        "protocol_sha256": protocol_digest(protocol),
        "training_seed": training_seed,
        "checkpoint_sha256": checkpoint_hash,
        "policy_sha256_before": before,
        "policy_sha256_after": after,
        "phase": "validation",
    }
    rows = []
    for r in episodes:
        success = bool(r["goal_reached"])
        rows.append(
            {
                **metadata,
                "topology_seed": r["topology_seed"],
                "topology_hash": r["topology_hash"],
                "evaluation_episode_seed": r["evaluation_seed"],
                "success": success,
                "steps_to_success": r["steps_to_goal"] if success else None,
                "episode_length": r["episode_length"],
                "environment_return": r["total_reward"],
                "failed_actions": r["failed_actions"],
                "terminal_outcome": r["terminal_reason"],
                "objective_reached": success,
            }
        )
    successful_steps = [r["steps_to_success"] for r in rows if r["success"]]
    summary = {
        **metadata,
        "episode_count": len(rows),
        "successful_episodes": len(successful_steps),
        "failed_episodes": len(rows) - len(successful_steps),
        "success_rate": len(successful_steps) / len(rows),
        "per_topology_success_rate": {
            str(t): mean(r["success"] for r in rows if r["topology_seed"] == t) for t in seeds
        },
        "mean_steps_to_success": mean(successful_steps) if successful_steps else None,
        "median_steps_to_success": median(successful_steps) if successful_steps else None,
        "mean_environment_return": mean(r["environment_return"] for r in rows),
        "mean_failed_actions": mean(r["failed_actions"] for r in rows),
        "mean_episode_length": mean(r["episode_length"] for r in rows),
        "validation_topology_seeds": list(seeds),
        "evaluation_episode_seeds": list(episode_seeds),
        "deterministic": protocol["evaluation"]["deterministic"],
        "gradient_updates": False,
        "final_test_evaluated": False,
    }
    # Persist only after the population and frozen-policy assertions succeed.
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    (output / "episodes.json").write_text(json.dumps(rows, indent=2, sort_keys=True))
    with (output / "episodes.csv").open("x", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    with (output / "trajectories.jsonl").open("x") as handle:
        for step in steps:
            step = dict(step)
            step["evaluation_episode_seed"] = step.pop("evaluation_seed")
            handle.write(json.dumps({**step, **metadata}, sort_keys=True) + "\n")
    (output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True))
    return summary
