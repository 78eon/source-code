#!/usr/bin/env python3
"""Read-only historical descriptive arithmetic; no models, environments or writes."""

import csv
import hashlib
import json
import math
from pathlib import Path
from statistics import mean, pstdev

ROOT = Path(__file__).resolve().parents[1]
CAMPAIGN = (
    ROOT
    / "docs/research_evidence/MASTER_PROJECT_AUDIT/01_REGISTERED_CAMPAIGN"
    / "onprem-generalisation-registered"
)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def diagnose(campaign=CAMPAIGN):
    output = []
    for seed in range(42, 52):
        folder = campaign / f"seed-{seed}"
        path = folder / "training_episodes.csv"
        manifest_path = folder / "training_manifest.json"
        manifest = json.loads(manifest_path.read_text())
        if (
            manifest["protocol_sha256"]
            != "f78fa879b20d4552893177a55f7750db09dc32a7b5678f3a6d9808422a4d96ac"
            or manifest["actual_timesteps"] != 1_000_192
            or manifest["training_seed"] != seed
            or manifest["final_test_evaluated"] is not False
        ):
            raise ValueError("unexpected registered manifest identity")
        if sha(path) != manifest["training_audit_sha256"]:
            raise ValueError(f"seed {seed}: training CSV hash mismatch")
        with path.open(newline="") as handle:
            all_rows = list(csv.DictReader(handle))
        if any(row["completed"] not in {"True", "False"} for row in all_rows):
            raise ValueError("unknown completed flag")
        rows = [row for row in all_rows if row["completed"] == "True"]
        if len(rows) < 600 or len(rows) != manifest["completed_episodes"]:
            raise ValueError("insufficient/mismatched completed episodes")
        if any(int(row["training_seed"]) != seed for row in rows):
            raise ValueError("wrong training seed")
        rewards = [float(row["environment_return"]) for row in rows]
        if not all(math.isfinite(value) for value in rewards):
            raise ValueError("non-finite historical reward")
        first, last = mean(rewards[:100]), mean(rewards[-300:])
        recorded = manifest["convergence"]
        for name, actual in (("first_100_mean", first), ("last_300_mean", last)):
            if not math.isclose(recorded[name], actual, rel_tol=1e-12, abs_tol=1e-10):
                raise ValueError(f"recorded {name} mismatch")
        rise, required = last - first, max(5, 0.10 * abs(first))
        if (rise >= required) != recorded["rise"]:
            raise ValueError("recorded rise classification mismatch")
        validation_path = folder / "validation/summary.json"
        validation = json.loads(validation_path.read_text())
        output.append(
            {
                "seed": seed,
                "first100_mean": first,
                "last300_mean": last,
                "observed_rise": rise,
                "required_rise": required,
                "passed": rise >= required,
                "first100_population_sd": pstdev(rewards[:100]),
                "last300_population_sd": pstdev(rewards[-300:]),
                "minimum": min(rewards),
                "maximum": max(rewards),
                "completed_episode_count": len(rows),
                "partial_episode_count": len(all_rows) - len(rows),
                "mean_steps": mean(float(row["episode_length"]) for row in rows),
                "first100_mean_steps": mean(float(row["episode_length"]) for row in rows[:100]),
                "last300_mean_steps": mean(float(row["episode_length"]) for row in rows[-300:]),
                "mean_failed_actions": mean(float(row["failed_actions"]) for row in rows),
                "training_objective_success_frequency": None,
                "historical_reward_component_totals": None,
                "validation_successes": validation["successful_episodes"],
                "validation_episodes": validation["episode_count"],
                "training_csv_sha256": sha(path),
                "manifest_sha256": sha(manifest_path),
                "validation_summary_sha256": sha(validation_path),
                "checkpoint_sha256": manifest["checkpoint_sha256"],
                "protocol_sha256": manifest["protocol_sha256"],
            }
        )
    return output


if __name__ == "__main__":
    print(json.dumps(diagnose(), indent=2, allow_nan=False))
