"""Opt-in seed-42 runner; registration verification precedes every side effect."""

from __future__ import annotations

import csv
import json
import math
import os
import time
from pathlib import Path

import numpy as np

from .onprem import OnPremCurriculumEnv, OnPremTopologyConfig
from .onprem_protocol import ROOT, digest, file_hash, verify_protocol


class AuditedTrainingEnv(OnPremCurriculumEnv):
    """Episode RNG and topology audit stay outside the policy observation/mask."""

    def __init__(self, topology_seeds, *, config, training_seed, audit_path):
        self.training_seed = training_seed
        self.episode_rng = np.random.default_rng(training_seed)
        self.audit_path = Path(audit_path)
        self.episode_index = -1
        self.total_reward = 0.0
        self.episode_length = 0
        self.failed_actions = 0
        self._audit = self.audit_path.open("x", newline="")
        self._writer = csv.DictWriter(
            self._audit,
            fieldnames=[
                "training_seed",
                "training_episode_seed",
                "episode_index",
                "topology_seed",
                "topology_hash",
                "episode_length",
                "environment_return",
                "failed_actions",
                "completed",
            ],
        )
        self._writer.writeheader()
        super().__init__(topology_seeds, config=config)

    def reset(self, *, seed=None, options=None):
        if seed is not None:
            self.episode_rng = np.random.default_rng(seed)
        self.episode_seed = int(self.episode_rng.integers(0, 2**31 - 1))
        self.episode_index += 1
        self.total_reward, self.episode_length, self.failed_actions = 0.0, 0, 0
        observation, info = super().reset(seed=self.episode_seed, options=options)
        self.audit_topology_hash = info["topology_hash"]
        return observation, info

    def _record(self, completed):
        if not self.episode_length:
            return
        self._writer.writerow(
            {
                "training_seed": self.training_seed,
                "training_episode_seed": self.episode_seed,
                "episode_index": self.episode_index,
                "topology_seed": self.topology_seed,
                "topology_hash": self.audit_topology_hash,
                "episode_length": self.episode_length,
                "environment_return": self.total_reward,
                "failed_actions": self.failed_actions,
                "completed": completed,
            }
        )
        self._audit.flush()
        self.episode_length = 0

    def step(self, action):
        result = super().step(action)
        _, reward, terminated, truncated, info = result
        self.total_reward += float(reward)
        self.episode_length += 1
        self.failed_actions += int(not info["event"].success)
        if terminated or truncated:
            self._record(True)
        return result

    def close(self):
        if not self._audit.closed:
            self._record(False)
            self._audit.close()
        super().close()


def convergence_diagnostics(returns, diagnostic_rows):
    """Fixed-budget descriptive rule; no early stopping, tuning or seed exclusion."""
    required = (
        "approx_kl",
        "clip_fraction",
        "explained_variance",
        "entropy_loss",
        "policy_gradient_loss",
        "value_loss",
    )
    if len(returns) < 600 or not diagnostic_rows:
        return {"passed": False, "reason": "insufficient logged evidence"}
    values = np.asarray(returns, dtype=float)
    first, last = float(values[:100].mean()), float(values[-300:].mean())
    tail = [float(x.mean()) for x in np.array_split(values[-300:], 3)]
    blocks = [float(values[i : i + 100].mean()) for i in range(0, len(values) - 99, 100)]
    best = max(blocks)
    healthy = bool(np.isfinite(values).all())
    for key in required:
        present = [
            row.get("train/" + key)
            for row in diagnostic_rows
            if row.get("train/" + key) not in (None, "")
        ]
        healthy = healthy and bool(present) and all(math.isfinite(float(x)) for x in present)
        healthy = healthy and diagnostic_rows[-1].get("train/" + key) not in (None, "")
    rise = last - first >= max(5, 0.1 * abs(first))
    stable = max(tail) - min(tail) <= max(5, 0.1 * abs(last))
    collapse = tail[-1] < best - max(5, 0.2 * abs(best))
    return {
        "passed": bool(rise and stable and not collapse and healthy),
        "rise": rise,
        "stable": stable,
        "late_collapse": collapse,
        "diagnostics_finite": healthy,
        "first_100_mean": first,
        "last_300_mean": last,
        "last_three_100_means": tail,
    }


def train_registered_seed42(protocol, *, root=ROOT):
    # No allow-dirty override, budget override, seed loop or final-test evaluation.
    report = verify_protocol(protocol, root)
    if not report["allowed_to_train"]:
        raise ValueError("; ".join(report["blockers"]))
    image = os.environ.get("RLREDTEAM_IMAGE_DIGEST", "")
    if image != protocol.get("container_image_id"):
        raise ValueError("container image identity missing/mismatched")
    from sb3_contrib import MaskablePPO
    from stable_baselines3.common.logger import configure

    from rlredteam.train import set_all_seeds

    from .generalisation import policy_digest

    output = Path(root) / "runs/onprem-generalisation-registered/seed-42"
    output.mkdir(parents=True, exist_ok=False)
    (output / "preflight.json").write_text(json.dumps(report, indent=2, sort_keys=True))
    set_all_seeds(42)
    env = AuditedTrainingEnv(
        tuple(protocol["splits"]["train"]),
        config=OnPremTopologyConfig(**protocol["topology"]),
        training_seed=42,
        audit_path=output / "training_episodes.csv",
    )
    started = time.monotonic()
    try:
        params = dict(protocol["ppo"])
        layers = params.pop("policy_layers")
        model = MaskablePPO(
            "MlpPolicy",
            env,
            seed=42,
            device="cpu",
            verbose=1,
            policy_kwargs={"net_arch": layers},
            **params,
        )
        model.set_logger(configure(str(output), ["stdout", "csv"]))
        model.learn(total_timesteps=protocol["total_timesteps"])
        model.logger.dump(step=model.num_timesteps)  # Include final optimizer diagnostics.
        if model.num_timesteps != protocol["total_timesteps"]:
            raise ValueError("actual timestep budget differs from registered budget")
        model.save(output / "model.zip")
        manifest = {
            "protocol_sha256": report["protocol_sha256"],
            "source_commit": protocol["source_commit"],
            "source_hashes": report["provenance"]["source_hashes"],
            "config_sha256": report["protocol_sha256"],
            "topology_config_sha256": report["topology_config_sha256"],
            "reward_definition_sha256": report["reward_definition_sha256"],
            "dependency_definition_sha256": report["provenance"]["dependency_definition_sha256"],
            "container_image_id": image,
            "training_seed": 42,
            "actual_timesteps": model.num_timesteps,
            "runtime_seconds": time.monotonic() - started,
            "policy_sha256": policy_digest(model),
            "checkpoint_sha256": file_hash(output / "model.zip"),
            "final_test_evaluated": False,
        }
    finally:
        env.close()
    with (output / "training_episodes.csv").open() as handle:
        episodes = list(csv.DictReader(handle))
    with (output / "progress.csv").open() as handle:
        diagnostics = list(csv.DictReader(handle))
    manifest["completed_episodes"] = sum(row["completed"] == "True" for row in episodes)
    manifest["training_topology_coverage"] = sorted({int(row["topology_seed"]) for row in episodes})
    manifest["convergence"] = convergence_diagnostics(
        [float(row["environment_return"]) for row in episodes if row["completed"] == "True"],
        diagnostics,
    )
    manifest["training_audit_sha256"] = file_hash(output / "training_episodes.csv")
    manifest["diagnostics_sha256"] = file_hash(output / "progress.csv")
    manifest["manifest_sha256"] = digest(manifest)
    (output / "training_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    return manifest
