"""Read frozen registered metadata only; never load checkpoints or run evaluation."""

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class EvidenceModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", allow_inf_nan=False)


class RegisteredPolicy(EvidenceModel):
    training_seed: int
    status: Literal["AVAILABLE", "UNAVAILABLE"] = "AVAILABLE"
    detail: str | None = None
    checkpoint_sha256: str | None = None
    policy_sha256: str | None = None
    policy_id: str | None = None
    checkpoint_binding: str | None = None
    validation_topology_count: int | None = None
    successful_episodes: int | None = Field(default=None, ge=0)
    episode_count: int | None = Field(default=None, ge=0)
    success_rate: float | None = Field(default=None, ge=0, le=1)
    per_topology_success_rate: dict[str, float] | None = None
    mean_steps_to_success: float | None = None
    median_steps_to_success: float | None = None
    mean_environment_return: float | None = None
    mean_failed_actions: float | None = None
    mean_episode_length: float | None = None
    reward_rise: bool | None = None
    convergence_passed: bool | None = None
    final_test_evaluated: bool | None = None
    source_sha256: dict[str, str] = Field(default_factory=dict)


class RegisteredResults(EvidenceModel):
    schema_version: Literal["registered-results-v1"] = "registered-results-v1"
    status: Literal["AVAILABLE", "PARTIAL", "UNAVAILABLE"] = "UNAVAILABLE"
    read_only: Literal[True] = True
    aggregation: Literal["per_policy"] = "per_policy"
    protocol_id: str | None = None
    protocol_sha256: str | None = None
    algorithm: str | None = None
    environment_source: str | None = None
    detail: str | None = None
    source_sha256: dict[str, str] = Field(default_factory=dict)
    policies: list[RegisteredPolicy] = Field(default_factory=list)


METRICS = (
    "successful_episodes", "episode_count", "success_rate", "per_topology_success_rate",
    "mean_steps_to_success", "median_steps_to_success", "mean_environment_return",
    "mean_failed_actions", "mean_episode_length", "final_test_evaluated",
)


def _read(root, relative, hashes):
    path = root / relative
    # Bounded regular metadata files, no links or recursive evidence crawling.
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("symlink metadata")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 2 * 1024 * 1024:
            raise ValueError("invalid metadata size")
        content = stream.read(2 * 1024 * 1024 + 1)
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate metadata key")
            result[key] = value
        return result
    data = json.loads(content, object_pairs_hook=pairs)
    if not isinstance(data, dict):
        raise ValueError("invalid metadata object")
    hashes[relative] = hashlib.sha256(content).hexdigest()
    return data


def _sealed(data):
    content = {k: v for k, v in data.items() if k != "manifest_sha256"}
    actual = hashlib.sha256(json.dumps(
        content, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()).hexdigest()
    if actual != data.get("manifest_sha256"):
        raise ValueError("manifest identity mismatch")


def _digest(value):
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("invalid evidence identity")
    return value


class RegisteredResultsReader:
    def __init__(self, root=None):
        self.root = root

    def read(self):
        root = Path(self.root or os.environ.get("SECURITY_RL_REGISTERED_CAMPAIGN") or (
            Path(__file__).resolve().parents[3] / "docs/research_evidence/MASTER_PROJECT_AUDIT/"
            "01_REGISTERED_CAMPAIGN/onprem-generalisation-registered"
        ))
        hashes = {}
        try:
            manifest = _read(root, "protocol_manifest.json", hashes)
            _sealed(manifest)
            if manifest.get("registered") is not True:
                raise ValueError("not registered")
            protocol = _digest(manifest["protocol_sha256"])
            seeds = manifest["training_seeds"]
            if (not isinstance(seeds, list) or not seeds or len(seeds) > 100
                    or any(type(s) is not int or s < 0 for s in seeds)
                    or len(set(seeds)) != len(seeds)):
                raise ValueError("invalid registered seeds")
            result = RegisteredResults(
                protocol_id=manifest["protocol_id"], protocol_sha256=protocol, source_sha256=hashes
            )
            canonical = manifest.get("canonical_protocol", {})
            if not isinstance(canonical, dict):
                raise ValueError("invalid protocol algorithm metadata")
            if canonical.get("algorithm") == "MaskablePPO":
                result.algorithm = canonical["algorithm"]
            environment = "src/rlredteam/enterprise/environment.py"
            if environment in manifest.get("source_hashes", {}):
                result.environment_source = environment
        except (OSError, ValueError, KeyError, TypeError):
            return RegisteredResults(detail="Registered campaign metadata unavailable or invalid")
        for seed in seeds:
            sources = {}
            try:
                training = _read(root, f"seed-{seed}/training_manifest.json", sources)
                _sealed(training)
                summary = _read(root, f"seed-{seed}/validation/summary.json", sources)
                for record in (training, summary):
                    if (type(record.get("training_seed")) is not int
                            or record["training_seed"] != seed
                            or record.get("protocol_sha256") != protocol):
                        raise ValueError("policy provenance mismatch")
                checkpoint = _digest(training["checkpoint_sha256"])
                policy = _digest(training["policy_sha256"])
                if (summary.get("checkpoint_sha256") != checkpoint
                        or summary.get("policy_sha256_before") != policy
                        or summary.get("policy_sha256_after") != policy
                        or training.get("validation") != summary
                        or summary.get("phase") != "validation"
                        or training.get("final_test_evaluated") != summary.get("final_test_evaluated")):
                    raise ValueError("validation identity mismatch")
                row = RegisteredPolicy(
                    training_seed=seed, checkpoint_sha256=checkpoint, policy_sha256=policy,
                    policy_id="sha256:" + policy,
                    checkpoint_binding="Training and validation checkpoint/policy identities agree (metadata verified; checkpoint not loaded)",
                    validation_topology_count=len(summary["per_topology_success_rate"]) if isinstance(summary.get("per_topology_success_rate"), dict) else None,
                    reward_rise=training.get("convergence", {}).get("rise"),
                    convergence_passed=training.get("convergence", {}).get("passed"),
                    source_sha256=sources, **{key: summary.get(key) for key in METRICS},
                )
                if row.successful_episodes is not None and row.episode_count is not None:
                    if row.successful_episodes > row.episode_count:
                        raise ValueError("invalid validation count")
                    if row.success_rate is not None and (row.episode_count == 0 or abs(
                        row.success_rate - row.successful_episodes / row.episode_count
                    ) > 1e-9):
                        raise ValueError("validation rate mismatch")
                if row.per_topology_success_rate is not None and any(
                    not 0 <= rate <= 1 for rate in row.per_topology_success_rate.values()
                ):
                    raise ValueError("invalid topology rate")
                result.policies.append(row)
            except (OSError, ValueError, KeyError, TypeError, AttributeError):
                result.policies.append(RegisteredPolicy(
                    training_seed=seed, status="UNAVAILABLE",
                    detail="Policy metadata unavailable or inconsistent", source_sha256=sources,
                ))
        available = sum(row.status == "AVAILABLE" for row in result.policies)
        result.status = "AVAILABLE" if available == len(seeds) else "PARTIAL" if available else "UNAVAILABLE"
        result.detail = "Frozen metadata only; checkpoint contents are not loaded or reverified. No pooled statistics."
        return result
