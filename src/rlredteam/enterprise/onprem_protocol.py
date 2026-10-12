"""Fail-closed, local-only registration checks for the on-prem distribution study."""

from __future__ import annotations

import csv
import hashlib
import json
import subprocess
from dataclasses import asdict
from pathlib import Path

import yaml

from .onprem import OnPremTopologyConfig, generate_onprem_topology, topology_digest

ROOT = Path(__file__).resolve().parents[3]
CONFIG = Path("configs/experiments/onprem_generalisation_registered_v1.yaml")
SEMANTIC_DIGESTS = {
    "reward": "cc5ab301ec6c03da39fabdcbc68b0b47a800478617c90b429d168f6fceeaa000",
    "convergence": "49b12397913aeba3397619d8dd7d743d8a59e86608a8feaa49c416c0506f87fe",
    "ppo": "cd75e529e033a476a1a20e49dc387760dca601db06151c5cfedb1f12077ef815",
}
SOURCE_PATHS = (
    "src/rlredteam/enterprise/onprem.py",
    "src/rlredteam/enterprise/environment.py",
    "src/rlredteam/enterprise/model.py",
    "src/rlredteam/enterprise/state.py",
    "src/rlredteam/enterprise/generalisation.py",
    "src/rlredteam/enterprise/onprem_protocol.py",
    "src/rlredteam/catalogues.py",
    "src/rlredteam/train.py",
    "src/rlredteam/provenance.py",
    "configs/catalogues/simulated_world.yaml",
    "configs/catalogues/mitre.yaml",
    "pyproject.toml",
    "scripts/verify_onprem_protocol.py",
    "src/rlredteam/enterprise/registered_onprem.py",
    "scripts/train_registered_onprem.py",
)


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def file_hash(path):
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def protocol_digest(protocol):
    return digest(
        {
            k: v
            for k, v in protocol.items()
            if k not in {"registration_timestamp", "protocol_sha256"}
        }
    )


def load_protocol(path):
    value = yaml.safe_load(Path(path).read_text())
    if not isinstance(value, dict):
        raise ValueError("protocol mapping required")
    return value


def artifact_inventory(root):
    """Conservative inventory: even declared topology seeds count as previously used.

    No evaluation is executed. Missing/unreadable/malformed evidence blocks freshness.
    Binary checkpoints are not deserialized. Claims are limited to local visible evidence.
    """
    root = Path(root)
    files, used = [], set()

    def collect(value, found):
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "topology_seed" and type(item) is int:
                    found.add(item)
                elif key.endswith("topology_seeds") and isinstance(item, list):
                    found.update(x for x in item if type(x) is int)
                if key in {"distribution", "base_distribution"} and isinstance(item, dict):
                    for group in item.values():
                        if isinstance(group, dict):
                            found.update(int(x) for x in group if str(x).isdigit())
                collect(item, found)
        elif isinstance(value, list):
            for item in value:
                collect(item, found)

    for directory in (root / "runs", root / "results"):
        if not directory.is_dir():
            raise ValueError(f"missing evidence directory: {directory}")
        for path in sorted(directory.rglob("*")):
            if not path.is_file() or path.suffix not in {
                ".json",
                ".jsonl",
                ".csv",
                ".yaml",
                ".yml",
            }:
                continue
            if path == root / "runs/onprem-generalisation-registered/protocol_manifest.json":
                continue  # Registration metadata is not a prior evaluation.
            found = set()
            try:
                with path.open() as handle:
                    if path.suffix == ".csv":
                        for row in csv.DictReader(handle):
                            if row.get("topology_seed") not in (None, ""):
                                found.add(int(row["topology_seed"]))
                    elif path.suffix == ".jsonl":
                        for line in handle:
                            if line.strip():
                                collect(json.loads(line), found)
                    elif path.suffix == ".json":
                        collect(json.load(handle), found)
                    else:
                        collect(yaml.safe_load(handle), found)
            except (OSError, ValueError, yaml.YAMLError) as exc:
                raise ValueError(f"cannot audit {path.relative_to(root)}: {exc}") from exc
            files.append(
                {
                    "path": str(path.relative_to(root)),
                    "sha256": file_hash(path),
                    "topology_seeds": sorted(found),
                }
            )
            used.update(found)
    return {
        "scope": "local runs/ and results/ JSON, JSONL, CSV, YAML; declared seeds also excluded",
        "used_topology_seeds": sorted(used),
        "files": files,
        "inventory_sha256": digest(files),
    }


def choose_test_seeds(inventory):
    used = set(inventory["used_topology_seeds"])
    for start in range(2001, 100002, 1000):
        candidate = list(range(start, start + 20))
        if not used.intersection(candidate):
            return candidate
    raise ValueError("no fresh candidate block found")


def split_manifest(protocol):
    """Reconstruct/hash only; never evaluate the held-out policy or inspect outcomes."""
    config = OnPremTopologyConfig(**protocol["topology"])
    groups, seen_seeds, seen_hashes = {}, set(), set()
    for name in ("train", "validation", "test"):
        seeds = protocol["splits"][name]
        if not seeds or any(type(s) is not int or s < 0 for s in seeds):
            raise ValueError("invalid topology seed list")
        if len(set(seeds)) != len(seeds) or seen_seeds.intersection(seeds):
            raise ValueError("duplicate/overlapping topology seeds")
        seen_seeds.update(seeds)
        group = {}
        for seed in seeds:
            first = generate_onprem_topology(seed, config)
            second = generate_onprem_topology(seed, config)
            if topology_digest(first) != topology_digest(second):
                raise ValueError("non-deterministic topology reconstruction")
            structural = first.to_dict()
            structural.pop("name", None)  # Seed-bearing name must not hide identical graphs.
            structural_hash = digest(structural)
            if structural_hash in seen_hashes:
                raise ValueError("duplicate topology content across registered population")
            seen_hashes.add(structural_hash)
            group[str(seed)] = {
                "topology_hash": topology_digest(first),
                "structural_hash": structural_hash,
            }
        groups[name] = group
    return groups


def source_provenance(root):
    root = Path(root)

    def git(*args):
        return subprocess.run(
            ["git", *args], cwd=root, check=True, text=True, capture_output=True, timeout=15
        ).stdout.strip()

    # Do not trust RLREDTEAM_GIT_DIRTY environment overrides for registration.
    return {
        "git_commit": git("rev-parse", "HEAD"),
        "git_dirty": bool(git("status", "--porcelain", "--untracked-files=all")),
        "source_hashes": {p: file_hash(root / p) for p in SOURCE_PATHS},
        "dependency_definition_sha256": file_hash(root / "pyproject.toml"),
        "dependency_lock_sha256": None,
    }


def validate_design(protocol):
    for section, expected in SEMANTIC_DIGESTS.items():
        if digest(protocol[section]) != expected:
            raise ValueError(f"registered {section} contract digest mismatch")
    if (
        protocol["protocol_id"] != "onprem-generalisation-registered-v1"
        or protocol["protocol_version"] != 1
    ):
        raise ValueError("unknown registered protocol identity")
    if protocol["status"] not in {"draft", "registered"} or protocol["registered"] is not (
        protocol["status"] == "registered"
    ):
        raise ValueError("inconsistent registration status")
    if protocol["training_seeds"] != list(range(42, 52)):
        raise ValueError("PPO training seeds must be 42..51")
    if protocol["authorized_start_seeds"] != [42]:
        raise ValueError("only seed 42 is authorized in this task")
    if protocol["evaluation"]["final_test_authorized_now"] is not False:
        raise ValueError("final-test evaluation is not authorized")
    if (
        protocol["evaluation"]["evaluation_episode_seeds"] != [19001]
        or protocol["evaluation"]["deterministic"] is not True
    ):
        raise ValueError("registered evaluation schedule mismatch")
    if protocol["reward_implementation_sha256"] != file_hash(
        ROOT / "src/rlredteam/enterprise/environment.py"
    ):
        raise ValueError("reward implementation changed")
    if protocol["splits"]["train"] != list(range(1, 61)) or protocol["splits"][
        "validation"
    ] != list(range(1001, 1021)):
        raise ValueError("incorrect training/validation topology pool")
    test = protocol["splits"]["test"]
    if len(test) != 20 or test != list(range(test[0], test[0] + 20)):
        raise ValueError("twenty contiguous final topology seeds required")
    n_steps, n_envs = protocol["ppo"]["n_steps"], protocol["n_envs"]
    budget = protocol["total_timesteps"]
    if (n_steps, n_envs, budget) != (256, 1, 1000192) or budget % (n_steps * n_envs):
        raise ValueError("registered rollout budget mismatch")
    if n_steps % protocol["ppo"]["batch_size"]:
        raise ValueError("invalid PPO minibatch size")
    OnPremTopologyConfig(**protocol["topology"])
    if protocol["topology"] != asdict(OnPremTopologyConfig.from_yaml()):
        raise ValueError("generator configuration drift")
    if protocol["confirmatory_rerun"]["status"] != "parked" or any(
        protocol["confirmatory_rerun"][key]
        for key in ("full_ten_seed_rerun", "bounded_check_planned")
    ):
        raise ValueError("confirmatory rerun must remain parked")
    if protocol["safety"] != {
        "simulation_only": True,
        "live_collection": False,
        "digital_twin_input": False,
        "postgres_required": False,
    }:
        raise ValueError("invalid research boundary")
    if protocol.get("protocol_sha256") and protocol["protocol_sha256"] != protocol_digest(protocol):
        raise ValueError("protocol digest mismatch")


def verify_protocol(protocol, root=ROOT):
    """Read-only pre-flight. Draft/incomplete/dirty provenance always blocks training."""
    blockers = []
    validate_design(protocol)
    inventory = artifact_inventory(root)
    final_output = Path(root) / "results/onprem-generalisation-registered/test"
    if final_output.exists() and any(final_output.rglob("*")):
        blockers.append("final-test results already exist for this protocol")
    selected = set(protocol["splits"]["test"])
    if selected.intersection(inventory["used_topology_seeds"]):
        blockers.append("final topology seeds were already declared/evaluated locally")
    groups = split_manifest(protocol)
    provenance = source_provenance(root)
    if not protocol["registered"]:
        blockers.append("protocol is draft, not registered")
    if provenance["git_dirty"]:
        blockers.append("BLOCKED BEFORE REGISTERED RUN: source checkpoint commit required.")
    source_commit = protocol.get("source_commit")
    if not isinstance(source_commit, str) or len(source_commit) != 40:
        blockers.append("registered source commit missing")
    else:
        try:
            subprocess.run(
                ["git", "merge-base", "--is-ancestor", source_commit, "HEAD"],
                cwd=root,
                check=True,
                capture_output=True,
                timeout=15,
            )
            for path, expected in provenance["source_hashes"].items():
                blob = subprocess.run(
                    ["git", "show", f"{source_commit}:{path}"],
                    cwd=root,
                    check=True,
                    capture_output=True,
                    timeout=15,
                ).stdout
                if hashlib.sha256(blob).hexdigest() != expected:
                    raise ValueError("source differs from committed checkpoint")
        except (ValueError, subprocess.SubprocessError):
            blockers.append("registered source checkpoint does not contain exact runtime sources")
    if protocol.get("source_hashes") != provenance["source_hashes"]:
        blockers.append("registered source hashes missing or mismatched")
    if not protocol.get("registration_timestamp") or not protocol.get("protocol_sha256"):
        blockers.append("registration timestamp/hash missing")
    if protocol.get("implementation_ready") is not True:
        blockers.append("registered trainer logging/evaluation integration not yet verified")
    manifest_path = Path(root) / "runs/onprem-generalisation-registered/protocol_manifest.json"
    if not manifest_path.is_file():
        blockers.append("immutable registered manifest absent")
    else:
        manifest = json.loads(manifest_path.read_text())
        if (
            manifest.get("registered") is not True
            or manifest.get("protocol_sha256") != protocol_digest(protocol)
            or manifest.get("source_hashes") != provenance["source_hashes"]
            or manifest.get("split_sha256") != digest(groups)
            or manifest.get("reward_definition_sha256") != digest(protocol["reward"])
        ):
            blockers.append("immutable registration manifest mismatch")
    if protocol["freshness"]["inventory_sha256"] != inventory["inventory_sha256"]:
        blockers.append("local artifact inventory changed; freshness must be reviewed again")
    return {
        "allowed_to_train": not blockers,
        "blockers": blockers,
        "protocol_sha256": protocol_digest(protocol),
        "provenance": provenance,
        "split_sha256": digest(groups),
        "topologies": groups,
        "reward_definition_sha256": digest(protocol["reward"]),
        "topology_config_sha256": OnPremTopologyConfig(**protocol["topology"]).digest(),
        "freshness_inventory": inventory,
        "budget_arithmetic": (
            f"{protocol['total_timesteps']} % "
            f"({protocol['ppo']['n_steps']} * {protocol['n_envs']}) = 0"
        ),
    }
