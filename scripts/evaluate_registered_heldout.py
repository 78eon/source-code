#!/usr/bin/env python3
"""One-shot evaluator for the frozen registered generalisation campaign.

Use --verify-only to check inputs. Execution requires a separate approval JSON.
This module never trains, selects policies, or changes the registered protocol.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import yaml
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from registered_heldout_aggregation import aggregate_registered_results

ROOT = Path(__file__).resolve().parents[1]
CAMPAIGN = ROOT / "docs/research_evidence/MASTER_PROJECT_AUDIT/01_REGISTERED_CAMPAIGN/onprem-generalisation-registered"
PROTOCOL = ROOT / "configs/experiments/onprem_generalisation_registered_v1.yaml"
OUTPUT = Path.home() / ".local/state/security-rl-research/heldout/onprem-generalisation-registered-v1/one-pass-v1"
PROTOCOL_ID = "onprem-generalisation-registered-v1"
PROTOCOL_SHA = "f78fa879b20d4552893177a55f7750db09dc32a7b5678f3a6d9808422a4d96ac"
AGGREGATION_SHA256 = "5a578cf6553990fecc7247c57589ce68dedb83fa66bffdfbc99b31253a8ebf6c"
AGGREGATION_PATH = SCRIPT_DIR / "registered_heldout_aggregation.py"
SCIENTIFIC_COMMIT = "e4f39c08d350bf33d6b187068366aca539884786"
SCIENTIFIC_FILES = (
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
    "src/rlredteam/enterprise/registered_validation.py",
    "configs/onprem_topology.yaml",
    "tests/test_onprem_protocol.py",
    "tests/test_registered_validation.py",
    "tests/test_registration_readiness.py",
    "tests/test_onprem_generalisation.py",
    "tests/test_onprem_topology.py",
    "tests/test_enterprise_environment.py",
    "tests/test_nasim_adapter.py",
    "tests/test_reward.py",
    "tests/test_confirmatory_discovery.py",
    "tests/test_research_boundaries.py",
)


class Blocked(RuntimeError):
    pass


def file_sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_sha(value: object) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(data.encode()).hexdigest()


def canonical_protocol_sha(protocol: dict) -> str:
    body = {k: v for k, v in protocol.items() if k not in {"protocol_sha256", "registration_timestamp"}}
    return canonical_sha(body)


def verify_file_hash(path: Path, expected: str, label: str) -> str:
    actual = file_sha(Path(path))
    if actual != expected:
        raise Blocked(f"{label} hash mismatch")
    return actual


def verify_protocol_identity(protocol: dict, *, expected_id: str, expected_sha: str) -> None:
    if protocol.get("protocol_id") != expected_id or canonical_protocol_sha(protocol) != expected_sha:
        raise Blocked("scientific protocol canonical digest mismatch")


def expected_seeds(protocol: dict) -> tuple[int, ...]:
    seeds = protocol.get("splits", {}).get("test")
    exact = tuple(range(16001, 16021))
    if type(seeds) is not list or tuple(seeds) != exact:
        raise Blocked("registered held-out seed set mismatch")
    return exact


def validate_seed_request(requested: tuple[int, ...], registered: tuple[int, ...]) -> None:
    if tuple(requested) != tuple(registered):
        raise Blocked("partial or altered held-out seed range rejected")


def _marker_exists(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def reserve_output(path: Path) -> Path:
    path = Path(path)
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        raise Blocked("held-out output/partial-run marker already exists") from None
    return path


def verify_inputs(
    *, root: Path = ROOT,
    campaign: Path | None = None,
    protocol_path: Path | None = None,
    output: Path = OUTPUT,
    requested_seeds: tuple[int, ...] | None = None,
    source_check: bool = True,
    enforce_checkout: bool = True,
) -> dict:
    """Read-only input gate. requested_seeds injection is test-only plumbing."""
    root = Path(root)
    campaign = Path(campaign or root / "docs/research_evidence/MASTER_PROJECT_AUDIT/01_REGISTERED_CAMPAIGN/onprem-generalisation-registered")
    protocol_path = Path(protocol_path or root / "configs/experiments/onprem_generalisation_registered_v1.yaml")
    output = Path(output)
    manifest_path = campaign / "protocol_manifest.json"
    if not manifest_path.is_file() or not protocol_path.is_file():
        raise Blocked("registered manifest or protocol is missing")
    if not AGGREGATION_PATH.is_file() or file_sha(AGGREGATION_PATH) != AGGREGATION_SHA256:
        raise Blocked("registered aggregation implementation hash mismatch")
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("protocol_id") != PROTOCOL_ID or manifest.get("protocol_version") != 1 or manifest.get("registered") is not True:
        raise Blocked("governing campaign identity mismatch")
    if manifest.get("protocol_sha256") != PROTOCOL_SHA:
        raise Blocked("registered protocol digest mismatch")
    protocol = yaml.safe_load(protocol_path.read_text())
    if not isinstance(protocol, dict):
        raise Blocked("scientific configuration identity mismatch")
    verify_protocol_identity(protocol, expected_id=PROTOCOL_ID, expected_sha=PROTOCOL_SHA)
    seeds = expected_seeds(protocol)
    if requested_seeds is not None:
        validate_seed_request(tuple(requested_seeds), seeds)
    if manifest.get("canonical_protocol") != protocol:
        raise Blocked("protocol YAML differs from registered manifest")
    if manifest.get("source_commit") != SCIENTIFIC_COMMIT:
        raise Blocked("scientific source revision mismatch")
    if manifest.get("reward_definition_sha256") != "cc5ab301ec6c03da39fabdcbc68b0b47a800478617c90b429d168f6fceeaa000":
        raise Blocked("registered reward identity mismatch")
    if manifest.get("topology_config_sha256") != "98fa63b38c6412cb84b7f334050f5b3164cd94a82c58cdd900ba6c1c88256411":
        raise Blocked("registered topology identity mismatch")
    if manifest.get("canonical_protocol", {}).get("outcomes") != protocol.get("outcomes"):
        raise Blocked("registered metric contract missing")
    if manifest.get("canonical_protocol", {}).get("evaluation", {}).get("policy_updates") is not False:
        raise Blocked("registered no-update evaluation contract missing")
    checkpoints = {}
    for seed in range(42, 52):
        training_path = campaign / f"seed-{seed}/training_manifest.json"
        checkpoint_path = campaign / f"seed-{seed}/model.zip"
        if not training_path.is_file() or not checkpoint_path.is_file():
            raise Blocked(f"frozen policy/checkpoint missing for training seed {seed}")
        training = json.loads(training_path.read_text())
        expected = training.get("checkpoint_sha256")
        actual = verify_file_hash(checkpoint_path, training.get("checkpoint_sha256", ""), f"training seed {seed} checkpoint")
        if training.get("protocol_sha256") != PROTOCOL_SHA or training.get("training_seed") != seed:
            raise Blocked(f"training manifest identity mismatch for seed {seed}")
        if training.get("manifest_sha256") != canonical_sha({k: v for k, v in training.items() if k != "manifest_sha256"}):
            raise Blocked(f"training manifest self-hash mismatch for seed {seed}")
        if training.get("actual_timesteps") != 1000192 or training.get("final_test_evaluated") is not False:
            raise Blocked(f"checkpoint is not the registered terminal policy for seed {seed}")
        checkpoints[str(seed)] = {"path": str(checkpoint_path), "sha256": actual}
    if output != OUTPUT and output.resolve() != OUTPUT.resolve():
        raise Blocked("output path override is forbidden")
    if _marker_exists(output):
        raise Blocked("held-out output/partial-run marker already exists")
    for directory in (campaign, root / "results/onprem-generalisation", root / "runs/onprem-generalisation-registered"):
        if directory.is_dir() and any(
            "heldout" in p.name.lower() or "final_test" in p.name.lower()
            for p in directory.rglob("*")
        ):
            raise Blocked("prior held-out/final-test marker exists in registered result roots")
    # Existing parent must be private and operator-owned; do not create it at preflight.
    parent = output.parent
    if parent.exists():
        info = parent.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
            raise Blocked("held-out parent directory must be owner-only")
    registered = manifest.get("source_hashes", {})
    if source_check:
        if set(registered) != set(SCIENTIFIC_FILES):
            raise Blocked("frozen scientific source inventory differs")
        mismatches = []
        for rel in SCIENTIFIC_FILES:
            current = root / rel
            if not current.is_file() or file_sha(current) != registered[rel]:
                mismatches.append(rel)
        if mismatches:
            raise Blocked("active scientific source differs from frozen identity: " + ", ".join(mismatches))
        if enforce_checkout:
            head = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True)
            dirty = subprocess.run(["git", "-C", str(root), "status", "--porcelain", "--untracked-files=all"], capture_output=True, text=True)
            if head.returncode or head.stdout.strip() != SCIENTIFIC_COMMIT or dirty.returncode or dirty.stdout.strip():
                raise Blocked("source root must be a clean checkout of the registered scientific revision")
    return {
        "status": "INPUT_VERIFIED",
        "execution_authorized": False,
        "protocol_id": PROTOCOL_ID,
        "protocol_sha256": PROTOCOL_SHA,
        "protocol_file_sha256": file_sha(protocol_path),
        "manifest_file_sha256": file_sha(manifest_path),
        "launcher_sha256": file_sha(Path(__file__).resolve()),
        "aggregation_sha256": file_sha(AGGREGATION_PATH),
        "source_commit": SCIENTIFIC_COMMIT,
        "source_root": str(root.resolve()),
        "campaign_root": str(campaign.resolve()),
        "protocol_path": str(protocol_path.resolve()),
        "requested_topology_seeds": list(seeds),
        "evaluation_episode_seeds": manifest["canonical_protocol"]["evaluation"]["evaluation_episode_seeds"],
        "output_directory": str(OUTPUT),
        "checkpoints": checkpoints,
        "registered_source_hashes": registered if source_check else {},
        "frozen_input_hashes": {
            "protocol_sha256": PROTOCOL_SHA,
            "aggregation_sha256": file_sha(AGGREGATION_PATH),
            "protocol_file_sha256": file_sha(protocol_path),
            "manifest_file_sha256": file_sha(manifest_path),
            "reward_definition_sha256": manifest["reward_definition_sha256"],
            "topology_config_sha256": manifest["topology_config_sha256"],
            "scientific_source_hashes": registered,
            "checkpoint_hashes": {key: item["sha256"] for key, item in checkpoints.items()},
        },
    }


def authorize(report: dict, approval_path: Path) -> dict:
    approval_path = Path(approval_path)
    if approval_path.is_symlink() or not approval_path.is_absolute() or ".git" in approval_path.parts:
        raise Blocked("approval must be a private absolute file outside Git")
    info = approval_path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise Blocked("approval file must be owner-only")
    approval = json.loads(approval_path.read_text())
    required = {
        "execution_authorized": True,
        "protocol_sha256": report["protocol_sha256"],
        "launcher_sha256": report["launcher_sha256"],
        "approved_topology_seeds": report["requested_topology_seeds"],
    }
    if any(approval.get(k) != v for k, v in required.items()) or not approval.get("approved_by") or not approval.get("approval_timestamp"):
        raise Blocked("separate supervisor/operator approval is absent or does not bind these inputs")
    return approval


def run_once(report: dict, approval: dict, *, evaluator=None, model_loader=None, output: Path = OUTPUT) -> dict:
    """Execution entry point; production CLI never injects evaluator/model loader."""
    if approval.get("execution_authorized") is not True:
        raise Blocked("EXECUTION_AUTHORIZED = false")
    output = Path(output)
    if output != OUTPUT and (evaluator is None or model_loader is None):
        raise Blocked("output override is test-only")
    source_root = Path(report["source_root"])
    campaign_root = Path(report["campaign_root"])
    protocol_path = Path(report["protocol_path"])
    fresh = verify_inputs(
        root=source_root,
        campaign=campaign_root,
        protocol_path=protocol_path,
        requested_seeds=tuple(report["requested_topology_seeds"]),
    )
    if fresh != report:
        raise Blocked("inputs changed since INPUT_VERIFIED report")
    if not output.parent.exists():
        output.parent.mkdir(parents=True, mode=0o700)
    parent_info = output.parent.stat()
    if not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.getuid() or parent_info.st_mode & 0o077:
        raise Blocked("held-out parent directory must be owner-only")
    # Atomic exclusive reservation prevents concurrent and repeated runs.
    reserve_output(output)
    marker = output / "execution.json"
    marker.write_text(json.dumps({"status": "RUNNING", "execution_authorized": True, "input_report": report, "approval": approval}, sort_keys=True) + "\n")
    os.chmod(marker, 0o600)
    try:
        sys.path.insert(0, str(source_root / "src"))
        from sb3_contrib import MaskablePPO
        import torch
        from rlredteam.enterprise.generalisation import evaluate_policy, policy_digest

        evaluator = evaluator or evaluate_policy
        model_loader = model_loader or MaskablePPO.load
        protocol = yaml.safe_load(protocol_path.read_text())
        all_episodes, all_steps, checkpoint_results = [], [], {}
        for seed in range(42, 52):
            item = report["checkpoints"][str(seed)]
            if file_sha(Path(item["path"])) != item["sha256"]:
                raise Blocked(f"checkpoint changed after preflight for training seed {seed}")
            model = model_loader(item["path"], device="cpu")
            before = policy_digest(model)
            with torch.no_grad():
                episodes, steps = evaluator(model, topology_seeds=tuple(protocol["splits"]["test"]), evaluation_episode_seeds=(19001,), deterministic=True)
            after = policy_digest(model)
            if before != after or file_sha(Path(item["path"])) != item["sha256"]:
                raise Blocked(f"policy/checkpoint changed during evaluation for training seed {seed}")
            meta = {"protocol_sha256": PROTOCOL_SHA, "training_seed": seed, "checkpoint_sha256": item["sha256"], "policy_sha256_before": before, "policy_sha256_after": after, "deterministic": True, "gradient_updates": False}
            for episode in episodes:
                episode.update(meta)
            for step in steps:
                step.update(meta)
            all_episodes.extend(episodes)
            all_steps.extend(steps)
            checkpoint_results[str(seed)] = {**meta, "episode_count": len(episodes)}
        # Persist complete outputs only after all ten policies finish.
        if any((s["topology_seed"], s["evaluation_seed"]) not in {
            (episode["topology_seed"], episode["evaluation_seed"]) for episode in all_episodes
        } for s in all_steps):
            raise Blocked("trajectory outside evaluated population")
        metadata_rows = [
            {
                **episode,
                "phase": "heldout",
                "protocol_sha256": PROTOCOL_SHA,
                "deterministic": True,
                "gradient_updates": False,
            }
            for episode in all_episodes
        ]
        summary, rows = aggregate_registered_results(
            metadata_rows,
            training_seeds=tuple(protocol["training_seeds"]),
            topology_seeds=tuple(protocol["splits"]["test"]),
            evaluation_episode_seeds=tuple(protocol["evaluation"]["evaluation_episode_seeds"]),
            outcomes=protocol["outcomes"],
            phase="heldout",
            deterministic=protocol["evaluation"]["deterministic"],
        )
        summary["protocol_sha256"] = PROTOCOL_SHA
        summary["checkpoints"] = checkpoint_results
        (output / "episodes.json").write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n")
        with (output / "episodes.csv").open("x", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
        with (output / "trajectories.jsonl").open("x") as handle:
            for step in all_steps:handle.write(json.dumps(step, sort_keys=True) + "\n")
        (output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        hashes = {p.name: file_sha(p) for p in output.iterdir() if p.is_file() and p.name != "execution.json"}
        final = {"status": "COMPLETE", "execution_authorized": True, "input_report": report, "approval": approval, "output_sha256": hashes}
        marker.write_text(json.dumps(final, indent=2, sort_keys=True) + "\n")
        return final
    except BaseException as exc:
        marker.write_text(json.dumps({"status": "PARTIAL_OR_FAILED", "execution_authorized": True, "input_report": report, "error_type": type(exc).__name__}, sort_keys=True) + "\n")
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--approval", type=Path)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--campaign-root", type=Path, default=CAMPAIGN)
    parser.add_argument("--protocol-file", type=Path, default=PROTOCOL)
    args = parser.parse_args(argv)
    try:
        report = verify_inputs(
            root=args.source_root,
            campaign=args.campaign_root,
            protocol_path=args.protocol_file,
            requested_seeds=tuple(range(16001, 16021)),
        )
        report_path = ROOT / "docs/research_completion/HELDOUT_PREEXECUTION_REPORT.json"
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        if args.verify_only:
            print(json.dumps({"status": report["status"], "execution_authorized": False, "report": str(report_path)}, sort_keys=True))
            return 0
        if args.approval is None:
            raise Blocked("EXECUTION_AUTHORIZED = false; separate approval required")
        approval = authorize(report, args.approval)
        run_once(report, approval)
    except Exception as exc:
        failure_path = ROOT / "docs/research_completion/HELDOUT_PREEXECUTION_REPORT.json"
        details = {"status": "BLOCKED", "execution_authorized": False, "reason": str(exc), "output_directory": str(OUTPUT), "launcher_sha256": file_sha(Path(__file__).resolve())}
        try:
            inputs = verify_inputs(
                root=args.source_root,
                campaign=args.campaign_root,
                protocol_path=args.protocol_file,
                requested_seeds=tuple(range(16001, 16021)),
                source_check=False,
                enforce_checkout=False,
            )
            details["verified_artifact_hashes"] = {"protocol_file_sha256": inputs["protocol_file_sha256"], "manifest_file_sha256": inputs["manifest_file_sha256"], "checkpoints": inputs["checkpoints"], "frozen_input_hashes": inputs["frozen_input_hashes"]}
            details["scientific_source_check"] = "BLOCKED: active source tree differs from the frozen source hashes"
        except Exception as evidence_exc:
            details["artifact_verification_error"] = str(evidence_exc)
        failure_path.write_text(json.dumps(details, indent=2, sort_keys=True) + "\n")
        print(json.dumps({"status": "BLOCKED", "execution_authorized": False, "reason": str(exc)}, sort_keys=True))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
