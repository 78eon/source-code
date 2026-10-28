"""Operational single-seed gate; the registered scientific sources remain unchanged.

Authorization is pinned by its canonical digest supplied to the CLI. Historical
files, registered inputs and completed runs are exact hash sets. Only this
authorization and its one new seed namespace may be added to research storage.
"""

from __future__ import annotations

import csv
import hashlib
import importlib.metadata
import json
import math
import os
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from statistics import mean, median

from .onprem_protocol import (
    CONFIG,
    IMPLEMENTATION_TESTS,
    artifact_inventory,
    choose_test_seeds,
    digest,
    file_hash,
    load_protocol,
    protocol_digest,
    source_provenance,
    validate_design,
)
from .onprem_protocol import ROOT as ROOT
from .registered_onprem import AuditedTrainingEnv, convergence_diagnostics
from .registered_validation import validate_registered_checkpoint

PROTOCOL_SHA = "f78fa879b20d4552893177a55f7750db09dc32a7b5678f3a6d9808422a4d96ac"
HISTORICAL_SHA = "511dd93907706767e02b191d01b88f63ca59a7ad352c714dd603a4b2e647bc8d"
REGISTRATION_SHA = "9e85caaca4e4c6f4d6782fe2b80ca7725c3f9fb240143319bfefade5f06c0877"
SEED42_MANIFEST_SHA = "1e907dd872f2aaa39b4bef4ea25752cda9e421d3d755a23c033c51e9d1934556"
NAMESPACE = Path("runs/onprem-generalisation-registered")
LINEAGE = "scripts/campaign_tooling_lineage.json"
SEED43_AUTH_SHA = "696343648da0e17a18d80cf814faa4c363cf670930aa5649e42e7b9209647fba"
SEED43_AUTH_FILE_SHA = "4666a24ea0de9d1ca142afffed7c2db10fb8b31dbcf1f4c54f54e6753001ded7"
AUTH_FIELDS = frozenset(
    """
schema protocol_sha immutable_registered_protocol_sha authorized_training_seeds
authorization_timestamp source_commit campaign_tooling_commit scientific_source_commit
operational_source_hashes reason previous_completed_seeds previous_results
final_test_authorized automatic_next_seed protected_historical_files registered_input_files
completed_seed_files previous_authorization_files output_namespace authorization_sha256
""".split()
)


def authorization_path(seed):
    require(type(seed) is int, "seed must be an integer")
    return NAMESPACE / f"authorizations/seed-{seed}.json"


SUPPLEMENT_PATHS = (
    LINEAGE,
    "src/rlredteam/enterprise/campaign_execution.py",
    "scripts/registered_campaign.py",
    "tests/test_campaign_execution.py",
)
OUTPUT_FILES = {
    "preflight.json",
    "execution_provenance.json",
    "failure.json",
    "model.zip",
    "progress.csv",
    "training_episodes.csv",
    "training_manifest.json",
    "completion.json",
    "campaign_status.json",
    "validation/episodes.json",
    "validation/episodes.csv",
    "validation/summary.json",
    "validation/trajectories.jsonl",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def now():
    return datetime.now(UTC).isoformat()


def read_json(path):
    return json.loads(Path(path).read_text())


def write_new_json(path, value):
    with Path(path).open("x") as handle:
        json.dump(value, handle, sort_keys=True, indent=2, allow_nan=False)
        handle.flush()
        os.fsync(handle.fileno())


def canonical_manifest(value, field="manifest_sha256"):
    require(
        value.get(field) == digest({k: v for k, v in value.items() if k != field}),
        f"invalid {field}",
    )


def checked_path(root, name):
    relative = PurePosixPath(name)
    require(not relative.is_absolute() and ".." not in relative.parts, "unsafe inventory path")
    path = Path(root) / relative
    require(not any(p.is_symlink() for p in (path, *path.parents)), "symlink in evidence path")
    return path


def hash_tree(root, relative):
    directory = checked_path(root, str(relative))
    return {
        str(p.relative_to(root)): file_hash(checked_path(root, str(p.relative_to(root))))
        for p in sorted(directory.rglob("*"))
        if p.is_file() or p.is_symlink()
    }


def historical_files(index):
    require(file_hash(index) == HISTORICAL_SHA, "historical inventory identity changed")
    entries = {}
    for line in Path(index).read_text().splitlines():
        sha, name = line.split("  ", 1)
        require(name not in entries and len(sha) == 64, "invalid historical inventory")
        entries[name] = sha
    return entries


def verify_hashes(root, entries):
    for name, expected in entries.items():
        require(file_hash(checked_path(root, name)) == expected, f"protected file changed: {name}")


def git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root, text=True).strip()


def operational_sources(root):
    require(not git(root, "status", "--porcelain"), "source tree must be clean and committed")
    hashes = {p: file_hash(checked_path(root, p)) for p in SUPPLEMENT_PATHS}
    for name, expected in hashes.items():
        blob = subprocess.check_output(["git", "show", f"HEAD:{name}"], cwd=root)
        require(hashlib.sha256(blob).hexdigest() == expected, "tooling commit mismatch")
    return hashes


def verify_lineage(root):
    """Preserve the exact pre-commit tooling used by the completed seed 43."""
    snapshot = read_json(checked_path(root, LINEAGE))
    require(
        snapshot["seed43_authorization_sha256"] == SEED43_AUTH_SHA
        and snapshot["seed43_authorization_file_sha256"] == SEED43_AUTH_FILE_SHA,
        "seed 43 lineage identity changed",
    )
    path = checked_path(root, str(authorization_path(43)))
    require(file_hash(path) == SEED43_AUTH_FILE_SHA, "seed 43 authorization changed")
    original = read_json(path)
    canonical_manifest(original, "authorization_sha256")
    require(original["authorization_sha256"] == SEED43_AUTH_SHA, "seed 43 pin mismatch")
    require(
        original["source_commit"] == snapshot["seed43_source_commit"], "lineage source mismatch"
    )
    archived = snapshot["seed43_operational_files"]
    require(set(archived) == set(original["operational_source_hashes"]), "lineage file set changed")
    for name, item in archived.items():
        require(
            hashlib.sha256(item["content"].encode()).hexdigest()
            == item["sha256"]
            == original["operational_source_hashes"][name],
            "seed 43 tooling bytes changed",
        )
    verify_hashes(root, original["completed_seed_files"])
    require(
        hash_tree(root, NAMESPACE / "seed-42") == original["completed_seed_files"],
        "seed 42 file set changed",
    )
    completion = read_json(root / NAMESPACE / "seed-43/completion.json")
    require(
        file_hash(root / NAMESPACE / "seed-43/completion.json")
        == "c35489e023bd610685610d7b8119df0190d894de92738d75773345605036c704",
        "seed 43 completion changed",
    )
    verify_hashes(root, completion["output_hashes"])
    return snapshot


def check_authorization(authorization, pin, seed, protocol):
    canonical_manifest(authorization, "authorization_sha256")
    require(authorization["authorization_sha256"] == pin, "authorization pin mismatch")
    require(set(authorization) == AUTH_FIELDS, "unsupported authorization fields")
    require(
        authorization["schema"] == "CampaignExecutionAuthorization/v1"
        and authorization["protocol_sha"]
        == authorization["immutable_registered_protocol_sha"]
        == PROTOCOL_SHA
        == protocol_digest(protocol),
        "authorization protocol mismatch",
    )
    population = protocol["training_seeds"]
    require(type(seed) is int and seed in population, "seed outside registered population")
    require(
        authorization["authorized_training_seeds"] == [seed]
        and type(authorization["authorized_training_seeds"][0]) is int,
        "authorization must permit exactly the requested seed",
    )
    require(
        authorization["previous_completed_seeds"] == population[: population.index(seed)],
        "completed seed prefix mismatch",
    )
    require(seed not in authorization["previous_completed_seeds"], "completed seed cannot rerun")
    require(
        authorization["output_namespace"] == str(NAMESPACE / f"seed-{seed}"),
        "output namespace mismatch",
    )
    require(
        authorization["final_test_authorized"] is authorization["automatic_next_seed"] is False,
        "final test and automatic next seed are locked",
    )
    require(
        datetime.fromisoformat(authorization["authorization_timestamp"]).tzinfo is not None,
        "authorization timestamp must include timezone",
    )


def verify_registration(protocol, root):
    require(
        protocol_digest(protocol) == PROTOCOL_SHA == protocol["protocol_sha256"],
        "registered protocol changed",
    )
    validate_design(protocol)
    path = checked_path(root, str(NAMESPACE / "protocol_manifest.json"))
    require(file_hash(path) == REGISTRATION_SHA, "registration manifest changed")
    registration = read_json(path)
    canonical_manifest(registration)
    require(registration["canonical_protocol"] == protocol, "scientific-setting mismatch")
    require(
        all(
            importlib.metadata.version(name) == version
            for name, version in registration["package_versions"].items()
        ),
        "registered package versions changed",
    )
    require(protocol["registered"] is True, "registration missing")
    provenance = source_provenance(root)
    require(provenance["source_hashes"] == protocol["source_hashes"], "frozen source changed")
    subprocess.run(
        ["git", "merge-base", "--is-ancestor", protocol["source_commit"], "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    for name, expected in protocol["source_hashes"].items():
        blob = subprocess.check_output(
            ["git", "show", f"{protocol['source_commit']}:{name}"], cwd=root
        )
        require(hashlib.sha256(blob).hexdigest() == expected, "implementation commit mismatch")
    require(
        protocol["convergence"]["decision_role"]
        == "descriptive per-seed post-training diagnosis; never early stopping or seed exclusion",
        "unsupported stopping rule",
    )
    return registration, provenance


def verify_inventory(root, authorization, *, running=False):
    """Enumerate every research file; additions outside the exact allowlist fail."""
    seed = authorization["authorized_training_seeds"][0]
    previous_seeds = authorization["previous_completed_seeds"]
    protected = authorization["protected_historical_files"]
    encoded = "".join(f"{sha}  {name}\n" for name, sha in sorted(protected.items()))
    require(
        hashlib.sha256(encoded.encode()).hexdigest() == HISTORICAL_SHA,
        "historical inventory was redefined",
    )
    verify_hashes(root, protected)
    verify_hashes(root, authorization["registered_input_files"])
    verify_hashes(root, authorization["completed_seed_files"])
    require(
        {
            name: sha
            for prior in previous_seeds
            for name, sha in hash_tree(root, NAMESPACE / f"seed-{prior}").items()
        }
        == authorization["completed_seed_files"],
        "completed seed file set changed",
    )
    allowed = set(protected) | set(authorization["registered_input_files"])
    prior_auth = authorization["previous_authorization_files"]
    require(
        set(prior_auth)
        == {str(authorization_path(prior)) for prior in previous_seeds if prior != 42},
        "previous authorization set mismatch",
    )
    verify_hashes(root, prior_auth)
    allowed |= (
        set(authorization["completed_seed_files"])
        | set(prior_auth)
        | {str(authorization_path(seed))}
    )
    if running:
        allowed |= {str(NAMESPACE / f"seed-{seed}" / name) for name in OUTPUT_FILES}
    for directory in ("configs", "data", "runs", "results"):
        for path in (Path(root) / directory).rglob("*"):
            name = str(path.relative_to(root))
            checked_path(root, name)
            if path.is_file():
                require(name in allowed, f"unauthorized research output: {name}")
    campaign = Path(root) / NAMESPACE
    allowed_dirs = {"authorizations"} | {
        name for prior in previous_seeds for name in (f"seed-{prior}", f"seed-{prior}/validation")
    }
    if running:
        allowed_dirs |= {f"seed-{seed}", f"seed-{seed}/validation"}
    for path in campaign.rglob("*"):
        if path.is_dir():
            require(
                str(path.relative_to(campaign)) in allowed_dirs,
                f"unauthorized campaign directory: {path}",
            )
    require(
        not (Path(root) / "results/onprem-generalisation-registered/test").exists(),
        "final-test output exists",
    )
    inventory = artifact_inventory(root)  # Metadata only; no topology generation.
    require(
        not set(range(16001, 16021)) & set(inventory["used_topology_seeds"]),
        "held-out topology seeds present in evidence",
    )
    require(choose_test_seeds(inventory) == list(range(16001, 16021)), "freshness changed")
    return {
        "historical_inventory_sha256": HISTORICAL_SHA,
        "protected_file_count": len(protected),
        "final_test_fresh": True,
        "current_inventory_sha256": inventory["inventory_sha256"],
    }


def verify_completed_seed(protocol, root, seed):
    """Reconstruct descriptive checks from stored data; never execute a policy."""
    output = Path(root) / NAMESPACE / f"seed-{seed}"
    require(not (output / "failure.json").exists(), "technical failure present")
    manifest = read_json(output / "training_manifest.json")
    canonical_manifest(manifest)
    require(
        manifest["training_seed"] == seed and manifest["protocol_sha256"] == PROTOCOL_SHA,
        "completed run identity mismatch",
    )
    require(manifest["actual_timesteps"] == protocol["total_timesteps"], "budget mismatch")
    for key, name in (
        ("checkpoint_sha256", "model.zip"),
        ("training_audit_sha256", "training_episodes.csv"),
        ("diagnostics_sha256", "progress.csv"),
    ):
        require(manifest[key] == file_hash(output / name), f"run hash mismatch: {name}")
    require(
        manifest["source_commit"] == protocol["source_commit"]
        and manifest["source_hashes"] == protocol["source_hashes"],
        "run source mismatch",
    )
    require(
        manifest["config_sha256"] == PROTOCOL_SHA
        and manifest["reward_definition_sha256"] == digest(protocol["reward"])
        and manifest["topology_config_sha256"]
        == protocol["source_provenance"]["topology_config_sha256"]
        and manifest["container_image_id"] == protocol["container_image_id"],
        "run configuration mismatch",
    )
    with (output / "training_episodes.csv").open() as handle:
        episodes = list(csv.DictReader(handle))
    with (output / "progress.csv").open() as handle:
        diagnostics = list(csv.DictReader(handle))
    require(
        episodes and all(int(r["training_seed"]) == seed for r in episodes), "audit seed mismatch"
    )
    require(
        sum(int(r["episode_length"]) for r in episodes) == protocol["total_timesteps"],
        "audit timestep mismatch",
    )
    coverage = sorted({int(r["topology_seed"]) for r in episodes})
    require(
        coverage == manifest["training_topology_coverage"]
        and set(coverage) <= set(protocol["splits"]["train"]),
        "training coverage mismatch",
    )
    completed = [float(r["environment_return"]) for r in episodes if r["completed"] == "True"]
    require(len(completed) == manifest["completed_episodes"], "episode count mismatch")
    convergence = convergence_diagnostics(completed, diagnostics)
    require(convergence == manifest["convergence"], "convergence evidence mismatch")
    require(convergence.get("diagnostics_finite") is True, "nonfinite/missing training evidence")
    failed = [
        name
        for key, name in (
            ("rise", "reward_rise"),
            ("stable", "stability"),
            ("diagnostics_finite", "diagnostics_finite"),
        )
        if not convergence.get(key)
    ]
    if convergence.get("late_collapse"):
        failed.append("late_collapse")
    diagnostic_summary = {}
    for key in protocol["convergence"]["required_diagnostics"]:
        values = [
            float(row["train/" + key])
            for row in diagnostics
            if row.get("train/" + key) not in (None, "")
        ]
        diagnostic_summary[key] = {
            "mean": mean(values),
            "min": min(values),
            "max": max(values),
            "last": values[-1],
        }
    summary = read_json(output / "validation/summary.json")
    require(summary == manifest["validation"], "validation summary mismatch")
    require(
        summary["policy_sha256_before"]
        == summary["policy_sha256_after"]
        == manifest["policy_sha256"],
        "policy changed during validation",
    )
    require(
        summary["gradient_updates"] is False
        and summary["deterministic"] is True
        and summary["final_test_evaluated"] is manifest["final_test_evaluated"] is False,
        "validation execution contract mismatch",
    )
    rows = read_json(output / "validation/episodes.json")
    expected = {
        (t, e)
        for t in protocol["splits"]["validation"]
        for e in protocol["evaluation"]["evaluation_episode_seeds"]
    }
    require(
        len(rows) == summary["episode_count"] == len(expected)
        and {(r["topology_seed"], r["evaluation_episode_seed"]) for r in rows} == expected,
        "validation population mismatch",
    )
    metadata = {
        "training_seed": seed,
        "protocol_sha256": PROTOCOL_SHA,
        "phase": "validation",
        "checkpoint_sha256": manifest["checkpoint_sha256"],
        "policy_sha256_before": manifest["policy_sha256"],
        "policy_sha256_after": manifest["policy_sha256"],
    }
    for row in rows:
        require(all(row[k] == v for k, v in metadata.items()), "validation provenance mismatch")
        require(
            type(row["success"]) is bool
            and (
                row["steps_to_success"] == row["episode_length"]
                if row["success"]
                else row["steps_to_success"] is None
            ),
            "invalid success-only steps",
        )
        require(
            all(
                math.isfinite(row[k])
                for k in ("environment_return", "failed_actions", "episode_length")
            ),
            "nonfinite validation value",
        )
    with (output / "validation/episodes.csv").open() as handle:
        csv_rows = list(csv.DictReader(handle))
    require(
        csv_rows == [{k: "" if v is None else str(v) for k, v in row.items()} for row in rows],
        "validation CSV/JSON mismatch",
    )
    successes = [r["steps_to_success"] for r in rows if r["success"]]
    calculated = {
        "success_rate": len(successes) / len(rows),
        "successful_episodes": len(successes),
        "failed_episodes": len(rows) - len(successes),
        "mean_steps_to_success": mean(successes) if successes else None,
        "median_steps_to_success": median(successes) if successes else None,
        "mean_environment_return": mean(r["environment_return"] for r in rows),
        "mean_failed_actions": mean(r["failed_actions"] for r in rows),
    }
    require(all(summary[k] == v for k, v in calculated.items()), "validation metrics mismatch")
    traces = {pair: [] for pair in expected}
    with (output / "validation/trajectories.jsonl").open() as handle:
        for line in handle:
            step = json.loads(line)
            pair = step["topology_seed"], step["evaluation_episode_seed"]
            require(
                pair in expected and all(step[k] == v for k, v in metadata.items()),
                "trajectory population/provenance mismatch",
            )
            traces[pair].append(step)
    for row in rows:
        trace = traces[row["topology_seed"], row["evaluation_episode_seed"]]
        require([s["step"] for s in trace] == list(range(row["episode_length"])), "trajectory gaps")
        require(
            math.isclose(sum(s["reward"] for s in trace), row["environment_return"], abs_tol=1e-8),
            "trajectory return mismatch",
        )
        require(
            sum(not s["success"] for s in trace) == row["failed_actions"], "failed-action mismatch"
        )
    return {
        "training_seed": seed,
        "registered_convergence": convergence["passed"],
        "failed_convergence_components": failed,
        "validation_success_rate": summary["success_rate"],
        "actual_timesteps": manifest["actual_timesteps"],
        "runtime_seconds": manifest["runtime_seconds"],
        "topology_coverage": coverage,
        "validation": summary,
        "convergence": convergence,
        "checkpoint_sha256": manifest["checkpoint_sha256"],
        "training_manifest_sha256": manifest["manifest_sha256"],
        "training_manifest_file_sha256": file_hash(output / "training_manifest.json"),
        "policy_immutable": True,
        "diagnostics_finite": True,
        "diagnostics": diagnostic_summary,
    }


def prepare_authorization(root, index, seed):
    """Prepare one permission record; caller installs it exclusively and pins its digest."""
    root = Path(root)
    protocol = load_protocol(root / CONFIG)
    verify_registration(protocol, root)
    supplement = operational_sources(root)
    verify_lineage(root)
    require(type(seed) is int and seed in protocol["training_seeds"], "unregistered seed")
    require(not (root / NAMESPACE / f"seed-{seed}").exists(), "seed namespace already reserved")
    require(not (root / authorization_path(seed)).exists(), "authorization already exists")
    previous_seeds = protocol["training_seeds"][: protocol["training_seeds"].index(seed)]
    previous = [verify_completed_seed(protocol, root, prior) for prior in previous_seeds]
    for prior in previous_seeds:
        if prior >= 43:
            verify_completion(root, prior)
    commit = git(root, "rev-parse", "HEAD")
    authorization = {
        "schema": "CampaignExecutionAuthorization/v1",
        "protocol_sha": PROTOCOL_SHA,
        "immutable_registered_protocol_sha": PROTOCOL_SHA,
        "authorized_training_seeds": [seed],
        "authorization_timestamp": now(),
        "source_commit": commit,
        "campaign_tooling_commit": commit,
        "scientific_source_commit": protocol["source_commit"],
        "operational_source_hashes": supplement,
        "reason": f"Explicit user authorization for seed {seed} only; convergence is descriptive",
        "previous_completed_seeds": previous_seeds,
        "previous_results": previous,
        "final_test_authorized": False,
        "automatic_next_seed": False,
        "output_namespace": str(NAMESPACE / f"seed-{seed}"),
        "protected_historical_files": historical_files(index),
        "registered_input_files": {
            str(CONFIG): file_hash(root / CONFIG),
            str(NAMESPACE / "protocol_manifest.json"): REGISTRATION_SHA,
        },
        "completed_seed_files": {
            name: sha
            for prior in previous_seeds
            for name, sha in hash_tree(root, NAMESPACE / f"seed-{prior}").items()
        },
        "previous_authorization_files": {
            str(authorization_path(prior)): file_hash(root / authorization_path(prior))
            for prior in previous_seeds
            if prior != 42
        },
    }
    authorization["authorization_sha256"] = digest(authorization)
    check_authorization(authorization, authorization["authorization_sha256"], seed, protocol)
    verify_inventory(root, authorization)
    return authorization


def verify_completion(root, seed):
    output = Path(root) / NAMESPACE / f"seed-{seed}"
    completion = read_json(output / "completion.json")
    canonical_manifest(completion)
    require(
        completion["technical_verification_passed"] is True
        and completion["next_seed_authorized"] is False,
        "completion contract mismatch",
    )
    actual = hash_tree(root, NAMESPACE / f"seed-{seed}")
    actual.pop(str(NAMESPACE / f"seed-{seed}/completion.json"))
    require(actual == completion["output_hashes"], "completed output set/hash changed")
    result = verify_completed_seed(load_protocol(Path(root) / CONFIG), root, seed)
    require(result == completion["result"], "completion result changed")
    return completion


def learning_rate_summary(output):
    with (output / "progress.csv").open() as handle:
        values = [
            float(r["train/learning_rate"])
            for r in csv.DictReader(handle)
            if r.get("train/learning_rate") not in (None, "")
        ]
    require(values and all(math.isfinite(v) for v in values), "missing/nonfinite learning rate")
    return {"mean": mean(values), "min": min(values), "max": max(values), "last": values[-1]}


def implementation_checks(root):
    # The one split reconstruction test generates final-test topologies; omit it
    # here and actively forbid that generation in every other executed test.
    code = """import socket,sys,pytest
from rlredteam.enterprise import onprem
original=onprem.generate_onprem_topology
def guarded(seed,*args,**kwargs):
    if seed in range(16001,16021): raise AssertionError('Final-test topology locked')
    return original(seed,*args,**kwargs)
onprem.generate_onprem_topology=guarded
def denied(*args,**kwargs): raise AssertionError('Network forbidden')
for name in ('connect','connect_ex','bind','listen'): setattr(socket.socket,name,denied)
socket.create_connection=denied
socket.getaddrinfo=denied
sys.exit(pytest.main(sys.argv[1:]))
"""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            code,
            *IMPLEMENTATION_TESTS,
            SUPPLEMENT_PATHS[-1],
            "-q",
            "-p",
            "no:cacheprovider",
            "-k",
            "not test_hash_only_split_reconstruction_is_disjoint_and_deterministic",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=420,
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1", OMP_NUM_THREADS="1", MKL_NUM_THREADS="1"),
    )
    return {
        "passed": result.returncode == 0,
        "exit_code": result.returncode,
        "output": result.stdout + result.stderr,
        "final_test_generation_guard": True,
        "excluded": "test_hash_only_split_reconstruction_is_disjoint_and_deterministic",
    }


def verify_campaign(root, authorization_sha, seed, *, run_checks=True, running=False):
    root = Path(root)
    protocol = load_protocol(root / CONFIG)
    authorization = read_json(checked_path(root, str(authorization_path(seed))))
    check_authorization(authorization, authorization_sha, seed, protocol)
    registration, provenance = verify_registration(protocol, root)
    require(
        provenance["git_commit"]
        == authorization["source_commit"]
        == authorization["campaign_tooling_commit"],
        "source checkout changed",
    )
    require(
        operational_sources(root) == authorization["operational_source_hashes"],
        "operational source changed",
    )
    require(
        authorization["scientific_source_commit"] == protocol["source_commit"],
        "source identity mismatch",
    )
    require(
        set(authorization["registered_input_files"])
        == {str(CONFIG), str(NAMESPACE / "protocol_manifest.json")},
        "registered input set mismatch",
    )
    verify_lineage(root)
    inventory = verify_inventory(root, authorization, running=running)
    previous = [
        verify_completed_seed(protocol, root, prior)
        for prior in authorization["previous_completed_seeds"]
    ]
    for prior in authorization["previous_completed_seeds"]:
        if prior >= 43:
            verify_completion(root, prior)
    require(authorization["previous_results"] == previous, "completed seed result changed")
    if not running:
        require(not (root / NAMESPACE / f"seed-{seed}").exists(), "seed namespace already reserved")
    checks = (
        implementation_checks(root)
        if run_checks
        else {"passed": False, "not_run": "read-only integrity check"}
    )
    # Repeat protection after tests; no time-of-check checkout or evidence drift.
    require(source_provenance(root) == provenance, "source changed during checks")
    require(
        operational_sources(root) == authorization["operational_source_hashes"],
        "supplement changed during checks",
    )
    require(
        read_json(root / authorization_path(seed)) == authorization,
        "authorization changed during checks",
    )
    verify_inventory(root, authorization, running=running)
    return {
        "allowed_to_train": checks["passed"] and not running,
        "blockers": [] if checks["passed"] else ["implementation checks not passed"],
        "implementation_checks": checks,
        "authorization_sha256": authorization_sha,
        "protocol_sha256": PROTOCOL_SHA,
        "scientific_settings_unchanged": True,
        "completed_seeds_immutable": authorization["previous_completed_seeds"],
        "final_test_locked": True,
        "authorized_training_seeds": [seed],
        "provenance": provenance,
        "operational_source_hashes": authorization["operational_source_hashes"],
        "topology_config_sha256": registration["topology_config_sha256"],
        "reward_definition_sha256": registration["reward_definition_sha256"],
        "inventory": inventory,
        "previous_results": previous,
    }


def train_authorized_seed(root, authorization_sha, seed):
    """One sequential run. No budget override, retry, resume, seed loop or final test."""
    from sb3_contrib import MaskablePPO
    from stable_baselines3.common.logger import configure

    from rlredteam.train import set_all_seeds

    from .generalisation import policy_digest
    from .onprem import OnPremTopologyConfig

    root = Path(root)
    wall_started, started_at = time.monotonic(), now()
    report = verify_campaign(root, authorization_sha, seed)
    require(report["allowed_to_train"], "; ".join(report["blockers"]))
    protocol = load_protocol(root / CONFIG)
    require(
        os.environ.get("RLREDTEAM_IMAGE_DIGEST") == protocol["container_image_id"],
        "container image mismatch",
    )
    output = root / NAMESPACE / f"seed-{seed}"
    output.mkdir(exist_ok=False)  # Atomic reservation; concurrent/repeated starts fail.
    try:
        write_new_json(output / "preflight.json", report)
        set_all_seeds(seed)
        env = AuditedTrainingEnv(
            tuple(protocol["splits"]["train"]),
            config=OnPremTopologyConfig(**protocol["topology"]),
            training_seed=seed,
            audit_path=output / "training_episodes.csv",
        )
        started = time.monotonic()
        try:
            params = dict(protocol["ppo"])
            layers = params.pop("policy_layers")
            model = MaskablePPO(
                "MlpPolicy",
                env,
                seed=seed,
                device="cpu",
                verbose=1,
                policy_kwargs={"net_arch": layers},
                **params,
            )
            model.set_logger(configure(str(output), ["stdout", "csv"]))
            model.learn(total_timesteps=protocol["total_timesteps"])
            model.logger.dump(step=model.num_timesteps)
            require(
                model.num_timesteps == protocol["total_timesteps"], "registered budget mismatch"
            )
            model.save(output / "model.zip")
            manifest = {
                "protocol_sha256": PROTOCOL_SHA,
                "source_commit": protocol["source_commit"],
                "source_hashes": report["provenance"]["source_hashes"],
                "config_sha256": PROTOCOL_SHA,
                "topology_config_sha256": report["topology_config_sha256"],
                "reward_definition_sha256": report["reward_definition_sha256"],
                "dependency_definition_sha256": report["provenance"][
                    "dependency_definition_sha256"
                ],
                "container_image_id": protocol["container_image_id"],
                "training_seed": seed,
                "actual_timesteps": model.num_timesteps,
                "runtime_seconds": time.monotonic() - started,
                "policy_sha256": policy_digest(model),
                "checkpoint_sha256": file_hash(output / "model.zip"),
                "final_test_evaluated": False,
                "authorization_sha256": authorization_sha,
                "operational_source_hashes": report["operational_source_hashes"],
            }
        finally:
            env.close()
        manifest["validation"] = validate_registered_checkpoint(
            model,
            protocol,
            training_seed=seed,
            checkpoint=output / "model.zip",
            output=output / "validation",
        )
        with (output / "training_episodes.csv").open() as handle:
            episodes = list(csv.DictReader(handle))
        with (output / "progress.csv").open() as handle:
            diagnostics = list(csv.DictReader(handle))
        manifest["completed_episodes"] = sum(row["completed"] == "True" for row in episodes)
        manifest["training_topology_coverage"] = sorted(
            {int(row["topology_seed"]) for row in episodes}
        )
        manifest["convergence"] = convergence_diagnostics(
            [float(row["environment_return"]) for row in episodes if row["completed"] == "True"],
            diagnostics,
        )
        manifest["training_audit_sha256"] = file_hash(output / "training_episodes.csv")
        manifest["diagnostics_sha256"] = file_hash(output / "progress.csv")
        manifest["manifest_sha256"] = digest(manifest)
        write_new_json(output / "training_manifest.json", manifest)
        result = verify_completed_seed(protocol, root, seed)
        verify_campaign(root, authorization_sha, seed, run_checks=False, running=True)
        execution = {
            "status": "completed",
            "run_start_timestamp": started_at,
            "run_finish_timestamp": now(),
            "wall_seconds": time.monotonic() - wall_started,
            "source_commit": report["provenance"]["git_commit"],
            "operational_source_hashes": report["operational_source_hashes"],
            "authorization_sha256": authorization_sha,
            "protocol_sha256": PROTOCOL_SHA,
        }
        write_new_json(output / "execution_provenance.json", execution)
        write_new_json(
            output / "campaign_status.json",
            {
                "schema": "DescriptiveCampaignStatus/v1",
                "completed_seeds": [r["training_seed"] for r in report["previous_results"]]
                + [seed],
                "results": report["previous_results"] + [result],
                "learning_rate": learning_rate_summary(output),
                "final_test_evaluated": False,
                "next_seed_authorized": False,
            },
        )
        completion = {
            "result": result,
            "execution": execution,
            "output_hashes": hash_tree(root, NAMESPACE / f"seed-{seed}"),
            "technical_verification_passed": True,
            "next_seed_authorized": False,
        }
        completion["manifest_sha256"] = digest(completion)
        write_new_json(output / "completion.json", completion)
        for path in output.rglob("*"):
            if path.is_file():
                path.chmod(0o444)
        (output / "validation").chmod(0o555)
        output.chmod(0o555)
        return completion
    except BaseException as exc:
        write_new_json(
            output / "failure.json",
            {
                "training_seed": seed,
                "timestamp": now(),
                "error_type": type(exc).__name__,
                "error": str(exc),
            },
        )
        raise
