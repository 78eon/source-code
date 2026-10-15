"""Operational gate tests use temporary synthetic evidence, never research runs."""

import copy
import csv
import hashlib
import json

import pytest

from rlredteam.enterprise import campaign_execution as c
from rlredteam.enterprise.onprem_protocol import CONFIG, ROOT, load_protocol


def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


def csv_dump(path, rows):
    with path.open("w") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


@pytest.fixture
def evidence(tmp_path):
    p = load_protocol(ROOT / CONFIG)
    out = tmp_path / c.NAMESPACE / "seed-42"
    (out / "validation").mkdir(parents=True)
    (out / "model.zip").write_bytes(b"SYNTHETIC TEST; NOT A POLICY")
    training = [
        {
            "training_seed": 42,
            "topology_seed": i % 60 + 1,
            "episode_length": 200 if i < 5000 else 192,
            "environment_return": 110.0 if i < 100 else 100.0,
            "completed": True,
        }
        for i in range(5001)
    ]
    diagnostics = [{"train/" + k: 0.1 for k in p["convergence"]["required_diagnostics"]}]
    csv_dump(out / "training_episodes.csv", training)
    csv_dump(out / "progress.csv", diagnostics)
    metadata = {
        "training_seed": 42,
        "protocol_sha256": c.PROTOCOL_SHA,
        "phase": "validation",
        "checkpoint_sha256": c.file_hash(out / "model.zip"),
        "policy_sha256_before": "SYNTHETIC",
        "policy_sha256_after": "SYNTHETIC",
    }
    rows = [
        {
            **metadata,
            "topology_seed": seed,
            "evaluation_episode_seed": 19001,
            "success": True,
            "episode_length": 1,
            "steps_to_success": 1,
            "environment_return": 100.0,
            "failed_actions": 0,
        }
        for seed in p["splits"]["validation"]
    ]
    summary = {
        **metadata,
        "episode_count": 20,
        "successful_episodes": 20,
        "failed_episodes": 0,
        "success_rate": 1.0,
        "mean_steps_to_success": 1,
        "median_steps_to_success": 1,
        "mean_environment_return": 100.0,
        "mean_failed_actions": 0,
        "deterministic": True,
        "gradient_updates": False,
        "final_test_evaluated": False,
    }
    dump(out / "validation/episodes.json", rows)
    csv_dump(out / "validation/episodes.csv", rows)
    dump(out / "validation/summary.json", summary)
    (out / "validation/trajectories.jsonl").write_text(
        "".join(json.dumps({**row, "step": 0, "reward": 100.0}) + "\n" for row in rows)
    )
    manifest = {
        "training_seed": 42,
        "protocol_sha256": c.PROTOCOL_SHA,
        "config_sha256": c.PROTOCOL_SHA,
        "source_commit": p["source_commit"],
        "source_hashes": p["source_hashes"],
        "reward_definition_sha256": c.digest(p["reward"]),
        "topology_config_sha256": p["source_provenance"]["topology_config_sha256"],
        "container_image_id": p["container_image_id"],
        "actual_timesteps": 1000192,
        "runtime_seconds": 1.0,
        "training_topology_coverage": list(range(1, 61)),
        "completed_episodes": 5001,
        "convergence": c.convergence_diagnostics(
            [r["environment_return"] for r in training], diagnostics
        ),
        "policy_sha256": "SYNTHETIC",
        "final_test_evaluated": False,
        "validation": summary,
    }
    for key, name in (
        ("checkpoint_sha256", "model.zip"),
        ("training_audit_sha256", "training_episodes.csv"),
        ("diagnostics_sha256", "progress.csv"),
    ):
        manifest[key] = c.file_hash(out / name)
    manifest["manifest_sha256"] = c.digest(manifest)
    dump(out / "training_manifest.json", manifest)
    return p, tmp_path, out


def test_convergence_failure_is_preserved_and_does_not_block_completion(evidence):
    p, root, _ = evidence
    result = c.verify_completed_seed(p, root, 42)
    assert result["registered_convergence"] is False
    assert result["failed_convergence_components"] == ["reward_rise"]
    assert result["validation_success_rate"] == 1.0


@pytest.mark.parametrize(
    "name",
    [
        "model.zip",
        "progress.csv",
        "training_episodes.csv",
        "training_manifest.json",
        "validation/summary.json",
        "validation/episodes.csv",
        "validation/trajectories.jsonl",
    ],
)
def test_corrupt_completed_evidence_rejected(evidence, name):
    p, root, output = evidence
    path = output / name
    path.write_bytes(path.read_bytes() + b"CORRUPTION")
    with pytest.raises((ValueError, KeyError)):
        c.verify_completed_seed(p, root, 42)


@pytest.mark.parametrize(
    "field,value",
    [
        ("training_seed", 43),
        ("actual_timesteps", 1000000),
        ("policy_sha256", "CHANGED"),
        ("final_test_evaluated", True),
    ],
)
def test_rehashed_manifest_cannot_mask_contract_violation(evidence, field, value):
    p, root, output = evidence
    manifest = c.read_json(output / "training_manifest.json")
    manifest[field] = value
    manifest.pop("manifest_sha256")
    manifest["manifest_sha256"] = c.digest(manifest)
    dump(output / "training_manifest.json", manifest)
    with pytest.raises(ValueError):
        c.verify_completed_seed(p, root, 42)


@pytest.fixture
def inventory(tmp_path, monkeypatch):
    for folder in ("configs", "data", "runs", "results"):
        (tmp_path / folder).mkdir()
    original = tmp_path / "results/original.bin"
    original.write_bytes(b"historical")
    protected = {"results/original.bin": c.file_hash(original)}
    encoded = "".join(f"{sha}  {name}\n" for name, sha in protected.items())
    monkeypatch.setattr(c, "HISTORICAL_SHA", hashlib.sha256(encoded.encode()).hexdigest())
    dump(tmp_path / c.CONFIG, {})
    dump(tmp_path / c.NAMESPACE / "protocol_manifest.json", {})
    (tmp_path / c.NAMESPACE / "seed-42/validation").mkdir(parents=True)
    (tmp_path / c.NAMESPACE / "seed-42/model.zip").write_bytes(b"immutable")
    auth = {
        "authorized_training_seeds": [43],
        "previous_completed_seeds": [42],
        "previous_authorization_files": {},
        "protected_historical_files": protected,
        "registered_input_files": {
            str(c.CONFIG): c.file_hash(tmp_path / c.CONFIG),
            str(c.NAMESPACE / "protocol_manifest.json"): c.file_hash(
                tmp_path / c.NAMESPACE / "protocol_manifest.json"
            ),
        },
        "completed_seed_files": c.hash_tree(tmp_path, c.NAMESPACE / "seed-42"),
    }
    # Synthetic inventory has no older study metadata; fix selection only.
    monkeypatch.setattr(c, "choose_test_seeds", lambda inventory: list(range(16001, 16021)))
    return tmp_path, auth


def test_inventory_preserves_original_set_and_allows_only_authorized_outputs(inventory):
    root, auth = inventory
    assert c.verify_inventory(root, auth)["protected_file_count"] == 1
    dump(root / c.authorization_path(43), {})
    dump(root / c.NAMESPACE / "seed-43/preflight.json", {})
    with pytest.raises(ValueError, match="unauthorized"):
        c.verify_inventory(root, auth)
    assert c.verify_inventory(root, auth, running=True)["final_test_fresh"]


@pytest.mark.parametrize(
    "path",
    [
        "runs/unrelated.bin",
        "results/extra.csv",
        "data/new.bin",
        "runs/onprem-generalisation-registered/seed-44/model.zip",
        "runs/onprem-generalisation-registered/seed-43/other.bin",
        "runs/onprem-generalisation-registered/seed-42/extra.bin",
    ],
)
def test_new_outputs_outside_allowlist_rejected(inventory, path):
    root, auth = inventory
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"new")
    with pytest.raises(ValueError):
        c.verify_inventory(root, auth, running=True)


def test_historical_hashes_cannot_be_rebaselined(inventory):
    root, auth = inventory
    (root / "results/original.bin").write_bytes(b"changed")
    auth["protected_historical_files"]["results/original.bin"] = c.file_hash(
        root / "results/original.bin"
    )
    with pytest.raises(ValueError, match="redefined"):
        c.verify_inventory(root, auth)


def test_heldout_seed_in_authorized_namespace_rejected(inventory):
    root, auth = inventory
    dump(root / c.NAMESPACE / "seed-43/preflight.json", {"topology_seed": 16001})
    with pytest.raises(ValueError, match="held-out"):
        c.verify_inventory(root, auth, running=True)


def test_symlink_and_empty_other_seed_directory_rejected(inventory):
    root, auth = inventory
    (root / "runs/link").symlink_to(root / "results/original.bin")
    with pytest.raises(ValueError, match="symlink"):
        c.verify_inventory(root, auth)
    (root / "runs/link").unlink()
    (root / c.NAMESPACE / "seed-44").mkdir()
    with pytest.raises(ValueError, match="directory"):
        c.verify_inventory(root, auth)


@pytest.mark.parametrize("path", ["../outside", "/absolute"])
def test_inventory_path_escape_rejected(tmp_path, path):
    with pytest.raises(ValueError, match="unsafe"):
        c.checked_path(tmp_path, path)


def test_frozen_protocol_and_sources_match_registration():
    # Uses tracked inputs only, so this test also works in a clean checkout.
    p = load_protocol(ROOT / CONFIG)
    assert c.protocol_digest(p) == c.PROTOCOL_SHA
    assert {name: c.file_hash(ROOT / name) for name in p["source_hashes"]} == p["source_hashes"]
    assert p["authorized_start_seeds"] == [42]
    assert p["convergence"]["decision_role"].endswith("never early stopping or seed exclusion")


@pytest.mark.parametrize(
    "section", ["ppo", "reward", "convergence", "splits", "evaluation", "outcomes"]
)
def test_scientific_mutation_rejected(section):
    p = copy.deepcopy(load_protocol(ROOT / CONFIG))
    p[section]["post_hoc_change"] = True
    with pytest.raises(ValueError, match="protocol changed"):
        c.verify_registration(p, ROOT)


@pytest.fixture
def authorization():
    p = load_protocol(ROOT / CONFIG)
    auth = dict.fromkeys(c.AUTH_FIELDS, None)
    auth.update(
        {
            "schema": "CampaignExecutionAuthorization/v1",
            "protocol_sha": c.PROTOCOL_SHA,
            "immutable_registered_protocol_sha": c.PROTOCOL_SHA,
            "authorized_training_seeds": [44],
            "previous_completed_seeds": [42, 43],
            "output_namespace": str(c.NAMESPACE / "seed-44"),
            "authorization_timestamp": "2026-10-15T00:00:00+00:00",
            "final_test_authorized": False,
            "automatic_next_seed": False,
        }
    )
    reseal(auth)
    return p, auth


def reseal(auth):
    auth.pop("authorization_sha256", None)
    auth["authorization_sha256"] = c.digest(auth)
    return auth["authorization_sha256"]


def test_single_authorization_permits_only_requested_registered_seed(authorization):
    p, auth = authorization
    c.check_authorization(auth, auth["authorization_sha256"], 44, p)
    for seed in (42, 43, 45, 46, 47, 48, 49, 50, 51, 52, True):
        with pytest.raises(ValueError):
            c.check_authorization(auth, auth["authorization_sha256"], seed, p)


@pytest.mark.parametrize(
    "field",
    [
        "ppo",
        "reward",
        "splits",
        "total_timesteps",
        "evaluation",
        "convergence",
        "final_test_range",
        "learning_rate",
        "outcomes",
    ],
)
def test_authorization_cannot_override_science(authorization, field):
    p, auth = authorization
    auth[field] = {"override": True}
    with pytest.raises(ValueError, match="unsupported"):
        c.check_authorization(auth, reseal(auth), 44, p)


@pytest.mark.parametrize(
    "field,value",
    [
        ("authorized_training_seeds", [44, 45]),
        ("protocol_sha", "wrong"),
        ("immutable_registered_protocol_sha", "wrong"),
        ("previous_completed_seeds", [42]),
        ("output_namespace", "runs/onprem-generalisation-registered/seed-42"),
        ("final_test_authorized", True),
        ("automatic_next_seed", True),
    ],
)
def test_resealed_invalid_authorization_rejected(authorization, field, value):
    p, auth = authorization
    auth[field] = value
    with pytest.raises(ValueError):
        c.check_authorization(auth, reseal(auth), 44, p)


def test_authorization_pin_and_modified_record_rejected(authorization):
    p, auth = authorization
    with pytest.raises(ValueError, match="pin mismatch"):
        c.check_authorization(auth, "wrong", 44, p)
    pin = auth["authorization_sha256"]
    auth["reason"] = "changed"
    with pytest.raises(ValueError, match="invalid authorization_sha256"):
        c.check_authorization(auth, pin, 44, p)


def test_missing_authorization_has_no_output(tmp_path):
    dump(tmp_path / CONFIG, load_protocol(ROOT / CONFIG))
    with pytest.raises(FileNotFoundError):
        c.verify_campaign(tmp_path, "no-pin", 44)
    assert not (tmp_path / c.NAMESPACE).exists()


@pytest.fixture
def verifier(tmp_path, monkeypatch, authorization):
    p, auth = authorization
    auth.update(
        {
            "source_commit": "toolcommit",
            "campaign_tooling_commit": "toolcommit",
            "scientific_source_commit": p["source_commit"],
            "operational_source_hashes": {"test": "hash"},
            "registered_input_files": {
                str(CONFIG): "hash",
                str(c.NAMESPACE / "protocol_manifest.json"): "hash",
            },
            "previous_results": [{"training_seed": 42}, {"training_seed": 43}],
        }
    )
    reseal(auth)
    dump(tmp_path / CONFIG, p)
    dump(tmp_path / c.authorization_path(44), auth)
    provenance = {"git_commit": "toolcommit"}
    monkeypatch.setattr(
        c,
        "verify_registration",
        lambda *a: (
            {"topology_config_sha256": "topo", "reward_definition_sha256": "reward"},
            provenance,
        ),
    )
    monkeypatch.setattr(c, "source_provenance", lambda *a: provenance)
    monkeypatch.setattr(c, "operational_sources", lambda *a: {"test": "hash"})
    monkeypatch.setattr(c, "verify_inventory", lambda *a, **kw: {})
    monkeypatch.setattr(c, "verify_lineage", lambda *a: None)
    monkeypatch.setattr(c, "verify_completion", lambda *a: None)
    monkeypatch.setattr(c, "verify_completed_seed", lambda p, r, seed: {"training_seed": seed})
    monkeypatch.setattr(c, "implementation_checks", lambda *a: {"passed": True})
    return tmp_path, auth


def test_full_gate_allows44_but_missing45_fails(verifier):
    root, auth = verifier
    report = c.verify_campaign(root, auth["authorization_sha256"], 44)
    assert report["allowed_to_train"]
    assert report["authorized_training_seeds"] == [44]
    with pytest.raises(FileNotFoundError):
        c.verify_campaign(root, auth["authorization_sha256"], 45)


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_commit", "wrong"),
        ("campaign_tooling_commit", "wrong"),
        ("operational_source_hashes", {"test": "wrong"}),
        ("scientific_source_commit", "wrong"),
    ],
)
def test_wrong_source_and_tool_hash_fail(verifier, field, value):
    root, auth = verifier
    auth[field] = value
    reseal(auth)
    dump(root / c.authorization_path(44), auth)
    with pytest.raises(ValueError):
        c.verify_campaign(root, auth["authorization_sha256"], 44)


def test_existing_seed_namespace_denied_by_gate(verifier):
    root, auth = verifier
    (root / c.NAMESPACE / "seed-44").mkdir()
    with pytest.raises(ValueError, match="reserved"):
        c.verify_campaign(root, auth["authorization_sha256"], 44)


def test_lineage_preserves_exact_old_tooling():
    lineage = c.read_json(ROOT / c.LINEAGE)
    assert lineage["seed43_authorization_sha256"] == c.SEED43_AUTH_SHA
    assert lineage["seed43_authorization_file_sha256"] == c.SEED43_AUTH_FILE_SHA
    expected = {
        "scripts/registered_campaign.py": (
            "20ea0a840c99fe3006438f7d9c6889ba802e23de3f39a0271d8af5cdc629aa25"
        ),
        "src/rlredteam/enterprise/campaign_execution.py": (
            "fba86cc2eb942f2e77ba31a365063c8a823ed8424d6e42da078c1b28e0838061"
        ),
        "tests/test_campaign_execution.py": (
            "d78082f4001fcb6c5ecbea19b8a3e4f94ec27232724e75ce6fd4a8201e63d130"
        ),
    }
    assert set(lineage["seed43_operational_files"]) == set(expected)
    for name, item in lineage["seed43_operational_files"].items():
        assert (
            hashlib.sha256(item["content"].encode()).hexdigest() == item["sha256"] == expected[name]
        )


def test_train_gate_failure_has_no_side_effects(tmp_path, monkeypatch):
    monkeypatch.setattr(
        c, "verify_campaign", lambda *args: {"allowed_to_train": False, "blockers": ["blocked"]}
    )
    with pytest.raises(ValueError, match="blocked"):
        c.train_authorized_seed(tmp_path, "synthetic", 44)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("seed", [42, 43, 44])
def test_namespace_reservation_prevents_duplicate_run(tmp_path, monkeypatch, seed):
    p = load_protocol(ROOT / CONFIG)
    dump(tmp_path / CONFIG, p)
    output = tmp_path / c.NAMESPACE / f"seed-{seed}"
    output.mkdir(parents=True)
    sentinel = output / "model.zip"
    sentinel.write_bytes(b"do not overwrite")
    monkeypatch.setattr(
        c, "verify_campaign", lambda *args: {"allowed_to_train": True, "blockers": []}
    )
    monkeypatch.setenv("RLREDTEAM_IMAGE_DIGEST", p["container_image_id"])
    with pytest.raises(FileExistsError):
        c.train_authorized_seed(tmp_path, "synthetic", seed)
    assert sentinel.read_bytes() == b"do not overwrite"


def test_seed44_runner_uses_exact_registered_parameters(tmp_path, monkeypatch):
    import numpy as np
    import sb3_contrib
    import torch

    p = load_protocol(ROOT / CONFIG)
    dump(tmp_path / CONFIG, p)
    (tmp_path / c.NAMESPACE).mkdir(parents=True)
    report = {
        "allowed_to_train": True,
        "blockers": [],
        "previous_results": [],
        "operational_source_hashes": {},
        "provenance": {
            "source_hashes": p["source_hashes"],
            "dependency_definition_sha256": "test",
            "git_commit": "synthetic",
        },
        "topology_config_sha256": "synthetic",
        "reward_definition_sha256": c.digest(p["reward"]),
    }
    monkeypatch.setattr(c, "verify_campaign", lambda *args, **kwargs: report)
    monkeypatch.setenv("RLREDTEAM_IMAGE_DIGEST", p["container_image_id"])
    calls = []

    class Learner:
        def __init__(self, policy, env, **kwargs):
            expected = dict(p["ppo"])
            layers = expected.pop("policy_layers")
            assert kwargs == dict(
                expected, seed=44, device="cpu", verbose=1, policy_kwargs={"net_arch": layers}
            )
            assert env.topology_seeds == tuple(p["splits"]["train"])
            assert env.training_seed == 44
            self.env, self.policy = env, torch.nn.Linear(1, 1)

        def set_logger(self, logger):
            self.logger = logger

        def learn(self, *, total_timesteps):
            assert total_timesteps == 1000192
            self.num_timesteps = total_timesteps
            self.env.reset(seed=44)
            self.env.step(int(np.flatnonzero(self.env.action_masks())[0]))
            for key in p["convergence"]["required_diagnostics"]:
                self.logger.record("train/" + key, 0.1)
            self.logger.record("train/learning_rate", p["ppo"]["learning_rate"])
            calls.append("train")

        def save(self, path):
            path.write_bytes(b"SYNTHETIC UNIT TEST ONLY")

    def validation(model, protocol, **kwargs):
        assert protocol == p and kwargs["training_seed"] == 44
        assert kwargs["checkpoint"] == tmp_path / c.NAMESPACE / "seed-44/model.zip"
        kwargs["output"].mkdir()
        calls.append("validation")
        return {"synthetic": True}

    def completion(protocol, root, seed):
        assert seed == 44 and (root / c.NAMESPACE / "seed-44/training_manifest.json").is_file()
        calls.append("completion")
        return {"registered_convergence": False}

    monkeypatch.setattr(sb3_contrib, "MaskablePPO", Learner)
    monkeypatch.setattr(c, "validate_registered_checkpoint", validation)
    monkeypatch.setattr(c, "verify_completed_seed", completion)
    result = c.train_authorized_seed(tmp_path, "synthetic", 44)
    assert calls == ["train", "validation", "completion"]
    assert result["result"]["registered_convergence"] is False
    assert result["next_seed_authorized"] is False
    assert not (tmp_path / c.NAMESPACE / "seed-45").exists()
