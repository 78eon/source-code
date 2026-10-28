"""Synthetic GUI evidence fixtures only; never train or change frozen output."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from rlredteam.application.data.baseline import PACKAGE, BaselineData, load_baseline


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))
    return digest(path)


def reseal(root):
    report = root / PACKAGE / "report"
    put(
        report / "reviewed_manifest.json",
        {
            "files": {
                p.name: digest(p) for p in report.iterdir() if p.name != "reviewed_manifest.json"
            }
        },
    )


@pytest.fixture
def evidence(tmp_path):
    package = tmp_path / PACKAGE
    report = package / "report"
    quality = put(
        report / "metric_quality_addendum.json",
        {
            "reward_impact": "Training reward eligibility was affected.",
            "caution": "Discovery counts are withheld.",
        },
    )
    original = put(report / "results.json", {"legacy_discovered_hosts": 99999})
    names = [
        "native_return",
        "native_return_std",
        "success_rate",
        "steps_to_goal",
        "mean_cvss_exploited",
    ]
    summary = {
        arm: {
            "success_rate": 0.5,
            "steps_to_goal": 23,
            "native_return": 17,
            "failed_actions": 8,
            "discovered_hosts": None,
            "attack_path_length": None,
        }
        for arm in ("sparse", "shaped")
    }
    put(
        report / "reviewed_results.json",
        {
            "policy_pairs": 2,
            "total_episodes": 12,
            "episodes_per_policy": 3,
            "summary": summary,
            "interpretation": "Recorded policy outcomes only.",
            "metric_quality_addendum_sha256": quality,
            "original_results_sha256": original,
            "primary_statistics": [
                {
                    "metric": name,
                    "mean_a": 17,
                    "mean_b": 18,
                    "difference": 1,
                    "p_value": 0.2,
                    "p_bonferroni": 1.0,
                    "ci_low": -2,
                    "ci_high": 4,
                    "n_pairs": 2,
                    "significant": False,
                }
                for name in names
            ],
        },
    )
    (report / "primary_statistics.csv").write_text("metric,p_value\nnative_return,0.2\n")
    reseal(tmp_path)
    candidate = tmp_path / "results/convergence_v2/example"
    registration_hash = put(
        candidate / "registration.json", {"inputs": {"config_sha256": "c" * 64}}
    )
    assessment_hash = put(candidate / "assessment.json", {"passing_seeds": 2})
    frozen_hash = put(
        tmp_path / "results/convergence_v2/first_stable.json",
        {
            "candidate": "example",
            "assessment_sha256": assessment_hash,
        },
    )
    checkpoints = {str(seed): {"status": "complete", "actual_timesteps": 2048} for seed in (7, 8)}
    protocol_hash = put(
        package / "protocol.json",
        {
            "training_seeds": [7, 8],
            "primary_metrics": names,
            "frozen_shaped_sha256": frozen_hash,
            "registration_sha256": registration_hash,
            "shaped_checkpoints": checkpoints,
            "git_commit": "example-commit",
            "literal_topology_yaml_sha256": "a" * 64,
            "reconstructed_topology_sha256": "b" * 64,
            "cve_catalogue_sha256": "d" * 64,
            "evaluation_episode_seeds": [81, 82, 83],
            "evaluation": {"action_selection": "stochastic", "policy_updates": False},
            "normalization": {"enabled": False},
            "ppo": {"normalize_advantage": True},
        },
    )
    put(
        package / "sparse_frozen.json",
        {
            "protocol_sha256": protocol_hash,
            "checkpoints": checkpoints,
            "native_training_stability": {
                str(seed): {"native_return_stability_passed": True} for seed in (7, 8)
            },
        },
    )
    return tmp_path


def test_loader_reads_reviewed_data_without_fixed_outcomes_or_mutations(evidence):
    before = {str(p): digest(p) for p in evidence.rglob("*") if p.is_file()}
    data = load_baseline(evidence)
    assert data.state == "REVIEWED", data.detail
    assert data.policy_pairs == 2 and data.total_episodes == 12
    assert data.summary["shaped"]["native_return"] == 17
    assert data.training[0][3] == "2/2"
    assert data.summary["shaped"]["discovered_hosts"] is None
    assert "99999" not in repr(data)
    assert {str(p): digest(p) for p in evidence.rglob("*") if p.is_file()} == before


@pytest.mark.parametrize(
    "relative",
    [
        "report/reviewed_results.json",
        "report/primary_statistics.csv",
        "protocol.json",
        "report/metric_quality_addendum.json",
    ],
)
def test_tamper_does_not_fallback_to_original(evidence, relative):
    (evidence / PACKAGE / relative).write_text("{}")
    data = load_baseline(evidence)
    assert data.state == "INVALID"
    assert not data.summary and not data.comparisons and not data.training


def test_missing_package_is_unavailable(tmp_path):
    assert load_baseline(tmp_path).state == "UNAVAILABLE"


def test_unbound_statistics_file_is_not_exported(evidence):
    path = evidence / PACKAGE / "report/reviewed_manifest.json"
    manifest = json.loads(path.read_text())
    del manifest["files"]["primary_statistics.csv"]
    put(path, manifest)
    assert load_baseline(evidence).state == "INVALID"


@pytest.mark.parametrize("mode", ["unwithheld", "nonfinite", "duplicate", "wrong_n"])
def test_invalid_semantics_even_with_matching_manifest(evidence, mode):
    path = evidence / PACKAGE / "report/reviewed_results.json"
    value = json.loads(path.read_text())
    if mode == "unwithheld":
        value["summary"]["shaped"]["discovered_hosts"] = 123
    elif mode == "nonfinite":
        value["primary_statistics"][0]["p_value"] = float("nan")
    elif mode == "duplicate":
        value["primary_statistics"][1] = value["primary_statistics"][0]
    else:
        value["primary_statistics"][0]["n_pairs"] = 12
    put(path, value)
    reseal(evidence)
    assert load_baseline(evidence).state == "INVALID"


@pytest.mark.parametrize("name", ["../outside.json", "/tmp/outside.json"])
def test_manifest_path_traversal_rejected(evidence, name):
    path = evidence / PACKAGE / "report/reviewed_manifest.json"
    manifest = json.loads(path.read_text())
    manifest["files"][name] = "a" * 64
    put(path, manifest)
    data = load_baseline(evidence)
    assert data.state == "INVALID" and "unsafe evidence path" in data.detail


def test_document_symlink_outside_root_not_available(evidence, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside") / "private.md"
    outside.write_text("must not read")
    (evidence / "docs").mkdir()
    (evidence / "docs/SUPERVISOR_EVIDENCE_BUNDLE.md").symlink_to(outside)
    data = load_baseline(evidence)
    assert next(row for row in data.documents if row[0] == "Supervisor evidence bundle")[2] is False


def test_backend_prefers_reviewed_statistics_and_rejects_invalid(evidence, monkeypatch):
    from rlredteam.application.backend import ApplicationBackend

    monkeypatch.setattr("rlredteam.application.backend.REPO_ROOT", evidence)
    backend = ApplicationBackend()
    assert Path(backend.export_report()) == evidence / PACKAGE / "report/primary_statistics.csv"
    (evidence / PACKAGE / "report/reviewed_results.json").write_text("{}")
    with pytest.raises(ValueError, match="unavailable"):
        backend.export_report()
