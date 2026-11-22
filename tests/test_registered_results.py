"""Synthetic local metadata only. No policy loading, network or research writes."""
import hashlib
import json

import pytest

from rlredteam.application.registered_results import RegisteredResultsReader


def write(path, value, sealed=False):
    if sealed:
        value = dict(value)
        value.pop("manifest_sha256", None)
        value["manifest_sha256"] = hashlib.sha256(json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()).hexdigest()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


@pytest.fixture
def campaign(tmp_path):
    summary = dict(training_seed=7, protocol_sha256="a" * 64, phase="validation",
                   checkpoint_sha256="b" * 64, policy_sha256_before="c" * 64,
                   policy_sha256_after="c" * 64, successful_episodes=20, episode_count=20,
                   success_rate=1.0, per_topology_success_rate={"test-topology": 1.0},
                   mean_environment_return=-2.5, mean_failed_actions=0,
                   final_test_evaluated=False)
    write(tmp_path / "protocol_manifest.json", dict(registered=True, training_seeds=[7],
          protocol_id="synthetic", protocol_sha256="a" * 64), True)
    write_policy(tmp_path, summary)
    return tmp_path, summary


def write_policy(root, summary):
    write(root / "seed-7/validation/summary.json", summary)
    write(root / "seed-7/training_manifest.json", dict(training_seed=7,
          protocol_sha256="a" * 64, checkpoint_sha256="b" * 64, policy_sha256="c" * 64,
          final_test_evaluated=False, validation=summary,
          convergence=dict(rise=False, passed=False)), True)


def test_preserves_policy_validation_fail_pending_and_sources(campaign):
    root, _ = campaign
    before = {str(p): p.read_bytes() for p in root.rglob("*.json")}
    response = RegisteredResultsReader(root).read()
    row = response.policies[0]
    assert response.status == "AVAILABLE" and response.aggregation == "per_policy"
    assert (row.successful_episodes, row.episode_count, row.success_rate) == (20, 20, 1.0)
    assert row.reward_rise is False and row.convergence_passed is False
    assert row.final_test_evaluated is False
    assert row.mean_environment_return == -2.5 and row.mean_failed_actions == 0
    assert row.mean_steps_to_success is None
    assert row.per_topology_success_rate == {"test-topology": 1.0}
    assert len(row.source_sha256) == 2
    assert before == {str(p): p.read_bytes() for p in root.rglob("*.json")}
    assert "pooled" not in response.model_dump()


@pytest.mark.parametrize("field,value", [
    ("checkpoint_sha256", "d" * 64), ("success_rate", 100),
    ("successful_episodes", 21), ("final_test_evaluated", "false"),
    ("mean_environment_return", float("nan")),
])
def test_invalid_or_mismatched_evidence_is_unavailable(campaign, field, value):
    root, summary = campaign
    summary[field] = value
    if field == "mean_environment_return":
        write(root / "seed-7/validation/summary.json", summary)
    else:
        write_policy(root, summary)
    result = RegisteredResultsReader(root).read()
    assert result.status == "UNAVAILABLE"
    assert result.policies[0].success_rate is None


def test_missing_policy_is_retained_as_unavailable(campaign):
    root, _ = campaign
    write(root / "protocol_manifest.json", dict(registered=True, training_seeds=[7, 8],
          protocol_id="synthetic", protocol_sha256="a" * 64), True)
    result = RegisteredResultsReader(root).read()
    assert result.status == "PARTIAL"
    assert [p.training_seed for p in result.policies] == [7, 8]
    assert result.policies[1].status == "UNAVAILABLE"


def test_null_metrics_and_unknown_heldout_stay_null(campaign):
    root, summary = campaign
    summary["mean_environment_return"] = None
    summary.pop("final_test_evaluated")
    write_policy(root, summary)
    # Both records lack a claim about held-out execution.
    path = root / "seed-7/training_manifest.json"
    training = json.loads(path.read_text())
    training.pop("final_test_evaluated")
    write(path, training, True)
    result = RegisteredResultsReader(root).read()
    assert result.status == "AVAILABLE"
    assert result.policies[0].final_test_evaluated is None
    assert result.policies[0].mean_environment_return is None


def test_missing_campaign_and_symlink_are_unavailable(tmp_path, campaign):
    assert RegisteredResultsReader(tmp_path / "missing").read().status == "UNAVAILABLE"
    root, _ = campaign
    link = tmp_path / "linked"
    link.symlink_to(root, target_is_directory=True)
    assert RegisteredResultsReader(link).read().status == "UNAVAILABLE"


def test_registered_ppo_architecture_and_binding_are_metadata_derived(campaign):
    root, _ = campaign
    manifest = json.loads((root / 'protocol_manifest.json').read_text())
    manifest['canonical_protocol'] = {'algorithm':'MaskablePPO'}
    manifest['source_hashes'] = {'src/rlredteam/enterprise/environment.py':'e' * 64}
    write(root / 'protocol_manifest.json', manifest, True)
    result = RegisteredResultsReader(root).read()
    assert result.algorithm == 'MaskablePPO'
    assert result.environment_source == 'src/rlredteam/enterprise/environment.py'
    row = result.policies[0]
    assert row.policy_id == 'sha256:' + row.policy_sha256
    assert row.validation_topology_count == 1
    assert 'checkpoint not loaded' in row.checkpoint_binding
    assert row.reward_rise is False and row.final_test_evaluated is False
