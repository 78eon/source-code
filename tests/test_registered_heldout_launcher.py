"""Synthetic launcher contracts; no topology generator or held-out IDs are used."""

import importlib.util
import hashlib
import json
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("registered_heldout", "scripts/evaluate_registered_heldout.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

AGG_SPEC = importlib.util.spec_from_file_location(
    "registered_heldout_aggregation", "scripts/registered_heldout_aggregation.py"
)
AGGREGATION = importlib.util.module_from_spec(AGG_SPEC)
AGG_SPEC.loader.exec_module(AGGREGATION)

OUTCOMES = {
    "primary": "zero-shot success rate on final unseen topology seeds",
    "success": "terminated by nonempty intersection of accessed_assets and crown_jewels",
    "aggregation": "equally weighted topology episodes within training seed; report all ten seeds",
    "efficiency": "mean steps-to-success among successful episodes only; null when no successes",
    "supporting": ["environment_return", "failed_actions"],
    "descriptive": ["per_topology_success", "per_training_seed_success", "episode_length"],
}


def mocked_rows(policies=tuple(range(42, 52)), topologies=tuple(range(71, 91)), episode_seeds=(9,)):
    rows = []
    for policy in policies:
        for topology in topologies:
            for episode_seed in episode_seeds:
                rows.append({
                    "training_seed": policy,
                    "topology_seed": topology,
                    "topology_hash": f"topology-{topology}",
                    "evaluation_seed": episode_seed,
                    "goal_reached": topology % 2 == 0,
                    "steps_to_goal": 4 if topology % 2 == 0 else None,
                    "episode_length": 5,
                    "total_reward": float(topology),
                    "failed_actions": 1,
                    "terminal_reason": "goal" if topology % 2 == 0 else "step_limit",
                    "protocol_sha256": "fixture-protocol",
                    "checkpoint_sha256": f"fixture-{policy}",
                    "policy_sha256_before": f"policy-{policy}",
                    "policy_sha256_after": f"policy-{policy}",
                })
    return rows


def aggregate(rows, policies=tuple(range(42, 52)), topologies=tuple(range(71, 91)), episode_seeds=(9,), outcomes=None):
    return AGGREGATION.aggregate_registered_results(
        rows,
        training_seeds=tuple(policies),
        topology_seeds=tuple(topologies),
        evaluation_episode_seeds=tuple(episode_seeds),
        outcomes=OUTCOMES if outcomes is None else outcomes,
        phase="heldout",
        deterministic=True,
    )


def episode(topology, seed=7, success=False):
    return {"topology_seed": topology, "evaluation_seed": seed, "goal_reached": success,
            "steps_to_goal": 4 if success else None, "episode_length": 4,
            "total_reward": 5.0, "failed_actions": 0, "terminal_reason": "goal" if success else "step_limit"}


def test_seed_gate_accepts_only_complete_mocked_range():
    mocked = tuple(range(71, 75))
    MODULE.validate_seed_request(mocked, mocked)
    with pytest.raises(MODULE.Blocked, match="partial"):
        MODULE.validate_seed_request(mocked[:-1], mocked)
    with pytest.raises(MODULE.Blocked, match="partial"):
        MODULE.validate_seed_request((71, 72, 74, 75), mocked)


def test_protocol_seed_contract_rejects_altered_fixture_without_generation():
    with pytest.raises(MODULE.Blocked, match="registered held-out seed set"):
        MODULE.expected_seeds({"splits": {"test": [71, 72, 73, 75]}})


def test_altered_synthetic_protocol_and_checkpoint_are_rejected(tmp_path):
    frozen = {"protocol_id": "fixture-v1", "payload": {"metric": "success"}}
    expected = MODULE.canonical_protocol_sha(frozen)
    MODULE.verify_protocol_identity(frozen, expected_id="fixture-v1", expected_sha=expected)
    altered = {"protocol_id": "fixture-v1", "payload": {"metric": "return"}}
    with pytest.raises(MODULE.Blocked, match="protocol canonical digest"):
        MODULE.verify_protocol_identity(altered, expected_id="fixture-v1", expected_sha=expected)
    checkpoint = tmp_path / "synthetic-policy.bin"
    checkpoint.write_bytes(b"synthetic checkpoint")
    digest = hashlib.sha256(checkpoint.read_bytes()).hexdigest()
    assert MODULE.verify_file_hash(checkpoint, digest, "fixture") == digest
    checkpoint.write_bytes(b"altered synthetic checkpoint")
    with pytest.raises(MODULE.Blocked, match="fixture hash mismatch"):
        MODULE.verify_file_hash(checkpoint, digest, "fixture")


def test_ten_policies_by_twenty_mocked_topologies_are_accepted():
    campaign, _ = aggregate(mocked_rows())
    assert campaign["episode_count"] == 200
    assert campaign["policy_count"] == 10
    assert all(s["episode_count"] == 20 for s in campaign["policy_summaries"].values())


def test_missing_policy_is_blocked():
    rows = [r for r in mocked_rows() if r["training_seed"] != 51]
    with pytest.raises(AGGREGATION.AggregationBlocked, match="missing registered policy"):
        aggregate(rows)


@pytest.mark.parametrize("count", [19, 21])
def test_nineteen_or_twenty_one_topology_population_is_blocked(count):
    topology_ids = tuple(range(71, 71 + count))
    with pytest.raises(AGGREGATION.AggregationBlocked):
        aggregate(mocked_rows(topologies=topology_ids), topologies=topology_ids)


def test_duplicate_policy_topology_pair_is_blocked():
    rows = mocked_rows()
    rows.append(dict(rows[0]))
    with pytest.raises(AGGREGATION.AggregationBlocked, match="duplicate policy/topology"):
        aggregate(rows)


def test_duplicate_evaluation_seed_is_blocked():
    with pytest.raises(AGGREGATION.AggregationBlocked, match="duplicate or empty registered evaluation seed"):
        aggregate(mocked_rows(), episode_seeds=(9, 9))


def test_duplicate_topology_seed_is_blocked():
    with pytest.raises(AGGREGATION.AggregationBlocked, match="duplicate or empty registered topology"):
        aggregate(mocked_rows(), topologies=(71, 71, *range(73, 91)))


def test_unexpected_policy_is_blocked():
    rows = mocked_rows()
    rows[0]["training_seed"] = 99
    with pytest.raises(AGGREGATION.AggregationBlocked, match="unexpected policy"):
        aggregate(rows)


def test_validation_reconstruction_matches_all_registered_summaries_exactly():
    campaign_root = Path("docs/research_evidence/MASTER_PROJECT_AUDIT/01_REGISTERED_CAMPAIGN/onprem-generalisation-registered")
    validation_summaries = {}
    all_rows = []
    for policy in range(42, 52):
        policy_root = campaign_root / f"seed-{policy}" / "validation"
        validation_summaries[str(policy)] = json.loads((policy_root / "summary.json").read_text())
        all_rows.extend(json.loads((policy_root / "episodes.json").read_text()))
    topologies = tuple(validation_summaries["42"]["validation_topology_seeds"])
    episode_seeds = tuple(validation_summaries["42"]["evaluation_episode_seeds"])
    reconstructed, _ = AGGREGATION.aggregate_registered_results(
        all_rows,
        training_seeds=tuple(range(42, 52)),
        topology_seeds=topologies,
        evaluation_episode_seeds=episode_seeds,
        outcomes=OUTCOMES,
        phase="validation",
        deterministic=True,
    )
    assert reconstructed["episode_count"] == 200
    assert reconstructed["policy_count"] == 10
    assert reconstructed["policy_summaries"] == validation_summaries


def test_altered_registered_metric_definition_is_blocked():
    altered = dict(OUTCOMES)
    altered["primary"] = "mean environment return"
    with pytest.raises(AGGREGATION.AggregationBlocked, match="metric/outcome definition"):
        aggregate(mocked_rows(), outcomes=altered)


def test_existing_output_or_partial_marker_blocks(tmp_path):
    marker = tmp_path / "execution.json"
    marker.write_text(json.dumps({"status": "RUNNING"}))
    assert MODULE._marker_exists(tmp_path)
    assert MODULE._marker_exists(marker)


def test_approval_is_separate_from_input_verification(tmp_path):
    report = {"protocol_sha256": "p", "launcher_sha256": "l", "requested_topology_seeds": [71, 72]}
    approval = tmp_path / "approval.json"
    approval.write_text(json.dumps({"execution_authorized": False}))
    with pytest.raises(MODULE.Blocked, match="approval"):
        MODULE.authorize(report, approval)
    approval.write_text(json.dumps({"execution_authorized": True, "protocol_sha256": "p",
                                   "launcher_sha256": "l", "approved_topology_seeds": [71, 72],
                                   "approved_by": "test-only", "approval_timestamp": "fixture"}))
    approval.chmod(0o600)
    assert MODULE.authorize(report, approval)["execution_authorized"] is True


def test_output_reservation_is_exclusive_and_refuses_repeat(tmp_path):
    target = tmp_path / "new-one-pass-output"
    MODULE.reserve_output(target)
    assert target.stat().st_mode & 0o777 == 0o700
    with pytest.raises(MODULE.Blocked, match="already exists"):
        MODULE.reserve_output(target)
