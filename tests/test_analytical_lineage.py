"""Phase 5 pure contracts; no training, services or frozen evidence writes."""

import copy
from dataclasses import replace

import pytest

from rlredteam.attack_path_report import EvidenceValidationError, build_report
from rlredteam.causal_graph import build_causal_graph
from rlredteam.storage.analytical_identity import (
    build_analytical_report,
    count,
    digest,
    episode_uid,
    probability,
    require_hash,
    validate_payload,
    verify_graph_identity,
    verify_report_identity,
)
from rlredteam.storage.analytical_lineage import (
    fixture_snapshot,
    projection_freshness,
    verify_snapshot,
)
from tests.test_causal_graph import causal_document


def document():
    first = causal_document()[0]
    first.update(training_seed=42, topology_seed=1001, episode_index=0)
    second = copy.deepcopy(first)
    second["topology_seed"] = 1002
    return [first, second]


def bundle():
    report, prepared, lineage = build_analytical_report(document(), experiment_id="phase5-test")
    return report, build_causal_graph(report.to_dict(), prepared), lineage


def test_episode_collision_is_fixed_without_mutating_legacy():
    source = document()
    before = copy.deepcopy(source)
    report, graph, lineage = bundle()
    assert source == before
    assert len({r["episode_uid"] for r in lineage}) == 2
    assert len({r["legacy_episode_id"] for r in lineage}) == 1
    assert len({f.episode_id for f in report.facts}) == 2
    assert graph.report_id == report.report_id


def test_legacy_builder_rejects_duplicate_instead_of_silent_overwrite():
    with pytest.raises(EvidenceValidationError, match="duplicate"):
        build_report(
            document(),
            source_trajectory_hash="a" * 64,
            mode="simulation_report",
            experiment_id="test",
        )


def test_duplicate_v2_identity_is_rejected():
    source = document()
    with pytest.raises(ValueError, match="duplicate"):
        build_analytical_report([source[0], source[0]], experiment_id="test")


def test_v2_preparation_preserves_evaluation_seed_meaning():
    source = document()
    _, prepared, _ = build_analytical_report(source, experiment_id="test")
    assert [row["evaluation_seed"] for row in prepared] == [
        row["evaluation_seed"] for row in source
    ]
    assert all(row["episode_identity_version"] == "security-rl-episode-uid-v2" for row in prepared)


@pytest.mark.parametrize(
    "field,value",
    [
        ("experiment_id", "other"),
        ("run_id", "attempt-2"),
        ("run_seed", 43),
        ("topology_seed", 1002),
        ("episode_index", 1),
    ],
)
def test_episode_identity_changes_with_every_dimension(field, value):
    args = dict(
        experiment_id="exp", run_id="attempt-1", run_seed=42, topology_seed=1001, episode_index=0
    )
    original = episode_uid(**args)
    args[field] = value
    assert episode_uid(**args) != original


def test_v2_report_canonical_and_versioned():
    import json

    source = document()
    first, _, _ = build_analytical_report(source, experiment_id="test")
    second, _, _ = build_analytical_report(
        json.loads(json.dumps(source, indent=8, sort_keys=True)), experiment_id="test"
    )
    assert first.to_dict() == second.to_dict()
    verify_report_identity(first)
    source[0]["events"][0]["success"] = False
    changed, _, _ = build_analytical_report(source, experiment_id="test")
    assert first.report_id != changed.report_id


def test_graph_identity_and_report_linkage():
    report, graph, _ = bundle()
    verify_graph_identity(graph)
    again = bundle()[1]
    assert graph.graph_id == again.graph_id
    assert graph.report_id == report.report_id
    with pytest.raises(ValueError, match="identity"):
        verify_graph_identity(replace(graph, nodes=graph.nodes[:-1]))


def test_legacy_report_identity_supported():
    source = [document()[0]]
    report = build_report(
        source, source_trajectory_hash="a" * 64, mode="simulation_report", experiment_id="test"
    )
    verify_report_identity(report)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
def test_nonfinite_payload_rejected(value):
    with pytest.raises(ValueError):
        validate_payload({"nested": [value]})


@pytest.mark.parametrize("value", [-1, True, "2", float("nan"), 1.2])
def test_invalid_count_rejected(value):
    with pytest.raises(ValueError):
        count(value)


@pytest.mark.parametrize("value", [-0.01, 1.01, True, "0.5", float("inf")])
def test_invalid_probability_rejected(value):
    with pytest.raises(ValueError):
        probability(value)


@pytest.mark.parametrize("value", ["", "a" * 63, "G" * 64, "../evil", None])
def test_malformed_hash_rejected(value):
    with pytest.raises(ValueError):
        require_hash(value)


@pytest.mark.parametrize(
    "mutation,expected",
    [
        ("none", 0),
        ("orphan_projection", 1),
        ("graph_mismatch", 1),
        ("orphan_approval", 1),
        ("count_mismatch", 1),
        ("stale", 1),
        ("missing", 2),
        ("malformed", 4),
        ("duplicate", 1),
        ("hidden", 1),
        ("orphan_graph_report", 1),
    ],
)
def test_cross_store_fixture_failures(mutation, expected):
    snapshot = fixture_snapshot()
    projection = snapshot["projections"][0]
    if mutation == "orphan_projection":
        snapshot["graphs"] = []
    elif mutation == "graph_mismatch":
        projection["graph_id"] = "e" * 64
    elif mutation == "orphan_approval":
        snapshot["approvals"] = [dict(approval_id="f" * 64, report_id="e" * 64, approved=True)]
    elif mutation == "count_mismatch":
        projection["counts"] = dict(nodes=3, edges=1, evidence=1, techniques=1)
    elif mutation == "stale":
        projection["source_graph_sha256"] = "e" * 64
    elif mutation == "missing":
        snapshot["projections"] = []
    elif mutation == "malformed":
        projection["graph_id"] = "invalid"
    elif mutation == "duplicate":
        snapshot["projections"].append(copy.deepcopy(projection))
    elif mutation == "hidden":
        projection["hidden_topology_used"] = True
    elif mutation == "orphan_graph_report":
        snapshot["reports"] = []
    assert verify_snapshot(snapshot)["exit_code"] == expected


def test_projection_freshness_states():
    source = fixture_snapshot()["graphs"][0]
    assert projection_freshness(source, None) == "MISSING"
    assert projection_freshness(source, source) == "CURRENT"
    assert projection_freshness(source, dict(source, source_graph_sha256="e" * 64)) == "STALE"
    assert projection_freshness(source, dict(source, report_id="e" * 64)) == "INCONSISTENT"


def test_rebuild_rejects_ambient_transaction_before_touching_store():
    from types import SimpleNamespace

    from rlredteam.storage.analytical_lineage import rebuild_report

    with pytest.raises(ValueError, match="autocommit"):
        rebuild_report(SimpleNamespace(autocommit=False), None, "a" * 64)


def test_semantic_hash_not_file_format():
    import json

    doc = document()
    assert digest(doc) == digest(json.loads(json.dumps(doc, indent=2)))


def test_recorded_projection_count_tampering():
    snapshot = fixture_snapshot()
    snapshot["projections"][0]["node_count"] = 999
    assert verify_snapshot(snapshot)["exit_code"] == 1


@pytest.mark.parametrize(
    "mutation", ["heldout", "gradient", "protocol", "policy", "budget", "probability"]
)
def test_frozen_reconstruction_rejects_invalid_provenance_in_memory(monkeypatch, mutation):
    import json
    from pathlib import Path

    from rlredteam.storage.frozen_reconstruction import reconstruct_validation

    original = Path.read_bytes

    def read(path):
        data = original(path)
        target = "training_manifest.json" if mutation == "budget" else "summary.json"
        if path.name == target:
            obj = json.loads(data)
            if mutation == "heldout":
                obj["validation_topology_seeds"] = list(range(16001, 16021))
            elif mutation == "gradient":
                obj["gradient_updates"] = 1
            elif mutation == "protocol":
                obj["protocol_sha256"] = "f" * 64
            elif mutation == "policy":
                obj["policy_sha256_after"] = "f" * 64
            elif mutation == "budget":
                obj["actual_timesteps"] = 42
            else:
                obj["success_rate"] = "0.5"
            return json.dumps(obj).encode()
        return data

    monkeypatch.setattr(Path, "read_bytes", read)
    source = Path(
        "docs/research_evidence/MASTER_PROJECT_AUDIT/01_REGISTERED_CAMPAIGN/"
        "onprem-generalisation-registered/seed-42/validation"
    )
    with pytest.raises(ValueError):
        reconstruct_validation(source)


def test_fixture_cli_is_read_only_and_has_exit_codes(tmp_path):
    import json
    import subprocess
    import sys
    from pathlib import Path

    script = Path("scripts/verify_analytical_lineage.py").resolve()
    good = subprocess.run(
        [sys.executable, "-B", str(script), "--fixture-mode"], capture_output=True
    )
    assert good.returncode == 0
    path = tmp_path / "malformed.json"
    path.write_text(json.dumps({"invalid": True}))
    bad = subprocess.run(
        [sys.executable, "-B", str(script), "--fixture-mode", "--fixture", str(path)],
        capture_output=True,
    )
    assert bad.returncode == 4
    missing = subprocess.run(
        [
            sys.executable,
            "-B",
            str(script),
            "--fixture-mode",
            "--fixture",
            str(tmp_path / "absent"),
        ],
        capture_output=True,
    )
    assert missing.returncode == 2
