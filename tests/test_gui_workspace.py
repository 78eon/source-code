"""Workspace presentation tests: synthetic evidence; no research execution."""

import hashlib
import json
from dataclasses import asdict, replace

import pytest

from rlredteam.application.data.models import (
    AgentKnowledgeView,
    AttackTrajectorySummary,
    ComparisonOption,
    ExperimentReport,
    ResearchEvidenceSummary,
    ScenarioSummary,
    WorkspaceEvidence,
)
from rlredteam.application.data.workspace import (
    DIAGNOSTICS,
    METRICS,
    compare_options,
    knowledge_view,
    load_workspace,
    load_workspace_episode,
    simulation_workspace,
    timeline_entries,
)



def events():
    return [
        {
            "step": 0,
            "action": "service_scan",
            "target": "known",
            "success": True,
            "knowledge": {
                "nodes": ["known"],
                "known_node_types": {"known": "host"},
                "known_services": {"known": ["https"]},
                "access": {"known": "none"},
            },
            "native_reward": -1.0,
            "shaped_reward": 0.5,
        },
        {
            "step": 1,
            "action": "exploit_https",
            "action_kind": "exploit",
            "target": "known",
            "success": True,
            "cve_id": "CVE-2024-1234",
            "cvss_base": 8.1,
            "access_gained": 1,
            "native_reward": 5.0,
            "shaped_reward": 8.0,
            "framework_mappings": [
                {
                    "tactic_id": "TA0008",
                    "tactic_name": "Lateral Movement",
                    "technique_id": "T1210",
                    "technique_name": "Recorded mapping",
                }
            ],
            "knowledge": {
                "nodes": ["known", "later"],
                "access": {"known": "user"},
                "known_vulnerabilities": ["CVE-2024-1234"],
                "edges": [{"source": "known", "target": "later", "type": "REVEALED"}],
            },
            "knowledge_delta": {"discovered_nodes": ["later"]},
        },
    ]


def trajectory():
    return AttackTrajectorySummary(
        "Synthetic recorded episode",
        timeline_entries(events()),
        ExperimentReport(title="Synthetic", outcome="SUCCESS"),
        "Test fixture",
    )


def test_knowledge_projection_has_no_truth_join_or_future_discoveries():
    records = events()
    records[0]["knowledge"]["true_topology"] = {"hidden": "SECRET"}
    records[0]["knowledge"]["attributes"] = {"known": {"secret": "SECRET"}}
    records[0]["knowledge"]["edges"] = [{"source": "known", "target": "hidden", "type": "CONNECTS"}]
    entries = timeline_entries(records)
    assert "SECRET" not in json.dumps(asdict(entries[0]))
    assert "later" not in json.dumps(asdict(entries[0]))
    assert entries[0].before.nodes == ()
    assert entries[1].before == entries[0].after
    assert entries[0].after.edges == ()
    assert entries[0].after.nodes[0]["attributes"]["services"] == ["https"]


def test_legacy_discovery_counts_withheld_not_converted_to_knowledge():
    entry = timeline_entries(
        [
            {
                "step": 0,
                "target": "attempted_hidden",
                "newly_discovered": 8,
                "cve_id": "CVE-2024-1234",
            }
        ],
        legacy=True,
    )[0]
    assert entry.before == AgentKnowledgeView() and entry.after == AgentKnowledgeView()
    assert entry.action.newly_discovered is None
    assert "Withheld" in entry.action.knowledge_delta
    assert not entry.after.vulnerabilities  # action metadata is not an observed CVE inventory


def test_unknown_reward_and_action_mask_not_invented():
    entry = timeline_entries([{"step": 0, "reward": 7.0, "knowledge": {"nodes": []}}])[0]
    assert entry.action.recorded_reward == 7.0
    assert entry.action.native_reward is None and entry.action.shaped_reward is None
    assert entry.after.available_actions == ()
    assert entry.action.cve == "Unknown / not recorded"


@pytest.mark.parametrize("value", [[], "bad", 4])
def test_non_snapshot_knowledge_is_explicitly_unavailable(value):
    assert knowledge_view(value) == AgentKnowledgeView()


def test_malformed_or_missing_evidence_fails_safely(tmp_path):
    assert "not yet available" in load_workspace(tmp_path).status
    path = (
        tmp_path / "results/convergence_v2/final_baseline_evaluation/report/reviewed_manifest.json"
    )
    path.parent.mkdir(parents=True)
    path.write_text("[broken")
    assert load_workspace(tmp_path).episode_choices == ()
    assert "not yet available" in load_workspace_episode(tmp_path, "../../outside", 42, 1001).status


def test_frozen_episode_loader_binds_trace_to_reviewed_outcome(tmp_path, monkeypatch):
    from rlredteam.application.data import workspace as loader

    root = tmp_path
    frozen_path = root / loader.FROZEN
    frozen_path.parent.mkdir(parents=True)
    frozen_path.write_text("{}")
    directory = root / "fixture"
    trace = directory / "final-evaluation/shaped-42/steps.jsonl"
    trace.parent.mkdir(parents=True)
    rows = [
        dict(e, training_seed=42, evaluation_seed=1001, run_name="fixture-run") for e in events()
    ]
    trace.write_text("\n".join(map(json.dumps, rows)))

    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    matched = {
        "frozen_sha256": digest(frozen_path),
        "files": {"shaped-42/steps.jsonl": digest(trace)},
    }
    (trace.parent.parent / "matched_outcomes.json").write_text(json.dumps(matched))
    monkeypatch.setattr(
        loader,
        "_context",
        lambda _: (None, {"inputs": {"git_commit": "recorded-source"}}, directory, {}),
    )
    csv = (
        b"training_seed,evaluation_seed,length,goal_reached,run_name,native_return,failed_actions\n"
        b"42,1001,2,True,fixture-run,4.0,0\n"
    )
    monkeypatch.setattr(loader, "_report_blob", lambda *args: csv)
    before = {str(p): digest(p) for p in root.rglob("*") if p.is_file()}
    data = loader.load_workspace_episode(root, "shaped", 42, 1001)
    assert len(data.entries) == 2 and data.report.outcome == "SUCCESS", data.status
    assert dict(data.report.metrics)["Native return"] == "4.0"
    assert before == {str(p): digest(p) for p in root.rglob("*") if p.is_file()}
    wrong = csv.replace(b",4.0,", b",400.0,")
    monkeypatch.setattr(loader, "_report_blob", lambda *args: wrong)
    assert not loader.load_workspace_episode(root, "shaped", 42, 1001).entries
    monkeypatch.setattr(loader, "_report_blob", lambda *args: csv)
    trace.write_text("{}")
    assert not loader.load_workspace_episode(root, "shaped", 42, 1001).entries


def test_comparison_excludes_discovery_and_requires_matching_cohort():
    a = ComparisonOption(
        "A", "fixed", (("native_return", 1.0), ("discovered_hosts", 99.0)), "stored"
    )
    b = replace(a, label="B", metrics=(("native_return", 3.0), ("discovered_hosts", 999.0)))
    rows = compare_options(a, b)
    assert len(rows) == 1 and rows[0].metric == "native_return" and rows[0].difference == 2.0
    assert compare_options(a, replace(b, cohort="other simulator")) == ()
