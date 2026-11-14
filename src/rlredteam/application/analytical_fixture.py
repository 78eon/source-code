"""Explicit tiny development fixture; never used as a campaign result."""

from rlredteam.storage.analytical_identity import build_analytical_report


def fixture_bundle():
    from rlredteam.causal_graph import build_causal_graph

    document = [
        {
            "run_name": "engineering-fixture-v1",
            "training_seed": 0,
            "topology_seed": 0,
            "episode_index": 0,
            "evaluation_seed": 0,
            "goal_reached": False,
            "events": [
                {
                    "step": 0,
                    "action": "recorded-discovery",
                    "action_kind": "discover_network",
                    "source_node": "fixture-entry",
                    "target": "fixture-host",
                    "success": True,
                    "state_changed": True,
                    "knowledge_delta": {
                        "discovered_nodes": ["fixture-host"],
                        "observed_edges": [["fixture-entry", "fixture-host", "DISCOVERED"]],
                    },
                }
            ],
        }
    ]
    report, prepared, lineage = build_analytical_report(
        document, experiment_id="engineering-fixture-not-research-v1"
    )
    return document, report, build_causal_graph(report.to_dict(), prepared), lineage
