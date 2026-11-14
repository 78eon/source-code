"""Versioned post-registration identity; legacy builders remain explicit."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from dataclasses import asdict, replace
from typing import Any

EPISODE_VERSION = "security-rl-episode-uid-v2"
REPORT_VERSION = "security-rl-report-identity-v2"
GRAPH_BUILDER_VERSION = "security-rl-causal-attack-path-v1"


def validate_payload(value: Any) -> None:
    """Reject non-JSON and nonfinite numerics without changing their units."""
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("nonfinite analytical number")
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("JSON object keys must be strings")
        for item in value.values():
            validate_payload(item)
    elif isinstance(value, list | tuple):
        for item in value:
            validate_payload(item)
    elif value is not None and not isinstance(value, str | bool | int | float):
        raise ValueError("unsupported analytical payload type")


def digest(value: Any) -> str:
    validate_payload(value)
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def require_hash(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("expected lowercase SHA256")
    return value


def require_label(value: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise ValueError("nonempty bounded identity required")
    return value


def count(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("nonnegative integer required")
    return value


def probability(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError("numeric probability required")
    if not math.isfinite(value) or not 0 <= value <= 1:
        raise ValueError("probability outside [0,1]")
    return float(value)


def episode_uid(
    experiment_id: str, run_id: str, run_seed: int, topology_seed: int, episode_index: int
) -> str:
    # run_id additionally distinguishes separate attempts of the same seed.
    return digest(
        {
            "version": EPISODE_VERSION,
            "experiment_id": require_label(experiment_id),
            "run_id": require_label(run_id),
            "run_seed": count(run_seed),
            "topology_seed": count(topology_seed),
            "episode_index": count(episode_index),
        }
    )


def build_analytical_report(document: list[dict], *, experiment_id: str):
    """Return new v2 report, prepared trajectory copy, and explicit legacy linkage.

    No input mutation; complete seed/episode identity is required rather than
    inferred from host names. Physical source hash belongs in ingestion lineage.
    """
    from rlredteam.attack_path_report import build_report

    validate_payload(document)
    prepared = copy.deepcopy(document)
    lineage = []
    seen = set()
    checkpoints = {}
    for item in prepared:
        run = require_label(item.get("run_name") or item.get("run_id"))
        index = item.get("episode_index")
        uid = episode_uid(experiment_id, run, item["training_seed"], item["topology_seed"], index)
        if uid in seen:
            raise ValueError("duplicate analytical episode identity")
        seen.add(uid)
        legacy = f"{run}:{item.get('evaluation_seed', item.get('episode_id', index))}"
        lineage.append(
            {
                "episode_uid": uid,
                "legacy_episode_id": legacy,
                "experiment_key": experiment_id,
                "run_key": run,
                "run_seed": item["training_seed"],
                "topology_seed": item["topology_seed"],
                "episode_index": index,
                "identity_version": EPISODE_VERSION,
            }
        )
        item["episode_uid"] = uid
        item["episode_identity_version"] = EPISODE_VERSION
        item["run_name"] = run
        if item.get("checkpoint_sha256") is not None:
            checkpoint = require_hash(item["checkpoint_sha256"])
            if run in checkpoints and checkpoints[run] != checkpoint:
                raise ValueError("multiple checkpoints in one run identity")
            checkpoints[run] = checkpoint
    report = build_report(
        prepared,
        source_trajectory_hash=digest(document),
        mode="simulation_report",
        experiment_id=experiment_id,
        checkpoint_hashes=checkpoints,
        episode_identity_version=EPISODE_VERSION,
    )
    provenance = replace(report.provenance, report_schema_version=REPORT_VERSION)
    report = replace(report, provenance=provenance)
    payload = report.to_dict()
    payload.pop("report_id")
    report = replace(
        report,
        report_id=digest(
            {
                "report_id_version": REPORT_VERSION,
                "payload": payload,
            }
        ),
    )
    return report, prepared, lineage


def verify_graph_identity(graph) -> None:
    """Validate the historical graph v1 algorithm, rather than echoing its ID."""
    body = {
        "report_id": require_hash(graph.report_id),
        "schema_version": graph.schema_version,
        "nodes": [asdict(item) for item in graph.nodes],
        "edges": [asdict(item) for item in graph.edges],
        "evidence": [asdict(item) for item in graph.evidence],
    }
    if graph.schema_version != GRAPH_BUILDER_VERSION or digest(body) != graph.graph_id:
        raise ValueError("causal graph content identity mismatch")
    node_ids = [item.node_id for item in graph.nodes]
    evidence_ids = [item.evidence_id for item in graph.evidence]
    edge_ids = [item.edge_id for item in graph.edges]
    for values in (node_ids, evidence_ids, edge_ids):
        if len(values) != len(set(values)):
            raise ValueError("duplicate graph entity identity")
    for edge in graph.edges:
        if edge.source_node not in node_ids or edge.target_node not in node_ids:
            raise ValueError("orphan graph endpoint")
        if not edge.evidence_ids or not set(edge.evidence_ids) <= set(evidence_ids):
            raise ValueError("orphan graph evidence")
    if graph.provenance.get("hidden_topology_used") is not False:
        raise ValueError("hidden topology provenance prohibited")


def verify_report_identity(report) -> None:
    payload = report.to_dict()
    require_hash(payload.pop("report_id"))
    if report.provenance.report_schema_version == REPORT_VERSION:
        expected = digest({"report_id_version": REPORT_VERSION, "payload": payload})
    elif report.provenance.report_schema_version == "security-rl-attack-path-report-v1":
        payload["mode"] = payload.pop("report_mode")
        expected = digest(payload)
    else:
        raise ValueError("unsupported report identity version")
    if expected != report.report_id:
        raise ValueError("report content identity mismatch")
