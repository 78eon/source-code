"""Read existing registered validation evidence; never execute a simulator."""

import copy
import hashlib
import json
import math
from collections import defaultdict
from pathlib import Path

from .analytical_identity import (
    build_analytical_report,
    count,
    probability,
    require_hash,
    validate_payload,
)

PROTOCOL = "f78fa879b20d4552893177a55f7750db09dc32a7b5678f3a6d9808422a4d96ac"


def reconstruct_validation(directory: Path):
    directory = Path(directory)
    names = (
        "episodes.json",
        "summary.json",
        "trajectories.jsonl",
        "../training_manifest.json",
        "../model.zip",
    )
    blobs = {name: (directory / name).read_bytes() for name in names}
    hashes = {name: hashlib.sha256(data).hexdigest() for name, data in blobs.items()}
    episodes = json.loads(blobs["episodes.json"])
    summary = json.loads(blobs["summary.json"])
    manifest = json.loads(blobs["../training_manifest.json"])
    rows = [json.loads(line) for line in blobs["trajectories.jsonl"].splitlines() if line.strip()]
    validate_payload([episodes, summary, rows])
    if (
        summary["phase"] != "validation"
        or summary["final_test_evaluated"] is not False
        or summary["deterministic"] is not True
        or summary["gradient_updates"] != 0
        or summary["protocol_sha256"] != PROTOCOL
    ):
        raise ValueError("not registered non-held-out frozen validation")
    if summary["validation_topology_seeds"] != list(range(1001, 1021)):
        raise ValueError("wrong registered validation population")
    if summary["evaluation_episode_seeds"] != [19001] or len(episodes) != 20:
        raise ValueError("wrong registered validation episode contract")
    require_hash(summary["checkpoint_sha256"])
    if hashes["../model.zip"] != summary["checkpoint_sha256"]:
        raise ValueError("checkpoint file identity mismatch")
    if (
        manifest["protocol_sha256"] != PROTOCOL
        or manifest["source_commit"] != "e4f39c08d350bf33d6b187068366aca539884786"
    ):
        raise ValueError("registered scientific provenance mismatch")
    require_hash(summary["policy_sha256_before"])
    if summary["policy_sha256_before"] != summary["policy_sha256_after"]:
        raise ValueError("validation policy changed")
    seed = summary["training_seed"]
    if seed not in range(42, 52):
        raise ValueError("outside registered model seed set")
    if (
        manifest["actual_timesteps"] != 1000192
        or manifest["training_seed"] != seed
        or manifest["checkpoint_sha256"] != summary["checkpoint_sha256"]
    ):
        raise ValueError("registered training provenance mismatch")
    if count(summary["episode_count"]) != 20:
        raise ValueError("invalid validation count")
    probability(summary["success_rate"])
    grouped = defaultdict(list)
    for row in rows:
        if not isinstance(row["success"], bool) or not isinstance(row["state_changed"], bool):
            raise ValueError("invalid recorded outcome type")
        if row["topology_seed"] not in range(1001, 1021):
            raise ValueError("non-validation trajectory")
        for key in (
            "protocol_sha256",
            "training_seed",
            "checkpoint_sha256",
            "policy_sha256_before",
            "policy_sha256_after",
            "phase",
        ):
            if row[key] != summary[key]:
                raise ValueError("trajectory provenance mismatch")
        if row["evaluation_episode_seed"] != 19001:
            raise ValueError("wrong episode seed")
        grouped[row["topology_seed"]].append(row)
    if set(grouped) != set(range(1001, 1021)):
        raise ValueError("missing trajectory population")
    document = []
    if len({ep["topology_seed"] for ep in episodes}) != 20:
        raise ValueError("duplicate episode topology")
    for episode in sorted(episodes, key=lambda item: item["topology_seed"]):
        if not isinstance(episode["objective_reached"], bool):
            raise ValueError("invalid objective outcome type")
        count(episode["failed_actions"])
        topology = episode["topology_seed"]
        events = grouped[topology]
        length = count(episode["episode_length"])
        if [e["step"] for e in events] != list(range(length)):
            raise ValueError("missing or repeated recorded steps")
        if not math.isclose(
            math.fsum(e["reward"] for e in events),
            episode["environment_return"],
            rel_tol=1e-9,
            abs_tol=1e-8,
        ):
            raise ValueError("recorded reward reconstruction mismatch")
        for key in (
            "protocol_sha256",
            "training_seed",
            "checkpoint_sha256",
            "policy_sha256_before",
            "policy_sha256_after",
            "phase",
        ):
            if episode[key] != summary[key]:
                raise ValueError("episode provenance mismatch")
        if episode["evaluation_episode_seed"] != 19001:
            raise ValueError("episode seed mismatch")
        if any(event["topology_hash"] != episode["topology_hash"] for event in events):
            raise ValueError("episode topology hash mismatch")
        # Explicit import translation only: historical SYN-* values are native
        # synthetic identifiers, not CVEs. Preserve the raw field and source hash.
        translated_events = copy.deepcopy(events)
        for event in translated_events:
            identifier = event.get("cve_id")
            if isinstance(identifier, str) and identifier.startswith("SYN-"):
                event["recorded_raw_cve_id"] = identifier
                event["simulator_vulnerability_id"] = identifier
                event["cve_id"] = None
                event["import_translation_version"] = "registered-validation-import-v1"
        document.append(
            {
                "run_name": f"registered-seed-{seed}-validation",
                "training_seed": seed,
                "topology_seed": topology,
                "episode_index": 0,
                "evaluation_seed": 19001,
                "goal_reached": episode["objective_reached"],
                "checkpoint_sha256": summary["checkpoint_sha256"],
                "policy_sha256_before": summary["policy_sha256_before"],
                "policy_sha256_after": summary["policy_sha256_after"],
                "protocol_sha256": PROTOCOL,
                "topology_hash": episode["topology_hash"],
                "events": translated_events,
            }
        )
    report, prepared, lineage = build_analytical_report(
        document, experiment_id="onprem-generalisation-registered-v1"
    )
    from rlredteam.causal_graph import build_causal_graph

    graph = build_causal_graph(report.to_dict(), prepared)
    for row in lineage:
        row.update(
            source_commit=manifest["source_commit"],
            checkpoint_sha256=summary["checkpoint_sha256"],
            policy_sha256=summary["policy_sha256_before"],
            source_files_sha256=hashes,
            import_translation_version="registered-validation-import-v1",
        )
    after = {name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in names}
    if hashes != after:
        raise ValueError("frozen source changed during read reconstruction")
    return report, graph, lineage, hashes
