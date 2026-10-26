"""Read persisted engineering snapshots and explicitly selected analyst reports.

No simulation construction, research directory traversal, or execution capabilities.
"""

import os
import stat
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from enum import Enum

from rlredteam.digital_twin.models import DigitalTwin
from rlredteam.digital_twin.serialization import loads


def plain(value):
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {f.name: plain(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, Mapping):
        return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, tuple | list):
        return [plain(v) for v in value]
    return value


class SnapshotReader:
    """Explicit export path, existing validated serialization, bounded regular file."""

    def __init__(self, path=None):
        self.path = path

    def read(self):
        path = self.path or os.environ.get("SECURITY_RL_TWIN_SNAPSHOT")
        if not path:
            return None
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 8 * 1024 * 1024:
                raise ValueError("Snapshot must be a bounded regular file")
            document = stream.read(8 * 1024 * 1024 + 1)
        if len(document) > 8 * 1024 * 1024:
            raise ValueError("Snapshot exceeds size limit")
        twin = loads(document.decode("utf-8"))
        if not isinstance(twin, DigitalTwin) or twin.snapshot is None:
            raise ValueError("Expected a validated snapshotted DigitalTwin")
        return twin

    def summary(self):
        twin = self.read()
        if twin is None:
            return {"status": "UNAVAILABLE", "detail": "No persisted Digital Twin available"}
        groups = ("assets", "services", "software", "identities", "findings", "relationships")
        return {
            "status": "AVAILABLE",
            "source": "digital-twin-snapshot-json",
            "snapshot_id": twin.snapshot.stable_id,
            "counts": {k: len(getattr(twin, k)) for k in groups},
            "unresolved_conflicts": len(twin.conflicts),
            "snapshot": plain(twin.snapshot),
        }

    def entities(self):
        twin = self.read()
        if twin is None:
            return []
        groups = (
            "assets",
            "services",
            "software",
            "identities",
            "zones",
            "findings",
            "relationships",
            "conflicts",
            "resolutions",
        )
        return [
            {
                **plain(entity),
                "id": entity.stable_id,
                "entity_type": group,
                "relationships": [
                    plain(r)
                    for r in twin.relationships
                    if entity.stable_id in (r.source_id, r.target_id)
                ],
            }
            for group in groups
            for entity in getattr(twin, group)
        ]


def simulation_replays(reports, allowed_ids):
    """Replay recorded Phase 14 facts. Missing run metadata stays unknown.

    Explicit report selection prevents browsing registered campaign runs by default.
    No aggregate outcome is inferred from the success of an individual action.
    """
    items = []
    for report in reports:
        if (
            report.get("report_id") not in allowed_ids
            or report.get("report_mode") != "simulation_report"
        ):
            continue
        episodes = {}
        for fact in report.get("facts", []):
            episodes.setdefault(fact["episode_id"], []).append(fact)
        for episode, facts in sorted(episodes.items()):
            facts = sorted(facts, key=lambda f: f["trajectory_step"])
            items.append(
                {
                    "id": report["report_id"] + ":" + episode,
                    "report_id": report["report_id"],
                    "episode_id": episode,
                    "run_ids": sorted({f["run_id"] for f in facts}),
                    "profile": None,
                    "timestamp": None,
                    "outcome": "UNKNOWN",
                    "step_count": len({f["trajectory_step"] for f in facts}),
                    "objective_observed": any(f.get("crown_jewel_objective") for f in facts),
                    "timeline": facts,
                    "source": "persisted-phase14-report-facts",
                }
            )
    return items
