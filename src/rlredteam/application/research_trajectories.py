"""Read frozen validation action records only. No model, simulator or storage imports."""

import hashlib
import json
import math
import os
import stat
from pathlib import Path
from .registered_results import _read, _sealed, _digest

LABEL = "REGISTERED PPO VALIDATION EVIDENCE — READ-ONLY RECONSTRUCTION"
EXPLANATION = (
    "This viewer reconstructs recorded PPO validation actions from frozen research evidence. "
    "Chronological links do not imply host-to-host network connectivity unless explicitly "
    "present in the source evidence."
)
NOT_RECORDED = "Not recorded"
LIMITATIONS = [
    "Chronological links indicate next recorded step only, not network connectivity or causal dependency.",
    "Source hosts, before/after access state, observations, action masks and state snapshots are not supplied by these validation records.",
    "Policy logits, alternative actions and reward decomposition are not supplied; action-selection reasons cannot be inferred.",
    "Recorded prerequisite/outcome tokens and state_changed flags are not full state snapshots.",
    "SYN-* identifiers and their recorded scores describe synthetic vulnerabilities, not empirical CVEs or attributable real-world CVSS.",
    "Policy/checkpoint identities are checked against metadata; checkpoint contents are never loaded or reverified by this viewer.",
    "This is a derived read-only presentation. No PPO execution, validation rerun, held-out access or database import is performed.",
]
IDENTITY = ("training_seed", "topology_seed", "topology_hash", "evaluation_episode_seed",
            "checkpoint_sha256", "policy_sha256_before", "policy_sha256_after", "protocol_sha256", "phase")
MISSING_FIELDS = {
    "Source host": "source_node", "Access state before": "access_before", "Access state after": "access_after",
    "Observations": "observation", "Action masks": "action_mask", "State snapshots": "state_snapshot",
    "Knowledge deltas": "knowledge_delta", "Policy logits": "logits", "Alternative actions": "alternative_actions",
    "Reward decomposition": "reward_components",
}


class SelectionError(ValueError):
    """An input selection is outside the recorded validation population."""


def _integer(value):
    return type(value) is int and value >= 0


def _number(value):
    return type(value) in (int, float) and math.isfinite(value)


def _reserved(value):
    return 16001 <= value <= 16020


def _json(line):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate trajectory field")
            result[key] = value
        return result
    def nonfinite(_):
        raise ValueError("Nonfinite trajectory value")
    return json.loads(line, object_pairs_hook=pairs, parse_constant=nonfinite)


class ResearchTrajectoryReader:
    def __init__(self, root=None):
        self.root = Path(root or os.environ.get("SECURITY_RL_REGISTERED_CAMPAIGN") or (
            Path(__file__).resolve().parents[3] / "docs/research_evidence/MASTER_PROJECT_AUDIT/"
            "01_REGISTERED_CAMPAIGN/onprem-generalisation-registered"
        ))

    def _protocol(self, hashes):
        manifest = _read(self.root, "protocol_manifest.json", hashes)
        _sealed(manifest)
        if manifest.get("registered") is not True or manifest.get("canonical_protocol", {}).get("algorithm") != "MaskablePPO":
            raise ValueError("Registered PPO protocol unavailable")
        _digest(manifest["protocol_sha256"])
        seeds = manifest["training_seeds"]
        validation = manifest["topology_seeds"]["validation"]
        if (not seeds or len(seeds) > 100 or any(not _integer(s) for s in seeds)
                or len(set(seeds)) != len(seeds) or not validation or len(validation) > 1000
                or any(not _integer(s) or _reserved(s) for s in validation)
                or len(set(validation)) != len(validation)):
            raise ValueError("Invalid registered validation population")
        return manifest

    def _policy(self, seed, manifest, hashes):
        if not _integer(seed) or seed not in manifest["training_seeds"]:
            raise SelectionError("Policy is not in registered campaign")
        prefix = f"seed-{seed}/"
        training = _read(self.root, prefix + "training_manifest.json", hashes)
        _sealed(training)
        summary = _read(self.root, prefix + "validation/summary.json", hashes)
        # episodes.json is an array, whereas the shared metadata reader accepts objects.
        episodes = self._array(prefix + "validation/episodes.json", hashes)
        if (training["training_seed"] != seed or summary["training_seed"] != seed
                or training["protocol_sha256"] != manifest["protocol_sha256"]
                or summary["protocol_sha256"] != manifest["protocol_sha256"]
                or training["validation"] != summary or summary["phase"] != "validation"
                or summary["gradient_updates"] is not False
                or summary["checkpoint_sha256"] != training["checkpoint_sha256"]
                or summary["policy_sha256_before"] != training["policy_sha256"]
                or summary["policy_sha256_after"] != training["policy_sha256"]
                or summary["validation_topology_seeds"] != manifest["topology_seeds"]["validation"]):
            raise ValueError("Frozen validation identity mismatch")
        for key in ("checkpoint_sha256", "policy_sha256"):
            _digest(training[key])
        evaluation = summary["evaluation_episode_seeds"]
        if not evaluation or any(not _integer(s) or _reserved(s) for s in evaluation) or len(set(evaluation)) != len(evaluation):
            raise ValueError("Invalid evaluation episode seeds")
        expected = {(t, e) for t in summary["validation_topology_seeds"] for e in evaluation}
        if len(episodes) != len(expected) or summary["episode_count"] != len(expected):
            raise ValueError("Incomplete episode population")
        observed = set()
        for episode in episodes:
            pair = (episode["topology_seed"], episode["evaluation_episode_seed"])
            if pair in observed or pair not in expected:
                raise ValueError("Duplicate or non-validation episode")
            observed.add(pair)
            for key in ("training_seed", "checkpoint_sha256", "policy_sha256_before", "policy_sha256_after", "protocol_sha256", "phase"):
                if episode[key] != summary[key]:
                    raise ValueError("Episode identity mismatch")
            _digest(episode["topology_hash"])
            if (not _integer(episode["episode_length"]) or not _number(episode["environment_return"])
                    or not _integer(episode["failed_actions"]) or type(episode["objective_reached"]) is not bool
                    or episode["success"] is not episode["objective_reached"]):
                raise ValueError("Invalid episode metrics")
        return training, summary, episodes

    def _bytes(self, relative, hashes, limit):
        path = self.root / relative
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError("Evidence symlinks prohibited")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                raise ValueError("Invalid evidence size/type")
            content = stream.read(limit + 1)
        if len(content) > limit:
            raise ValueError("Evidence limit exceeded")
        hashes[relative] = hashlib.sha256(content).hexdigest()
        return content

    def _array(self, relative, hashes):
        result = _json(self._bytes(relative, hashes, 2 * 1024 * 1024))
        if not isinstance(result, list) or any(not isinstance(r, dict) for r in result):
            raise ValueError("Invalid episode array")
        return result

    def index(self):
        hashes = {}
        manifest = self._protocol(hashes)
        policies = []
        for seed in manifest["training_seeds"]:
            sources = {}
            try:
                training, _, episodes = self._policy(seed, manifest, sources)
                policies.append({"training_seed": seed, "status": "AVAILABLE",
                    "policy_sha256": training["policy_sha256"], "checkpoint_sha256": training["checkpoint_sha256"],
                    "episodes": [{k: e[k] for k in ("topology_seed", "topology_hash", "evaluation_episode_seed", "episode_length")} for e in episodes]})
            except (OSError, ValueError, KeyError, TypeError, AttributeError):
                policies.append({"training_seed": seed, "status": "UNAVAILABLE", "episodes": []})
        return {"read_only": True, "label": LABEL, "policies": policies}

    def episode(self, training_seed, topology_seed, evaluation_seed):
        # Reject reserved input before constructing or reading any seed-specific path.
        if any(not _integer(v) or _reserved(v) for v in (topology_seed, evaluation_seed)):
            raise SelectionError("Only registered validation episodes may be selected")
        hashes = {}
        manifest = self._protocol(hashes)
        if topology_seed not in manifest["topology_seeds"]["validation"]:
            raise SelectionError("Not a validation topology")
        _, summary, episodes = self._policy(training_seed, manifest, hashes)
        selected = next((e for e in episodes if (e["topology_seed"], e["evaluation_episode_seed"]) == (topology_seed, evaluation_seed)), None)
        if selected is None:
            raise SelectionError("Episode is not recorded")
        relative = f"seed-{training_seed}/validation/trajectories.jsonl"
        content = self._bytes(relative, hashes, 64 * 1024 * 1024)
        groups = {(e["topology_seed"], e["evaluation_episode_seed"]): (e, []) for e in episodes}
        for line_number, line in enumerate(content.splitlines(), 1):
            if line_number > 100000:
                raise ValueError("Too many trajectory records")
            if not line.strip():
                continue
            row = _json(line)
            if not isinstance(row, dict):
                raise ValueError("Invalid trajectory record")
            episode, rows = groups[(row["topology_seed"], row["evaluation_episode_seed"])]
            if any(row[k] != episode[k] for k in IDENTITY):
                raise ValueError("Trajectory identity mismatch")
            if (not _integer(row["step"]) or not _number(row["reward"])
                    or any(type(row[k]) is not bool for k in ("success", "goal_reached", "state_changed"))
                    or (row.get("rl_action_index") is not None and not _integer(row["rl_action_index"]))):
                raise ValueError("Invalid trajectory step")
            for key in ("prerequisites", "outcomes", "framework_mappings"):
                if row.get(key) is not None and not isinstance(row[key], list):
                    raise ValueError("Invalid recorded tokens/mappings")
            rows.append({"recorded": row, "source_line": line_number})
        for episode, rows in groups.values():
            events = [r["recorded"] for r in rows]
            if (not events or [r["step"] for r in events] != list(range(episode["episode_length"]))
                    or not math.isclose(math.fsum(r["reward"] for r in events), episode["environment_return"], rel_tol=1e-9, abs_tol=1e-8)
                    or sum(not r["success"] for r in events) != episode["failed_actions"]
                    or events[-1]["goal_reached"] is not episode["objective_reached"]):
                raise ValueError("Episode step order, rewards or terminal result mismatch")
        completion_path = self.root / f"seed-{training_seed}/completion.json"
        anchor = NOT_RECORDED
        if completion_path.exists():
            completion = _read(self.root, f"seed-{training_seed}/completion.json", hashes)
            _sealed(completion)
            anchors = [value for name, value in completion["output_hashes"].items() if name.endswith("/" + relative)]
            if anchors != [hashes[relative]]:
                raise ValueError("Frozen trajectory completion hash mismatch")
            anchor = "Completion trajectory hash verified"
        rows = groups[(topology_seed, evaluation_seed)][1]
        events = [r["recorded"] for r in rows]
        techniques = []
        for row in events:
            for mapping in row.get("framework_mappings") or []:
                if not isinstance(mapping, dict):
                    raise ValueError("Invalid recorded MITRE mapping")
                if mapping not in techniques:
                    techniques.append(mapping)
        stages = []
        for row in events:
            category = row.get("action_kind") or NOT_RECORDED
            if stages and stages[-1]["category"] == category:
                stages[-1]["last_step"] = row["step"]
            else:
                stages.append({"category": category, "first_step": row["step"], "last_step": row["step"]})
        def action(row):
            return f"Step {row['step']}: {row.get('simulator_action') or row.get('action') or NOT_RECORDED}; target {row.get('target_entity') or NOT_RECORDED}; reward {row['reward']}; success {row['success']}"
        from .registered_journey import with_journey

        episode = {"schema_version": "research-trajectory-v1", "read_only": True,
            "evidence_class": "registered_ppo_validation", "research_status": "registered", "label": LABEL,
            "explanation": EXPLANATION, "identity": {k: selected[k] for k in IDENTITY}, "episode": selected,
            "summary": {"start": action(events[0]), "major_stages": stages,
                "notable_actions": [action(r) for r in events if r.get("outcomes") or r["goal_reached"]],
                "notable_rule": "Recorded nonempty outcome tokens or goal flag; not inferred policy importance",
                "objective_reached": selected["objective_reached"], "final_action": action(events[-1]),
                "total_steps": selected["episode_length"], "total_return": selected["environment_return"],
                "terminal_outcome": selected.get("terminal_outcome", NOT_RECORDED), "mitre_techniques": techniques},
            "steps": rows, "chronology": {"relationship": "next_recorded_step", "meaning": "chronological_order_only",
                "links": [{"from_step": a["step"], "to_step": b["step"]} for a, b in zip(events, events[1:])]},
            "evidence_availability": {label: "Present in some recorded steps" if any(r.get(key) is not None for r in events) else NOT_RECORDED for label, key in MISSING_FIELDS.items()},
            "limitations": LIMITATIONS, "provenance": {"source_sha256": hashes, "trajectory_file": relative,
                "checkpoint_verification": "Recorded metadata binding only; checkpoint not loaded",
                "trajectory_completion_anchor": anchor, "episode_identity": "training_seed + topology_seed + evaluation_episode_seed; no episode ordinal inferred"}}
        return with_journey(episode, manifest.get("canonical_protocol", {}).get("topology", {}))
