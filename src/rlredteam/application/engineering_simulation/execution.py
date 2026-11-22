"""Bounded existing V2 reasoning and EnterpriseCyberEnv execution; no live adapters."""

from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
from pathlib import Path
from rlredteam.storage.analytical_identity import digest, build_analytical_report
from .models import POLICY, DECISION_ENGINE, episode_seed


def execute(spec, topology, assignments, simulation_id):
    from rlredteam.enterprise.environment import EnterpriseCyberEnv, EnterpriseActionType
    from rlredteam.enterprise.environment_config import EnterpriseEnvironmentConfig
    from rlredteam.enterprise.reward_config import EnterpriseRewardConfig
    from rlredteam.enterprise.v2_reasoner import reason_next_action
    from rlredteam.causal_graph import build_causal_graph
    from rlredteam.frameworks import map_simulator_behavior
    from rlredteam.enterprise.reward_attribution import implementation_sha256

    # Engineering reward profile is explicit; no registered experiment configuration is loaded.
    reward = EnterpriseRewardConfig(
        -5,
        -1,
        100,
        0.5,
        0.1,
        {
            "discover_network": 1,
            "enumerate_host": 1,
            "enumerate_service": 1,
            "enumerate_application": 1,
            "assess_vulnerability": 1,
            "obtain_credential": 2,
            "authenticate": 3,
            "pivot": 3,
            "escalate_privilege": 4,
            "access_asset": 0,
        },
    )
    capacity = len(topology.nodes)
    env = EnterpriseCyberEnv(
        topology,
        environment_config=EnterpriseEnvironmentConfig(
            spec.max_steps, capacity, max(1, len(topology.vulnerabilities))
        ),
        reward_config=reward,
    )
    annotations = {item["id"]: item for item in assignments}
    episodes = []
    for episode in range(spec.episodes):
        rng_seed = episode_seed(spec.seed, episode)
        env.reset(seed=rng_seed)
        events = []
        attempts = Counter()
        for _ in range(spec.max_steps):
            known = env.agent_knowledge
            reasoning = reason_next_action(env, goal_id=topology.crown_jewels[0], max_hops=4)
            mask = env.action_masks()
            offered = [i for i, valid in enumerate(mask) if valid]
            if not offered:
                break

            def resolved(i):
                action = env.actions[i]
                order = (
                    known.vulnerability_order
                    if action.type == EnterpriseActionType.EXPLOIT
                    else known.discovery_order
                )
                return action.type.value, order[int(action.target.rsplit("_", 1)[1])]

            # Fallback also consumes only masks and observed slot identities.
            if spec.vulnerabilities.access == "local":
                offered = [
                    i
                    for i in offered
                    if resolved(i)[0] != "exploit"
                    or known.vulnerability_targets.get(resolved(i)[1]) in known.access
                ]
            if not offered:
                break
            plan = reasoning.execution_plan
            use_v2 = (
                plan is not None
                and plan.action_index in offered
                and attempts[plan.action_index] < 3
            )
            index = plan.action_index if use_v2 else min(offered, key=lambda i: (attempts[i], i))
            kind, target = resolved(index)
            attempts[index] += 1
            selection_rule = (
                reasoning.explanation.selection_rule
                if use_v2 and reasoning.explanation
                else "Least-attempted valid observed action; deterministic slot order (V2 fallback)"
            )
            before = env.agent_knowledge
            _, value, terminated, truncated, info = env.step(index)
            event = info["event"]
            after = env.agent_knowledge
            annotation = annotations.get(target)
            supported_sources = sorted(a for a, b, _ in before.known_edges if b == target)
            source = next(
                (p.split(":", 1)[1] for p in event.prerequisites if p.startswith("access:")),
                supported_sources[0]
                if supported_sources
                else before.vulnerability_targets.get(target, "UNKNOWN"),
            )
            item = {
                "step": event.step,
                "rl_action_index": index,
                "simulator_action": kind,
                "action_kind": kind,
                "source_node": source,
                "node_type": before.known_node_types[target].value
                if target in before.known_node_types
                else None,
                "target": event.action.target,
                "success": event.success,
                "state_changed": event.state_changed,
                "reward": float(value),
                "goal_reached": event.goal_reached,
                "prerequisites": list(event.prerequisites),
                "outcomes": list(event.outcomes),
                "reason": event.reason,
                "access_before": before.access.get(target, "UNKNOWN"),
                "access_after": after.access.get(target, "UNKNOWN"),
                "simulator_vulnerability_id": target if kind == "exploit" else None,
                # A CVE is never relabelled as proven applicable by the synthetic transition.
                "cve_id": None,
                "cvss_score": None,
                "catalogue_context": annotation,
                "knowledge_delta": {
                    "discovered_nodes": sorted(after.discovered - before.discovered),
                    "observed_edges": [
                        [a, b, c.value]
                        for a, b, c in sorted(after.known_edges - before.known_edges)
                    ],
                    "compromised_nodes": sorted(set(after.access) - set(before.access)),
                    "access_changes": [
                        [node, level]
                        for node, level in sorted(after.access.items())
                        if before.access.get(node) != level
                    ],
                },
                "reward_attribution": asdict(info["reward_attribution"]),
                "decision": {
                    "availability": "Existing environment action mask over observed AgentKnowledge",
                    "selection_rule": selection_rule,
                    "score": reasoning.selected_decision.score if use_v2 else None,
                    "score_meaning": "heuristic ranking, not a probability",
                    "explanation": asdict(reasoning.explanation)
                    if use_v2 and reasoning.explanation
                    else None,
                    "alternatives": [
                        {"target": d.target_id, "kind": d.kind.value, "score": d.score}
                        for d in reasoning.decisions[:10]
                    ],
                },
                "mitre_mappings": [m.as_dict() for m in map_simulator_behavior(kind)],
            }
            item["evidence_id"] = digest(
                {"simulation": simulation_id, "episode": episode, "event": item}
            )
            events.append(item)
            if terminated or truncated:
                break
        episodes.append(
            {
                "run_name": f"{simulation_id}-engineering",
                "training_seed": spec.seed,
                "topology_seed": spec.seed,
                "evaluation_seed": rng_seed,
                "episode_index": episode,
                "goal_reached": bool(env.knowledge.accessed_assets),
                "events": events,
                "environment_return": env.episode_return,
                "outcome": "OBJECTIVE_REACHED" if env.knowledge.accessed_assets else "NOT_REACHED",
                "evidence_class": "engineering_simulation",
                "research_status": "not_registered",
            }
        )
    if not any(e["events"] for e in episodes):
        raise ValueError("Simulation produced no recorded actions")
    report, prepared, lineage = build_analytical_report(episodes, experiment_id=simulation_id)
    graph = build_causal_graph(report.to_dict(), prepared)
    code_root = Path(__file__).parent
    reasoning_root = Path(reason_next_action.__code__.co_filename).parent
    policy_sources = {
        name: hashlib.sha256((reasoning_root / name).read_bytes()).hexdigest()
        for name in [
            "v2_reasoner.py",
            "v2_execution.py",
            "decision_action_mapper.py",
            "attacker_decision.py",
            "attacker_graph.py",
            "attack_path_reasoner.py",
            "belief.py",
            "information_value.py",
        ]
    }
    policy_sources["engineering_execution.py"] = hashlib.sha256(
        (code_root / "execution.py").read_bytes()
    ).hexdigest()
    return {
        "episodes": episodes,
        "report": report.to_dict(),
        "graph": graph.to_dict(),
        "lineage": lineage,
        "source_sha256": digest(episodes),
        "policy_id": POLICY,
        "decision_engine": DECISION_ENGINE,
        "ppo_compatibility": "Not evaluated",
        "policy_checkpoint_sha256": None,
        "policy_implementation_sha256": digest(policy_sources),
        "simulator_version": "EnterpriseCyberEnv/" + implementation_sha256(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "report_id": report.report_id,
        "graph_id": graph.graph_id,
        "evidence_class": "engineering_simulation",
        "research_status": "not_registered",
    }
