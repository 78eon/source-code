"""Read-only selected engineering workspace joined to authoritative PostgreSQL evidence."""

from collections import Counter

from .report import assessment


def summary(service, identifier, repository):
    record, result = service.get(identifier), service.result(identifier)
    reports = repository.attack_path_reports(report_ids=[result["report_id"]])
    graphs = repository.causal_attack_graphs(report_ids=[result["report_id"]])
    report = next((r for r in reports if r["report_id"] == result["report_id"]), None)
    graph = next((g for g in graphs if g["graph_id"] == result["graph_id"]), None)
    if report is None or graph is None:
        return {"state": "assessment_not_published", "simulation_id": identifier}
    if graph["report_id"] != result["report_id"] or report != result["report"]:
        raise ValueError("Published report differs from selected stored assessment")
    facts = list({(f["episode_id"], f["trajectory_step"]): f for f in report["facts"]}.values())
    # Findings are saved synthetic assignments whose assessment exists in database facts.
    assessed = {
        f["target"] for f in facts if f["success"] and f["action_kind"] == "assess_vulnerability"
    }
    data = assessment(record, result)
    findings = [f for f in data["findings"] if f["target"] in assessed]
    nodes = {n["node_id"]: n for n in graph["nodes"]}
    topology = record["topology"]
    names = {n["id"]: n["name"] for n in topology["nodes"]}
    critical_hosts = set(topology["crown_jewels"])
    for _ in topology["nodes"]:
        for edge in topology["edges"]:
            if edge["type"] in {"hosts", "contains"} and edge["target"] in critical_hosts:
                critical_hosts.add(edge["source"])
    assets = []
    for n in topology["nodes"]:
        if n["type"] != "host":
            continue
        observed = nodes.get(n["id"])
        assets.append(
            {
                "id": n["id"],
                "name": n["name"],
                **n["attributes"],
                "observed": observed is not None,
                "access": observed["current_access_level"] if observed else "Not recorded",
                "critical": n["id"] in critical_hosts,
                "evidence": observed["evidence_ids"] if observed else [],
            }
        )
    for f in findings:
        f["host_label"] = names.get(f["host"], f["host"])
    return {
        "state": "available",
        "identity": {
            "simulation_id": identifier,
            "report_id": result["report_id"],
            "graph_id": result["graph_id"],
            "runs": result["lineage"],
        },
        "name": record["specification"]["name"],
        "engine": result["decision_engine"],
        "configured": {
            "systems": len(assets),
            "zones": len(record["specification"]["subnets"]),
            "services": sum(n["type"] == "service" for n in topology["nodes"]),
            "critical_assets": [
                {"id": n["id"], "name": n["name"]}
                for n in topology["nodes"]
                if n["id"] in topology["crown_jewels"]
            ],
            "controls": record["specification"]["controls"],
        },
        "observed": {
            "hosts": sum(n["node_type"] == "host" for n in nodes.values()),
            "services": sum(n["node_type"] == "service" for n in nodes.values()),
            "findings": len(findings),
            "severity": dict(Counter(f["severity"] for f in findings)),
            "evidence": len(graph["evidence"]),
        },
        "episode": {
            "actions": len(facts),
            "successful": sum(f["success"] is True for f in facts),
            "failed": sum(f["success"] is False for f in facts),
            "objective_reached": any(f["crown_jewel_objective"] for f in facts),
            "final_event": facts[-1]["action_kind"] if facts else None,
        },
        "findings": findings,
        "assets": assets,
        "progression": facts,
        "sources": {
            "observed": "PostgreSQL selected report and causal graph",
            "configured": "Hash-verified saved simulation",
            "findings": "Saved synthetic assignments matched to PostgreSQL assessment facts",
        },
    }
