"""Presentation of canonical recorded edges; enrichment carries evidence references."""


def graph_dto(result, view="all"):
    if view not in {
        "all",
        "successful",
        "failed",
        "evidence",
        "vulnerabilities",
        "mitre",
        "attack",
    }:
        raise ValueError("Unsupported graph filter")
    graph = result["graph"]
    edges = graph["edges"]
    if view == "successful":
        edges = [e for e in edges if e["success"]]
    if view == "attack":
        from rlredteam.enterprise.trajectory import reconstruct_attack_path

        steps = {
            (row["run_key"] + ":" + row["episode_uid"], e["step"])
            for episode, row in zip(result["episodes"], result["lineage"])
            for e in reconstruct_attack_path(episode["events"])
        }
        edges = [e for e in edges if (e["episode_id"], e["step"]) in steps]
    if view == "failed":
        edges = [e for e in edges if not e["success"]]
    if view == "vulnerabilities":
        edges = [e for e in edges if e["vulnerability_id"] != "UNKNOWN"]
    if view == "mitre":
        edges = [e for e in edges if e["mitre_mappings"]]
    ids = {n for e in edges for n in (e["source_node"], e["target_node"])}
    nodes = [
        {
            "id": n["node_id"],
            "type": n["node_type"],
            "label": n["node_id"],
            "metadata": n,
            "provenance": n["evidence_ids"],
            "status": (
                "FOOTHOLD"
                if n["node_id"] == "entry"
                else "OBJECTIVE"
                if n["node_type"] == "asset"
                else "ACCESSED"
                if n["current_access_level"] != "UNKNOWN"
                else "SYNTHETIC"
            ),
        }
        for n in graph["nodes"]
        if view == "all" or n["node_id"] in ids
    ]
    converted = [
        {
            "id": e["edge_id"],
            "source": e["source_node"],
            "target": e["target_node"],
            "type": e["relationship_type"],
            "metadata": e,
            "evidence_refs": e["evidence_ids"],
        }
        for e in edges
    ]
    if view == "evidence":
        for item in graph["evidence"]:
            identifier = "evidence:" + item["evidence_id"]
            nodes.append(
                {
                    "id": identifier,
                    "type": "evidence",
                    "label": identifier,
                    "metadata": item,
                    "provenance": [item["evidence_id"]],
                    "status": "SYNTHETIC",
                }
            )
            for e in edges:
                if item["evidence_id"] in e["evidence_ids"]:
                    converted.append(
                        {
                            "id": e["edge_id"] + identifier,
                            "source": e["target_node"],
                            "target": identifier,
                            "type": "SUPPORTED_BY_EVIDENCE",
                            "metadata": {},
                            "evidence_refs": [item["evidence_id"]],
                        }
                    )
    return {
        "source": "engineering-simulation",
        "graph_id": graph["graph_id"],
        "nodes": nodes,
        "edges": converted,
        "metadata": {
            "canonical_graph_id": graph["graph_id"],
            "report_id": graph["report_id"],
            "view": view,
            "total_nodes": len(graph["nodes"]),
            "total_edges": len(graph["edges"]),
            "displayed_nodes": len(nodes),
            "displayed_edges": len(converted),
            "evidence_class": "engineering_simulation",
            "research_status": "not_registered",
            "interpretation": "Observed simulation relationships; not a live route. Evidence links are presentation enrichment.",
        },
    }
