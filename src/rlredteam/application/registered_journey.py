"""Analyst presentation of frozen rows. No simulator imports or topology reconstruction."""

RECON = "Reconnaissance & Planning"
INITIAL = "Initial Access"
MOVEMENT = "Lateral Movement & Privilege Escalation"
OBJECTIVE = "Objective Execution / Impact"
UNCLASSIFIED = "Unclassified"
TACTICS = {"discovery": RECON, "reconnaissance": RECON, "initial access": INITIAL,
           "lateral movement": MOVEMENT, "privilege escalation": MOVEMENT, "impact": OBJECTIVE}


def lifecycle(row):
    if row.get("goal_reached") is True:
        return OBJECTIVE
    kind = row.get("action_kind")
    if kind in {"discover_network", "enumerate_host", "enumerate_service", "enumerate_application",
                "assess_vulnerability"}:
        return RECON
    if kind in {"pivot", "escalate_privilege"}:
        return MOVEMENT
    stages = {TACTICS[tactic] for mapping in row.get("framework_mappings") or []
              if (tactic := str(mapping.get("tactic_name", "")).lower()) in TACTICS}
    return next(iter(stages)) if len(stages) == 1 else UNCLASSIFIED


def describe(events):
    """Groups cover contiguous rows. Keep short changes together; bound uninterrupted groups."""
    groups, notes, seen = [], {}, set()
    previous = None
    for index, row in enumerate(events):
        stage = lifecycle(row)
        mappings = {m["technique_id"] for m in row.get("framework_mappings") or [] if m.get("technique_id")}
        reasons = []
        if previous is None or stage != lifecycle(previous):
            reasons.append("First action in this lifecycle stage range")
        if previous and previous.get("success") is False and row.get("success") is True:
            reasons.append("Recorded success after a failed action")
        if mappings - seen:
            reasons.append("First recorded occurrence of an ATT&CK technique")
        if row.get("goal_reached") is True:
            reasons.append("Objective flag recorded")
        if reasons:
            notes[str(row["step"])] = reasons
        seen.update(mappings)
        if (not groups or groups[-1]["count"] == 16 or
                (groups[-1]["count"] >= 6 and stage != lifecycle(previous))):
            groups.append(dict(offset=index, first=row["step"], count=0, successful=0, failed=0,
                               reward=0, targets=[], techniques=[], stages=[]))
        group = groups[-1]
        group["last"] = row["step"]
        group["count"] += 1
        group["successful"] += row.get("success") is True
        group["failed"] += row.get("success") is False
        group["reward"] += row["reward"]
        for key, values in (("targets", [row.get("target_entity")]), ("techniques", sorted(mappings)),
                            ("stages", [stage])):
            for item in values:
                if item and item not in group[key]:
                    group[key].append(item)
        previous = row
    return {"groups": groups, "notable": notes, "stages": [lifecycle(r) for r in events],
            "rule_version": "registered-journey-v1"}


def defensive_review(row):
    """Questions for a control review, grounded in this action; no measured mitigation effect."""
    evidence = {"step": row["step"], "target": row.get("target_entity"),
                "recorded_action": row.get("simulator_action"), "prerequisites": row.get("prerequisites"),
                "recorded_outcomes": row.get("outcomes")}
    if row.get("success") is not True:
        return dict(evidence, interpretation="This row does not establish successful access.",
                    control_review="No blocking control is identified by the outcome alone.")
    if row.get("goal_reached") is True:
        return dict(evidence, interpretation="The recorded transition satisfied the synthetic objective.",
                    control_review="Review permissions required by the recorded objective transition.",
                    detection_review="Consider auditing successful access to this objective target.")
    if row.get("action_kind") in {"pivot", "authenticate", "access_asset", "escalate_privilege"}:
        return dict(evidence, interpretation="The simulator permitted this transition on the named target.",
                    control_review="Review the recorded access prerequisite against intended access restrictions.",
                    detection_review="Check whether equivalent access transitions would produce an audit event.")
    return dict(evidence, interpretation="This row records a successful simulated action.",
                control_review="A specific control gap is not established.")


def with_journey(episode, topology_limits):
    rows = [s["recorded"] for s in episode["steps"]]
    journey = describe(rows)
    journey["review"] = {str(r["step"]): defensive_review(r) for r in rows
                         if str(r["step"]) in journey["notable"]}
    return dict(episode, journey=journey, topology_context={
        "registered_limits": topology_limits, "structure_status": "Not recorded",
        "target_ids": sorted({r["target_entity"] for r in rows if r.get("target_entity")}),
        "structural_edges": [], "limit_source": "protocol_manifest.json / canonical_protocol.topology"})
