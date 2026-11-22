from rlredteam.application.registered_journey import lifecycle, with_journey


def test_unknown_and_conflicting_tactics_remain_unclassified():
    assert lifecycle({}) == "Unclassified"
    assert lifecycle({"framework_mappings": [{"tactic_name": t} for t in
                     ("Initial Access", "Privilege Escalation")]}) == "Unclassified"
    assert lifecycle({"action_kind":"reporting"}) == "Unclassified"


def test_groups_and_targets_are_descriptive_only():
    rows = [dict(step=i, action_kind="discover_network" if i<8 else "pivot",
                 reward=i, success=i>0, target_entity=str(i%3)) for i in range(28)]
    rows[-1]["goal_reached"] = True
    episode = {"steps": [{"recorded":row} for row in rows]}
    result = with_journey(episode, {})
    groups = result["journey"]["groups"]
    assert groups[0]["last"] == 7
    assert sum(g["count"] for g in groups)==len(rows)
    assert sum(g["reward"] for g in groups)==sum(range(28))
    assert result == with_journey(episode, {})
    assert result["journey"]["review"]["27"]["step"] == 27
    assert "Objective flag recorded" in result["journey"]["notable"]["27"]
    assert result["journey"]["stages"][-1]=="Objective Execution / Impact"
    assert result["topology_context"]["structural_edges"]==[]
    assert result["topology_context"]["target_ids"]==["0","1","2"]
