from rlredteam.application.assessment_layout import Section
from rlredteam.application.progression_figures import Link, add_figures


def test_snapshots_observe_episode_time_and_source_boundaries():
    rows = [
        dict(
            step=i,
            action_kind=kind,
            success=ok,
            source_node="UNKNOWN",
            target=target,
            knowledge_delta={"observed_edges": edges},
        )
        for i, (kind, ok, target, edges) in enumerate(
            [
                ("discover", True, "a", []),
                ("pivot", False, "b", []),
                ("pivot", True, "b", [("a", "b", "observed")]),
            ]
        )
    ]
    section = Section("progress")
    add_figures(section, rows, {}, "Objective", False, detail=True)
    first, last = [value[1] for kind, value in section.blocks if kind == "graph"]
    assert all(link.right != "b" for link in first)
    assert any(link.kind == "time" for link in last)
    assert any(link.relation == "observed" for link in last)
    assert all("UNKNOWN" not in link.left for link in first + last)
    section = Section("research")
    add_figures(section, rows, {}, "Objective", False, ppo=True)
    links = section.blocks[0][1][1]
    assert all(link.kind != "structural" for link in links)
    assert links[-1].kind == "unreached" and not links[-1].left


def test_objective_retained_after_repeated_access_and_formats_agree():
    from copy import deepcopy

    from rlredteam.application.assessment_layout import Document, html, pdf

    rows = [
        dict(
            step=i,
            action_kind="access_asset",
            target_entity=f"asset-{i}",
            success=True,
            goal_reached=i == 2,
            reward=i,
        )
        for i in range(3)
    ]
    original = deepcopy(rows)
    doc = Document("Report", "Research", "Validation", "Episode")
    section = doc.section("Milestones")
    add_figures(section, rows, {}, "Objective", True, detail=True, ppo=True)
    snapshots = [value for kind, value in section.blocks if kind == "graph"]
    assert len(snapshots) == 2
    assert snapshots[-1][1][-1] == Link(
        "Step 2 | access asset", "objective reached", "asset-2", "objective"
    )
    assert rows == original
    assert '<circle ' in html(doc) and 'data-icon="objective"' in html(doc)
    assert pdf(doc).startswith(b"%PDF")
