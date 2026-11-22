"""Read-only presentation of recorded milestones. Each diagram row is a typed edge."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Link:
    left: str
    relation: str
    right: str
    kind: str


def milestones(rows):
    seen = set()
    selected = []
    for row in rows:
        kind = row.get("action_kind")
        if row.get("success") is True and (
            kind not in seen or row.get("goal_reached") or row is rows[-1]
        ):
            selected.append(row)
            seen.add(kind)
    return selected


def add_figures(section, rows, names, objective, reached, *, detail=False, ppo=False):
    def label(key):
        if not key or str(key).upper() == "UNKNOWN":
            return ""
        name = names.get(key)
        return f"{name} | {key}" if name and name != key else str(key)

    selected = milestones(rows)
    overview = []
    previous = None
    structural = []
    selected_steps = {r["step"] for r in selected}
    for row in rows:
        delta = row.get("knowledge_delta") or {}
        for left, right, relation in delta.get("observed_edges", ()):
            if label(left) and label(right) and not ppo:
                structural.append((left, right, relation))
        if row["step"] not in selected_steps:
            continue
        action = row["action_kind"].replace("_", " ")
        event = f"Step {row['step']} | {action}"
        target = row.get("target_entity") or row.get("target")
        discovery = action.startswith(("discover", "enumerate"))
        kind = "objective" if row.get("goal_reached") else "discovery" if discovery else "progress"
        edge = Link(
            event,
            "objective reached" if kind == "objective" else "selected target",
            label(target) or "Target not recorded",
            kind,
        )
        overview.append(edge)
        local = []
        if previous:
            local.append(Link(previous, "next recorded stage", event, "time"))
        source = label(row.get("source_node"))
        if source and not ppo:
            local.append(Link(source, "recorded source", event, "structural"))
        local.append(edge)
        discoveries = delta.get("discovered_nodes") or []
        related = next((item for item in reversed(structural) if target in item[:2]), None)
        if related:
            a, b, rel = related
            local.append(Link(label(a), rel.replace("_", " "), label(b), "structural"))
        if discoveries:
            entity = next((item for item in discoveries if label(item)), None)
            if entity:
                local.append(Link(event, "revealed", label(entity), "discovery"))
        changes = delta.get("access_changes") or []
        if changes:
            asset, access = changes[0]
            local.append(Link(event, "access change", f"{label(asset)} | {access}", "progress"))
        if detail:
            section.heading(event)
            section.prose(
                f"The recorded {action} action succeeded. Its target was {edge.right}. "
                f"State change: {flag(row.get('state_changed'))}."
            )
            if discoveries:
                section.prose(
                    f"This action added {len(discoveries)} entities to recorded knowledge. "
                    "The snapshot includes a local example."
                )
            if changes:
                section.prose(
                    f"The recorded transition changed access on {label(asset)} to {access}."
                )
            if row.get("goal_reached"):
                section.prose(
                    f"The simulator recorded objective completion and reward {row.get('reward')}."
                )
            elif not discoveries and not changes and row.get("state_changed") is True:
                section.prose("The simulator recorded a change in state at this step.")
            elif not discoveries and not changes:
                section.prose("A successful return alone does not establish a new access level.")
            section.blocks.append(("graph", ("Progression snapshot", local)))
        elif related and discovery:
            overview.append(Link(label(a), rel.replace("_", " "), label(b), "structural"))
        previous = event
    if not detail:
        if objective and not reached:
            overview.append(Link("", "", f"{objective} | NOT REACHED", "unreached"))
        section.blocks.append(("graph", ("Recorded milestones in episode order", overview)))
        if rows:
            last = rows[-1]
            action = last.get("simulator_action") or last["action_kind"]
            section.prose(f"The record ends at step {last['step']} with {action}.")
            if reached is False:
                section.prose(
                    "No evidence-supported continuation to the designated "
                    "critical asset was recorded."
                )


def flag(value):
    return {True: "yes", False: "no"}.get(value, "not recorded")
