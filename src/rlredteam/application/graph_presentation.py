"""Derived graph display DTO. No source records are modified."""

import re

# Vector strokes in a 20 by 20 viewport, shared by SVG, PDF and the desktop DTO.
ICONS = {
    "workstation": [
        [(-8, -6), (8, -6), (8, 4), (-8, 4), (-8, -6)],
        [(0, 4), (0, 8)],
        [(-5, 8), (5, 8)],
    ],
    "web": [[(-7, 0), (7, 0)], [(0, -8), (0, 8)], [(-6, -6), (6, 6)], [(-6, 6), (6, -6)]],
    "application": [
        [(-7, -7), (7, -7), (7, -1), (-7, -1), (-7, -7)],
        [(-7, 2), (7, 2), (7, 8), (-7, 8), (-7, 2)],
    ],
    "identity": [
        [(-6, -5), (-3, -8), (0, -5), (-3, -2), (-6, -5)],
        [(-3, -2), (5, 6), (8, 3)],
        [(3, 4), (6, 1)],
    ],
    "file": [[(-8, -5), (-2, -5), (0, -2), (8, -2), (8, 7), (-8, 7), (-8, -5)]],
    "database": [
        [
            (-7, -5),
            (-3, -8),
            (3, -8),
            (7, -5),
            (3, -2),
            (-3, -2),
            (-7, -5),
            (-7, 5),
            (-3, 8),
            (3, 8),
            (7, 5),
            (7, -5),
        ],
        [(-7, 1), (-3, 4), (3, 4), (7, 1)],
    ],
    "security": [
        [(-7, -6), (0, -9), (7, -6), (6, 3), (0, 9), (-6, 3), (-7, -6)],
        [(-3, 0), (0, 3), (4, -3)],
    ],
    "service": [[(-7, -5), (7, -5)], [(-7, 0), (7, 0)], [(-7, 5), (7, 5)]],
    "event": [[(2, -9), (-5, 1), (1, 1), (-2, 9), (6, -2), (0, -2), (2, -9)]],
    "finding": [[(0, -9), (9, 7), (-9, 7), (0, -9)], [(0, -3), (0, 2)], [(0, 4), (0, 5)]],
    "objective": [
        [
            (0, -9),
            (2, -3),
            (9, -3),
            (4, 1),
            (6, 8),
            (0, 4),
            (-6, 8),
            (-4, 1),
            (-9, -3),
            (-2, -3),
            (0, -9),
        ]
    ],
    "zone": [[(-7, -7), (7, -7), (7, 7), (-7, 7), (-7, -7)]],
}


def classify(node):
    attributes = node.get("attributes", node.get("metadata", {}))
    kind = str(attributes.get("category", node.get("type", ""))).lower()
    role = str(attributes.get("role", "")).lower()
    if node.get("status") == "OBJECTIVE" or attributes.get("crown_jewel"):
        return 5, "objective"
    if node.get("type") == "entry_point" or attributes.get("internet_exposed"):
        return 0, "web"
    if re.search("security|monitor|firewall", kind + role):
        return 6, "security"
    if re.search("identity|admin|privileged|jump", kind + role):
        return 2, "identity"
    for pattern, tier, icon in [
        ("database", 4, "database"),
        ("file", 3, "file"),
        ("web", 3, "web"),
        ("application|server", 3, "application"),
        ("workstation|laptop", 1, "workstation"),
        ("service", 3, "service"),
        ("event|action", 3, "event"),
        ("finding|vulnerab", 3, "finding"),
        ("identity", 2, "identity"),
        ("segment|zone", 0, "zone"),
    ]:
        if re.search(pattern, kind):
            return tier, icon
    return 7, "workstation"


def build_presentation(topology):
    raw = topology.get("nodes", [])
    edges = topology.get("edges", [])
    crowns = set(topology.get("crown_jewels", []))
    membership = {e["source"]: e["target"] for e in edges if e["type"].lower() == "located_in"}
    for _ in raw:
        changed = False
        for edge in edges:
            if (
                edge["type"].lower() in {"hosts", "contains", "yields_credential"}
                and edge["source"] in membership
                and edge["target"] not in membership
            ):
                membership[edge["target"]] = membership[edge["source"]]
                changed = True
        if not changed:
            break
    zones = sorted((n for n in raw if n["type"] == "network_segment"), key=lambda n: n["id"])
    zone_index = {n["id"]: i for i, n in enumerate(zones)}
    counts = {}
    nodes = []
    for item in sorted(raw, key=lambda n: (membership.get(n["id"], ""), classify(n)[0], n["id"])):
        node = dict(item, status="OBJECTIVE" if item["id"] in crowns else item.get("status"))
        tier, icon = classify(node)
        zone = membership.get(node["id"])
        zi = zone_index.get(zone, len(zones))
        slot = counts.get(zone, 0)
        counts[zone] = slot + 1
        visible = item["type"] in {"host", "entry_point"} or item["id"] in crowns
        # Space hidden detail nodes separately; they do not spread the primary inventory.
        if visible:
            ordinal = sum(n["visible"] and n["zone"] == zone for n in nodes)
            x = 54 + (zi % 2) * 250 + (ordinal % 3) * 66
            y = 60 + (zi // 2) * 175 + (ordinal // 3) * 49
        else:
            x = 44 + (zi % 2) * 250 + (slot % 4) * 54
            y = 65 + (zi // 2) * 175 + (slot // 4) * 42
        nodes.append(
            {
                "id": node["id"],
                "label": node.get("name", node.get("label", node["id"])),
                "type": node["type"],
                "zone": zone,
                "tier": tier,
                "icon": icon,
                "critical": node["id"] in crowns,
                "visible": visible,
                "x": x,
                "y": y,
            }
        )
    return {
        "version": "security-rl-graph-presentation-v1",
        "nodes": nodes,
        "zones": [{"id": z["id"], "label": z["name"]} for z in zones],
        "edges": edges,
        "icons": ICONS,
    }
