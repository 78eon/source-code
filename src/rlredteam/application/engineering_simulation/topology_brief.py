"""Presentation of configured inventory, independent from episode reconstruction."""

from collections import Counter

from ..assessment_context import UNKNOWN


def describe(section, data):
    scope = data["scope"]
    topology = scope.get("configured_topology", {})
    nodes = {node["id"]: node for node in topology.get("nodes", [])}
    edges = topology.get("edges", [])
    zones = scope["subnets"]
    controls = scope["controls"]
    segmentation = controls.get("firewall_segmentation")
    classification = "Enterprise logical zones" if zones else UNKNOWN
    if len(zones) > 1 and segmentation is True:
        classification = "Segmented enterprise logical topology"
    entries = topology.get("entry_points", [])
    section.heading("Topology Profile")
    section.table(
        ("Property", "Recorded value or classification"),
        [
            ("Environment", scope.get("environment_type") or UNKNOWN),
            ("Topology class", classification),
            ("Systems / logical zones", f"{data['summary']['systems']} / {len(zones)}"),
            ("Assessment Entry Context", ", ".join(entries) or UNKNOWN),
            ("Critical asset", scope.get("critical_asset") or UNKNOWN),
            ("Segmentation", {True: "Enabled", False: "Disabled"}.get(segmentation, UNKNOWN)),
            ("Physical topology", "Not explicitly modelled"),
            (
                "Logical topology",
                "Configured zone membership, hosted services and access relationships",
            ),
            ("Assessment engine", data["decision_engine"]),
        ],
    )
    section.prose(
        "Physical cabling and switch fabric topology are not represented by this simulation. "
        "The entry represents the configured starting condition for the assessment."
    )
    section.heading("Network zones and asset roles")
    groups = scope["devices"]
    rows, panels = [], []
    for i, zone in enumerate(zones):
        members = [g for g in groups if g["subnet"] == i]
        counts = Counter()
        for group in members:
            counts[group["category"]] += group["count"]
            rows.append(
                (
                    zone["label"],
                    group.get("role") or group["category"],
                    group["count"],
                    group.get("criticality") or UNKNOWN,
                    {True: "Public-facing", False: "Internal"}.get(
                        group.get("internet_exposed"), UNKNOWN
                    ),
                )
            )
        panels.append(
            (
                zone["label"],
                zone.get("role") or UNKNOWN,
                ", ".join(f"{count} {category}" for category, count in counts.items()),
            )
        )
    section.table(("Zone", "Asset role", "Count", "Criticality", "Exposure"), rows)
    section.heading("Access and Reachability")
    section.prose(
        "Each row describes an explicit configured relation between two entities. "
        "A pivot relation is a modelled opportunity; administrative access still depends "
        "on the episode state. Omitted pairs have unknown reachability."
    )
    relations = [
        e for e in edges if e["type"] in {"connects", "pivots_to", "blocked", "restricted"}
    ]
    if relations:
        section.table(
            ("Source", "Destination", "Relationship", "Basis"),
            [
                (e["source"], e["target"], e["type"].replace("_", " "), "Configured")
                for e in relations
            ],
        )
    if not any(
        nodes.get(e["source"], {}).get("type") == "network_segment"
        and nodes.get(e["target"], {}).get("type") == "network_segment"
        for e in relations
    ):
        section.prose(
            "Inter-segment reachability is not explicitly represented in retained evidence."
        )
    section.blocks.append(("topology_graph", ("Enterprise Topology Overview", [])))
    containers = {}
    for edge in edges:
        if edge["type"] in {"hosts", "contains"}:
            containers.setdefault(edge["target"], set()).add(edge["source"])
    memberships = {
        e["source"]: nodes.get(e["target"], {}).get("name", UNKNOWN)
        for e in edges
        if e["type"] == "located_in"
    }
    for asset in scope.get("objective_assets", []):
        pending, seen, locations = [asset], set(), set()
        while pending:
            item = pending.pop()
            if item in seen:
                continue
            seen.add(item)
            if item in memberships:
                locations.add(memberships[item])
            pending.extend(containers.get(item, ()))
        name = nodes.get(asset, {}).get("name") or scope.get("critical_asset") or asset
        reached = any(
            event.get("goal_reached") is True and event.get("target") == asset
            for episode in data["recorded_episodes"]
            for event in episode["events"]
        )
        status = (
            "REACHED"
            if reached
            else (
                "NOT REACHED"
                if not data["summary"]["objective_reached"]
                else "Individual outcome not established"
            )
        )
        zone_names = ", ".join(sorted(locations)) or UNKNOWN
        section.prose(f"Crown jewel: {name} ({asset}) | Zone: {zone_names} | {status}")
    section.heading("Topology security interpretation")
    section.prose(
        "Zone membership identifies where a decision took effect. Discovery, current "
        "access and service exposure constrain the decision engine's available actions. "
        "The following progression figures show which opportunities were exercised."
    )
