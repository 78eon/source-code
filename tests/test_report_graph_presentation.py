from copy import deepcopy

from rlredteam.application import static_graph
from rlredteam.application.assessment_layout import Document, html, pdf
from rlredteam.application.graph_presentation import ICONS, build_presentation
from rlredteam.application.progression_figures import Link


def test_shared_coordinates_icons_and_disconnected_objective():
    raw = {
        "nodes": [
            {"id": "zone", "name": "Test zone", "type": "network_segment", "attributes": {}},
            {
                "id": "device",
                "name": "Test workstation",
                "type": "host",
                "attributes": {"category": "workstation"},
            },
            {"id": "goal", "name": "Designated objective", "type": "asset", "attributes": {}},
        ],
        "edges": [
            {"source": "device", "target": "zone", "type": "located_in"},
            {"source": "device", "target": "goal", "type": "hosts"},
        ],
        "crown_jewels": ["goal"],
    }
    before = deepcopy(raw)
    presentation = build_presentation(raw)
    assert presentation == build_presentation(dict(raw, nodes=list(reversed(raw["nodes"]))))
    assert len({str(value) for value in ICONS.values()}) == len(ICONS)
    doc = Document("Report", "Simulation", "Context", "Identity", graph_presentation=presentation)
    doc.section("Topology").blocks.append(("topology_graph", ("Topology", [])))
    links = [
        Link("Step 0", "target", "Test workstation | device", "progress"),
        Link("", "", "Designated objective | NOT REACHED", "unreached"),
    ]
    doc.section("Progression").blocks.append(("graph", ("Progression snapshot", links)))
    positions = static_graph.positions(doc)
    shared = next(n for n in presentation["nodes"] if n["id"] == "device")
    assert positions["Test workstation | device"] == (shared["x"], shared["y"])
    svg = static_graph.svg(links, positions)
    assert "<circle " in svg and 'data-icon="workstation"' in svg
    assert 'data-icon="objective"' in svg
    assert svg.count("<path ") == 1  # No invented objective edge.
    assert 'class="link ' not in html(doc)
    assert 'class="zones"' not in html(doc)
    assert pdf(doc).startswith(b"%PDF")
    assert raw == before


def test_snapshot_geometry_uses_one_document_scale():
    doc = Document("Report", "Simulation", "Context", "Identity")
    first = [Link("Step 0", "selected target", "entity-a", "progress")]
    last = first + [Link("Step 1", "selected target", "entity-b", "progress")]
    doc.section("First").blocks.append(("graph", ("Snapshot", first)))
    doc.section("Final").blocks.append(("graph", ("Snapshot", last)))
    layout = static_graph.positions(doc)
    a = static_graph.geometry(first, layout)[2]
    b = static_graph.geometry(last, layout)[2]
    assert a["entity-a"] == b["entity-a"]


def test_provenance_routing_is_deterministic_and_keeps_coordinates():
    from copy import deepcopy

    points = {"a": (40, 40), "b": (180, 200), "obstacle": (110, 120)}
    links = [Link("a", "selected target", "b", "progress"),
             Link("a", "recorded context", "b", "structural")]
    before = deepcopy(points)
    routes = static_graph.provenance_routes(links, points)
    assert routes == static_graph.provenance_routes(links, points)
    assert len(routes) == len(links)
    assert points == before
    assert routes[0][0] == routes[1][0]
    assert routes[0][-1] == routes[1][-1]
