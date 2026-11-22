"""Static light-theme export of the shared graph presentation DTO."""

import textwrap
from html import escape

from .graph_presentation import ICONS


class Layout(dict):
    """Coordinates keyed by report label, with canonical entity aliases."""

    nodes = None
    zones = None

    def __init__(self):
        super().__init__()
        self.nodes = {}
        self.zones = []


def positions(document):
    layout = Layout()
    presentation = document.graph_presentation
    canonical = {n["id"]: n for n in presentation.get("nodes", [])}
    for node in canonical.values():
        if node["visible"]:
            label = node["label"] + " | " + node["id"]
            layout[label] = (node["x"], node["y"])
            layout.nodes[label] = node
    layout.zones = presentation.get("zones", [])
    labels = set()
    for section in document.sections:
        for kind, content in section.blocks:
            if kind == "graph":
                for link in content[1]:
                    labels.update(x for x in (link.left, link.right) if x)
    # Alias contextual access-state labels to the same canonical coordinates.
    details = 0
    for label in sorted(labels):
        candidate = next(
            (n for key, n in canonical.items() if key == label or key in label.split(" | ")), None
        )
        if candidate is None:
            candidate = next(
                (n for n in canonical.values() if n["critical"] and n["label"] in label), None
            )
        if candidate:
            if candidate.get("visible"):
                layout[label] = (candidate["x"], candidate["y"])
            else:
                layout[label] = (45 + details % 5 * 100, 570 + details // 5 * 70)
                details += 1
            layout.nodes[label] = candidate
        else:
            i = sum(n["type"] == "event" for n in layout.nodes.values())
            layout[label] = (45 + (i % 5) * 100, 730 + (i // 5) * 70)
            layout.nodes[label] = {
                "id": label,
                "label": label,
                "type": "event",
                "icon": "event",
                "zone": None,
                "critical": False,
            }
    for section in document.sections:
        for kind, content in section.blocks:
            if kind == "graph":
                for link in content[1]:
                    if link.kind in {"objective", "unreached"} and link.right in layout.nodes:
                        layout.nodes[link.right] = dict(
                            layout.nodes[link.right], critical=True, icon="objective"
                        )
    return layout


def scene(links, layout, topology=False):
    active = {x for link in links for x in (link.left, link.right) if x}
    # Include inventory context in every figure with unchanged coordinates.
    labels = [
        label for label, node in layout.nodes.items() if (node.get("visible") or label in active)
    ]
    unique = {}
    for label in labels:
        unique[layout.nodes[label]["id"]] = label
    labels = sorted(unique.values())
    return labels, max((layout[label][1] for label in labels), default=40) + 40


def geometry(links, layout, topology=False):
    labels, height = scene(links, layout, topology)
    factor = min(1, 450 / max((y + 40 for _, y in layout.values()), default=height))
    points = {label: (x, y * factor) for label, (x, y) in layout.items()}
    return labels, height * factor, points


def strokes(icon):
    return ICONS.get(icon, ICONS["workstation"])


def provenance_routes(links, points):
    """Choose side lanes deterministically, penalising node strikes and prior crossings."""
    routes = {}
    occupied = []
    for index, link in sorted(enumerate(links), key=lambda item: (
            points.get(item[1].left, (0, 0))[1], item[1].left, item[1].right, item[0])):
        if not link.left:
            continue
        x, y = points[link.left]
        a, b = points[link.right]
        candidates = []
        # Vertical hierarchy gets top/bottom anchors; lateral links get side anchors.
        for lane in (0, -30, 30, -65, 65, -105, 105):
            if abs(b-y) > abs(a-x):
                direction = 1 if b > y else -1
                start, end = (x, y+13*direction), (a, b-13*direction)
                middle = (x+a)/2+lane
                controls = (middle, start[1]+(b-y)*.3), (middle, end[1]-(b-y)*.3)
            else:
                direction = 1 if a > x else -1
                start, end = (x+13*direction, y), (a-13*direction, b)
                controls = (start[0]+(a-x)*.35, y+lane), (end[0]-(a-x)*.35, b+lane)
            curve = (start, *controls, end)
            samples = []
            for n in range(25):
                t = n/24
                samples.append(tuple((1-t)**3*start[d]+3*(1-t)**2*t*controls[0][d]
                                     +3*(1-t)*t*t*controls[1][d]+t**3*end[d]
                                     for d in (0, 1)))
            strikes = sum((px-nx)**2+(py-ny)**2 < 19**2
                          for key, (nx, ny) in points.items()
                          if key not in (link.left, link.right)
                          for px, py in samples[2:-2])
            strikes += sum(px < 15 or px > 508 or py < 15 or py > max(v[1] for v in points.values())+30 for px, py in samples)
            crossings = 0
            for p, q in zip(samples, samples[1:]):
                for u, v in occupied:
                    def side(origin, end, point):
                        return ((end[0]-origin[0])*(point[1]-origin[1])
                                -(end[1]-origin[1])*(point[0]-origin[0]))
                    crossings += side(p,q,u)*side(p,q,v) < 0 and side(u,v,p)*side(u,v,q) < 0
            candidates.append((strikes*100+crossings*8+abs(lane)*.015, curve, samples))
        _, curve, samples = min(candidates, key=lambda candidate: candidate[0])
        routes[index] = curve
        occupied.extend(zip(samples, samples[1:]))
    return routes


def provenance_labels(labels, links, layout, points):
    """Reserve readable two-line labels for active entities and the objective."""
    active = {x for link in links for x in (link.left, link.right) if x}
    boxes, result = [], {}
    ordered = sorted(labels, key=lambda label: (
        not layout.nodes[label]["critical"], label not in active, label))
    for label in ordered:
        node = layout.nodes[label]
        if label not in active and not node["critical"]:
            continue
        lines = textwrap.wrap(node["label"].replace(" | ", " "), 17)[:2]
        x, y = points[label]
        for shift in (0, 12, -45, 24):
            box = (x-29, y+17+shift, x+29, y+17+shift+8*len(lines))
            if box[1] < 12 or box[3] > max(p[1] for p in points.values())+33:
                continue
            if any(box[0] < b[2] and box[2] > b[0] and
                   box[1] < b[3] and box[3] > b[1] for b in boxes):
                continue
            if any(box[0]-2 < nx < box[2]+2 and box[1]-10 < ny < box[3]+10
                   for key, (nx, ny) in points.items() if key != label):
                continue
            boxes.append(box)
            result[label] = (lines, shift)
            break
    return result


def svg(links, layout, topology=False, provenance=False):
    labels, height, points = geometry(links, layout, topology)
    routes = provenance_routes(links, points) if provenance else {}
    label_plan = provenance_labels(labels, links, layout, points) if provenance else {}
    active = {x for link in links for x in (link.left, link.right) if x}
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Evidence '
        f'graph" viewBox="0 0 523 {height}">'
    ]
    for zone in layout.zones:
        members = [
            points[label]
            for label in labels
            if layout.nodes[label].get("zone") == zone["id"] and layout.nodes[label].get("visible")
        ]
        if members:
            x, y = min(p[0] for p in members) - 29, min(p[1] for p in members) - 31
            w, h = max(p[0] for p in members) - x + 30, max(p[1] for p in members) - y + 36
            out.append(
                f'<rect class="zone-hull" x="{x}" y="{y}" width="{w}" height="{h}" rx="25" '
                f'fill="#f4f8f8" stroke="#c2d4d1"/><text x="{x+8}" y="{y+11}" font-size="8">'
                f'{escape(zone["label"])}</text>'
            )
    for i, link in enumerate(links):
        if not link.left:
            continue
        x, y = points[link.left]
        a, b = points[link.right]
        lane = 12 + (i % 3) * 5
        if provenance:
            start, c1, c2, end = routes[i]
            x, y = start
            a, b = end
            path = f"M{x},{y} C{c1[0]},{c1[1]} {c2[0]},{c2[1]} {a},{b}"
        else:
            path = f"M{x+13},{y} C{x+lane},{y} {a-lane},{b} {a-13},{b}"
        dash = ' stroke-dasharray="4 4"' if link.kind == "time" else ""
        out.append(
            f'<path d="{path}" fill="none" '
            f'stroke="#628b82"{dash}><title>{escape(link.relation)}</title></path>'
        )
    for label in labels:
        n = layout.nodes[label]
        x, y = points[label]
        opacity = "1" if topology or label in active or n["critical"] else ".35"
        out.append(
            f'<g class="graph-node" data-entity="{escape(n["id"],quote=True)}" '
            f'opacity="{opacity}"><title>{escape(label)}</title><circle cx="{x}" cy="{y}" '
            f'r="13" fill="white" stroke="{"#a97821" if n["critical"] else "#236a60"}"/>'
        )
        for stroke in strokes(n["icon"]):
            coords = " ".join(f"{x+a*.8},{y+b*.8}" for a, b in stroke)
            out.append(
                f'<polyline data-icon="{n["icon"]}" points="{coords}" fill="none" '
                f'stroke="#28594f" stroke-width="1.2"/>'
            )
        text = n["label"]
        if n["type"] == "event":
            text = text.replace(" | ", " ")
        lines, shift = label_plan.get(label, ([], 0)) if provenance else (textwrap.wrap(text, 17)[:2], 0)
        for index, line in enumerate(lines):
            out.append(
                f'<text x="{x}" y="{y+23+index*8+shift}" text-anchor="middle" font-size="6.5">'
                f'{escape(line)}</text>'
            )
        out.append("</g>")
    return "".join(out) + "</svg>"


def pdf_commands(links, layout, top, draw, commands, topology=False, provenance=False):
    labels, height, points = geometry(links, layout, topology)
    routes = provenance_routes(links, points) if provenance else {}
    label_plan = provenance_labels(labels, links, layout, points) if provenance else {}
    active = {x for link in links for x in (link.left, link.right) if x}
    for zone in layout.zones:
        members = [
            points[label]
            for label in labels
            if layout.nodes[label].get("zone") == zone["id"] and layout.nodes[label].get("visible")
        ]
        if members:
            x, y = min(p[0] for p in members) - 25, min(p[1] for p in members) - 28
            w, h = max(p[0] for p in members) - x + 26, max(p[1] for p in members) - y + 31
            # Elliptical soft boundary, never an asset card.
            cx, cy, rx, ry = x + w / 2 + 36, top - y - h / 2, w / 2, h / 2
            commands.append(
                f"q 0.95 0.98 0.97 rg 0.8 0.86 0.84 RG {cx+rx} {cy} m {cx+rx} {cy+ry*.552} "
                f"{cx+rx*.552} {cy+ry} {cx} {cy+ry} c {cx-rx*.552} {cy+ry} {cx-rx} "
                f"{cy+ry*.552} {cx-rx} {cy} c {cx-rx} {cy-ry*.552} {cx-rx*.552} {cy-ry} {cx} "
                f"{cy-ry} c {cx+rx*.552} {cy-ry} {cx+rx} {cy-ry*.552} {cx+rx} {cy} c B Q"
            )
            draw(zone["label"], x + 44, top - y + 2, 8, True)
    for i, link in enumerate(links):
        if not link.left:
            continue
        x, y = points[link.left]
        a, b = points[link.right]
        x, a, y, b = x + 36, a + 36, top - y, top - b
        lane = 18 + (i % 3) * 5
        dash = "[3 3] 0 d" if link.kind == "time" else "[] 0 d"
        if provenance:
            start, c1, c2, end = routes[i]
            commands.append(
                f"q 0.38 0.55 0.51 RG {dash} {start[0]+36} {top-start[1]} m "
                f"{c1[0]+36} {top-c1[1]} {c2[0]+36} {top-c2[1]} "
                f"{end[0]+36} {top-end[1]} c S Q")
        else:
            commands.append(
                f"q 0.38 0.55 0.51 RG {dash} {x+13} {y} m {x+lane} {y} "
                f"{a-lane} {b} {a-13} {b} c S Q")
    for label in labels:
        n = layout.nodes[label]
        x, y = points[label]
        x, y = x + 36, top - y
        r, k = 13, 7.18
        color = (
            "0.65 0.45 0.12"
            if n["critical"]
            else "0.14 0.42 0.38"
            if topology or label in active
            else "0.65 0.74 0.71"
        )
        commands.append(
            f"q 1 1 1 rg {color} RG {x+r} {y} m {x+r} {y+k} {x+k} {y+r} {x} {y+r} c {x-k} "
            f"{y+r} {x-r} {y+k} {x-r} {y} c {x-r} {y-k} {x-k} {y-r} {x} {y-r} c {x+k} "
            f"{y-r} {x+r} {y-k} {x+r} {y} c B Q"
        )
        for stroke in strokes(n["icon"]):
            path = " ".join(
                f"{x+a*.8} {y-b*.8} " + ("m" if i == 0 else "l") for i, (a, b) in enumerate(stroke)
            )
            commands.append(f"q {color} RG 1 w {path} S Q")
        lines, shift = label_plan.get(label, ([], 0)) if provenance else (
            textwrap.wrap(n["label"].replace(" | ", " "), 17)[:2], 0)
        for index, line in enumerate(lines):
            draw(line, x - 29, y - 23 - index * 8 - shift, 6.2)
    return height
