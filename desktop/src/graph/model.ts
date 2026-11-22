import { MultiDirectedGraph } from "graphology";
import type { GraphDTO } from "../types";
export function buildGraph(
  dto: GraphDTO,
  search = "",
  nodeType = "",
  edgeType = "",
) {
  const graph = new MultiDirectedGraph();
  const lanes = [...new Set(dto.nodes.map(n=>String(n.metadata.subnet ?? n.type)))].sort();
  const positions = new Map<string,number>();
  dto.nodes.forEach((n) => {
    if (nodeType && n.type !== nodeType) return;
    const match =
      !!search && n.label.toLowerCase().includes(search.toLowerCase());
    const lane=String(n.metadata.subnet ?? n.type);
    const ordinal=positions.get(lane) ?? 0;
    positions.set(lane,ordinal+1);
    graph.addNode(n.id, {
      x: lanes.indexOf(lane)*3,
      y: -ordinal*2,
      size: match ? 14 : 9,
      highlighted: match,
      label: n.label,
      color: match
        ? "#ffffff"
        : ((
            {
              CONFIRMED: "#72b7a1",
              INFERRED: "#d9ad68",
              OBSERVED: "#72b9e7",
              CONFLICTING: "#e78090",
              UNKNOWN: "#7f9fbe",
              SYNTHETIC: "#b795df",
              FOOTHOLD: "#67d9bd",
              OBJECTIVE: "#f5c46a",
              ACCESSED: "#ee9b89",
            } as Record<string, string>
          )[n.status.toUpperCase()] ?? "#7f9fbe"),
      fact: n,
    });
  });
  dto.edges.forEach((e) => {
    if (!e.type || !e.evidence_refs?.length)
      throw new Error("Relationship lacks semantic type or source evidence");
    if (edgeType && e.type !== edgeType) return;
    if (graph.hasNode(e.source) && graph.hasNode(e.target))
      graph.addEdgeWithKey(e.id, e.source, e.target, {
        label: e.type,
        size: 2,
        color: e.metadata.success === false ? "#e78090" : "#637c92",
        type: "arrow",
        fact: e,
      });
  });
  return graph;
}
