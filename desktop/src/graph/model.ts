import { MultiDirectedGraph } from "graphology";
import type { GraphDTO } from "../types";
export function buildGraph(
  dto: GraphDTO,
  search = "",
  nodeType = "",
  edgeType = "",
) {
  const graph = new MultiDirectedGraph();
  const count = dto.nodes.length;
  dto.nodes.forEach((n, i) => {
    if (nodeType && n.type !== nodeType) return;
    if (search && !n.label.toLowerCase().includes(search.toLowerCase())) return;
    const angle = (2 * Math.PI * i) / Math.max(count, 1);
    graph.addNode(n.id, {
      x: Math.cos(angle),
      y: Math.sin(angle),
      size: 9,
      label: n.label,
      color:
        n.status === "CONFIRMED"
          ? "#72b7a1"
          : n.status === "INFERRED"
            ? "#d9ad68"
            : "#7f9fbe",
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
        color: "#637c92",
        type: "arrow",
        fact: e,
      });
  });
  return graph;
}
