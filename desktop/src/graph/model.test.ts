import { describe, it, expect } from "vitest";
import { buildGraph } from "./model";
import type { GraphDTO } from "../types";
const dto: GraphDTO = {
  source: "neo4j",
  graph_id: "fixture",
  nodes: [
    {
      id: "a",
      type: "Asset",
      label: "A",
      metadata: {},
      status: "UNKNOWN",
      provenance: [],
    },
    {
      id: "b",
      type: "Asset",
      label: "B",
      metadata: {},
      status: "INFERRED",
      provenance: [],
    },
  ],
  edges: [
    {
      id: "e",
      source: "a",
      target: "b",
      type: "DISCOVERED",
      metadata: {},
      evidence_refs: ["step:1"],
    },
  ],
};
describe("evidence graph", () => {
  it("preserves semantics and uncertainty", () => {
    const g = buildGraph(dto);
    expect(g.size).toBe(1);
    expect(g.getEdgeAttribute("e", "label")).toBe("DISCOVERED");
    expect(g.getNodeAttribute("b", "fact").status).toBe("INFERRED");
  });
  it("filters without dangling edges", () =>
    expect(buildGraph(dto, "", "Service").size).toBe(0));
  it("highlights search while retaining causal context", () => {
    const graph = buildGraph(dto, "A");
    expect(graph.size).toBe(1);
    expect(graph.getNodeAttribute("a", "highlighted")).toBe(true);
    expect(graph.getNodeAttribute("b", "highlighted")).toBe(false);
  });
  it("rejects unsupported relationships", () =>
    expect(() =>
      buildGraph({ ...dto, edges: [{ ...dto.edges[0], evidence_refs: [] }] }),
    ).toThrow());
});
