import { useEffect, useRef, useState } from "react";
import Sigma from "sigma";
import type { GraphDTO } from "../../types";
import { buildGraph } from "../../graph/model";
import { Details } from "../../components/Details";
export function GraphWorkspace({ data }: { data: GraphDTO }) {
  const container = useRef<HTMLDivElement>(null);
  const [search, setSearch] = useState(""),
    [nodeType, setNodeType] = useState(""),
    [edgeType, setEdgeType] = useState("");
  const [selected, setSelected] = useState<unknown>(null),
    [error, setError] = useState("");
  useEffect(() => {
    setSelected(null);
    setError("");
    if (!container.current || !data.nodes.length) return;
    let renderer: Sigma | undefined;
    try {
      renderer = new Sigma(
        buildGraph(data, search, nodeType, edgeType),
        container.current,
        {
          renderEdgeLabels: true,
          enableEdgeEvents: true,
          labelColor: { color: "#dbe4ec" },
          defaultEdgeType: "arrow",
        },
      );
      renderer.on("clickNode", ({ node }) =>
        setSelected(data.nodes.find((n) => n.id === node)),
      );
      renderer.on("clickEdge", ({ edge }) =>
        setSelected(data.edges.find((e) => e.id === edge)),
      );
      renderer.on("clickStage", () => setSelected(null));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Graph rendering unavailable");
    }
    return () => renderer?.kill();
  }, [data, search, nodeType, edgeType]);
  return (
    <div className="graph-workspace">
      <aside className="filters">
        <h3>Projection filters</h3>
        <label>
          Search
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Node label"
          />
        </label>
        <label>
          Node type
          <select
            value={nodeType}
            onChange={(e) => setNodeType(e.target.value)}
          >
            <option value="">All types</option>
            {[...new Set(data.nodes.map((n) => n.type))].map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
        </label>
        <label>
          Relationship
          <select
            value={edgeType}
            onChange={(e) => setEdgeType(e.target.value)}
          >
            <option value="">All relationships</option>
            {[...new Set(data.edges.map((e) => e.type))].map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
        </label>
        <p>Neo4j projection · evidence-backed relationships only.</p>
        <p>Unknown and inferred facts are not confirmed facts.</p>
      </aside>
      <section className="canvas-wrap">
        {error && <p role="alert">{error}</p>}
        {!data.nodes.length && <p className="empty">No data available</p>}
        <div className="canvas" ref={container} />
      </section>
      <Details value={selected} />
    </div>
  );
}
