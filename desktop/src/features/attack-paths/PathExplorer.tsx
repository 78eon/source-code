import { useState, useEffect } from "react";
import type { Fact } from "../../types";
import { Details } from "../../components/Details";
export function PathExplorer({ paths }: { paths: Fact[] }) {
  const [id, setId] = useState(""),
    [selected, setSelected] = useState<unknown>(null);
  useEffect(() => {
    setId("");
    setSelected(null);
  }, [paths]);
  const path = paths.find((p) => p.graph_id === id);
  const edges = (path?.edges ?? []) as Fact[];
  return (
    <>
      <label>
        Recorded path
        <select
          value={id}
          onChange={(e) => {
            setId(e.target.value);
            setSelected(null);
          }}
        >
          <option value="">Select a stored path</option>
          {paths.map((p) => (
            <option key={String(p.graph_id)} value={String(p.graph_id)}>
              {String(p.graph_id)}
            </option>
          ))}
        </select>
      </label>
      <div className="record-workspace">
        <section>
          <p>
            {path
              ? edges.length + " recorded relationships"
              : "No path selected"}{" "}
            · Recorded order, not a frontend-computed route
          </p>
          {edges.map((edge, i) => (
            <article className="notice" key={String(edge.edge_id ?? i)}>
              <button onClick={() => setSelected(edge)}>
                {String(edge.source_node ?? "Unknown")} →{" "}
                {String(edge.target_node ?? "Unknown")}
              </button>
              <h3>
                {String(edge.relationship_type ?? "Unknown relationship")}
              </h3>
              <p>
                Action: {String(edge.simulator_action ?? "Unknown")} · Access:{" "}
                {String(edge.access_before ?? "Unknown")} →{" "}
                {String(edge.access_after ?? "Unknown")}
              </p>
              <p>
                Step: {String(edge.step ?? "Unknown")} · Service:{" "}
                {String(edge.service ?? "Unknown")} /{" "}
                {String(edge.port ?? "Unknown")} /{" "}
                {String(edge.protocol ?? "Unknown")}
              </p>
              <p>
                CVE: {String(edge.cve_id ?? "Unknown")} · Evidence:{" "}
                {JSON.stringify(edge.evidence_ids ?? [])}
              </p>
              <p>MITRE: {JSON.stringify(edge.mitre_mappings ?? [])}</p>
            </article>
          ))}
          {!paths.length && <p className="empty">No data available</p>}
        </section>
        <Details value={selected ?? path} />
      </div>
    </>
  );
}
