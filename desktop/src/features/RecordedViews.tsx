import { useState } from "react";
import type { Fact } from "../types";
import { RecordBrowser } from "../components/RecordBrowser";
import { PathExplorer } from "./attack-paths/PathExplorer";

export function TwinView({
  summary,
  entities,
}: {
  summary: Fact;
  entities: Fact[];
}) {
  if (summary.status === "UNAVAILABLE")
    return <p className="empty">No persisted Digital Twin available</p>;
  const counts = (summary.counts ?? {}) as Fact;
  return (
    <>
      <div className="cards">
        {Object.entries({
          ...counts,
          unresolved_conflicts: summary.unresolved_conflicts,
        }).map(([label, count]) => (
          <section className="card" key={label}>
            <h3>{label.replaceAll("_", " ")}</h3>
            <strong>{String(count)}</strong>
          </section>
        ))}
      </div>
      <p>
        Persisted snapshot · Observed, inferred, confirmed, synthetic and
        unresolved facts retain their original status.
      </p>
      <RecordBrowser
        rows={entities}
        columns={[
          "entity_type",
          "id",
          "status",
          "confidence",
          "resolution_state",
          "evidence_ids",
        ]}
      />
    </>
  );
}

export function SimulationView({ data }: { data: Fact }) {
  const [id, setId] = useState("");
  const items = (data.items ?? []) as Fact[];
  const selected = items.find((item) => item.id === id);
  if (data.status === "UNAVAILABLE" || !items.length)
    return (
      <p className="empty">
        {String(data.detail ?? "No recorded simulations available")}
      </p>
    );
  return (
    <>
      <p>
        Read-only replay of recorded report facts. Missing episode outcomes and
        run metadata remain unknown.
      </p>
      <label>
        Recorded simulation
        <select value={id} onChange={(e) => setId(e.target.value)}>
          <option value="">Select a recorded episode</option>
          {items.map((item) => (
            <option key={String(item.id)} value={String(item.id)}>
              {String(item.episode_id)}
            </option>
          ))}
        </select>
      </label>
      <RecordBrowser
        rows={items}
        columns={[
          "episode_id",
          "profile",
          "timestamp",
          "outcome",
          "step_count",
          "path_available",
        ]}
      />
      {selected && (
        <section aria-label="Episode replay">
          <h2>Recorded episode timeline</h2>
          <p>
            Objective observed in recorded facts:{" "}
            {String(selected.objective_observed ?? "unknown")}
          </p>
          <RecordBrowser
            rows={selected.timeline as Fact[]}
            columns={[
              "trajectory_step",
              "simulator_action",
              "target",
              "success",
              "technique_id",
              "knowledge_delta",
            ]}
          />
          <PathExplorer paths={(selected.paths ?? []) as Fact[]} />
        </section>
      )}
    </>
  );
}
