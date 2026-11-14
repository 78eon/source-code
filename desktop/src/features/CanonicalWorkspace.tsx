import { useEffect, useRef, useState } from "react";
import { get } from "../api/client";

const sections = [
  ["jobs", "Assessment / Scope / Jobs"],
  ["assets", "Assets"], ["services", "Services"], ["software", "Software"],
  ["vulnerabilities", "Vulnerability applicability"], ["evidence", "Evidence / History"],
  ["twin", "Digital Twin"], ["graph", "Topology"], ["paths", "Candidate Paths / Scoring"],
  ["advisory", "Planner Advisory"], ["attack", "ATT&CK"],
  ["defenses", "Mitigations / Detection"], ["report", "Report / Provenance"],
] as const;
type Correlation = { correlation_id: string; snapshot_id: string; graph_id: string };

export function CanonicalWorkspace({ token, importedJobId }: { token: string; importedJobId?: string }) {
  const [items, setItems] = useState<Correlation[]>([]);
  const [identifier, setIdentifier] = useState("");
  const [sourceIds, setSourceIds] = useState("");
  const [section, setSection] = useState<string>("assets");
  const [data, setData] = useState<unknown>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const request = useRef<AbortController | null>(null);
  useEffect(() => {
    request.current?.abort(); setData(null); setLoading(false);
    return () => request.current?.abort();
  }, [token, identifier, section, sourceIds, importedJobId]);
  useEffect(() => {
    const controller = new AbortController();
    setItems([]); setData(null); setError(""); setIdentifier("");
    if (importedJobId) return () => controller.abort();
    get<{items: Correlation[]}>("workspace/correlations", token, controller.signal)
      .then(result => { if (!controller.signal.aborted) setItems(result.items); })
      .catch(reason => { if (!controller.signal.aborted) setError(String(reason)); });
    return () => controller.abort();
  }, [token, importedJobId]);
  async function load() {
    request.current?.abort();
    const controller = new AbortController(); request.current = controller;
    setLoading(true); setError(""); setData(null);
    const query = new URLSearchParams();
    sourceIds.split(",").map(x => x.trim()).filter(Boolean).forEach(x => query.append("source_id", x));
    try {
      const path = importedJobId
        ? `workspace/jobs/${encodeURIComponent(importedJobId)}${section === "jobs" ? "" : `/views/${section}?${query}`}`
        : section === "jobs" ? "workspace/jobs" : `workspace/correlations/${encodeURIComponent(identifier)}/${section}?${query}`;
      const result = await get(path, token, controller.signal);
      if (!controller.signal.aborted) setData(result);
    } catch (reason) { if (!controller.signal.aborted) setError(String(reason)); }
    finally { if (!controller.signal.aborted) setLoading(false); }
  }
  return <section aria-label="Canonical evidence workspace">
    <h2>Canonical Evidence Workspace</h2>
    <p>Imported evidence only. Inventory paths are hypotheses, not confirmed compromise routes.
      Heuristic scoring and planner preference remain separate. No execution controls.</p>
    {importedJobId ? <p>Imported assessment: {importedJobId}. Observed inventory and unresolved
      identities are shown separately from resolved Twin assets.</p> : <label>Persisted correlation
      <select aria-label="Persisted correlation" value={identifier} onChange={e => {setIdentifier(e.target.value); setData(null);}}>
        <option value="">Select persisted evidence</option>
        {items.map(item => <option key={item.correlation_id} value={item.correlation_id}>{item.correlation_id}</option>)}
      </select>
    </label>}
    <label>View
      <select aria-label="Canonical view" value={section} onChange={e => {setSection(e.target.value); setData(null);}}>
        {sections.map(([key, label]) => <option key={key} value={key}>{label}</option>)}
      </select>
    </label>
    <label>Persistent source node IDs (comma-separated, required for path analysis)
      <input aria-label="Persistent source node IDs" value={sourceIds} onChange={e => setSourceIds(e.target.value)} />
    </label>
    <button disabled={(!importedJobId && !identifier && section !== "jobs") || loading} onClick={() => void load()}>Load canonical evidence</button>
    {loading && <p role="status">Loading canonical evidence…</p>}
    {error && <p role="alert">{error}. No simulation or substitute data displayed.</p>}
    {!importedJobId && !items.length && !error && <p>No persisted canonical correlations available.</p>}
    {data !== null && <pre aria-label="Canonical evidence details">{JSON.stringify(data, null, 2)}</pre>}
  </section>;
}
