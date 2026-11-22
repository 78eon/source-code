import { Fields } from "../components/EvidenceDisplay";
import { useEffect, useState } from "react";
import { get } from "../api/client";
import { RecordBrowser } from "../components/RecordBrowser";
import type { Fact } from "../types";

interface Assessment {
  name: string;
  decision_engine?: string;
  summary: Fact;
  findings: Fact[];
  attack_paths?: {path_id: string; step_count: number; outcome: string; steps: Fact[]}[];
  methodology: string[];
  limitations: string[];
  scope: Fact;
  provenance: Fact;
  remediation: Fact;
}

export function SimulationAssessment({id, token}: {id: string; token: string}) {
  const [data, setData] = useState<Assessment | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    const abort = new AbortController();
    setData(null); setError("");
    get<Assessment>(`engineering-simulations/${id}/export/json`, token, abort.signal)
      .then(value => {if (!abort.signal.aborted) setData(value);})
      .catch(reason => {if (!abort.signal.aborted) setError(String(reason));});
    return () => abort.abort();
  }, [id, token]);
  if (error) return <p role="alert">Assessment unavailable: {error}</p>;
  if (!data) return <p role="status">Loading stored assessment…</p>;
  return <section aria-label="Stored simulation assessment">
    <h3>{data.name}</h3>
    <p>Decision Engine: {data.decision_engine ?? "Not available from recorded simulation evidence"}</p>
    <h4>Executive summary</h4>
    <div className="cards">{[
      ["Synthetic systems", "systems"], ["Observed findings", "observed_findings"],
      ["Successful recorded paths", "successful_paths"], ["Objective reached in model", "objective_reached"],
      ["Highest observed severity", "highest_observed_severity"],
    ].map(([label, key]) => <section className="card" key={key}><h4>{label}</h4>
      <strong>{data.summary[key] == null ? "Unavailable" : String(data.summary[key])}</strong></section>)}</div>
    <p>{String(data.summary.posture ?? "Not available from recorded simulation evidence")}</p>
    <h4>Observed findings</h4>
    {data.findings.length ? <RecordBrowser rows={data.findings}
      columns={["finding_id", "host", "service", "severity", "cvss", "synthetic_risk_score", "cve_id"]}/>
      : <p>No vulnerability findings were observed in this recorded simulation.</p>}
    <h4>Attack path</h4>
    {data.attack_paths?.length ? data.attack_paths.map(path=><details key={path.path_id}>
      <summary>{path.step_count} recorded steps · {path.outcome}</summary>
      <RecordBrowser rows={path.steps} columns={["step","action_kind","target","success","reward","evidence_id"]}/>
    </details>) : <p>No recorded path is available in this assessment.</p>}
    <h4>Methodology</h4><ul>{data.methodology.map(item => <li key={item}>{item}</li>)}</ul>
    {([['Scope', data.scope], ['Remediation plan', data.remediation], ['Evidence provenance', data.provenance]] as const)
      .map(([label, value]) => <details key={label}><summary>{label}</summary><Fields value={value}/><details><summary>View raw record</summary><pre>{JSON.stringify(value, null, 2)}</pre></details></details>)}
    <h4>Limitations</h4><ul>{data.limitations.map(item => <li key={item}>{item}</li>)}</ul>
  </section>;
}
