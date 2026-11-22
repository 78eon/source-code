import { Badge } from "../components/EvidenceDisplay";
import { useState } from "react";
import { ResearchTrajectories } from "./ResearchTrajectories";

export interface RegisteredPolicy {
  training_seed: number;
  status: "AVAILABLE" | "UNAVAILABLE";
  detail?: string | null;
  checkpoint_sha256?: string | null;
  policy_sha256?: string | null;
  policy_id?: string | null;
  checkpoint_binding?: string | null;
  validation_topology_count?: number | null;
  successful_episodes?: number | null;
  episode_count?: number | null;
  success_rate?: number | null;
  per_topology_success_rate?: Record<string, number> | null;
  mean_steps_to_success?: number | null;
  median_steps_to_success?: number | null;
  mean_environment_return?: number | null;
  mean_failed_actions?: number | null;
  mean_episode_length?: number | null;
  reward_rise?: boolean | null;
  convergence_passed?: boolean | null;
  final_test_evaluated?: boolean | null;
  source_sha256?: Record<string, string>;
}
export interface RegisteredResults {
  schema_version: "registered-results-v1";
  status: "AVAILABLE" | "PARTIAL" | "UNAVAILABLE";
  read_only: true;
  aggregation: "per_policy";
  protocol_id?: string | null;
  protocol_sha256?: string | null;
  algorithm?: string | null;
  environment_source?: string | null;
  detail?: string | null;
  source_sha256?: Record<string, string>;
  policies: RegisteredPolicy[];
}
const number = (value?: number | null) =>
  typeof value === "number" && Number.isFinite(value) ? String(value) : "Unavailable";
const percent = (value?: number | null) =>
  typeof value === "number" && Number.isFinite(value) ? `${Number((value * 100).toFixed(6))}%` : "Unavailable";
const diagnostic = (value?: boolean | null) => value === true ? "PASS" : value === false ? "FAIL" : "Unavailable";
const metrics = [
  ["mean_steps_to_success", "Mean steps to success"],
  ["median_steps_to_success", "Median successful steps"],
  ["mean_environment_return", "Mean environment return"],
  ["mean_failed_actions", "Mean failed actions"],
  ["mean_episode_length", "Mean episode length"],
] as const;

export function RegisteredResearchView({ data, token="", openTrajectories=false }: { openTrajectories?:boolean; data: RegisteredResults; token?: string }) {
  const [tab,setTab]=useState<"results"|"trajectories">(openTrajectories?"trajectories":"results");
  return <section aria-label="Registered research results">
    <div className="simulation-tabs"><button aria-pressed={tab==="results"} onClick={()=>setTab("results")}>Validation Results</button><button aria-pressed={tab==="trajectories"} onClick={()=>setTab("trajectories")}>PPO Trajectories</button></div>
    {tab==="trajectories"?<ResearchTrajectories token={token}/>:<>
    <h2>Frozen registered campaign</h2>
    <section className="notice" aria-label="RL Intelligence"><h3>RL Intelligence</h3>
    <h4>What PPO Contributed</h4><p>PPO is the learned decision policy used in the registered research campaign. The frozen policy selected sequential simulated actions on unseen validation topologies.</p>
    <h4>Autonomous RL-Driven Attack Path Discovery Workflow</h4>
    <p>Enterprise simulation → observation → valid-action constraints → MaskablePPO → selected action → simulator outcome → reward and new state → next decision → recorded trajectory → defensive review</p>
    <h4>Why use reinforcement learning here?</h4><p>The research question concerns which valid action to select as observed knowledge changes. Training rewards encourage progression toward the simulated objective.</p>
    <p>The engineering and registered PPO workflows use different experimental contracts. Their step counts and outcomes do not constitute a controlled performance comparison.</p>
    </section>
    <dl className="summary-strip"><div><dt>Algorithm</dt><dd>{data.algorithm ?? "Unavailable"}</dd></div><div><dt>Policies listed</dt><dd>{data.policies.length}</dd></div></dl>
    <aside className="notice" aria-label="Where PPO is used">
      <h3>Where PPO is used</h3>
      {data.algorithm === "MaskablePPO" ? <>
        <p>Frozen protocol algorithm: <strong>{data.algorithm}</strong>. Environment source: {data.environment_source ?? "Unavailable from metadata"}.</p>
        <p>Registered synthetic topology distribution → registered simulator → observation + action mask → MaskablePPO policy → simulated action → reward → validation evaluation</p>
        <details><summary>Training and evaluation methodology</summary><ol><li>PPO was used in the registered research campaign.</li>
          <li>MaskablePPO learned policies within the registered simulator/topology distribution.</li>
          <li>The action mask restricts invalid actions.</li>
          <li>The trained policy selects an action from its observation and valid-action mask.</li>
          <li>The simulated environment applies that action.</li>
          <li>During training, the environment returns reward to the agent.</li>
          <li>Frozen policies are evaluated on unseen registered validation topologies.</li>
          <li>The analyst-facing engineering simulator is a separate artefact layer.</li></ol></details>
      </> : <p>Registered algorithm metadata is unavailable. No policy architecture is inferred.</p>}
      <p>This read-only view loads metadata, not policies. No training, checkpoint execution or held-out evaluation is started.</p>
    </aside>
    <p>Per-policy validation results. Topologies within a policy are not independent policy samples.
      No pooled statistic is computed. Validation success and training convergence are separate findings.</p>
    <details><summary>Protocol identity</summary><p>Protocol: {data.protocol_id ?? "Unavailable"} · {data.protocol_sha256 ?? "Unavailable"}</p></details>
    {data.status !== "AVAILABLE" && <p role="status">Research results {data.status.toLowerCase()}. Missing evidence remains unavailable.</p>}
    {data.detail && <p>{data.detail}</p>}
    {!data.policies.length && <p>No registered policy results available.</p>}
    {data.policies.length>0&&<div className="table-wrap"><table><caption>Policy validation summary</caption><thead><tr>{["Seed","Topologies","Success rate","Convergence","Held-out"].map(h=><th key={h}>{h}</th>)}</tr></thead><tbody>{data.policies.map(p=><tr key={p.training_seed}><td>{p.training_seed}</td><td>{number(p.validation_topology_count)}</td><td>{percent(p.success_rate)}</td><td>{diagnostic(p.convergence_passed).toLowerCase()}</td><td><Badge>{p.final_test_evaluated===false?"Pending":p.final_test_evaluated===true?"Evaluated":"Unknown"}</Badge></td></tr>)}</tbody></table></div>}
    {data.policies.map(policy => <section className="notice" key={policy.training_seed} aria-label={`Policy ${policy.training_seed}`}>
      <h3>Policy seed {policy.training_seed}</h3>
      {policy.status === "UNAVAILABLE" ? <p>{policy.detail ?? "Policy evidence unavailable"}</p> : <>
        <details><summary>Policy identifiers</summary><p>Policy SHA256: {policy.policy_sha256 ?? "Unavailable"}</p>
        <p>Content-addressed policy ID: {policy.policy_id ?? "Unavailable"}</p>
        <p>Policy/checkpoint binding: {policy.checkpoint_binding ?? "Unavailable"}</p>
        <p>Checkpoint SHA256: {policy.checkpoint_sha256 ?? "Unavailable"}</p></details>
        <details><summary>Validation metrics and diagnostics</summary><dl>
          <dt>Validation topology count</dt><dd>{number(policy.validation_topology_count)}</dd>
          <dt>Successful episodes / episode count</dt>
          <dd>{number(policy.successful_episodes)}/{number(policy.episode_count)} / {percent(policy.success_rate)}</dd>
          {metrics.map(([field, label]) => <div key={field}><dt>{label}</dt><dd>{number(policy[field])}</dd></div>)}
          <dt>reward_rise</dt><dd>{diagnostic(policy.reward_rise)}</dd>
          <dt>Convergence</dt><dd>{diagnostic(policy.convergence_passed)}</dd>
          <dt>Held-out evaluation</dt><dd>{policy.final_test_evaluated === false ? "Pending / Not Evaluated"
            : policy.final_test_evaluated === true ? "Evaluated (results not supplied by this validation view)" : "Unavailable"}</dd>
        </dl></details>
        <details><summary>Per-topology validation success</summary>
          {policy.per_topology_success_rate && Object.keys(policy.per_topology_success_rate).length
            ? <table><thead><tr><th>Topology</th><th>Success rate</th></tr></thead><tbody>
              {Object.entries(policy.per_topology_success_rate).map(([id, rate]) =>
                <tr key={id}><td>{id}</td><td>{percent(rate)}</td></tr>)}
            </tbody></table> : <p>Per-topology success unavailable.</p>}
        </details>
      </>}
      <details><summary>Policy evidence sources (SHA256)</summary><pre>{JSON.stringify(policy.source_sha256 ?? {}, null, 2)}</pre></details>
    </section>)}
    <details><summary>Campaign evidence sources (SHA256)</summary><pre>{JSON.stringify(data.source_sha256 ?? {}, null, 2)}</pre></details>
    </>}
  </section>;
}
