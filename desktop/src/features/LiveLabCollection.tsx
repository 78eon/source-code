import { useEffect, useRef, useState } from "react";
import { get, post } from "../api/client";
import { CanonicalWorkspace } from "./CanonicalWorkspace";

type Configuration = {enabled: boolean; profile?: string; budget?: unknown;
  scopes?: {scope_id: string; name: string; authorization_id: string}[]};
type Plan = {plan_digest: string; scope_validated: boolean; budget: unknown};

export function LiveLabCollection({token}: {token: string}) {
  const [configLoading, setConfigLoading] = useState(true);
  const [configError, setConfigError] = useState("");
  const [config, setConfig] = useState<Configuration | null>(null);
  const [scope, setScope] = useState("");
  const [target, setTarget] = useState("");
  const [ports, setPorts] = useState("");
  const [plan, setPlan] = useState<Plan | null>(null);
  const [approved, setApproved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<unknown>(null);
  const [job, setJob] = useState("");
  const active = useRef<AbortController | null>(null);
  useEffect(() => {
    const abort = new AbortController();
    setConfigLoading(true); setConfigError("");
    setConfig(null); setPlan(null); setApproved(false); setResult(null); setJob("");
    setScope(""); setTarget(""); setPorts(""); setBusy(false); setError("");
    get<Configuration>("workspace/live/configuration", token, abort.signal)
      .then(value => {if (!abort.signal.aborted) setConfig(value);})
      .catch(() => {if (!abort.signal.aborted) setConfigError("Live collection configuration unavailable. Backend request failed.");})
      .finally(() => {if (!abort.signal.aborted) setConfigLoading(false);});
    return () => {abort.abort(); active.current?.abort();};
  }, [token]);
  function invalidate() {setPlan(null); setApproved(false); setError("");}
  async function submit(collect: boolean) {
    const controller = new AbortController(); active.current = controller;
    setBusy(true); setError(""); setResult(null); setJob("");
    try {
      const selected = config?.scopes?.find(item => item.scope_id === scope);
      if (!selected) throw new Error("Select a backend-approved live scope.");
      const entries = ports.split(",").map(value => value.trim());
      if (entries.some(value => !/^\d+$/.test(value))) throw new Error("Enter explicit integer ports.");
      const values = {scope_id: scope, authorization_id: selected.authorization_id,
        target, ports: entries.map(Number), profile: config?.profile};
      if (!collect) {
        const response = await post<Plan>("workspace/live/plan", token, values, controller.signal);
        if (!controller.signal.aborted) {setPlan(response); setApproved(false);}
      } else {
        if (!plan || !approved) throw new Error("Review and approve the backend plan first.");
        const response = await post<{events: {job_id: string; state: string}[]}>("workspace/live/collect", token,
          {...values, plan_digest: plan.plan_digest, operator_approved: approved}, controller.signal);
        if (!controller.signal.aborted) {
          setResult(response); setPlan(null); setApproved(false);
          const last = response.events.at(-1);
          if (last) {setJob(last.job_id); if (last.state !== "COMPLETE") setError(`Collection ${last.state}`);}
        }
      }
    } catch (reason) {
      if (!controller.signal.aborted) setError(String(reason));
    } finally {if (!controller.signal.aborted) setBusy(false);}
  }
  if (configLoading) return <p role="status">Loading live collection configuration…</p>;
  if (configError) return <p role="alert">{configError}</p>;
  if (!config?.enabled) return <p>LIVE_LAB collection is not configured/enabled by the backend. Manual XML import remains available.</p>;
  return <section aria-label="Controlled live lab collection">
    <h3>LIVE_LAB — controlled collection</h3>
    <p>Backend authorization is required. Planning sends no target traffic. Approval confirms one exact plan; it does not grant scope.</p>
    <p>Collector: Nmap TCP connect. Profile: {config.profile}. No exploitation, DNS, discovery sweep or version probes.</p>
    <pre aria-label="Configured collection budget">{JSON.stringify(config.budget, null, 2)}</pre>
    <label>Live approved scope<select disabled={busy} value={scope} onChange={e => {setScope(e.target.value); invalidate();}}>
      <option value="">Select approved live scope</option>
      {config.scopes?.map(item => <option key={item.scope_id} value={item.scope_id}>{item.name}</option>)}
    </select></label>
    <label>Live target address<input disabled={busy} value={target} onChange={e => {setTarget(e.target.value); invalidate();}} /></label>
    <label>Live ports<input disabled={busy} value={ports} onChange={e => {setPorts(e.target.value); invalidate();}} /></label>
    <button disabled={busy || !scope || !target || !ports} onClick={() => void submit(false)}>Validate live plan (no scan)</button>
    {plan && <><p>Scope validated: {String(plan.scope_validated)}. Authorization checked by backend.</p>
      <pre aria-label="Validated live plan">{JSON.stringify(plan, null, 2)}</pre>
      <label>I approve this exact lab collection<input disabled={busy} type="checkbox" checked={approved} onChange={e => setApproved(e.target.checked)} /></label>
      <button disabled={busy || !approved} onClick={() => void submit(true)}>Collect approved inventory</button></>}
    {busy && <><p role="status">Backend operation running…</p><button onClick={() => {
      active.current?.abort(); setBusy(false); invalidate(); setError("Cancellation requested. Inspect Jobs for the backend terminal state.");
    }}>Cancel collection request</button></>}
    {error && <p role="alert">{error}</p>}
    {result !== null && <pre aria-label="Live collection result">{JSON.stringify(result, null, 2)}</pre>}
    {job && <CanonicalWorkspace token={token} importedJobId={job} />}
  </section>;
}
