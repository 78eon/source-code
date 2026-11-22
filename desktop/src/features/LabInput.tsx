import { useEffect, useRef, useState } from "react";
import { get, post } from "../api/client";
import { ManualLabSetup } from "./ManualLabSetup";
import { CanonicalWorkspace } from "./CanonicalWorkspace";
import { LiveLabCollection } from "./LiveLabCollection";

type Scope = { scope_id: string; name: string };

export function LabInput({ token, allowOfflineProcessing = false }: { token: string; allowOfflineProcessing?: boolean }) {
  const [scopesLoading, setScopesLoading] = useState(true);
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [scope, setScope] = useState("");
  const [authorization, setAuthorization] = useState("");
  const [target, setTarget] = useState("");
  const [ports, setPorts] = useState("");
  const [collectedAt, setCollectedAt] = useState("");
  const [xml, setXml] = useState("");
  const [error, setError] = useState("");
  const [result, setResult] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [processOffline, setProcessOffline] = useState(false);
  const [importedJobId, setImportedJobId] = useState("");
  const generation = useRef(0);
  useEffect(() => {
    generation.current++;
    const abort = new AbortController();
    setScopesLoading(true);
    setScopes([]);
    setScope("");
    setResult(null);
    setImportedJobId("");
    setBusy(false);
    setError("");
    get<Scope[]>("lab-input/scopes", token, abort.signal)
      .then(value => { if (!abort.signal.aborted) setScopes(value); })
      .catch(() => {
        if (!abort.signal.aborted)
          setError("Offline input unavailable: backend-approved scopes must be configured.");
      })
      .finally(() => { if (!abort.signal.aborted) setScopesLoading(false); });
    return () => { generation.current++; abort.abort(); };
  }, [token]);
  return (
    <section>
      <h2>Test / Lab Input</h2>
      <ManualLabSetup />
      {allowOfflineProcessing && scopes.length > 0 && <LiveLabCollection token={token} />}
      <p>{processOffline ? "Explicit offline import: approved evidence will be persisted. No scanning, exploit or scope expansion." : "Offline XML preview only. No scan, exploit, database write or scope expansion."}</p>
      <form onSubmit={async (event) => {
        event.preventDefault();
        const current = ++generation.current;
        setError(""); setResult(null); setImportedJobId(""); setBusy(true);
        try {
          const entries = ports.split(",").map((value) => value.trim());
          if (entries.some((value) => !/^\d+$/.test(value)))
            throw new Error("Enter comma-separated integer ports.");
          const parsed = entries.map(Number);
          if (parsed.some((value) => value < 1 || value > 65535) || new Set(parsed).size !== parsed.length)
            throw new Error("Enter unique valid ports.");
          const response = await post<{events?: {job_id: string; state: string}[]}>(processOffline ? "workspace/jobs/offline" : "lab-input/preview", token, {
            scope_id: scope, authorization_id: authorization, target,
            ports: parsed, collected_at: collectedAt, xml,
          });
          if (current !== generation.current) return;
          setResult(response);
          const final = response.events?.at(-1);
          if (final?.job_id) {
            setImportedJobId(final.job_id);
            if (final.state !== "COMPLETE") setError(`Import ${final.state}; inspect job status. Earlier evidence may have been retained.`);
          }
        } catch (reason) {
          if (current === generation.current) setError(reason instanceof Error ? reason.message : "Preview rejected");
        } finally { if (current === generation.current) setBusy(false); }
      }}>
        <label>Approved scope<select required value={scope} onChange={(e) => setScope(e.target.value)}>
          <option value="">Select approved scope</option>
          {scopes.map((s) => <option key={s.scope_id} value={s.scope_id}>{s.name}</option>)}
        </select></label>
        <label>Authorization reference<input required value={authorization}
          onChange={(e) => setAuthorization(e.target.value)} autoComplete="off" /></label>
        <label>Target address<input required value={target} onChange={(e) => setTarget(e.target.value)} /></label>
        <label>Permitted ports<input required value={ports} onChange={(e) => setPorts(e.target.value)} /></label>
        <label>Collection timestamp with timezone<input required value={collectedAt}
          onChange={(e) => setCollectedAt(e.target.value)} /></label>
        <label>Nmap XML<textarea required value={xml} onChange={(e) => setXml(e.target.value)} /></label>
        {allowOfflineProcessing && <label>Persist approved offline import
          <input type="checkbox" checked={processOffline} onChange={e => {setProcessOffline(e.target.checked); setResult(null);}} />
        </label>}
        <button disabled={busy || !scopes.length}>{processOffline ? "Process approved offline import" : "Validate offline preview"}</button>
      </form>
      {scopesLoading && <p role="status">Loading approved scopes…</p>}
      {!scopesLoading && !scopes.length && !error && <p>No backend-approved offline scopes available.</p>}
      {error && <p role="alert">{error}</p>}
      {result !== null && <pre aria-label="Preview result">{JSON.stringify(result, null, 2)}</pre>}
      {importedJobId && <CanonicalWorkspace key={importedJobId} token={token} importedJobId={importedJobId} />}
    </section>
  );
}
