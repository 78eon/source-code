import { useState } from "react";

const fields = [
  ["targets", "Target VM addresses"],
  ["networks", "Approved lab networks"],
  ["collector", "Collector VM or host"],
  ["interface", "Collector interface"],
  ["gateway", "Lab gateway (optional)"],
  ["ports", "Approved ports and protocols"],
  ["profile", "Approved collection profile"],
  ["scopeFile", "Backend ObservationScope file path"],
  ["authorizationFile", "Backend AuthorizationRecord file path"],
  ["authorizationReference", "Lab approval reference"],
  ["window", "Authorized test window"],
  ["isolation", "Routing and egress isolation evidence"],
  ["stopConditions", "Stop conditions and cleanup procedure"],
] as const;

export function ManualLabSetup() {
  const [values, setValues] = useState<Record<string, string>>({});
  const [plan, setPlan] = useState<Record<string, string> | null>(null);
  return <details>
    <summary>Manual VM setup</summary>
    <p>Enter your own VM details for a local planning checklist. This does not
      authorize a target, configure the backend, validate isolation or start scanning.
      No credentials: enter backend file paths only. Details stay in memory and
      are lost when this view closes.</p>
    <form onSubmit={event => { event.preventDefault(); setPlan({ ...values }); }}>
      <fieldset>
        <legend>Manual lab test details</legend>
        {fields.map(([key, label]) => <label key={key}>{label}
          <textarea autoComplete="off" maxLength={4096} value={values[key] ?? ""}
            onChange={event => {
              setValues(previous => ({ ...previous, [key]: event.target.value }));
              setPlan(null);
            }} />
        </label>)}
      </fieldset>
      <button type="submit">Prepare manual test checklist</button>
      <button type="button" onClick={() => { setValues({}); setPlan(null); }}>Clear VM details</button>
    </form>
    {plan !== null && <section aria-label="Manual VM checklist">
      <h3>Unvalidated operator plan — no execution</h3>
      <p>Configure approved scopes on the backend separately. After your authorized
        manual collection, enter the target, approved ports, timestamp and original
        XML in the offline form below. Backend authorization checks still apply.</p>
      <pre>{JSON.stringify({ kind: "manual-lab-plan", validated: false,
        execution_enabled: false, operator_input: plan }, null, 2)}</pre>
    </section>}
  </details>;
}
