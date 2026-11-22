import { EmptyState } from "../components/EvidenceDisplay";
import { useEffect, useState } from "react";
import { configureOrigin, get } from "../api/client";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { type Page, type Fact, type GraphDTO } from "../types";
import { RecordBrowser } from "../components/RecordBrowser";
import { GraphWorkspace } from "../features/topology/GraphWorkspace";
import { PathExplorer } from "../features/attack-paths/PathExplorer";
import { TwinView, SimulationView } from "../features/RecordedViews";
import { RegisteredResearchView, type RegisteredResults } from "../features/RegisteredResearchView";
import { AssessmentOperations } from "../features/AssessmentOperations";
import { EngineeringSimulations } from "../features/EngineeringSimulations";
import { LabInput } from "../features/LabInput";
import { CanonicalWorkspace } from "../features/CanonicalWorkspace";
import {
  ConfigurationView,
  type LocalSettings,
} from "../features/ConfigurationView";
const navigation = {
  Workspace: ["Dashboard","Registered Research","Simulations"],
  Analysis: ["Evidence","Assets","Network Graph","Vulnerabilities","Attack Paths"],
  System: ["Digital Twin","Simulation","Reports"],
} satisfies Record<string,Page[]>;
const endpoints: Record<Page, string> = {
  Dashboard: "assets",
  "Registered Research": "research/registered-results",
  Simulations: "engineering-simulations/status",
  Evidence: "reports",
  Assets: "assets",
  "Network Graph": "graph/topology",
  Vulnerabilities: "findings",
  "Attack Paths": "attack-paths",
  "Digital Twin": "digital-twin/summary",
  Simulation: "simulations",
  Reports: "reports",
};
export function App() {
  const [assessmentId,setAssessmentId]=useState<string|null>(null);
  const [selectedPublication,setSelectedPublication]=useState<Fact|null>(null);
  const [openTrajectories,setOpenTrajectories]=useState(false);
  const [engineeringTab,setEngineeringTab] = useState<"new"|"saved"|"runs"|"examples">("saved");
  const [showLabInput, setShowLabInput] = useState(false);
  const [showCanonical, setShowCanonical] = useState(false);
  const native = isTauri();
  const [backendReady, setBackendReady] = useState(!native);
  const [startupError, setStartupError] = useState("");
  const [settings, setSettings] = useState<LocalSettings | null>(null);
  const [settingsPath, setSettingsPath] = useState("");
  const [showSettings, setShowSettings] = useState(false);
  const [sessionGeneration, setSessionGeneration] = useState(0);
  const [page, setPage] = useState<Page>("Dashboard"),
    [token, setToken] = useState(""),
    [entry, setEntry] = useState(""),
    [reload, setReload] = useState(0);
  const [data, setData] = useState<unknown>(null),
    [entities, setEntities] = useState<Fact[]>([]),
    [health, setHealth] = useState("OFFLINE"),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(false);
  const [storedGraphs,setStoredGraphs]=useState<number|null>(null);
  const [runtimeState, setRuntimeState] = useState<{state: string; message: string} | null>(null);
  useEffect(() => {
    if (!native) return;
    let active = true;
    invoke<{ configured: boolean; settings: LocalSettings | null; settings_path?: string }>(
      "desktop_configuration",
      { operation: "get" },
    )
      .then(async (configuration) => {
        if (!active) return null;
        setSettings(configuration.settings);
        setSettingsPath(configuration.settings_path ?? "");
        if (!configuration.configured) {
          setShowSettings(true);
          return null;
        }
        return invoke<{ origin: string; token: string }>("backend_session");
      })
      .then((session) => {
        if (!active || !session) return;
        configureOrigin(session.origin);
        setToken(session.token);
        setBackendReady(true);
      })
      .catch((reason: unknown) => {
        if (active)
          setStartupError(
            typeof reason === "string"
              ? reason
              : "Local backend could not start. Check the configured container Python runtime and whether another desktop instance is open.",
          );
      });
    return () => {
      active = false;
    };
  }, [native, sessionGeneration]);
  useEffect(() => {
    if (!backendReady) return;
    const abort = new AbortController();
    setData(null);
    setEntities([]);
    setError("");
    setRuntimeState(null);
    setStoredGraphs(null);
    setLoading(true);
    (async () => {
      try {
        await get("health", token, abort.signal);
        setHealth("DEGRADED");
      } catch {
        if (!abort.signal.aborted) {
          setHealth("OFFLINE");
          setError(
            "Local backend unavailable. Start the presentation API on 127.0.0.1:8765.",
          );
          setLoading(false);
        }
        return;
      }
      try {
        if (page === "Simulations") {setHealth("CONNECTED");return;}
        if (page === "Registered Research") {
          const result = await get<RegisteredResults>(endpoints[page], token, abort.signal);
          if (!abort.signal.aborted) {
            setData(result);
            setHealth(result.status === "AVAILABLE" ? "CONNECTED" : "DEGRADED");
          }
          return;
        }
        if(assessmentId&&["Dashboard","Vulnerabilities","Assets","Attack Paths","Reports","Evidence"].includes(page)){setHealth("CONNECTED");return;}
        const readiness = await get<{state?: string; message?: string; graphs?:number}>("readiness", token, abort.signal);
        if (readiness?.state && readiness.state !== "EVIDENCE_READY") {
          if (!abort.signal.aborted) {
            setRuntimeState({state: readiness.state, message: readiness.message ?? "Evidence not ready"});
            setHealth("DEGRADED");
          }
          return;
        }
        if(!abort.signal.aborted && typeof readiness?.graphs==="number") setStoredGraphs(readiness.graphs);
        const bound=page==="Network Graph"?selectedPublication:null;
        const result = await get<unknown>(endpoints[page]+(bound?"?graph_id="+encodeURIComponent(String(bound.graph_id)):""), token, abort.signal);
        if(bound&&((result as GraphDTO).graph_id!==bound.graph_id||((result as GraphDTO).metadata?.projection as Fact)?.report_id!==bound.report_id)) throw Error("Selected projection unavailable. Add its report ID to the approved selection in Settings and reconnect.");
        const twinEntities =
          page === "Digital Twin"
            ? await get<Fact[]>("digital-twin/entities", token, abort.signal)
            : [];
        if (!abort.signal.aborted) {
          setData(result);
          setEntities(twinEntities);
          setHealth(
            result &&
              typeof result === "object" &&
              "status" in result &&
              result.status === "UNAVAILABLE"
              ? "DEGRADED"
              : "CONNECTED",
          );
        }
      } catch (e) {
        if (!abort.signal.aborted) {
          setHealth("DEGRADED");
          setError(e instanceof Error ? e.message : "Data unavailable");
        }
      } finally {
        if (!abort.signal.aborted) setLoading(false);
      }
    })();
    return () => abort.abort();
  }, [page, token, reload, backendReady,selectedPublication,assessmentId]);
  const rows = Array.isArray(data) ? (data as Fact[]) : [];
  if (native && showSettings)
    return (
      <ConfigurationView
        initial={settings}
        settingsPath={settingsPath}
        onPersisted={(saved, path) => {setSettings(saved); setSettingsPath(path);}}
        startupError={startupError}
        onCancel={() => {
          setShowSettings(false);
          setBackendReady(false);
          setSessionGeneration((n) => n + 1);
        }}
        onSaved={() => {
          setData(null);
          setBackendReady(false);
          setStartupError("");
          setShowSettings(false);
          setSessionGeneration((n) => n + 1);
        }}
      />
    );
  return (
    <div className="shell">
      <nav className="sidebar">
        <div className="brand">
          SECURITY<span>RL / ANALYST</span>
        </div>
        {Object.entries(navigation).map(([group,items])=><div className="nav-group" key={group}><p className="eyebrow">{group}</p>{items.map((p) => (
          <button
            key={p}
            aria-current={page === p ? "page" : undefined}
            onClick={() => {
              setShowLabInput(false);
              setShowCanonical(false);
              if (p !== page) {
                setData(null);
                setError("");
                setLoading(true);
                setOpenTrajectories(false);setPage(p);
              }
            }}
          >
            {p}
          </button>
        ))}</div>)}
        <div className="simulation-subnav" aria-label="Simulation navigation">
          {([["examples","Example Scenarios"],["new","New Simulation"],["saved","Saved Simulations"],["runs","Simulation Runs"]] as const).map(([tab,label]) =>
            <button key={tab} onClick={()=>{setShowCanonical(false);setShowLabInput(false);setEngineeringTab(tab);setPage("Simulations");}}>{label}</button>)}
        </div>
        <footer>
          Analyst workspace
          <br />
          Evidence browsing · Lab collection requires backend authorization and explicit approval
        </footer>
      </nav>
      <main>
        <header>
          <div>
            <p className="eyebrow">SECURITY OPERATIONS · LOCAL DESKTOP</p>
            <h1>{page}</h1>
          </div>
          <span className={"status " + health.toLowerCase()}>{health}</span>
          <button onClick={() => setReload((r) => r + 1)}>Refresh</button>
          <button onClick={() => setShowLabInput((shown) => !shown)}>Test / Lab Input</button>
          <button onClick={() => {setShowCanonical(shown => !shown); setShowLabInput(false);}}>Canonical Evidence</button>
          {native && (
            <button onClick={() => setShowSettings(true)}>Settings</button>
          )}
        </header>
        {native && settings?.profile === "demo" && (
          <p className="notice">
            Demo profile · Only explicitly configured development evidence is
            displayed.
          </p>
        )}
        {!native && (
          <form
            className="connection"
            onSubmit={(e) => {
              e.preventDefault();
              setToken(entry);
              setEntry("");
            }}
          >
            <label>
              Local API token
              <input
                type="password"
                autoComplete="off"
                value={entry}
                onChange={(e) => setEntry(e.target.value)}
                placeholder="Session only — not stored"
              />
            </label>
            <button>Connect</button>
            <small>
              PostgreSQL evidence · Neo4j graph analysis · localhost API
            </small>
          </form>
        )}
        {startupError ? (
          <p role="alert">{startupError}</p>
        ) : !backendReady ? (
          <p className="empty">Starting local backend…</p>
        ) : showCanonical ? (
          <CanonicalWorkspace token={token} />
        ) : showLabInput ? (
          <LabInput token={token} allowOfflineProcessing />
        ) : page === "Simulations" ? (
          <EngineeringSimulations token={token} initialTab={engineeringTab} onSelection={(id,identity)=>{setAssessmentId(id);setSelectedPublication(identity);}} onOperations={id=>{setAssessmentId(id);setPage("Dashboard");}} onGraph={g=>{setSelectedPublication(g);setPage("Network Graph");}} onResearch={()=>{setOpenTrajectories(true);setPage("Registered Research");}} />
        ) : assessmentId&&["Dashboard","Vulnerabilities","Assets","Attack Paths","Reports","Evidence"].includes(page) ? (<AssessmentOperations id={assessmentId} page={page} token={token}/>) : loading ? (
          <p className="empty">Loading recorded evidence…</p>
        ) : error ? (
          <section className="notice" role="alert">
            <h2>Data unavailable</h2>
            <p>{error}</p>
            <p>No fixture or substitute data is displayed.</p>
          </section>
        ) : runtimeState ? (
          <section className="notice" role="status">
            <h2>{runtimeState.state}</h2>
            <p>{runtimeState.message}</p>
            <p>No substitute evidence is displayed. No automatic repair or acquisition was started.</p>
          </section>
        ) : page === "Registered Research" && data ? (
          <RegisteredResearchView openTrajectories={openTrajectories} data={data as RegisteredResults} token={token} />
        ) : page === "Network Graph" && data ? (
          <>{selectedPublication&&<p>Selected assessment: {String(selectedPublication.assessment)} · Report: {String(selectedPublication.report_id)} · Graph: {String(selectedPublication.graph_id)}</p>}<GraphWorkspace key={(data as GraphDTO).graph_id} data={data as GraphDTO} token={token} /></>
        ) : page === "Dashboard" ? (
          <>
            <p>No engineering assessment selected. Open a saved assessment to select its Security Operations workspace.</p><details><summary>Canonical database counters</summary>
            <div className="cards">
              {[
                ["Selected graph-node occurrences", data ? rows.length : null],
                ["Critical assets", null],
                [
                  "Service-node occurrences",
                  data
                    ? rows.filter(
                        (r) => String(r.node_type).toLowerCase() === "service",
                      ).length
                    : null,
                ],
                ["Stored graphs", storedGraphs], ["Recorded finding occurrences", Array.isArray(data) && rows.every(r=>Array.isArray(r.discovered_vulnerabilities)) ? rows.reduce((n,r)=>n+(r.discovered_vulnerabilities as unknown[]).length,0) : null], ["Recorded paths", null],
              ].map(([k, v]) => (
                <section className="card" key={String(k)}>
                  <h3>{k}</h3>
                  <strong>{v ?? "Not available"}</strong>
                  <p>
                    {v === null ? "No data available" : "From stored evidence"}
                  </p>
                </section>
              ))}
            </div>
            </details><section className="notice">
              <p>Counts include node occurrences across selected stored graphs; repeated assets may occur.
                Reads include at most 50 stored graphs/reports. Completeness and truncation are unknown.
                Empty selections do not establish an empty environment.</p>
              <h2>Current workspace</h2><p>Analyst evidence · selected stored reports and graph projections</p>
              <p>
                Explore recorded assets, findings and attack paths. Unknown risk
                and applicability remain unknown. Simulation replay shows stored
                report facts.
              </p>
            </section>
          </>
        ) : page === "Digital Twin" && data ? (
          <TwinView summary={data as Fact} entities={entities} />
        ) : page === "Simulation" && data ? (
          <SimulationView data={data as Fact} />
        ) : page === "Attack Paths" ? (
          <PathExplorer paths={rows} />
        ) : page === "Vulnerabilities" && !rows.length ? <EmptyState>No recorded vulnerability findings are available for the current canonical selection.<br/>This does not establish that the environment is vulnerability-free.</EmptyState> : page === "Assets" && !rows.length ? <EmptyState>No assets are recorded in this selection.</EmptyState> : (
          <RecordBrowser
            rows={rows}
            assessment={page==="Reports"}
            headers={page === "Assets" ? {id:"Asset",node_type:"Type",current_access_level:"Access",evidence_ids:"Evidence"} : page === "Vulnerabilities" ? {vulnerability_id:"ID",asset_id:"Asset",cvss:"CVSS",evidence_refs:"Evidence"} : {}}
            columns={
              page === "Assets"
                ? ["id", "node_type", "current_access_level", "evidence_ids"]
                : page === "Vulnerabilities"
                  ? [
                      "vulnerability_id", "asset_id", "severity",
                      "cvss",
                      "applicability",
                      "evidence_refs",
                    ]
                  : ["report_id", "report_mode", "methodology"]
            }
          />
        )}
      </main>
    </div>
  );
}
