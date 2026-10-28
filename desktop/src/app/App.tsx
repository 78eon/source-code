import { useEffect, useState } from "react";
import { configureOrigin, get } from "../api/client";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { pages, type Page, type Fact, type GraphDTO } from "../types";
import { RecordBrowser } from "../components/RecordBrowser";
import { GraphWorkspace } from "../features/topology/GraphWorkspace";
import { PathExplorer } from "../features/attack-paths/PathExplorer";
import { TwinView, SimulationView } from "../features/RecordedViews";
import {
  ConfigurationView,
  type LocalSettings,
} from "../features/ConfigurationView";
const endpoints: Record<Page, string> = {
  Dashboard: "assets",
  Assets: "assets",
  "Network Graph": "graph/topology",
  Vulnerabilities: "findings",
  "Attack Paths": "attack-paths",
  "Digital Twin": "digital-twin/summary",
  Simulation: "simulations",
  Reports: "reports",
};
export function App() {
  const native = isTauri();
  const [backendReady, setBackendReady] = useState(!native);
  const [startupError, setStartupError] = useState("");
  const [settings, setSettings] = useState<LocalSettings | null>(null);
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
  useEffect(() => {
    if (!native) return;
    let active = true;
    invoke<{ configured: boolean; settings: LocalSettings | null }>(
      "desktop_configuration",
      { operation: "get" },
    )
      .then(async (configuration) => {
        if (!active) return null;
        setSettings(configuration.settings);
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
        const result = await get<unknown>(endpoints[page], token, abort.signal);
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
  }, [page, token, reload, backendReady]);
  const rows = Array.isArray(data) ? (data as Fact[]) : [];
  if (native && showSettings)
    return (
      <ConfigurationView
        initial={settings}
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
        <p className="eyebrow">WORKSPACE</p>
        {pages.map((p) => (
          <button
            key={p}
            aria-current={page === p ? "page" : undefined}
            onClick={() => {
              if (p !== page) {
                setData(null);
                setError("");
                setLoading(true);
                setPage(p);
              }
            }}
          >
            {p}
          </button>
        ))}
        <footer>
          Read-only analyst workspace
          <br />
          No scanning or execution controls
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
        ) : loading ? (
          <p className="empty">Loading recorded evidence…</p>
        ) : error ? (
          <section className="notice" role="alert">
            <h2>Data unavailable</h2>
            <p>{error}</p>
            <p>No fixture or substitute data is displayed.</p>
          </section>
        ) : page === "Network Graph" && data ? (
          <GraphWorkspace data={data as GraphDTO} />
        ) : page === "Dashboard" ? (
          <>
            <div className="cards">
              {[
                ["Recorded graph nodes", data ? rows.length : null],
                ["Critical assets", null],
                [
                  "Services",
                  data
                    ? rows.filter(
                        (r) => String(r.node_type).toLowerCase() === "service",
                      ).length
                    : null,
                ],
                ["Crown-jewel assets", null],
              ].map(([k, v]) => (
                <section className="card" key={String(k)}>
                  <h3>{k}</h3>
                  <strong>{v ?? "—"}</strong>
                  <p>
                    {v === null ? "No data available" : "From stored evidence"}
                  </p>
                </section>
              ))}
            </div>
            <section className="notice">
              <h2>Analyst overview</h2>
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
        ) : (
          <RecordBrowser
            rows={rows}
            columns={
              page === "Assets"
                ? ["id", "node_type", "current_access_level", "evidence_ids"]
                : page === "Vulnerabilities"
                  ? [
                      "id",
                      "asset_id",
                      "vulnerability_id",
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
