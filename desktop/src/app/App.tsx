import { useEffect, useState } from "react";
import { get } from "../api/client";
import { pages, type Page, type Fact, type GraphDTO } from "../types";
import { RecordBrowser } from "../components/RecordBrowser";
import { GraphWorkspace } from "../features/topology/GraphWorkspace";
import { PathExplorer } from "../features/attack-paths/PathExplorer";
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
  const [page, setPage] = useState<Page>("Dashboard"),
    [token, setToken] = useState(""),
    [entry, setEntry] = useState(""),
    [reload, setReload] = useState(0);
  const [data, setData] = useState<unknown>(null),
    [health, setHealth] = useState("OFFLINE"),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(false);
  useEffect(() => {
    const abort = new AbortController();
    setData(null);
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
        if (!abort.signal.aborted) {
          setData(result);
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
  }, [page, token, reload]);
  const rows = Array.isArray(data) ? (data as Fact[]) : [];
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
            onClick={() => setPage(p)}
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
        </header>
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
        {loading ? (
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
                and applicability remain unknown. Recent simulation summaries
                are not yet connected.
              </p>
            </section>
          </>
        ) : page === "Digital Twin" || page === "Simulation" ? (
          <section className="notice">
            <h2>{page} integration</h2>
            <p>{String((data as Fact)?.detail ?? "No data available")}</p>
            <p>
              OBSERVED · INFERRED · CONFIRMED · CONFLICTING · UNKNOWN remain
              distinct. No inference is promoted to confirmation.
            </p>
          </section>
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
                  : ["report_id", "schema_version"]
            }
          />
        )}
      </main>
    </div>
  );
}
