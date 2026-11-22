import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
export interface LocalSettings {
  version: number;
  profile: "demo" | "analyst";
  postgres: {
    host: string;
    port: number;
    database: string;
    user: string;
    sslmode: string;
  } | null;
  neo4j: { uri: string; database: string; user: string } | null;
  report_ids: string[];
  twin_snapshot: string | null;
}
export const offlineDemo: LocalSettings = {
  version: 1,
  profile: "demo",
  postgres: null,
  neo4j: null,
  report_ids: [],
  twin_snapshot: null,
};
export function ConfigurationView({
  initial,
  onSaved,
  onCancel,
  startupError,
  settingsPath,
  onPersisted,
}: {
  initial: LocalSettings | null;
  onSaved: () => void;
  onCancel: () => void;
  startupError: string;
  settingsPath?: string;
  onPersisted?: (settings: LocalSettings, path: string) => void;
}) {
  const [settings, setSettings] = useState<LocalSettings>(
    initial ?? offlineDemo,
  );
  const [passwords, setPasswords] = useState({ postgres: "", neo4j: "" });
  const [error, setError] = useState(startupError),
    [busy, setBusy] = useState(false),
    [checks, setChecks] = useState("");
  const [diagnosis,setDiagnosis]=useState<{stages:Record<string,string>;reason?:string;projection_count?:number}|null>(null);
  async function diagnose() {
    setBusy(true);setDiagnosis(null);
    try {setDiagnosis(await invoke("desktop_configuration",{operation:"check",payload:{diagnostic:"neo4j"}}));}
    catch {setError("Unable to check the saved Neo4j connection.");}
    finally {setBusy(false);}
  }
  const [savedNotice, setSavedNotice] = useState("");
  async function save(open: boolean) {
    setBusy(true);
    setError("");
    setChecks("");
    setSavedNotice("");
    try {
      const saved = await invoke<{settings: LocalSettings; settings_path: string}>("desktop_configuration", {
        operation: "save",
        payload: { settings, passwords },
      });
      if (!saved.settings || !saved.settings_path) throw "Settings save confirmation is missing. Reopen Settings before checking connections.";
      setSettings(saved.settings);
      onPersisted?.(saved.settings, saved.settings_path);
      setSavedNotice(`Settings saved and read back from ${saved.settings_path}. Neo4j URI: ${saved.settings.neo4j?.uri ?? "not configured"}. Connection results below do not undo this save.`);
      setPasswords({ postgres: "", neo4j: "" });
      if (open) onSaved();
      else {
        const result = await invoke<{
          checks: Record<string, string>;
          offline: boolean;
        }>("desktop_configuration", { operation: "check" });
        setChecks(
          result.offline
            ? "Offline profile validated. No databases were contacted."
            : Object.entries(result.checks)
                .map(([key, value]) => `${key}: ${value}`)
                .join("\n"),
        );
      }
    } catch (reason) {
      setError(
        typeof reason === "string" ? reason : "Configuration validation failed",
      );
    } finally {
      setBusy(false);
    }
  }
  return (
    <main className="setup">
      <p className="eyebrow">SECURITY-RL · LOCAL DESKTOP SETUP</p>
      <h1>Configure your analyst workspace</h1>
      <p>
        Connection details are stored locally. Credentials are protected using the operating system credential store and are not written to application settings.
      </p>
      {error && <p role="alert">{error}</p>}
      <details><summary>Technical details</summary>{settingsPath && <p>Settings file: <code>{settingsPath}</code></p>}
      {savedNotice && <p>{savedNotice}</p>}{checks && <pre role="status">{checks}</pre>}</details>
      <button type="button" disabled={busy} onClick={()=>void diagnose()}>Diagnose saved Neo4j connection</button>
      {diagnosis&&<section aria-label="Neo4j diagnostic"><dl>{Object.entries(diagnosis.stages).map(([k,v])=><div key={k}><dt>{k}</dt><dd>{v}</dd></div>)}</dl>
      <details><summary>Technical diagnostics</summary>{diagnosis.reason??`Readable projections: ${diagnosis.projection_count??0}`}</details></section>}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void save(true);
        }}
      >
        <label>
          Profile
          <select
            value={settings.profile}
            onChange={(e) =>
              setSettings({
                ...settings,
                profile: e.target.value as LocalSettings["profile"],
              })
            }
          >
            <option value="demo">Demo</option>
            <option value="analyst">Analyst</option>
          </select>
        </label>
        <p>
          Demo starts offline unless you configure an external development
          database. No research records or simulated results are bundled or
          fabricated.
        </p>
        <label>
          <input
            type="checkbox"
            checked={!!settings.postgres}
            onChange={(e) =>
              setSettings({
                ...settings,
                postgres: e.target.checked
                  ? {
                      host: "127.0.0.1",
                      port: 5432,
                      database: "security_rl_demo",
                      user: "analyst_reader",
                      sslmode: "disable",
                    }
                  : null,
              })
            }
          />
          Use external PostgreSQL
        </label>
        {settings.postgres && (
          <fieldset>
            <legend>PostgreSQL — read-only account</legend>
            {(["host", "database", "user"] as const).map((key) => (
              <label key={key}>
                PostgreSQL {key}
                <input
                  required
                  value={settings.postgres![key]}
                  onChange={(e) =>
                    setSettings({
                      ...settings,
                      postgres: {
                        ...settings.postgres!,
                        [key]: e.target.value,
                      },
                    })
                  }
                />
              </label>
            ))}
            <label>
              PostgreSQL port
              <input
                type="number"
                min={1}
                max={65535}
                required
                value={settings.postgres.port}
                onChange={(e) =>
                  setSettings({
                    ...settings,
                    postgres: {
                      ...settings.postgres!,
                      port: Number(e.target.value),
                    },
                  })
                }
              />
            </label>
            <label>
              PostgreSQL TLS
              <select
                value={settings.postgres.sslmode}
                onChange={(e) =>
                  setSettings({
                    ...settings,
                    postgres: {
                      ...settings.postgres!,
                      sslmode: e.target.value,
                    },
                  })
                }
              >
                <option value="verify-full">
                  Verify certificate and hostname
                </option>
                <option value="require">
                  Require encryption (loopback only)
                </option>
                <option value="disable">Disabled (loopback only)</option>
              </select>
            </label>
            <label>
              PostgreSQL password
              <input
                type="password"
                autoComplete="new-password"
                value={passwords.postgres}
                onChange={(e) =>
                  setPasswords({ ...passwords, postgres: e.target.value })
                }
              />
            </label>
          </fieldset>
        )}
        <label>
          <input
            type="checkbox"
            checked={!!settings.neo4j}
            onChange={(e) =>
              setSettings({
                ...settings,
                neo4j: e.target.checked
                  ? {
                      uri: "bolt://127.0.0.1:7687",
                      database: "neo4j",
                      user: "analyst_reader",
                    }
                  : null,
              })
            }
          />
          Use external Neo4j
        </label>
        {settings.neo4j && (
          <fieldset>
            <legend>Neo4j — read-only account</legend>
            <p>
              Changing the Neo4j address, database or user requires entering its
              password. A blank password reuses only a credential already saved
              for those exact settings.
            </p>
            {(["uri", "database", "user"] as const).map((key) => (
              <label key={key}>
                Neo4j {key}
                <input
                  required
                  value={settings.neo4j![key]}
                  onChange={(e) =>
                    setSettings({
                      ...settings,
                      neo4j: { ...settings.neo4j!, [key]: e.target.value },
                    })
                  }
                />
              </label>
            ))}
            <label>
              Neo4j password
              <input
                type="password"
                autoComplete="new-password"
                value={passwords.neo4j}
                onChange={(e) =>
                  setPasswords({ ...passwords, neo4j: e.target.value })
                }
              />
            </label>
          </fieldset>
        )}
        <label>
          Approved report IDs (comma separated)
          <input
            value={settings.report_ids.join(",")}
            onChange={(e) =>
              setSettings({
                ...settings,
                report_ids: e.target.value
                  .split(",")
                  .map((v) => v.trim())
                  .filter(Boolean),
              })
            }
          />
        </label>
        <label>
          Existing Digital Twin snapshot (absolute path)
          <input
            value={settings.twin_snapshot ?? ""}
            onChange={(e) =>
              setSettings({
                ...settings,
                twin_snapshot: e.target.value || null,
              })
            }
          />
        </label>
        <button disabled={busy} type="submit">
          Save and open workspace
        </button>{" "}
        <button disabled={busy} type="button" onClick={() => void save(false)}>
          Save and check connections
        </button>{" "}
        <button disabled={busy} type="button" onClick={onCancel}>
          Cancel
        </button>

      </form>
    </main>
  );
}
