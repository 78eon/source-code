import { Fields, Badge, shortId } from "./EvidenceDisplay";
import { useEffect, useState } from "react";
import type { Fact } from "../types";
import { Details } from "./Details";
export function RecordBrowser({
  rows,
  columns,
  headers = {},
  assessment=false,
}: {
  rows: Fact[];
  columns: string[];
  headers?: Record<string,string>;
  assessment?: boolean;
}) {
  const [search, setSearch] = useState(""),
    [selected, setSelected] = useState<Fact | null>(null);
  useEffect(() => setSelected(null), [rows]);
  const filtered = rows.filter((r) =>
    JSON.stringify(r).toLowerCase().includes(search.toLowerCase()),
  );
  return (
    <div className="record-workspace">
      <section>
        <input
          aria-label="Search records"
          placeholder="Search recorded facts…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                {columns.map((c) => (
                  <th key={c}>{headers[c] ?? c.replaceAll("_", " ")}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((r, i) => (
                <tr
                  key={String(r.id ?? r.graph_id ?? r.report_id ?? i)}
                  onClick={() => setSelected(r)}
                >
                  <td>
                    <button
                      className="row-button"
                      onClick={() => setSelected(r)}
                    >
                      <span title={String(r[columns[0]] ?? "")}>{columns[0].endsWith("id") ? shortId(String(r[columns[0]] ?? "Unknown")) : String(r[columns[0]] ?? "Unknown")}</span>
                    </button>
                  </td>
                  {columns.slice(1).map((c) => (
                    <td key={c}>
                      {["severity","node_type","applicability"].includes(c) ? <Badge>{String(r[c] ?? "Unknown")}</Badge> : typeof r[c]==="string" && c==="report_mode" ? String(r[c]) : <Fields value={r[c]}/> }
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
          {!filtered.length && <p className="empty">No data available</p>}
        </div>
      </section>
      {assessment && selected ? <article className="notice" aria-label="Stored assessment preview">
        <h2>Assessment report</h2><Badge>{String(selected.report_mode ?? "Classification unavailable")}</Badge>
        <p>Report ID · <Fields value={selected.report_id}/></p>
        <p>Date · {String(selected.created_at ?? "Not recorded")}</p>
        <h3>Executive summary</h3><Fields value={selected.methodology}/>
        {[["Findings","observed_path_criticality"],["Recorded attack path","phases"],["Remediation","remediation"],["Technical evidence","provenance"]].map(([title,key])=><details key={key}><summary>{title}</summary><Fields value={selected[key]}/></details>)}
        <details><summary>View raw record</summary><pre>{JSON.stringify(selected,null,2)}</pre></details>
      </article> : <Details value={selected} />}
    </div>
  );
}
