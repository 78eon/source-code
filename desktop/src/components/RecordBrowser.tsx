import { useEffect, useState } from "react";
import type { Fact } from "../types";
import { Details } from "./Details";
export function RecordBrowser({
  rows,
  columns,
}: {
  rows: Fact[];
  columns: string[];
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
                  <th key={c}>{c.replaceAll("_", " ")}</th>
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
                      {String(r[columns[0]] ?? "Unknown")}
                    </button>
                  </td>
                  {columns.slice(1).map((c) => (
                    <td key={c}>
                      {r[c] === null || r[c] === undefined
                        ? "Unknown"
                        : typeof r[c] === "object"
                          ? JSON.stringify(r[c])
                          : String(r[c])}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
          {!filtered.length && <p className="empty">No data available</p>}
        </div>
      </section>
      <Details value={selected} />
    </div>
  );
}
