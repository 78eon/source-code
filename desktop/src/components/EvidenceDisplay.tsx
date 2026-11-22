import { useState, type ReactNode } from "react";

export function Badge({children}: {children: ReactNode}) {
  return <span className="analyst-badge">{children}</span>;
}

export function EmptyState({children}: {children: ReactNode}) {
  return <p className="empty">{children}</p>;
}

export function shortId(id: string) {
  return id.length > 22 ? id.slice(0, 10) + "…" + id.slice(-6) : id;
}

export function Identifier({id}: {id: string}) {
  const [feedback, setFeedback] = useState("");
  return <span className="identifier"><code title={id}>{shortId(id)}</code>{" "}
    <button aria-label={"Copy " + id} onClick={async () => {
      try { await navigator.clipboard.writeText(id); setFeedback("Copied"); }
      catch { setFeedback("Copy unavailable"); }
    }}>Copy</button><small role="status">{feedback}</small></span>;
}

export function Fields({value}: {value: unknown}) {
  if (value == null) return <Badge>Not recorded</Badge>;
  if (Array.isArray(value)) return value.length ? <ul className="field-list">{value.map((v,i)=><li key={i}><Fields value={v}/></li>)}</ul> : <>None recorded</>;
  if (typeof value === "object") return <dl className="facts">{Object.entries(value).map(([k,v])=><div key={k}><dt>{k.replaceAll("_"," ")}</dt><dd>{v && typeof v === "object" || typeof v === "string" && (v.length>180 || /xml|artifact/i.test(k)) ? <details><summary>Inspect {k.replaceAll("_"," ")}</summary><Fields value={v}/></details> : <Fields value={v}/>}</dd></div>)}</dl>;
  if (typeof value === "string" && /[a-f0-9]{32}/i.test(value)) return <Identifier id={value}/>;
  return <>{typeof value === "string" && /^[a-z]+(?:_[a-z]+)+$/.test(value) ? value.replaceAll("_"," ") : String(value)}</>;
}

export function Mappings({value}: {value: unknown}) {
  if (!Array.isArray(value) || !value.length) return <Badge>Not recorded</Badge>;
  return <div className="table-wrap"><table><thead><tr>{["Technique","ID","Tactic"].map(h=><th key={h}>{h}</th>)}</tr></thead>
    <tbody>{value.map((m,i)=><tr key={i}><td>{m.technique_name ?? "Not recorded"}</td><td>{m.technique_id ?? "Not recorded"}</td><td>{m.tactic_name ?? m.tactic_id ?? "Not recorded"}</td></tr>)}</tbody></table>
    <details><summary>Mapping sources</summary><Fields value={value}/></details></div>;
}
