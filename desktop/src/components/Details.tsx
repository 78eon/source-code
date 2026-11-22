import { Fields } from "./EvidenceDisplay";
export function Details({ value }: { value: unknown }) {
  return (
    <aside className="details">
      <h3>Evidence inspector</h3>
      {value ? (
        <><Fields value={value}/><details><summary>View raw record</summary><pre>{JSON.stringify(value, null, 2)}</pre></details></>
      ) : (
        <p>Select an item to inspect its recorded facts and provenance.</p>
      )}
    </aside>
  );
}
