export function Details({ value }: { value: unknown }) {
  return (
    <aside className="details">
      <h3>Evidence inspector</h3>
      {value ? (
        <pre>{JSON.stringify(value, null, 2)}</pre>
      ) : (
        <p>Select an item to inspect its recorded facts and provenance.</p>
      )}
    </aside>
  );
}
