import { useEffect, useState } from "react";
import { api, RequestRow } from "./api";

/** Requests to decide (for things the user may share) and the user's own. */
export function Requests() {
  const [rows, setRows] = useState<RequestRow[] | null>(null);
  const [error, setError] = useState("");
  const load = () => api.requests().then(setRows, (e) => setError(e.message));
  useEffect(() => { load(); }, []);
  const run = async (fn: () => Promise<unknown>) => {
    setError("");
    try { await fn(); await load(); } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  };
  if (rows === null) return <p className="hint">{error || "Loading..."}</p>;
  const toDecide = rows.filter((r) => !r.mine), mine = rows.filter((r) => r.mine);
  const deny = (id: number) => {
    const note = prompt("Why not? (optional)");
    if (note !== null) run(() => api.decide(id, false, note || undefined));   // Cancel: nothing is decided
  };
  const what = (r: RequestRow) => <>
    {r.relation === "editor" ? "edit" : "view"} {r.object_type}{" "}
    <a href={r.object_type === "folder" ? `#/folder/${r.object_id}` : "#/"}>#{r.object_id}</a>
    {r.duration ? ` for ${r.duration}` : ""}: "{r.reason}"</>;
  return (
    <section>
      <h2>Requests to decide</h2>
      {toDecide.length === 0 ? <p className="empty">None.</p> :
        <ul className="requests">{toDecide.map((r) => (
          <li key={r.id}>{r.requester_name ?? r.requester} asks to {what(r)}
            <span className="actions">
              <button onClick={() => run(() => api.decide(r.id, true))}>Approve</button>
              <button className="link" onClick={() => deny(r.id)}>Deny</button>
            </span></li>))}
        </ul>}
      <h2>My requests</h2>
      {mine.length === 0 ? <p className="empty">None pending.</p> :
        <ul className="requests">{mine.map((r) => (
          <li key={r.id}>To {what(r)}
            <span className="actions"><button className="link" onClick={() => run(() => api.cancelRequest(r.id))}>Cancel</button></span>
          </li>))}
        </ul>}
      {error && <p className="error">{error}</p>}
    </section>
  );
}
