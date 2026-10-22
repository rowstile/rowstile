import { useEffect, useState } from "react";
import { api, Group, Kind, Relation, ShareRow, User } from "./api";
import { endOfDay, lastDay } from "./dates";

/** Who it is shared with, sharing it with more people or groups, who has access and why. */
export function ShareDialog({ kind, id, name, onClose }: { kind: Kind; id: number; name: string; onClose: () => void }) {
  const [shares, setShares] = useState<ShareRow[] | null>(null);
  const [people, setPeople] = useState<User[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [access, setAccess] = useState<User[] | null>(null);
  const [why, setWhy] = useState<string[] | null>(null);
  const [q, setQ] = useState("");
  const [relation, setRelation] = useState<Relation>("viewer");
  const [expires, setExpires] = useState("");
  const [error, setError] = useState("");
  const [links, setLinks] = useState<{ id: string; created_at: string; expires_at: string | null; created_by: string }[]>([]);
  const [newLink, setNewLink] = useState("");

  const load = () => Promise.all([
    api.shares(kind, id).then(setShares, (e) => setError(e.message)),
    api.links(kind, id).then(setLinks, () => setLinks([])),
  ]);
  useEffect(() => { load(); api.groups().then(setGroups, () => {}); }, []);
  useEffect(() => {
    if (q.length < 2) { setPeople([]); return; }
    const t = setTimeout(() => api.users(q).then(setPeople, () => {}), 200);
    return () => clearTimeout(t);
  }, [q]);

  const run = async (fn: () => Promise<unknown>) => {
    setError("");
    try { await fn(); await load(); } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  };
  const add = (subject_type: "user" | "group", subject_id: string) => run(async () => {
    await api.share(kind, id, { relation, subject_type, subject_id, expires_at: expires ? endOfDay(expires) : null });
    setQ("");
  });

  return (
    <div className="modal" onClick={onClose}><div className="box wide" onClick={(e) => e.stopPropagation()}>
      <h3>Share {name}</h3>
      {shares === null ? <p className="hint">{error || "Loading..."}</p> : <>
        <table className="list">
          <tbody>
            {shares.length === 0 && <tr><td className="hint">Not shared with anyone yet.</td></tr>}
            {shares.map((s) => (
              <tr key={`${s.relation}${s.subject_type}${s.subject_id}`}>
                <td>{s.subject_type === "group" ? "👥 " : ""}{s.subject_name ?? s.subject_id}</td>
                <td>{s.relation === "editor" ? "can edit" : "can view"}</td>
                <td className="hint">{s.expires_at ? `until ${lastDay(s.expires_at)}` : ""}</td>
                <td className="actions"><button className="link" onClick={() => run(() => api.unshare(kind, id, {
                  relation: s.relation, subject_type: s.subject_type, subject_id: s.subject_id }))}>Remove</button></td>
              </tr>))}
          </tbody>
        </table>
        <div className="row">
          <select value={relation} onChange={(e) => setRelation(e.target.value as Relation)}>
            <option value="viewer">can view</option><option value="editor">can edit</option>
          </select>
          <label className="inline">until <input type="date" value={expires} onChange={(e) => setExpires(e.target.value)} /></label>
        </div>
        <input placeholder="Find people by email or name" value={q} onChange={(e) => setQ(e.target.value)} />
        <ul className="pick">
          {people.map((u) => <li key={u.id}><button className="link" onClick={() => add("user", u.id)}>{u.name} ({u.email})</button></li>)}
        </ul>
        {groups.length > 0 && <label>Or a group <select value="" onChange={(e) => e.target.value && add("group", e.target.value)}>
          <option value="">choose...</option>
          {groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
        </select></label>}
      </>}
      <h4>Anyone with the link can view</h4>
      {links.map((l) => (
        <div className="row" key={l.id}>
          <span className="hint">Link made by {l.created_by} on {new Date(l.created_at).toLocaleDateString()}
            {l.expires_at ? `, until ${lastDay(l.expires_at)}` : ""}</span>
          <button className="link" onClick={() => run(() => api.revokeLink(kind, id, l.id))}>Turn off</button>
        </div>))}
      {newLink && <div className="row"><input readOnly value={newLink} onFocus={(e) => e.target.select()} />
        <span className="hint">Copy it now: it is shown only once.</span></div>}
      <button className="link" onClick={() => run(async () => {
        const l = await api.createLink(kind, id, expires ? endOfDay(expires) : null);
        setNewLink(`${window.location.origin}${window.location.pathname}${l.path}`);
      })}>Make a link{expires ? " (until the date above)" : ""}</button>
      {error && shares !== null && <p className="error">{error}</p>}
      <div className="buttons">
        <button className="link" onClick={() => api.access(kind, id, "view").then(setAccess, (e) => setError(e.message))}>Who can see it?</button>
        <button className="link" onClick={() => api.why(kind, id, "edit").then((w) => setWhy(w.lines), (e) => setError(e.message))}>
          Why can I edit it, or not?</button>
        <button onClick={onClose}>Done</button>
      </div>
      {access && <p className="hint">Can see it: {access.map((u) => u.name).join(", ") || "nobody else"}</p>}
      {why && <ul className="why">{why.map((l, i) => <li key={i}>{l}</li>)}</ul>}
    </div></div>
  );
}
