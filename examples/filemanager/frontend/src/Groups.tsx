import { useEffect, useState } from "react";
import { api, Group, Member, User } from "./api";

/** Groups: everyone sees them (to share with them); owners and admins run them. */
export function Groups({ me }: { me: User }) {
  const [groups, setGroups] = useState<Group[] | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [error, setError] = useState("");
  const load = () => api.groups().then(setGroups, (e) => setError(e.message));
  useEffect(() => { load(); }, []);
  const run = async (fn: () => Promise<unknown>) => {
    setError("");
    try { await fn(); await load(); } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  };
  const create = (parent: string | null) => {
    const name = prompt(parent ? "Name of the sub-group" : "Name of the new group");
    if (name) run(() => api.createGroup(name, parent));
  };
  if (groups === null) return <p className="hint">{error || "Loading..."}</p>;
  const children = (parent: string | null): Group[] => groups.filter((g) => g.parent_id === parent);
  const tree = (parent: string | null, depth: number): React.ReactElement[] => children(parent).flatMap((g) => [
    <tr key={g.id}>
      <td className="name" style={{ paddingLeft: `${0.8 + depth * 1.4}em` }}>
        <button className="link" onClick={() => setOpen(open === g.id ? null : g.id)}>👥 {g.name}</button>
        {g.member && <span className="tag">member</span>}
        {g.manage && <span className="tag">you manage it</span>}
      </td>
      <td className="actions">
        {g.manage && <>
          <button className="link" onClick={() => create(g.id)}>Add sub-group</button>
          <button className="link" onClick={() => { const n = prompt("New name", g.name); if (n) run(() => api.renameGroup(g.id, n)); }}>Rename</button>
          <button className="link" onClick={() => confirm(`Delete ${g.name}?`) && run(() => api.deleteGroup(g.id))}>Delete</button>
        </>}
      </td>
    </tr>,
    ...(open === g.id ? [<tr key={`${g.id}-m`}><td colSpan={2}><Members group={g} me={me} onChange={load} /></td></tr>] : []),
    ...tree(g.id, depth + 1),
  ]);
  return (
    <section>
      <div className="toolbar"><h2 style={{ margin: 0, flex: 1 }}>Groups</h2><button onClick={() => create(null)}>New group</button></div>
      {groups.length === 0 ? <p className="empty">No groups yet.</p> : <table className="list"><tbody>{tree(null, 0)}</tbody></table>}
      {error && <p className="error">{error}</p>}
    </section>
  );
}

function Members({ group, me, onChange }: { group: Group; me: User; onChange: () => void }) {
  const [members, setMembers] = useState<Member[] | null>(null);
  const [manage, setManage] = useState(false);
  const [q, setQ] = useState("");
  const [found, setFound] = useState<User[]>([]);
  const [error, setError] = useState("");
  const load = () => api.members(group.id).then((r) => { setMembers(r.members); setManage(r.manage); }, (e) => setError(e.message));
  useEffect(() => { load(); }, [group.id]);
  useEffect(() => {
    if (q.length < 2) { setFound([]); return; }
    const t = setTimeout(() => api.users(q).then(setFound, () => {}), 200);
    return () => clearTimeout(t);
  }, [q]);
  const run = async (fn: () => Promise<unknown>) => {
    setError("");
    try { await fn(); await load(); onChange(); } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  };
  if (members === null) return <p className="hint">{error || "Loading..."}</p>;
  return (
    <div className="members">
      {members.length === 0 && <p className="hint">No members.</p>}
      <ul className="pick">{members.map((m) => (
        <li key={m.id}>{m.name} <span className="hint">{m.email}</span>{m.is_admin && <span className="tag">admin</span>}
          {manage && <>
            <button className="link" onClick={() => run(() => api.addMember(group.id, m.id, !m.is_admin))}>
              {m.is_admin ? "Make member" : "Make admin"}</button>
            <button className="link" onClick={() => run(() => api.removeMember(group.id, m.id))}>Remove</button>
          </>}
        </li>))}
      </ul>
      {group.member && <button className="link" onClick={() => run(() => api.removeMember(group.id, me.id))}>Leave this group</button>}
      {manage && <>
        <input placeholder="Add people by email or name" value={q} onChange={(e) => setQ(e.target.value)} />
        <ul className="pick">{found.map((u) => (
          <li key={u.id}><button className="link" onClick={() => { setQ(""); run(() => api.addMember(group.id, u.id, false)); }}>
            {u.name} ({u.email})</button></li>))}
        </ul>
      </>}
      {error && <p className="error">{error}</p>}
    </div>
  );
}
