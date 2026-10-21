import { useEffect, useState } from "react";
import { api, ApiError, Bot, Chat, Invite, User } from "./api";

type Props = { chat: Chat; me: User; onChanged: () => void; onClose: () => void; onLeft: () => void };

/** Group settings and members, or the other person in a direct chat. Every button here is shown only if
 * chat.perms (authz.perms, from the database) says you may; the database checks again when you press it. */
export function ChatInfo({ chat, me, onChanged, onClose, onLeft }: Props) {
  const [error, setError] = useState("");
  const [why, setWhy] = useState<string[]>([]);
  const manage = chat.perms.includes("manage");
  const mine = chat.members.find((m) => m.user_id === me.id);
  const run = async (fn: () => Promise<unknown>) => {
    setError(""); setWhy([]);
    try { await fn(); onChanged(); }
    catch (e) { setError(e instanceof Error ? e.message : String(e)); if (e instanceof ApiError) setWhy(e.why); }
  };

  return (
    <aside className="info">
      <header><b>{chat.kind === "group" ? "Group info" : "Contact info"}</b><span className="grow" />
        <button className="icon" onClick={onClose}>✕</button></header>
      <div className="scroll">
        {chat.kind === "group" ? <GroupSettings chat={chat} manage={manage} run={run} />
          : <section><h2>{chat.title}</h2><p className="hint">{chat.members.find((m) => m.user_id === chat.peer_id)?.phone}</p>
              <p>{chat.members.find((m) => m.user_id === chat.peer_id)?.about}</p></section>}

        {chat.kind === "group" && <section>
          <h3>{chat.members.length} members</h3>
          {chat.perms.includes("add_members") && <AddMember onAdd={(id) => run(() => api.addMember(chat.id, id))} />}
          <ul className="members">
            {chat.members.map((m) => (
              <li key={m.user_id}>
                <div className="grow"><b>{m.user_id === me.id ? "You" : m.name}</b> <span className="hint">{m.phone}</span></div>
                {m.role !== "member" && <span className="tag">{m.role}</span>}
                {manage && m.role !== "owner" && m.user_id !== me.id && <>
                  <button className="link" onClick={() => run(() => api.setRole(chat.id, m.user_id, m.role === "admin" ? "member" : "admin"))}>
                    {m.role === "admin" ? "dismiss as admin" : "make admin"}</button>
                  <button className="link danger" onClick={() => run(() => api.removeMember(chat.id, m.user_id))}>remove</button>
                </>}
              </li>))}
          </ul>
        </section>}

        {chat.kind === "group" && <Bots chat={chat} manage={manage} run={run} />}
        {chat.perms.includes("invite") && <InviteLink chatId={chat.id} />}

        {error && <div className="refusal"><span>{error}</span>{why.length > 0 && <pre>{why.join("\n")}</pre>}</div>}

        <section className="danger-zone">
          {chat.kind === "direct" && chat.peer_id && (chat.i_blocked
            ? <button onClick={() => run(() => api.unblock(chat.peer_id!))}>Unblock {chat.title}</button>
            : <button className="danger" onClick={() => run(() => api.block(chat.peer_id!))}>Block {chat.title}</button>)}
          {chat.kind === "group" && mine && mine.role !== "owner" &&
            <button className="danger" onClick={() => run(async () => { await api.removeMember(chat.id, me.id); onLeft(); })}>Leave group</button>}
          {chat.kind === "group" && mine?.role === "owner" &&
            <button className="danger" onClick={() => confirm(`Delete "${chat.title}" for everyone?`) &&
                                                     run(async () => { await api.deleteChat(chat.id); onLeft(); })}>Delete group</button>}
        </section>
      </div>
    </aside>
  );
}

function GroupSettings({ chat, manage, run }: { chat: Chat; manage: boolean; run: (fn: () => Promise<unknown>) => void }) {
  const [title, setTitle] = useState(chat.title), [about, setAbout] = useState(chat.about);
  useEffect(() => { setTitle(chat.title); setAbout(chat.about); }, [chat.title, chat.about]);
  if (!manage) return <section><h2>{chat.title}</h2>{chat.about && <p>{chat.about}</p>}
    {chat.admins_only && <p className="hint">Only admins can send messages.</p>}</section>;
  return (
    <section>
      <input className="title" value={title} onChange={(e) => setTitle(e.target.value)} />
      <textarea placeholder="Group description" value={about} onChange={(e) => setAbout(e.target.value)} />
      {(title !== chat.title || about !== chat.about) &&
        <button onClick={() => run(() => api.changeChat(chat.id, { title, about }))}>Save</button>}
      <label className="check">
        <input type="checkbox" checked={chat.admins_only}
               onChange={(e) => run(() => api.changeChat(chat.id, { admins_only: e.target.checked }))} />
        Only admins can send messages
      </label>
    </section>
  );
}

function AddMember({ onAdd }: { onAdd: (userId: string) => void }) {
  const [phone, setPhone] = useState(""), [note, setNote] = useState("");
  const add = async (e: React.FormEvent) => {
    e.preventDefault();
    const people = await api.findPerson(phone);
    if (people.length === 0) { setNote("Nobody with that number"); return; }
    setNote(""); setPhone(""); onAdd(people[0]!.id);
  };
  return (
    <form className="inline" onSubmit={add}>
      <input placeholder="Add by phone number" value={phone} onChange={(e) => setPhone(e.target.value)} />
      <button type="submit" disabled={!phone.trim()}>Add</button>
      {note && <span className="hint">{note}</span>}
    </form>
  );
}

function Bots({ chat, manage, run }: { chat: Chat; manage: boolean; run: (fn: () => Promise<unknown>) => void }) {
  const [mine, setMine] = useState<Bot[]>([]);
  useEffect(() => { if (manage) api.bots().then(setMine, () => undefined); }, [manage]);
  const addable = mine.filter((b) => b.active && !chat.bots.some((x) => x.id === b.id));
  if (chat.bots.length === 0 && addable.length === 0) return null;
  return (
    <section>
      <h3>Bots</h3>
      <ul className="members">
        {chat.bots.map((b) => (
          <li key={b.id}><div className="grow">🤖 {b.name}</div>
            {manage && <button className="link danger" onClick={() => run(() => api.removeBot(chat.id, b.id))}>remove</button>}</li>))}
      </ul>
      {addable.map((b) => <button key={b.id} className="link" onClick={() => run(() => api.addBot(chat.id, b.id))}>+ add {b.name}</button>)}
    </section>
  );
}

function InviteLink({ chatId }: { chatId: number }) {
  const [link, setLink] = useState("");
  const [invites, setInvites] = useState<Invite[]>([]);
  const load = () => api.invites(chatId).then(setInvites, () => setInvites([]));
  useEffect(() => { load(); }, [chatId]);
  return (
    <section>
      <h3>Invite link</h3>
      {link ? <><input readOnly value={link} onFocus={(e) => e.target.select()} />
                <p className="hint">Anyone with this link can join until it expires: the list below says when. Only a hash of it is stored.</p></>
        : <button className="link" onClick={async () => { setLink(`${location.origin}/join/${(await api.invite(chatId)).token}`); load(); }}>
            Create an invite link</button>}
      <ul className="people">
        {invites.map((i) => (
          <li key={i.id}><div className="grow hint">Link made by {i.created_by ?? "someone"} on {new Date(i.created_at).toLocaleDateString()}
              {i.expires_at ? `, until ${new Date(i.expires_at).toLocaleDateString()}` : ""}</div>
            <button className="link danger" onClick={async () => { await api.turnOffInvite(chatId, i.id); load(); }}>turn off</button></li>))}
      </ul>
    </section>
  );
}
