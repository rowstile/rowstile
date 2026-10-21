import { useEffect, useState } from "react";
import { api, Bot, User } from "./api";

function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) {
  return (
    <div className="modal" onClick={onClose}>
      <div className="box" onClick={(e) => e.stopPropagation()}>
        <header><b>{title}</b><span className="grow" /><button className="icon" onClick={onClose}>✕</button></header>
        {children}
      </div>
    </div>
  );
}

/** A direct chat with someone, by phone number; or a group with a name and people. */
export function NewChatDialog({ me, onClose, onOpen }: { me: User; onClose: () => void; onOpen: (id: number) => void }) {
  const [mode, setMode] = useState<"direct" | "group">("direct");
  const [phone, setPhone] = useState(""), [title, setTitle] = useState("");
  const [people, setPeople] = useState<User[]>([]);
  const [error, setError] = useState("");
  const find = async () => {
    const found = await api.findPerson(phone);
    if (found.length === 0) throw new Error("Nobody with that number");
    if (found[0]!.id === me.id) throw new Error("That's you");
    return found[0]!;
  };
  const guard = async (fn: () => Promise<void>) => {
    setError("");
    try { await fn(); } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  };
  return (
    <Modal title="New chat" onClose={onClose}>
      <div className="tabs">
        <button className={mode === "direct" ? "on" : ""} onClick={() => setMode("direct")}>Someone</button>
        <button className={mode === "group" ? "on" : ""} onClick={() => setMode("group")}>New group</button>
      </div>
      {mode === "direct" ? (
        <form onSubmit={(e) => { e.preventDefault(); guard(async () => onOpen((await api.newDirect((await find()).id)).id)); }}>
          <input placeholder="Their phone number" value={phone} onChange={(e) => setPhone(e.target.value)} autoFocus />
          <button type="submit" disabled={!phone.trim()}>Chat</button>
        </form>
      ) : (
        <form onSubmit={(e) => { e.preventDefault(); guard(async () => onOpen((await api.newGroup(title, people.map((p) => p.id))).id)); }}>
          <input placeholder="Group name" value={title} onChange={(e) => setTitle(e.target.value)} autoFocus />
          <div className="inline">
            <input placeholder="Add by phone number" value={phone} onChange={(e) => setPhone(e.target.value)} />
            <button type="button" disabled={!phone.trim()}
                    onClick={() => guard(async () => { const p = await find(); setPeople((x) => x.some((y) => y.id === p.id) ? x : [...x, p]); setPhone(""); })}>
              Add</button>
          </div>
          <ul className="chips">{people.map((p) => <li key={p.id}>{p.name}
            <button type="button" className="link" onClick={() => setPeople((x) => x.filter((y) => y.id !== p.id))}>✕</button></li>)}</ul>
          <button type="submit" disabled={!title.trim()}>Create group</button>
        </form>
      )}
      {error && <p className="error">{error}</p>}
    </Modal>
  );
}

/** Your profile, your bots (and their API keys), the people you blocked. */
export function SettingsDialog({ me, onMe, onClose }: { me: User; onMe: (u: User) => void; onClose: () => void }) {
  const [name, setName] = useState(me.name), [about, setAbout] = useState(me.about);
  const [bots, setBots] = useState<Bot[]>([]), [blocked, setBlocked] = useState<User[]>([]);
  const [botName, setBotName] = useState(""), [newKey, setNewKey] = useState<Bot | null>(null);
  const [error, setError] = useState("");
  const guard = async (fn: () => Promise<void>) => {
    setError("");
    try { await fn(); } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  };
  const load = () => guard(async () => { const [b, u] = await Promise.all([api.bots(), api.blocks()]); setBots(b); setBlocked(u); });
  useEffect(() => { load(); }, []);
  return (
    <Modal title="Settings" onClose={onClose}>
      <section>
        <h3>Profile</h3>
        <input value={name} onChange={(e) => setName(e.target.value)} />
        <input value={about} onChange={(e) => setAbout(e.target.value)} />
        <p className="hint">{me.phone}</p>
        {(name !== me.name || about !== me.about) && <button onClick={() => guard(async () => onMe(await api.editProfile({ name, about })))}>Save</button>}
      </section>
      <section>
        <h3>Bots</h3>
        <p className="hint">A bot signs in with its own API key and posts in the groups you add it to, as itself.</p>
        <ul className="members">{bots.map((b) => <li key={b.id}><div className="grow">🤖 {b.name}</div>
          <span className="hint">#{b.id}{b.active ? "" : " (off)"}</span></li>)}</ul>
        <form className="inline" onSubmit={(e) => { e.preventDefault(); guard(async () => { setNewKey(await api.newBot(botName)); setBotName(""); await load(); }); }}>
          <input placeholder="New bot's name" value={botName} onChange={(e) => setBotName(e.target.value)} />
          <button type="submit" disabled={!botName.trim()}>Create</button>
        </form>
        {newKey && <div className="key">
          <p>The key of <b>{newKey.name}</b>, shown once:</p>
          <input readOnly value={newKey.key} onFocus={(e) => e.target.select()} />
          <pre>{`curl -X POST ${location.origin}/api/bot/chats/<chat>/messages \\
  -H "Authorization: Bearer ${newKey.key}" \\
  -H "Content-Type: application/json" -d '{"body": "hello"}'`}</pre>
        </div>}
      </section>
      <section>
        <h3>Blocked</h3>
        {blocked.length === 0 && <p className="hint">Nobody.</p>}
        <ul className="members">{blocked.map((u) => <li key={u.id}><div className="grow">{u.name} <span className="hint">{u.phone}</span></div>
          <button className="link" onClick={() => guard(async () => { await api.unblock(u.id); await load(); })}>unblock</button></li>)}</ul>
      </section>
      {error && <p className="error">{error}</p>}
    </Modal>
  );
}
