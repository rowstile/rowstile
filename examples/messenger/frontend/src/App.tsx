import { useCallback, useEffect, useState } from "react";
import { api, ApiError, ChatSummary, initials, listen, time, User } from "./api";
import { Conversation } from "./Conversation";
import { NewChatDialog, SettingsDialog } from "./Dialogs";

export function App() {
  const [me, setMe] = useState<User | null | undefined>(undefined);
  useEffect(() => { api.me().then(setMe, () => setMe(null)); }, []);
  if (me === undefined) return <div className="splash">Messenger</div>;
  if (me === null) return <Login onIn={setMe} />;
  const join = location.pathname.match(/^\/join\/([^/]+)$/);
  if (join) return <JoinPage token={join[1]} />;
  return <Main me={me} onMe={setMe} />;
}

function Login({ onIn }: { onIn: (u: User) => void }) {
  const [mode, setMode] = useState<"in" | "up">("in");
  const [phone, setPhone] = useState(""), [name, setName] = useState(""), [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    try { onIn(mode === "in" ? await api.logIn(phone, password) : await api.signUp(phone, name, password)); }
    catch (err) { setError(err instanceof Error ? err.message : String(err)); }
  };
  return (
    <div className="login">
      <form onSubmit={submit}>
        <h1>Messenger</h1>
        <p className="hint">A messaging app whose every access rule lives in one policy file, enforced by the database.</p>
        <input placeholder="Phone number" value={phone} onChange={(e) => setPhone(e.target.value)} autoFocus />
        {mode === "up" && <input placeholder="Your name" value={name} onChange={(e) => setName(e.target.value)} />}
        <input placeholder="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        {error && <p className="error">{error}</p>}
        <button type="submit">{mode === "in" ? "Sign in" : "Create account"}</button>
        <button type="button" className="link" onClick={() => setMode(mode === "in" ? "up" : "in")}>
          {mode === "in" ? "New here? Create an account" : "I have an account"}
        </button>
      </form>
    </div>
  );
}

function Main({ me, onMe }: { me: User; onMe: (u: User | null) => void }) {
  const [chats, setChats] = useState<ChatSummary[]>([]);
  const [open, setOpen] = useState<number | null>(() => Number(new URLSearchParams(location.search).get("chat")) || null);
  const [version, setVersion] = useState<Record<number, number>>({});
  const [dialog, setDialog] = useState<"new" | "settings" | null>(null);
  const [filter, setFilter] = useState("");
  const [error, setError] = useState("");
  const refresh = useCallback(() => api.chats().then(setChats, () => undefined), []);
  // one function for as long as Main lives: the open conversation reloads when it changes
  const close = useCallback(() => { setOpen(null); refresh(); }, [refresh]);

  useEffect(() => { refresh(); }, [refresh]);
  // live: the server says which chat changed (only chats we may read); we refetch it through the API
  useEffect(() => listen((chatId) => {
    refresh();
    setVersion((v) => ({ ...v, [chatId]: (v[chatId] ?? 0) + 1 }));
  }), [refresh]);
  useEffect(() => { history.replaceState(null, "", open ? `/?chat=${open}` : "/"); }, [open]);

  // a direct chat whose other person left has no name: it stays in the list (as "(unknown)")
  const shown = chats.filter((c) => (c.name ?? "").toLowerCase().includes(filter.toLowerCase()));
  const signOut = async () => {
    setError("");
    try { await api.logOut(); onMe(null); }
    catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  };
  return (
    <div className="app">
      <aside className="sidebar">
        <header>
          <span className="avatar" title={me.name}>{initials(me.name)}</span>
          <span className="grow" />
          <button className="icon" title="New chat" onClick={() => setDialog("new")}>✎</button>
          <button className="icon" title="Settings" onClick={() => setDialog("settings")}>⚙</button>
          <button className="icon" title="Sign out" onClick={signOut}>⎋</button>
        </header>
        {error && <p className="error">{error}</p>}
        <input className="search" placeholder="Search chats" value={filter} onChange={(e) => setFilter(e.target.value)} />
        <ul className="chats">
          {shown.map((c) => (
            <li key={c.id} className={c.id === open ? "open" : ""} onClick={() => setOpen(c.id)}>
              <span className={`avatar ${c.kind}`}>{c.kind === "group" ? "👥" : initials(c.name ?? "?")}</span>
              <div className="grow">
                <div className="row"><b>{c.name ?? "(unknown)"}</b><span className="hint">{c.last_at ? time(c.last_at) : ""}</span></div>
                <div className="row">
                  <span className="preview">
                    {c.last_seq == null ? <i>No messages yet</i> : c.last_deleted ? <i>This message was deleted</i>
                      : <>{c.kind === "group" && c.last_sender && <>{c.last_sender_id === me.id ? "You" : c.last_sender}: </>}{c.last_body}</>}
                  </span>
                  {c.unread > 0 && <span className="badge">{c.unread}</span>}
                </div>
              </div>
            </li>))}
          {chats.length === 0 && <li className="empty">No chats yet. Start one with ✎.</li>}
        </ul>
      </aside>
      <main className="pane">
        {open ? <Conversation key={open} chatId={open} me={me} version={version[open] ?? 0} onChanged={refresh}
                              onClose={close} />
          : <div className="welcome"><h2>Messenger</h2><p>Pick a chat, or start one.</p>
              <p className="hint">Who may read, post, add people or delete messages is decided by the database,
                from <code>db/policy.authz</code>. This app only asks.</p></div>}
      </main>
      {dialog === "new" && <NewChatDialog me={me} onClose={() => setDialog(null)}
                                          onOpen={(id) => { setDialog(null); refresh(); setOpen(id); }} />}
      {dialog === "settings" && <SettingsDialog me={me} onMe={onMe} onClose={() => setDialog(null)} />}
    </div>
  );
}

function JoinPage({ token }: { token: string }) {
  const [chat, setChat] = useState<{ id: number; title: string; about: string; member: boolean } | null>(null);
  const [error, setError] = useState("");
  const named = new URLSearchParams(location.search).get("chat");
  useEffect(() => { api.joinPreview(token, named).then(setChat, (e: ApiError) => setError(e.message)); }, [token, named]);
  const go = (id: number) => { location.href = `/?chat=${id}`; };
  const join = async () => {
    setError("");
    try { go((await api.join(token, named)).id); }
    catch (e) { setError(e instanceof Error ? e.message : String(e)); }
  };
  return (
    <div className="login"><div className="box">
      <h1>Messenger</h1>
      {error && <p className="error">{error}</p>}
      {chat && <>
        <p>You are invited to the group</p>
        <h2>{chat.title}</h2>
        {chat.about && <p className="hint">{chat.about}</p>}
        {chat.member ? <button onClick={() => go(chat.id)}>You are in it: open it</button>
          : <button onClick={join}>Join the group</button>}
      </>}
      <button className="link" onClick={() => { location.href = "/"; }}>Back to my chats</button>
    </div></div>
  );
}

