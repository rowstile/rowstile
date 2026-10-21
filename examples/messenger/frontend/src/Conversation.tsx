import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError, Chat, initials, Message, time, User } from "./api";
import { ChatInfo } from "./ChatInfo";

type Props = { chatId: number; me: User; version: number; onChanged: () => void; onClose: () => void };

export function Conversation({ chatId, me, version, onChanged, onClose }: Props) {
  const [chat, setChat] = useState<Chat | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [older, setOlder] = useState(true);
  const [error, setError] = useState<ApiError | null>(null);
  const [info, setInfo] = useState(false);
  const [editing, setEditing] = useState<Message | null>(null);
  const [text, setText] = useState("");
  const bottom = useRef<HTMLDivElement>(null);

  const load = useCallback(async () => {
    try {
      const [c, m] = await Promise.all([api.chat(chatId), api.messages(chatId)]);
      setChat(c);
      setMessages((old) => {
        // keep earlier pages already loaded; replace what this page covers
        const first = m[0]?.seq ?? Infinity;
        return [...old.filter((x) => x.seq < first), ...m];
      });
      // only what is new: marking read what was read already would still tell every member's browser
      const last = m[m.length - 1];
      const read = c.members.find((x) => x.user_id === me.id)?.last_read_seq ?? 0;
      if (last && last.seq > read) api.markRead(chatId, last.seq).then(onChanged, () => undefined);
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) onClose();     // removed from it, or it's gone
    }
  }, [chatId, me.id, onChanged, onClose]);

  useEffect(() => { load(); }, [load, version]);
  useEffect(() => { bottom.current?.scrollIntoView({ block: "end" }); }, [messages.length]);

  const loadOlder = async () => {
    setError(null);
    try {
      const page = await api.messages(chatId, messages[0]?.seq);
      if (page.length === 0) setOlder(false);
      setMessages((m) => [...page, ...m]);
    } catch (err) { setError(err instanceof ApiError ? err : new ApiError(String(err), 0)); }
  };

  const send = async (e: React.FormEvent) => {
    e.preventDefault();
    const body = text.trim();
    if (!body) return;
    setError(null);
    try {
      if (editing) await api.edit(chatId, editing.seq, body);
      else await api.send(chatId, body);
      setText(""); setEditing(null);
      await load();
    } catch (err) { setError(err instanceof ApiError ? err : new ApiError(String(err), 0)); }
  };

  if (!chat) return <div className="welcome">Loading…</div>;
  const others = chat.members.filter((m) => m.user_id !== me.id);
  const canPost = chat.perms.includes("post");
  return (
    <div className="conversation">
      <div className="chat-main">
        <header onClick={() => setInfo(!info)}>
          <span className={`avatar ${chat.kind}`}>{chat.kind === "group" ? "👥" : initials(chat.title)}</span>
          <div className="grow">
            <b>{chat.title}</b>
            <div className="hint">{chat.kind === "group"
              ? [...chat.members.map((m) => m.user_id === me.id ? "You" : m.name), ...chat.bots.map((b) => `${b.name} (bot)`)].join(", ")
              : others[0]?.about}</div>
          </div>
          <button className="icon" title="Chat info">ⓘ</button>
        </header>
        <div className="messages">
          {older && messages.length >= 50 && <button className="link center" onClick={loadOlder}>Earlier messages</button>}
          {messages.map((m) => <Bubble key={m.seq} m={m} me={me} chat={chat}
                                       onEdit={() => { setEditing(m); setText(m.body); }}
                                       onRemove={async () => { try { await api.remove(chatId, m.seq); await load(); }
                                                               catch (err) { setError(err as ApiError); } }} />)}
          <div ref={bottom} />
        </div>
        {error && <Refusal error={error} onClose={() => setError(null)} />}
        {canPost ? (
          <form className="composer" onSubmit={send}>
            {editing && <span className="editing">Editing <button type="button" className="link" onClick={() => { setEditing(null); setText(""); }}>cancel</button></span>}
            <input value={text} onChange={(e) => setText(e.target.value)} placeholder="Type a message" autoFocus />
            <button type="submit" disabled={!text.trim()}>{editing ? "Save" : "Send"}</button>
          </form>
        ) : <CannotPost chat={chat} />}
      </div>
      {info && <ChatInfo chat={chat} me={me} onChanged={() => { load(); onChanged(); }} onClose={() => setInfo(false)} onLeft={onClose} />}
    </div>
  );
}

function Bubble({ m, me, chat, onEdit, onRemove }: { m: Message; me: User; chat: Chat; onEdit: () => void; onRemove: () => void }) {
  const mine = m.sender_id === me.id;
  // read receipts: everyone else in the chat has read up to this message
  const readers = chat.members.filter((x) => x.user_id !== me.id);
  const read = readers.length > 0 && readers.every((x) => x.last_read_seq >= m.seq);
  return (
    <div className={`bubble ${mine ? "mine" : ""} ${m.bot_id ? "bot" : ""}`}>
      {!mine && chat.kind === "group" && <div className="sender">{m.bot_name ? `🤖 ${m.bot_name}` : m.sender_name}</div>}
      {m.deleted ? <i className="hint">This message was deleted</i> : <span className="body">{m.body}</span>}
      <span className="meta">
        {m.edited_at && !m.deleted && "edited "}{time(m.created_at)}
        {mine && !m.deleted && <span className={`ticks ${read ? "read" : ""}`}>{read ? "✓✓" : "✓"}</span>}
      </span>
      {!m.deleted && (m.can_edit || m.can_remove) && (
        <span className="actions">
          {m.can_edit && <button className="link" onClick={onEdit}>edit</button>}
          {m.can_remove && <button className="link" onClick={onRemove}>delete for everyone</button>}
        </span>)}
    </div>
  );
}

/** What the database said when it refused, with its explanation (authz.explain) behind "why?". */
function Refusal({ error, onClose }: { error: ApiError; onClose: () => void }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="refusal">
      <span>{error.message}</span>
      {error.why.length > 0 && <button className="link" onClick={() => setOpen(!open)}>why?</button>}
      <button className="link" onClick={onClose}>✕</button>
      {open && <pre>{error.why.join("\n")}</pre>}
    </div>
  );
}

function CannotPost({ chat }: { chat: Chat }) {
  const [why, setWhy] = useState<string[] | null>(null);
  const ask = async () => {
    if (why) { setWhy(null); return; }
    try { setWhy(await api.why(chat.id, "post")); }
    catch (err) { setWhy([err instanceof Error ? err.message : String(err)]); }
  };
  const reason = chat.i_blocked ? "You blocked this person. Unblock them to send messages."
    : chat.kind === "direct" ? "You can't message this person."
    : chat.admins_only ? "Only admins can send messages." : "You can't send messages here.";
  return (
    <div className="composer closed">
      <span>{reason}</span>
      <button className="link" onClick={ask}>why?</button>
      {why && <pre>{why.join("\n")}</pre>}
    </div>
  );
}
