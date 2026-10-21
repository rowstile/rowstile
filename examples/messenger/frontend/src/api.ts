// The backend's API. What you may do comes back from the server (chat.perms: authz.perms in the
// database); the web app only shows or hides buttons by it. The database enforces the same thing.

export type User = { id: string; phone: string; name: string; about: string };

export type ChatSummary = {
  id: number; kind: "direct" | "group"; name: string | null; admins_only: boolean; role: string;
  last_read_seq: number; last_seq: number | null; last_body: string | null; last_deleted: boolean | null;
  last_at: string | null; last_sender: string | null; last_sender_id: string | null; unread: number;
};

export type Member = { user_id: string; role: "owner" | "admin" | "member"; name: string; phone: string; about: string;
  last_read_seq: number };

export type Chat = {
  id: number; kind: "direct" | "group"; title: string; about: string; admins_only: boolean; last_seq: number;
  members: Member[]; bots: { id: number; name: string }[]; perms: string[];
  peer_id?: string; i_blocked?: boolean;
};

export type Message = {
  seq: number; sender_id: string | null; bot_id: number | null; body: string; deleted: boolean;
  created_at: string; edited_at: string | null; sender_name: string | null; bot_name: string | null;
  can_edit: boolean; can_remove: boolean;
};

export type Bot = { id: number; name: string; active: boolean; created_at: string; key?: string };

/** An invite link as the database lists it: its id names it to turn it off, and is not the link. */
export type Invite = { id: string; created_by: string | null; created_at: string; expires_at: string | null };

/** An error from the API: its message, and when the database refused something, its explanation. */
export class ApiError extends Error {
  constructor(message: string, public status: number, public why: string[] = []) { super(message); }
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const r = await fetch(path, {
    method, credentials: "same-origin",
    headers: body === undefined ? {} : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (r.status === 204) return undefined as T;
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    const detail = typeof data.detail === "string" ? data.detail : r.statusText;
    throw new ApiError(detail, r.status, data.why ?? []);
  }
  return data as T;
}

const get = <T,>(p: string) => call<T>("GET", p);
const post = <T,>(p: string, b?: unknown) => call<T>("POST", p, b ?? {});
const patch = <T,>(p: string, b: unknown) => call<T>("PATCH", p, b);
const del = <T,>(p: string) => call<T>("DELETE", p);

export const api = {
  me: () => get<User>("/api/me"),
  signUp: (phone: string, name: string, password: string) => post<User>("/api/signup", { phone, name, password }),
  logIn: (phone: string, password: string) => post<User>("/api/login", { phone, password }),
  logOut: () => post("/api/logout"),
  editProfile: (b: { name?: string; about?: string }) => patch<User>("/api/me", b),
  findPerson: (phone: string) => get<User[]>(`/api/people?phone=${encodeURIComponent(phone)}`),

  chats: () => get<ChatSummary[]>("/api/chats"),
  chat: (id: number) => get<Chat>(`/api/chats/${id}`),
  newDirect: (userId: string) => post<{ id: number }>("/api/chats", { kind: "direct", user_id: userId }),
  newGroup: (title: string, memberIds: string[]) => post<{ id: number }>("/api/chats", { kind: "group", title, member_ids: memberIds }),
  changeChat: (id: number, b: { title?: string; about?: string; admins_only?: boolean }) => patch(`/api/chats/${id}`, b),
  deleteChat: (id: number) => del(`/api/chats/${id}`),
  why: (id: number, perm: string) => get<string[]>(`/api/chats/${id}/why/${perm}`),

  messages: (id: number, before?: number) => get<Message[]>(`/api/chats/${id}/messages${before ? `?before=${before}` : ""}`),
  send: (id: number, body: string) => post<{ seq: number }>(`/api/chats/${id}/messages`, { body }),
  edit: (id: number, seq: number, body: string) => patch(`/api/chats/${id}/messages/${seq}`, { body }),
  remove: (id: number, seq: number) => del(`/api/chats/${id}/messages/${seq}`),
  markRead: (id: number, seq: number) => post(`/api/chats/${id}/read`, { seq }),

  addMember: (id: number, userId: string) => post(`/api/chats/${id}/members`, { user_id: userId }),
  setRole: (id: number, userId: string, role: "admin" | "member") => patch(`/api/chats/${id}/members/${userId}`, { role }),
  removeMember: (id: number, userId: string) => del(`/api/chats/${id}/members/${userId}`),

  invite: (id: number) => post<{ token: string; expires_at: string }>(`/api/chats/${id}/invite`),
  invites: (id: number) => get<Invite[]>(`/api/chats/${id}/invites`),
  turnOffInvite: (id: number, linkId: string) => del(`/api/chats/${id}/invites/${linkId}`),
  // an invite link is /join/<token>?chat=<id>: the token lets you in; the chat answers for its admins, who need none
  joinPreview: (token: string, chat: string | null) =>
    get<{ id: number; title: string; about: string; member: boolean }>(`/api/join/${token}${chat ? `?chat=${chat}` : ""}`),
  join: (token: string, chat: string | null) => post<{ id: number }>(`/api/join/${token}${chat ? `?chat=${chat}` : ""}`),

  blocks: () => get<User[]>("/api/blocks"),
  block: (userId: string) => post("/api/blocks", { user_id: userId }),
  unblock: (userId: string) => del(`/api/blocks/${userId}`),

  bots: () => get<Bot[]>("/api/bots"),
  newBot: (name: string) => post<Bot>("/api/bots", { name }),
  addBot: (id: number, botId: number) => post(`/api/chats/${id}/bots`, { bot_id: botId }),
  removeBot: (id: number, botId: number) => del(`/api/chats/${id}/bots/${botId}`),
};

/** Live updates: calls onChat(chatId) whenever a chat you may read changes; reconnects if dropped. */
export function listen(onChat: (chatId: number) => void): () => void {
  let ws: WebSocket | null = null;
  let stopped = false;
  const open = () => {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    ws = new WebSocket(`${proto}://${location.host}/api/events`);
    ws.onmessage = (e) => onChat(JSON.parse(e.data).chat);
    ws.onclose = () => { if (!stopped) setTimeout(open, 2000); };
  };
  open();
  return () => { stopped = true; ws?.close(); };
}

export const initials = (name: string) => name.split(/\s+/).filter(Boolean).slice(0, 2).map((w) => w[0]!.toUpperCase()).join("");

export const time = (iso: string) => {
  const d = new Date(iso);
  const today = new Date().toDateString() === d.toDateString();
  return today ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : d.toLocaleDateString();
};
