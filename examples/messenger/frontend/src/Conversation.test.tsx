// An open conversation loads once, and marks read only what is new: the app against a fake API (npm test)
import { act } from "react";
import { createRoot, Root } from "react-dom/client";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import type { Chat, ChatSummary, Message, User } from "./api";
import { App } from "./App";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
Element.prototype.scrollIntoView = () => {}; // jsdom lays nothing out

const me: User = { id: "u1", phone: "+15550000001", name: "Ann", about: "" };
const ben = { user_id: "u2", role: "member" as const, name: "Ben", phone: "+15550000002", about: "", last_read_seq: 1 };

/** The API as the backend answers it, for chat 7 with one message (seq 1); each request is logged. */
function fakeApi(read: number) {
  const log: string[] = [];
  const answer = (method: string, path: string, body: unknown): unknown => {
    if (path === "/api/me") return me;
    if (path === "/api/chats") {
      const c: ChatSummary = {
        id: 7, kind: "direct", name: "Ben", admins_only: false, role: "member", last_read_seq: read, last_seq: 1,
        last_body: "hi", last_deleted: false, last_at: null, last_sender: "Ben", last_sender_id: "u2", unread: 1 - read,
      };
      return [c];
    }
    if (path === "/api/chats/7") {
      const c: Chat = {
        id: 7, kind: "direct", title: "Ben", about: "", admins_only: false, last_seq: 1, bots: [], perms: ["read", "post"],
        members: [{ ...ben, user_id: me.id, name: me.name, phone: me.phone, last_read_seq: read }, ben],
      };
      return c;
    }
    if (path === "/api/chats/7/messages") {
      const m: Message = {
        seq: 1, sender_id: "u2", bot_id: null, body: "hi", deleted: false, created_at: new Date().toISOString(),
        edited_at: null, sender_name: "Ben", bot_name: null, can_edit: false, can_remove: false,
      };
      return [m];
    }
    if (method === "POST" && path === "/api/chats/7/read") {
      read = Math.max(read, (body as { seq: number }).seq);
      return { ok: true };
    }
    throw new Error(`no answer for ${method} ${path}`);
  };
  const fetch = async (path: string, init: RequestInit) => {
    const method = init.method ?? "GET";
    log.push(`${method} ${path}`);
    await new Promise((r) => setTimeout(r, 1)); // over the network: a request in a loop doesn't starve the test
    const body = typeof init.body === "string" ? JSON.parse(init.body) : undefined;
    return new Response(JSON.stringify(answer(method, path, body)), { status: 200 });
  };
  return { log, fetch };
}

class NoSocket {
  onmessage: unknown = null;
  onclose: unknown = null;
  close() {}
}

let root: Root | null = null;

beforeEach(() => {
  vi.stubGlobal("WebSocket", NoSocket);
  history.replaceState(null, "", "/?chat=7");
});

afterEach(() => {
  act(() => root?.unmount());
  root = null;
  vi.unstubAllGlobals();
});

/** The app with chat 7 open, given time to settle: the requests it sent. */
async function openChat(read: number): Promise<string[]> {
  const api = fakeApi(read);
  vi.stubGlobal("fetch", api.fetch);
  const div = document.createElement("div");
  document.body.append(div);
  root = createRoot(div);
  await act(async () => root!.render(<App />));
  for (let i = 0; i < 10; i++) await act(() => new Promise((r) => setTimeout(r, 20)));
  return api.log;
}

const count = (log: string[], request: string) => log.filter((x) => x === request).length;

test("an open chat with unread messages loads once and marks them read once", async () => {
  const log = await openChat(0);
  expect(count(log, "GET /api/chats/7")).toBe(1);
  expect(count(log, "GET /api/chats/7/messages")).toBe(1);
  expect(count(log, "POST /api/chats/7/read")).toBe(1);
  expect(count(log, "GET /api/chats")).toBe(2); // the list, then again for its unread count
});

test("an open chat read to its last message marks nothing read", async () => {
  const log = await openChat(1);
  expect(count(log, "GET /api/chats/7")).toBe(1);
  expect(count(log, "POST /api/chats/7/read")).toBe(0);
  expect(count(log, "GET /api/chats")).toBe(1);
});
