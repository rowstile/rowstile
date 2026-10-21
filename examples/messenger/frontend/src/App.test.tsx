// What the web app shows when the API refuses or fails: every button that asks it says so (npm test). The app runs
// against a fake API: each test says what some requests answer, the rest answer as a small group (chat 7) does.
import { act } from "react";
import { createRoot, Root } from "react-dom/client";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import type { Chat, ChatSummary, Message, User } from "./api";
import { App } from "./App";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
Element.prototype.scrollIntoView = () => {}; // jsdom lays nothing out

const me: User = { id: "u1", phone: "+15550000001", name: "Ann", about: "" };

/** An answer the API gives with a status other than 200: its words, and the database's why. */
class Failure {
  constructor(public status: number, public detail: string, public why: string[] = []) {}
}

type Answers = Record<string, unknown>;

const summary: ChatSummary = {
  id: 7, kind: "group", name: "Club", admins_only: false, role: "owner", last_read_seq: 1, last_seq: 1, last_body: "hi",
  last_deleted: false, last_at: null, last_sender: "Ann", last_sender_id: me.id, unread: 0,
};

const group: Chat = {
  id: 7, kind: "group", title: "Club", about: "", admins_only: false, last_seq: 1, bots: [],
  perms: ["read", "post", "manage", "invite", "add_members"],
  members: [{ user_id: me.id, role: "owner", name: me.name, phone: me.phone, about: "", last_read_seq: 1 }],
};

const message = (seq: number): Message => ({
  seq, sender_id: me.id, bot_id: null, body: `m${seq}`, deleted: false, created_at: new Date().toISOString(),
  edited_at: null, sender_name: me.name, bot_name: null, can_edit: false, can_remove: false,
});

/** The requests the app sent ("POST /api/logout"), answered from `answers` ("METHOD path" with its query) first. */
function fakeApi(answers: Answers) {
  const log: string[] = [];
  const defaults: Answers = {
    "GET /api/me": me, "GET /api/chats": [summary], "GET /api/chats/7": group, "GET /api/chats/7/messages": [message(1)],
    "GET /api/chats/7/invites": [], "GET /api/bots": [], "GET /api/blocks": [],
  };
  const fetch = async (path: string, init: RequestInit) => {
    const request = `${init.method ?? "GET"} ${path}`;
    log.push(request);
    await new Promise((r) => setTimeout(r, 1));
    const answer = request in answers ? answers[request] : request in defaults ? defaults[request] : new Failure(404, "not found");
    if (answer instanceof Failure) {
      return new Response(JSON.stringify({ detail: answer.detail, why: answer.why }), { status: answer.status });
    }
    return answer === null ? new Response(null, { status: 204 }) : new Response(JSON.stringify(answer), { status: 200 });
  };
  return { log, fetch };
}

class NoSocket {
  onmessage: unknown = null;
  onclose: unknown = null;
  close() {}
}

let root: Root | null = null;
let div: HTMLDivElement;

beforeEach(() => {
  vi.stubGlobal("WebSocket", NoSocket);
});

afterEach(() => {
  act(() => root?.unmount());
  root = null;
  div?.remove();
  vi.unstubAllGlobals();
});

const settle = async () => {
  for (let i = 0; i < 10; i++) await act(() => new Promise((r) => setTimeout(r, 10)));
};

/** The app at `url`, against the fake API, given time to settle: the requests it sent. */
async function start(url: string, answers: Answers = {}): Promise<string[]> {
  history.replaceState(null, "", url);
  const api = fakeApi(answers);
  vi.stubGlobal("fetch", api.fetch);
  div = document.createElement("div");
  document.body.append(div);
  root = createRoot(div);
  await act(async () => root!.render(<App />));
  await settle();
  return api.log;
}

/** Presses the button (or link) whose text or title starts with `text`, and waits for what follows. */
async function press(text: string): Promise<void> {
  const button = [...div.querySelectorAll("button")].find(
    (b) => b.textContent!.trim().startsWith(text) || b.title === text,
  );
  if (!button) throw new Error(`no button "${text}" in: ${div.textContent}`);
  await act(async () => button.click());
  await settle();
}

/** Types into the input whose value or placeholder is `which`, as a person would (React reads the input event). */
async function type(which: string, value: string): Promise<void> {
  const input = [...div.querySelectorAll("input")].find((i) => i.value === which || i.placeholder === which);
  if (!input) throw new Error(`no input "${which}"`);
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

const shown = () => div.textContent ?? "";

test("a direct chat whose other person left stays in the list, unnamed", async () => {
  await start("/", { "GET /api/chats": [{ ...summary, id: 8, kind: "direct", name: null }] });
  expect(shown()).toContain("(unknown)");
  expect(shown()).not.toContain("No chats yet");
});

test("signing out that fails says so", async () => {
  await start("/", { "POST /api/logout": new Failure(500, "the server is down") });
  await press("Sign out");
  expect(shown()).toContain("the server is down");
});

test("an invite link names its chat, and joining with one that is refused says so", async () => {
  const log = await start("/join/tok?chat=7", {
    "GET /api/join/tok?chat=7": { id: 7, title: "Club", about: "", member: false },
    "POST /api/join/tok?chat=7": new Failure(403, "you can't add this person here"),
  });
  expect(log).toContain("GET /api/join/tok?chat=7");
  await press("Join the group");
  expect(shown()).toContain("you can't add this person here");
});

test("making an invite link writes its chat into it; making or turning one off that is refused says why", async () => {
  const invite = { id: "l1", created_by: "Ann", created_at: new Date().toISOString(), expires_at: null };
  await start("/?chat=7", {
    "POST /api/chats/7/invite": { token: "tok", expires_at: new Date().toISOString() },
    "GET /api/chats/7/invites": [invite],
    "DELETE /api/chats/7/invites/l1": new Failure(403, "you may not do that here", ["no   unshare"]),
  });
  await press("Chat info");
  await press("Create an invite link");
  expect([...div.querySelectorAll("input")].map((i) => i.value)).toContain(`${location.origin}/join/tok?chat=7`);
  await press("turn off");
  expect(shown()).toContain("you may not do that here");
  expect(shown()).toContain("no   unshare");
});

test("making an invite link that is refused says why", async () => {
  await start("/?chat=7", { "POST /api/chats/7/invite": new Failure(403, "you may not do that here", ["no   invite"]) });
  await press("Chat info");
  await press("Create an invite link");
  expect(shown()).toContain("no   invite");
});

test("earlier messages that fail to load say so", async () => {
  const page = Array.from({ length: 50 }, (_, i) => message(i + 51));
  await start("/?chat=7", {
    "GET /api/chats/7": { ...group, last_seq: 100 },
    "GET /api/chats/7/messages": page,
    "GET /api/chats/7/messages?before=51": new Failure(500, "the server is down"),
  });
  await press("Earlier messages");
  expect(shown()).toContain("the server is down");
});

test("why? under a closed composer says so when the API fails", async () => {
  await start("/?chat=7", {
    "GET /api/chats/7": { ...group, perms: ["read"] },
    "GET /api/chats/7/why/post": new Failure(500, "the server is down"),
  });
  await press("why?");
  expect(shown()).toContain("the server is down");
});

test("settings that fail to load say so", async () => {
  await start("/", { "GET /api/blocks": new Failure(500, "the server is down") });
  await press("Settings");
  expect(shown()).toContain("the server is down");
});

test("saving a profile, making a bot and unblocking, refused, say so", async () => {
  const bo = { id: "u2", phone: "+15550000002", name: "Bo", about: "" };
  await start("/", {
    "GET /api/blocks": [bo],
    "PATCH /api/me": new Failure(400, "the name is too long"),
    "POST /api/bots": new Failure(403, "you may not do that here"),
    "DELETE /api/blocks/u2": new Failure(500, "the server is down"),
  });
  await press("Settings");
  await type("Ann", "Ann Lee");
  await press("Save");
  expect(shown()).toContain("the name is too long");
  await type("New bot's name", "weather");
  await press("Create");
  expect(shown()).toContain("you may not do that here");
  await press("unblock");
  expect(shown()).toContain("the server is down");
});

test("adding someone by phone number when the search fails says so", async () => {
  await start("/?chat=7", { "GET /api/people?phone=123": new Failure(500, "the server is down") });
  await press("Chat info");
  await type("Add by phone number", "123");
  await press("Add");
  expect(shown()).toContain("the server is down");
});
