// The web app against a fake API (npm test): it offers only what the API says the user may do, says when a call
// fails, and a date picked for a share holds to the end of that day. Each test says what some requests answer; the
// rest answer as alice's files do. vite.config.ts runs these west of UTC (TZ), where a day's start in UTC is the
// evening before.
import { act } from "react";
import { createRoot, Root } from "react-dom/client";
import { afterEach, expect, test, vi } from "vitest";
import type { FileRow, Folder, RequestRow, User, Version } from "./api";
import { App } from "./App";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const me: User = { id: "u1", email: "alice@example.com", name: "alice" };
const bob: User = { id: "u2", email: "bob@example.com", name: "bob" };
const at = "2026-10-01T09:00:00Z";

const file = (id: number, name: string, mine: boolean, more: Partial<FileRow> = {}): FileRow => ({
  id, folder_id: 10, name, owner_id: mine ? me.id : bob.id, size: 5, content_type: "text/csv", created_at: at,
  updated_at: at, can_edit: mine, can_share: mine, ...more,
});
const folder = (id: number, name: string, mine: boolean): Folder => ({
  id, parent_id: null, name, owner_id: mine ? me.id : bob.id, inherit: true, created_at: at, can_edit: mine,
  can_share: mine,
});
const version = (id: number, current: boolean): Version => ({
  id, file_id: 2, size: 5, content_type: "text/csv", created_at: at, created_by: bob.id, created_by_name: "bob", current,
});

/** An answer the API gives with a status other than 200: its words. */
class Failure {
  constructor(public status: number, public detail: string) {}
}

type Answers = Record<string, unknown>;

const defaults: Answers = {
  "GET /api/me": me,
  // alice's own file, a file and a folder bob shared with her to view
  "GET /api/home": { folders: [folder(3, "Bob's photos", false)], files: [file(1, "mine.csv", true), file(2, "his.csv", false)] },
  "GET /api/files/1/versions": [version(11, true), version(12, false)],
  "GET /api/files/2/versions": [version(21, true), version(22, false)],
  "GET /api/files/1/shares": [], "GET /api/files/1/links": [], "GET /api/groups": [],
};

let root: Root | null = null;
let div: HTMLDivElement;
/** The requests the app sent ("POST /api/logout"), and the body of each. */
let log: string[] = [];
let bodies: Record<string, unknown> = {};

afterEach(() => {
  act(() => root?.unmount());
  root = null;
  div?.remove();
  vi.unstubAllGlobals();
});

const settle = async () => {
  for (let i = 0; i < 10; i++) await act(() => new Promise((r) => setTimeout(r, 10)));
};

/** The app at `hash`, against the fake API, given time to settle. */
async function start(hash: string, answers: Answers = {}): Promise<void> {
  log = [];
  bodies = {};
  vi.stubGlobal("fetch", async (path: string, init: RequestInit) => {
    const request = `${init.method ?? "GET"} ${path}`;
    log.push(request);
    if (typeof init.body === "string") bodies[request] = JSON.parse(init.body);
    await new Promise((r) => setTimeout(r, 1));
    const answer = request in answers ? answers[request] : request in defaults ? defaults[request] : new Failure(404, "not found");
    if (answer instanceof Failure) return new Response(JSON.stringify({ detail: answer.detail }), { status: answer.status });
    return answer === null ? new Response(null, { status: 204 }) : new Response(JSON.stringify(answer), { status: 200 });
  });
  history.replaceState(null, "", `/${hash}`);
  div = document.createElement("div");
  document.body.append(div);
  root = createRoot(div);
  await act(async () => root!.render(<App />));
  await settle();
}

/** The table row that names `name`, or the whole page. */
function within(name?: string): Element {
  if (name === undefined) return div;
  const row = [...div.querySelectorAll("tr")].find((r) => r.querySelector(".name")?.textContent?.includes(name));
  if (!row) throw new Error(`no row "${name}" in: ${div.textContent}`);
  return row;
}

/** The buttons in a row's actions. */
const actions = (name: string) => [...within(name).querySelectorAll(".actions button")].map((b) => b.textContent);

/** The buttons of the dialog open on the page. */
const dialogButtons = () => [...div.querySelectorAll(".modal button")].map((b) => b.textContent!.trim());

/** Presses the button whose text starts with `text` (in the row that names `row`), and waits for what follows. */
async function press(text: string, row?: string): Promise<void> {
  const button = [...within(row).querySelectorAll("button")].find((b) => b.textContent!.trim().startsWith(text));
  if (!button) throw new Error(`no button "${text}" in: ${within(row).textContent}`);
  await act(async () => button.click());
  await settle();
}

/** Types into the input whose placeholder or type is `which`, as a person would (React reads the input event). */
async function type(which: string, value: string): Promise<void> {
  const input = [...div.querySelectorAll("input")].find((i) => i.placeholder === which || i.type === which);
  if (!input) throw new Error(`no input "${which}"`);
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

const shown = () => div.textContent ?? "";

test("the tests run west of UTC", () => {
  expect(new Date(2026, 9, 20).getTimezoneOffset()).toBeGreaterThan(0);
});

test("on the home page, what is shared to view offers no button that changes it", async () => {
  await start("#/");
  expect(actions("mine.csv")).toEqual(["Share", "Versions", "Rename", "Move", "Delete"]);
  expect(actions("his.csv")).toEqual(["Versions"]);
  expect(actions("Bob's photos")).toEqual([]);
  await press("Versions", "his.csv");
  expect(shown()).toContain("Versions of his.csv");
  expect(dialogButtons()).toEqual(["Download", "Download", "Close"]);
  await press("Close");
  await press("Versions", "mine.csv");
  expect(dialogButtons()).toEqual(["Download", "Download", "Make current", "Upload a new version", "Close"]);
});

test("in a folder, a file the user may edit and not share offers no Share", async () => {
  await start("#/folder/10", {
    "GET /api/folders/10": {
      folder: folder(10, "Team", false), path: [{ id: 10, name: "Team" }], folders: [], perms: ["view", "edit"],
      files: [file(4, "notes.csv", false, { can_edit: true })],
    },
  });
  expect(actions("notes.csv")).toEqual(["Versions", "Rename", "Move", "Delete"]);
});

test("a share or a link until a date holds to the end of that day, and is shown back as that day", async () => {
  const end = new Date(2026, 9, 21).toISOString(); // the 20th's end where the person is: the 21st's midnight
  await start("#/", {
    "GET /api/users?q=bo": [bob],
    "POST /api/files/1/shares": { ok: true },
    "POST /api/files/1/links": { token: "tok", path: "#/link/file/1/tok" },
  });
  await press("Share", "mine.csv");
  await type("date", "2026-10-20");
  await type("Find people by email or name", "bo");
  await act(() => new Promise((r) => setTimeout(r, 300))); // the search waits for typing to pause
  await settle();
  defaults["GET /api/files/1/shares"] = [{
    relation: "viewer", subject_type: "user", subject_id: bob.id, subject_name: "bob", subject_relation: "",
    expires_at: end, created_by: me.id,
  }];
  defaults["GET /api/files/1/links"] = [{ id: "l1", created_at: at, expires_at: end, created_by: "alice" }];
  try {
    await press("bob (bob@example.com)");
    expect(bodies["POST /api/files/1/shares"]).toEqual({
      relation: "viewer", subject_type: "user", subject_id: bob.id, expires_at: end,
    });
    await press("Make a link");
    expect(bodies["POST /api/files/1/links"]).toEqual({ expires_at: end });
    const day = new Date(2026, 9, 20).toLocaleDateString();
    expect(div.querySelector(".modal tr")?.textContent).toBe(`bobcan viewuntil ${day}Remove`);
    expect(shown()).toContain(`, until ${day}`);
  } finally {
    defaults["GET /api/files/1/shares"] = [];
    defaults["GET /api/files/1/links"] = [];
  }
});

test("Deny, then Cancel, denies nothing; a reason goes with the denial", async () => {
  const request: RequestRow = {
    id: 5, object_type: "folder", object_id: "3", relation: "viewer", requester: bob.id, reason: "to read",
    duration: "7 days", created_at: at, mine: false, requester_name: "bob",
  };
  await start("#/requests", { "GET /api/requests": [request], "POST /api/requests/5/decision": { ok: true } });
  expect(shown()).toContain('bob asks to view folder #3 for 7 days: "to read"');
  vi.stubGlobal("prompt", () => null);
  await press("Deny");
  expect(log).not.toContain("POST /api/requests/5/decision");
  vi.stubGlobal("prompt", () => "not now");
  await press("Deny");
  expect(bodies["POST /api/requests/5/decision"]).toEqual({ approve: false, note: "not now" });
});

test("a preview's Download that fails says so", async () => {
  await start("#/", {
    "GET /api/home": { folders: [], files: [file(1, "photo.png", true, { content_type: "image/png" })] },
    "GET /api/files/1/download?preview=true": { url: "about:blank", content_type: "image/png" },
    "GET /api/files/1/download": new Failure(404, "not found"),
  });
  await press("📄 photo.png");
  await press("Download");
  expect(div.querySelector(".modal .error")?.textContent).toBe("not found");
});

test("leaving a group asks only to leave, and a refusal says so", async () => {
  const team = { id: "g1", name: "Team", parent_id: null, member: true, manage: false };
  await start("#/groups", {
    "GET /api/groups": [team],
    "GET /api/groups/g1/members": { members: [], manage: false },
    "DELETE /api/groups/g1/members/u1": new Failure(500, "the server is down"),
  });
  await press("👥 Team");
  log = [];
  await press("Leave this group");
  expect(log[0]).toBe("DELETE /api/groups/g1/members/u1");
  expect(shown()).toContain("the server is down");
});
