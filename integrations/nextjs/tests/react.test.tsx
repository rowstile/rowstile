// @vitest-environment jsdom
// The React kit against the running app's routes (authzRoutes): a list's buttons in one call, <Can>, the
// headless share dialog, access requests, and the change feed that keeps them current. Then, without the
// server, what the routes don't do on cue: errors, live updates, keys of several columns.
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { idText, type Id } from "@rowstile/client";
import { AuthzProvider, Can, ShareDialog, useAccessRequest, usePerms } from "@rowstile/react";
import { SERVER, as, seed } from "./data";

beforeEach(seed);
afterEach(cleanup);

const nodeFetch = globalThis.fetch;
const asUser = (user: string): typeof fetch => (input, init) =>
  nodeFetch(String(input).startsWith("http") ? input : `${SERVER}${input}`, as(user, init as RequestInit));

function Buttons() {
  const perms = usePerms("project", [1, 2, 3]);
  if (perms.loading) return <p>loading</p>;
  return <ul>{[1, 2, 3].map((id) => <li key={id}>{id}:{perms(id).perms.join(",")}{perms(id).can("edit") && " [rename]"}</li>)}</ul>;
}

test("usePerms: one call for a list; <Can>", async () => {
  render(
    <AuthzProvider fetch={asUser("3")} live={false}>
      <Buttons />
      <Can type="project" id={1} perm="edit" fallback={<span>no edit on 1</span>}><span>edit on 1</span></Can>
      <Can type="project" id={3} perm="edit" fallback={<span>no edit on 3</span>}><span>edit on 3</span></Can>
    </AuthzProvider>,
  );
  await waitFor(() => expect(screen.getByText("1:edit,view [rename]")).toBeTruthy());
  expect(screen.getByText("2:")).toBeTruthy();                   // bo's project: cy may not see it
  expect(screen.getByText("3:view")).toBeTruthy();
  await waitFor(() => expect(screen.getByText("edit on 1")).toBeTruthy());
  expect(screen.getByText("no edit on 3")).toBeTruthy();
});

test("ShareDialog: share and unshare, as the database allows", async () => {
  let dialog: Parameters<Parameters<typeof ShareDialog>[0]["children"]>[0] | undefined;
  render(
    <AuthzProvider fetch={asUser("1")} live={false}>
      <ShareDialog type="project" id={1}>
        {(d) => {
          dialog = d;
          if (d.error) return <p>{d.error.message}</p>;
          return <p>{d.loading ? "loading" : `shared with ${d.shares.map((s) => s.subject_id).join(",") || "nobody"}`}</p>;
        }}
      </ShareDialog>
    </AuthzProvider>,
  );
  await waitFor(() => expect(screen.getByText("shared with nobody")).toBeTruthy());
  await act(() => dialog!.share("viewer", "user", 2));
  await waitFor(() => expect(screen.getByText("shared with 2")).toBeTruthy());
  expect(await (await nodeFetch(`${SERVER}/api/projects`, as("2"))).json()).toEqual([1, 2, 3]);
  await act(() => dialog!.unshare("viewer", "user", 2));
  await waitFor(() => expect(screen.getByText("shared with nobody")).toBeTruthy());
  expect(await (await nodeFetch(`${SERVER}/api/projects`, as("2"))).json()).toEqual([2, 3]);
});

test("ShareDialog: a user who may not share is refused, with the reason", async () => {
  let dialog: Parameters<Parameters<typeof ShareDialog>[0]["children"]>[0] | undefined;
  render(
    <AuthzProvider fetch={asUser("2")} live={false}>
      <ShareDialog type="project" id={3}>{(d) => { dialog = d; return <p>{d.loading ? "loading" : "ready"}</p>; }}</ShareDialog>
    </AuthzProvider>,
  );
  await waitFor(() => expect(screen.getByText("ready")).toBeTruthy());
  const e = await dialog!.share("viewer", "user", 2).catch((err) => err);
  expect(e.problem?.status).toBe(403);
});

// the answers are the signed-in user's: when the provider's user changes, the hooks ask again, and the
// earlier user's answers are not shown meanwhile
test("usePerms: another user, without a page load", async () => {
  let who = "3";
  const asWho: typeof fetch = (input, init) => asUser(who)(input, init);
  const page = (user: string) => (
    <AuthzProvider fetch={asWho} live={false} user={user}>
      <Can type="project" id={1} perm="edit" fallback={<span>no edit on 1</span>}><span>edit on 1</span></Can>
    </AuthzProvider>);
  const { rerender } = render(page("3"));
  await waitFor(() => expect(screen.getByText("edit on 1")).toBeTruthy());
  who = "2";
  rerender(page("2"));
  expect(screen.getByText("no edit on 1")).toBeTruthy();          // at once: cy's answer is forgotten
  await new Promise((r) => setTimeout(r, 300));
  expect(screen.getByText("no edit on 1")).toBeTruthy();
});

function Many() {
  const ids = Array.from({ length: 400 }, (_, i) => i + 1);
  const perms = usePerms("project", ids);
  return <p>{perms.loading ? "loading" : perms.error ? `failed: ${perms.error.message}` : `1:${perms(1).perms.join(",")} 400:${perms(400).perms.join(",")}`}</p>;
}

test("usePerms: a long list of ids", async () => {
  const posted: string[] = [];
  const counting: typeof fetch = (input, init) => {
    posted.push(`${init?.method ?? "GET"} ${String(input).split("?")[0]}`);
    return asUser("3")(input, init);
  };
  render(<AuthzProvider fetch={counting} live={false}><Many /></AuthzProvider>);
  await waitFor(() => expect(screen.getByText("1:edit,view 400:")).toBeTruthy());
  expect(posted).toEqual(["POST /api/authz/perms"]);
});

function Ask() {
  const r = useAccessRequest("project", 2);
  return <button onClick={() => r.request("viewer", "for the review").catch(() => undefined)}>{r.status}</button>;
}

test("useAccessRequest: asking for access", async () => {
  render(<AuthzProvider fetch={asUser("3")} live={false}><Ask /></AuthzProvider>);
  await act(async () => screen.getByText("idle").click());
  await waitFor(() => expect(screen.getByText("sent")).toBeTruthy());
});

// A server component renders the kit: the app's layout (app/layout.tsx) wraps every page in <AuthzProvider>,
// and app/buttons/page.tsx renders <Can>, whose fallback the server sends until the browser has asked.
test("a server component renders the provider and <Can> (the App Router's layout)", async () => {
  const r = await nodeFetch(`${SERVER}/buttons`, as("1"));
  const html = await r.text();
  expect(r.status, html.slice(0, 500)).toBe(200);
  expect(html).toContain('<span id="rename">no rename yet</span>');
});

// --- without the server: answers of the test's own, for what the routes don't do on cue ---------------------
/** A fetch that answers as the routes might, and keeps what it was asked. */
function answering(answer: (path: string, init?: RequestInit) => Response) {
  const asked: string[] = [];
  const f: typeof fetch = async (input, init) => {
    asked.push(`${init?.method ?? "GET"} ${String(input)}${init?.body ? " " + String(init.body) : ""}`);
    return answer(String(input), init);
  };
  return Object.assign(f, { asked });
}

/** jsdom has no EventSource: one the test drives. */
class Events {
  static last: Events | undefined;
  listeners: Record<string, (() => void)[]> = {};
  closed = false;
  constructor(public url: string) {
    Events.last = this;
  }
  addEventListener(type: string, listener: () => void) {
    (this.listeners[type] ??= []).push(listener);
  }
  emit(type: string) {
    for (const listener of this.listeners[type] ?? []) listener();
  }
  close() {
    this.closed = true;
  }
}

function One({ ids = [1] as Id[] }) {
  const perms = usePerms("project", ids);
  return <p>{perms.loading ? "loading" : perms.error ? `failed: ${perms.error.message}` : ids.map((id) => `${JSON.stringify(id)}:${perms(id).perms.join(",")}`).join(" ")}</p>;
}

test("live: a change asks again, once for changes close together, and so does a stream opened again", async () => {
  vi.stubGlobal("EventSource", Events);
  const answers = [{ "1": ["view"] }, { "1": ["edit", "view"] }, { "1": [] }];
  const f = answering(() => Response.json(answers.shift()));
  try {
    const { unmount } = render(<AuthzProvider fetch={f} endpoint="/authz"><One /></AuthzProvider>);
    await waitFor(() => expect(screen.getByText("1:view")).toBeTruthy());
    const source = Events.last!;
    expect(source.url).toBe("/authz/events");
    source.emit("open");                                          // the first time: nothing was missed
    await new Promise((r) => setTimeout(r, 100));
    expect(f.asked.length).toBe(1);
    source.emit("changed");
    await new Promise((r) => setTimeout(r, 10));
    source.emit("changed");                                       // two changes 10 ms apart: asked again once
    await waitFor(() => expect(screen.getByText("1:edit,view")).toBeTruthy());
    await new Promise((r) => setTimeout(r, 100));
    expect(f.asked.length).toBe(2);
    source.emit("open");                                          // opened again after a gap: what changed meanwhile
    await waitFor(() => expect(screen.getByText("1:")).toBeTruthy());
    expect(f.asked).toEqual(Array(3).fill("GET /authz/perms?type=project&ids=1"));
    unmount();
    expect(source.closed).toBe(true);
  } finally {
    vi.unstubAllGlobals();
  }
});

test("the page's own fetch by default, no live updates without EventSource, and a hook outside the provider", async () => {
  const f = answering(() => Response.json({ "1": ["view"] }));
  vi.stubGlobal("fetch", f);
  const said = vi.spyOn(console, "error").mockImplementation(() => undefined);
  try {
    render(<AuthzProvider><One /></AuthzProvider>);
    await waitFor(() => expect(screen.getByText("1:view")).toBeTruthy());
    expect(f.asked).toEqual(["GET /api/authz/perms?type=project&ids=1"]);
    expect(() => render(<One />)).toThrow("@rowstile/react: wrap the app in <AuthzProvider>");
  } finally {
    vi.unstubAllGlobals();
    said.mockRestore();
  }
});

test("an answer that isn't ok: its problem's detail, else its title, else its status", async () => {
  const f = answering((path) => (path.endsWith("ids=1") ? Response.json({ title: "Forbidden", status: 403, detail: "" }, { status: 403 })
    : new Response("<html>", { status: 502, statusText: "Bad Gateway" })));
  render(<AuthzProvider fetch={f} live={false}><One ids={[1]} /><One ids={[2]} /></AuthzProvider>);
  await waitFor(() => expect(screen.getByText("failed: Forbidden")).toBeTruthy());
  await waitFor(() => expect(screen.getByText("failed: Bad Gateway")).toBeTruthy());
});

test("a key of several columns, as the database writes it; an empty list asks nothing", async () => {
  const f = answering(() => Response.json({ '("1","a\\"b")': ["view"], "4": ["edit"] }));
  render(<AuthzProvider fetch={f} live={false}><One ids={[[1, 'a"b'], [4], 5]} /><One ids={[]} /></AuthzProvider>);
  await waitFor(() => expect(screen.getByText('[1,"a\\"b"]:view [4]:edit 5:')).toBeTruthy());
  expect(screen.queryByText("loading")).toBeNull();                // the empty list: answered at once, with nothing,
  expect(f.asked).toEqual([`GET /api/authz/perms?type=project&ids=${encodeURIComponent('("1","a\\"b")')}&ids=4&ids=5`]);   // unasked
});

// the kit writes keys itself (@rowstile/client needs Node, so a browser can't load its idText): the same text
test("a key as the kit writes it is the client's idText", async () => {
  const ids: Id[] = [[1, 'a"b'], ["x\\y", "c,d"], [7, ""], ["(", ")"], [4], "5", 6];
  const f = answering(() => Response.json({}));
  render(<AuthzProvider fetch={f} live={false}><One ids={ids} /></AuthzProvider>);
  await waitFor(() => expect(f.asked.length).toBe(1));
  expect(f.asked).toEqual([`GET /api/authz/perms?type=project&${ids.map((id) => "ids=" + encodeURIComponent(idText(id))).join("&")}`]);
});

test("the share dialog: another user's shares never shown, an error, a share, asked again", async () => {
  let listed = 0;
  const f = answering((path) => {
    if (!path.includes("/shares")) return Response.json({ ok: true });
    listed += 1;
    if (listed === 2) return Response.json({ title: "Forbidden", status: 403, detail: "you cannot see the shares of project 1" }, { status: 403 });
    return Response.json(listed === 1 ? [{ relation: "viewer", subject_type: "user", subject_id: "2", subject_relation: "" }] : []);
  });
  let dialog: Parameters<Parameters<typeof ShareDialog>[0]["children"]>[0] | undefined;
  const page = (user: string) => (
    <AuthzProvider fetch={f} live={false} user={user}>
      <ShareDialog type="project" id={1}>
        {(d) => { dialog = d; return <p>{d.loading ? "loading" : d.error ? d.error.message : d.shares.map((s) => s.subject_id).join(",") || "nobody"}</p>; }}
      </ShareDialog>
    </AuthzProvider>);
  const { rerender } = render(page("1"));
  await waitFor(() => expect(screen.getByText("2")).toBeTruthy());
  rerender(page("3"));                                             // another user: not the earlier one's, even for a moment
  expect(screen.getByText("loading")).toBeTruthy();
  await waitFor(() => expect(screen.getByText("you cannot see the shares of project 1")).toBeTruthy());
  await act(() => dialog!.share("viewer", "team", 7, "member"));
  await waitFor(() => expect(screen.getByText("nobody")).toBeTruthy());
  act(() => dialog!.refresh());
  await waitFor(() => expect(listed).toBe(4));
  expect(f.asked).toContain('POST /api/authz/share {"type":"project","id":"1","relation":"viewer","subjectType":"team","subjectId":"7","subjectRelation":"member"}');
});

test("an access request refused: failed, and the error is the caller's to see", async () => {
  const f = answering(() => Response.json({ title: "Forbidden", status: 403, detail: "you may not ask for project 2" }, { status: 403 }));
  render(<AuthzProvider fetch={f} live={false}><Ask /></AuthzProvider>);
  await act(async () => screen.getByText("idle").click());
  await waitFor(() => expect(screen.getByText("failed")).toBeTruthy());
});

test("live updates: the change feed says when access may have changed", async () => {
  const controller = new AbortController();
  const events = await nodeFetch(`${SERVER}/api/authz/events`, as("2", { signal: controller.signal }));
  expect(events.headers.get("content-type")).toContain("text/event-stream");
  const reader = events.body!.getReader();
  const seen: string[] = [];
  const reading = (async () => {
    const decoder = new TextDecoder();
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return;
      seen.push(decoder.decode(value));
      if (seen.join("").includes("event: changed")) return;
    }
  })();
  await new Promise((r) => setTimeout(r, 300));                 // the server is listening
  const share = await nodeFetch(`${SERVER}/api/authz/share`, as("1", {
    method: "POST", body: JSON.stringify({ type: "project", id: "1", relation: "viewer", subjectType: "user", subjectId: "2" }),
  }));
  expect(share.status).toBe(200);
  await Promise.race([reading, new Promise((_, no) => setTimeout(() => no(new Error("no change event: " + seen.join(""))), 10_000))]);
  expect(seen.join("")).toContain("event: changed");
  controller.abort();
});
