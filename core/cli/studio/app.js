// rowstile Studio: the page. Everything it shows comes from the command's API (studio.py), asked with the
// token from the URL; text goes into the page as text, never as HTML.
// Plain JavaScript, typed with JSDoc and checked strictly (core/cli/tsconfig.studio.json).
"use strict";

// --- what the API answers (studio.py) ---------------------------------------------------------------------
/** @typedef {{name: string, src: string, line: string}} Perm */
/** @typedef {{name: string, line: string, subjects: string[], shared: boolean}} Relation */
/** @typedef {{name: string, table: string, principal: boolean, perms: Perm[], relations: Relation[], line: string}} Type */
/** @typedef {{database: string, as: string, writable: boolean, types: Type[], tables: string[], principals: string[], policy_file: string | null}} Overview */
/** @typedef {{id: string | null, visible: boolean, values: Record<string, unknown>, masked: string[], perms: string[]}} Row */
/** @typedef {{table: string, type: string | null, columns: string[], rows: Row[], offset: number, more: boolean, total: number, visible_total: number}} Rows */
/** @typedef {{text: string, grants: boolean, more_objects: number, more_people: number, also: string[], elsewhere: {type: string, perm: string, n: number}[], fewer_people: number, takes: {type: string, perm: string, n: number, people: number}[], lines: string[], kinds: string[]}} Way */
/** @typedef {{text: string, error: string, lines: string[], kinds: string[]}} Untried */
/** @typedef {{holds: boolean, explain: string[], needs: string, tried: boolean, stops: string[], notes: string[], ways: Way[], untried: Untried[]}} Why */
/** @typedef {{check: string, named: string}} Test */
/** @typedef {{change: string, type: string, what: string, users: number, objects: number}} Summary */
/** @typedef {{change: string, type: string, what: string, id: string, user_id: string | null}} Change */
/** @typedef {{same_text: boolean, summary: Summary[], rows: Change[], truncated: boolean}} Diff */
/** @typedef {{relation: string, subject_type: string, subject_id: string, subject_relation: string, expires_at: string | null, created_by: string | null}} Share */
/** @typedef {{id: number, object_type: string, object_id: string, relation: string, requester: string, reason: string | null}} AccessRequest */
/** @typedef {{shares: Share[], requests: AccessRequest[]}} Shares */
/** @typedef {{overview: Overview, rows: Rows, why: Why, test: Test, graph: {mermaid: string}, diff: Diff, shares: Shares,
 *             share: {ok: boolean}, unshare: {ok: boolean}, decide: {ok: boolean}}} Answers */
/** @typedef {{initialize(options: object): void, render(id: string, text: string): Promise<{svg: string}>}} Mermaid */

/** An answer the API refused, with the database's reasons when it gave them. */
class Refusal extends Error {
  /** @param {string} message @param {string[]} why */
  constructor(message, why) {
    super(message);
    this.why = why;
  }
}

const token = new URLSearchParams(location.search).get("token") || sessionStorage.getItem("rowstile-token") || "";
sessionStorage.setItem("rowstile-token", token);
if (location.search) history.replaceState(null, "", location.pathname);

/** @type {{overview: Overview | null, as: string, table: string | null, offset: number, rows: Rows | null, selected: Row | null}} */
const state = { overview: null, as: localStorage.getItem("rowstile-as") || "", table: null, offset: 0, rows: null, selected: null };

// --- small helpers --------------------------------------------------------------------------------------
/** @typedef {string | number | boolean | null | undefined | ((ev: Event) => unknown)} AttrValue */
/** @typedef {Node | string | number | null | undefined | false} Leaf */
/** @typedef {Leaf | Leaf[]} Child */
/**
 * @template {keyof HTMLElementTagNameMap} K
 * @param {K} tag @param {Record<string, AttrValue>} [attrs] @param {Child[]} children
 * @returns {HTMLElementTagNameMap[K]}
 */
function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = String(v);
    else if (k.startsWith("on")) { if (typeof v === "function") e.addEventListener(k.slice(2), v); }
    else if (v !== false && v !== null && v !== undefined) e.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat(Infinity)) if (c !== null && c !== undefined && c !== false) e.append(c instanceof Node ? c : String(c));
  return e;
}
/** @param {string} id @returns {HTMLElement} */
function $(id) {
  const e = document.getElementById(id);
  if (!e) throw new Error(`the page has no #${id}`);
  return e;
}
/** @param {string} id @returns {HTMLInputElement} */
const input = (id) => /** @type {HTMLInputElement} */ ($(id));
/** @param {unknown} e */
const message = (e) => (e instanceof Error ? e.message : String(e));
/** @type {ReturnType<typeof setTimeout> | undefined} */
let toastTimer;
/** @param {string} text */
function toast(text) {
  const t = $("toast");
  t.textContent = text;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 5000);
}
/**
 * @template {keyof Answers} P
 * @param {P} path @param {Record<string, string | number | null | undefined>} [params] @param {object} [body]
 * @returns {Promise<Answers[P]>}
 */
async function api(path, params = {}, body) {
  const qs = new URLSearchParams(Object.entries(params).flatMap(([k, v]) => (v === undefined || v === null ? [] : [[k, String(v)]]))).toString();
  const r = await fetch(`/api/${path}${qs ? "?" + qs : ""}`, {
    method: body ? "POST" : "GET",
    headers: { "X-Studio-Token": token, ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const out = await r.json().catch(() => ({ detail: r.statusText }));
  // a token this Studio doesn't take (it was started again since the page was opened, the answer says): forgotten,
  // so a reload asks for the address rowstile printed rather than sending it again
  if (r.status === 401) sessionStorage.removeItem("rowstile-token");
  if (!r.ok) throw new Refusal(out.detail || r.statusText, out.why || []);
  return out;
}
const who = () => state.as || "anyone";
/** What the page loaded first (start() sets it before anything else runs). */
function overview() {
  if (!state.overview) throw new Error("Studio hasn't loaded yet");
  return state.overview;
}

// --- tabs and the view-as box ---------------------------------------------------------------------------
/** @type {Record<string, () => unknown>} */
const tabs = { graph: loadGraph, diff: loadDiff, shares: loadRequests };
document.querySelectorAll("nav button").forEach((b) => b.addEventListener("click", () => {
  const tab = /** @type {HTMLElement} */ (b).dataset.tab || "";
  document.querySelectorAll("nav button").forEach((x) => x.classList.toggle("on", x === b));
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("on", t.id === tab));
  (tabs[tab] || (() => {}))();
}));
$("as-form").addEventListener("submit", (e) => {
  e.preventDefault();
  state.as = input("as").value.trim();
  localStorage.setItem("rowstile-as", state.as);
  if (state.table) loadRows(state.table, state.offset);
});

async function start() {
  if (!token) {
    $("grid-head").textContent = "Open Studio from the address rowstile printed (it carries the token).";
    return;
  }
  try {
    state.overview = await api("overview");
  } catch (e) {
    $("grid-head").textContent = message(e);
    return;
  }
  const o = state.overview;
  $("db").textContent = `${o.database}, as ${o.as}`;
  $("mode").textContent = o.writable ? "can write" : "read-only";
  $("mode").classList.toggle("write", o.writable);
  input("as").value = state.as;
  $("as-list").replaceChildren(el("option", { value: "anyone" }), ...o.principals.map((p) => el("option", { value: `${p}:` })));
  const types = new Map(o.types.map((t) => [t.table, t.name]));
  $("table-list").replaceChildren(...o.tables.map((t) => el("button", { "data-table": t, onclick: () => loadRows(t, 0) },
    t, types.get(t) ? el("small", {}, `type ${types.get(t)}`) : null)));
  $("shares-type").replaceChildren(...o.types.filter((t) => t.relations.some((r) => r.shared)).map((t) => el("option", {}, t.name)));
}

// --- tables, as someone -----------------------------------------------------------------------------------
/** @param {string} table @param {number} offset */
async function loadRows(table, offset) {
  state.table = table;
  state.offset = offset;
  document.querySelectorAll("#table-list button").forEach((b) => b.classList.toggle("on", /** @type {HTMLElement} */ (b).dataset.table === table));
  $("grid-head").textContent = "Loading…";
  let data;
  try {
    data = await api("rows", { table, as: who(), offset });
  } catch (e) {
    $("grid-head").textContent = message(e);
    $("grid").replaceChildren();
    return;
  }
  state.rows = data;
  $("grid-head").replaceChildren(el("strong", {}, who()), ` sees ${data.visible_total} of ${data.total} rows of ${table}`,
    data.type ? ` (type ${data.type}; click a row for why)` : "");
  const cols = data.columns.slice(0, 8);
  const head = el("tr", {}, el("th", {}, ""), ...cols.map((c) => el("th", {}, c)), data.type ? el("th", {}, "permissions") : null);
  const body = data.rows.map((r) => el("tr", {
    class: `row${r.visible ? "" : " gone"}`, "data-id": r.id,
    onclick: data.type ? (/** @type {Event} */ ev) => select(r, /** @type {HTMLElement} */ (ev.currentTarget)) : null,
  },
    el("td", { title: r.visible ? "visible" : "hidden from them" }, r.visible ? "" : "hidden"),
    // a masked column they may not read: what they get is empty, and the grid says why
    ...cols.map((c) => (r.masked.includes(c) ? el("td", { class: "masked", title: "masked: they get it empty" }, "masked")
      : el("td", { title: fmt(r.values[c]) }, fmt(r.values[c])))),
    data.type ? el("td", {}, r.perms.length ? r.perms.map((p) => el("span", { class: "chip" }, p)) : el("span", { class: "muted" }, "none")) : null));
  $("grid").replaceChildren(el("table", {}, el("thead", {}, head), el("tbody", {}, body)));
  $("pager").replaceChildren(
    offset > 0 ? el("button", { onclick: () => loadRows(table, Math.max(0, offset - 50)) }, "Previous") : "",
    " ", data.more ? el("button", { onclick: () => loadRows(table, offset + 50) }, "Next") : "");
  $("panel").hidden = true;
}
/** @param {unknown} v */
const fmt = (v) => (v === null || v === undefined ? "" : typeof v === "object" ? JSON.stringify(v) : String(v));

/** @param {Row} row @param {HTMLElement} tr */
function select(row, tr) {
  document.querySelectorAll("tr.row").forEach((x) => x.classList.toggle("sel", x === tr));
  state.selected = row;
  const type = overview().types.find((t) => t.name === state.rows?.type);
  if (!type || row.id === null) return;
  const id = row.id;
  const panel = $("panel");
  panel.hidden = false;
  panel.replaceChildren(
    el("h3", {}, `${type.name} ${id}`),
    el("p", { class: "muted" }, `as ${who()}; ${row.visible ? "the row is visible to them" : "the row is hidden from them"}`),
    ...type.perms.map((p) => {
      const holds = row.perms.includes(p.name);
      const out = el("div", { class: "perm-body" });
      return el("div", { class: "perm" },
        el("div", { class: "perm-head" },
          el("span", { class: `chip${holds ? "" : " no"}` }, holds ? "yes" : "no"),
          el("span", { class: "name" }, p.name), el("code", { class: "muted" }, p.line),
          el("button", { onclick: () => why(type.name, id, p.name, out) }, holds ? "Why?" : "Why not?")),
        out);
    }));
}

/** @param {string} type @param {string} id @param {string} perm @param {HTMLElement} out */
async function why(type, id, perm, out) {
  out.replaceChildren(el("p", { class: "muted" }, state.as ? "Asking…" : "Pick someone to view as first."));
  if (!state.as || state.as === "anyone") return;
  let a;
  try {
    a = await api("why", { as: who(), type, id, perm });
  } catch (e) {
    out.replaceChildren(el("p", {}, message(e)));
    return;
  }
  /** @type {HTMLElement[]} */
  const parts = [el("pre", {}, a.explain.join("\n") || (a.holds ? "yes" : "no")), el("p", { class: "muted mono" }, a.needs)];
  if (!a.holds) {
    if (a.ways.length) {
      parts.push(el("p", {}, a.tried ? "Would be granted by (each tried, then undone):" : "Might be granted by (not tried: Studio is read-only here):"));
      parts.push(el("ul", { class: "ways" }, a.ways.map((w) => el("li", {}, w.text, " ", el("code", { class: "muted" }, w.lines.join(", ")),
        (w.also.length || w.more_objects || w.elsewhere.length || w.more_people || w.takes.length) ? el("div", { class: "also" },
          [w.also.length ? `also gives ${w.also.join(", ")} on it` : "",
           w.more_objects ? `also gives ${perm} on ${w.more_objects} more ${type}${w.more_objects === 1 ? "" : "s"} to them` : "",
           ...w.elsewhere.map((e) => `also gives ${e.perm} on ${e.n} more ${e.type}${e.n === 1 ? "" : "s"} to them`),
           w.more_people ? `and to ${w.more_people} more ${w.more_people === 1 ? "person" : "people"} on this ${type}` : "",
           ...w.takes.map((e) => `takes ${e.perm} on ${e.n ? `${e.n} other ${e.type}${e.n === 1 ? "" : "s"}` : "it"} from ${e.people} ${e.people === 1 ? "person" : "people"}`)].filter(Boolean).join(", ")) : null))));
    } else if (a.stops.length) {
      // the person or the object isn't there, or the type's where leaves it out: nothing was tried
      for (const s of a.stops) parts.push(el("p", {}, s));
    } else {
      parts.push(el("p", {}, a.untried.length ? "No single change that could be tried grants it." : "No single change to shares or links grants it."));
    }
    // the changes the database refused to try, with its reason (rowstile why's "could not be tried")
    if (a.untried.length) {
      parts.push(el("p", {}, "Could not be tried:"));
      parts.push(el("ul", { class: "ways" }, a.untried.map((u) => el("li", {}, u.text, " ", el("code", { class: "muted" }, u.lines.join(", ")),
        el("div", { class: "also" }, u.error)))));
    }
    for (const n of a.notes) parts.push(el("p", { class: "muted" }, n));
  }
  parts.push(el("div", { class: "row" }, el("span", { class: "muted" }, "Make a test:"),
    el("button", { onclick: () => makeTest(type, id, perm, "can", out) }, `${who()} can ${perm}`),
    el("button", { onclick: () => makeTest(type, id, perm, "cannot", out) }, `… cannot`)));
  out.replaceChildren(...parts);
}

/** @param {string} type @param {string} id @param {string} perm @param {"can" | "cannot"} expect @param {HTMLElement} out */
async function makeTest(type, id, perm, expect, out) {
  try {
    const t = await api("test", { as: who(), type, id, perm, expect });
    const box = el("div", {},
      el("p", { class: "muted" }, "A check on the data there now (the policy's test section):"),
      el("pre", {}, t.check), copy(t.check),
      el("p", { class: "muted" }, "A named test that brings its own rows (add the rows that link them):"),
      el("pre", {}, t.named), copy(t.named));
    out.append(box);
  } catch (e) {
    toast(message(e));
  }
}
/** @param {string} text */
const copy = (text) => el("button", { onclick: () => navigator.clipboard.writeText(text).then(() => toast("Copied")) }, "Copy");

// --- the graph ------------------------------------------------------------------------------------------------
const page = /** @type {Window & {mermaid?: Mermaid}} */ (window);
// Mermaid, one version, checked against its hash before it runs: this page holds the token
const MERMAID = "https://cdn.jsdelivr.net/npm/mermaid@11.17.2/dist/mermaid.min.js";
const MERMAID_HASH = "sha384-EOXBFmc3gx5mb+vn0vPvvGqACToJD24hhacX5Yx+8NUUQrHIle/Qi5Bg9o3zKwW2";
let graphs = 0;
async function loadGraph() {
  const view = $("graph-view");
  let g;
  try {
    g = await api("graph");
  } catch (e) {
    view.textContent = message(e);
    return;
  }
  try {
    const mermaid = await script(MERMAID, MERMAID_HASH);
    const dark = matchMedia("(prefers-color-scheme: dark)").matches;
    mermaid.initialize({ startOnLoad: false, securityLevel: "strict", theme: dark ? "dark" : "default" });
    // drawn again each time the tab is opened: under rowstile dev the policy changes
    const { svg } = await mermaid.render(`policy-graph-${++graphs}`, g.mermaid);
    view.innerHTML = svg;               // mermaid's own output, from the policy's names (strict mode)
    view.querySelectorAll("g.node").forEach((n) => n.addEventListener("click", () => detail(n.id)));
    view.querySelectorAll("g.cluster").forEach((n) => n.addEventListener("click", () => detail(n.id)));
  } catch {
    view.replaceChildren(el("p", { class: "muted" }, "Mermaid couldn't load (offline?): the graph as text, for any Mermaid viewer."),
      el("pre", {}, g.mermaid));
  }
}
/** Mermaid, loaded once. @param {string} src @param {string} integrity @returns {Promise<Mermaid>} */
function script(src, integrity) {
  return new Promise((ok, no) => {
    const loaded = () => (page.mermaid ? ok(page.mermaid) : no(new Error("mermaid didn't load")));
    if (page.mermaid) return loaded();
    const s = el("script", { src, integrity, crossorigin: "anonymous" });
    s.onload = loaded;
    s.onerror = no;
    document.head.append(s);
  });
}
/** @param {string} domId */
function detail(domId) {
  const types = overview().types;
  // a node is type__name, a type's box type__0 (devtools.py): names hold no __, so the split is the type's
  const [typeName, member] = domId.replace(/^flowchart-/, "").replace(/-\d+$/, "").split("__");
  const t = types.find((x) => x.name === typeName);
  if (!t) return;
  const name = member && member !== "0" ? member : null;
  const p = t.perms.find((x) => x.name === name);
  const r = t.relations.find((x) => x.name === name);
  $("graph-detail").replaceChildren(...present(
    el("h3", {}, name ? `${t.name}.${name}` : `type ${t.name}`),
    el("p", { class: "muted mono" }, `${t.table}, ${t.line}`),
    p ? el("pre", {}, `can ${p.name} = ${p.src}   (${p.line})`) : null,
    r ? el("pre", {}, `${r.name} : ${r.subjects.join(", ")}${r.shared ? "  shared" : ""}   (${r.line})`) : null,
    !name ? el("pre", {}, [...t.relations.map((x) => `${x.name} : ${x.subjects.join(", ")}${x.shared ? "  shared" : ""}`),
      ...t.perms.map((x) => `can ${x.name} = ${x.src}`)].join("\n")) : null));
}
/** The parts that are there. @param {(HTMLElement | null)[]} parts @returns {HTMLElement[]} */
const present = (...parts) => parts.filter((x) => x !== null);

// --- the access diff -------------------------------------------------------------------------------------------
async function loadDiff() {
  const view = $("diff-view");
  view.textContent = "Comparing the policy file with the one in force…";
  let d;
  try {
    d = await api("diff");
  } catch (e) {
    view.textContent = message(e);
    return;
  }
  if (!d.summary.length) {
    view.replaceChildren(el("p", {}, d.same_text ? "The policy file is the one in force." : "The policy file changes no one's access on this data."));
    return;
  }
  view.replaceChildren(
    el("p", {}, `What ${overview().policy_file || "the policy file"} would change on this data, if applied:`),
    el("table", {}, el("thead", {}, el("tr", {}, ...["change", "type", "permission", "people", "objects"].map((h) => el("th", {}, h)))),
      el("tbody", {}, d.summary.map((s) => el("tr", {}, el("td", { class: s.change.startsWith("gain") ? "gain" : "lose" }, s.change),
        el("td", {}, s.type), el("td", {}, s.what), el("td", {}, s.users), el("td", {}, s.objects))))),
    el("h2", {}, d.truncated ? "The first 500" : "Each one"),
    el("table", {}, el("tbody", {}, d.rows.map((r) => el("tr", {},
      el("td", { class: r.change.startsWith("gain") ? "gain" : "lose" }, r.change), el("td", {}, r.user_id || "anyone"),
      el("td", {}, `${r.what} on ${r.type} ${r.id}`))))));
}

// --- shares and requests ---------------------------------------------------------------------------------------
$("shares-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  await loadShares(input("shares-type").value, input("shares-id").value.trim());
});
/** @param {string} type @param {string} id */
async function loadShares(type, id) {
  const view = $("shares-view");
  if (!id) return;
  let d;
  try {
    d = await api("shares", { type, id });
  } catch (e) {
    view.textContent = message(e);
    return;
  }
  const w = overview().writable;
  const t = overview().types.find((x) => x.name === type);
  view.replaceChildren(
    d.shares.length ? el("table", {}, el("tbody", {}, d.shares.map((s) => el("tr", {},
      el("td", {}, s.relation), el("td", {}, `${s.subject_type}${s.subject_relation ? "#" + s.subject_relation : ""} ${s.subject_id}`),
      el("td", { class: "muted" }, s.expires_at ? `until ${s.expires_at}` : ""), el("td", { class: "muted" }, s.created_by ? `by ${s.created_by}` : ""),
      w ? el("td", {}, el("button", { onclick: () => change("unshare", { type, id, relation: s.relation, subject_type: s.subject_type, subject_id: s.subject_id, subject_relation: s.subject_relation }, () => loadShares(type, id)) }, "Unshare")) : null))))
      : el("p", { class: "muted" }, `No shares on ${type} ${id}.`),
    w && t ? shareForm(t, id) : el("p", { class: "muted" }, "Read-only: start Studio with --write (or rowstile dev) to change shares."));
}
/** @param {Type} t @param {string} id */
function shareForm(t, id) {
  const rel = el("select", {}, t.relations.filter((r) => r.shared).map((r) => el("option", {}, r.name)));
  const st = el("input", { placeholder: "user", size: 8, value: "user" });
  const sid = el("input", { placeholder: "id", size: 6 });
  return el("form", { class: "row", onsubmit: (e) => {
    e.preventDefault();
    change("share", { type: t.name, id, relation: rel.value, subject_type: st.value, subject_id: sid.value }, () => loadShares(t.name, id));
  } }, el("span", { class: "muted" }, `As ${who()}, share`), rel, "with", st, sid, el("button", { class: "primary" }, "Share"));
}
/** @param {"share" | "unshare" | "decide"} what @param {object} body @param {() => unknown} then */
async function change(what, body, then) {
  try {
    await api(what, {}, { ...body, as: who() });
    toast("Done");
    then();
  } catch (e) {
    toast(e instanceof Refusal && e.why.length ? `${e.message}: ${e.why[0]}` : message(e));
  }
}
async function loadRequests() {
  const view = $("requests-view");
  let d;
  try {
    d = await api("shares");
  } catch (e) {
    view.textContent = message(e);
    return;
  }
  const w = overview().writable;
  view.replaceChildren(d.requests.length ? el("table", {}, el("tbody", {}, d.requests.map((r) => el("tr", {},
    el("td", {}, `#${r.id}`), el("td", {}, `user ${r.requester} asks for ${r.relation} on ${r.object_type} ${r.object_id}`),
    el("td", { class: "muted" }, r.reason || ""),
    w ? el("td", {}, el("button", { onclick: () => change("decide", { request: r.id, approve: true }, loadRequests) }, `Approve as ${who()}`),
      " ", el("button", { onclick: () => change("decide", { request: r.id, approve: false }, loadRequests) }, "Deny")) : null))))
    : el("p", { class: "muted" }, "None pending."));
}

start();
