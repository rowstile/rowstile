// The playground page: edit a policy, its tables and its tests; on each change the policy is compiled (in
// Pyodide, in a worker), applied to a fresh database with the tables (PGlite) and its tests run. The engine is
// core.mjs, which test.mjs runs headless. The versions below are package.json's (test.mjs checks they match).
// Plain JavaScript, typed with JSDoc and checked strictly (playground/tsconfig.json).
import { database, line } from "./core.mjs";

const PYODIDE = "https://cdn.jsdelivr.net/npm/pyodide@314.0.7/";
const PGLITE = "https://cdn.jsdelivr.net/npm/@electric-sql/pglite@0.5.8/dist/index.js";
const MERMAID = "https://cdn.jsdelivr.net/npm/mermaid@12.0.0/dist/mermaid.esm.min.mjs";

/** @typedef {import("./core.mjs").Compile} Compile */
/** @typedef {import("./core.mjs").Compiled} Compiled */
/** @typedef {import("./core.mjs").Run} Run */
/** @typedef {import("./core.mjs").Database} Database */
/** @typedef {import("./build.mjs").Example} Example */
/** @typedef {{policy: string, data: string, tests: string, as?: string, ask?: string}} State  what a link carries */
/** @typedef {{start(files: Record<string, string>): Promise<boolean>, compile(policy: string, tests: string): Promise<Compile>,
 *             help(code: string): Promise<string | null>}} Engine */
/** @typedef {{initialize(options: object): void, render(id: string, text: string): Promise<{svg: string}>}} Mermaid */

/** @param {string} id @returns {HTMLElement} */
const $ = (id) => {
  const e = document.getElementById(id);
  if (!e) throw new Error(`the page has no #${id}`);
  return e;
};
/** @param {string} id */
const area = (id) => /** @type {HTMLTextAreaElement} */ ($(id));
/** @param {string} id */
const button = (id) => /** @type {HTMLButtonElement} */ ($(id));
const el = {
  example: /** @type {HTMLSelectElement} */ ($("example")), state: $("state"), share: button("share"), policy: area("policy"),
  gutter: $("gutter"), status: $("status"), data: area("data"), tests: area("tests"),
  who: /** @type {HTMLInputElement} */ ($("who")), query: area("query"), runAsk: button("run-ask"),
  answer: $("answer"), results: $("pane-results"), count: $("count"), sql: $("sql"), graph: $("pane-graph"),
  help: $("pane-help"), notice: $("notice"),
};
/** @type {{compiler: Record<string, string>, examples: Example[]}} */
let bundle = { compiler: {}, examples: [] };
/** @type {Engine | null} */
let engine = null;
/** @type {Database | null} */
let db = null;
/** @type {Compiled | null} */
let compiled = null;
/** @type {number | null} */
let errorLine = null;
/** @type {string | null} */
let graphShown = null;
/** @type {State | null} */
let linked = null;                                // what the link the page was opened with carries
const inLine = line();                            // PGlite runs one thing at a time: runs and asks wait in line
let generation = 0;                               // a newer edit makes older answers stale

/** The compiler, in compiler.worker.mjs: each call a promise. @returns {Engine} */
function compilerWorker() {
  const worker = new Worker(new URL("./compiler.worker.mjs", import.meta.url), { type: "module" });
  /** @type {Map<number, {resolve: (result: any) => void, reject: (e: Error) => void}>} */
  const waiting = new Map();
  let n = 0;
  worker.onmessage = ({ data }) => {
    const p = waiting.get(data.id);
    waiting.delete(data.id);
    if (!p) return;
    if (data.error !== undefined) p.reject(new Error(data.error));
    else p.resolve(data.result);
  };
  worker.onerror = (e) => {
    for (const p of waiting.values()) p.reject(new Error(e.message || "the compiler's worker failed"));
    waiting.clear();
  };
  /** @param {string} method @param {unknown[]} args @returns {Promise<any>} (the worker's answer to that method) */
  const call = (method, ...args) => new Promise((resolve, reject) => {
    waiting.set(++n, { resolve, reject });
    worker.postMessage({ id: n, method, args });
  });
  return {
    start: (files) => call("start", PYODIDE, files),
    compile: (policy, tests) => call("compile", policy, tests),
    help: (code) => call("help", code),
  };
}

/** @param {unknown} e */
const said = (e) => (e instanceof Error ? e.message : String(e));
/** @param {unknown} s */
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => /** @type {Record<string, string>} */ ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
/** @param {() => unknown} fn @param {number} ms */
const later = (fn, ms) => {
  /** @type {ReturnType<typeof setTimeout> | undefined} */
  let t;
  return () => { clearTimeout(t); t = setTimeout(fn, ms); };
};

// --- what is being edited, and links that carry it ------------------------------------------------------
/** @returns {State} */
function current() {
  return { policy: el.policy.value, data: el.data.value, tests: el.tests.value, as: el.who.value, ask: el.query.value };
}

/** @param {State} s */
function show(s) {
  el.policy.value = s.policy; el.data.value = s.data; el.tests.value = s.tests;
  el.who.value = s.as ?? "user:1"; el.query.value = s.ask ?? "";
  el.answer.innerHTML = "";
  gutter();
}

/** @param {State} obj */
async function pack(obj) {
  const stream = new Blob([JSON.stringify(obj)]).stream().pipeThrough(new CompressionStream("deflate-raw"));
  const bytes = new Uint8Array(await new Response(stream).arrayBuffer());
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/** @param {string} text @returns {Promise<State>} */
async function unpack(text) {
  const bin = atob(text.replaceAll("-", "+").replaceAll("_", "/"));
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  // whatever the link holds, the page only takes a state: three texts, and who asks what
  /** @type {unknown} */
  const s = JSON.parse(await new Response(stream).text());
  /** @param {unknown} v @returns {v is Record<string, unknown>} */
  const isObject = (v) => typeof v === "object" && v !== null;
  if (!isObject(s) || typeof s.policy !== "string" || typeof s.data !== "string" || typeof s.tests !== "string") {
    throw new Error("not a playground's link");
  }
  return { policy: s.policy, data: s.data, tests: s.tests, as: typeof s.as === "string" ? s.as : undefined,
    ask: typeof s.ask === "string" ? s.ask : undefined };
}

// --- the policy editor's line numbers ------------------------------------------------------------------
function gutter() {
  const n = el.policy.value.split("\n").length;
  el.gutter.innerHTML = Array.from({ length: n }, (_, i) =>
    i + 1 === errorLine ? `<span class="err">${i + 1}</span>` : String(i + 1)).join("\n");
  el.gutter.scrollTop = el.policy.scrollTop;
}

// --- compile, run, show --------------------------------------------------------------------------------
/** @param {Compile} out */
function status(out) {
  if (out.ok) {
    el.status.className = "status ok";
    el.status.textContent = `compiles: ${out.types.length} types, app role ${out.role}`;
    return;
  }
  el.status.className = "status bad";
  const where = out.line ? `${out.file ? `${out.file} ` : ""}line ${out.line}: ` : "";
  const code = out.code ? ` <a href="#" data-code="${esc(out.code)}">${esc(out.code)}</a>` : "";
  el.status.innerHTML = `${esc(where + out.message)}${code}`;
  if (out.help) helpPage(out.help);
}

/** @param {string} markdown */
function helpPage(markdown) {
  // the pages are small and plain: headings, paragraphs, code blocks and `code`
  /** @param {string} s */
  const inline = (s) => esc(s).replace(/`([^`]+)`/g, "<code>$1</code>");
  const html = markdown.split(/(^```\w*\n[\s\S]*?\n```$)/m).map((part) => {      // each code block whole
    const fence = /^```\w*\n([\s\S]*?)\n```$/.exec(part);
    if (fence) return `<pre><code>${esc(fence[1])}</code></pre>`;
    return part.split(/\n{2,}/).map((p) => p.trim()).filter(Boolean).map((p) =>
      p.startsWith("## ") ? `<h3>${inline(p.slice(3))}</h3>` : p.startsWith("# ") ? `<h2>${inline(p.slice(2))}</h2>`
        : `<p>${inline(p)}</p>`).join("");
  }).join("");
  el.help.innerHTML = html;
}

/** @param {Run} run */
function results(run) {
  if (!run.ok) {
    el.count.textContent = "";
    el.results.innerHTML = `<div class="error"><strong>${esc(run.step)}:</strong> ${esc(run.message)}` +
      `${run.detail ? `<pre>${esc(run.detail)}</pre>` : ""}${run.hint ? `<pre>${esc(run.hint)}</pre>` : ""}</div>`;
    return;
  }
  const failed = run.tests.filter((t) => !t.ok).length;
  el.count.textContent = run.tests.length ? (failed ? `${failed} failing` : `${run.tests.length} ✓`) : "";
  if (!run.tests.length) {
    el.results.innerHTML = `<p class="muted">Applied. No tests yet: write some under Named tests, or a <code>test</code> section in the policy.</p>`;
    return;
  }
  let html = "";
  /** @type {string | null} */
  let last = null;
  for (const t of run.tests) {
    if (t.test !== last) {
      html += `<div class="test">${esc(t.test)}</div>`;
      last = t.test;
    }
    const [first, ...rest] = (t.detail ?? "").split("\n");
    html += `<div class="check"><span class="mark ${t.ok ? "ok" : "bad"}">${t.ok ? "ok" : "FAIL"}</span>` +
      `<span>${esc((t.line && !t.ok ? `${t.line}: ` : "") + first)}</span>` +
      `${!t.ok && rest.length ? `<pre>${esc(rest.join("\n"))}</pre>` : ""}</div>`;
  }
  el.results.innerHTML = html;
}

async function refresh() {
  const database = db;
  if (!engine || !database) return;
  const mine = ++generation;
  /** @type {Compile} */
  let out;
  try {
    out = await engine.compile(el.policy.value, el.tests.value);
  } catch (e) {
    // the compiler itself failed: say so, or the page goes on showing the last policy as this one
    out = { ok: false, file: null, line: null, code: null, help: null,
      message: `the compiler stopped: ${e instanceof Error ? e.message.trim().split("\n").at(-1) : String(e)}` };
  }
  if (mine !== generation) return;                // edited again while it compiled
  errorLine = !out.ok && !out.file ? out.line : null;
  gutter();
  status(out);
  if (!out.ok) {
    // the results below are the last policy that compiled: say so, rather than show its count as this one's
    el.count.textContent = "";
    el.state.className = "pill bad";
    el.state.textContent = "doesn't compile";
    return;
  }
  compiled = out;
  el.sql.textContent = out.sql;
  if (selected() === "graph") graph();
  const data = el.data.value;
  await inLine(async () => {
    if (mine !== generation) return;              // edited again meanwhile
    el.state.textContent = "running…";
    const run = await database.run(data, out);
    if (mine !== generation) return;
    el.state.className = run.ok && run.tests.every((t) => t.ok) ? "pill ok" : "pill bad";
    el.state.textContent = run.ok ? "applied" : `failed: ${run.step}`;
    results(run);
    // the question shown is asked again, here: this step already holds the line, so not through ask()
    if (run.ok && el.answer.innerHTML) await answer(database, el.who.value.trim(), el.query.value);
  }).catch((e) => {
    el.state.className = "pill bad";
    el.state.textContent = "failed";
    el.results.innerHTML = `<div class="error"><strong>the page:</strong> ${esc(said(e))}</div>`;
  });
}

// PGlite gives an int8 beyond 2^53 as a BigInt, which JSON.stringify refuses: an array of them shows as text
/** @param {string} _ @param {unknown} v */
const plain = (_, v) => (typeof v === "bigint" ? String(v) : v);

/** Asks the database sql as who, and shows the answer. Its own mistakes are shown too: it never throws.
 *  @param {Database} database @param {string} who @param {string} sql */
async function answer(database, who, sql) {
  try {
    const r = await database.ask(who, sql);
    if (!r.ok) {
      el.answer.innerHTML = `<div class="error"><strong>${esc(r.code === "42501" ? "refused" : r.step)}:</strong> ` +
        `${esc(r.message)}${r.detail ? `<pre>${esc(r.detail)}</pre>` : ""}${r.hint ? `<pre>${esc(r.hint)}</pre>` : ""}</div>`;
      return;
    }
    const head = r.fields.map((f) => `<th>${esc(f)}</th>`).join("");
    const body = r.rows.map((row) => `<tr>${row.map((cell) =>
      `<td>${cell === null ? '<span class="muted">null</span>' : esc(typeof cell === "object" ? JSON.stringify(cell, plain) : cell)}</td>`).join("")}</tr>`).join("");
    const ended = (r.rolledBack ? "rolled back" : "not rolled back: the statement ended the page's transaction " +
      "(COMMIT or ROLLBACK), so what it wrote stays until the next edit, and what followed ran signed in as nobody") +
      (r.asRole ? `; it ended as ${esc(r.asRole)}, not the app role (RESET ROLE), and the owner sees every row` : "");
    el.answer.innerHTML = r.fields.length
      ? `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>` +
        `<p class="muted">${r.rows.length} row${r.rows.length === 1 ? "" : "s"}, as ${esc(who || "nobody")}; ${ended}</p>`
      : `<p class="muted">done, as ${esc(who || "nobody")}; ${ended}</p>`;
  } catch (e) {
    el.answer.innerHTML = `<div class="error"><strong>the page:</strong> ${esc(said(e))}</div>`;
  }
}

async function ask() {
  const database = db;
  if (!database || !compiled) return;
  const who = el.who.value.trim(), sql = el.query.value;
  await inLine(() => answer(database, who, sql));
}

async function graph() {
  const shown = compiled;
  if (!shown || graphShown === shown.graph) return;
  graphShown = shown.graph;
  el.graph.innerHTML = `<p class="muted">drawing…</p>`;
  try {
    /** @type {{default: Mermaid}} */
    const { default: mermaid } = await import(MERMAID);
    const dark = matchMedia("(prefers-color-scheme: dark)").matches;
    mermaid.initialize({ startOnLoad: false, theme: dark ? "dark" : "neutral", securityLevel: "strict" });
    const { svg } = await mermaid.render(`g${Date.now()}`, shown.graph);
    el.graph.innerHTML = svg;
  } catch {
    el.graph.innerHTML = `<pre>${esc(shown.graph)}</pre>`;          // the diagram's text, if it can't be drawn
  }
}

// --- tabs ----------------------------------------------------------------------------------------------
function selected() {
  return document.querySelector(/** @type {"button"} */ ('.tab[aria-selected="true"]'))?.dataset.pane;
}

/** @param {string | undefined} pane */
function open(pane) {
  for (const t of document.querySelectorAll(/** @type {"button"} */ (".tab"))) t.setAttribute("aria-selected", String(t.dataset.pane === pane));
  for (const p of document.querySelectorAll(".pane")) p.classList.toggle("on", p.id === `pane-${pane}`);
  if (pane === "graph") graph();
}

// --- wiring --------------------------------------------------------------------------------------------
function wire() {
  const soon = later(refresh, 350);
  for (const area of [el.policy, el.data, el.tests]) {
    area.addEventListener("input", () => { if (area === el.policy) gutter(); soon(); });
    area.addEventListener("keydown", (e) => {        // Tab indents, as policies do
      if (e.key !== "Tab" || e.shiftKey) return;
      e.preventDefault();
      area.setRangeText("  ", area.selectionStart, area.selectionEnd, "end");
      area.dispatchEvent(new Event("input"));
    });
  }
  el.policy.addEventListener("scroll", () => { el.gutter.scrollTop = el.policy.scrollTop; });
  for (const t of document.querySelectorAll(/** @type {"button"} */ (".tab"))) t.addEventListener("click", () => open(t.dataset.pane));
  el.status.addEventListener("click", async (e) => {
    const target = e.target instanceof Element ? e.target.closest("a") : null;
    const code = target?.dataset.code;
    if (!code || !engine) return;
    e.preventDefault();
    helpPage((await engine.help(code)) ?? `No page for ${code}.`);
    open("help");
  });
  el.runAsk.addEventListener("click", ask);
  el.query.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); ask(); }
  });
  el.example.addEventListener("change", () => {
    const chosen = el.example.value === "" ? linked : bundle.examples[Number(el.example.value)];   // "": from the link
    if (!chosen) return;
    show(chosen);
    el.notice.hidden = true;                      // what it said of the link the page was opened with
    history.replaceState(null, "", location.pathname);
    refresh();
  });
  el.share.addEventListener("click", async () => {
    const url = `${location.origin}${location.pathname}#s=${await pack(current())}`;
    history.replaceState(null, "", url);
    try {
      await navigator.clipboard.writeText(url);
      el.share.textContent = "Link copied";
    } catch {
      el.share.textContent = "Link in the address bar";
    }
    setTimeout(() => { el.share.textContent = "Copy link"; }, 2000);
  });
}

/** The page couldn't start: it says why, rather than seem to load for ever. @param {string} why */
function stopped(why) {
  el.state.className = "pill bad";
  el.state.textContent = "couldn't load";
  el.status.className = "status bad";
  el.status.textContent = why;
}

async function start() {
  try {
    const res = await fetch("./bundle.json");
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    bundle = await res.json();
  } catch (e) {
    stopped(`The compiler and the examples didn't load: bundle.json: ${said(e)}`);
    return;
  }
  el.example.innerHTML = bundle.examples.map((x, i) => `<option value="${i}">${esc(x.name)}</option>`).join("");
  /** @type {State} */
  let state = bundle.examples[0];
  const shared = /^#s=(.+)$/.exec(location.hash);
  if (shared) {
    try {
      state = linked = await unpack(shared[1]);
      el.example.insertAdjacentHTML("afterbegin", `<option value="" selected>from the link</option>`);
    } catch {
      // beside the compiler's status, which each run writes over
      el.notice.textContent = "The link's policy couldn't be read: this is an example.";
      el.notice.hidden = false;
    }
  }
  // #e=<slug>: one of the page's own examples, by its name (the cookbook's recipes link here)
  const named = /^#e=([a-z0-9-]+)$/.exec(location.hash);
  if (named) {
    const at = bundle.examples.findIndex((x) => x.slug === named[1]);
    if (at >= 0) {
      state = bundle.examples[at];
      el.example.value = String(at);
    }
  }
  show(state);
  wire();
  const began = performance.now();
  try {
    // Python in the worker and Postgres here start at the same time
    const worker = compilerWorker();
    /** @type {Promise<typeof import("@electric-sql/pglite")>} */
    const pglite = import(PGLITE);
    const [, pg] = await Promise.all([worker.start(bundle.compiler), pglite.then(({ PGlite }) => PGlite.create())]);
    engine = worker;
    db = database(pg);
  } catch (e) {
    stopped(`Python or Postgres didn't load: ${said(e)}`);
    return;
  }
  const took = performance.now() - began;
  document.documentElement.dataset.readyMs = String(Math.round(took));     // for browser_test.mjs
  el.state.textContent = `ready in ${(took / 1000).toFixed(1)} s`;
  el.share.disabled = false;
  el.runAsk.disabled = false;
  await refresh();
}

start();
