// Studio's page in a real browser (headless Chrome or Edge, over the DevTools protocol), on the docs app: the
// grid's cells under their headings, "Why?" as anyone and as someone, the graph drawn (Mermaid from the CDN, checked
// against its hash) and a node's detail, the shares and requests as the API sends them, and a policy applied while
// the page is open. studio_test.py asks the API; this asks what the page makes of it.
//   PGHOST=... PGUSER=authz_owner node tests/studio_page.mjs [path/to/chrome]      (skipped when there is no browser)
// It makes the database authz_studio_page (python3 runs its SQL with the command's own client: no psql needed) and
// drops it after. tests/studio_page.sh runs it on a Postgres of its own (CI's studio-page job).
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { createServer } from "node:net";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const CORE = fileURLToPath(new URL("../", import.meta.url));
const CLI = join(CORE, "cli", "rowstile_cli.py");
const DB = "authz_studio_page";
/** @typedef {any} Answer  the browser's answer (the DevTools protocol's JSON): its shape is what the checks check */
const BROWSERS = /** @type {string[]} */ ([process.argv[2], process.env.CHROME, "/usr/bin/google-chrome", "/usr/bin/chromium",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"].filter(Boolean));
let fails = 0;
/** @param {string} what @param {unknown} ok @param {unknown} [got] */
const check = (what, ok, got) => {
  if (ok) console.log(`ok    ${what}`);
  else {
    fails += 1;
    console.log(`FAIL  ${what}${got === undefined ? "" : `: ${JSON.stringify(got).slice(0, 600)}`}`);
  }
};

const browser = BROWSERS.find((b) => existsSync(b));
if (!browser) {
  console.log("skip  no Chrome or Edge (pass its path, or set CHROME)");
  process.exit(0);
}

// --- the database: the docs app, a few shares and a request ---------------------------------------------------
const RUN_SQL = "import sys; sys.path.insert(0, sys.argv[1]); import pgwire\n"
  + "c = pgwire.connect(**pgwire.parse_dsn(sys.argv[2])); c.script(sys.stdin.read()); c.close()";
/** Statements run in one go on a database, as its owner. @param {string} dbname @param {string} text */
function sql(dbname, text) {
  const r = spawnSync("python3", ["-c", RUN_SQL, join(CORE, "cli"), `dbname=${dbname}`], { input: text, encoding: "utf8" });
  if (r.status !== 0) throw new Error(`SQL on ${dbname} failed: ${r.stderr}`);
}
/** The command on the database: what it printed. @param {string[]} args */
function command(...args) {
  const r = spawnSync("python3", [CLI, "--db", `dbname=${DB}`, ...args], { encoding: "utf8" });
  if (r.status !== 0) throw new Error(`rowstile ${args.join(" ")}: ${r.stdout}${r.stderr}`);
  return r.stdout;
}
// the docs app's policy, with what the shares tab shows besides: a link, a custom role, a caveat
const dir = mkdtempSync(join(tmpdir(), "rowstile-studio-page-policy-"));
const policy = join(dir, "docs.authz");
const docs = readFileSync(join(CORE, "example", "docs.authz"), "utf8");
const withShares = [
  ["viewer      : user, team#member, org#member shared", "viewer      : user, team#member, org#member, link shared"],
  ["app role app_user\n", "app role app_user\n\ncaveat business_hours = {authz.ctx('mode') = 'business'}\n"],
  ["type org = app.orgs\n", "type org = app.orgs\n  can manage_roles = admin\n"],
  ["  can break_glass = org.member\n", "  can break_glass = org.member\n  roles       : user from org\n  can peek    = view or roles\n"],
].reduce((text, [from, to]) => {
  if (!text.includes(from)) throw new Error(`docs.authz has no ${JSON.stringify(from)}`);
  return text.replace(from, to);
}, docs);
writeFileSync(policy, withShares);
sql("postgres", `DROP DATABASE IF EXISTS ${DB}`);
sql("postgres", `CREATE DATABASE ${DB}`);
// psql's own lines (\set) are psql's: the rest is SQL
sql(DB, readFileSync(join(CORE, "example", "app_schema.sql"), "utf8").replace(/^\\.*$/gm, ""));
command("apply", policy);
// erin owns Company (folder 1) and is an admin of Acme: she shares it with Acme's members, with dave from tomorrow on,
// with gina as a reviewer (a role Acme made), with frank in business hours, and as a link; bob asks to see Secrets for
// a week
sql(DB, `SELECT authz.act_as('user', '5');
  SELECT authz.share('folder', '1', 'viewer', 'org', '1', 'member');
  SELECT authz.share('folder', '1', 'viewer', 'user', '4', '', NULL, now() + interval '1 day');
  SELECT authz.share('folder', '1', 'role:' || authz.create_role('org', '1', 'folder', 'reviewer', ARRAY['peek']), 'user', '7');
  SELECT authz.share('folder', '1', 'viewer', 'user', '6', '', NULL, NULL, 'business_hours');
  SELECT authz.create_link('folder', '1', 'viewer');
  SELECT authz.act_as('user', '2');
  SELECT authz.request_access('folder', '5', 'viewer', 'for the audit', interval '7 days');`);

// --- Studio, able to write (as under rowstile dev) ------------------------------------------------------------
// a port free now (Studio takes a port above 0)
const port = await new Promise((resolve) => {
  const s = createServer().listen(0, "127.0.0.1", () => {
    const a = s.address();
    s.close(() => resolve(a !== null && typeof a === "object" ? a.port : 0));
  });
});
const studio = spawn("python3", [CLI, "--db", `dbname=${DB}`, "studio", "--write", "--port", String(port)], { stdio: ["ignore", "pipe", "pipe"] });
let said = "";
/** @type {string | null} */
const address = await new Promise((resolve) => {
  /** @param {Buffer} d */
  const read = (d) => {
    said += d;
    const m = /(http:\/\/127\.0\.0\.1:\d+\/\?token=\S+)/.exec(said);
    if (m) resolve(m[1]);
  };
  studio.stdout.on("data", read);
  studio.stderr.on("data", read);
  setTimeout(() => resolve(null), 30000);
});
if (address === null) {
  studio.kill();
  throw new Error(`Studio didn't start: ${said}`);
}

// --- the browser ---------------------------------------------------------------------------------------------
const profile = mkdtempSync(join(tmpdir(), "rowstile-studio-page-"));
/** Starts the browser and waits for its DevTools address; null when it says nothing within the wait (it is
 *  stopped then). On a shared runner a first start now and then hangs: it is tried again, not failed. */
async function start(/** @type {string} */ exe, /** @type {string} */ dir, /** @type {number} */ wait) {
  const child = spawn(exe, ["--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
    `--user-data-dir=${dir}`, "--remote-debugging-port=0", "about:blank"], { stdio: ["ignore", "ignore", "pipe"] });
  let err = "";
  /** @type {string | null} */
  const url = await new Promise((resolve) => {
    child.stderr.on("data", (/** @type {Buffer} */ d) => {
      err += d;
      const m = /DevTools listening on (ws:\S+)/.exec(err);
      if (m) resolve(m[1]);
    });
    setTimeout(() => resolve(null), wait);
  });
  if (url === null) child.kill();
  return { child, url, err };
}
let started = await start(browser, profile, 30000);
for (let attempt = 2; started.url === null && attempt <= 3; attempt += 1) {
  console.log(`the browser didn't start within 30 s: attempt ${attempt}`);
  started = await start(browser, mkdtempSync(join(tmpdir(), "rowstile-studio-page-")), 30000);
}
if (started.url === null) {
  studio.kill();
  throw new Error(`the browser didn't start, three times: ${started.err.slice(0, 300)}`);
}
const chrome = started.child;

// the DevTools protocol, over the WebSocket Node has built in
const ws = new WebSocket(started.url);
await new Promise((r) => ws.addEventListener("open", r, { once: true }));
let next = 0;
/** @type {Map<number, (msg: Answer) => void>} */
const pending = new Map();
ws.addEventListener("message", (e) => {
  const msg = JSON.parse(e.data);
  if (msg.id && pending.has(msg.id)) {
    pending.get(msg.id)?.(msg);
    pending.delete(msg.id);
  }
});
/** A DevTools call, answered. @param {string} method @param {object} [params] @param {string} [sessionId] @returns {Promise<Answer>} */
const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
  const id = ++next;
  pending.set(id, (msg) => (msg.error ? reject(new Error(msg.error.message)) : resolve(msg.result)));
  ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
});
const { targetId } = await send("Target.createTarget", { url: "about:blank" });
const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });
// wide enough for the tables tab's three columns (the list, the grid, the panel)
await send("Emulation.setDeviceMetricsOverride", { width: 1400, height: 900, deviceScaleFactor: 1, mobile: false }, sessionId);
/** @param {string} expression @returns {Promise<Answer>} */
const js = async (expression) => {
  const r = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true }, sessionId);
  if (r.exceptionDetails) throw new Error(`${expression.slice(0, 120)}: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
  return r.result.value;
};
/** A function run in the page, with its arguments passed as values (never written into its code): its value.
 *  @template {unknown[]} A @param {(...args: A) => unknown} fn @param {A} args @returns {Promise<Answer>} */
const call = async (fn, ...args) => {
  // the page's global object, asked each time: a navigation makes another
  const { result: page } = await send("Runtime.evaluate", { expression: "globalThis" }, sessionId);
  const r = await send("Runtime.callFunctionOn", { functionDeclaration: fn.toString(), objectId: page.objectId,
    arguments: args.map((value) => ({ value })), awaitPromise: true, returnByValue: true }, sessionId);
  if (r.exceptionDetails) throw new Error(`${fn.toString().slice(0, 120)}: ${r.exceptionDetails.exception?.description ?? r.exceptionDetails.text}`);
  return r.result.value;
};
/** The value once it is truthy (an expression's, or what ask gives); null when it isn't within ms.
 *  @param {string | (() => Promise<Answer>)} ask @param {number} [ms] @returns {Promise<Answer>} */
const until = async (ask, ms = 30000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const v = await (typeof ask === "string" ? js(ask) : ask());
    if (v) return v;
    await new Promise((r) => setTimeout(r, 100));
  }
  return null;
};
/** Clicks the first element the selector finds whose text is the one given (any, without text). @param {string} selector @param {string} [text] */
const click = (selector, text) => call((/** @type {string} */ selector, /** @type {string | null} */ text) => {
  const e = [...document.querySelectorAll(selector)].find((x) => text === null || x.textContent === text);
  if (!e) throw new Error(`nothing to click: ${selector} ${text ?? ""}`);
  e.dispatchEvent(new MouseEvent("click", { bubbles: true }));
}, selector, text ?? null);
/** Clicks the first element the selector finds whose data-<key> is the value given.
 *  @param {string} selector @param {string} key @param {string} value */
const clickWhere = (selector, key, value) => call((/** @type {string} */ selector, /** @type {string} */ key, /** @type {string} */ value) => {
  const e = [...document.querySelectorAll(selector)].find((x) => x instanceof HTMLElement && x.dataset[key] === value);
  if (!e) throw new Error(`nothing to click: ${selector} with data-${key} ${value}`);
  e.dispatchEvent(new MouseEvent("click", { bubbles: true }));
}, selector, key, value);
/** Views the page as someone (the box at the top). @param {string} who */
const viewAs = (who) => call((/** @type {string} */ who) => {
  /** @type {HTMLInputElement} */ (document.getElementById("as")).value = who;
  /** @type {HTMLFormElement} */ (document.getElementById("as-form")).requestSubmit();
}, who);
/** Opens a table of the tables tab, and waits for its rows. @param {string} table @param {string} who */
const openTable = async (table, who) => {
  await clickWhere("#table-list button", "table", table);
  return until(() => call((/** @type {string} */ who) => document.getElementById("grid-head")?.textContent?.startsWith(`${who} sees`)
    && document.querySelectorAll("#grid tbody tr").length, who));
};
/** Selects a row of the grid by its id, and opens a permission's "Why?" (or "Why not?").
 *  @param {string} id @param {string} perm */
const whyOf = async (id, perm) => {
  await clickWhere("#grid tbody tr", "id", id);
  await until(`!document.getElementById('panel').hidden`);
  await call((/** @type {string} */ perm) => {
    const p = [...document.querySelectorAll("#panel .perm")].find((x) => x.querySelector(".name")?.textContent === perm);
    const b = p?.querySelector(".perm-head button");
    if (!(b instanceof HTMLElement)) throw new Error(`no permission ${perm} in the panel`);
    b.click();
  }, perm);
};
/** What the panel says under a permission: its text, the line before the ways (when there are ways), and the row of
 *  buttons that make a test (its display and its buttons). @param {string} perm */
const permBody = (perm) => call((/** @type {string} */ perm) => {
  const body = [...document.querySelectorAll("#panel .perm")].find((x) => x.querySelector(".name")?.textContent === perm)
    ?.querySelector(".perm-body");
  if (!body) throw new Error(`no permission ${perm} in the panel`);
  const actions = body.querySelector(".actions");
  return {
    text: body.textContent,
    ways: body.querySelector("ul.ways") ? body.querySelector("p:nth-of-type(2)")?.textContent : null,
    actions: actions && [getComputedStyle(actions).display, [...actions.querySelectorAll("button")].map((b) => b.textContent)],
  };
}, perm);
/** Each row of a table as its cells' text. @param {string} selector */
const cells = (selector) => call((/** @type {string} */ selector) => [...document.querySelectorAll(`${selector} tr`)]
  .map((tr) => [...tr.children].map((td) => td.textContent)), selector);

try {
  await send("Page.navigate", { url: address }, sessionId);
  check("the page opens, with its tables",
    await until("document.querySelectorAll('#table-list button').length") === 5, await js("document.body.innerText.slice(0, 300)"));

  // the grid: a table, its cells under their headings
  await viewAs("anyone");
  const rows = await openTable("app.folders", "anyone");
  check("the folders, as anyone", rows === 8, rows);
  const layout = await js(`(() => {
    const left = (/** @type {Element} */ e) => Math.round(e.getBoundingClientRect().left);
    const heads = [...document.querySelectorAll('#grid thead th')].map(left);
    return { displays: [...new Set([...document.querySelectorAll('#grid tbody tr')].map((tr) => getComputedStyle(tr).display))],
             off: [...document.querySelectorAll('#grid tbody tr')].flatMap((tr) => [...tr.children]
               .map((td, i) => left(td) === heads[i] ? null : tr.dataset.id + ':' + i + ' at ' + left(td) + ', not ' + heads[i]).filter(Boolean)) };
  })()`);
  check("each row is a table's row", JSON.stringify(layout.displays) === '["table-row"]', layout.displays);
  check("... and each cell sits under its heading", JSON.stringify(layout.off) === "[]", layout.off);

  // Why? as anyone: the page asks for someone, and doesn't wait for an answer that never comes
  await whyOf("1", "view");
  check("Why? as anyone: pick someone first",
    await until(async () => (await permBody("view")).text === "Pick someone to view as first.", 3000) === true,
    (await permBody("view")).text);

  // as carol: why not edit, the changes that would grant it, and the row that makes a test
  await viewAs("user:3");
  await until(`document.getElementById('grid-head').textContent.startsWith('user:3 sees')`);
  await whyOf("3", "edit");
  const ways = await until(async () => (await permBody("edit")).ways);
  check("Why not? as carol: the changes that would grant it, each tried", ways === "Would be granted by (each tried, then undone):", ways);
  const testRow = (await permBody("edit")).actions;
  check("... and a row of buttons to make a test from it", JSON.stringify(testRow) === '["flex",["user:3 can edit","… cannot"]]', testRow);

  // the graph: Mermaid loads (its hash is checked) and draws it; a node shows how it is written
  await click("nav button", "Graph");
  const drawn = await until("document.querySelector('#graph-view svg') !== null || document.querySelector('#graph-view pre') !== null");
  check("the graph is drawn by Mermaid, from the CDN, its hash checked", drawn === true
    && (await js("document.querySelector('#graph-view svg') !== null")), await js("document.getElementById('graph-view').textContent.slice(0, 200)"));
  await js(`(() => { const n = [...document.querySelectorAll('#graph-view g.node')].find((x) => /flowchart-folder__view-\\d+$/.test(x.id));
    if (!n) throw new Error('no node for folder.view: ' + [...document.querySelectorAll('#graph-view g.node')].map((x) => x.id).join(' '));
    n.dispatchEvent(new MouseEvent('click', { bubbles: true })); })()`);
  check("... a node, clicked: how the permission is written",
    (await until("document.querySelector('#graph-detail h3')?.textContent")) === "folder.view",
    await js("document.getElementById('graph-detail').textContent"));

  // shares and requests, as the API sends them
  await click("nav button", "Shares and requests");
  /** The shares on folder 1, once shown: each row's cells. */
  const shares = async () => {
    await js(`(() => { document.getElementById('shares-view').replaceChildren(); document.getElementById('shares-type').value = 'folder';
      document.getElementById('shares-id').value = '1'; document.getElementById('shares-form').requestSubmit(); })()`);
    await until("document.querySelector('#shares-view tr')");
    return /** @type {string[][]} */ (await cells("#shares-view"));
  };
  let got = await shares();
  check("the share with Acme's members", got.some((r) => JSON.stringify(r) === '["viewer","org#member 1","","by 5","Unshare"]'), got);
  const later = got.find((r) => r[1] === "user 4");
  check("a share that starts later: from when", later !== undefined && later.length === 5 && later[2].startsWith("from ")
    && later[3] === "by 5" && later[4] === "Unshare", later);
  check("a share link: how it is turned off, and no Unshare that would leave it",
    got.some((r) => JSON.stringify(r) === '["viewer","a share link","","by 5","turned off with authz.revoke_link"]'), got);
  check("the form's row of controls", (await js("getComputedStyle(document.querySelector('#shares-view form')).display")) === "flex");
  const requests = await until("document.querySelector('#requests-view tr') && document.querySelector('#requests-view tr').innerText");
  check("a request: for how long the approval gives it",
    JSON.stringify(await cells("#requests-view")) === JSON.stringify([["#1", "user 2 asks for viewer on folder 5 for 7 days", "for the audit", "Approve as user:3 for 7 days Deny"]]),
    requests);
  check("a custom role's share: the role's name", got.some((r) => JSON.stringify(r) === '["reviewer","user 7","","by 5","Unshare"]'), got);
  check("a share with a caveat: on what condition", got.some((r) => JSON.stringify(r) === '["viewer","user 6","if business_hours","by 5","Unshare"]'), got);

  // the policy changes while the page is open (rowstile dev applies each save). The page asks for it again when a
  // table is opened: a new permission is offered in the panel
  await click("nav button", "Tables");
  const glance = withShares.replace("  can peek    = view or roles\n", "  can peek    = view or roles\n  can glance  = viewer\n");
  writeFileSync(policy, glance);
  command("apply", policy);
  await openTable("app.folders", "user:3");
  await clickWhere("#grid tbody tr", "id", "1");
  const perms = await until("!document.getElementById('panel').hidden && [...document.querySelectorAll('#panel .perm .name')].map((n) => n.textContent)");
  check("a permission added since the page opened: offered once a table is opened", JSON.stringify(perms) === '["share","edit","view","break_glass","peek","glance"]', perms);
  // ... and when a tab is opened: the graph's detail says how a new permission is written
  writeFileSync(policy, glance.replace("  can share = owner or folder.share\n", "  can share = owner or folder.share\n  can glimpse = viewer\n"));
  command("apply", policy);
  await click("nav button", "Graph");
  await until("[...document.querySelectorAll('#graph-view g.node')].some((x) => /flowchart-file__glimpse-\\d+$/.test(x.id))");
  await js(`document.getElementById('graph-detail').replaceChildren();
    [...document.querySelectorAll('#graph-view g.node')].find((x) => /flowchart-file__glimpse-\\d+$/.test(x.id))
      .dispatchEvent(new MouseEvent('click', { bubbles: true }))`);
  const glimpse = await until("document.querySelector('#graph-detail h3') && (document.querySelector('#graph-detail pre')?.textContent ?? 'no pre')", 5000);
  check("... and once a tab is opened: the graph's detail of one added since", /^can glimpse = viewer {3}\(line \d+\)$/.test(String(glimpse)), glimpse);
} catch (e) {
  check("the page", false, e instanceof Error ? e.message : String(e));
} finally {
  ws.close();
  chrome.kill();
  studio.kill("SIGINT");
  await new Promise((r) => studio.once("exit", r));
  setTimeout(() => rmSync(profile, { recursive: true, force: true }), 500);
  rmSync(dir, { recursive: true, force: true });
  try {
    sql("postgres", `DROP DATABASE IF EXISTS ${DB}`);
  } catch (e) {
    check("the database dropped", false, e instanceof Error ? e.message : String(e));
  }
}
console.log(`Studio's page in a browser: ${fails ? `${fails} failed` : "all passed"}`);
process.exitCode = fails ? 1 : 0;
