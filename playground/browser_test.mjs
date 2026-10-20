// The page in a real browser (headless Chrome or Edge, over the DevTools protocol): it loads Python and
// Postgres from the CDN, runs the example's tests, shows a mistake with its code and page, and asks as
// someone. Also how long loading takes, from nothing cached and again (the design's limit is 5 s).
//   node build.mjs && node browser_test.mjs [path/to/chrome]      (skipped when there is no browser)
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { deflateRawSync } from "node:zlib";

const DIST = fileURLToPath(new URL("./dist/", import.meta.url));
/** @typedef {any} Answer  the browser's answer (the DevTools protocol's JSON): its shape is what the checks check */
const BROWSERS = /** @type {string[]} */ ([process.argv[2], process.env.CHROME, "/usr/bin/google-chrome", "/usr/bin/chromium",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"].filter(Boolean));
// the design's limit for a cached load, on the dev laptop; CI's smaller machines pass their own (ci.yml)
const LIMIT_MS = Number(process.env.PLAYGROUND_LIMIT_MS || 5000);
let fails = 0;
/** @param {string} what @param {unknown} ok @param {unknown} [got] */
const check = (what, ok, got) => {
  if (ok) console.log(`ok    ${what}`);
  else {
    fails += 1;
    console.log(`FAIL  ${what}${got === undefined ? "" : `: ${JSON.stringify(got).slice(0, 400)}`}`);
  }
};

const browser = BROWSERS.find((b) => existsSync(b));
if (!browser) {
  console.log("skip  no Chrome or Edge (pass its path, or set CHROME)");
  process.exit(0);
}
if (!existsSync(join(DIST, "bundle.json"))) {
  console.log("FAIL  no dist/: node build.mjs first");
  process.exit(1);
}

// dist/, served as a static host would
/** @type {Record<string, string>} */
const TYPES = { ".html": "text/html", ".mjs": "text/javascript", ".json": "application/json" };
const server = createServer(async (req, res) => {
  try {
    const path = new URL(req.url ?? "/", "http://x").pathname;
    const body = await readFile(join(DIST, decodeURIComponent(path).replace(/^\/$/, "/index.html")));
    res.writeHead(200, { "content-type": TYPES[extname(path)] ?? "text/html" }).end(body);
  } catch {
    res.writeHead(404).end();
  }
}).listen(0, "127.0.0.1");
await new Promise((r) => server.once("listening", r));
const address = server.address();
if (address === null || typeof address === "string") throw new Error("the server has no port");
const PAGE = `http://127.0.0.1:${address.port}/`;

const profile = mkdtempSync(join(tmpdir(), "pga-playground-"));
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
  started = await start(browser, mkdtempSync(join(tmpdir(), "pga-playground-")), 30000);
}
if (started.url === null) throw new Error(`the browser didn't start, three times: ${started.err.slice(0, 300)}`);
const chrome = started.child;
const wsUrl = started.url;

// the DevTools protocol, over the WebSocket Node has built in
const ws = new WebSocket(wsUrl);
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
/** @param {string} expression @returns {Promise<Answer>} */
const js = async (expression) => (await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true }, sessionId)).result.value;
/** @param {string} expression @param {number} [ms] @returns {Promise<Answer>} */
const until = async (expression, ms = 60000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const v = await js(expression);
    if (v) return v;
    await new Promise((r) => setTimeout(r, 100));
  }
  return null;
};
const load = async () => {
  await send("Page.navigate", { url: PAGE }, sessionId);
  await until("document.readyState === 'complete' && document.getElementById('state') !== null");
  return until("document.documentElement.dataset.readyMs && document.getElementById('count').textContent");
};

try {
  const cold = await load();
  const coldMs = Number(await js("document.documentElement.dataset.readyMs"));
  check(`the page loads Python and Postgres, and runs the example (cold: ${coldMs} ms)`, cold === "7 ✓", cold);
  const warm = await load();
  const warmMs = Number(await js("document.documentElement.dataset.readyMs"));
  check(`... again, cached: ${warmMs} ms (limit ${LIMIT_MS} ms)`, warm === "7 ✓" && warmMs < LIMIT_MS, warmMs);
  if (process.env.SCREENSHOT) {                  // SCREENSHOT=page.png: what the page looks like, loaded
    await send("Emulation.setDeviceMetricsOverride", { width: 1400, height: 900, deviceScaleFactor: 1, mobile: false }, sessionId);
    const { data } = await send("Page.captureScreenshot", { format: "png" }, sessionId);
    (await import("node:fs")).writeFileSync(process.env.SCREENSHOT, Buffer.from(data, "base64"));
  }

  // a mistake: the policy's line in the gutter, the code, and its page in Help
  await js(`(() => { const p = document.getElementById('policy');
    p.value = p.value.replace('can edit  = share or editor', 'can edit  = share or edtor');
    p.dispatchEvent(new Event('input')); })()`);
  const mistake = await until("document.querySelector('#status a[data-code]')?.textContent");
  check("a mistake shows its code", mistake === "AZ203", mistake);
  check("... and the tests' count is not shown as this policy's", (await js("document.getElementById('count').textContent")) === "");
  check("... its line is marked", Boolean(await js("document.querySelector('#gutter .err')?.textContent")));
  await js("document.querySelector('#status a[data-code]').click()");
  const help = await until("document.querySelector('#pane-help.on h2')?.textContent", 10000);
  check("... and the code opens its page", help?.startsWith("AZ203"), help);

  // fixed again, then asked as someone
  await js(`(() => { const p = document.getElementById('policy');
    p.value = p.value.replace('share or edtor', 'share or editor'); p.dispatchEvent(new Event('input')); })()`);
  check("fixed: the tests pass again", (await until("document.getElementById('count').textContent === '7 ✓'")) === true);
  await js(`(() => { document.querySelector('[data-pane=ask]').click(); document.getElementById('who').value = 'user:3';
    document.getElementById('run-ask').click(); })()`);
  const rows = await until("document.querySelector('#answer p')?.textContent");
  check("asking as cy: no rows, as row-level security says", rows?.startsWith("0 rows, as user:3"), rows);
  await js(`(() => { document.getElementById('who').value = 'user:1'; document.getElementById('run-ask').click(); })()`);
  const ada = await until("document.querySelector('#answer p')?.textContent?.startsWith('1 row') && document.querySelector('#answer td')?.textContent");
  check("... as ada: her note", ada === "1", ada);

  await js("document.querySelector('[data-pane=graph]').click()");
  const drawn = await until("document.querySelector('#pane-graph svg') !== null", 30000);
  check("the graph is drawn (mermaid)", drawn === true, await js("document.getElementById('pane-graph').textContent.slice(0, 200)"));

  // a link that carries the policy
  await js(`(() => { const p = document.getElementById('policy'); p.value += '\\n-- from the link\\n';
    p.dispatchEvent(new Event('input')); })()`);
  await js("document.getElementById('share').click()");
  const link = await until("location.hash.startsWith('#s=') && location.href");
  /** A new page at url (from about:blank: else only the hash changes), once it is ready. @param {string} url */
  const open = async (url) => {
    await send("Page.navigate", { url: "about:blank" }, sessionId);
    await until("location.href === 'about:blank'");
    await send("Page.navigate", { url }, sessionId);
    return until("document.documentElement.dataset.readyMs", 90000);
  };
  await open(link);
  const fromLink = await js(`document.getElementById('example').value === ''
    && document.getElementById('policy').value.endsWith('-- from the link\\n') && document.getElementById('who').value`);
  check("a copied link opens the same policy and state", fromLink === "user:1", fromLink);
  await js(`(() => { const s = document.getElementById('example'); s.value = '1'; s.dispatchEvent(new Event('change')); })()`);
  await until("!document.getElementById('policy').value.includes('-- from the link')");
  await js(`(() => { const s = document.getElementById('example'); s.value = ''; s.dispatchEvent(new Event('change')); })()`);
  check("... and 'from the link', chosen again after another example, is the link's policy",
    (await until("document.getElementById('policy').value.endsWith('-- from the link\\n')", 5000)) === true);

  // a link that holds something else than a state: the example, not a page that never loads
  const ready = await open(`${PAGE}#s=${deflateRawSync(Buffer.from("null")).toString("base64url")}`);
  const shown = await until("document.getElementById('count').textContent");
  check("a link that isn't a state: the page loads, with an example", Boolean(ready) && shown === "7 ✓"
    && (await js("document.getElementById('example').value")) === "0", [ready, shown]);

  // a link that names one of the page's examples (the cookbook's recipes link this way)
  await open(`${PAGE}#e=owner-only`);
  const recipe = await js(`(() => { const s = document.getElementById('example');
    return [s.options[s.selectedIndex].textContent, document.getElementById('policy').value.includes('type note = app.notes')]; })()`);
  check("a link that names an example opens it", Array.isArray(recipe) && String(recipe[0]).startsWith("Recipe: ") && recipe[1] === true, recipe);
  check("... and its tests pass", /^\d+ ✓$/.test(String(await until("document.getElementById('count').textContent"))),
    await js("document.getElementById('count').textContent"));
  await open(`${PAGE}#e=no-such-recipe`);
  check("a link that names no example: the first one", (await js("document.getElementById('example').value")) === "0");
} catch (e) {
  check("the page", false, e instanceof Error ? e.message : String(e));
} finally {
  ws.close();
  chrome.kill();
  server.close();
  setTimeout(() => rmSync(profile, { recursive: true, force: true }), 500);
}
console.log(`playground in a browser: ${fails ? `${fails} failed` : "all passed"}`);
process.exitCode = fails ? 1 : 0;
