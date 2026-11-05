// The playground's engine, headless: the compiler in Pyodide and the SQL in PGlite, as the page runs them.
// Every example compiles, applies and passes its tests; asking as someone shows only their rows; a mistake
// comes back with its line, code and page; a run starts from nothing. Also: how long loading takes.
//   cd playground && npm ci && node test.mjs
import { loadPyodide } from "pyodide";
import { PGlite } from "@electric-sql/pglite";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { bundle } from "./build.mjs";
import { compiler, database, line } from "./core.mjs";

let fails = 0;
/** @param {string} what @param {unknown} ok @param {unknown} [got] */
const check = (what, ok, got) => {
  if (ok) console.log(`ok    ${what}`);
  else {
    fails += 1;
    console.log(`FAIL  ${what}${got === undefined ? "" : `: ${JSON.stringify(got).slice(0, 600)}`}`);
  }
};

// the page loads the versions package.json pins, from the CDN
const pkg = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8"));
const page = readFileSync(new URL("./playground.mjs", import.meta.url), "utf8");
check("the page loads the Pyodide and PGlite package.json pins",
  page.includes(`pyodide@${pkg.devDependencies.pyodide}/`) && page.includes(`pglite@${pkg.devDependencies["@electric-sql/pglite"]}/`));

let t = Date.now();
const [py, pg] = await Promise.all([loadPyodide(), PGlite.create()]);
const loaded = Date.now() - t;
// the schema public as a new database has it, before any run (each run's reset makes it again)
/** @returns {Promise<unknown>} */
const publicSchema = async () => (await pg.query(
  "SELECT pg_get_userbyid(nspowner) AS owner, nspacl::text AS acl, obj_description(oid, 'pg_namespace') AS comment FROM pg_namespace WHERE nspname = 'public'")).rows[0];
const freshPublic = await publicSchema();
// and the session as it starts: settings a run may SET, and its temporary tables
/** @returns {Promise<unknown>} */
const session = async () => (await pg.query(`SELECT current_setting('session_replication_role') AS srr,
  current_setting('search_path') AS path, current_setting('statement_timeout') AS timeout,
  coalesce(current_setting('authz.user_id', true), '') AS uid, to_regclass('pg_temp.leftover') IS NULL AS no_temp`)).rows[0];
const freshSession = await session();
const { compiler: files, examples } = bundle();
const c = compiler(py, files);
const db = database(pg);
/** What compiled, or an error: the examples below compile (the first checks say so).
 *  @param {import("./core.mjs").Compile} out */
const must = (out) => {
  if (!out.ok) throw new Error(`doesn't compile: ${out.message}`);
  return out;
};
console.log(`-- loaded Pyodide and PGlite in ${loaded} ms (Node, from disk)`);

for (const ex of examples) {
  console.log(`-- ${ex.name}`);
  t = Date.now();
  const out = c.compile(ex.policy, ex.tests);
  check(`compiles (${Date.now() - t} ms)`, out.ok, out);
  if (!out.ok) continue;
  t = Date.now();
  const run = await db.run(ex.data, out);
  check(`tables, policy and tests run (${Date.now() - t} ms)`, run.ok, run);
  if (!run.ok) continue;
  const failed = run.tests.filter((r) => !r.ok);
  check(`its ${run.tests.length} checks pass`, run.tests.length > 0 && failed.length === 0, failed);
  const asked = await db.ask(ex.as, ex.ask);
  check(`asking as ${ex.as}: rows`, asked.ok && asked.rows.length > 0, asked);
}

console.log("-- asking as someone (getting started: ada owns the project, bo and cy don't see it)");
const gs = examples[0];
await db.run(gs.data, must(c.compile(gs.policy, gs.tests)));
/** @param {string} who */
const notes = async (who) => {
  const r = await db.ask(who, "SELECT body FROM app.notes");
  return r.ok ? r.rows.map((row) => row[0]) : undefined;
};
check("ada sees her note", JSON.stringify(await notes("user:1")) === '["Chapter one"]', await notes("user:1"));
check("cy sees nothing", JSON.stringify(await notes("user:3")) === "[]", await notes("user:3"));
check("nobody signed in sees nothing", JSON.stringify(await notes("")) === "[]", await notes(""));
const refused = await db.ask("user:2", "INSERT INTO app.notes (project_id, author_id, body) VALUES (1, 2, 'mine')");
check("bo's insert is refused, with the reason", !refused.ok && refused.code === "42501" && /may not insert/.test(refused.message)
  && Boolean(refused.detail), refused);
const writes = await db.ask("user:1", "INSERT INTO app.notes (project_id, author_id, body) VALUES (1, 1, 'two') RETURNING id");
check("ada's insert works, and is rolled back", writes.ok && writes.rows.length === 1 && writes.rolledBack && writes.asRole === null
  && JSON.stringify(await notes("user:1")) === '["Chapter one"]', writes);
const committed = await db.ask("user:1", "INSERT INTO app.notes (project_id, author_id, body) VALUES (1, 1, 'kept'); COMMIT; SELECT 1");
check("a COMMIT in the statement: the answer says it wasn't rolled back", committed.ok && committed.rolledBack === false
  && JSON.stringify(await notes("user:1")) === '["Chapter one","kept"]', committed);
const ended = await db.ask("user:1", "SELECT 1; ROLLBACK; SELECT 2");
check("... a ROLLBACK, and what follows it: the same", ended.ok && ended.rolledBack === false, ended);
const escaped = await db.ask("user:3", "RESET ROLE; SELECT count(*)::int FROM app.notes");
check("a RESET ROLE in the statement: the answer says which role it ended as", escaped.ok && escaped.asRole === "postgres"
  && escaped.rows[0][0] === 2, escaped);
await db.run(gs.data, must(c.compile(gs.policy, gs.tests)));
const twice = await db.ask("user:1", "SELECT 1 AS x, 2 AS x");
check("two columns with one name: each cell its own value", twice.ok && JSON.stringify([twice.fields, twice.rows]) === '[["x","x"],[[1,2]]]', twice);
const colon = await db.ask("user:1:x", "SELECT current_setting('authz.user_id')");
check("an id with a colon is taken whole", colon.ok && colon.rows[0][0] === "1:x", colon);
const owner = await pg.query("SELECT current_user AS u");
check("after asking, the owner again (the role was reset)", owner.rows[0].u === "postgres", owner.rows);

console.log("-- mistakes");
const broken = c.compile(gs.policy.replace("can edit  = share or editor", "can edit  = share or edtor"), gs.tests);
check("a mistake: its line, message and code", !broken.ok && (broken.line ?? 0) > 0 && broken.message.includes("edtor")
  && broken.code === "AZ203", broken);
const help = broken.ok ? null : broken.help;
check("... and its page", typeof help === "string" && help.startsWith("# AZ203"), help?.slice(0, 80));
const badTest = c.compile(gs.policy, gs.tests.replace("user $ada can edit note $n", "user $ada can edt note $n"));
check("a mistake in a test names the tests", !badTest.ok && badTest.file === "tests.authz" && badTest.code === "AZ203", badTest);
const deep = c.compile(gs.policy.replace("can edit  = share or editor", `can edit  = ${"(".repeat(2000)}share or editor${")".repeat(2000)}`), gs.tests);
check("an expression nested too deep: a mistake, as the command says it", !deep.ok && deep.message.includes("nested too deep"), deep);
check("... and the compiler still works", c.compile(gs.policy, gs.tests).ok);
const badData = await db.run("CREATE TABLE app.oops (", must(c.compile(gs.policy, gs.tests)));
check("a mistake in the tables: which step, and Postgres's message", !badData.ok && badData.step === "tables and data"
  && badData.message.includes("syntax error"), badData);
const stale = await db.ask("user:1", "SELECT 1");
check("... then asking: the policy isn't applied, not the last one's role", !stale.ok
  && stale.message === "the policy isn't applied: the Tests tab says why", stale);
const missing = await db.run("CREATE SCHEMA app;", must(c.compile(gs.policy, gs.tests)));
check("tables the policy names that aren't there: AZ601", !missing.ok && missing.step === "applying the policy"
  && missing.message.includes("[AZ601]"), missing);

console.log("-- each run starts from nothing");
const again = await db.run(gs.data, must(c.compile(gs.policy, gs.tests)));
check("the same example again (roles and schemas dropped first)", again.ok && again.tests.every((r) => r.ok), again);
const other = examples[1];
const second = await db.run(other.data, must(c.compile(other.policy, other.tests)));
// the getting-started example's tables are gone (both examples use the schema app)
const left = await pg.query("SELECT (to_regclass('app.projects') IS NULL AND to_regclass('app.notes') IS NULL) AS gone");
check("another example after it, and nothing of the one before", second.ok && left.rows[0].gone === true, [second, left.rows]);

// the tables in the schema public, as Prisma, Django or Rails put them: the app role may use it, run after run
const inPublic = {
  policy: "app role app_user\n\ntype user = public.users\n\ntype doc = public.docs\n  owner : user = owner_id\n\n  can view = owner\n\n"
    + "rules public.docs\n  select : view\n",
  data: "CREATE TABLE users (id bigint PRIMARY KEY);\nCREATE TABLE docs (id bigint PRIMARY KEY, owner_id bigint REFERENCES users);\n"
    + "CREATE ROLE app_user NOSUPERUSER NOBYPASSRLS;\nGRANT SELECT ON users, docs TO app_user;\n"
    + "INSERT INTO users VALUES (1), (2);\nINSERT INTO docs VALUES (10, 1), (20, 2);\n",
};
for (const n of [1, 2]) {
  const run = await db.run(inPublic.data, must(c.compile(inPublic.policy)));
  const mine = await db.ask("user:1", "SELECT id::int FROM docs");
  check(`tables in the schema public, run ${n}: the app role reads them, its own rows only`, run.ok && mine.ok
    && JSON.stringify(mine.rows) === "[[10]]", [run, mine]);
}
const publicNow = await publicSchema();
check("... and the schema public is as a new database has it (its owner, its privileges)",
  JSON.stringify(publicNow) === JSON.stringify(freshPublic), [freshPublic, publicNow]);

// what a run's SQL sets for the session (SET, a temporary table) is gone at the next run
const setting = "SET session_replication_role = replica;\nSET search_path = app, public;\nSET statement_timeout = '7s';\n"
  + "SET authz.user_id = '3';\nCREATE TEMP TABLE leftover (x int);\n";
await db.run(setting + gs.data, must(c.compile(gs.policy, gs.tests)));
const reset = await db.run(gs.data, must(c.compile(gs.policy, gs.tests)));
const sessionNow = await session();
check("settings and temporary tables the run before made: gone", reset.ok
  && JSON.stringify(sessionNow) === JSON.stringify(freshSession), [reset.ok, freshSession, sessionNow]);

console.log("-- one thing at a time");
const inLine = line();
/** @type {string[]} */
const order = [];
const first = inLine(async () => { await new Promise((r) => setTimeout(r, 20)); order.push("first"); });
const broke = inLine(async () => { order.push("broke"); throw new Error("a step that fails"); });
const after = inLine(async () => { order.push("after"); return "answered"; });
const settled = await Promise.allSettled([first, broke, after]);
check("steps run in order, one at a time", JSON.stringify(order) === '["first","broke","after"]', order);
check("a step that fails rejects its own promise; the steps after it still run",
  settled[1].status === "rejected" && settled[2].status === "fulfilled" && settled[2].value === "answered", settled);

// the glue calls the compiler its own way: what it writes is what the command writes
console.log("-- the same SQL as the command");
const python = process.env.PYTHON || "python3";
const compilePolicy = fileURLToPath(new URL("../core/compile_policy.py", import.meta.url));
const dir = mkdtempSync(join(tmpdir(), "rowstile-playground-"));
for (const ex of examples) {
  writeFileSync(join(dir, "policy.authz"), ex.policy);
  const command = execFileSync(python, [compilePolicy, "policy.authz"], { cwd: dir, encoding: "utf8", maxBuffer: 1 << 28 });
  const here = must(c.compile(ex.policy, ""));
  check(`${ex.name}: ${here.sql.length} characters, the command's`, here.sql === command, [here.sql.length, command.length]);
}
// the build, run by a path through a symbolic link: it builds (Node gives the module its real path, not the one typed)
console.log("-- the build");
symlinkSync(fileURLToPath(new URL(".", import.meta.url)), join(dir, "link"), "dir");
const built = execFileSync(process.execPath, [join(dir, "link", "build.mjs")], { encoding: "utf8" });
check("build.mjs run through a symbolic link writes dist/", built.startsWith("wrote "), built);
rmSync(dir, { recursive: true, force: true });

console.log(`playground: ${fails ? `${fails} failed` : "all passed"}`);
process.exit(fails ? 1 : 0);
