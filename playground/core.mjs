// The playground's engine, the same in the browser and in Node (test.mjs): the compiler in Pyodide (it is
// core/authzlib, standard library only) and the SQL it writes in PGlite (Postgres in WebAssembly).
// Nothing here touches the page: playground.mjs does. Plain JavaScript, typed with JSDoc and checked strictly
// (playground/tsconfig.json).

/** @typedef {{ok: true, sql: string, tests: string, graph: string, role: string, types: string[]}} Compiled */
/** @typedef {{ok: false, file: string | null, line: number | null, message: string, code: string | null, help: string | null}} Mistake */
/** @typedef {Compiled | Mistake} Compile */
/** @typedef {{compile(policy: string, tests?: string): Compile, help(code: string): string | null}} Compiler */
/** @typedef {{ok: false, step: string, message: string, detail: string | null, hint: string | null, code: string | null}} Failure */
/** @typedef {{test: string, line: string | null, ok: boolean, detail: string | null}} TestRow */
/** @typedef {{ok: true, tests: TestRow[]} | Failure} Run */
/** @typedef {{ok: true, fields: string[], rows: unknown[][], rolledBack: boolean, asRole: string | null} | Failure} Answer
 *  (rows: each a list, in the fields' order; rolledBack: false when the statement ended the transaction itself, with a
 *  COMMIT or ROLLBACK; asRole: the role it ended as, when that isn't the app role, as after a RESET ROLE) */
/** @typedef {{run(data: string, compiled: Compiled): Promise<Run>, ask(who: string, sql: string): Promise<Answer>}} Database */

const GLUE = `
import json, re, sys
sys.path.insert(0, "/rowstile")
from authzlib import Compiler, PolicyError, parse_policy, errors

LINE = re.compile(r"(?:(\\S+) )?line (\\d+): (.*)", re.S)


def _mistake(e):
    message, code = errors.split(str(e))
    m = LINE.fullmatch(message)
    return {"ok": False, "file": m.group(1) if m else None, "line": int(m.group(2)) if m else None,
            "message": m.group(3) if m else message, "code": code,
            "help": errors.page(code) if code in errors.CODES else None}


def pg_compile(policy, tests):
    """The policy's SQL, the SQL of its tests (the test section, the named tests, the invariants) and its
    graph; or the first mistake, with its line, code and page."""
    try:
        c = Compiler(parse_policy(policy, None, files={}))
        sql = c.compile("policy.authz")
        graph = c.graph()
        if tests.strip():
            c.add_test_files({"tests.authz": tests})
        return json.dumps({"ok": True, "sql": sql, "tests": c.tests_function_sql(), "graph": graph,
                           "role": c.role, "types": sorted(c.types)})
    except PolicyError as e:
        return json.dumps(_mistake(e))
    except RecursionError:      # what the command says of it
        return json.dumps({"ok": False, "file": None, "line": None, "code": None, "help": None,
                           "message": "an expression in the policy is nested too deep to read"})


def pg_help(code):
    return errors.page(code) if code in errors.CODES else None
`;

/** The compiler, in a Pyodide that has loaded: the bundle's files (authzlib) written into its file system.
 *  @param {import("pyodide").PyodideAPI} py @param {Record<string, string>} files @returns {Compiler} */
export function compiler(py, files) {
  py.FS.mkdirTree("/rowstile/authzlib");
  for (const [name, text] of Object.entries(files)) py.FS.writeFile(`/rowstile/authzlib/${name}`, text);
  py.runPython(GLUE);
  /** @param {string} name @param {unknown[]} args @returns {unknown} */
  const call = (name, ...args) => {
    const fn = py.globals.get(name);
    try {
      return fn(...args);
    } finally {
      fn.destroy();
    }
  };
  return {
    /** {ok, sql, tests, graph, role, types} or {ok: false, line, message, code, help} */
    compile: (policy, tests = "") => JSON.parse(String(call("pg_compile", policy, tests))),
    help: (code) => {
      const page = call("pg_help", code);
      return typeof page === "string" ? page : null;
    },
  };
}

// psql's own commands (\set, \echo) mean nothing to Postgres itself
/** @param {string} sql */
const withoutPsql = (sql) => sql.split("\n").filter((line) => !line.trimStart().startsWith("\\")).join("\n");

const RESET = `
RESET ROLE;
DO $reset$
DECLARE r record;
BEGIN
  FOR r IN SELECT nspname FROM pg_namespace
           WHERE nspname NOT LIKE 'pg\\_%' AND nspname NOT IN ('information_schema', 'public') LOOP
    EXECUTE format('DROP SCHEMA %I CASCADE', r.nspname);
  END LOOP;
  FOR r IN SELECT rolname FROM pg_roles WHERE rolname NOT LIKE 'pg\\_%' AND rolname <> current_user LOOP
    EXECUTE format('DROP OWNED BY %I CASCADE', r.rolname);
    EXECUTE format('DROP ROLE %I', r.rolname);
  END LOOP;
END $reset$;
DROP SCHEMA public CASCADE;
CREATE SCHEMA public;
`;

/** Where a statement failed, as the page shows it: Postgres's error fields, when it has them.
 *  @param {string} step @param {unknown} e @returns {Failure} */
function failure(step, e) {
  /** @type {{message?: unknown, detail?: unknown, hint?: unknown, code?: unknown}} */
  const f = typeof e === "object" && e !== null ? e : { message: String(e) };
  /** @param {unknown} v */
  const text = (v) => (typeof v === "string" ? v : null);
  return { ok: false, step, message: text(f.message) ?? String(e), detail: text(f.detail), hint: text(f.hint), code: text(f.code) };
}

/** One thing at a time (PGlite runs one statement at a time): each step starts once the one before it has
 *  settled. A step that fails rejects its own promise only; the steps after it still run.
 *  @returns {<T>(step: () => Promise<T>) => Promise<T>} */
export function line() {
  /** @type {Promise<unknown>} */
  let tail = Promise.resolve();
  /** @template T @param {() => Promise<T>} step @returns {Promise<T>} */
  const next = (step) => {
    const done = tail.then(step);
    tail = done.catch(() => undefined);
    return done;
  };
  return next;
}

/** A database for the playground: empty again before each run, then the app's tables and data, then the
 *  policy, then its tests. pg is a PGlite; its user is the superuser, which owns the tables, as the owner
 *  would on a server. @param {import("@electric-sql/pglite").PGlite} pg @returns {Database} */
export function database(pg) {
  /** @type {string | null} */
  let role = null;
  return {
    /** Everything from nothing: {ok, tests: [{test, line, ok, detail}]} or {ok: false, step, message, ...} */
    async run(data, compiled) {
      role = null;                                        // the reset below drops the last policy's role
      try {
        await pg.exec("ROLLBACK").catch(() => undefined);     // what a failed run left open (a policy is BEGIN ... COMMIT)
        await pg.exec(RESET);
      } catch (e) {
        return failure("reset", e);
      }
      try {
        await pg.exec(withoutPsql(data));
      } catch (e) {
        return failure("tables and data", e);
      }
      try {
        await pg.exec(compiled.sql);
      } catch (e) {
        return failure("applying the policy", e);
      }
      role = compiled.role;
      try {
        await pg.exec(compiled.tests);
        const r = await pg.query("SELECT test, line, ok, detail FROM pg_temp.authz_policy_tests()");
        return { ok: true, tests: /** @type {TestRow[]} */ (r.rows) };     // the test function's columns
      } catch (e) {
        return failure("tests", e);
      }
    },

    /** A statement as the app role, signed in as who ('user:3', 'bot:7', or '' for nobody); rolled back, unless
     *  the statement ends the transaction itself. {ok, fields, rows, rolledBack, asRole} or {ok: false, message, ...} */
    async ask(who, sql) {
      if (!role) return failure("ask", "the policy isn't applied: the Tests tab says why");
      if (role === "PUBLIC") {
        return failure("ask", "the policy names no app role: add a line like 'app role app_user'");
      }
      const cut = who.indexOf(":");                   // the first colon: an id may have its own
      const [kind, id] = cut < 0 ? ["user", who] : [who.slice(0, cut), who.slice(cut + 1)];
      await pg.exec("RESET ROLE; ROLLBACK;").catch(() => undefined);
      try {
        await pg.exec(`SET ROLE "${role.replaceAll('"', '""')}"`);
        await pg.exec("BEGIN");
        await pg.query("SELECT set_config('playground.asking', 'on', true)");     // gone once this transaction ends
        await pg.query("SELECT authz.act_as($1, $2)", [kind, id || null]);
        // rows as lists: two columns may have one name (a join's two ids), and a row keyed by name keeps one
        const results = await pg.exec(sql, { rowMode: "array" });
        const last = results[results.length - 1] ?? { fields: [], rows: [] };
        // a COMMIT or ROLLBACK in the statement ended the transaction (what it wrote stays), a RESET ROLE the app role
        const after = await pg.query("SELECT current_setting('playground.asking', true) IS NOT DISTINCT FROM 'on' AS open, current_user AS u");
        const { open, u } = /** @type {{open: boolean, u: string}} */ (after.rows[0]);
        return { ok: true, fields: last.fields.map((f) => f.name), rows: /** @type {unknown[][]} */ (last.rows),
          rolledBack: open, asRole: u === role ? null : u };
      } catch (e) {
        return failure("ask", e);
      } finally {
        await pg.exec("ROLLBACK; RESET ROLE;").catch(() => undefined);
      }
    },
  };
}
