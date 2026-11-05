// Builds the playground into playground/dist/: the page, its scripts, bundle.json (the compiler's files and the
// examples, read from the repository so they are the tested ones), and Pyodide and PGlite, copied from node_modules
// (npm ci here first: the versions package.json pins, checked against package-lock.json's hashes). The page loads
// them from its own site, not from a CDN. Serve dist/ from any static host.
//   (cd playground && npm ci) && node playground/build.mjs
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..");
/** @param {string[]} parts */
const read = (...parts) => readFileSync(join(REPO, ...parts), "utf8");

/** An example; `slug` names one a link can open (/playground/#e=<slug>).
 *  @typedef {{slug?: string, name: string, source: string, data: string, policy: string, tests: string, as: string, ask: string}} Example */

/** The fenced block of a markdown file whose info string is `lang name` (name: "" for the first unnamed one).
 *  @param {string} markdown @param {string} lang @param {string} name @returns {string} */
function block(markdown, lang, name) {
  for (const m of markdown.matchAll(/```(\w+)[ \t]*([^\n]*)\n([\s\S]*?)```/g)) {
    if (m[1] === lang && m[2].trim() === name) return m[3];
  }
  throw new Error(`no \`\`\`${lang} ${name} block`);
}

/** The compiler (core/authzlib) and the examples, as the page loads them.
 *  @returns {{compiler: Record<string, string>, examples: Example[]}} */
export function bundle() {
  /** @type {Record<string, string>} */
  const compiler = {};
  for (const f of readdirSync(join(REPO, "core", "authzlib")).sort()) {
    if (f.endsWith(".py")) compiler[f] = read("core", "authzlib", f);
  }
  const guide = read("docs", "getting-started.md");
  /** @type {Example[]} */
  const examples = [
    {
      name: "Getting started: projects and notes",
      source: "docs/getting-started.md",
      data: block(guide, "sql", ""),
      policy: block(guide, "authz", "db/policy.authz"),
      tests: block(guide, "authz", "db/tests/first.authz"),
      as: "user:1",
      ask: "SELECT n.id, n.body, p.name AS project\nFROM app.notes n JOIN app.projects p ON p.id = n.project_id",
    },
    {
      name: "Folders and files: inheritance, teams, denies",
      source: "core/example/docs.authz",
      data: read("core", "example", "app_schema.sql"),
      policy: read("core", "example", "docs.authz"),
      tests: read("core", "example", "docs.test.authz"),
      as: "user:1",
      ask: "SELECT f.id, f.name, f.folder_id FROM app.files f ORDER BY f.id",
    },
  ];
  // the cookbook's recipes (docs/cookbook/<name>.md shows docs/cookbook/<name>/): each page links to
  // /playground/#e=<name>. rows.sql is a few rows to ask about; the tests bring their own
  const book = join(REPO, "docs", "cookbook");
  for (const entry of readdirSync(book, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    if (!entry.isDirectory() || !existsSync(join(book, entry.name, "policy.authz"))) continue;
    const policy = read("docs", "cookbook", entry.name, "policy.authz");
    const title = read("docs", "cookbook", `${entry.name}.md`).match(/^# (.+)/m);
    const table = policy.match(/^rules (\S+)/m);
    if (!title || !table) throw new Error(`docs/cookbook/${entry.name}: its page needs a title, its policy a rules block`);
    examples.push({
      slug: entry.name,
      name: `Recipe: ${title[1]}`,
      source: `docs/cookbook/${entry.name}.md`,
      data: read("docs", "cookbook", entry.name, "schema.sql") + "\n" + read("docs", "cookbook", entry.name, "rows.sql"),
      policy,
      tests: read("docs", "cookbook", entry.name, "tests.authz"),
      as: "user:1",
      // what to ask first: the recipe's ask.sql if it has one (a masked column can't be read with *), else the
      // first table that has rules
      ask: existsSync(join(book, entry.name, "ask.sql")) ? read("docs", "cookbook", entry.name, "ask.sql").trim() : `SELECT * FROM ${table[1]}`,
    });
  }
  return { compiler, examples };
}

/** What the page loads of Pyodide and PGlite, as [the file in node_modules, where dist/ has it]: Pyodide's
 *  interpreter and standard library (no packages: the compiler needs none), PGlite's modules and its Postgres
 *  (no extensions). Each package's version must be the one package.json pins: a node_modules from before a new pin
 *  would build the page with another.
 *  @returns {[string, string][]} */
export function vendored() {
  const modules = join(HERE, "node_modules");
  const pins = JSON.parse(readFileSync(join(HERE, "package.json"), "utf8")).devDependencies;
  /** @type {[string, string][]} */
  const files = [];
  for (const [name, from, to, take] of /** @type {[string, string, string, (f: string) => boolean][]} */ ([
    ["pyodide", "", "pyodide",
      (f) => ["pyodide.mjs", "pyodide.asm.mjs", "pyodide.asm.wasm", "python_stdlib.zip", "pyodide-lock.json"].includes(f)],
    ["@electric-sql/pglite", "dist", "pglite", (f) => /\.(js|wasm|data)$/.test(f)],
  ])) {
    const where = join(modules, ...name.split("/"));
    if (!existsSync(join(where, "package.json"))) throw new Error(`no ${name} in playground/node_modules: npm ci in playground first`);
    const version = JSON.parse(readFileSync(join(where, "package.json"), "utf8")).version;
    if (version !== pins[name]) throw new Error(`playground/node_modules has ${name} ${version}, package.json pins ${pins[name]}: npm ci in playground`);
    for (const f of readdirSync(join(where, from)).sort()) if (take(f)) files.push([join(where, from, f), join(to, f)]);
  }
  return files;
}

// run, not imported: Node gives the module its real path, and argv[1] the one typed (a symbolic link's)
if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const dist = join(HERE, "dist");
  mkdirSync(dist, { recursive: true });
  for (const f of ["index.html", "core.mjs", "playground.mjs", "compiler.worker.mjs"]) copyFileSync(join(HERE, f), join(dist, f));
  for (const [from, to] of vendored()) {
    mkdirSync(dirname(join(dist, to)), { recursive: true });
    copyFileSync(from, join(dist, to));
  }
  writeFileSync(join(dist, "bundle.json"), JSON.stringify(bundle()));
  console.log(`wrote ${dist}`);
}
