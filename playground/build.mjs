// Builds the playground into playground/dist/: the page, its scripts, and bundle.json (the compiler's files and
// the examples, read from the repository so they are the tested ones). Serve dist/ from any static host.
//   node playground/build.mjs
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
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

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const dist = join(HERE, "dist");
  mkdirSync(dist, { recursive: true });
  for (const f of ["index.html", "core.mjs", "playground.mjs", "compiler.worker.mjs"]) copyFileSync(join(HERE, f), join(dist, f));
  writeFileSync(join(dist, "bundle.json"), JSON.stringify(bundle()));
  console.log(`wrote ${dist}`);
}
