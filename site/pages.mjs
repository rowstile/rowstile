// The site's pages: which Markdown in the repository, at which address. The files stay where they are, written
// for GitHub and editors (links relative to the file); siteLink() turns each link into the site's: a page's address,
// or the file on GitHub. A link to a file that isn't in the repository fails the build.
// Plain JavaScript, typed with JSDoc and checked strictly (site/tsconfig.json).
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, posix, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const GITHUB = "https://github.com/rowstile/rowstile";
const BRANCH = "main";

const errorPages = readdirSync(join(REPO, "docs", "errors")).filter((f) => /^AZ\d+\.md$/.test(f)).sort();
// a recipe with a page of its own: docs/cookbook/<name>.md, beside the folder that holds what it shows
const recipePages = readdirSync(join(REPO, "docs", "cookbook")).filter((f) => /^[a-z0-9-]+\.md$/.test(f)).sort();
// a page per alternative: docs/compare/<name>.md, titled "rowstile and <the alternative>"
const COMPARE = join(REPO, "docs", "compare");
const comparePages = existsSync(COMPARE) ? readdirSync(COMPARE).filter((f) => /^[a-z0-9-]+\.md$/.test(f)).sort() : [];

/** A post of the blog.
 *  @typedef {{file: string, source: string, address: string, slug: string, date: string, title: string,
 *             author: string, summary: string}} Post */

/** Markdown as plain text, for a summary: links as their words, no backticks or emphasis. @param {string} text */
function plain(text) {
  return text.replace(/\[([^\]]+)\]\([^)]+\)/g, "$1").replace(/[`*_]/g, "").replace(/\s+/g, " ").trim();
}

/** A post, from its file's name and text: docs/blog/2026-10-23-how-it-is-checked.md, which begins with its title,
 *  then its byline (the author's name and the date its name has), then a first paragraph, which is its summary
 *  (what a feed and a search result show). Its address has no date: /blog/how-it-is-checked. A file that isn't
 *  so fails the build.
 *  @param {string} file @param {string} text @returns {Post} */
export function readPost(file, text) {
  const name = file.match(/^(\d{4}-\d{2}-\d{2})-([a-z0-9]+(?:-[a-z0-9]+)*)\.md$/);
  if (!name) throw new Error(`docs/blog/${file}: a post is named <date>-<slug>.md (2026-10-23-how-it-is-checked.md)`);
  const [, date, slug] = name;
  const day = new Date(`${date}T00:00:00Z`);
  if (Number.isNaN(day.getTime()) || day.toISOString().slice(0, 10) !== date) {
    throw new Error(`docs/blog/${file}: ${date} is not a date`);
  }
  const blocks = text.replace(/\r\n/g, "\n").split(/\n{2,}/).map((b) => b.trim()).filter(Boolean);
  const title = blocks[0]?.match(/^# (.+)$/);
  if (!title) throw new Error(`docs/blog/${file}: its first line is its title (# ...)`);
  const byline = blocks[1]?.match(/^\*([^*,]+), (\d{4}-\d{2}-\d{2})\*$/);
  if (!byline) throw new Error(`docs/blog/${file}: under the title, the author and the date: *Their Name, ${date}*`);
  if (byline[2] !== date) throw new Error(`docs/blog/${file}: its byline says ${byline[2]}, its name ${date}`);
  const first = blocks[2] ?? "";
  if (!first || /^(#|```|\||>|[-*] |\d+\. |<)/.test(first)) {
    throw new Error(`docs/blog/${file}: after the byline, a first paragraph (what a feed and a search result show)`);
  }
  return { file, source: `docs/blog/${file}`, address: `blog/${slug}.md`, slug, date, title: title[1],
           author: byline[1].trim(), summary: plain(first) };
}

/** The blog's posts, newest first: docs/blog/<date>-<slug>.md, each listed in docs/blog/README.md (the index, on
 *  GitHub too). With no post there is no blog: no page, no feed, nothing in the navigation.
 *  @type {Post[]} */
export const POSTS = (() => {
  const folder = join(REPO, "docs", "blog");
  if (!existsSync(folder)) return [];
  const posts = readdirSync(folder).filter((f) => f.endsWith(".md") && f !== "README.md")
    .map((f) => readPost(f, readFileSync(join(folder, f), "utf8")))
    .sort((a, b) => (a.date === b.date ? a.slug.localeCompare(b.slug) : a.date < b.date ? 1 : -1));
  const index = posts.length ? readFileSync(join(folder, "README.md"), "utf8") : "";
  for (const p of posts) {
    if (posts.some((q) => q !== p && q.slug === p.slug)) throw new Error(`docs/blog: two posts are named ${p.slug}`);
    if (!index.includes(`](${p.file})`)) throw new Error(`docs/blog/README.md doesn't list ${p.file}`);
  }
  return posts;
})();

/** Repository path -> address in the site (the page's path, with .md). @type {Record<string, string>} */
export const PAGES = {
  "site/index.md": "index.md",
  "docs/installing.md": "installing.md",
  "docs/getting-started.md": "getting-started.md",
  // an index, not cookbook.md: beside a folder of the same name, a static host answers /cookbook with the folder
  "docs/cookbook.md": "cookbook/index.md",
  ...Object.fromEntries(recipePages.map((f) => [`docs/cookbook/${f}`, `cookbook/${f}`])),
  "docs/troubleshooting.md": "troubleshooting.md",
  "docs/operations.md": "operations.md",
  "docs/managed-postgres.md": "managed-postgres.md",
  "docs/signed-urls.md": "signed-urls.md",
  "docs/comparison.md": "comparison.md",
  ...Object.fromEntries(comparePages.map((f) => [`docs/compare/${f}`, `compare/${f}`])),
  "docs/how-it-is-checked.md": "how-it-is-checked.md",
  "docs/threat-model.md": "threat-model.md",
  "SECURITY.md": "security.md",
  "CHANGELOG.md": "changelog.md",
  "docs/reference/language.md": "reference/language.md",
  "docs/reference/app-code.md": "reference/app-code.md",
  "docs/reference/identity.md": "reference/identity.md",
  "docs/reference/governance.md": "reference/governance.md",
  "docs/reference/tools.md": "reference/tools.md",
  "docs/reference/migrations.md": "reference/migrations.md",
  "docs/reference/review.md": "reference/review.md",
  "docs/reference/guarantees.md": "reference/guarantees.md",
  "docs/reference/limits.md": "reference/limits.md",
  "core/README.md": "development.md",
  "core/CONTEXT.md": "words.md",
  "editor/README.md": "editor.md",
  "core/bench/README.md": "benchmark.md",
  "docs/stacks/README.md": "stacks/index.md",
  "docs/stacks/fastapi.md": "stacks/fastapi.md",
  "docs/stacks/nextjs.md": "stacks/nextjs.md",
  "docs/stacks/node.md": "stacks/node.md",
  "docs/stacks/python.md": "stacks/python.md",
  "docs/stacks/sql.md": "stacks/sql.md",
  "sdk/python/README.md": "sdk/python.md",
  "sdk/typescript/README.md": "sdk/typescript.md",
  "integrations/README.md": "sdk/conformance.md",
  "examples/README.md": "examples/index.md",
  "examples/filemanager/README.md": "examples/filemanager.md",
  "examples/messenger/README.md": "examples/messenger.md",
  "site/problems/refused.md": "problems/refused.md",
  "site/problems/not-found.md": "problems/not-found.md",
  "site/problems/bad-argument.md": "problems/bad-argument.md",
  "site/problems/not-signed-in.md": "problems/not-signed-in.md",
  "site/problems/conflict.md": "problems/conflict.md",
  "docs/errors/README.md": "errors/index.md",
  ...Object.fromEntries(errorPages.map((f) => [`docs/errors/${f}`, `errors/${f}`])),
  ...(POSTS.length ? { "docs/blog/README.md": "blog/index.md" } : {}),
  ...Object.fromEntries(POSTS.map((p) => [p.source, p.address])),
};

/** Titles for pages whose first heading says something else on the site. @type {Record<string, string>} */
export const TITLES = { "development.md": "Working on rowstile", "words.md": "Words" };

/** Where the site is served: the sitemap's and the canonical links' host. */
export const ORIGIN = "https://rowstile.dev";

/** One sentence per page, for search results and shared links. It is here and not in the Markdown, which is read on
 *  GitHub too, where front matter shows as a table. An error page's and a recipe's are made from their titles, a
 *  post's is its first paragraph, and so is a comparison page's that has no sentence here (describe).
 *  @type {Record<string, string>} */
export const DESCRIPTIONS = {
  "index.md": "Authorization for Postgres apps: access rules in a policy file, compiled into row-level security. Sharing, groups, nested folders, tenants.",
  "installing.md": "Install the rowstile command and its SDKs with npm, pip or Docker. Nothing is installed in the Postgres database. PostgreSQL 16, 17 and 18.",
  "getting-started.md": "From a Postgres schema to a tested access policy enforced by row-level security, the edit loop and the first migration, in about fifteen minutes.",
  "cookbook/index.md": "Tested row-level security recipes for Postgres: multi-tenant apps, roles, nested teams, folders that inherit, sharing and links, soft deletes, masked columns.",
  "troubleshooting.md": "What people run into with rowstile and Postgres row-level security, by what they see, and how to fix each.",
  "operations.md": "Running rowstile in production: behind PgBouncer and other poolers, deploying a policy change, upgrading, backups, retention, what to watch.",
  "managed-postgres.md": "rowstile on managed Postgres: the setup on Neon and Supabase as tried, with their poolers, connection strings and limits.",
  "signed-urls.md": "Files in S3-compatible storage behind Postgres row-level security: a signed URL handed out only after the row was read.",
  "comparison.md": "rowstile beside OpenFGA, SpiceDB, Cerbos, ZenStack, hand-written row-level security and checks in app code: where the facts live, who enforces, and when each is the better choice.",
  "compare/openfga.md": "rowstile and OpenFGA compared: the same model in both, what the app writes when a fact changes, lists, consistency, and when OpenFGA is the better choice.",
  "compare/spicedb.md": "rowstile and SpiceDB compared: the same schema in both, ZedTokens and transactions, caveats and SQL conditions, lists, and when SpiceDB is the better choice.",
  "compare/zenstack.md": "rowstile and ZenStack compared: access rules enforced by the ORM or by Postgres row-level security, what each stops, and when ZenStack is the better choice.",
  "compare/hand-written-rls.md": "Postgres row-level security by hand or generated: a flat rule, a tree and the infinite recursion error, who is asking, and when CREATE POLICY by hand is enough.",
  "compare/app-code.md": "Permission checks in app code or in the database: the forgotten check, the list filtered twice, what a handler looks like without checks, and what it costs.",
  "how-it-is-checked.md": "What checks rowstile, since nobody outside has audited it: a second implementation, random policies, the app role's boundary, races, proofs, and what a review of every file found.",
  "threat-model.md": "rowstile's threat model: what the generated row-level security protects, who is trusted, what stops what, and the known limits.",
  "security.md": "How to report a vulnerability in rowstile privately, and what to expect.",
  "changelog.md": "What changed in each rowstile release, and what to do when upgrading.",
  "reference/language.md": "The rowstile policy language: types, relations, permissions, inheritance, denies, rules per table command, masked columns, invariants, tests.",
  "reference/app-code.md": "Using rowstile from app code: the authz.* SQL functions for checks, lists, sharing, who has access and why, and the generated clients.",
  "reference/identity.md": "Who is asking, in each transaction: a trusted backend, API keys with scopes, JWT login, services, and signed sessions in Postgres.",
  "reference/governance.md": "Audit trail, change feed, access requests, break glass, access reviews and authz.lint() for Postgres row-level security.",
  "reference/tools.md": "Every rowstile command (init, dev, check, test, prove, review, migrate, why, Studio), rowstile.toml and the MCP server for coding agents.",
  "reference/migrations.md": "A policy change as a migration for Alembic, Prisma, Drizzle Kit, plain SQL, goose, dbmate or Flyway, and the lock file.",
  "reference/review.md": "rowstile review says on the pull request what a policy change does: who gains or loses access, the risk, the tests, the deploy. For GitHub and GitLab.",
  "reference/guarantees.md": "How rowstile works: what a policy compiles to in Postgres (views, closure tables, row-level security policies), what it guarantees, security.",
  "reference/limits.md": "The measured speed of rowstile's row-level security at 20 million files, its limits, and what a 0.x release promises.",
  "development.md": "Working on rowstile's core: what is where, and the test suites.",
  "words.md": "The words rowstile uses: policy, object, subject, principal, relation, permission, share, role, rule.",
  "editor.md": "rowstile in your editor: the VS Code and Zed extensions, Tree-sitter for Helix and Neovim, and the language server for .authz files.",
  "benchmark.md": "rowstile's scale benchmark: row-level security reads and tree writes in Postgres, measured with 20 million files and a million folders.",
  "stacks/index.md": "rowstile in your stack: FastAPI, Next.js with Prisma, Node with pg, postgres.js or Drizzle, Python, or plain SQL from any language.",
  "stacks/fastapi.md": "Permissions for a FastAPI app with SQLAlchemy and Alembic, enforced by Postgres row-level security: each transaction signed in, 403 and 404 from the database.",
  "stacks/nextjs.md": "Permissions for a Next.js app with Prisma and React, enforced by Postgres row-level security: every query signed in, refusals as errors, signed-in reads out of the caches.",
  "stacks/node.md": "rowstile for Node apps on pg, postgres.js or Drizzle (Express, Hono, workers): transactions signed in as the request's user.",
  "stacks/python.md": "rowstile for Python apps on SQLAlchemy, SQLModel, psycopg or asyncpg: transactions signed in as the request's user.",
  "stacks/sql.md": "rowstile from any language (Go, Ruby, Java, Rust): the few SQL statements that sign a transaction in and read a refusal.",
  "sdk/python.md": "The rowstile Python SDK: FastAPI, SQLAlchemy, psycopg, asyncpg, Alembic and pytest on a rowstile policy.",
  "sdk/typescript.md": "The rowstile TypeScript SDK: Next.js, Prisma, Drizzle, pg, postgres.js, React and Vitest on a rowstile policy.",
  "sdk/conformance.md": "The conformance suites: the checks every rowstile SDK must pass, run by a small app per stack.",
  "examples/index.md": "Complete apps built on rowstile, with no permission checks in their backends: a file manager and a messenger.",
  "examples/filemanager.md": "A file manager on rowstile: folders inside folders, sharing with people and groups, links and versions, with FastAPI, React and S3-compatible storage.",
  "examples/messenger.md": "A WhatsApp-style messenger on rowstile: direct chats, groups and admins, invite links, blocking, bots with API keys, live updates.",
  "problems/refused.md": "The problem type the rowstile SDKs answer with (403) when Postgres refused a write, with the rule and the reason.",
  "problems/not-found.md": "The problem type the rowstile SDKs answer with (404) when a row isn't there or can't be seen, or what a call names isn't there.",
  "problems/bad-argument.md": "The problem type the rowstile SDKs answer with (400) when the database says a call lacks an argument or has a wrong one.",
  "problems/not-signed-in.md": "The problem type the rowstile SDKs answer with (401) when the database says a call needs someone signed in, or a login was refused.",
  "problems/conflict.md": "The problem type the rowstile SDKs answer with (409) when the database turns down a move that would put an object inside itself, or a row changed since it was read.",
  "errors/index.md": "Every rowstile error code: what it means, the mistake, and the same mistake fixed.",
};

{
  const addresses = new Set(Object.values(PAGES));
  const stale = Object.keys(DESCRIPTIONS).filter((a) => !addresses.has(a));
  if (stale.length) throw new Error(`site/pages.mjs: DESCRIPTIONS names what isn't a page: ${stale.join(", ")}`);
}

/** A page's description. A page without one fails the build: add its sentence to DESCRIPTIONS.
 *  @param {string} address @param {string} title */
export function describe(address, title) {
  const said = DESCRIPTIONS[address];
  if (said) return said;
  if (/^errors\/AZ\d+\.md$/.test(address)) return `${title}: what this rowstile error means, the mistake, and the same mistake fixed.`;
  if (/^cookbook\/[a-z0-9-]+\.md$/.test(address)) {
    return `${title}: a tested recipe for Postgres row-level security, with its tables, its policy and its tests.`;
  }
  if (address === "blog/index.md") {
    return "The rowstile blog: how row-level security in Postgres works at scale, how rowstile is checked, and what was measured.";
  }
  const post = POSTS.find((p) => p.address === address);
  if (post) return short(post.summary);
  const compared = address.match(/^compare\/([a-z0-9-]+\.md)$/);
  if (compared) {
    // a page that came after this file was last written: its first paragraph, as a post's
    const blocks = readFileSync(join(COMPARE, compared[1]), "utf8").replace(/\r\n/g, "\n").split(/\n{2,}/);
    const first = (blocks[1] ?? "").trim();
    if (!first || /^(#|```|\||>|[-*] |\d+\. |<)/.test(first)) {
      throw new Error(`docs/compare/${compared[1]}: after the title, a first paragraph (what a search result shows)`);
    }
    return short(plain(first));
  }
  throw new Error(`${address}: no description in site/pages.mjs (DESCRIPTIONS)`);
}

/** A summary as a description. A search result shows about 160 characters: the first sentences that fit, else cut
 *  at a word. @param {string} summary */
function short(summary) {
  if (summary.length <= 200) return summary;
  const sentences = summary.slice(0, 200).match(/^.*[.!?](?= )/s);
  return sentences ? sentences[0] : summary.slice(0, 197).replace(/\s+\S*$/, "") + "...";
}

/** A page's URL: "/reference", "/stacks/". @param {string} address */
export function url(address) {
  return "/" + address.replace(/(^|\/)index\.md$/, "$1").replace(/\.md$/, "");
}

/** Where a link written in `source` (a repository path) goes on the site: a page's URL, or GitHub.
 *  @param {string} source @param {string} href @returns {string} */
export function siteLink(source, href) {
  if (/^([a-z][a-z0-9+.-]*:|\/\/|#)/i.test(href)) return href;       // elsewhere, mailto:, or on the same page
  const cut = href.indexOf("#");
  const path = cut < 0 ? href : href.slice(0, cut);
  const hash = cut < 0 ? "" : href.slice(cut);
  const target = posix.normalize(path.startsWith("/") ? path.slice(1) : posix.join(posix.dirname(source), decodeURI(path)))
    .replace(/\/$/, "");
  if (target.startsWith("..") || !existsSync(join(REPO, target))) {
    throw new Error(`${source}: the link ${href} points to ${target}, which isn't in the repository`);
  }
  const dir = statSync(join(REPO, target)).isDirectory();
  const page = PAGES[target] ?? (dir ? PAGES[posix.join(target, "README.md")] : undefined);
  if (page) return url(page) + hash;
  if (target === ".") return GITHUB;
  return `${GITHUB}/${dir ? "tree" : "blob"}/${BRANCH}/${target}${hash}`;
}

/** Every other Markdown file in the repository, and the folders of what's installed or built: not pages. */
export function notPages() {
  const skip = new Set(["node_modules", ".git", "dist", ".venv", ".vitepress", ".next", "out", ".cache"]);
  const found = [...skip].map((d) => `**/${d}/**`);
  (function walk(/** @type {string} */ rel) {
    for (const e of readdirSync(join(REPO, rel), { withFileTypes: true })) {
      const p = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) { if (!skip.has(e.name)) walk(p); }
      else if (e.name.endsWith(".md") && !(p in PAGES)) found.push(p);
    }
  })("");
  return found;
}

/** The recipes' sidebar: each page's title (its first heading). @returns {{text: string, link: string}[]} */
export function recipeSidebar() {
  return recipePages.map((f) => {
    const title = readFileSync(join(REPO, "docs", "cookbook", f), "utf8").match(/^# (.+)/m);
    if (!title) throw new Error(`docs/cookbook/${f} has no title`);
    return { text: title[1], link: `/cookbook/${f.replace(/\.md$/, "")}` };
  });
}

/** The comparison pages' sidebar: what each is compared with, from its title ("# rowstile and OpenFGA").
 *  @returns {{text: string, link: string}[]} */
export function compareSidebar() {
  return comparePages.map((f) => {
    const title = readFileSync(join(COMPARE, f), "utf8").match(/^# rowstile and (.+)/);
    if (!title) throw new Error(`docs/compare/${f}: its first line is its title, "# rowstile and <the alternative>"`);
    return { text: title[1][0].toUpperCase() + title[1].slice(1), link: `/compare/${f.replace(/\.md$/, "")}` };
  });
}

/** The blog's sidebar: the posts, newest first.@returns {{text: string, link: string}[]} */
export function blogSidebar() {
  return POSTS.map((p) => ({ text: p.title, link: url(p.address) }));
}

/** The error pages' sidebar: the sections of docs/errors/README.md, each code with its title. */
/** @typedef {{text: string, link: string}} Item */
/** @typedef {{text: string, collapsed: boolean, items: Item[]}} Group */
/** @returns {Group[]} */
export function errorSidebar() {
  /** @type {Group[]} */
  const groups = [];
  for (const line of readFileSync(join(REPO, "docs", "errors", "README.md"), "utf8").split("\n")) {
    const h = line.match(/^## (.+)/);
    const item = line.match(/^- \[(AZ\d+)\]\(AZ\d+\.md\): (.+)/);
    if (h) groups.push({ text: h[1], collapsed: true, items: [] });
    else if (item) groups.at(-1)?.items.push({ text: `${item[1]} ${item[2]}`, link: `/errors/${item[1]}` });
  }
  return groups;
}
