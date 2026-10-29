// The site's links without building it (pages.mjs): where a link to a file on GitHub goes when the site is built from
// a tag, a heading's anchor, the links to a heading that isn't there, the Markdown copies' links, and the menus
// against the pages.   node site/pages_test.mjs
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { createMarkdownRenderer } from "vitepress";

// what site.yml gives the build when it is built from a tag (read when pages.mjs is imported)
process.env.SITE_CODE = "site-v4";
const { PAGES, POSTS, REPO, checkMenus, deadAnchors, inSitemap, menuLinks, pageTitle, rewriteLinks, siteLink, slug, structured, url } =
  await import("./pages.mjs");
const { KEY, KEY_FILE, payload } = await import("./indexnow.mjs");

let failed = 0;
/** @param {string} label @param {unknown} ok @param {unknown} [detail] */
function check(label, ok, detail) {
  if (ok) console.log(`ok    ${label}`);
  else {
    failed++;
    console.log(`FAIL  ${label}${detail === undefined ? "" : ": " + String(detail).slice(0, 600)}`);
  }
}
/** @param {() => unknown} fn @returns {string} the error's message, or "" if it didn't throw */
function refused(fn) {
  try {
    fn();
    return "";
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
}
/** @param {unknown} got @param {unknown} want */
const same = (got, want) => JSON.stringify(got) === JSON.stringify(want);

// a link to a file on GitHub: the tag the site is built from
const GH = "https://github.com/rowstile/rowstile";
for (const [label, source, href, want] of [
  ["a recipe's folder", "docs/cookbook/tenants.md", "tenants/", `${GH}/tree/site-v4/docs/cookbook/tenants`],
  ["a file, its anchor kept", "docs/troubleshooting.md", "../core/tests/unit_test.py#L1", `${GH}/blob/site-v4/core/tests/unit_test.py#L1`],
  ["a workflow", "docs/how-it-is-checked.md", "../.github/workflows/nightly.yml", `${GH}/blob/site-v4/.github/workflows/nightly.yml`],
  ["a post's run", "docs/blog/README.md", "recursive-row-level-security", `${GH}/tree/site-v4/docs/blog/recursive-row-level-security`],
  ["a page stays a page", "docs/troubleshooting.md", "operations.md#behind-a-pooler", "/operations#behind-a-pooler"],
]) {
  const got = siteLink(source, href);
  check(`a link at a tag: ${label}`, got === want, got);
}

// headings' anchors as GitHub makes them, which the links are written for
for (const [heading, want] of [
  ["What a 0.x release promises", "what-a-0x-release-promises"],
  ["AZ101: a line the language doesn't read", "az101-a-line-the-language-doesnt-read"],
  ["`authz.can(type, id, perm)`: one check", "authzcantype-id-perm-one-check"],
  ["1. The natural policy", "1-the-natural-policy"],
  ["Sharing & links, snake_case", "sharing--links-snake_case"],
  ["Café, naïve", "café-naïve"],
]) {
  check(`a heading's anchor: ${heading}`, slug(heading) === want, slug(heading));
}

// links to a heading, against the ids of the built pages
/** @param {string} source @param {string} html */
const page = (source, html) => ({ source, html });
const built = new Map([
  ["/operations", page("docs/operations.md", '<h2 id="behind-a-pooler">Behind a pooler</h2><a href="#behind-a-pooler">#</a>' +
    '<main id="VPContent"></main><a href="#VPContent">skip</a>')],
  ["/stacks/", page("docs/stacks/README.md", '<div id="VPContent"></div><h2 id="what-a-0x-release-promises">x</h2>' +
    '<a href="/operations#behind-a-pooler">ok</a><a href="/playground/#e=tenants">elsewhere</a><a href="#">top</a>')],
]);
check("links to headings that are there", same(deadAnchors(built), []), deadAnchors(built));
built.set("/troubleshooting", page("docs/troubleshooting.md", '<a href="/operations#no-such-heading">x</a>' +
  '<a href="/stacks/#what-a-0-x-release-promises">y</a><a href="#nor-here">z</a><a href="/operations#behind-a-pooler">fine</a>'));
check("links to headings that aren't there, each named with the file it is in", same(deadAnchors(built), [
  "docs/troubleshooting.md: the link /operations#no-such-heading goes to a heading docs/operations.md doesn't have",
  "docs/troubleshooting.md: the link /stacks/#what-a-0-x-release-promises goes to a heading docs/stacks/README.md doesn't have",
  "docs/troubleshooting.md: the link #nor-here goes to a heading docs/troubleshooting.md doesn't have",
]), deadAnchors(built));
built.delete("/troubleshooting");
const fromLlms = deadAnchors(built, [{ from: "llms.txt", href: "/operations#gone" }, { from: "llms.txt", href: "/operations#behind-a-pooler" },
  { from: "llms.txt", href: "#top" }]);
check("... and llms.txt's", same(fromLlms, ["llms.txt: the link /operations#gone goes to a heading docs/operations.md doesn't have"]), fromLlms);
check("an anchor written with entities and escapes", same(deadAnchors(new Map([
  ["/a", page("a.md", '<h2 id="café--co">x</h2><a href="/a#caf%C3%A9--co">x</a><h2 id="a&amp;b">y</h2><a href="#a&amp;b">y</a>' +
    '<h2 id="100%">z</h2><a href="#100%">z</a>')],
])), []));

// the Markdown copies' links: rewritten where Markdown reads a link, refused where it can't be
const md = await createMarkdownRenderer(REPO);
/** @param {string} text */
const parse = (text) => md.parse(text, {});
/** @param {string} text */
const rewrite = (text) => rewriteLinks(parse, "docs/x.md", text, (href) => `/to/${href}`);
const text = [
  "# A page",
  "",
  "See [the pooler](operations.md#behind-a-pooler), [a title](a.md \"its title\") and [brackets](<b c.md>).",
  "![the mark](mark.svg) and <https://example.com> and https://example.org stay.",
  "Code isn't a link: `[x](not-a-link.md)`, nor ``a ` [y](tick.md)``.",
  "",
  "```sql",
  "SELECT '[x](in-a-fence.md)';",
  "```",
  "",
  "    [x](indented.md)",
  "",
  "<div>[x](in-html.md)</div>",
  "",
].join("\n");
const out = (() => {
  try {
    return rewrite(text);
  } catch (e) {
    return String(e);
  }
})();
check("a copy's links: rewritten, a title kept", out.includes("[the pooler](/to/operations.md#behind-a-pooler), " +
  '[a title](/to/a.md "its title") and [brackets](/to/b c.md).') && out.includes("![the mark](/to/mark.svg)"), out);
check("... what is code or HTML kept as it is", ["`[x](not-a-link.md)`", "``a ` [y](tick.md)``", "SELECT '[x](in-a-fence.md)';",
  "    [x](indented.md)", "<div>[x](in-html.md)</div>", "<https://example.com>"].every((s) => out.includes(s)), out);
check("... and the rest of the file too", out.split("\n").length === text.split("\n").length && out.startsWith("# A page\n"), out);
for (const [label, body, said] of [
  ["a reference", "See [the pooler][p].\n\n[p]: operations.md\n", "a link the Markdown copy can't rewrite, to operations.md"],
  ["parentheses in an address", "See [x](a_(b).md).\n", "a link the Markdown copy can't rewrite, to a_(b).md"],
  ["what reads as a link but isn't one", "Brackets written as such: \\[x\\](y.md)\n", "](y.md) reads as a link here but isn't one"],
]) {
  const got = refused(() => rewrite(body));
  check(`refused in a copy: ${label}`, got.startsWith("docs/x.md: ") && got.includes(said), got || "it was rewritten");
}

// the menus against the pages: every page is in one, every link of one goes to a page
const everyPage = Object.values(PAGES).filter((a) => a !== "index.md" && !a.startsWith("problems/")).map(url);
const menus = [{ text: "Guide", link: "/getting-started" }, { text: "Play", link: "/playground/" },
  { text: "All", items: everyPage.map((link) => ({ text: link, link })) }, { text: "Out", link: "https://example.com" }];
check("menus: their links, items inside items", same(menuLinks([menus, [{ items: [{ items: [{ link: "/x" }] }] }]]).slice(-1), ["/x"]));
check("menus that list every page pass", refused(() => checkMenus(menuLinks(menus))) === "");
const without = menuLinks(menus).filter((l) => l !== "/signed-urls" && l !== "/stacks/");
check("refused: pages no menu lists", refused(() => checkMenus(without)) ===
  "site/.vitepress/config.mts: no menu lists /signed-urls, /stacks/: add each to the sidebar", refused(() => checkMenus(without)));
check("refused: a menu's link to no page", refused(() => checkMenus([...menuLinks(menus), "/reference/nothing"])) ===
  "site/.vitepress/config.mts: a menu links to /reference/nothing, which is no page");

// a page's title says what rowstile is after its own words, once; the home page says it in one title
check("title: the home page's, alone", same(pageTitle("index.md", "rowstile"),
  { title: "rowstile: authorization for Postgres, compiled into row-level security", template: false }));
check("title: a page's, then what rowstile is", same(pageTitle("getting-started.md", "Getting started"),
  { title: "Getting started", template: ":title | rowstile, authorization for Postgres" }));
check("title: a page that names rowstile doesn't name it twice", pageTitle("compare/spicedb.md", "rowstile and SpiceDB").template
  === ":title | authorization for Postgres");
check("title: a recipe's says row-level security", pageTitle("cookbook/tenants.md", "Multi-tenant").template
  === ":title | Postgres row-level security, rowstile");
// the sitemap leaves out an error code's page, and only that
check("sitemap: an error code's page left out", !inSitemap("/errors/AZ201"));
check("sitemap: the errors' index, a recipe, the home page listed", inSitemap("/errors/") && inSitemap("/cookbook/tenants")
  && inSitemap("/"));
// what a page says of itself as JSON-LD: the software on the home page, an article on a post, nothing elsewhere
const home = /** @type {Record<string, unknown>} */ (structured("index.md", "d"));
check("JSON-LD: the home page is the software", home["@type"] === "SoftwareApplication" && home.description === "d"
  && home.url === "https://rowstile.dev/", home);
check("JSON-LD: nothing for a page that is neither", structured("getting-started.md", "d") === null);
const post = POSTS[0];
if (post) {
  const article = /** @type {Record<string, unknown>} */ (structured(post.address, "d"));
  check("JSON-LD: a post is an article, with its date and author", article["@type"] === "BlogPosting"
    && article.datePublished === post.date && same(article.author, { "@type": "Person", name: post.author }), article);
}
// IndexNow: the sitemap's addresses, on the site's host only, and the key's file at the root
const sent = payload("<urlset><url><loc>https://rowstile.dev/</loc></url><url><loc>https://rowstile.dev/reference</loc></url></urlset>");
check("IndexNow: the sitemap's addresses", same(sent, { host: "rowstile.dev", key: KEY,
  keyLocation: `https://rowstile.dev/${KEY_FILE}`, urlList: ["https://rowstile.dev/", "https://rowstile.dev/reference"] }), JSON.stringify(sent));
check("IndexNow: refused, an address elsewhere", refused(() => payload("<loc>https://rowstile.dev.evil/x</loc>")) ===
  "the sitemap lists addresses elsewhere: https://rowstile.dev.evil/x");
check("IndexNow: refused, an empty sitemap", refused(() => payload("<urlset></urlset>")) === "the sitemap lists no address");
check("IndexNow: the key is what it accepts (8 to 128 of a-z, A-Z, 0-9, -)", /^[a-zA-Z0-9-]{8,128}$/.test(KEY));

// site.yml gives the build the tag it is built from (else its links go to main), and builds only what deploys
const workflow = readFileSync(join(REPO, ".github", "workflows", "site.yml"), "utf8");
check("site.yml builds with the tag it deploys", /- if: steps\.from\.outputs\.deploy == 'true'\n\s+env:\n\s+SITE_CODE: \$\{\{ env\.GIVEN \}\}\n\s+run: [^\n]*node build\.mjs/.test(workflow));

check("site.yml sends IndexNow after the deploy, never failing it",
  /\n  indexnow:\n    needs: deploy\n[\s\S]*- run: node site\/indexnow\.mjs\n\s+continue-on-error: true\n/.test(workflow));

console.log(failed ? `pages: ${failed} failed` : "pages: all passed");
process.exit(failed ? 1 : 0);
