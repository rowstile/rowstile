// The site's links without building it (pages.mjs): where a link to a file on GitHub goes when the site is built from
// a tag, a heading's anchor, the links to a heading that isn't there, the Markdown copies' links, and the menus
// against the pages.   node site/pages_test.mjs
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { createMarkdownRenderer } from "vitepress";

// what site.yml gives the build when a blog tag publishes onto a site tag (read when pages.mjs is imported)
process.env.SITE_CODE = "site-v4";
process.env.SITE_CONTENT = "blog-v2";
const { DESCRIPTIONS, NOTE, PAGES, POSTS, REPO, checkCopy, checkDescriptions, checkMenus, checkSitemap, deadAnchors, describe,
  inSitemap, menuLinks, pageTitle, rewriteLinks, siteLink, slug, structured, url, withoutNotes } = await import("./pages.mjs");
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

// a link to a file on GitHub: the tag the site is built from, or the blog tag for its two folders
const GH = "https://github.com/rowstile/rowstile";
for (const [label, source, href, want] of [
  ["a recipe's folder", "docs/cookbook/tenants.md", "tenants/", `${GH}/tree/site-v4/docs/cookbook/tenants`],
  ["a file, its anchor kept", "docs/troubleshooting.md", "../core/tests/unit_test.py#L1", `${GH}/blob/site-v4/core/tests/unit_test.py#L1`],
  ["a workflow", "docs/how-it-is-checked.md", "../.github/workflows/nightly.yml", `${GH}/blob/site-v4/.github/workflows/nightly.yml`],
  ["a post's run: the blog tag's", "docs/blog/README.md", "recursive-row-level-security", `${GH}/tree/blog-v2/docs/blog/recursive-row-level-security`],
  ["a page stays a page", "docs/troubleshooting.md", "operations.md#behind-a-pooler", "/operations#behind-a-pooler"],
]) {
  const got = siteLink(source, href);
  check(`a link at a tag: ${label}`, got === want, got);
}
// a link to what isn't in the repository fails the build, and so does one out of it
for (const [label, href, said] of [
  ["a file that isn't there", "nowhere.md", "docs/x.md: the link nowhere.md points to docs/nowhere.md, which isn't in the repository"],
  ["a folder that isn't there", "../core/nowhere/#top", "docs/x.md: the link ../core/nowhere/#top points to core/nowhere, which isn't in the repository"],
  ["out of the repository", "../../etc/passwd", "docs/x.md: the link ../../etc/passwd points to ../etc/passwd, which isn't in the repository"],
  ["from its root, a file that isn't there", "/etc/passwd", "docs/x.md: the link /etc/passwd points to etc/passwd, which isn't in the repository"],
]) {
  check(`refused, a link: ${label}`, refused(() => siteLink("docs/x.md", href)) === said, refused(() => siteLink("docs/x.md", href)));
}

// an image: the file itself (raw), not GitHub's page about it
const RAW = "https://raw.githubusercontent.com/rowstile/rowstile";
check("an image at a tag: the file itself", siteLink("examples/messenger/README.md", "docs/group.png", true) ===
  `${RAW}/site-v4/examples/messenger/docs/group.png`, siteLink("examples/messenger/README.md", "docs/group.png", true));
check("... a link to it stays GitHub's page", siteLink("examples/messenger/README.md", "docs/group.png") ===
  `${GH}/blob/site-v4/examples/messenger/docs/group.png`);
check("... an image elsewhere stays where it is", siteLink("README.md", "https://api.scorecard.dev/b", true) === "https://api.scorecard.dev/b");

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
const rewrite = (text) => rewriteLinks(parse, "docs/x.md", text, (href, image) => `/to/${image ? "image:" : ""}${href}`);
const text = [
  "# A page",
  "",
  "See [the pooler](operations.md#behind-a-pooler), [a title](a.md \"its title\") and [brackets](<b c.md>).",
  "![the mark](mark.svg) and <https://example.com> and https://example.org stay.",
  "A badge: [![its [words]](badge.svg)](https://example.com/b), and \\![a link](not-an-image.md).",
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
  '[a title](/to/a.md "its title") and [brackets](/to/b c.md).') && out.includes("![the mark](/to/image:mark.svg)") &&
  out.includes("A badge: [![its [words]](/to/image:badge.svg)](/to/https://example.com/b), and \\![a link](/to/not-an-image.md)."), out);
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

// the copies leave out the notes for the repository's checks: after a sentence, and a line of their own
const noted = [
  "<!-- tested: every line of code below is in integrations/x -->",
  "",
  "A promise. <!-- checked: tests/x.sh \"its label\"; tests/y.py \"another\" --> The next one. <!-- unchecked: why -->",
  "Its markers stay: `<!-- rowstile:begin -->`, and <!-- llms-full's own -->.",
  "<!-- not run: it needs a server -->",
  "```sh",
  "rowstile check",
  "```",
].join("\n");
check("a copy without its notes: after a sentence, and a line of their own", withoutNotes(noted) === [
  "",
  "A promise. The next one.",
  "Its markers stay: `<!-- rowstile:begin -->`, and <!-- llms-full's own -->.",
  "```sh",
  "rowstile check",
  "```",
].join("\n"), withoutNotes(noted));
const notes = Object.keys(PAGES).flatMap((source) => withoutNotes(readFileSync(join(REPO, source), "utf8")).split("\n")
  .filter((line) => NOTE.test(line)).map((line) => `${source}: ${line}`));
check("... and no page's copy keeps one", notes.length === 0, notes.join("\n"));

// every stack's page and every SDK's README is a page (each TypeScript and .NET package's own README isn't: the
// SDK's says what each holds)
const shouldBe = [
  ...readdirSync(join(REPO, "docs", "stacks")).filter((f) => f.endsWith(".md")).map((f) => `docs/stacks/${f}`),
  ...readdirSync(join(REPO, "sdk")).filter((d) => existsSync(join(REPO, "sdk", d, "README.md"))).map((d) => `sdk/${d}/README.md`),
  "sdk/java/rowstile-kotlin/README.md",
];
check("every stack's page and every SDK's README is a page", shouldBe.every((f) => f in PAGES), shouldBe.filter((f) => !(f in PAGES)));

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

// a sentence for every page, and only for pages
check("descriptions: one for each page passes", refused(() => checkDescriptions(DESCRIPTIONS, PAGES)) === "");
check("refused: a description of what isn't a page", refused(() => checkDescriptions({ ...DESCRIPTIONS, "gone.md": "x", "old/a.md": "y" }, PAGES)) ===
  "site/pages.mjs: DESCRIPTIONS names what isn't a page: gone.md, old/a.md");
check("refused: a page with no description", refused(() => describe("operations-new.md", "x")) ===
  "operations-new.md: no description in site/pages.mjs (DESCRIPTIONS)");
check("... an error page's and a recipe's are made from their titles", describe("errors/AZ999.md", "AZ999: x").startsWith("AZ999: x: ") &&
  describe("cookbook/new.md", "New").startsWith("New: a tested recipe"));

// the sitemap VitePress wrote: every page but an error code's, and none of those
/** @param {string[]} paths */
const sitemapOf = (paths) => `<urlset>${paths.map((p) => `<url><loc>https://rowstile.dev${p}</loc></url>`).join("")}</urlset>`;
const somePages = ["/", "/operations", "/errors/", "/errors/AZ201", "/errors/AZ202"];
check("sitemap: every page but the error codes' passes", refused(() => checkSitemap(sitemapOf(["/", "/operations", "/errors/"]), somePages)) === "");
check("... and the site's own pages", refused(() => checkSitemap(sitemapOf(Object.values(PAGES).map(url).filter(inSitemap)))) === "");
check("refused: a sitemap without a page", refused(() => checkSitemap(sitemapOf(["/", "/errors/"]), somePages)) ===
  "sitemap.xml doesn't list /operations");
check("refused: a sitemap with an error code's page", refused(() => checkSitemap(sitemapOf(["/", "/operations", "/errors/", "/errors/AZ202"]),
  somePages)) === "sitemap.xml lists what it leaves out: /errors/AZ202");
check("refused: no page left out", refused(() => checkSitemap(sitemapOf(["/", "/operations"]), ["/", "/operations"])) ===
  "inSitemap leaves out no page: the error codes' are");

// a copy keeps no note: one written so that withoutNotes can't take it out fails the build
check("a copy without notes passes", refused(() => checkCopy("docs/x.md", withoutNotes(noted))) === "");
check("refused: a copy that keeps a note", refused(() => checkCopy("docs/x.md", withoutNotes('A promise. <!-- checked: tests/x.sh "a > b" -->\n'))) ===
  'docs/x.md: its Markdown copy keeps a note: A promise. <!-- checked: tests/x.sh "a > b" -->');

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

// site.yml gives the build the tags it is built from (else its links go to main), and builds only what deploys
const workflow = readFileSync(join(REPO, ".github", "workflows", "site.yml"), "utf8");
check("site.yml builds with the tags source.mjs named", /- if: steps\.from\.outputs\.deploy == 'true'\n\s+env:\n\s+SITE_CODE: \$\{\{ steps\.from\.outputs\.code \}\}\n\s+SITE_CONTENT: \$\{\{ steps\.from\.outputs\.content \}\}\n\s+SITE_PINNED: \$\{\{ steps\.from\.outputs\.pinned \}\}\n\s+run: [^\n]*node build\.mjs/.test(workflow));

check("build.mjs writes what the site shows, which the next run reads (source.mjs)",
  readFileSync(join(REPO, "site", "build.mjs"), "utf8").includes("writeFileSync(join(DIST, DEPLOYED), deployed(process.env));"));
check("site.yml says why a tag deploys nothing, or deploys the newest site in its place",
  /- if: steps\.from\.outputs\.why != ''\n\s+env:\n\s+WHY: \$\{\{ steps\.from\.outputs\.why \}\}\n\s+run: echo "::notice::\$GIVEN \(\$WHY\)"\n/.test(workflow));

check("site.yml sends IndexNow after the deploy, the sitemap it built, never failing it",
  /\n  indexnow:\n    needs: deploy\n[\s\S]*with: \{name: sitemap, path: "\$\{\{ runner\.temp \}\}\/sitemap"\}\n\s+- run: node site\/indexnow\.mjs "\$RUNNER_TEMP\/sitemap\/sitemap\.xml"\n\s+continue-on-error: true\n/.test(workflow) &&
  /- if: steps\.from\.outputs\.deploy == 'true'\n\s+uses: actions\/upload-artifact@\w+ +# v[\d.]+\n\s+with: \{name: sitemap, path: site\/dist\/sitemap\.xml, retention-days: 1\}\n/.test(workflow));

console.log(failed ? `pages: ${failed} failed` : "pages: all passed");
process.exit(failed ? 1 : 0);
