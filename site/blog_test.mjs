// The blog without a post to try it on: what a post's file must be (readPost), and the feed made from two
// made-up posts (well-formed XML, the fields a reader needs, newest first); and the comparison pages, listed
// from their folder.   node site/blog_test.mjs
import { feed, forFeed, postBody } from "./blog.mjs";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { DESCRIPTIONS, PAGES, REPO, compareSidebar, describe, readPost, readPosts } from "./pages.mjs";

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

const text = [
  "# What a closure table costs",
  "",
  "*Ada Example, 2026-10-23*",
  "",
  "Folders inside folders, read through [row-level security](../reference/guarantees.md): a `WITH RECURSIVE`",
  "per row is slow, so *rowstile* keeps a table.",
  "",
  "## The table",
  "",
  "More.",
  "",
].join("\n");

const post = readPost("2026-10-23-what-a-closure-table-costs.md", text);
check("a post: its address has no date", post.address === "blog/what-a-closure-table-costs.md", post.address);
check("... its title, author and date", post.title === "What a closure table costs" && post.author === "Ada Example" && post.date === "2026-10-23", JSON.stringify(post));
check(
  "... its summary is the first paragraph, as plain text",
  post.summary === "Folders inside folders, read through row-level security: a WITH RECURSIVE per row is slow, so rowstile keeps a table.",
  post.summary,
);
check("... with Windows line ends too", readPost(post.file, text.replace(/\n/g, "\r\n")).summary === post.summary);

for (const [label, file, body, said] of [
  ["a name without a date", "closure.md", text, "is named <date>-<slug>.md"],
  ["a date that isn't one", "2026-02-30-closure.md", text, "is not a date"],
  ["no title", post.file, text.replace("# What", "What"), "its first line is its title"],
  ["no byline", post.file, text.replace("*Ada Example, 2026-10-23*\n\n", ""), "the author and the date"],
  ["a byline with another date", post.file, text.replace("2026-10-23*", "2026-10-24*"), "its byline says 2026-10-24"],
  ["a heading where the summary goes", post.file, text.replace(/Folders[^]*?table\.\n\n/, ""), "a first paragraph"],
]) {
  const got = refused(() => readPost(file, body));
  check(`refused: ${label}`, got.includes(said), got || "it was read");
}

// the posts: two with one slug, or one the index doesn't list, fail the build; with none, the index isn't read
const other = text.replace("# What a closure table costs", "# Another");
check("posts, newest first, each listed in the index", JSON.stringify(readPosts({ "2026-10-09-a.md": other.replaceAll("2026-10-23", "2026-10-09"),
  [post.file]: text }, () => `- [x](${post.file})\n- [y](2026-10-09-a.md)\n`).map((p) => p.slug)) === JSON.stringify([post.slug, "a"]));
check("refused: two posts with one slug", refused(() => readPosts({ [post.file]: text, "2026-10-24-what-a-closure-table-costs.md":
  text.replaceAll("2026-10-23", "2026-10-24") }, () => "")) === "docs/blog: two posts are named what-a-closure-table-costs");
check("refused: a post the index doesn't list", refused(() => readPosts({ [post.file]: text }, () => "- [x](2026-10-23-other.md)\n")) ===
  `docs/blog/README.md doesn't list ${post.file}`);
check("no post: no blog, its index unread", readPosts({}, () => { throw new Error("read"); }).length === 0);

check("the body a feed carries has no title and no byline", postBody(text).startsWith("Folders inside folders") && postBody(text).includes("## The table"), postBody(text));
const page = '<h2 id="t" tabindex="-1">The table <a class="header-anchor" href="#t" aria-label="Permalink">&ZeroWidthSpace;</a></h2>' +
  '<div class="language-sql vp-adaptive-theme"><button title="Copy Code" class="copy"></button><span class="lang">sql</span>' +
  '<pre class="shiki vp-code" tabindex="0" v-pre=""><code><span class="line"><span style="--shiki-light:#D73A49">SELECT</span>' +
  '<span style="--shiki-light:#005CC5"> 1</span></span></code></pre></div><p>See <a href="https://rowstile.dev/x" target="_blank">x</a>.</p>';
check(
  "... nor the page's own controls and the highlighter's spans: code is <pre><code>, links stay",
  forFeed(page) === '<h2 id="t">The table</h2><div><pre><code>SELECT 1</code></pre></div><p>See <a href="https://rowstile.dev/x" target="_blank">x</a>.</p>',
  forFeed(page),
);

const older = readPost("2026-10-09-first.md", "# A & B < C\n\n*Ada Example, 2026-10-09*\n\nOne \"quoted\" line.\n");
const xml = feed([post, older], (p) => `<p>${p.slug} &amp; more</p>`);

/** Whether text is well-formed XML as this feed writes it: tags balanced, no bare & or < in text. @param {string} doc */
function wellFormed(doc) {
  const body = doc.replace(/^<\?xml[^>]*\?>\s*/, "");
  /** @type {string[]} */
  const open = [];
  let rest = body;
  while (rest.length) {
    const lt = rest.indexOf("<");
    const chunk = lt < 0 ? rest : rest.slice(0, lt);
    if (/&(?!(amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)/.test(chunk)) return `a bare & in ${JSON.stringify(chunk.slice(0, 60))}`;
    if (lt < 0) break;
    const tag = rest.slice(lt).match(/^<(\/?)([A-Za-z][\w:.-]*)((?:\s+[\w:.-]+="[^"<]*")*)\s*(\/?)>/);
    if (!tag) return `not a tag: ${JSON.stringify(rest.slice(lt, lt + 60))}`;
    if (tag[1]) {
      if (open.pop() !== tag[2]) return `</${tag[2]}> closes nothing`;
    } else if (!tag[4]) open.push(tag[2]);
    rest = rest.slice(lt + tag[0].length);
  }
  return open.length ? `<${open.at(-1)}> is never closed` : "";
}

check("the feed is well-formed XML", wellFormed(xml) === "", wellFormed(xml));
check("... the check itself refuses what isn't", wellFormed("<a><b></a>") !== "" && wellFormed("<a>x & y</a>") !== "" && wellFormed("<a>") !== "");
check("... an Atom feed that names itself", xml.includes('<feed xmlns="http://www.w3.org/2005/Atom">') &&
  xml.includes('<link rel="self" type="application/atom+xml" href="https://rowstile.dev/blog/feed.xml"/>'), xml);
check("... updated when its newest post was", xml.includes("  <updated>2026-10-23T00:00:00Z</updated>\n  <entry>"), xml);
const entries = [...xml.matchAll(/<entry>[^]*?<\/entry>/g)].map((m) => m[0]);
check("... an entry per post, newest first", entries.length === 2 && entries[0].includes("What a closure table costs"), entries.length);
check(
  "... each with its address as its id, its date and its author",
  entries[0].includes("<id>https://rowstile.dev/blog/what-a-closure-table-costs</id>") &&
    entries[0].includes('<link rel="alternate" type="text/html" href="https://rowstile.dev/blog/what-a-closure-table-costs"/>') &&
    entries[0].includes("<published>2026-10-23T00:00:00Z</published>") &&
    entries[0].includes("<author><name>Ada Example</name></author>"),
  entries[0],
);
check("... the post whole, as escaped HTML", entries[0].includes('<content type="html">&lt;p&gt;what-a-closure-table-costs &amp;amp; more&lt;/p&gt;</content>'), entries[0]);
check("... a title's and a summary's own characters escaped", entries[1].includes("<title>A &amp; B &lt; C</title>") &&
  entries[1].includes("<summary>One &quot;quoted&quot; line.</summary>"), entries[1]);

// the comparison pages are listed from their folder too: a new one needs nothing here or in pages.mjs
const compared = Object.keys(PAGES).filter((f) => f.startsWith("docs/compare/"));
const beside = compareSidebar();
check("a comparison page per file of docs/compare/, each in the sidebar", compared.length === beside.length &&
  compared.every((f, i) => PAGES[f] === `${beside[i].link.slice(1)}.md`), JSON.stringify(beside));
check("... named for what it is compared with", beside.every((b) => b.text && !b.text.startsWith("rowstile") &&
  b.text[0] === b.text[0].toUpperCase()), JSON.stringify(beside));
for (const f of compared.slice(0, 1)) {
  const said = DESCRIPTIONS[PAGES[f]];
  delete DESCRIPTIONS[PAGES[f]];
  const why = refused(() => describe(PAGES[f], ""));
  const made = why ? "" : describe(PAGES[f], "");
  // the page's first paragraph, as plain text: what describe() keeps of it is its first sentences, or its start
  const first = readFileSync(join(REPO, f), "utf8").split(/\n{2,}/)[1].replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
    .replace(/[`*_]/g, "").replace(/\s+/g, " ").trim();
  check("... one without a sentence of its own is described by its first paragraph", !why && made.length > 40 &&
    made.length <= 200 && !/[`*\[\]]/.test(made) && made !== said && first.startsWith(made.replace(/\.\.\.$/, "")), why || made);
  if (said) DESCRIPTIONS[PAGES[f]] = said;
}

console.log(failed ? `blog: ${failed} failed` : "blog: all passed");
process.exit(failed ? 1 : 0);
