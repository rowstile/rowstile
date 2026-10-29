// Builds the docs site into site/dist/: the pages (VitePress), the playground at /playground/, each page's
// Markdown beside it (/getting-started.md, its links pointing to the others'), llms.txt with its links pointing
// there, llms-full.txt, IndexNow's key (indexnow.mjs), and the blog's feed (/blog/feed.xml) once there is a post.
// Any static host serves dist/. A link to a file, a page or a heading that isn't there fails it (pages.mjs). Plain JavaScript, typed with JSDoc and checked
// strictly (site/tsconfig.json). Its links to files on GitHub go to SITE_CODE's tag (site.yml), else to main.
//   cd site && npm ci && node build.mjs          (PYTHON=... if python3 isn't the one)
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build, createMarkdownRenderer } from "vitepress";
import { FEED, LANGUAGES, feed, forFeed, postBody } from "./blog.mjs";
import { KEY, KEY_FILE } from "./indexnow.mjs";
import { ORIGIN, PAGES, POSTS, REPO, deadAnchors, rewriteLinks, siteLink, url } from "./pages.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const DIST = join(HERE, "dist");

/** @param {string} cmd @param {string[]} args */
function run(cmd, ...args) {
  const r = spawnSync(cmd, args, { cwd: REPO, stdio: "inherit" });
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(" ")} failed`);
}

/** A file's Markdown links, for readers of the Markdown itself: a page's .md copy, or GitHub.
 *  @param {string} source @param {string} text */
function markdownLinks(source, text) {
  return rewriteLinks(parse(source), source, text, (href) => {
    const link = siteLink(source, href);
    const cut = link.indexOf("#");
    const path = cut < 0 ? link : link.slice(0, cut);
    if (!path.startsWith("/")) return link;
    const page = path.endsWith("/") ? `${path}index.md` : `${path}.md`;
    return `${page}${cut < 0 ? "" : link.slice(cut)}`;
  });
}

/** A file's text once it is whole. VitePress ends its sitemap's stream without waiting for it, so the file is
 *  finished a moment after build() returns.
 *  @param {string} file @param {string} end */
async function written(file, end) {
  for (let tries = 0; tries < 100; tries++) {
    if (existsSync(file)) {
      const text = readFileSync(file, "utf8");
      if (text.includes(end)) return text;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`${file} wasn't written`);
}

await build(HERE);

// the build's own Markdown renderer, with the config's rules (VitePress keeps the one it made, so this comes after
// the build): what reads a file's links (rewriteLinks), and renders the posts for the feed
const md = await createMarkdownRenderer(REPO, { languages: LANGUAGES });
/** @param {string} source @returns {(text: string) => import("./pages.mjs").Token[]} */
const parse = (source) => (text) => md.parse(text, { path: join(REPO, source), relativePath: source });

// for search engines: the sitemap VitePress wrote must hold every page, and robots.txt names it (the site's source
// folder is the repository's root, so there is no public/ folder to put the file in)
const sitemap = await written(join(DIST, "sitemap.xml"), "</urlset>");
const unlisted = Object.values(PAGES).map((address) => ORIGIN + url(address)).filter((u) => !sitemap.includes(`<loc>${u}</loc>`));
if (unlisted.length) throw new Error(`sitemap.xml doesn't list ${unlisted.join(", ")}`);
// the mark and the card for shared links, at the site's root (no public/ folder: see above)
for (const f of ["mark.svg", "card.png"]) cpSync(join(HERE, "assets", f), join(DIST, f));
writeFileSync(join(DIST, "robots.txt"), `User-agent: *\nAllow: /\n\nSitemap: ${ORIGIN}/sitemap.xml\n`);
// IndexNow's key, at the root: what says the site's own deploy sent the addresses (indexnow.mjs, site.yml)
writeFileSync(join(DIST, KEY_FILE), KEY);

// the blog's feed: each post whole, as HTML, its links to the site's pages by their full address
if (POSTS.length) {
  /** @type {Map<string, string>} */
  const html = new Map();
  for (const post of POSTS) {
    const body = rewriteLinks(parse(post.source), post.source, postBody(readFileSync(join(REPO, post.source), "utf8")), (href) => {
      const link = siteLink(post.source, href);
      return link.startsWith("/") ? ORIGIN + link : link;
    });
    // the renderer is the build's own, with the config's rules: they ask which file the text is from
    html.set(post.slug, forFeed(md.render(body, { path: join(REPO, post.source) })));
  }
  mkdirSync(dirname(join(DIST, FEED)), { recursive: true });
  writeFileSync(join(DIST, FEED), feed(POSTS, (post) => html.get(post.slug) ?? ""));
}

run(process.execPath, "playground/build.mjs");
cpSync(join(REPO, "playground", "dist"), join(DIST, "playground"), { recursive: true });

for (const [source, address] of Object.entries(PAGES)) {
  mkdirSync(dirname(join(DIST, address)), { recursive: true });
  writeFileSync(join(DIST, address), markdownLinks(source, readFileSync(join(REPO, source), "utf8")));
}
const llms = markdownLinks("llms.txt", readFileSync(join(REPO, "llms.txt"), "utf8"));
writeFileSync(join(DIST, "llms.txt"), llms);

// a link to a heading must find it: each page's links, and llms.txt's (to the pages' .md copies), against the ids of
// the pages VitePress wrote
const built = new Map(Object.entries(PAGES).map(([source, a]) =>
  [url(a), { source, html: readFileSync(join(DIST, a.replace(/\.md$/, ".html")), "utf8") }]));
const fromLlms = [...llms.matchAll(/\]\((\/[^)\s]*)\)/g)].map((m) => ({
  from: "llms.txt",
  href: m[1].replace(/(^|\/)index\.md(?=#|$)/, "$1").replace(/\.md(?=#|$)/, ""),
}));
const dead = deadAnchors(built, fromLlms);
if (dead.length) throw new Error(`links to a heading that isn't there:\n  ${dead.join("\n  ")}`);

run(process.env.PYTHON || "python3", "docs/llms_full.py", join(DIST, "llms-full.txt"));
console.log(`wrote ${DIST}`);
