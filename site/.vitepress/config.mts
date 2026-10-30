// The docs site. The pages are the repository's Markdown, where it is (pages.mjs says which, and where each goes).
import { join, relative } from "node:path";
import type { Plugin } from "vite";
import { defineConfig } from "vitepress";
import { FEED, FEED_TITLE, LANGUAGES } from "../blog.mjs";
import { GITHUB, ORIGIN, PAGES, POSTS, REPO, TITLES, blogSidebar, checkMenus, compareSidebar, describe, errorSidebar, inSitemap, menuLinks, notPages, pageTitle, recipeSidebar, siteLink, slug, structured, url } from "../pages.mjs";

// The pages are outside site/, and so is Vite's root (the repository), where there is no Vue: the pages' imports of
// it are resolved from here, and the server bundle leaves Vue out (it imports it at run time, from site/.vitepress)
const SITE = join(REPO, "site");
const vueFromSite: Plugin = {
  name: "rowstile:vue-from-site",
  enforce: "pre",
  async resolveId(id, importer, options) {
    if (!/^(vue|@vue\/[^/]+)(\/|$)/.test(id) || !importer) return null;
    if (options?.ssr) return { id, external: true };
    if (importer.replaceAll("\\", "/").startsWith(SITE.replaceAll("\\", "/") + "/")) return null;
    return this.resolve(id, join(SITE, "index.md"), { ...options, skipSelf: true });
  },
};

const guide = [
  { text: "Installing", link: "/installing" },
  { text: "Getting started", link: "/getting-started" },
  { text: "Troubleshooting", link: "/troubleshooting" },
  { text: "Running rowstile", link: "/operations" },
  { text: "Managed Postgres: Neon, Supabase", link: "/managed-postgres" },
  { text: "Files in S3-compatible storage", link: "/signed-urls" },
  { text: "How rowstile is checked", link: "/how-it-is-checked" },
  { text: "Threat model", link: "/threat-model" },
  { text: "Reporting a vulnerability", link: "/security" },
  { text: "Changelog", link: "/changelog" },
];
const compare = [{ text: "rowstile and the alternatives", link: "/comparison" }, ...compareSidebar()];
const stacks = [
  { text: "Pick yours", link: "/stacks/" },
  { text: "FastAPI, SQLAlchemy, Alembic", link: "/stacks/fastapi" },
  { text: "Next.js, Prisma", link: "/stacks/nextjs" },
  { text: "Node: pg, postgres.js, Drizzle", link: "/stacks/node" },
  { text: "Python", link: "/stacks/python" },
  { text: "Go (preview)", link: "/stacks/go" },
  { text: "Django (preview)", link: "/stacks/django" },
  { text: "ASP.NET Core, EF Core (preview)", link: "/stacks/aspnetcore" },
  { text: "Rails (preview)", link: "/stacks/rails" },
  { text: "Spring Boot, JPA, Flyway (preview)", link: "/stacks/spring" },
  { text: "Kotlin: Ktor, Exposed (preview)", link: "/stacks/ktor" },
  { text: "Rust: Axum, sqlx (preview)", link: "/stacks/axum" },
  { text: "Phoenix, Ecto (preview)", link: "/stacks/phoenix" },
  { text: "Any other stack: SQL", link: "/stacks/sql" },
];
const sdks = [
  { text: "Python SDK", link: "/sdk/python" },
  { text: "TypeScript SDK", link: "/sdk/typescript" },
  { text: "Ruby SDK (preview)", link: "/sdk/ruby" },
  { text: "Java SDK (preview)", link: "/sdk/java" },
  { text: "Kotlin SDK (preview)", link: "/sdk/kotlin" },
  { text: "Rust SDK (preview)", link: "/sdk/rust" },
  { text: "Elixir SDK (preview)", link: "/sdk/elixir" },
  { text: "Conformance suites", link: "/sdk/conformance" },
];
const reference = [
  { text: "The policy language", link: "/reference/language" },
  { text: "Using it from app code", link: "/reference/app-code" },
  { text: "Identity", link: "/reference/identity" },
  { text: "Governance", link: "/reference/governance" },
  { text: "Tools", link: "/reference/tools" },
  { text: "Migrations", link: "/reference/migrations" },
  { text: "Reviewing a change", link: "/reference/review" },
  { text: "How it works", link: "/reference/guarantees" },
  { text: "Speed and limits", link: "/reference/limits" },
  { text: "Error codes", link: "/errors/" },
  { text: "Words", link: "/words" },
  { text: "Editor", link: "/editor" },
  { text: "Scale benchmark", link: "/benchmark" },
  { text: "Working on rowstile", link: "/development" },
];
const examples = [
  { text: "Examples", link: "/examples/" },
  { text: "File manager", link: "/examples/filemanager" },
  { text: "Messenger", link: "/examples/messenger" },
];

const nav = [
  { text: "Guide", link: "/getting-started" },
  { text: "Reference", link: "/reference/language" },
  { text: "Stacks", link: "/stacks/" },
  { text: "Errors", link: "/errors/" },
  ...(POSTS.length ? [{ text: "Blog", link: "/blog/" }] : []),
  { text: "Playground", link: "/playground/", target: "_self" },
];
const sidebar = {
  "/errors/": [{ text: "Error codes", link: "/errors/" }, ...errorSidebar()],
  "/": [
    { text: "Guide", items: guide },
    { text: "Recipes", items: [{ text: "Cookbook", link: "/cookbook/" }, ...recipeSidebar()] },
    { text: "Compare", items: compare },
    { text: "Stacks", items: stacks },
    { text: "SDKs", items: sdks },
    { text: "Reference", items: reference },
    { text: "Examples", items: examples },
    ...(POSTS.length ? [{ text: "Blog", items: [{ text: "All posts", link: "/blog/" }, ...blogSidebar()] }] : []),
  ],
};
// every page is in a menu, and every menu's link goes to a page (pages.mjs)
checkMenus(menuLinks([nav, Object.values(sidebar)]));

export default defineConfig({
  title: "rowstile",
  description: "Authorization for Postgres apps: access rules in a policy file, compiled into row-level security",
  srcDir: "..",
  srcExclude: notPages(),
  rewrites: PAGES,
  outDir: "./dist",
  cacheDir: "./.vitepress/cache",
  cleanUrls: true,
  // the pages a search should find first (pages.mjs: inSitemap); each item's url is the page's, without the first /
  sitemap: {
    hostname: ORIGIN,
    transformItems: (items) => items.filter((item) => inSitemap(`/${item.url.replace(/^\//, "")}`)),
  },
  // the mark (site/assets/mark.svg, which build.mjs puts at the site's root): the tab's icon and the navigation's
  head: [
    ["link", { rel: "icon", type: "image/svg+xml", href: "/mark.svg" }],
    // the blog's feed, once there is a post: what a feed reader finds from any page
    ...(POSTS.length
      ? [["link", { rel: "alternate", type: "application/atom+xml", title: FEED_TITLE, href: "/" + FEED }] as [string, Record<string, string>]]
      : []),
  ],
  vite: { plugins: [vueFromSite] },
  markdown: {
    languages: LANGUAGES,
    // headings' anchors as GitHub makes them: the links are written for GitHub
    anchor: { slugify: slug },
    config(md) {
      // indented code blocks (the docs use them for commands) get the fenced blocks' box, which scrolls
      md.core.ruler.push("indented_as_fenced", (state) => {
        for (const t of state.tokens) if (t.type === "code_block") Object.assign(t, { type: "fence", info: "", markup: "```" });
      });
      // before VitePress's own link handling: links are relative to the source file, not the page's address
      const linkOpen = md.renderer.rules.link_open!;
      md.renderer.rules.link_open = (tokens, idx, options, env, self) => {
        const href = tokens[idx].attrGet("href");
        const source = relative(REPO, env.realPath ?? env.path).replaceAll("\\", "/");
        if (href) tokens[idx].attrSet("href", siteLink(source, href));
        return linkOpen(tokens, idx, options, env, self);
      };
    },
  },
  transformPageData(page) {
    const named = pageTitle(page.relativePath, TITLES[page.relativePath] ?? page.title);
    page.title = named.title;
    page.titleTemplate = named.template;
    // each page's own sentence, for search results and shared links (pages.mjs: a page without one fails the build)
    if (!page.isNotFound) page.description = describe(page.relativePath, page.title);
  },
  // one address per page, said to search engines, and what a shared link shows
  transformHead({ pageData, title, description }) {
    if (pageData.isNotFound) return [];
    const href = ORIGIN + url(pageData.relativePath);
    const about = structured(pageData.relativePath, description);
    return [
      ["link", { rel: "canonical", href }],
      // the page's Markdown, which build.mjs writes beside it: what an agent reads in place of the HTML
      ["link", { rel: "alternate", type: "text/markdown", href: `${ORIGIN}/${pageData.relativePath}` }],
      ["meta", { property: "og:type", content: "website" }],
      ["meta", { property: "og:site_name", content: "rowstile" }],
      ["meta", { property: "og:title", content: title }],
      ["meta", { property: "og:description", content: description }],
      ["meta", { property: "og:url", content: href }],
      // the card (site/assets/card.png): one image for every page
      ["meta", { property: "og:image", content: `${ORIGIN}/card.png` }],
      ["meta", { property: "og:image:width", content: "1200" }],
      ["meta", { property: "og:image:height", content: "630" }],
      ["meta", { name: "twitter:card", content: "summary_large_image" }],
      // what the page is, for search engines (pages.mjs); "<" escaped, so no text in it can end the script
      ...(about ? [["script", { type: "application/ld+json" }, JSON.stringify(about).replaceAll("<", "\\u003c")] as [string, Record<string, string>, string]] : []),
    ];
  },
  themeConfig: {
    logo: "/mark.svg",
    nav,
    sidebar,
    outline: [2, 3],
    search: { provider: "local" },
    socialLinks: [{ icon: "github", link: GITHUB }],
  },
});
