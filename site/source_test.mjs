// Which tags deploy the site, and what from (source.mjs): the rule on made-up tags, then in a repository made for the test, with
// real commits and tags.   node site/source_test.mjs
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { FOLDERS, MAIN, deploys, missing, pages, read, take } from "./source.mjs";

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

// Made-up tags. A commit is the list of what it holds: main's nth is m1..mn, and a branch adds its own after
/** @param {number} n @param {string[]} more */
const main = (n, ...more) => [...Array.from({ length: n }, (_, i) => `m${i + 1}`), ...more];
/** @param {string} given @param {Record<string, string[]>} at each tag's commit @param {boolean} [byHand] */
const decide = (given, at, byHand = false) => {
  /** @type {Record<string, string[]>} */
  const all = { ...at, [MAIN]: main(99) };
  const { deploy, why } = deploys(given, Object.keys(at), (a, b) => all[b].includes(/** @type {string} */ (all[a].at(-1))), byHand);
  return deploy ? "deploys" : why;
};
/** What a tag that deploys is built from. @param {string} given @param {Record<string, string[]>} at @param {boolean} [byHand] */
const built = (given, at, byHand = false) => {
  /** @type {Record<string, string[]>} */
  const all = { ...at, [MAIN]: main(99) };
  const { code, content } = deploys(given, Object.keys(at), (a, b) => all[b].includes(/** @type {string} */ (all[a].at(-1))), byHand);
  return `${code} + ${content || "its own"}`;
};

const first = { "v0.1.0-rc.1": ["off-main"], "v0.1.0-beta.1": main(5), "site-v1": main(8) };
check("a site tag on main, the last: deploys", decide("site-v1", first) === "deploys");
check("a release's tag on main, the last: deploys", decide("v0.1.0-beta.1", { "v0.1.0-beta.1": main(5) }) === "deploys");
check("... with no release yet, a site tag too", decide("site-v1", { "site-v1": main(2) }) === "deploys");
check("a release's tag before a site tag, pushed later: the site doesn't go back",
  decide("v0.1.0-beta.1", first) === "site-v1 on a later commit of main: the site stays at what it shows", decide("v0.1.0-beta.1", first));
check("... by hand, it does", decide("v0.1.0-beta.1", first, true) === "deploys");
const both = { ...first, "v0.1.0": main(8) };
check("a release's tag on a site tag's commit: deploys", decide("v0.1.0", both) === "deploys");
check("... and the site tag again, beside it", decide("site-v1", both) === "deploys");
const many = { ...both, "site-v2": main(11), "site-v9": main(12), "site-v10": main(13) };
check("an earlier site tag, pushed again: names every tag after it",
  decide("site-v2", many) === "site-v10, site-v9 on a later commit of main: the site stays at what it shows", decide("site-v2", many));
const patch = { ...many, "v0.0.9": main(4, "b1") };
check("a patch to an older line: no deploy, no failure",
  decide("v0.0.9", patch) === "v0.0.9 isn't on main (a patch to an older line): the site stays as it is", decide("v0.0.9", patch));
check("... by hand neither", decide("v0.0.9", patch, true).startsWith("v0.0.9 isn't on main"));
check("a tag off main doesn't hold the site back", decide("site-v10", { ...many, "v0.1.1": main(13, "b1") }) === "deploys");
check("refused: a site tag that isn't on main",
  refused(() => decide("site-v11", { ...many, "site-v11": main(13, "b1") })) === "site-v11 isn't a commit of main: a site tag publishes what was merged");
check("refused: a tag that isn't there", refused(() => decide("site-v99", many)) === "site-v99: no such tag");
check("refused: a tag of another kind", refused(() => decide("nightly", { ...many, nightly: main(30) })).includes("not a site tag"));
check("a tag of another kind doesn't hold the site back", decide("site-v10", { ...many, nightly: main(30) }) === "deploys");

// a blog tag: the articles and the comparison pages alone, on the site of the newest site or release tag
const blog = { ...many, "blog-v1": main(15) };
check("a blog tag after the newest site tag: deploys, on that site", decide("blog-v1", blog) === "deploys" && built("blog-v1", blog) === "site-v10 + blog-v1");
check("... and that site tag again, by hand, keeps its articles", built("site-v10", blog, true) === "site-v10 + blog-v1");
check("... an older one by hand too", built("site-v2", blog, true) === "site-v2 + blog-v1");
const released = { ...blog, "v0.2.0": main(14), "v0.3.0": main(16) };
check("on the newest site or release tag, by commit", built("blog-v1", { ...blog, "v0.2.0": main(14) }) === "v0.2.0 + blog-v1");
check("a release after the blog tag holds it already", built("v0.3.0", released) === "v0.3.0 + its own");
check("... so the blog tag deploys nothing", decide("blog-v1", released) === "v0.3.0 holds it already: the site stays as it is");
check("... on the same commit as a site tag too", decide("blog-v1", { ...many, "blog-v1": main(13) }) === "site-v10 holds it already: the site stays as it is");
const blogs = { ...blog, "blog-v2": main(17), "blog-v9": main(18), "blog-v10": main(18) };
check("the newest blog tag: the highest count on the newest commit", built("site-v10", blogs, true) === "site-v10 + blog-v10");
check("an earlier blog tag, pushed again: deploys nothing",
  decide("blog-v2", blogs) === "blog-v10, blog-v9 on a later commit of main: the blog stays at what it shows", decide("blog-v2", blogs));
check("... by hand, it does", built("blog-v2", blogs, true) === "site-v10 + blog-v2");
check("refused: a blog tag that isn't on main",
  refused(() => decide("blog-v11", { ...blogs, "blog-v11": main(13, "b1") })) === "blog-v11 isn't a commit of main: a blog tag publishes what was merged");
check("refused: a blog tag before any site or release tag",
  refused(() => decide("blog-v1", { "blog-v1": main(2) })).includes("no site tag or release's tag on main yet"));

check("the pages the two folders make", JSON.stringify(pages([
  "docs/blog/README.md", "docs/blog/2026-10-23-recursive-row-level-security.md", "docs/blog/recursive-row-level-security",
  "docs/compare/openfga.md", "docs/compare/hand-written-rls.md",
])) === JSON.stringify(["blog/index.html", "blog/recursive-row-level-security.html", "compare/hand-written-rls.html", "compare/openfga.html"]));
check("... and none without a post", pages(["docs/blog/README.md"]).length === 0);
check("the folders a blog tag publishes", JSON.stringify(FOLDERS) === JSON.stringify(["docs/blog", "docs/compare"]));

// A repository made for the test: a release, then main moves on, a site tag, more commits
const repo = mkdtempSync(join(tmpdir(), "rowstile-site-"));
/** @param {string[]} args */
function git(...args) {
  const run = spawnSync("git", ["-c", "user.name=A Test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false",
    "-c", "tag.gpgsign=false", "-c", "core.autocrlf=false", ...args], { cwd: repo, encoding: "utf8" });
  if (run.status !== 0) throw new Error(`git ${args.join(" ")}: ${run.stderr}`);
  return run.stdout.trim();
}
/** @param {Record<string, string | null>} files what a commit writes (null: removes) @param {string} [tag] */
function commit(files, tag) {
  for (const [path, text] of Object.entries(files)) {
    if (text === null) rmSync(join(repo, path));
    else {
      mkdirSync(dirname(join(repo, path)), { recursive: true });
      writeFileSync(join(repo, path), text);
    }
  }
  git("add", "-A");
  git("commit", "--quiet", "-m", tag ?? "a change");
  if (tag) git("tag", "-a", tag, "-m", tag);
  git("update-ref", MAIN, "HEAD");
}
/** A file as checked out (on Windows git may write its lines' ends its own way). @param {string} path */
const now = (path) => (existsSync(join(repo, path)) ? readFileSync(join(repo, path), "utf8").replaceAll("\r\n", "\n") : null);

try {
  git("init", "--quiet", "--initial-branch=main");
  commit({ "docs/reference.md": "as released\n", "site/pages.mjs": "the release's\n" }, "v0.1.0-beta.1");
  commit({ "docs/reference.md": "what main says, not released\n", "site/pages.mjs": "main's\n",
           "docs/blog/2026-10-23-a-post.md": "a post\n" }, "site-v1");
  commit({ "docs/blog/2026-11-06-not-yet.md": "merged, not published\n" });

  check("in a repository: the site tag deploys", JSON.stringify(read(repo, "site-v1", false)) ===
    JSON.stringify({ deploy: true, why: "", code: "site-v1", content: "" }));
  take(repo, "site-v1", false);
  check("... the whole site as the site tag has it: the reference, the site's code, the post",
    now("docs/reference.md") === "what main says, not released\n" && now("site/pages.mjs") === "main's\n" &&
      now("docs/blog/2026-10-23-a-post.md") === "a post\n");
  check("... without what main got after it", now("docs/blog/2026-11-06-not-yet.md") === null);
  git("checkout", "--quiet", "--force", "main");
  check("the release before it doesn't deploy", read(repo, "v0.1.0-beta.1", false).why.startsWith("site-v1 on a later commit"));
  writeFileSync(join(repo, "stray.txt"), "a change of its own\n");
  check("... and isn't checked out", take(repo, "v0.1.0-beta.1", false).deploy === false && git("rev-parse", "HEAD") === git("rev-parse", "main"));
  check("refused, by hand: a clone with changes of its own", refused(() => take(repo, "v0.1.0-beta.1", true)).includes("changes of its own"));
  rmSync(join(repo, "stray.txt"));
  take(repo, "v0.1.0-beta.1", true);
  check("... else by hand it is: the site as released", now("docs/reference.md") === "as released\n" && now("docs/blog/2026-10-23-a-post.md") === null);

  git("checkout", "--quiet", "--force", "main");
  commit({ "docs/reference.md": "the next release's\n", "docs/compare/a.md": "a comparison\n" }, "v0.1.0");
  take(repo, "v0.1.0", false);
  check("the next release deploys: everything its own, the post merged since too",
    now("docs/reference.md") === "the next release's\n" && now("docs/blog/2026-11-06-not-yet.md") === "merged, not published\n" &&
      git("status", "--porcelain") === "");

  // a blog tag: a post arrives and one changes, a comparison page goes, the reference moves on, on the release's site
  git("checkout", "--quiet", "--force", "main");
  commit({ "docs/reference.md": "main moves on\n", "docs/blog/2026-11-06-not-yet.md": "corrected\n",
           "docs/blog/2026-11-20-third.md": "a third\n", "docs/blog/third/run.txt": "its run\n", "docs/compare/a.md": null }, "blog-v1");
  commit({ "docs/blog/2026-12-01-after.md": "merged after the blog tag\n" });
  check("in a repository: the blog tag on the release's site", JSON.stringify(read(repo, "blog-v1", false)) ===
    JSON.stringify({ deploy: true, why: "", code: "v0.1.0", content: "blog-v1" }), JSON.stringify(read(repo, "blog-v1", false)));
  take(repo, "blog-v1", false);
  check("... the reference and the site's code as the release has them", now("docs/reference.md") === "the next release's\n");
  check("... the two folders as the blog tag has them: what arrived, what changed",
    now("docs/blog/2026-11-20-third.md") === "a third\n" && now("docs/blog/third/run.txt") === "its run\n" &&
      now("docs/blog/2026-11-06-not-yet.md") === "corrected\n");
  check("... without what it removed, or what main got after it", now("docs/compare/a.md") === null && now("docs/blog/2026-12-01-after.md") === null);
  check("the built site lacks the pages the site's code doesn't make", JSON.stringify(missing(repo)) ===
    JSON.stringify(["blog/a-post.html", "blog/index.html", "blog/not-yet.html", "blog/third.html"]), missing(repo));
  for (const p of missing(repo)) {
    mkdirSync(dirname(join(repo, "site", "dist", p)), { recursive: true });
    writeFileSync(join(repo, "site", "dist", p), "");
  }
  check("... and lacks none once they are built", missing(repo).length === 0, missing(repo));
  rmSync(join(repo, "site", "dist"), { recursive: true });
  git("checkout", "--quiet", "--force", "main");
  commit({ "site/pages.mjs": "main's, later\n" }, "site-v2");
  check("a site tag after the blog tag: its own two folders", JSON.stringify(read(repo, "site-v2", false)) ===
    JSON.stringify({ deploy: true, why: "", code: "site-v2", content: "" }));
  check("... the release by hand: the blog tag's, which it doesn't hold", read(repo, "v0.1.0", true).content === "blog-v1");

  git("checkout", "--quiet", "-b", "aside", "main");
  commit({ "docs/blog/2026-12-02-unmerged.md": "not on main\n" }, "site-v3");
  git("update-ref", MAIN, "main");
  check("refused: a site tag on a commit that isn't main's",
    refused(() => take(repo, "site-v3", false)).includes("site-v3 isn't a commit of main"), refused(() => take(repo, "site-v3", false)));
} finally {
  rmSync(repo, { recursive: true, force: true });
}

console.log(failed ? `source: ${failed} failed` : "source: all passed");
process.exit(failed ? 1 : 0);
