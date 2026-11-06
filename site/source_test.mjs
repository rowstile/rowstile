// Which tags deploy the site, and what from (source.mjs): the rule on made-up tags, then in a repository made for the test, with
// real commits and tags.   node site/source_test.mjs
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { FOLDERS, MAIN, deployed, deploys, missing, pages, read, shownBy, take, withoutGit } from "./source.mjs";

// as a git hook or git rebase --exec runs it, with git's own variables naming the repository it was started in:
// each git call here works in the repository made for the test, named by its folder alone
process.env.GIT_DIR = join(tmpdir(), "rowstile-site-not-this-one");
process.env.GIT_WORK_TREE = join(tmpdir(), "rowstile-site-not-this-one");
process.env.GIT_INDEX_FILE = join(tmpdir(), "rowstile-site-not-this-one", "index");

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

// what the live site shows (deployed.json): a run cancelled or failed leaves it behind the tags, and the next run that
// would deploy nothing deploys the newest site; a site put back by hand stays
/** @param {string} given @param {Record<string, string[]>} at @param {import("./source.mjs").Shown | null} [shown]
 *  @param {boolean} [byHand] */
const live = (given, at, shown, byHand = false) => {
  /** @type {Record<string, string[]>} */
  const all = { ...at, [MAIN]: main(99) };
  const d = deploys(given, Object.keys(at), (a, b) => all[b].includes(/** @type {string} */ (all[a].at(-1))), byHand, shown);
  return `${d.deploy ? "deploys" : "nothing"} ${d.code} + ${d.content || "its own"}${d.pinned ? ", pinned" : ""}: ${d.why}`;
};
/** @param {string} code @param {string} [content] @param {boolean} [pinned] */
const shows = (code, content = "", pinned = false) => ({ code, content, pinned });
const held = { ...many, "blog-v1": main(13) };
check("the live site as the tags say: a tag held already deploys nothing", live("blog-v1", held, shows("site-v10")) ===
  "nothing site-v10 + blog-v1: site-v10 holds it already: the site stays as it is", live("blog-v1", held, shows("site-v10")));
check("... nor when it names another tag on the same commit", live("v0.1.0-beta.1", both, shows("site-v1")).startsWith("nothing") &&
  live("v0.1.0-beta.1", both, shows("v0.1.0")).startsWith("nothing"), live("v0.1.0-beta.1", both, shows("site-v1")));
check("a newer tag's run that didn't finish: the next run deploys the newest site", live("blog-v1", held, shows("site-v9")) ===
  "deploys site-v10 + its own: the site shows site-v9, not site-v10: a run before this one was cancelled or failed. Deploys site-v10",
  live("blog-v1", held, shows("site-v9")));
check("... an older tag pushed again too", live("site-v2", blogs, shows("site-v10", "blog-v2")) ===
  "deploys site-v10 + blog-v10: the site shows site-v10 with blog-v2, not site-v10 with blog-v10: a run before this one was cancelled or failed. " +
  "Deploys site-v10 with blog-v10", live("site-v2", blogs, shows("site-v10", "blog-v2")));
check("... and a patch to an older line", live("v0.0.9", { ...patch, "blog-v1": main(15) }, shows("site-v9")).startsWith("deploys site-v10 + blog-v1:"));
check("... a blog tag missing from it", live("blog-v2", blogs, shows("site-v10")).startsWith("deploys site-v10 + blog-v10:"));
check("a site that doesn't say what it shows: the newest is deployed", live("blog-v1", held, null) ===
  "deploys site-v10 + its own: the site doesn't say what it shows (deployed.json): deploys the newest, site-v10", live("blog-v1", held, null));
check("a site put back by hand stays", live("blog-v1", held, shows("site-v2", "", true)) ===
  "nothing site-v10 + blog-v1: site-v10 holds it already: the site stays as it is; the site was put back to site-v2 by hand, and stays",
  live("blog-v1", held, shows("site-v2", "", true)));
check("... until a newer tag deploys", live("site-v11", { ...held, "site-v11": main(20) }, shows("site-v2", "", true)) ===
  "deploys site-v11 + its own: ");
check("put back by hand: an older site is pinned", live("site-v2", many, undefined, true) === "deploys site-v2 + its own, pinned: ");
check("... the newest isn't", live("site-v10", blog, undefined, true) === "deploys site-v10 + blog-v1: " &&
  live("site-v10", { ...many, "v0.1.2": main(13) }, undefined, true) === "deploys site-v10 + its own: ");
check("... nor a tag that deploys as pushed", live("site-v10", many, shows("site-v9")) === "deploys site-v10 + its own: ");
check("what a deploy writes, read back", JSON.stringify(shownBy(deployed({ SITE_CODE: "site-v4", SITE_CONTENT: "blog-v2", SITE_PINNED: "true" }))) ===
  JSON.stringify(shows("site-v4", "blog-v2", true)) && JSON.stringify(shownBy(deployed({ SITE_CODE: "v0.2.0", SITE_PINNED: "false" }))) ===
  JSON.stringify(shows("v0.2.0")), deployed({ SITE_CODE: "site-v4" }));
check("... a build of a branch says main", shownBy(deployed({}))?.code === "main");
check("... and what isn't such a file says nothing", shownBy("<html>404</html>") === null && shownBy('{"code": "site-v1"}') === null &&
  shownBy("null") === null);

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
    "-c", "tag.gpgsign=false", "-c", "core.autocrlf=false", ...args], { cwd: repo, encoding: "utf8", env: withoutGit() });
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
    JSON.stringify({ deploy: true, why: "", code: "site-v1", content: "", pinned: false }));
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
  commit({ "docs/reference.md": "the next release's\n", "docs/compare/a.md": "a comparison\n", "docs/blog/old/run.txt": "a run\n" }, "v0.1.0");
  take(repo, "v0.1.0", false);
  check("the next release deploys: everything its own, the post merged since too",
    now("docs/reference.md") === "the next release's\n" && now("docs/blog/2026-11-06-not-yet.md") === "merged, not published\n" &&
      git("status", "--porcelain") === "");

  // a blog tag: a post arrives and one changes, a run goes, the reference moves on, on the release's site
  git("checkout", "--quiet", "--force", "main");
  commit({ "docs/reference.md": "main moves on\n", "docs/blog/2026-11-06-not-yet.md": "corrected\n",
           "docs/blog/2026-11-20-third.md": "a third\n", "docs/blog/third/run.txt": "its run\n", "docs/blog/old/run.txt": null }, "blog-v1");
  commit({ "docs/blog/2026-12-01-after.md": "merged after the blog tag\n" });
  check("in a repository: the blog tag on the release's site", JSON.stringify(read(repo, "blog-v1", false)) ===
    JSON.stringify({ deploy: true, why: "", code: "v0.1.0", content: "blog-v1", pinned: false }), JSON.stringify(read(repo, "blog-v1", false)));
  take(repo, "blog-v1", false);
  check("... the reference and the site's code as the release has them", now("docs/reference.md") === "the next release's\n");
  check("... the two folders as the blog tag has them: what arrived, what changed",
    now("docs/blog/2026-11-20-third.md") === "a third\n" && now("docs/blog/third/run.txt") === "its run\n" &&
      now("docs/blog/2026-11-06-not-yet.md") === "corrected\n");
  check("... without what it removed, or what main got after it", now("docs/blog/old/run.txt") === null && now("docs/blog/2026-12-01-after.md") === null);
  check("the built site lacks the pages the site's code doesn't make", JSON.stringify(missing(repo)) ===
    JSON.stringify(["blog/a-post.html", "blog/index.html", "blog/not-yet.html", "blog/third.html", "compare/a.html"]), missing(repo));
  for (const p of missing(repo)) {
    mkdirSync(dirname(join(repo, "site", "dist", p)), { recursive: true });
    writeFileSync(join(repo, "site", "dist", p), "");
  }
  check("... and lacks none once they are built", missing(repo).length === 0, missing(repo));
  rmSync(join(repo, "site", "dist"), { recursive: true });
  git("checkout", "--quiet", "--force", "main");
  commit({ "site/pages.mjs": "main's, later\n" }, "site-v2");
  check("a site tag after the blog tag: its own two folders", JSON.stringify(read(repo, "site-v2", false)) ===
    JSON.stringify({ deploy: true, why: "", code: "site-v2", content: "", pinned: false }));
  check("... the release by hand: the blog tag's, which it doesn't hold", read(repo, "v0.1.0", true).content === "blog-v1");

  // a branch named like a tag, on another commit: what is decided and what is checked out are the tag's
  git("checkout", "--quiet", "--force", "main");
  git("branch", "site-v2", "v0.1.0");
  git("branch", "v0.1.0", "v0.1.0-beta.1");
  git("branch", "blog-v1", "v0.1.0-beta.1");
  take(repo, "site-v2", true);
  check("a branch named like a tag: the tag's commit is checked out", git("rev-parse", "HEAD") === git("rev-parse", "refs/tags/site-v2^{commit}") &&
    now("site/pages.mjs") === "main's, later\n", git("rev-parse", "HEAD"));
  git("checkout", "--quiet", "--force", "main");
  take(repo, "v0.1.0", true);
  check("... and with a blog tag's two folders", git("rev-parse", "HEAD") === git("rev-parse", "refs/tags/v0.1.0^{commit}") &&
    now("docs/blog/2026-11-20-third.md") === "a third\n", git("rev-parse", "HEAD"));
  git("checkout", "--quiet", "--force", "main");
  git("branch", "-D", "site-v2", "v0.1.0", "blog-v1");

  // a comparison page a blog tag adds, a later one may remove; one the site tag has, its own pages name
  commit({ "docs/compare/b.md": "a newer comparison\n" }, "blog-v2");
  commit({ "docs/compare/b.md": null }, "blog-v3");
  take(repo, "blog-v3", false);
  check("a blog tag removes a comparison page a blog tag added", now("docs/compare/b.md") === null && now("docs/compare/a.md") === "a comparison\n");
  git("checkout", "--quiet", "--force", "main");
  commit({ "docs/compare/a.md": null, "docs/compare/a2.md": "renamed\n" }, "blog-v4");
  const removes = "blog-v4 removes docs/compare/a.md, which site-v2's own pages name (docs/comparison.md links each " +
    "comparison page, site/pages.mjs describes it): removing or renaming a comparison page takes a site tag";
  check("refused: a blog tag that removes a comparison page the site tag has", refused(() => take(repo, "blog-v4", false)) === removes,
    refused(() => take(repo, "blog-v4", false)));
  check("... by hand too, and nothing is checked out", refused(() => take(repo, "blog-v4", true)) === removes &&
    git("rev-parse", "HEAD") === git("rev-parse", "main"));

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
