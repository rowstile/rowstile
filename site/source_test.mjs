// Which tags deploy the site (source.mjs): the rule on made-up tags, then in a repository made for the test, with
// real commits and tags.   node site/source_test.mjs
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { MAIN, deploys, read, take } from "./source.mjs";

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
check("refused: a tag of another kind", refused(() => decide("nightly", { ...many, nightly: main(30) })).includes("not a release's tag"));
check("a tag of another kind doesn't hold the site back", decide("site-v10", { ...many, nightly: main(30) }) === "deploys");

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

  check("in a repository: the site tag deploys", JSON.stringify(read(repo, "site-v1", false)) === JSON.stringify({ deploy: true, why: "" }));
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
  commit({ "docs/reference.md": "the next release's\n" }, "v0.1.0");
  take(repo, "v0.1.0", false);
  check("the next release deploys: everything its own, the post merged since too",
    now("docs/reference.md") === "the next release's\n" && now("docs/blog/2026-11-06-not-yet.md") === "merged, not published\n" &&
      git("status", "--porcelain") === "");

  git("checkout", "--quiet", "-b", "aside", "main");
  commit({ "docs/blog/2026-12-01-unmerged.md": "not on main\n" }, "site-v2");
  git("update-ref", MAIN, "main");
  check("refused: a site tag on a commit that isn't main's",
    refused(() => take(repo, "site-v2", false)).includes("site-v2 isn't a commit of main"), refused(() => take(repo, "site-v2", false)));
} finally {
  rmSync(repo, { recursive: true, force: true });
}

console.log(failed ? `source: ${failed} failed` : "source: all passed");
process.exit(failed ? 1 : 0);
