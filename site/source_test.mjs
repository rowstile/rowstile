// What the site is built from (source.mjs): the rule on made-up tags, then in a repository made for the test, with
// real commits and tags.   node site/source_test.mjs
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { FOLDERS, MAIN, missing, pages, read, shown, sources, take } from "./source.mjs";

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
/** @param {Record<string, string[]>} at each tag's commit @returns {[string[], (a: string, b: string) => boolean]} */
const repository = (at) => {
  /** @type {Record<string, string[]>} */
  const all = { ...at, [MAIN]: main(99) };
  return [Object.keys(at), (a, b) => all[b].includes(/** @type {string} */ (all[a].at(-1)))];
};
/** @param {string} given @param {Record<string, string[]>} at */
const from = (given, at) => {
  const { code, content } = sources(given, ...repository(at));
  return `${code} + ${content || "its own"}`;
};

// a tag that isn't main's doesn't count, whatever its version: the last one on main is shown, not the highest
const alphas = { "v0.1.0-rc.1": ["off-main"], "v0.1.0-alpha.4": main(5), "v0.1.0-alpha.5": main(6) };
check("with no final release, the site shows the last alpha, beta or candidate on main", shown(...repository(alphas)) === "v0.1.0-alpha.5");
const betas = { ...alphas, "v0.1.0-beta.1": main(7) };
check("... a beta on main after the alphas", shown(...repository(betas)) === "v0.1.0-beta.1");
check("... a candidate on main after the beta", shown(...repository({ ...betas, "v0.1.0-rc.2": main(8) })) === "v0.1.0-rc.2");
check("refused: no release on main", refused(() => shown(...repository({ "v0.1.0-rc.1": ["off-main"] }))).includes("no alpha, beta or candidate on main yet"));
check("a release's tag: its own files", from("v0.1.0-alpha.5", alphas) === "v0.1.0-alpha.5 + its own");
check("... a beta's too", from("v0.1.0-beta.1", betas) === "v0.1.0-beta.1 + its own");
const first = { ...alphas, "site-v1": main(8) };
check("a site tag: the release the site shows, with its two folders", from("site-v1", first) === "v0.1.0-alpha.5 + site-v1");
check("... and that release again, by hand, keeps them", from("v0.1.0-alpha.5", first) === "v0.1.0-alpha.5 + site-v1");
const next = { ...first, "v0.1.0-alpha.6": main(10) };
check("a release after the site tag holds it already", from("v0.1.0-alpha.6", next) === "v0.1.0-alpha.6 + its own");
check("... and is what the site shows", shown(...repository(next)) === "v0.1.0-alpha.6");
const many = { ...next, "site-v2": main(11), "site-v9": main(12), "site-v10": main(13) };
check("the last site tag is the highest number, not the last in the alphabet", from("v0.1.0-alpha.6", many) === "v0.1.0-alpha.6 + site-v10");
check("an earlier site tag, by hand", from("site-v2", many) === "v0.1.0-alpha.6 + site-v2");

// once a final release exists the site shows the highest one: not a later alpha, not a patch to an older line
const finals = { ...many, "v0.1.0": main(14), "v0.2.0-alpha.1": main(16), "site-v11": main(17) };
check("with a final release, the site shows it", shown(...repository(finals)) === "v0.1.0");
check("... so a site tag after an alpha is built on the final one", from("site-v11", finals) === "v0.1.0 + site-v11");
const lines = { ...finals, "v0.9.0": main(20), "v0.10.0": main(22), "v0.9.1": main(20, "b1"), "site-v12": main(24) };
check("the highest final release, by number", shown(...repository(lines)) === "v0.10.0");
check("a patch to an older line, by hand: the last site tag's folders, which it doesn't hold", from("v0.9.1", lines) === "v0.9.1 + site-v12");

check("refused: a site tag the shown release already holds",
  refused(() => from("site-v10", lines)).includes("site-v10 isn't after v0.10.0, which the site shows"), refused(() => from("site-v10", lines)));
const side = { ...lines, "site-v13": main(20, "b1", "b2") };
check("refused: a site tag beside the shown release, not after it",
  refused(() => from("site-v13", side)).includes("doesn't come after v0.10.0"), refused(() => from("site-v13", side)));
check("refused: a tag that isn't there", refused(() => from("site-v99", lines)) === "site-v99: no such tag");
check("refused: a tag of another kind", refused(() => from("nightly", { ...lines, nightly: main(30) })).includes("not a release's tag"));
check("refused: a site tag before any release", refused(() => from("site-v1", { "site-v1": main(2) })).includes("no release tag yet"));

check("the pages the two folders make", JSON.stringify(pages([
  "docs/blog/README.md", "docs/blog/2026-10-23-recursive-row-level-security.md", "docs/blog/recursive-row-level-security",
  "docs/compare/openfga.md", "docs/compare/hand-written-rls.md",
])) === JSON.stringify(["blog/index.html", "blog/recursive-row-level-security.html", "compare/hand-written-rls.html", "compare/openfga.html"]));
check("... and none without a post", pages(["docs/blog/README.md"]).length === 0);

// A repository made for the test: a release, then main moves on (the reference changes, a post and a comparison
// page arrive, another goes), a site tag, more commits, the next release
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
  commit({ "docs/reference.md": "as released\n", "site/pages.mjs": "the release's\n", "docs/compare/old.md": "old\n",
           "docs/compare/kept.md": "kept, first\n" }, "v0.1.0-alpha.6");
  commit({ "docs/reference.md": "what main says, not released\n", "site/pages.mjs": "main's\n" });
  commit({ "docs/blog/README.md": "the index\n", "docs/blog/2026-10-23-a-post.md": "a post\n", "docs/blog/a-post/run.txt": "its run\n",
           "docs/compare/new.md": "new\n", "docs/compare/kept.md": "kept, corrected\n", "docs/compare/old.md": null }, "site-v1");
  commit({ "docs/blog/2026-11-06-not-yet.md": "merged, not published\n" });

  check("in a repository: a site tag is built from the release before it", JSON.stringify(read(repo, "site-v1")) ===
    JSON.stringify({ code: "v0.1.0-alpha.6", content: "site-v1" }), JSON.stringify(read(repo, "site-v1")));
  take(repo, "site-v1");
  check("... the reference and the site's code as released", now("docs/reference.md") === "as released\n" && now("site/pages.mjs") === "the release's\n");
  check("... the two folders as the site tag has them: what arrived, what changed, what its pages show",
    now("docs/blog/2026-10-23-a-post.md") === "a post\n" && now("docs/blog/a-post/run.txt") === "its run\n" &&
      now("docs/compare/new.md") === "new\n" && now("docs/compare/kept.md") === "kept, corrected\n");
  check("... without what it removed, or what main got after it", now("docs/compare/old.md") === null && now("docs/blog/2026-11-06-not-yet.md") === null);

  check("the built site lacks the pages a release older than the blog doesn't make",
    JSON.stringify(missing(repo)) === JSON.stringify(["blog/a-post.html", "blog/index.html", "compare/kept.html", "compare/new.html"]), missing(repo));
  for (const p of ["blog/a-post.html", "blog/index.html", "compare/kept.html", "compare/new.html"]) {
    mkdirSync(dirname(join(repo, "site", "dist", p)), { recursive: true });
    writeFileSync(join(repo, "site", "dist", p), "");
  }
  check("... and lacks none once they are built", missing(repo).length === 0, missing(repo));

  check("refused: a clone with changes of its own", refused(() => take(repo, "site-v1")).includes("changes of its own"));
  rmSync(join(repo, "site", "dist"), { recursive: true });
  git("checkout", "--quiet", "--force", "main");
  commit({ "docs/reference.md": "the next release's\n" }, "v0.1.0-alpha.7");
  take(repo, "v0.1.0-alpha.7");
  check("the next release: everything its own, the post merged since too",
    now("docs/reference.md") === "the next release's\n" && now("docs/blog/2026-11-06-not-yet.md") === "merged, not published\n" &&
      git("status", "--porcelain") === "");

  git("checkout", "--quiet", "-b", "aside", "main");
  commit({ "docs/blog/2026-12-01-unmerged.md": "not on main\n" }, "site-v2");
  git("update-ref", MAIN, "main");
  check("refused: a site tag on a commit that isn't main's",
    refused(() => take(repo, "site-v2")).includes("site-v2 isn't a commit of main"), refused(() => take(repo, "site-v2")));
  check("the folders a site tag publishes", JSON.stringify(FOLDERS) === JSON.stringify(["docs/blog", "docs/compare"]));
} finally {
  rmSync(repo, { recursive: true, force: true });
}

console.log(failed ? `source: ${failed} failed` : "source: all passed");
process.exit(failed ? 1 : 0);
