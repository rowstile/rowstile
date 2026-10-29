// Which tags deploy the site, and what from. The whole site (its code, the home page, the docs, the playground) is
// built from a tag's own commit, and doesn't wait for a release: a site tag (site-v1, site-v2, ...) on a commit of
// main deploys it, and so does a release's tag (vX.Y.Z) on main. A blog tag (blog-v1, blog-v2, ...) publishes the
// articles and the comparison pages alone: the site of the newest site or release tag on main, with docs/blog/ and
// docs/compare/ as they are at the blog tag. A tag pushed on a commit older than another of its kind deploys
// nothing, so the site never goes back by itself; run by hand, a tag deploys whatever comes after it.
//   node site/source.mjs <tag> [--by-hand]          deploy=true|false, why=..., code=<the tag the site is built
//                                                    from>, content=<the blog tag whose two folders replace its own>
//   node site/source.mjs --take <tag> [--by-hand]   the same, and checks out what it is built from when it deploys,
//                                                    in a clone with no changes of its own (the site workflow)
//   node site/source.mjs --built                    after the build: every post and comparison page is a page of site/dist
// Plain JavaScript, typed with JSDoc and checked strictly (site/tsconfig.json).
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, realpathSync, rmSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

/** The folders a blog tag publishes. */
export const FOLDERS = ["docs/blog", "docs/compare"];

// a release's tag: the version as packaging/version.py writes it, its stages those of core/authzlib/versions.py
// (Delivery in core/tests/unit_test.py holds the two together)
const RELEASE = /^v\d+\.\d+\.\d+(?:-(?:alpha|beta|rc)\.\d+)?$/;
const SITE = /^site-v([1-9]\d*)$/;
const BLOG = /^blog-v([1-9]\d*)$/;
/** The branch site and blog tags are made on, as a clone names it. */
export const MAIN = "refs/remotes/origin/main";

/** Whether a's commit is b's, or one before it (a, b: tags, or MAIN). @typedef {(a: string, b: string) => boolean} Before */
/** Whether a tag deploys the site, and if not, why ("" when it does); what it is built from: a site or release tag,
 *  and the blog tag whose two folders replace its own ("": none). @typedef {{deploy: boolean, why: string, code:
 *  string, content: string}} Decision */

/** What a tag deploys.
 *  @param {string} given the tag pushed, or named by hand @param {string[]} tags the repository's
 *  @param {Before} before @param {boolean} byHand @returns {Decision} */
export function deploys(given, tags, before, byHand) {
  if (!tags.includes(given)) throw new Error(`${given}: no such tag`);
  const whole = (/** @type {string} */ t) => SITE.test(t) || RELEASE.test(t);
  if (!whole(given) && !BLOG.test(given)) {
    throw new Error(`${given}: not a site tag (site-v3), a blog tag (blog-v3) or a release's (v0.2.0)`);
  }
  if (!before(given, MAIN)) {
    if (RELEASE.test(given)) {
      return { deploy: false, why: `${given} isn't on main (a patch to an older line): the site stays as it is`, code: "", content: "" };
    }
    throw new Error(`${given} isn't a commit of main: a ${given.split("-")[0]} tag publishes what was merged`);
  }
  const after = (/** @type {string} */ a, /** @type {string} */ b) => before(b, a) && !before(a, b);   // a's commit is later
  const onMain = tags.filter((t) => before(t, MAIN));
  const number = (/** @type {string} */ t) => Number(t.match(BLOG)?.[1]);
  /** the newest of these tags: none on a later commit, the highest count on the same one @param {string[]} some */
  const newest = (some) => some.filter((t) => !some.some((u) => after(u, t))).sort((a, b) => number(a) - number(b)).at(-1);
  const blogs = onMain.filter((t) => BLOG.test(t));
  if (whole(given)) {
    const later = onMain.filter((t) => whole(t) && after(t, given)).sort();
    if (later.length && !byHand) {
      return { deploy: false, why: `${later.join(", ")} on a later commit of main: the site stays at what it shows`, code: given, content: "" };
    }
    return { deploy: true, why: "", code: given, content: newest(blogs.filter((t) => after(t, given))) ?? "" };
  }
  const code = newest(onMain.filter(whole));
  if (!code) throw new Error("no site tag or release's tag on main yet: a blog tag publishes onto the site one deploys");
  if (!after(given, code)) {
    return { deploy: false, why: `${code} holds it already: the site stays as it is`, code, content: given };
  }
  const later = blogs.filter((t) => after(t, given)).sort();
  if (later.length && !byHand) {
    return { deploy: false, why: `${later.join(", ")} on a later commit of main: the blog stays at what it shows`, code, content: given };
  }
  return { deploy: true, why: "", code, content: given };
}

/** The pages a folder's files make, as files of the built site: a post is docs/blog/<date>-<slug>.md, a comparison
 *  page docs/compare/<name>.md; the blog's index comes with its first post.
 *  @param {string[]} files repository paths @returns {string[]} */
export function pages(files) {
  const made = [];
  for (const f of files) {
    const post = f.match(/^docs\/blog\/\d{4}-\d{2}-\d{2}-([a-z0-9-]+)\.md$/);
    const compared = f.match(/^docs\/compare\/([a-z0-9-]+)\.md$/);
    if (post) made.push(`blog/${post[1]}.html`);
    if (compared) made.push(`compare/${compared[1]}.html`);
  }
  if (made.some((p) => p.startsWith("blog/"))) made.push("blog/index.html");
  return made.sort();
}

/** @param {string} repo @param {string[]} args @returns {{ok: boolean, out: string}} */
function git(repo, ...args) {
  const run = spawnSync("git", args, { cwd: repo, encoding: "utf8" });
  if (run.error) throw run.error;
  return { ok: run.status === 0, out: run.stdout.trim() + (run.status === 0 ? "" : run.stderr.trim()) };
}

/** @param {string} repo a clone with every tag and origin/main @param {string} given @param {boolean} byHand
 *  @returns {Decision} */
export function read(repo, given, byHand) {
  const tags = git(repo, "tag", "-l").out.split("\n").map((t) => t.trim()).filter(Boolean);
  return deploys(given, tags, (a, b) => git(repo, "merge-base", "--is-ancestor", `${a}^{commit}`, `${b}^{commit}`).ok,
    byHand);
}

/** What a tag deploys, and when it does, checks that out: the site or release tag, then the blog tag's two folders in
 *  place of its own. @param {string} repo a clone with every tag and origin/main, and no changes of its own
 *  @param {string} given @param {boolean} byHand @returns {Decision} */
export function take(repo, given, byHand) {
  const decided = read(repo, given, byHand);
  if (!decided.deploy) return decided;
  const changed = git(repo, "status", "--porcelain").out;
  if (changed) throw new Error(`this clone has changes of its own, which taking ${given} would lose:\n${changed}`);
  const out = git(repo, "checkout", "--quiet", "--detach", decided.code);
  if (!out.ok) throw new Error(`git checkout ${decided.code}: ${out.out}`);
  if (!decided.content) return decided;
  for (const folder of FOLDERS) {
    rmSync(join(repo, folder), { recursive: true, force: true });
    if (!git(repo, "cat-file", "-e", `${decided.content}:${folder}`).ok) continue;     // the blog tag has no such folder
    const put = git(repo, "checkout", "--quiet", decided.content, "--", folder);
    if (!put.ok) throw new Error(`git checkout ${decided.content} -- ${folder}: ${put.out}`);
  }
  return decided;
}

/** The pages the two folders should have made that the built site doesn't have: the site's code it was built with
 *  is older than what makes them. @param {string} repo @returns {string[]} */
export function missing(repo) {
  const files = FOLDERS.flatMap((folder) =>
    existsSync(join(repo, folder)) ? readdirSync(join(repo, folder)).map((f) => `${folder}/${f}`) : []);
  return pages(files).filter((p) => !existsSync(join(repo, "site", "dist", p)));
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  const byHand = args.at(-1) === "--by-hand";
  const [how, tag] = byHand ? args.slice(0, -1) : args;
  const repo = process.cwd();
  try {
    if (how === "--built" && tag === undefined && !byHand) {
      const lost = missing(repo);
      if (lost.length) {
        throw new Error(`the site was built without ${lost.join(", ")}: the site's code it is built from doesn't make ` +
          "these pages yet. They go out with the next site tag");
      }
      console.log("every post and comparison page is on the built site");
    } else {
      /** @type {Decision} */
      let decided;
      if (how === "--take" && tag) decided = take(repo, tag, byHand);
      else if (how && !how.startsWith("--") && tag === undefined) decided = read(repo, how, byHand);
      else throw new Error("usage: node site/source.mjs <tag> [--by-hand] | --take <tag> [--by-hand] | --built");
      console.log(`deploy=${decided.deploy}\nwhy=${decided.why}\ncode=${decided.code}\ncontent=${decided.content}`);
    }
  } catch (e) {
    console.error(`site/source.mjs: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  }
}
