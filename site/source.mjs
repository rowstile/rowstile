// What the site is built from. The reference, the guide and the install lines describe a release, so they come
// from its tag (vX.Y.Z), with the site's own code. An article and a comparison page describe no version, and don't
// wait for one: a site tag (site-v1, site-v2, ...) publishes those two folders as they are at its commit, on the
// release the site shows. Nothing else comes from a site tag, so it never builds new pages with older code.
//   node site/source.mjs <tag>          what a tag is built from: code=<a release's tag>, content=<a site tag, or nothing>
//   node site/source.mjs --take <tag>   checks that out, in a clone with no changes of its own (the site workflow)
//   node site/source.mjs --built        after the build: every post and comparison page is a page of site/dist
// Plain JavaScript, typed with JSDoc and checked strictly (site/tsconfig.json).
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, realpathSync, rmSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

/** The folders a site tag publishes. */
export const FOLDERS = ["docs/blog", "docs/compare"];

// a release's tag: the version as packaging/version.py writes it, its stages those of core/authzlib/versions.py
// (Delivery in core/tests/unit_test.py holds the two together)
const RELEASE = /^v\d+\.\d+\.\d+(?:-(?:alpha|beta|rc)\.\d+)?$/;
const SITE = /^site-v([1-9]\d*)$/;
/** The branch releases and site tags are made on, as a clone names it. */
export const MAIN = "refs/remotes/origin/main";

/** Whether a's commit is b's, or one before it (a, b: tags, or MAIN). @typedef {(a: string, b: string) => boolean} Before */
/** What to build from: a release's tag, and the site tag whose two folders replace the release's ("": none, the
 *  release holds them already). @typedef {{code: string, content: string}} Source */

/** The release the site shows: the highest final one (what a plain install gets), or while there is none the last
 *  alpha, beta or candidate on main, the one every other there is before. Their order on main is their versions'
 *  (alphas, betas, candidates), so this needs no order of stages of its own; a tag that isn't main's doesn't count.
 *  @param {string[]} tags the repository's @param {Before} before */
export function shown(tags, before) {
  const releases = tags.filter((t) => RELEASE.test(t));
  if (!releases.length) throw new Error("no release tag yet (vX.Y.Z): the site is built from one");
  const finals = releases.filter((t) => !t.includes("-"));
  if (finals.length) {
    const key = (/** @type {string} */ t) => t.slice(1).split(".").map(Number);
    const higher = (/** @type {string} */ a, /** @type {string} */ b) => {
      const [x, y] = [key(a), key(b)];
      return x[0] - y[0] || x[1] - y[1] || x[2] - y[2];
    };
    return finals.sort(higher)[finals.length - 1];
  }
  const mains = releases.filter((t) => before(t, MAIN));
  const last = mains.filter((t) => mains.every((u) => before(u, t)));
  if (last.length !== 1) throw new Error("no alpha, beta or candidate on main yet: the site is built from one");
  return last[0];
}

/** What a tag is built from. A release's tag: its own files, with the two folders of the last site tag unless the
 *  release holds that tag (it is the site tag's commit, or after it). A site tag: the release the site shows, with
 *  the site tag's two folders; it must come after that release, which otherwise holds it already.
 *  @param {string} given the tag pushed, or named by hand @param {string[]} tags the repository's
 *  @param {Before} before @returns {Source} */
export function sources(given, tags, before) {
  if (!tags.includes(given)) throw new Error(`${given}: no such tag`);
  if (RELEASE.test(given)) {
    const number = (/** @type {string} */ t) => Number(t.match(SITE)?.[1]);
    const last = tags.filter((t) => SITE.test(t)).sort((a, b) => number(a) - number(b)).at(-1);
    return { code: given, content: last && !before(last, given) ? last : "" };
  }
  if (!SITE.test(given)) throw new Error(`${given}: not a release's tag (v0.2.0) or a site tag (site-v3)`);
  const code = shown(tags, before);
  if (before(given, code)) throw new Error(`${given} isn't after ${code}, which the site shows: that release holds it already`);
  if (!before(code, given)) throw new Error(`${given} doesn't come after ${code}, which the site shows: tag a commit of main`);
  return { code, content: given };
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

/** @param {string} repo a clone with every tag @param {string} given @returns {Source} */
export function read(repo, given) {
  const tags = git(repo, "tag", "-l").out.split("\n").map((t) => t.trim()).filter(Boolean);
  return sources(given, tags, (a, b) => git(repo, "merge-base", "--is-ancestor", `${a}^{commit}`, `${b}^{commit}`).ok);
}

/** Checks out what a tag is built from: the release, then the site tag's two folders in place of the release's.
 *  @param {string} repo a clone with every tag and origin/main, and no changes of its own @param {string} given
 *  @returns {Source} */
export function take(repo, given) {
  const from = read(repo, given);
  const changed = git(repo, "status", "--porcelain").out;
  if (changed) throw new Error(`this clone has changes of its own, which taking ${given} would lose:\n${changed}`);
  if (from.content && !git(repo, "merge-base", "--is-ancestor", `${from.content}^{commit}`, MAIN).ok) {
    throw new Error(`${from.content} isn't a commit of main: a site tag publishes what was merged`);
  }
  const out = git(repo, "checkout", "--quiet", "--detach", from.code);
  if (!out.ok) throw new Error(`git checkout ${from.code}: ${out.out}`);
  if (!from.content) return from;
  for (const folder of FOLDERS) {
    rmSync(join(repo, folder), { recursive: true, force: true });
    if (!git(repo, "cat-file", "-e", `${from.content}:${folder}`).ok) continue;     // the site tag has no such folder
    const put = git(repo, "checkout", "--quiet", from.content, "--", folder);
    if (!put.ok) throw new Error(`git checkout ${from.content} -- ${folder}: ${put.out}`);
  }
  return from;
}

/** The pages the two folders should have made that the built site doesn't have: the release it was built from is
 *  older than what makes them. @param {string} repo @returns {string[]} */
export function missing(repo) {
  const files = FOLDERS.flatMap((folder) =>
    existsSync(join(repo, folder)) ? readdirSync(join(repo, folder)).map((f) => `${folder}/${f}`) : []);
  return pages(files).filter((p) => !existsSync(join(repo, "site", "dist", p)));
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const [how, tag] = process.argv.slice(2);
  const repo = process.cwd();
  try {
    if (how === "--built" && tag === undefined) {
      const lost = missing(repo);
      if (lost.length) {
        throw new Error(`the site was built without ${lost.join(", ")}: the release it is built from doesn't make these ` +
          "pages yet. They go out with the next release");
      }
      console.log("every post and comparison page is on the built site");
    } else if (how === "--take" && tag) {
      const from = take(repo, tag);
      console.log(`code=${from.code}\ncontent=${from.content}`);
    } else if (how && !how.startsWith("--") && tag === undefined) {
      const from = read(repo, how);
      console.log(`code=${from.code}\ncontent=${from.content}`);
    } else {
      throw new Error("usage: node site/source.mjs <tag> | --take <tag> | --built");
    }
  } catch (e) {
    console.error(`site/source.mjs: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  }
}
