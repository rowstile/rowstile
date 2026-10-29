// Which tags deploy the site. The whole site (its code, the home page, the docs, the playground) is built from a
// tag's own commit, and doesn't wait for a release: a site tag (site-v1, site-v2, ...) on a commit of main deploys
// it, and so does a release's tag (vX.Y.Z) on main. A tag pushed on a commit older than another such tag's on main
// deploys nothing, so the site never goes back by itself; run by hand, a tag on main deploys whatever comes after it.
//   node site/source.mjs <tag> [--by-hand]          whether the tag deploys: deploy=true|false, why=...
//   node site/source.mjs --take <tag> [--by-hand]   the same, and checks the tag out when it deploys, in a clone with
//                                                    no changes of its own (the site workflow)
// Plain JavaScript, typed with JSDoc and checked strictly (site/tsconfig.json).
import { spawnSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

// a release's tag: the version as packaging/version.py writes it, its stages those of core/authzlib/versions.py
// (Delivery in core/tests/unit_test.py holds the two together)
const RELEASE = /^v\d+\.\d+\.\d+(?:-(?:alpha|beta|rc)\.\d+)?$/;
const SITE = /^site-v([1-9]\d*)$/;
/** The branch site tags are made on, as a clone names it. */
export const MAIN = "refs/remotes/origin/main";

/** Whether a's commit is b's, or one before it (a, b: tags, or MAIN). @typedef {(a: string, b: string) => boolean} Before */
/** Whether a tag deploys the site, and if not, why ("" when it does). @typedef {{deploy: boolean, why: string}} Decision */

/** Whether a tag deploys the site, from its own commit.
 *  @param {string} given the tag pushed, or named by hand @param {string[]} tags the repository's
 *  @param {Before} before @param {boolean} byHand @returns {Decision} */
export function deploys(given, tags, before, byHand) {
  if (!tags.includes(given)) throw new Error(`${given}: no such tag`);
  const site = SITE.test(given);
  if (!site && !RELEASE.test(given)) throw new Error(`${given}: not a release's tag (v0.2.0) or a site tag (site-v3)`);
  if (!before(given, MAIN)) {
    if (site) throw new Error(`${given} isn't a commit of main: a site tag publishes what was merged`);
    return { deploy: false, why: `${given} isn't on main (a patch to an older line): the site stays as it is` };
  }
  if (byHand) return { deploy: true, why: "" };
  const later = tags.filter((t) => t !== given && (SITE.test(t) || RELEASE.test(t)) && before(t, MAIN) &&
    before(given, t) && !before(t, given));
  if (later.length) {
    return { deploy: false, why: `${later.sort().join(", ")} on a later commit of main: the site stays at what it shows` };
  }
  return { deploy: true, why: "" };
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

/** Whether a tag deploys the site, and if it does, checks it out.
 *  @param {string} repo a clone with every tag and origin/main, and no changes of its own @param {string} given
 *  @param {boolean} byHand @returns {Decision} */
export function take(repo, given, byHand) {
  const decided = read(repo, given, byHand);
  if (!decided.deploy) return decided;
  const changed = git(repo, "status", "--porcelain").out;
  if (changed) throw new Error(`this clone has changes of its own, which taking ${given} would lose:\n${changed}`);
  const out = git(repo, "checkout", "--quiet", "--detach", given);
  if (!out.ok) throw new Error(`git checkout ${given}: ${out.out}`);
  return decided;
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const args = process.argv.slice(2);
  const byHand = args.at(-1) === "--by-hand";
  const [how, tag] = byHand ? args.slice(0, -1) : args;
  const repo = process.cwd();
  try {
    /** @type {Decision} */
    let decided;
    if (how === "--take" && tag) decided = take(repo, tag, byHand);
    else if (how && !how.startsWith("--") && tag === undefined) decided = read(repo, how, byHand);
    else throw new Error("usage: node site/source.mjs <tag> [--by-hand] | --take <tag> [--by-hand]");
    console.log(`deploy=${decided.deploy}\nwhy=${decided.why}`);
  } catch (e) {
    console.error(`site/source.mjs: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  }
}
