#!/usr/bin/env node
// rowstile for npm: runs the command (Python, standard library only, in ../command) on the Python that came
// with it, from the package for this platform (@rowstile/cli-<platform>-<arch>, -musl on a Linux with musl), so
// a TypeScript app needs no Python. ROWSTILE_PYTHON names another, a Python 3.11 or later; without either, a
// python3 of 3.11 or later on PATH.
// Plain JavaScript, typed with JSDoc and checked strictly (packaging/npm/tsconfig.json).
"use strict";
const { spawn, spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const PLATFORMS = ["linux-x64", "linux-arm64", "linux-x64-musl", "linux-arm64-musl", "darwin-x64", "darwin-arm64",
  "win32-x64"];
const command = path.join(__dirname, "..", "command", "cli", "rowstile_cli.py");

/** Whether this Linux's C library is musl (Alpine) and not glibc: Node's report names glibc's version when
 *  that is what Node runs on. @returns {boolean} */
function musl() {
  if (process.platform !== "linux") return false;
  try {
    const report = /** @type {{excludeNetwork?: boolean, getReport(): object}} */ (process.report);
    report.excludeNetwork = true;                     // the report's network part can take seconds
    const header = /** @type {{header?: {glibcVersionRuntime?: string}}} */ (report.getReport()).header;
    return !header?.glibcVersionRuntime;
  } catch {
    return fs.existsSync("/etc/alpine-release");
  }
}

// the package for this machine first; on Linux the other C library's after it, for an npm that installed that
// one (an npm that doesn't read a package's libc installs both)
const base = `${process.platform}-${process.arch}`;
const keys = process.platform !== "linux" ? [base] : musl() ? [`${base}-musl`, base] : [base, `${base}-musl`];
const key = keys[0];

// the bundled Python, when it is installed but can't be made executable (a read-only node_modules): said below
let unusable = "";

/** @returns {string | null} */
function bundled() {
  for (const k of keys) {
    if (!PLATFORMS.includes(k)) continue;
    let exe;
    try {
      const manifest = require.resolve(`@rowstile/cli-${k}/package.json`);
      exe = path.join(path.dirname(manifest), JSON.parse(fs.readFileSync(manifest, "utf8")).rowstilePython);
    } catch {
      continue;   // not installed
    }
    if (!fs.existsSync(exe)) continue;
    if (process.platform !== "win32") {
      try {
        fs.accessSync(exe, fs.constants.X_OK);
      } catch {
        try {
          fs.chmodSync(exe, 0o755);
        } catch (e) {
          unusable = `The Python of @rowstile/cli-${k} (${exe}) isn't executable, and can't be made so ` +
            `(${/** @type {Error} */ (e).message})`;
          continue;
        }
      }
      // the other C library's Python, when it is the only one here, can't start: say so below, not ENOENT
      if (k !== key && spawnSync(exe, ["-c", "pass"]).status !== 0) continue;
    }
    return exe;
  }
  return null;
}

/** The version of the Python a name runs ("3.13.1"), or why it gives none: "can't be run (...)", "isn't a
 *  Python". @param {string} name @returns {{version: string} | {why: string}} */
function version(name) {
  const r = spawnSync(name, ["-E", "-s", "-c", "import sys; print('%d.%d.%d' % sys.version_info[:3])"], { encoding: "utf8" });
  if (r.error) return { why: `can't be run (${r.error.message})` };
  const v = r.status === 0 ? /^\d+\.\d+\.\d+$/.exec(r.stdout.trim()) : null;
  return v ? { version: v[0] } : { why: "isn't a Python" };
}

/** Whether a version is 3.11 or later, what the command runs on. @param {string} v */
const recent = (v) => {
  const [major, minor] = v.split(".").map(Number);
  return major > 3 || (major === 3 && minor >= 11);
};

/** @returns {string | null} */
function onPath() {
  for (const name of process.platform === "win32" ? ["python", "py"] : ["python3", "python"]) {
    const v = version(name);
    if ("version" in v && recent(v.version)) return name;
  }
  return null;
}

/** On Windows, a file of the bundled Python whose path is longer than Windows loads (259 characters, unless long
 *  paths are turned on): Python then stops with "DLL load failed ... The filename or extension is too long",
 *  from inside node_modules. Null when every file is within the limit.
 *  @param {string} exe @returns {string | null} */
function tooLong(exe) {
  if (process.platform !== "win32") return null;
  try {
    const dlls = path.join(path.dirname(fs.realpathSync.native(exe)), "DLLs");
    const longest = fs.readdirSync(dlls).map((f) => path.join(dlls, f)).sort((a, b) => b.length - a.length)[0];
    if (!longest || longest.length <= 259) return null;
    // with long paths turned on, or when only files the command never loads are past the limit, it runs all
    // the same: ask it for the compiled modules the command uses
    const probe = "import unicodedata, ssl, hashlib, socket, select, zlib, decimal";
    return spawnSync(exe, ["-E", "-s", "-c", probe]).status === 0 ? null : longest;
  } catch {
    return null;
  }
}

const chosen = process.env.ROWSTILE_PYTHON;
if (chosen) {
  const v = version(chosen);
  if (!("version" in v) || !recent(v.version)) {
    console.error(`rowstile: ROWSTILE_PYTHON is ${chosen}, which ${"version" in v ? `is Python ${v.version}` : v.why}: ` +
      "name a Python 3.11 or later, or unset it to run on the Python that came with the package");
    process.exit(1);
  }
}
const own = chosen ? null : bundled();
const long = own && tooLong(own);
if (long && !onPath()) {
  console.error(`rowstile: this project's path is too long for Windows to load the Python that came with the package ` +
    `(${long.length} characters to ${path.basename(long)}; Windows loads up to 259). Move the project to a shorter path, ` +
    "or turn long paths on in Windows (LongPathsEnabled), or install Python 3.11 or later: rowstile then runs on that one");
  process.exit(1);
}
// a Python on PATH, when the bundled one can't be loaded from here
const python = chosen || (long ? null : own) || onPath();
if (!python) {
  console.error("rowstile: no Python to run on. " + (unusable ||
    `The package for this platform (@rowstile/cli-${key}) isn't installed` +
    (PLATFORMS.includes(key) ? " (optional dependencies turned off?)" : `, and there is none for ${key}`)) +
    "; install Python 3.11 or later, or set ROWSTILE_PYTHON to one");
  process.exit(1);
}
// -E -s: whichever Python it is ignores PYTHON* variables and the user's site-packages; -X utf8: one encoding
// everywhere
const child = spawn(python, ["-E", "-s", "-X", "utf8", command, ...process.argv.slice(2)], { stdio: "inherit" });
// A signal sent to this process is passed on to the command. From a terminal, Ctrl-C and a hang-up reach the
// command by themselves (it is in this process's group): passing those on would give it each one twice.
const SIGNALS = /** @type {NodeJS.Signals[]} */ (["SIGINT", "SIGTERM", "SIGHUP"]);
for (const signal of SIGNALS) {
  process.on(signal, () => {
    if (signal === "SIGTERM" || !process.stdin.isTTY) child.kill(signal);
  });
}
child.on("error", (e) => {
  console.error(`rowstile: could not run ${python}: ${e.message}` +
    (chosen ? "" : "; install Python 3.11 or later, or set ROWSTILE_PYTHON to one"));
  process.exit(1);
});
child.on("exit", (code, signal) => {
  if (!signal) process.exit(code ?? 1);
  // The command was stopped by a signal: this process ends the same way, never with 0. Its own listeners
  // would take the signal, so they go first; where the signal doesn't end it, the shell's code for it.
  for (const s of SIGNALS) process.removeAllListeners(s);
  process.kill(process.pid, signal);
  setTimeout(() => process.exit(128 + (os.constants.signals[signal] ?? 1)), 200);
});
