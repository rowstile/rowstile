// Builds the npm packages of the rowstile command: `rowstile` (the launcher and the command, which is Python,
// standard library only) and one `@rowstile/cli-<platform>` per platform with a standalone Python in it
// (python-build-standalone), trimmed of what the command never uses.
//
//   node packaging/npm/build.mjs                         # rowstile, and the package for this platform
//   node packaging/npm/build.mjs --platform linux-x64    # ... for these platforms (repeat it), or --all
//
// Writes packaging/npm/out/<package>/; downloads are kept in packaging/npm/.cache/.
// Plain JavaScript, typed with JSDoc and checked strictly (packaging/npm/tsconfig.json).
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync, cpSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const OUT = join(HERE, "out");
const CACHE = join(HERE, ".cache");

// python-build-standalone: one release, CPython 3.13, the stripped install-only builds. Each file's SHA-256 is
// the release's own (its SHA256SUMS): a download, or a file kept from an earlier one, that isn't those bytes
// is refused. A new RELEASE or PYTHON needs the seven sums again, and python-licenses/ again: the licence
// texts of the libraries built into that Python (OpenSSL, SQLite, zlib...), which only the release's full
// archives carry (python/licenses/, the same files for every target), less those of the parts trim() removes.
// RELEASING.md's release steps check for a newer release: nothing else watches it.
const RELEASE = "20260924";
const PYTHON = "3.13.15";
/** @typedef {{triple: string, os: string, cpu: string, libc?: string, sha256: string}} Target */
/** @type {Record<string, Target>} */
const TARGETS = {
  "linux-x64": { triple: "x86_64-unknown-linux-gnu", os: "linux", cpu: "x64", libc: "glibc",
    sha256: "d0b640eed27fbdd6f5f2bd33444aee53df2c8863f8b2a96f4094717411e3de9c" },
  "linux-arm64": { triple: "aarch64-unknown-linux-gnu", os: "linux", cpu: "arm64", libc: "glibc",
    sha256: "5ad58156cbec94e5643c13caa792e92df72a23f33d3a6425d4cbff5c4b7a040c" },
  // Linux with musl (Alpine): glibc's Python can't start there
  "linux-x64-musl": { triple: "x86_64-unknown-linux-musl", os: "linux", cpu: "x64", libc: "musl",
    sha256: "94c39f6249241858871b9fe9cae8b506076ed8291860b1334210a76c13ac2b65" },
  "linux-arm64-musl": { triple: "aarch64-unknown-linux-musl", os: "linux", cpu: "arm64", libc: "musl",
    sha256: "e919f032be1fbcd7cac8c591f89df461f21749ca6c9c7cee78fbd0909af4cc64" },
  "darwin-x64": { triple: "x86_64-apple-darwin", os: "darwin", cpu: "x64",
    sha256: "327814efd865a0b6a99c149b12a261e9d0ad409183515c745d41bda2d07282e9" },
  "darwin-arm64": { triple: "aarch64-apple-darwin", os: "darwin", cpu: "arm64",
    sha256: "064afb7c2fc0bbf511d886288adf98696af5105e36c138cdf2c199c0146fcf68" },
  "win32-x64": { triple: "x86_64-pc-windows-msvc", os: "win32", cpu: "x64",
    sha256: "e42fa944748a50e9ff481cbb817ef8a6e3da6fbcf0cf6f29b554e1acb8c7384d" },
};
// the command's files, each folder of core/ and the endings of its files the command runs (the Python package's
// build reads the same list): file by file, so nothing else of the tree it is built from goes in
const COMMAND = readFileSync(join(ROOT, "sdk", "python", "command-files.txt"), "utf8").split("\n")
  .map((line) => line.replace(/#.*/, "").trim().split(/\s+/)).filter(([folder]) => folder)
  .flatMap(([folder, ...endings]) => readdirSync(join(ROOT, "core", folder), { withFileTypes: true })
    .filter((f) => f.isFile() && endings.some((e) => f.name.endsWith(e))).map((f) => `${folder}/${f.name}`));
// what the command never uses: the standard library's tests, GUIs, installers and headers
const UNUSED = ["test", "idlelib", "tkinter", "turtledemo", "turtle.py", "ensurepip", "lib2to3", "pydoc_data",
  "site-packages", "venv", "__phello__"];
// python-licenses/: each text, and the licence it is (SPDX), for the package's `license`. Left out, with the parts
// trim() removes: Berkeley DB (in _dbm), Tcl, Tk, Tix and the X11 libraries Tk uses; OpenSSL 1.1 (no target has it)
/** @type {Record<string, string>} */
const LICENSES = {
  "LICENSE.cpython.txt": "PSF-2.0", "LICENSE.openssl-3.txt": "Apache-2.0", "LICENSE.sqlite.txt": "blessing",
  "LICENSE.zlib.txt": "Zlib", "LICENSE.bzip2.txt": "bzip2-1.0.6", "LICENSE.liblzma.txt": "0BSD",
  "LICENSE.libffi.txt": "MIT", "LICENSE.expat.txt": "MIT", "LICENSE.mpdecimal.txt": "BSD-2-Clause",
  "LICENSE.libuuid.txt": "BSD-3-Clause", "LICENSE.libedit.txt": "BSD-3-Clause",
  "LICENSE.ncurses.txt": "X11-distribute-modifications-variant",
};

const version = /^__version__ = "([^"]+)"/m.exec(readFileSync(join(ROOT, "core", "authzlib", "__init__.py"), "utf8"))?.[1];
if (!version) throw new Error("core/authzlib/__init__.py has no __version__");

/** The first name in dir that matches, or an error naming what is missing. @param {string} dir @param {RegExp} name */
function find(dir, name) {
  const found = readdirSync(dir).find((f) => name.test(f));
  if (!found) throw new Error(`nothing in ${dir} matches ${name}`);
  return found;
}

/** The platforms asked for. @returns {string[]} */
function args() {
  const a = process.argv.slice(2);
  if (a.includes("--all")) return Object.keys(TARGETS);
  /** @type {string[]} */
  const out = [];
  for (let i = 0; i < a.length; i++) if (a[i] === "--platform") out.push(a[++i]);
  if (out.length) return out;
  const here = `${process.platform}-${process.arch}`;
  return TARGETS[here] ? [here] : [];
}

/** @param {string} path @param {string | object} data */
function write(path, data) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, typeof data === "string" ? data : JSON.stringify(data, null, 2) + "\n");
}

/** @param {string} dest */
function copyCommand(dest) {
  for (const file of COMMAND) cpSync(join(ROOT, "core", file), join(dest, file));
}

/** @param {string[]} platforms */
function launcher(platforms) {
  const dir = join(OUT, "rowstile");
  rmSync(dir, { recursive: true, force: true });
  cpSync(join(HERE, "rowstile"), dir, { recursive: true });
  cpSync(join(ROOT, "LICENSE"), join(dir, "LICENSE"));
  copyCommand(join(dir, "command"));
  const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
  pkg.version = version;
  pkg.optionalDependencies = Object.fromEntries(Object.keys(TARGETS).map((k) => [`@rowstile/cli-${k}`, version]));
  write(join(dir, "package.json"), pkg);
  console.log(`built rowstile ${version}${platforms.length ? "" : " (no platform packages)"}`);
}

/** @param {string} file @returns {string} */
const sha256 = (file) => createHash("sha256").update(readFileSync(file)).digest("hex");

/** The target's Python, downloaded or kept from before, and the bytes its release published.
 *  @param {Target} target @returns {string} */
function download(target) {
  const name = `cpython-${PYTHON}+${RELEASE}-${target.triple}-install_only_stripped.tar.gz`;
  const file = join(CACHE, name);
  // a file kept from a download that was cut short isn't the release's: fetch it again
  if (existsSync(file) && sha256(file) !== target.sha256) rmSync(file, { force: true });
  if (!existsSync(file)) {
    mkdirSync(CACHE, { recursive: true });
    const url = `https://github.com/astral-sh/python-build-standalone/releases/download/${RELEASE}/${encodeURIComponent(name)}`;
    console.log(`downloading ${name}`);
    // the network may drop a download: a few tries, then the checksum says whether it is whole
    execFileSync("curl", ["-fsSL", "--retry", "4", "--retry-all-errors", "-o", file, url], { stdio: "inherit" });
    const got = sha256(file);
    if (got !== target.sha256) {
      rmSync(file, { force: true });
      throw new Error(`${name}: its SHA-256 is ${got}, not ${target.sha256}`);
    }
  }
  return file;
}

/** @param {string} python @param {Target} target */
function trim(python, target) {
  const lib = target.os === "win32" ? join(python, "Lib")
    : join(python, "lib", find(join(python, "lib"), /^python3\.\d+$/));
  for (const name of UNUSED) rmSync(join(lib, name), { recursive: true, force: true });
  for (const d of readdirSync(lib)) if (d.startsWith("config-")) rmSync(join(lib, d), { recursive: true, force: true });
  if (target.os === "win32") {
    for (const d of ["tcl", "include", "libs", "Scripts"]) rmSync(join(python, d), { recursive: true, force: true });
    for (const f of readdirSync(join(python, "DLLs"))) {
      if (/^(tcl|tk)\d|_tkinter/.test(f)) rmSync(join(python, "DLLs", f), { force: true });
    }
  } else {
    for (const d of ["include", "share"]) rmSync(join(python, d), { recursive: true, force: true });
    for (const f of readdirSync(join(python, "lib"))) {
      if (/^(libtcl|libtk|tcl|tk|itcl|thread|pkgconfig)/.test(f)) rmSync(join(python, "lib", f), { recursive: true, force: true });
    }
    // libpython: the binary is linked statically and loads none (readelf -d, otool -L); python3.13-config: for
    // building against the headers removed above
    for (const f of readdirSync(join(python, "lib"))) {
      if (/^libpython3/.test(f)) rmSync(join(python, "lib", f), { force: true });
    }
    for (const f of readdirSync(join(python, "bin"))) {
      if (/^(idle|pydoc|2to3|pip)|-config$/.test(f)) rmSync(join(python, "bin", f), { force: true });
    }
    // _dbm: the dbm module's C part (Berkeley DB on Linux), which the command never imports
    const dyn = join(lib, "lib-dynload");
    if (existsSync(dyn)) for (const f of readdirSync(dyn)) if (/^(_tkinter|_dbm)\./.test(f)) rmSync(join(dyn, f), { force: true });
  }
}

// npm leaves symlinks out of packages: drop them (bin/python3 -> python3.13, the name asked for)
/** @param {string} dir */
function unlink(dir) {
  for (const f of readdirSync(dir)) {
    const p = join(dir, f);
    const st = lstatSync(p);
    if (st.isSymbolicLink()) rmSync(p, { force: true });
    else if (st.isDirectory()) unlink(p);
  }
}

/** @param {string} path @returns {number} */
function size(path) {
  const s = statSync(path);
  return s.isDirectory() ? readdirSync(path).reduce((n, f) => n + size(join(path, f)), 0) : s.size;
}

// the package's own licence (LICENSE), then each of its Python's
const licence = [...new Set(["Apache-2.0", ...Object.values(LICENSES)])].join(" AND ");
const texts = readdirSync(join(HERE, "python-licenses")).sort().join(", ");
if (texts !== Object.keys(LICENSES).sort().join(", ")) {
  throw new Error(`python-licenses/ holds ${texts}: LICENSES in build.mjs names each text the packages carry`);
}

/** @param {string} key */
function platform(key) {
  const target = TARGETS[key];
  if (!target) throw new Error(`no platform ${key} (${Object.keys(TARGETS).join(", ")})`);
  const tarball = download(target);
  const dir = join(OUT, `cli-${key}`);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  execFileSync("tar", ["-xzf", tarball, "-C", dir], { stdio: "inherit" });   // makes python/
  trim(join(dir, "python"), target);
  let exe = "python/python.exe";
  if (target.os !== "win32") {
    unlink(join(dir, "python"));
    const bin = join(dir, "python", "bin");
    exe = "python/bin/" + find(bin, /^python3\.\d+$/);
    chmodSync(join(dir, exe), 0o755);
  }
  write(join(dir, "package.json"), {
    name: `@rowstile/cli-${key}`,
    version,
    description: `The Python the rowstile command runs on, for ${key} (python-build-standalone ${PYTHON}, trimmed)`,
    license: licence,
    homepage: "https://rowstile.dev",
    keywords: ["rowstile"],
    repository: { type: "git", url: "git+https://github.com/rowstile/rowstile.git", directory: "packaging/npm" },
    os: [target.os],
    cpu: [target.cpu],
    ...(target.libc ? { libc: [target.libc] } : {}),      // npm installs the one for the machine's C library
    files: ["python", "README.md"],
    preferUnplugged: true,
    rowstilePython: exe,
  });
  cpSync(join(ROOT, "LICENSE"), join(dir, "LICENSE"));    // the package's; Python's own is python/**/LICENSE.txt
  // ... and those of the libraries built into this Python, where python-build-standalone's full archives put them
  for (const f of Object.keys(LICENSES)) cpSync(join(HERE, "python-licenses", f), join(dir, "python", "licenses", f));
  write(join(dir, "README.md"), `# @rowstile/cli-${key}\n\nThe Python that the \`rowstile\` command runs on, for ${key}: ` +
    `CPython ${PYTHON} from python-build-standalone (${RELEASE}), without the parts the command never uses. ` +
    "Installed by `rowstile` as an optional dependency; not for use on its own.\n\n" +
    "Python's licence is `python/lib/python3.13/LICENSE.txt` (`python/LICENSE.txt` on Windows); the licences of the " +
    "libraries built into it (OpenSSL, SQLite, zlib, bzip2, xz, libffi and others) are in `python/licenses/`.\n");
  console.log(`built @rowstile/cli-${key} (${(size(dir) / 1e6).toFixed(1)} MB unpacked)`);
}

const platforms = args();
mkdirSync(OUT, { recursive: true });
launcher(platforms);
for (const key of platforms) platform(key);
