// The images made from the mark (mark.svg), rendered with a headless Chrome or Chromium and committed: nothing renders
// them at build time. Run again after changing mark.svg or card.html:
//   node site/assets/render.mjs        (CHROME=... if the browser isn't where it usually is)
// The card's fonts are beside it (fonts/), so any machine renders the same card; the run stops if they didn't load.
// Where no Chrome is installed, Debian's Chromium in a container does it, from the repository's root:
//   docker run --rm -v "$PWD:/w" -w /w node:24 sh -c 'apt-get update -q && apt-get install -qy chromium >/dev/null &&
//     node site/assets/render.mjs && chown "$(stat -c %u:%g .)" site/assets/card.png editor/icon.png'
// It writes site/assets/card.png (1200 x 630: what a shared link shows) and editor/icon.png (256 x 256: the
// VS Code extension's icon). Plain JavaScript, typed with JSDoc and checked strictly (site/tsconfig.json).
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const BROWSERS = [
  process.env.CHROME ?? "",
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
];
const browser = BROWSERS.find((b) => b && existsSync(b));
if (!browser) throw new Error("no Chrome or Chromium (set CHROME to its path)");
/** The fonts card.html names, each of which must load. */
const FONTS = ["Inter", "JetBrains Mono"];

/** A headless run of the browser on a local page; its output. @param {string} page @param {string[]} args */
function headless(page, ...args) {
  const profile = mkdtempSync(join(tmpdir(), "rowstile-render-"));
  // no sandbox: in a container, as root, Chrome's doesn't start, and the page is the repository's own. The virtual
  // time lets the fonts load before the page is read
  const run = spawnSync(/** @type {string} */ (browser), [
    "--headless=new", "--no-sandbox", "--disable-gpu", "--no-first-run", "--no-default-browser-check", "--hide-scrollbars",
    `--user-data-dir=${profile}`, "--virtual-time-budget=10000", ...args, pathToFileURL(page).href,
  ], { encoding: "utf8", timeout: 60000 });
  rmSync(profile, { recursive: true, force: true });
  if (run.status !== 0) throw new Error(`${browser} on ${page}: exit ${run.status}\n${run.stderr ?? ""}`);
  return run.stdout;
}

/** A screenshot of a local page. @param {string} page @param {string} out @param {number} width @param {number} height */
function shot(page, out, width, height) {
  headless(page, "--default-background-color=00000000", `--window-size=${width},${height}`, "--force-device-scale-factor=1",
    `--screenshot=${out}`);
  if (!existsSync(out)) throw new Error(`no screenshot of ${page}`);
  console.log(`wrote ${out}`);
}

// the card's fonts: each loaded (card.html says so on the page), or the screenshot would show others
const card = join(HERE, "card.html");
const said = headless(card, "--dump-dom").match(/data-fonts="([^"]*)"/)?.[1] ?? "";
const unloaded = FONTS.filter((f) => !said.includes(`${f}: loaded`));
if (unloaded.length) throw new Error(`the card's fonts didn't load (${unloaded.join(", ")}): the page says "${said}"`);
shot(card, join(HERE, "card.png"), 1200, 630);

// the icon: the mark alone, on a page of its size (beside mark.svg, which it names)
const icon = join(HERE, ".icon.html");
writeFileSync(icon, '<!doctype html>\n<meta charset="utf-8">\n<style>html, body { margin: 0; background: transparent; } ' +
  'img { display: block; width: 256px; height: 256px; }</style>\n<img src="mark.svg" alt="">\n');
try {
  shot(icon, join(HERE, "..", "..", "editor", "icon.png"), 256, 256);
} finally {
  rmSync(icon, { force: true });
}
