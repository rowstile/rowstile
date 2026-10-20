// The images made from the mark (mark.svg), rendered with a headless Chrome or Edge and committed: nothing renders
// them at build time. Run again after changing mark.svg or card.html:
//   node site/assets/render.mjs        (CHROME=... if the browser isn't where it usually is)
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
  "/usr/bin/chromium",
];
const browser = BROWSERS.find((b) => b && existsSync(b));
if (!browser) throw new Error("no Chrome or Edge (set CHROME to its path)");

/** A screenshot of a local page. @param {string} page @param {string} out @param {number} width @param {number} height */
function shot(page, out, width, height) {
  const profile = mkdtempSync(join(tmpdir(), "rowstile-render-"));
  const run = spawnSync(/** @type {string} */ (browser), [
    "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check", "--hide-scrollbars",
    "--default-background-color=00000000", `--user-data-dir=${profile}`, `--window-size=${width},${height}`,
    "--force-device-scale-factor=1", `--screenshot=${out}`, pathToFileURL(page).href,
  ], { stdio: "ignore", timeout: 60000 });
  rmSync(profile, { recursive: true, force: true });
  if (run.status !== 0 || !existsSync(out)) throw new Error(`no screenshot of ${page} (exit ${run.status})`);
  console.log(`wrote ${out}`);
}

shot(join(HERE, "card.html"), join(HERE, "card.png"), 1200, 630);

// the icon: the mark alone, on a page of its size (beside mark.svg, which it names)
const icon = join(HERE, ".icon.html");
writeFileSync(icon, '<!doctype html>\n<meta charset="utf-8">\n<style>html, body { margin: 0; background: transparent; } ' +
  'img { display: block; width: 256px; height: 256px; }</style>\n<img src="mark.svg" alt="">\n');
try {
  shot(icon, join(HERE, "..", "..", "editor", "icon.png"), 256, 256);
} finally {
  rmSync(icon, { force: true });
}
