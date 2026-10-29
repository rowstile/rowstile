// After a deploy, tells the search engines that take IndexNow (Bing, Yandex, Seznam, Naver) every address the site
// has, so they read the pages again without waiting for a crawl. Bing's index is what several assistants search.
// The key is public by design: the file /<KEY>.txt on the site, which build.mjs writes, says the site sent it.
// Plain JavaScript, typed with JSDoc and checked strictly (site/tsconfig.json).
//   node site/indexnow.mjs          after a deploy (site.yml): the live sitemap's addresses, sent
//   node site/indexnow.mjs --dry    what it would send
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { ORIGIN } from "./pages.mjs";

export const KEY = "93a02742bbbc92488eb28c766342f8b4";
/** The file that holds the key, at the site's root. */
export const KEY_FILE = `${KEY}.txt`;
const ENDPOINT = "https://api.indexnow.org/indexnow";

/** What IndexNow is sent: the sitemap's addresses, each on the site's own host (it refuses any other).
 *  @param {string} sitemap @returns {{host: string, key: string, keyLocation: string, urlList: string[]}} */
export function payload(sitemap) {
  const urlList = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);
  if (!urlList.length) throw new Error("the sitemap lists no address");
  const other = urlList.filter((u) => u !== ORIGIN && !u.startsWith(`${ORIGIN}/`));
  if (other.length) throw new Error(`the sitemap lists addresses elsewhere: ${other.join(", ")}`);
  return { host: new URL(ORIGIN).host, key: KEY, keyLocation: `${ORIGIN}/${KEY_FILE}`, urlList };
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  const got = await fetch(`${ORIGIN}/sitemap.xml`);
  if (!got.ok) throw new Error(`${ORIGIN}/sitemap.xml: ${got.status}`);
  const body = payload(await got.text());
  if (process.argv[2] === "--dry") {
    console.log(JSON.stringify(body, null, 2));
  } else {
    // 200: taken; 202: taken, the key not yet checked. Anything else is a refusal, said with its reason
    const sent = await fetch(ENDPOINT, {
      method: "POST",
      headers: { "content-type": "application/json; charset=utf-8" },
      body: JSON.stringify(body),
    });
    console.log(`IndexNow: ${sent.status} for ${body.urlList.length} addresses`);
    if (sent.status !== 200 && sent.status !== 202) {
      console.log(await sent.text());
      process.exit(1);
    }
  }
}
