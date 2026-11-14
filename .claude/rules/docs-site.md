---
paths:
  - "docs/**"
  - "site/**"
  - "playground/**"
  - "README.md"
  - "llms.txt"
  - "context7.json"
---

# The docs, the site and the playground

Where the docs live, the rules their pages keep, how the site and the playground are built.

- `playground/` — rowstile in the browser: the compiler in Pyodide (a worker), the SQL in PGlite; `core.mjs` is the
  engine, `test.mjs` runs it in Node, `browser_test.mjs` the page in headless Chrome, `build.mjs` writes `dist/`
  (its examples are read from the repository: the getting-started guide's own, the docs app, the cookbook's
  recipes)
- `README.md` — the landing page: the pitch, installing, the docs, the folders. `core/README.md` is for working
  on the core folder (what's where, the test suites)
- `docs/` — `reference/` (the reference by subject: `language.md`, `app-code.md`, `identity.md`,
  `governance.md`, `tools.md`, `migrations.md`, `review.md`, `guarantees.md`, `limits.md`, `sync.md`),
  `installing.md` (the site's Installing page: it holds the README's install lines, `DocPages` checks),
  `getting-started.md` (run as written by `tests/docs_test.sh`, its Python too, with the README's and the home page's
  policy and SQL), `cookbook.md` + `cookbook/` (the index, and
  the recipes: each is `cookbook/<name>.md` beside `cookbook/<name>/` with `schema.sql`, `policy.authz`,
  `tests.authz`, `rows.sql` for the playground, `rowstile.toml` (so `rowstile dev` runs in a copy of the folder)
  and, where `SELECT *` on the first governed table isn't the question to ask there, `ask.sql`;
  `tests/cookbook.sh` applies and tests each, proves its invariants, runs `rowstile dev --once` in a copy, runs
  each SQL block its page shows (as user 1, the app role; `<!-- not run: why -->` before one it can't), compares
  each `$ rowstile ...` output with what the command prints, and checks every policy and test line its page shows
  is in its files; the site and the playground list them from the folders,
  and `/playground/#e=<name>` opens one), `how-it-is-checked.md` (how rowstile is checked, for readers to judge it),
  `troubleshooting.md`,
  `operations.md`, `managed-postgres.md` (the setup on a managed service; Neon and Supabase, as tried),
  `signed-urls.md`, `comparison.md` and `compare/` (a page per alternative, titled `# rowstile and <it>`, which
  the site lists from the folder: what they say of another project is quoted from its docs with the day they
  were read, and wants reading again each quarter (`docs/compare_readings.py`, the nightly's `readings` job, fails
  once a reading is older); `ComparePages` checks what they say of rowstile), `stacks/` (a page per stack; every line of code in them is in a
  conformance app, `StackPages` in `tests/unit_test.py`), `errors/` (a page per error code, written from
  `authzlib/errors.py` by `unit_test.py --update`)
- `context7.json` — for an index of docs that coding agents ask (Context7): the folders it reads, and what an
  agent should know first (`LlmsTxt` in `unit_test.py` checks its paths and its limits)
- `llms.txt` — for agents: what to know, and the links; `docs/llms_full.py` puts those files in one
  (`llms-full.txt`, built when the docs are published, not committed)
- `site/` — the docs site (VitePress; own `package.json`, like `playground/`): the Markdown stays where it is,
  `pages.mjs` says which files are pages and at which address, and turns each link (written relative to its
  file, for GitHub) into the page's address or the file on GitHub; a link to a missing file or page fails the
  build, and so do a link to a heading that isn't there (its anchor against the ids of the page it goes to) and a
  page no menu lists (`checkMenus`); `pages_test.mjs` checks those rules without building. `build.mjs` writes
  `dist/`: the pages, `/playground/`, each page's Markdown (`/getting-started.md`), `llms.txt` pointing to those,
  `llms-full.txt`. Its own pages: `index.md` and `problems/` (the SDKs' problem
  `type` URLs). A new doc page goes in `PAGES`, with its sentence in `DESCRIPTIONS` (what a search result and a
  shared link show; a page without one fails the build), and in the sidebar (`.vitepress/config.mts`). `build.mjs`
  also checks that the sitemap lists every page, and writes `robots.txt`. The blog: a post is
  `docs/blog/<date>-<slug>.md` (its title, `*Author's Name, <date>*`, then a first paragraph, its summary),
  listed in `docs/blog/README.md` (the index); `pages.mjs` reads them (`POSTS`, `readPost`), `blog.mjs` writes the
  Atom feed (`/blog/feed.xml`), `blog_test.mjs` checks both on made-up posts. With no post there is no blog on
  the site. `assets/` holds the mark (`mark.svg`:
  the tab's icon, the navigation's) and what is rendered from it and committed, by `node site/assets/render.mjs`
  with a headless Chrome or Edge: `card.png` (what a shared link shows, from `card.html`) and `editor/icon.png`.
  `.github/workflows/site.yml` deploys it to GitHub Pages (rowstile.dev), the whole site built from a tag's
  commit of `main`, without waiting for a release: a site tag (`site-vN`), or a release's tag on `main`; a blog
  tag (`blog-vN`) publishes `docs/blog/` and `docs/compare/` alone, on the site of the newest of those. One on a
  commit older than another of its kind deploys nothing. `source.mjs` is the rule (whether a tag deploys, what
  from, and the checkout), `source_test.mjs` its test, `RELEASING.md` the steps
- `docs/threat-model.md` — the trust boundary and what `tests/adversarial.sh` checks

## Rules for the pages

- Promises in the docs: on `docs/reference/`, `docs/threat-model.md` and `docs/how-it-is-checked.md`, a sentence
  that says always, never, can't, only, refuses, keeps or removes ends with
  `<!-- checked: tests/<suite> "<its label>" -->` (text that suite's file holds) or `<!-- unchecked: why -->`,
  written after it on the line it ends on, no `--` or `>` inside (`Promises` in `tests/unit_test.py` has the rule). Every code block of `docs/reference/`
  runs in `tests/reference.sh`, or a comment right before it says why not: `<!-- not run: why -->`.
