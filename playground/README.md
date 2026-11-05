# The playground

rowstile in the browser, with nothing installed: write a policy, its tables and its tests, and see Postgres
enforce it. The compiler (`core/authzlib`, standard library only) runs in Pyodide, in a worker; the SQL it
writes runs in PGlite, Postgres 18 in WebAssembly. On each change the policy is compiled, applied to a fresh
database with the tables, and its tests run. A mistake shows its line, its code and the code's page; "Ask as
someone" runs a statement as the app role, signed in as whoever you name, and rolls it back (a `COMMIT` or
`ROLLBACK` in the statement ends that transaction early, and what follows runs signed in as nobody; a `RESET
ROLE` makes the rest run as the owner: the answer says so). "Copy link" puts
the whole state in the link, and `#e=<name>` opens one of the page's own examples (each recipe of the cookbook
links here that way; a name that isn't one opens the first example, and says so).

One thing it can't show is signed sessions. PGlite has a single session, the owner's, and rowstile believes
the owner's settings without a signature: a statement under "Ask as someone" may `SET authz.user_id` and
become someone else. On a server the app role's session is believed only after `authz.act_as()` (the page says
so under the box).

| file | what |
|---|---|
| `core.mjs` | the engine: compile (Pyodide), run and ask (PGlite); the same in the page and in `test.mjs` |
| `compiler.worker.mjs` | the compiler in a worker, so Python starts beside Postgres and typing never waits |
| `playground.mjs`, `index.html` | the page |
| `build.mjs` | writes `dist/`: the page, `bundle.json` with the compiler and the examples, read from the repository (the getting-started guide's own schema, policy and test; the docs example; the cookbook), and Pyodide and PGlite, copied from `node_modules` |
| `test.mjs` | the engine headless, in Node: every example compiles, applies and passes its tests; asking as someone; mistakes; each run starts from nothing; the SQL is the command's (it runs `core/compile_policy.py`: `PYTHON=...` if `python3` isn't the one) |
| `browser_test.mjs` | the page in headless Chrome or Edge, over the DevTools protocol; also how long loading takes |

```sh
cd playground && npm ci
node test.mjs                          # the engine, headless
node build.mjs && node browser_test.mjs  # the page (SCREENSHOT=page.png to see it)
npx serve dist                         # or any static host
```

Pyodide and PGlite come with the page: `build.mjs` copies them from `node_modules` into `dist/`, at the versions
`package.json` pins (`npm ci` checks them against `package-lock.json`'s hashes, and the build refuses a
`node_modules` with other versions). The page loads one file from another site: mermaid (the graph), from jsDelivr,
checked against its hash (Studio's file and hash: `unit_test.py` holds them to one). Its Content-Security-Policy
lets scripts run from the site itself and that file alone. Once they are cached, `browser_test.mjs` asks that the
page load within 5 s in headless Chrome (CI's runners, which are slower, within 10 s); the first time also
downloads about 12 MB, compressed.
