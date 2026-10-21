# The playground

rowstile in the browser, with nothing installed: write a policy, its tables and its tests, and see Postgres
enforce it. The compiler (`core/authzlib`, standard library only) runs in Pyodide, in a worker; the SQL it
writes runs in PGlite, Postgres 18 in WebAssembly. On each change the policy is compiled, applied to a fresh
database with the tables, and its tests run. A mistake shows its line, its code and the code's page; "Ask as
someone" runs a statement as the app role, signed in as whoever you name, and rolls it back. "Copy link" puts
the whole state in the link, and `#e=<name>` opens one of the page's own examples (each recipe of the cookbook
links here that way).

One thing it can't show is signed sessions. PGlite has a single session, the owner's, and rowstile believes
the owner's settings without a signature: a statement under "Ask as someone" may `SET authz.user_id` and
become someone else. On a server the app role's session is believed only after `authz.act_as()` (the page says
so under the box).

| file | what |
|---|---|
| `core.mjs` | the engine: compile (Pyodide), run and ask (PGlite); the same in the page and in `test.mjs` |
| `compiler.worker.mjs` | the compiler in a worker, so Python starts beside Postgres and typing never waits |
| `playground.mjs`, `index.html` | the page |
| `build.mjs` | writes `dist/`: the page, and `bundle.json` with the compiler and the examples, read from the repository (the getting-started guide's own schema, policy and test; the docs example; the cookbook) |
| `test.mjs` | the engine headless, in Node: every example compiles, applies and passes its tests; asking as someone; mistakes; each run starts from nothing; the SQL is the command's (it runs `core/compile_policy.py`: `PYTHON=...` if `python3` isn't the one) |
| `browser_test.mjs` | the page in headless Chrome or Edge, over the DevTools protocol; also how long loading takes |

```sh
cd playground && npm ci
node test.mjs                          # the engine, headless
node build.mjs && node browser_test.mjs  # the page (SCREENSHOT=page.png to see it)
npx serve dist                         # or any static host
```

Pyodide and PGlite load from jsDelivr, at the versions `package.json` pins (`test.mjs` checks the page asks for
the same ones), and mermaid (the graph) at the one `playground.mjs` names. Once they are cached, `browser_test.mjs` asks that the
page load within 5 s in headless Chrome (CI's runners, which are slower, within 10 s); the first time also
downloads about 12 MB.
