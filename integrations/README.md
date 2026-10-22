# Conformance suites

One list of checks, run by a small app per stack (`integrations/<stack>/`, each with its own `test.sh`), in CI
on PostgreSQL 16 for each push, and on 17 and 18 every night (`PG_MAJOR=17` or `18` runs a suite on another
version). Every night they also run on 16 with the app connecting through PgBouncer in transaction mode
(`POOLER=pgbouncer`, `pooler.sh`; the owner and the change feed stay direct). The tests are numbered after
this list.

1. Signed in, a list shows only the user's rows.
2. Signed out on purpose, only what `anyone` may see.
3. Not signed in: the not-signed-in error (AZ701), naming `act_as`.
4. With a pool of one connection, a request as Ann, then one as Bob: Bob never sees Ann's rows.
5. Concurrent requests never mix users.
6. A refused insert: 403 with the problem body naming the rule.
7. An update of a hidden row: 404. Of a visible row the user may not edit: 403, with the reason.
8. Insert, then read back, works when the select rule allows it, and is explained when not.
9. The generated names type-check, and a wrong permission name doesn't: in the generated client, and in the
   SDK's own calls.
10. A background job signs in as a service principal.
11. A fresh database: migrate, and the policy tests pass. Then the tool's own diff shows no change.
12. The framework's test database has the policy: a copy of the migrated one for each test worker (Vitest's,
    pytest-xdist's).
13. The app refuses to start on a connection that skips row-level security.
14. After a policy change and a new migration, the app works with the new generated names.
15. Next.js only: a signed-in page is never served from a cache to another user, and a signed-in read inside
    `unstable_cache` or `"use cache"` fails instead of being cached.
16. A call the database turns down that is no refusal answers as its code's page says, with the database's
    words: what it names isn't there (AZ708) 404, a missing or wrong argument (AZ710) 400, a call that needs
    someone signed in (AZ714) or a login refused (AZ703) 401, a move inside itself (AZ713) 409. A refusal by the
    database's own code (AZ704, AZ705, AZ715) is 403. The app's mistakes stay errors, a 500: a share the policy
    doesn't declare (AZ706), a name not in the policy (AZ707), who is signed in changed by hand (AZ702). In
    every integration that answers HTTP (Next.js: `route()`, `action()`, `authzRoutes()`).

A new stack gets its own folder here, with every check that applies to it.
