# How rowstile is checked

**Nobody outside the project has audited rowstile.** This page says what does check it, so that you can judge
for yourself. Every line names the test that does the checking; they all run in CI, in the open, and
[the table of suites](../core/README.md#tested) lists every one.

## Two ways to answer, which must agree

rowstile answers "may this person do that?" in two ways: with lookups into views for reads and lists, and with
a check of the single row for writes and `authz.can`. They are written separately, and they must give the same
answer. After every random change, [`tests/difftest.py`](../core/tests/difftest.py) asks both, for every
user, and compares.

## A second implementation

Tests written by the author of the code share the author's mistakes. So the answers are also compared with a
second implementation: the reference evaluator ([`authzlib/evaluate.py`](../core/authzlib/evaluate.py)),
which works straight from the policy, on sets of ids, to a fixed point, and knows nothing of the SQL the
compiler writes. The two share one thing, the parser: a policy misread there would be misread by both, and
they would agree. So the evaluator is held to answers that neither of them wrote, below.

- **A second reading of the language**: the editors' grammar ([`editor/tree-sitter-authz`](../editor/tree-sitter-authz))
  was written apart from the parser. [`tests/parse_agreement.py`](../core/tests/parse_agreement.py) has both
  read every policy in the repository and two hundred random ones, and compares what they read: the types,
  each relation's sources, the permissions with their grouping, the rules, the tests. They read each one alike.
  (The grammar takes more than the parser does, as an editor must: what the parser refuses isn't compared.) <!-- checked: tests/parse_agreement.py "policy the parser refuses is not compared" -->
- **Random data**: [`tests/difftest.py`](../core/tests/difftest.py) fills six policies' tables with random
  rows and makes a hundred random changes to each (moves, links, loops, groups inside groups, inheritance
  through two types at once, shares that start and end, ids that change, `TRUNCATE`, several statements in
  one transaction). After each change,
  `authz.can`, `authz.list`, `authz.explain`, `authz.who`, what row-level security lets each user read, every
  rule's condition and the masked views are compared with the evaluator's answer. `authz.explain` is asked by
  each user too: about a row they can't see, it must say nothing more than about a missing one. <!-- checked: tests/difftest.py "explain self"; tests/adversarial.sh "explaining a folder she can't see (but may break the glass on) reads as a missing one" -->
  So is
  `authz.explain_rule`: nothing about such a row, and on the others, for an update or a delete, the rules' own
  answer.
- **Random policies**: [`tests/genpolicy.py`](../core/tests/genpolicy.py) writes policies at random, with
  their tables and data, and checks them the same way: twelve on each full run, and a hundred with new seeds
  every night. A third of them name their tables and columns as an app's own may be: with capitals, with words
  SQL reserves (`select`, `order`, `user`), or as long as Postgres allows. Every name the compiler writes into
  SQL is then one it must quote. Nearly half give their keys another type than `bigint`: `int`, `text` or
  `uuid`; some key their rows by two columns, an org's and the row's own. Some put two types' rows inside
  each other, so that one recursion runs through both. Some have caveats, which some of their shares carry,
  and some scopes, with which one user is asked again after each change. Some mask a column in a view, and some
  give permissions by custom roles, or share by links.
- **Random worlds**: the two above compare answers in one setting: plain tables, and the owner's session
  switched to the app role. [`tests/around.py`](../core/tests/around.py) takes the random policies again and
  draws what is around each one too: tables that are partitioned, or have a table that inherits from them;
  default privileges of the owner's; a login role that is a member of the app role and signs each user in;
  planner settings, a read-only transaction, a search path that starts with a schema of decoys; and, halfway,
  something changed behind the policy's back (a grant on rowstile's own tables, row-level security turned
  off, a new partition). <!-- checked: tests/around.py "class World"; tests/around.py "read-only reads" --> Besides the comparisons above, asked in that session, it tries real writes as the
  app role on every row and undoes them, shares too (against who may share and what the relation's
  `shared if` says of the share), checks that no share outlives its row, that a role the policy
  doesn't name gets nothing, and that `authz.lint()` reports what changed and `rowstile apply` puts it right.
  A few on every run, sixty with new seeds every night.
- **Answers worked out by hand**: `HandAnswers` in [`tests/unit_test.py`](../core/tests/unit_test.py) gives
  the evaluator small policies and worlds whose answers were worked out from
  [the language's reference](reference/language.md), by hand: `not` and parentheses, inheritance stopped by
  a condition or by a type's `where`, a suspended user, groups inside groups and in a loop, each kind of
  subject (`user:*`, `anyone`, a link, a service), a deny inside inheritance, folders and projects inside each
  other, custom roles with and without `from`, NULL in conditions.
- **Conditions, against Postgres**: `rowstile prove` and the review read simple conditions (`{not archived}`,
  `{size > 10}`, `{owner_id = authz.uid()}`) themselves, in worlds they make up. difftest never does: it
  asks the database. <!-- unchecked: how difftest is written, which reading it shows -->
  So [`tests/conditions_test.py`](../core/tests/conditions_test.py) makes conditions up at
  random over columns of each kind, and each one the evaluator reads itself must get Postgres's answer on
  every row: three thousand on every run, fifty thousand with new seeds every night.

## The boundary

The app role is the one rowstile doesn't trust ([the threat model](threat-model.md) says who is trusted with
what).

- [`tests/adversarial.sh`](../core/tests/adversarial.sh) logs in as the app role and tries to read hidden
  rows (by id, with `COPY`, through leaky functions and prepared statements), to reach rowstile's own tables
  and functions, to turn row-level security off, to change or share what it may not, and to learn whether
  a hidden row exists. It also checks the catalog each policy leaves: which functions run with their owner's
  rights, and that the app role may call the API and nothing else.
- [`tests/sessions.sh`](../core/tests/sessions.sh) checks that the app role can't choose who is signed in
  by setting a variable, widen an API key's scopes, or reuse a sign-in in another transaction or connection. <!-- checked: tests/sessions.sh "changing authz.user_id after signing in is an error"; tests/sessions.sh "clearing its scopes is an error, not a way to write"; tests/sessions.sh "a signature from an earlier transaction is refused in the next one"; tests/sessions.sh "and one from another connection too" -->
- [`tests/identity.sh`](../core/tests/identity.sh) covers API keys and JWTs: a bad signature, an expired
  token, one without an expiry, `alg: none`.
- Every refusal the runtime can raise is asked for by its words by some check, not only by its error code (two
  guards that answer with the same code look alike): `Guards` in
  [`tests/unit_test.py`](../core/tests/unit_test.py) fails when one isn't. <!-- checked: tests/unit_test.py "test_each_guard_is_asked_for_by_its_words" -->

## Trees, under load

Inherited permissions are kept in tables by triggers, and those tables must match the tree at every commit. <!-- checked: tests/races.sh "50 races, inheritance tables exact after each"; tests/stress.sh "the inheritance tables match a rebuild" -->
[`tests/races.sh`](../core/tests/races.sh) races every pair of tree writes in two sessions at each isolation
level, and [`tests/stress.sh`](../core/tests/stress.sh) lets sixteen clients write one tree at once; after
each, the tables are compared with a rebuild, and the biggest moves on the tree they leave are timed alone.

## Proofs in small worlds

`rowstile prove` takes a policy's invariants ("never: someone views a workspace of an organisation they aren't
in") and looks for a small world in which one fails: a few users, a few rows, every way of linking them, and
at each size worlds where every condition holds on every row or on none (a counterexample that needs several
at once is rare in worlds drawn row by row); then worlds where most links hold (a long `and` of them), and
chains of objects one link longer than the policy reads deep. <!-- checked: tests/confidence_test.py "an invariant the policy doesn't guarantee: exit 1, and the smallest counterexample"; tests/unit_test.py "test_prove_finds_a_counterexample_that_needs_conditions_at_once"; tests/unit_test.py "test_prove_tries_what_a_counterexample_may_need" -->
It answers with the smallest counterexample, or
says that there is none among the worlds tried. <!-- checked: tests/unit_test.py "test_prove_finds_the_smallest_counterexample"; tests/unit_test.py "test_prove_says_when_none_is_found" -->
It is a search,
not a proof for worlds of any size, and it reads the policy, not your data.

## What ships, and what the docs say

- **Migrations**: for each kind of policy change, [`tests/migrate_test.py`](../core/tests/migrate_test.py)
  checks that the migration leaves exactly what applying the new policy whole leaves: functions and their
  privileges, views, triggers, policies, the inheritance rows.
- **Upgrades**: [`tests/upgrade.sh`](../core/tests/upgrade.sh) installs the release before this one from PyPI
  and makes the docs app's database with it, each way an app may have one: pushed to, applied, set up by
  migrations. The app shares, makes an API key and asks for access. This version then upgrades each database as
  the app would, and each holds what applying this version on a new database leaves, down to the columns of the
  tables rowstile keeps across applies; the policy's tests and the scenario pass, and what the app made before
  still works. <!-- checked: tests/upgrade.sh "it holds what applying this version on a new database leaves"; tests/upgrade.sh "the API key made before still signs dave in" -->
- **The parser**: [`tests/fuzz_parser.py`](../core/tests/fuzz_parser.py) feeds it thousands of broken
  policies; each is accepted, or refused with a line number, never a crash. <!-- checked: tests/fuzz_parser.py "refused without a line number" -->
- **The docs**: the getting-started guide runs as written, every line the cookbook shows is in a policy that
  is applied and tested, and every line of code on the stack pages is in an app whose tests pass. <!-- checked: tests/docs_test.sh "every block of the guide runs"; tests/cookbook.sh "every line its page shows is in its tested policy or tests"; tests/unit_test.py "test_every_line_is_in_a_tested_app" -->
  Every block of code in the reference runs too, or says why it can't, and each promise these pages make, and
  the reference's, names the check that holds it in a comment readers don't see, or says why none does. <!-- checked: tests/reference.sh "every block of the reference runs, or says why not"; tests/unit_test.py "test_every_promise_says_what_holds_it"; tests/unit_test.py "test_each_tag_names_checks_that_are_there" -->
- **Three versions of Postgres**: every suite on PostgreSQL 16 for each change, and on 17 and 18
  [every night](../.github/workflows/nightly.yml), with the races, the stress test and the random policies.
- **The suites themselves**: each passes as many checks as
  [`tests/check_counts.txt`](../core/tests/check_counts.txt) says, no fewer and no more, or the run fails. A
  suite that stopped checking something (a glob that matches nothing, a loop over an empty list) can't stay
  green unseen. <!-- checked: tests/unit_test.py "test_fewer_or_more_is_said"; tests/unit_test.py "test_each_suite_written_is_one_run_tests_records" -->

## What a review of every file found

Before the first public release, every file was read with one question: what does the documentation promise
here, and does a test hold the code to it? It found 153 things to fix. Eleven were wrong access: a row seen or
written that the policy didn't allow, or refused when it allowed it. <!-- unchecked: a record of what a review found -->
Ten of those eleven were found by reading,
one by the random policies. All 153 are fixed.

Then the suites themselves were tested: 44 mistakes were put into the compiler on purpose, one at a time. The
suites caught 42. The two they missed got tests.

That was done again in October 2026, with twenty more mistakes for what had been added since and for checks no
mistake had been tried on: 64 in all. The suites caught 60. Each of the four they missed got a test, which
fails with the mistake put back.

Then the reference evaluator, whose answers the suites take as the truth: 40 mistakes put into it. The suites
caught 26. One of the 14 they missed can't change an answer: the fixed point stopping when a set of ids
shrinks, which none ever does. <!-- unchecked: a record of what a run of mistakes put in on purpose found -->
The others were answers nothing else asked for (an assignment of another
org's custom role, `signed_in` for a service, the simple conditions), and how `prove` and the review make up
and shrink their worlds. The answers worked out by hand and the comparison of conditions with Postgres came
of that. With them, and four more mistakes for what they changed, the suites catch each of the 44 but that
one.

## When something is found

Vulnerabilities are reported privately ([SECURITY.md](../SECURITY.md)) and published as advisories once
fixed. There has been one so far: GHSA-6g93-673q-c29f, in `@rowstile/prisma`, found by the project itself, and
fixed and published the same day.

## What this doesn't cover

- An audit by someone outside the project. There has been none.
- The limits [the threat model](threat-model.md#known-limits-accepted) accepts: side channels such as
  `EXPLAIN ANALYZE` row counts, tables without rules, `SECURITY DEFINER` functions an app adds.
- Managed Postgres services other than the two [it was tried on](managed-postgres.md), and macOS.
- Your policy. rowstile enforces what the policy says; whether it says what you meant is what its tests, its
  invariants and [the review of each change](reference/review.md) are for.
