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
- **A third evaluator**: [`tests/third.py`](../core/tests/third.py) was written from the language's reference
  alone and imports nothing of the compiler's or the reference evaluator's. It reads each policy through the
  editors' grammar, writes what the page says as Datalog rules, run by an engine of its own
  ([`tests/datalog.py`](../core/tests/datalog.py)), and reads a world as rows, shares and custom roles.
  [`tests/third_compare.py`](../core/tests/third_compare.py) holds the two evaluators to each other in many worlds
  per policy: each relation and permission for each one who signs in, a share link's holder and nobody, the rows
  each rule allows, who breaks each invariant. On each push: every policy in the repository and the cases worked
  out by hand from the page (94 policies, 3,724 worlds, about 250,000 answers, in 40 seconds); each night, a
  thousand random policies with new seeds too (about 7 million answers). A disagreement is made as small as it can be and
  printed with the paragraphs of the page it concerns. The two share one input: which rows each condition holds
  on, as neither runs SQL.
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
- **Random policies**: [`tests/genpolicy.py`](../core/tests/genpolicy.py) writes policies at random, with their
  tables and data, and checks them the same way: on each full run, the few policies, of a thousand, in which
  every two of the shapes below meet (sixteen), and a hundred with new seeds every night. A third of them name
  their tables and columns as an app's own may be: with capitals, with words SQL reserves (`select`, `order`,
  `user`), with a quote or an accent, or as long as Postgres allows. Every name the compiler writes into SQL is
  then one it must quote.
  Nearly half give their keys another type than `bigint`: `int`, `text` or `uuid`; some key their rows by two
  columns, an org's and the row's own. Some put two types' rows inside each other, so that one recursion runs
  through both. Some have caveats, which some of their shares carry, and some scopes, with which one user is
  asked again after each change. Some mask a column in a view, and some give permissions by custom roles, or
  share by links; some rules say they are checked before or after the change. A quarter are written in two
  files, one including the other.
- **Random worlds**: the two above compare answers in one setting: plain tables, and the owner's session
  switched to the app role. [`tests/around.py`](../core/tests/around.py) takes the random policies again and
  draws what is around each one too, under the names and with the keys the policy drew (the awkward names,
  `uuid` and `text` keys, keys of two columns): tables that are partitioned, or have a table that inherits
  from them (the governed tables, the users' table, the link tables); a database in the C locale, in LATIN1,
  or in Turkish, where `lower('I')` is not `i`;
  default privileges of the owner's; a login role that is a member of the app role and signs each user in,
  with `authz.act_as` or with the user's own API key or JWT (limited to a scope, for the one asked with a scope);
  planner settings, a read-only transaction, a search path that starts with a schema of decoys; and, halfway,
  something changed behind the policy's back (a grant on rowstile's own tables, row-level security turned
  off, a new partition). <!-- checked: tests/around.py "class World"; tests/around.py "read-only reads" --> Besides the comparisons above, asked in that session, it tries real writes as the
  app role on every row and undoes them (updates, deletes, and inserts of rows like the ones there), shares too (against who may share and what the relation's
  `shared if` says of the share), checks that no share outlives its row, that a role the policy
  doesn't name gets nothing, and that `authz.lint()` reports what changed and `rowstile apply` puts it right.
  A few on every run; on the full run the twenty worlds, of a thousand seeds, in which every two of those
  features meet; sixty with new seeds every night.
- **Every small policy**: a random draw can wait long for the one small policy, and the one small world, that a
  mistake needs. [`tests/small.py`](../core/tests/small.py) lists every policy of the core language up to a size
  instead, each once (two that differ in their names alone, or in the order of an `or`'s or an `and`'s parts, are
  one): the user type with or without a `where`; one object type, or two, the second naming the first; relations
  from each kind of source (a column, a link table or shares; to users, to `user:*`, to `anyone`, to a group's
  members; a `parent` from a column, from a link table or from a pair of columns naming two types; an `up`); one
  or two permissions a type, each of up to three parts joined by `or`, `and` and `and not`: inheritance, and
  denies. Up to six sources, parts and `where`s there are 51,155, and 19,828 of seven with a deny, the smallest a
  deny can be; the compiler takes 29,738 of them. For each, the reference evaluator answers in every world of
  one and two rows of each type (up to 400 of each), and in some of three; in each, the same policy written
  another way (its names swapped, its parts turned round) must get the same answers. Then each part of the policy
  is made wrong in turn (held by nobody or by anyone, an `and` for an `or`, a `not` left out, a link read the other
  way round, inheritance one step deep), and the few worlds that tell every such part apart are loaded as rows (two
  or three a policy): forty policies applied as one, and difftest's checks hold every answer of the database's to
  the evaluator's. Each push checks those up to size three and the denies of four (96); each night, a seventh of
  them all; each week, the whole list.
- **Answers worked out by hand**: each paragraph of [the language's reference](reference/language.md) that says
  who may do what, given a policy and rows, carries an anchor readers don't see (40 of them), and each anchor has
  a case whose answers were worked out from that paragraph, by hand, and written down before anything ran.
  `HandAnswers` in [`tests/unit_test.py`](../core/tests/unit_test.py) gives the reference evaluator the 39 it can
  answer: small policies and worlds, `not` and parentheses, inheritance through any mix of sources and stopped by a
  condition or a type's `where`, a suspended user, groups inside groups and in a loop, each kind of subject (`user:*`,
  `anyone`, a link, a service), a relation followed to a user's own permission, a deny inside inheritance, custom
  roles with and without `from` and a folder moved to another org, NULL in conditions, an invariant asked as a
  service and as nobody. [`tests/hand_answers.sh`](../core/tests/hand_answers.sh) gives the database the 25 that are
  its alone to answer (143 checks), as named tests in `tests/hand/`: a share that expires or starts later, a caveat,
  `shared if`, who may share, a write checked before and after, column rules, an insert, a masked column, `this` and a
  bare column in a subquery, conditions read with the policy's rights, a polymorphic pair naming a type the policy
  doesn't have, a key of two columns. A unit test fails when an anchor has no case, or a case names none. <!-- checked: tests/unit_test.py "test_every_answering_paragraph_has_a_case" -->
- **Conditions, against Postgres**: `rowstile prove` and the review read simple conditions (`{not archived}`,
  `{size > 10}`, `{owner_id = authz.uid()}`) themselves, in worlds they make up. difftest never does: it
  asks the database. <!-- unchecked: how difftest is written, which reading it shows -->
  So [`tests/conditions_test.py`](../core/tests/conditions_test.py) makes conditions up at
  random over columns of each kind, and each one the evaluator reads itself must get Postgres's answer on
  every row: three thousand on every run, fifty thousand with new seeds every night.
- **The review, against the database**: `rowstile review` says whether a pull request that rewrites permissions
  grants the same as before, from small worlds made up for the two policies; it reads no database for that.
  [`tests/rewrites.py`](../core/tests/rewrites.py) holds that verdict against one. It rewrites a permission or a
  select rule of random policies, in ways that change nothing by what `or`, `and` and `not` mean (its parts
  turned round, a part said twice, a part absorbed) and in ways that may (an `and` for an `or`, a part dropped,
  one relation in place of another). Where the review says "grants the same", the database's own answers on the
  policy's data, for everyone, before and after the rewrite, are the same too; and a rewrite that changes
  nothing is given no difference by either.
- **Changes that change nothing**: a policy written another way says the same, and data renumbered is the same
  data. [`tests/invariance.py`](../core/tests/invariance.py) writes each random policy three other ways: its
  blocks, the lines in each and the operands of every `or` and `and` in another order; its blocks spread over
  files it includes, one included from a folder below; its expressions broken over lines, then formatted by
  `rowstile fmt`. Each compiles to the same objects, read back as migrations read them, each made by the same
  SQL but for the order things come in, the lines they are on and the names the compiler numbers as it meets
  them. Each is applied, and every answer on the policy's data is the same: lists (whole, and in pages of
  two), checks, the rows each select rule shows, who holds what, why a write would be refused, the
  invariants. <!-- checked: tests/invariance.py "the same answers" --> Then every key of each type is replaced by another drawn at random, in the rows, the link
  tables, the shares and the custom roles, and the answers are the same, mapped back. One policy and the nine
  fixed policies' SQL on every run; eight policies, and the fixed policies' answers, on the full run; twenty
  with new seeds every night.

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
  When `authz.who`, `authz.explain`, `authz.who_among` or `authz.check_invariants` fail half way, signed in as
  someone else, the transaction goes on signed in as before: the same settings and signature, the same rows
  seen and changed. <!-- checked: tests/sessions.sh "who fails half way: its error, and the same user signed in, seeing and changing the same"; tests/sessions.sh "explain for user 3 fails: the same user signed in"; tests/sessions.sh "who_among fails at user 3: the same user signed in"; tests/sessions.sh "check_invariants fails at user 3: the same user signed in" -->
- [`tests/identity.sh`](../core/tests/identity.sh) covers API keys and JWTs: a bad signature, an expired
  token, one without an expiry, `alg: none`.
- Every refusal the runtime can raise is asked for by its words by some check, not only by its error code (two
  guards that answer with the same code look alike), and words several functions raise (`no type ... in the
  policy`) beside the name of each function of the API that raises them: `Guards` in
  [`tests/unit_test.py`](../core/tests/unit_test.py) fails when one isn't. <!-- checked: tests/unit_test.py "test_each_guard_is_asked_for_by_its_words" -->

## Trees, under load

Inherited permissions are kept in tables by triggers, and those tables must match the tree at every commit. <!-- checked: tests/interleave.py "inheritance tables exact after each"; tests/stress.sh "the inheritance tables match a rebuild" -->
[`tests/interleave.py`](../core/tests/interleave.py) runs two writes to a folder tree in two sessions (a folder
created, moved, linked, unlinked, deleted, given a new id, shared, unshared): each of the 36 pairs in every order
of their steps that Postgres allows (a read, the write, the commit: 558 of the 720 orders written out), with each
session at each isolation level, 5,022 schedules. It sends one step at a time and asks Postgres which session
waits for a lock, so no order depends on timing. After each, the tables are compared with a rebuild, what
`authz.list` says with the reference evaluator, and in SERIALIZABLE the rows with the two transactions run one
after the other. In READ COMMITTED no write ever needs a retry. <!-- checked: tests/interleave.py "none needing a retry" -->
Each change runs it in READ COMMITTED, and every night at all three levels on 16, 17 and 18.
[`tests/stress.sh`](../core/tests/stress.sh) lets sixteen clients write one tree at once; after it, the tables
are compared with a rebuild, and the biggest moves on the tree it leaves are timed alone.

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
  Every night it does the same from every release on PyPI (six alphas today), and each also makes a world of
  data the way the random checks do: shares in every state, links, moves, through that release's own triggers
  and `authz.share`. After the upgrade, by `reapply` and by the next migration, `authz.can` answers every user,
  object and permission (1,277 checks) as on a new database with the same rows, all of difftest's questions get
  the reference evaluator's answers, and the catalog and the inheritance rows are the new database's. <!-- checked: tests/upgrade_world.py "answers as on a new database"; tests/upgrade.sh "it holds what applying this version on a new database with its rows leaves" -->
- **Cut half way**: [`tests/interrupt.py`](../core/tests/interrupt.py) runs `rowstile apply` (on a new database
  and over a policy), `push`, `reapply --force` and both migrations of a change that builds an inheritance table
  beside the one in use, on the docs app, and cuts each after one of its statements: the server ends the session,
  or the connection is closed under it. After each cut the command says it lost the database (exit 2), the
  database is as it was before the run, and the app, reading as the app role just before the cut and after it,
  gets the old policy's answers, whole; after some, the next run leaves what an uncut one does. <!-- checked: tests/interrupt.py "after each cut, the database is as it was"; tests/interrupt.py "the app read the old policy's answers, whole" -->
  Between the two migrations the old policy is in force. <!-- checked: tests/interrupt.py "between a migration's two: the old policy in force" -->
  Each night, after every one of their 1,923 statements (about 25 minutes); on each push, ten cuts of each. The real
  command is also ended while one of its statements waits for a lock, and stopped by `statement_timeout`. Every
  night the soak cuts the first apply of twenty-five other policies, random ones among them, where its seed says.
- **The parser**: [`tests/fuzz_parser.py`](../core/tests/fuzz_parser.py) feeds it thousands of broken
  policies; each is accepted, or refused with a line number, never a crash. <!-- checked: tests/fuzz_parser.py "refused without a line number" -->
- **The docs**: the getting-started guide runs as written, every line the cookbook shows is in a policy that
  is applied and tested, and every line of code on the stack pages is in an app whose tests pass. <!-- checked: tests/docs_test.sh "every block of the guide runs"; tests/cookbook.sh "every line its page shows is in its tested policy or tests"; tests/unit_test.py "test_every_line_is_in_a_tested_app" -->
  Every block of code in the reference runs too, or says why it can't, and each promise these pages make, and
  the reference's, names the check that holds it in a comment readers don't see, or says why none does. <!-- checked: tests/reference.sh "every block of the reference runs, or says why not"; tests/unit_test.py "test_every_promise_says_what_holds_it"; tests/unit_test.py "test_each_tag_names_checks_that_are_there" -->
- **Three versions of Postgres**: every suite on PostgreSQL 16 for each change, and on 17 and 18
  [every night](../.github/workflows/nightly.yml), with every order of two tree writes, the stress test and the
  random policies.
- **The suites themselves**: each passes as many checks as
  [`tests/check_counts.txt`](../core/tests/check_counts.txt) says, no fewer and no more, or the run fails. A
  suite that stopped checking something (a glob that matches nothing, a loop over an empty list) can't stay
  green unseen. <!-- checked: tests/unit_test.py "test_fewer_or_more_is_said"; tests/unit_test.py "test_each_suite_written_is_one_run_tests_records" -->
- **What the database runs**: [every night](../.github/workflows/nightly.yml) the suites run on PostgreSQL 16 with
  plpgsql_check's profiler on (in the test image: rowstile itself needs no extension), and
  [`tests/coverage_report.py`](../core/tests/coverage_report.py) lists each statement and branch of rowstile's
  PL/pgSQL that no suite runs, by kind of function, each `RAISE` first. It reads each function's source to know
  which statements begin which branch, and holds that reading to plpgsql_check's own figures. <!-- checked: tests/unit_test.py "test_which_statements_begin_which_arm" -->
  On 14 October 2026 the suites ran 2,926 of 4,551 statements (64%) and 1,634 of 3,046 branches (54%); 26
  `RAISE` statements in functions they call were not reached. Checks for each followed: the same day, with the
  policy part run again, 3,016 of 4,698 statements (64%) and 1,695 of 3,194 branches (53%), and every `RAISE`.
  A rule on columns counts once for each form of its refusal (a key of one column, of several), not once per
  policy. A function Postgres counts as called whose statements the profiler read none of is listed: a GRANT, a
  REVOKE or an apply after the calls made its catalog row anew, and the counts with it. <!-- checked: tests/unit_test.py "test_statements_lost_with_the_catalog_row" -->

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
fixed. There have been six so far, each found by the project itself: GHSA-6g93-673q-c29f, in `@rowstile/prisma`,
fixed and published the same day, and five fixed in 0.1.0-alpha.7 and published the day it came out. Two of
those are rated high: a rule on a column that was not checked on the rows of a partition made since the last
apply (GHSA-h92j-8v4p-93hc), and the command's Postgres client, which sent the password before it honoured
`channel_binding=require` (GHSA-g2rq-h47r-5v2c). [The advisories](https://github.com/rowstile/rowstile/security/advisories)
are all listed there.

## What this doesn't cover

- An audit by someone outside the project. There has been none.
- The limits [the threat model](threat-model.md#known-limits-accepted) accepts: side channels such as
  `EXPLAIN ANALYZE` row counts, tables without rules, `SECURITY DEFINER` functions an app adds.
- Managed Postgres services other than the two [it was tried on](managed-postgres.md), and macOS.
- Your policy. rowstile enforces what the policy says; whether it says what you meant is what its tests, its
  invariants and [the review of each change](reference/review.md) are for.
