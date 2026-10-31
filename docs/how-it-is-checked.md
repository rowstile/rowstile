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
  read every policy in the repository, two hundred random ones and the small policies up to size four (1,379, each
  written two ways: as listed, and with its names swapped and its parts turned round), and compares what they
  read: the types, each relation's sources, the permissions with their grouping, the rules, each line of the tests
  part by part, and of a policy that includes a file, its own lines. They read each one alike.
  Each night they read all 130,431 small policies, and each written another way where that is a policy. <!-- checked: tests/unit_test.py "test_small_policies_written_two_ways" -->
  (The grammar takes more than the parser does, as an editor must: what the parser refuses isn't compared.) <!-- checked: tests/parse_agreement.py "policy the parser refuses is not compared" -->
- **Random data**: [`tests/difftest.py`](../core/tests/difftest.py) fills six policies' tables with random
  rows and makes random changes to each (moves, links, loops, groups inside groups, inheritance
  through two types at once, shares that start and end, ids that change, `TRUNCATE`, several statements in
  one transaction): fifteen on each push, a hundred in the full run, and five hundred with a new seed in each
  night's soak. After each change,
  `authz.can`, `authz.list`, `authz.explain`, `authz.who`, what row-level security lets each user read, every
  rule's condition and the masked views are compared with the evaluator's answer. One user a change, in turn,
  is also asked `authz.list` in pages of two: the pages, one after another, must be the whole list in key order,
  as the database orders the key (a text key by its collation). <!-- checked: tests/difftest.py "in key order (as the database orders it)" --> `authz.explain` is asked by
  each user too: about a row they can't see, it must say nothing more than about a missing one. <!-- checked: tests/difftest.py "explain self"; tests/adversarial.sh "explaining a folder she can't see (but may break the glass on) reads as a missing one" -->
  So is
  `authz.explain_rule`: nothing about such a row, and on the others, for an update or a delete, the rules' own
  answer. A quarter of the changes aim at the parts of the policy (a source, a part of a permission, a depth of
  inheritance) that haven't yet decided an answer. The run ends with a report of the parts that never did, whose
  SQL was never judged there ([`tests/decisions.py`](../core/tests/decisions.py)): it is for people to read, in
  the run's log, and fails nothing. <!-- unchecked: a report in the log, which no check reads -->
- **Random policies**: [`tests/genpolicy.py`](../core/tests/genpolicy.py) writes policies at random, with their
  tables and data, and checks them the same way: in the full run each night, the few policies, of a thousand, in which
  every two of the shapes below meet (twenty-three), and a hundred with new seeds every night. A third of them name
  their tables and columns as an app's own may be: with capitals, with words SQL reserves (`select`, `order`,
  `user`), with a quote or an accent, or as long as Postgres allows. Every name the compiler writes into SQL is
  then one it must quote.
  Nearly half give their keys another type than `bigint`: `int`, `text` or `uuid`; some key their rows by two
  columns, an org's and the row's own. Half of those with `text` keys make them words, not numerals: with a
  space, quotes of both kinds, capitals, accents, a dotted and a dotless `i`, one the start of another, in an
  order each collation has its own of (`B` comes before `ab` in the C locale, after it in English). A key folded
  to lower case, or compared in another collation than the database's, then changes an answer. Some put two types' rows inside each other, so that one recursion runs
  through both. Some have caveats, which some of their shares carry, and some scopes, with which one user is
  asked again after each change. Some mask a column in a view, and some give permissions by custom roles, or
  share by links; some rules say they are checked before or after the change, some are on two columns. Some
  share by the type's `share`, to every service (`bot:*`), or make a share a link of a tree; some link tables
  name the type of the row they link to; some permissions read who is signed in, or another table. A quarter are
  written in two files, one including the other.
- **Random worlds**: the two above compare answers in one setting: plain tables, and the owner's session
  switched to the app role. [`tests/around.py`](../core/tests/around.py) takes the random policies again and
  draws what is around each one too, under the names and with the keys the policy drew (the awkward names,
  `uuid` and `text` keys, text keys that are words, keys of two columns): tables that are partitioned, or have a table that inherits
  from them (the governed tables, the users' table, the link tables); a database in the C locale, in LATIN1,
  or in Turkish, where `lower('I')` is not `i`;
  default privileges of the owner's; a login role that is a member of the app role and signs each user in,
  with `authz.act_as` or with the user's own API key or JWT (limited to a scope, for the one asked with a scope);
  planner settings, a read-only transaction, a search path that starts with a schema of decoys; and, halfway,
  something changed behind the policy's back (a grant on rowstile's own tables, row-level security turned
  off, a new partition). <!-- checked: tests/around.py "decoys first on the search path"; tests/around.py "read-only reads" --> Besides the comparisons above, asked in that session, it tries real writes as the
  app role on every row and undoes them (updates, deletes, and inserts of rows like the ones there), shares too (against who may share and what the relation's
  `shared if` says of the share), checks that no share outlives its row, that a role the policy
  doesn't name gets nothing, and that `authz.lint()` reports what changed and `rowstile apply` puts it right.
  A few on every run; in the full run each night the two dozen or so worlds, of a thousand seeds, in which every
  two of those features meet (words for keys in the Turkish database among them); sixty with new seeds every night.
- **Every small policy**: a random draw can wait long for the one small policy, and the one small world, that a
  mistake needs. [`tests/small.py`](../core/tests/small.py) lists every policy of the core language up to a size
  instead, each once (two that differ in their names alone, or in the order of an `or`'s or an `and`'s parts, are
  one): the user type with or without a `where`; one object type, or two, the second naming the first; relations
  from each kind of source (a column, a link table or shares; to users, to `user:*`, to `anyone`, to a link, to a
  group's members; a `parent` from a column, from a link table, or from a pair of columns or a link table naming
  two types; an `up` from a column, a link table or shares); one or two permissions a type, each of up to three
  parts joined by `or`, `and` and `and not`, or one of `signed_in`, `anyone` and `nobody` alone: inheritance, and
  denies. Up to six sources, parts and `where`s there are 94,599, and 35,832 of seven with a deny (the whole of
  size seven is out of reach). For each, the reference evaluator answers in every world of
  one and two rows of each type (up to 400 of each), and in some of three; in each, the same policy written
  another way (its names swapped, its parts turned round) must get the same answers. Then each part of the policy
  is made wrong in turn (held by nobody or by anyone, an `and` for an `or`, a `not` left out, a link read the other
  way round, inheritance one step deep), and the few worlds that tell every such part apart are loaded as rows (two
  or three a policy): forty policies applied as one, and difftest's checks hold every answer of the database's to
  the evaluator's. Each push checks those up to size three and the denies of four (122); each night, a fourteenth
  of them all; every two weeks, the whole list.
- **Answers worked out by hand**: each paragraph of [the language's reference](reference/language.md) that says
  who may do what, given a policy and rows, carries an anchor readers don't see, and each anchor has
  a case whose answers were worked out from that paragraph, by hand, and written down before anything ran.
  `HandAnswers` in [`tests/unit_test.py`](../core/tests/unit_test.py) gives the reference evaluator the cases it can
  answer: small policies and worlds, `not` and parentheses, inheritance through any mix of sources and stopped by a
  condition or a type's `where`, a suspended user, groups inside groups and in a loop, each kind of subject (`user:*`,
  `anyone`, a link, a service), a relation followed to a user's own permission, a deny inside inheritance, custom
  roles with and without `from` and a folder moved to another org, NULL in conditions, an invariant asked as a
  service and as nobody. [`tests/hand_answers.sh`](../core/tests/hand_answers.sh) gives the database those that are
  its alone to answer, as named tests in `tests/hand/`: a share that expires or starts later, a caveat,
  `shared if`, who may share, a write checked before and after, column rules, an insert, a masked column, `this` and a
  bare column in a subquery, conditions read with the policy's rights, a polymorphic pair naming a type the policy
  doesn't have, keys of two columns and keys that are text, a group named by a permission (`team#manage`), a
  relation declared again for another type. A unit test fails when an anchor has no case, or a case names none. <!-- checked: tests/unit_test.py "test_every_answering_paragraph_has_a_case" -->
- **Conditions, against Postgres**: `rowstile prove` and the review read simple conditions (`{not archived}`,
  `{size > 10}`, `{owner_id = authz.uid()}`) themselves, in worlds they make up. difftest never does: it
  asks the database. <!-- unchecked: how difftest is written, which reading it shows -->
  So [`tests/conditions_test.py`](../core/tests/conditions_test.py) makes conditions up at
  random over columns of each kind, some named in quotes, with decimals among the numbers, and each one the
  evaluator reads itself must get Postgres's answer on every row: three thousand on every run, fifty thousand with
  new seeds every night. Two of the columns tell texts apart otherwise than byte by byte: one under a collation
  that ignores case, accents and punctuation, and a `char(3)`. A made-up row holds a text the conditions name or
  another, so two texts a column may hold as one value are left to the database, and the run asks Postgres
  which texts are one value, two by two, under five such collations and as eight types (a date, a uuid, a
  tsvector...): each such pair must be one the evaluator leaves to the database.
- **The review, against the database**: `rowstile review` says whether a pull request that rewrites permissions
  grants the same as before, from small worlds made up for the two policies; it reads no database for that.
  [`tests/rewrites.py`](../core/tests/rewrites.py) holds that verdict against one. It rewrites a permission or a
  select rule of random policies, in ways that change nothing by what `or`, `and` and `not` mean (its parts
  turned round, a part said twice, a part absorbed) and in ways that may (an `and` for an `or`, a part dropped,
  one relation in place of another). Where the review says "grants the same", the database's own answers on the
  policy's data, for everyone, before and after the rewrite, are the same too; and a rewrite that changes
  nothing is given no difference by either, and is refused by the compiler only for a shape the language limits
  (how a permission recurses or inherits, where `roles` is said). <!-- checked: tests/rewrites.py "it changes nothing, and the compiler refuses it" --> The first difference the review shows for each policy is replayed in a
  database: the small world it was found in, made as rows, gives the user the answers the review says, under the
  policy and under the rewrite. A condition the review doesn't read (a subquery) holds where the rows say,
  which may not be where the world says. So what the rows hold is read back: they must hold the world but
  for such conditions, and the database must answer as the reference evaluator does on them.
- **Changes that change nothing**: a policy written another way says the same, and data renumbered is the same
  data. [`tests/invariance.py`](../core/tests/invariance.py) writes each random policy three other ways: its
  blocks, the lines in each and the operands of every `or` and `and` in another order; its blocks spread over
  files it includes, one included from a folder below; its expressions broken over lines, then formatted by
  `rowstile fmt`. Each compiles to the same objects, read back as migrations read them, each made by the same
  SQL but for the order things come in, the lines they are on and the names the compiler numbers as it meets
  them (not a rule on columns: Postgres fires a table's triggers in the order of their names, so each is named
  after its rule). The SQL is read as SQL, not as a set of words: the operands of an `or` or an `and`, the items
  of a list and statements that don't read what another sets may come in another order, but an `and` in place of
  an `or`, or an operand moved across one, is another SQL. Each is applied, and every answer on the policy's data is the same: lists (whole, and in
  pages of two), checks, the rows each select rule shows, who holds what, why a write would be refused, which
  rule on columns refuses an update two of them guard, the invariants. <!-- checked: tests/invariance.py "the same answers" --> Then every key of each type is replaced by another drawn at random, in the rows, the link
  tables, the shares and the custom roles, and the answers are the same, mapped back. One policy and the nine
  fixed policies' SQL on every run; eight policies, and the fixed policies' answers, in the full run each night; twenty
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
[`tests/interleave.py`](../core/tests/interleave.py) runs two writes to a tree in two sessions, on four trees:
the docs app's folders (a folder created, moved, linked, unlinked, deleted, given a new id, shared, unshared); a
tree of two types whose condition reads another table (folders and projects); a tree on a partitioned table,
whose links and the table its condition reads each have a table that inherits from them; and a tree of two types
linked by their own columns, whose condition reads the tree's own table. Each of the 88 pairs runs in every order
of its steps that Postgres allows (a read, the write, the commit: 1,286 of the 1,760 orders written out), with
each session at each isolation level, 11,574 schedules. It sends one step at a time and asks Postgres which session
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
A counterexample is the world as you would make it: its rows, its links and shares (one to `user:*` says so), the
custom roles given, the values its conditions read, and the rows each type's `where` keeps. <!-- checked: tests/unit_test.py "test_a_world_says_what_each_link_and_role_names"; tests/unit_test.py "test_a_counterexample_says_which_rows_the_types_where_keeps"; tests/unit_test.py "test_a_link_to_every_user_reads_as_one" -->
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
  The release before is one from 0.1.0-beta.1 on: the beta started afresh, and no alpha is upgraded from. Until
  a release after the beta is out, the suite says there is nothing to upgrade from, and skips. <!-- checked: tests/unit_test.py "test_the_alphas_are_never_the_release_before"; tests/unit_test.py "test_an_upgrade_with_nothing_to_upgrade_from" -->
  It also makes a world of data the way the random checks do: shares in every state, links, moves, through that
  release's own triggers and `authz.share`; every night it does all of this from every release on PyPI
  from the beta on. Each release is upgraded with the docs app it was released with: a copy in the tests where it
  differs from today's ([`tests/docs_app.py`](../core/tests/docs_app.py)), so a change to the docs app that an
  old release would not compile leaves its upgrade checked. <!-- checked: tests/unit_test.py "test_each_release_is_upgraded_with_its_own"; tests/upgrade.sh "the docs app" --> After the upgrade, by `reapply` and by the next migration, `authz.can` answers every user,
  object and permission (1,277 checks) as on a new database with the same rows, all of difftest's questions get
  the reference evaluator's answers, and the catalog and the inheritance rows are the new database's. <!-- checked: tests/upgrade_world.py "answers as on a new database"; tests/upgrade.sh "it holds what applying this version on a new database with its rows leaves" -->
- **Cut half way**: [`tests/interrupt.py`](../core/tests/interrupt.py) runs `rowstile apply` (on a new database
  and over a policy), `push`, `reapply --force` and both migrations of a change that builds an inheritance table
  beside the one in use, on the docs app, and cuts each after one of its statements: the server ends the session,
  or the connection is closed under it. After each cut the command says it lost the database and why (the server's
  words, when the server ended the session; exit 2), the database is as it was before the run, and the app,
  reading as the app role just before the cut and after it, gets the old policy's answers, whole; after some, the
  next run leaves what an uncut one does. <!-- checked: tests/interrupt.py "after each cut, the database is as it was"; tests/interrupt.py "the app read the old policy's answers, whole" -->
  Between the two migrations the old policy is in force. <!-- checked: tests/interrupt.py "between a migration's two: the old policy in force" -->
  Each night, after every one of their statements (about 25 minutes); on each push, ten cuts of each. The real
  command is also ended while one of its statements waits for a lock, and stopped by `statement_timeout`; and
  `rowstile review --db` as soon as it signs in. Every night the soak cuts the first apply of twenty-five other policies, random ones among them, where its seed says.
- **Reads that stay fast**: where a read or a list needs a permission's starting points (a function that
  works them out), Postgres runs it once, not again for each row a nested loop looks at. `PointChecks` in
  [`tests/unit_test.py`](../core/tests/unit_test.py) checks the compiled SQL of six policies and a random one for
  it, and [`tests/confidence_test.py`](../core/tests/confidence_test.py) counts the calls of a list of seven rows
  on that random policy: 76 on PostgreSQL 16, where calling the function for each row made 10,768 and took over a
  second. <!-- checked: tests/unit_test.py "test_starting_points_are_read_in_from"; tests/confidence_test.py "its starting points run once where they are read" -->
- **The parser**: [`tests/fuzz_parser.py`](../core/tests/fuzz_parser.py) feeds it thousands of broken
  policies, each made from one of the suites' own with the language's words put in; each is accepted, or refused
  with a line number, never a crash. <!-- checked: tests/fuzz_parser.py "refused without a line number" -->
  Every night [`tests/fuzz_coverage.py`](../core/tests/fuzz_coverage.py) gives the parser and the compiler
  twenty minutes more under Atheris, a fuzzer that watches which branches each input reaches and works from the
  ones that reach new ground, held to the same rule.
- **The docs**: the getting-started guide runs as written, its Python too, against the client it writes; the
  policy and the SQL the README and the site's home page show apply and run; every line of policy and tests the
  cookbook shows is in a recipe that is applied and tested, the SQL it shows runs, and every line of code on the
  stack pages is in an app whose tests pass. <!-- checked: tests/docs_test.sh "every block of the guide runs"; tests/docs_test.sh "the guide's Python, for cy, who can't see the note: its handler answers 404"; tests/docs_test.sh "its SQL, once 42 may edit folder 7"; tests/cookbook.sh "every line of policy and tests its page shows is in its files"; tests/cookbook.sh "the SQL its page shows runs, as its first user"; tests/unit_test.py "test_every_line_is_in_a_tested_app" -->
  Every block of code in the reference runs too, or says why it can't, and each promise these pages make, and
  the reference's, names the check that holds it in a comment readers don't see, or says why none does. <!-- checked: tests/reference.sh "every block of the reference runs, or says why not"; tests/unit_test.py "test_every_promise_says_what_holds_it"; tests/unit_test.py "test_each_tag_names_checks_that_are_there" -->
- **Three versions of Postgres**: on PostgreSQL 16 for each change, every suite but genpolicy's random policies
  and the stress test, in shorter runs, with the orders of two tree writes in READ COMMITTED alone; the full run,
  with them all, on 16 [every night](../.github/workflows/nightly.yml). On 17 and 18 every night, the suites as 16
  runs them for each change, every order of two tree writes at each isolation level and the stress test; and the
  soak, the random checks' long run, on one of the three each night in turn.
- **The suites themselves**: each passes as many checks as
  [`tests/check_counts.txt`](../core/tests/check_counts.txt) says, no fewer and no more, or the run fails. A
  suite that stopped checking something (a glob that matches nothing, a loop over an empty list, a test that
  skips) can't stay green unseen. <!-- checked: tests/unit_test.py "test_fewer_or_more_is_said"; tests/unit_test.py "test_skipped_tests_are_not_passed"; tests/unit_test.py "test_each_suite_written_is_one_run_tests_records" -->
- **What the database runs**: [for each change](../.github/workflows/suites.yml) and
  [every night](../.github/workflows/nightly.yml) the suites run on PostgreSQL 16 with
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
  A change fails if it leaves more of the runtime's own PL/pgSQL (`authz`) or of the rules' (`authz_gen`) never
  run than [`tests/plpgsql_floor.txt`](../core/tests/plpgsql_floor.txt) says, and one that leaves fewer writes the
  file anew, so the count only goes down. <!-- checked: tests/unit_test.py "test_the_floor" -->
  The policies' own functions (`authz_int`) are reported, not held: the random checks write other policies on each
  run, and their counts move with them.

## Every feature, and what checks it

Every feature is in one list, [`tests/features.py`](../core/tests/features.py): each `authz.*` function, each
command and its flags, each setting of `rowstile.toml`, each form of the language, each error code, what each SDK
exports, the language server's methods, the MCP server's tools and Studio's routes, each in one feature. A feature
names the page that documents it, its fixed checks, and the checks that hold it to an answer the code didn't give:
the reference evaluator, a rebuild, the policy applied whole, Postgres. The list is read against the code, and
`Features` in [`tests/unit_test.py`](../core/tests/unit_test.py) fails on each push when a part of the surface is in
no feature, when a check the list names is gone from its suite (or left in a comment), when no suite gives a flag to
its command or sets a setting, when a feature of tier 1 (it decides access, grants or revokes it, or keeps data)
has no check against another answer, or when a refusal isn't asked for by its words. <!-- checked: tests/unit_test.py "test_every_item_is_in_a_feature_and_every_check_is_there"; tests/unit_test.py "test_each_refusal_is_asked_for_by_its_words"; tests/unit_test.py "test_a_check_gone_and_a_tier_one_feature_without_an_oracle_are_said"; tests/unit_test.py "test_a_check_in_comments_and_a_flag_or_setting_no_suite_runs_are_said" -->
Every feature that grants or revokes access is in tier 1. Requests for access, breaking the glass and access reviews
are tried by one user in each snapshot of the random changes, each attempt undone, and held to the reference
evaluator: what each call says, the requests it shows, the shares it makes or revokes, and the lines it writes in
the audit trail. <!-- checked: tests/difftest.py "the decisions say"; tests/difftest.py "authz.decide_request("; tests/unit_test.py "test_a_feature_that_grants_outside_tier_one_is_named_on_the_page" -->
Tier 2 is otherwise an answer shown to people, tier 3 the tools around them. `python3 core/tests/features.py
--matrix` prints each feature against each suite.

<!-- features: the table below is written by core/tests/features.py -->

| feature | tier | documented in | fixed checks | held to another answer by |
|---|---|---|---|---|
| Checks and lists: `authz.can`, `authz.list`, `authz.perms`, `authz.perms_of` | 1 | [app-code](reference/app-code.md) | `scenario.sql`, `devx.sh`, `capitals.sh` | `difftest.py`, `small.py`, `invariance.py`, `upgrade_world.py` |
| Inheritance tables that match a rebuild: `authz.verify` | 1 | [app-code](reference/app-code.md) | `scenario.sql`, `moves.sh`, `keep.sh`, `apply.sh` | `difftest.py`, `interleave.py`, `stress.sh` |
| Who holds a permission: `authz.who`, `authz.who_among` | 2 | [app-code](reference/app-code.md) | `devx.sh`, `principals.sh` | `difftest.py` |
| Why, or why not: `authz.explain`, `authz.explain_rule` | 2 | [app-code](reference/app-code.md) | `devx.sh`, `adversarial.sh`, `docs_test.sh` | `difftest.py` |
| Shares: `shared`, `shared by`, `shared if`, their start and end; `authz.share`, `authz.unshare`, `authz.list_shares` | 1 | [language](reference/language.md) | `multi_scenario.sql`, `governance.sh`, `concurrency.sh`, `scenario.sql`, `principals.sh`, `devx.sh` | `difftest.py`, `around.py`, `genpolicy.py`, hand answers |
| Share links: `link`, `authz.create_link`, `authz.list_links`, `authz.revoke_link` | 1 | [app-code](reference/app-code.md) | `multi_scenario.sql`, `adversarial.sh` | `difftest.py`, `genpolicy.py` |
| Custom roles at run time: `authz.create_role`, `authz.set_role_permissions`, `authz.delete_role`, `authz.roles_of` | 1 | [app-code](reference/app-code.md) | `multi_scenario.sql` | `difftest.py`, `genpolicy.py`, hand answers |
| Signing in: `authz.act_as`, `authz.login_key`, `authz.login_jwt`, `authz.view_as`, `authz.principal`, `authz.connection_check`; signed sessions | 1 | [identity](reference/identity.md) | `sessions.sh`, `identity.sh`, `principals.sh`, `integrations/fastapi` | `around.py` |
| API keys: `authz.create_api_key`, `authz.list_api_keys`, `authz.revoke_api_key` | 1 | [identity](reference/identity.md) | `identity.sh`, `principals.sh`, `children.sh` | `around.py`, `difftest.py` |
| Group sync from an identity provider: `authz.sync_members` | 1 | [app-code](reference/app-code.md) | `identity.sh` | `difftest.py` |
| Requests for access and breaking the glass: `authz.request_access`, `authz.decide_request`, `authz.cancel_request`, `authz.pending_requests`, `authz.break_glass` | 1 | [governance](reference/governance.md) | `governance.sh`, `concurrency.sh` | `difftest.py`, hand answers |
| Access reviews: `authz.start_review`, `authz.review_items`, `authz.review_decide`, `authz.close_review` | 1 | [governance](reference/governance.md) | `governance.sh`, `principals.sh` | `difftest.py` |
| The sync index, a preview: `sync role`, `sync <table> : <permission>`, `authz.sync_tick`, `authz.sync_verify` | 1 | [sync](reference/sync.md) | `sync.sh`, `policy_errors.py` | `difftest.py` |
| Electric on the sync index, a preview: `rowstile client electric`'s shapes, and `electricShape`, the route in front of Electric | 1 | [sync](reference/sync.md) | `unit_test.py`, `cli.sh`, `integrations/electric` | `integrations/electric` |
| The change feed: `authz.changes_since`, `authz.trim_changes`, `authz.announce_timed_shares` | 2 | [governance](reference/governance.md) | `governance.sh`, `integrations/nextjs` |  |
| The audit trail: `authz.audit`, `authz.trim_audit` | 1 | [governance](reference/governance.md) | `governance.sh` | `difftest.py` |
| Checking the database: `authz.lint`, `authz.check_invariants` | 2 | [governance](reference/governance.md) | `governance.sh`, `adversarial.sh`, `apply.sh` | `around.py` |
| What apps see of a refusal: each code's SQLSTATE and HTTP answer, the reason in the error | 1 | [app-code](reference/app-code.md) | `unit_test.py`, `reference.sh`, `adversarial.sh`, `integrations/fastapi`, `integrations/nextjs` | `around.py` |
| Applying a policy: `rowstile apply`, `check`, `push`, `diff`, `remove` | 1 | [tools](reference/tools.md) | `apply.sh`, `cli.sh`, `migrations.sh`, `children.sh` | `interrupt.py`, `around.py`, `migrate_test.py` |
| Migrations: `rowstile migrate`, the lock file, trees built beside then swapped in | 1 | [migrations](reference/migrations.md) | `migrations.sh`, `unit_test.py`, `migration_tools.sh` | `migrate_test.py`, `interrupt.py` |
| Upgrading rowstile: `rowstile reapply`, migrations from an older release (from the beta on) | 1 | [migrations](reference/migrations.md) | `upgrade.sh`, `unit_test.py`, `apply.sh`, `cli.sh` | `upgrade_world.py` |
| Running the policy's tests: `rowstile test` | 2 | [tools](reference/tools.md) | `cli.sh`, `devx.sh`, `confidence_test.py` |  |
| Asking the database as someone: `rowstile can`, `explain`, `perms`, `list`, `who`, `explain-rule`, `sql` | 2 | [tools](reference/tools.md) | `cli.sh`, `devx.sh`, `capitals.sh` |  |
| What would grant a permission: `rowstile why` | 2 | [tools](reference/tools.md) | `studio_test.py`, `unit_test.py` |  |
| Reviewing a change: `rowstile review`, `rowstile snapshot` | 2 | [review](reference/review.md) | `review.sh`, `unit_test.py`, `confidence_test.py` | `rewrites.py` |
| One layout for policies: `rowstile fmt` | 2 | [tools](reference/tools.md) | `review.sh`, `unit_test.py` | `invariance.py` |
| Invariants in small worlds: `rowstile prove` | 2 | [tools](reference/tools.md) | `confidence_test.py`, `unit_test.py`, `cli.sh` | `genpolicy.py` |
| Speed: `rowstile indexes`, `plans`, `bench` | 2 | [tools](reference/tools.md) | `capitals.sh`, `confidence_test.py`, `unit_test.py` |  |
| The diagram, the clients, lint and help: `rowstile graph`, `client`, `lint`, `help`, `--version` | 3 | [tools](reference/tools.md) | `cli.sh`, `tools_test.py`, `unit_test.py` |  |
| The development loop: `rowstile dev` | 3 | [tools](reference/tools.md) | `devx.sh`, `migrations.sh` |  |
| A first policy from the database: `rowstile init` | 3 | [tools](reference/tools.md) | `devx.sh`, `unit_test.py` |  |
| Studio, reading: `rowstile studio`, the rows as anyone, why, the graph, the access diff, shares, tests | 2 | [tools](reference/tools.md) | `studio_test.py` |  |
| Studio, writing (`--write`): share, unshare, decide a request | 1 | [tools](reference/tools.md) | `studio_test.py` | `difftest.py` |
| The language server: `rowstile lsp` | 3 | [tools](reference/tools.md) | `lsp_test.py` |  |
| The MCP server, for coding agents: `rowstile mcp` | 2 | [tools](reference/tools.md) | `mcp_test.py`, `reference.sh` |  |
| Types and the rows that count: `type`, `where`, `app role` | 1 | [language](reference/language.md) | `unit_test.py`, `policy_errors.py`, `principals.sh`, `apply.sh` | `difftest.py`, `small.py`, `genpolicy.py`, hand answers |
| Keys: of any type, of several columns | 1 | [language](reference/language.md) | `unit_test.py` | `difftest.py`, `genpolicy.py`, `around.py`, hand answers |
| Policies in several files: `include` | 2 | [language](reference/language.md) | `unit_test.py`, `cli.sh`, `policy_errors.py` | `invariance.py`, `genpolicy.py` |
| Relations and their sources: columns, pairs of columns, link tables | 1 | [language](reference/language.md) | `unit_test.py`, `scenario.sql` | `difftest.py`, `small.py`, `genpolicy.py`, hand answers |
| Subjects and principals: a type, a group's members, `user:*`, `anyone`, `link`, services | 1 | [language](reference/language.md) | `principals.sh`, `unit_test.py` | `difftest.py`, `small.py`, hand answers |
| Permissions: `can`, `or`, `and`, `not`, following a relation | 1 | [language](reference/language.md) | `unit_test.py`, `policy_errors.py` | `difftest.py`, `genpolicy.py`, `small.py`, `rewrites.py`, hand answers |
| Conditions: `{...}`, `this`, read with the policy's rights | 1 | [language](reference/language.md) | `devx.sh`, `apply.sh`, `unit_test.py`, `governance.sh`, `policy_errors.py` | `conditions_test.py`, `genpolicy.py`, hand answers |
| Inheritance and denies: `parent.view`, `and {condition}`, `and not`; moves, loops | 1 | [language](reference/language.md) | `scenario.sql`, `moves.sh`, `concurrency.sh`, `policy_errors.py`, `unit_test.py` | `difftest.py`, `interleave.py`, `small.py`, `genpolicy.py`, `stress.sh`, hand answers |
| Custom roles in the policy: `roles : ... from ...`, `roles` in a permission | 1 | [language](reference/language.md) | `multi_scenario.sql`, `unit_test.py` | `difftest.py`, `genpolicy.py`, hand answers |
| Rules: `select`, `insert`, `update` (before, after, on columns), `delete` | 1 | [language](reference/language.md) | `devx.sh`, `adversarial.sh`, `unit_test.py`, `children.sh`, `integrations/fastapi` | `difftest.py`, `around.py`, `genpolicy.py`, hand answers |
| Masked columns: `mask`, the view | 1 | [language](reference/language.md) | `masks.sh`, `multi_scenario.sql`, `apply.sh` | `difftest.py`, `genpolicy.py`, hand answers |
| Foreign keys whose action is meant: `cascade from`, and the warning of the others | 2 | [language](reference/language.md) | `apply.sh`, `policy_errors.py`, `unit_test.py` |  |
| Scopes: what a key or a token may do | 1 | [identity](reference/identity.md) | `identity.sh`, `sessions.sh` | `difftest.py`, `genpolicy.py` |
| Caveats: conditions a share carries | 1 | [language](reference/language.md) | `multi_scenario.sql` | `difftest.py`, `genpolicy.py`, hand answers |
| Invariants: `never` | 2 | [language](reference/language.md) | `governance.sh`, `principals.sh`, `unit_test.py` | `genpolicy.py`, hand answers |
| The policy's tests: checks, named tests, `given`, `as`, `with scope` | 2 | [language](reference/language.md) | `devx.sh`, `unit_test.py`, `cookbook.sh` | hand answers |
| The Python SDK: signing in, refusals as answers, jobs | 2 | [app-code](reference/app-code.md) | `integrations/fastapi` |  |
| The Python SDK's background jobs, in Celery's and RQ's workers (preview) | 2 | [python](stacks/python.md) | `integrations/fastapi` |  |
| The Python SDK's stacks: FastAPI, SQLAlchemy, psycopg, asyncpg, Alembic, pytest | 2 | [app-code](reference/app-code.md) | `integrations/fastapi` |  |
| The Python SDK's Django integration (a preview): every transaction signed in, the middleware, pytest-django | 2 | [django](stacks/django.md) | `integrations/django` |  |
| The TypeScript SDK: `@rowstile/client` | 2 | [app-code](reference/app-code.md) | `integrations/nextjs` |  |
| The Go SDK (a preview): pgx transactions signed in, refusals as errors, `net/http`, a database per test package | 2 | [app-code](reference/app-code.md) | `integrations/go` |  |
| The TypeScript SDK's drivers: `/pg`, `/postgres`, `/prisma`, `/drizzle` | 2 | [app-code](reference/app-code.md) | `integrations/nextjs` |  |
| The TypeScript SDK for Next.js and React: `/next`, `/react`, `/vitest` | 2 | [app-code](reference/app-code.md) | `integrations/nextjs` |  |
| The TypeScript SDK on Neon's serverless driver, the edge runtime, BullMQ and `after()` (preview) | 2 | [nextjs](stacks/nextjs.md) | `integrations/nextjs` |  |
| The TypeScript SDK for Jest, a preview: `/jest`; a plain Node server (Express) | 2 | [node](stacks/node.md) | `integrations/node` |  |
| The .NET SDK (preview): `Rowstile`, `Rowstile.EntityFrameworkCore`, `Rowstile.AspNetCore` | 2 | [app-code](reference/app-code.md) | `integrations/aspnetcore` |  |
| The Ruby SDK for Rails (preview): signing in, refusals as answers, jobs, tests | 2 | [rails](stacks/rails.md) | `integrations/rails` |  |
| The Java SDK (preview): JDBC, and the Spring Boot starter | 2 | [app-code](reference/app-code.md) | `integrations/spring` |  |
| The Kotlin module of the Java SDK (preview): coroutines, Exposed and Ktor | 2 | [app-code](reference/app-code.md) | `integrations/ktor` |  |
| The Rust SDK (preview): sqlx and tokio-postgres transactions signed in, refusals as errors, Axum | 2 | [app-code](reference/app-code.md) | `integrations/axum` |  |
| The Elixir SDK (preview): Ecto and Postgrex transactions, a Plug, Oban jobs, tests | 2 | [phoenix](stacks/phoenix.md) | `integrations/phoenix` |  |
| The PHP SDK (preview): PDO, and Laravel's connections, middleware, jobs and tests | 2 | [laravel](stacks/laravel.md) | `integrations/laravel` |  |

<!-- features: end of the table -->

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

Since October 2026 the mistakes are made by rule rather than picked by hand: [`core/mutants/`](../core/mutants/sweep.py)
makes about 10,000 of them in the compiler (an operator of its SQL or its Python turned round, a term dropped, a
quoting call left out), compiles every policy in the repository with each, and runs the suites on those that change
what one of them compiles to, on GitHub's runners, [weekly](../.github/workflows/mutants.yml). A mistake no suite
catches is listed in [`core/mutants/survivors.txt`](../core/mutants/survivors.txt), either as one that changes no answer or with the check that would
catch it, and one that isn't listed fails the run. <!-- checked: tests/unit_test.py "test_a_new_survivor_fails_the_run" -->
Up to 20 October 2026 the runs gave a result for 2,934 of the 10,749 it makes; the rest are still to run. Of those
2,934, 2,749 change what a policy compiles to and aren't listed as changing no answer: the suites caught 2,714 of
them (98.7%). Those they missed got a check, or a line in `survivors.txt`: why no answer changes, or which check
would catch it and is still to write.

## When something is found

Vulnerabilities are reported privately ([SECURITY.md](../SECURITY.md)) and published as advisories once
fixed. There have been twenty-two so far, each found by the project itself: GHSA-6g93-673q-c29f, in
`@rowstile/prisma`, fixed and published the same day; five fixed in 0.1.0-alpha.7 and five in 0.1.0-alpha.9; nine
in 0.1.0-beta.1, found by the audit before it; two in 0.1.0-beta.2. Each release's were published the day it came
out. Two of those are rated high: a rule on a column that was not checked on the rows of a partition made since the last
apply (GHSA-h92j-8v4p-93hc), and the command's Postgres client, which sent the password before it honoured
`channel_binding=require` (GHSA-g2rq-h47r-5v2c). [The advisories](https://github.com/rowstile/rowstile/security/advisories)
are all listed there.

## What this doesn't cover

- An audit by someone outside the project. There has been none.
- The limits [the threat model](threat-model.md#known-limits-accepted) accepts: side channels such as
  `EXPLAIN ANALYZE` row counts, tables without rules, `SECURITY DEFINER` functions an app adds.
- Managed Postgres services other than the two [it was tried on](managed-postgres.md).
- macOS and Windows: no machine or runner here has either. The npm packages for them are read by the packaging
  tests (their Python is built for that system and CPU, and holds every library and module the command loads),
  but not started. The Linux ones are started, x64 and arm64, glibc and musl. What the command does differently
  on Windows (a drive in an editor's address, paths on two drives, the console's code page, the shell's quotes,
  libpq's folder and its default user) is checked by unit tests that stand in for Windows, not on Windows itself.
- Your policy. rowstile enforces what the policy says; whether it says what you meant is what its tests, its
  invariants and [the review of each change](reference/review.md) are for.
