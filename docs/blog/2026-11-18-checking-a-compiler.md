# Checking a compiler against a second implementation

*Salaheddine El Hssani, 2026-11-18*

A test says what its author expected. When the author also wrote the code, both come from the same reading of
the problem, and a mistake in that reading is in both. They agree, the test passes, and the bug ships. Below is
one way out of that loop for code whose answers can be computed another way: write a second implementation that
is slow and plain, and compare the two on inputs neither author chose. It covers what that comparison found in a
policy compiler, what it missed, and why the second implementation needs checks of its own.

## The code under test

The code here is a compiler. It reads a short policy ("you may view a folder if it is shared with you, or if you
may view its parent") and writes PostgreSQL: views, row-level security policies, closure tables kept current by
triggers, functions for single-row checks. That output is built for speed. Inheritance is not walked at query
time; a table holds every ancestor of every folder, and triggers move its rows when a folder moves. Each
permission can be computed two ways: as a set of ids, for lists, and as a check of one row, for writes. A lookup
that another part of the permission already covers is left out.

Each of those choices is a place for a mistake. A closure row not moved on an edge case is a folder someone sees
after it moved away. The fast path for lists and the fast path for one row can disagree. A test written against
any of them is written by someone who knows what the optimisation was meant to do, and checks that.

## The second implementation

The reference evaluator answers the same question with none of those choices. It reads the policy as parsed, not
the compiler's model of it, and works on sets of ids in memory. Each relation is a set; each permission is
computed from the sets it names. Inheritance is a loop that adds what it finds until nothing changes, a least
fixed point. For the folder policy and one user, it comes down to this:

```python
# can view = viewer or parent.view, for one user, as sets of ids
parent = {2: 1, 3: 2, 4: 3, 5: 1}  # folder -> its parent
viewer = {2}                       # folders shared with the user

view: set[int] = set()
while True:
    new = viewer | {f for f, p in parent.items() if p in view}
    if new == view:
        break
    view = new
print(sorted(view))                # [2, 3, 4]
```

There is no closure table, no trigger and no SQL. A move is a changed dictionary entry, and the next evaluation
starts again from nothing. That is far too slow for an application, and fast enough for a test, whose worlds are
small.

The full version covers the whole language: groups inside groups, `and` and `not`, conditions on rows, links to
every user, share links, custom roles. It orders the permissions so that a `not` always reads a finished set, and
it computes each group of mutually recursive permissions to its fixed point before anything that reads them.

## The comparison

The harness ([`difftest.py`](../../core/tests/difftest.py)) applies a policy to a real database, fills its
tables with random rows, and then makes random changes: moves, new links, loops, groups inside groups, shares
that start and end, ids that change, `TRUNCATE`, several statements in one transaction. After each change it
reads the whole state back, gives it to the evaluator, and asks both sides the same questions for every user:
what may they list, may they act on each row, what does row-level security let them read, who holds each
permission, and why.

A quarter of the changes aim at parts of the policy that haven't yet decided any answer, such as a source no user
has gone through or a depth of inheritance not reached yet. Random changes alone spend most of their time where
the answer was already settled.

A second harness writes the policies too ([`genpolicy.py`](../../core/tests/genpolicy.py)): random types,
relations and permissions, their tables, their data, and the same checks. A third of them name their tables as
applications do, with capitals, reserved words, quotes and accents. Nearly half key their rows by something other
than a `bigint`. Half of those with text keys use words, which each collation puts in an order of its own. Each
night a hundred new ones run, with new seeds. When one fails, it is shrunk to a smaller policy that still fails.

## What it found

**A group that should not count.** A type of group can have a condition (`where {not disbanded}`): a disbanded
team gives its members nothing. In the compiled SQL, the walk through teams inside teams applied that condition to
its result but not on the way. So a disbanded team still passed its members up to the team that contained it.
The single-row check, the rows each user could read and `who` all agreed, because they read the same walk, and
they were all wrong. Asked about directly, a disbanded team gave nothing, as it should: the mistake was only on
the way through it. Only the evaluator, which computes membership from the policy's words, said no. The random
policies found it in their first long run. Before the first public release a review found eleven bugs that gave
the wrong access, and this is the only one of them the random policies found.

**A function run with the wrong rights.** A policy's condition may call one of the application's own functions.
Postgres reads a view's tables with the view owner's rights, but a function the view calls runs with the rights
of whoever reads it. So where the compiler's views read such a condition (through a permission on another type,
through inheritance, in a masked view), the function ran as the application's user and saw only what that user
may see. Under a `not`, row-level security then showed rows the policy refuses, while the single-row check was
right. The random policies met it in the nightly run, once the generator had been taught to draw conditions that
call functions. Two seeds failed: one with "stack depth limit exceeded", one with a row missing from a masked
view. It became an advisory,
[GHSA-gfc6-697v-pv35](https://github.com/rowstile/rowstile/security/advisories/GHSA-gfc6-697v-pv35), and was
fixed in the next release.

**The checker's own mistake.** Some tools, a prover and a reviewer, make up small worlds without a database and
read simple conditions (`{not archived}`, `{size > 10}`) themselves. The harness above never does that: it asks
the database for each condition on each row. So the evaluator's reading of conditions had never been compared with
anything. A test now makes conditions up at random over columns of every kind and checks each one against
Postgres's answer on the same rows ([`conditions_test.py`](../../core/tests/conditions_test.py)). Its first run
found 626 of 1,949 conditions read otherwise than Postgres reads them. Texts in order: Postgres follows a
collation, Python the code points. Texts Postgres reads as the column's type: `'010'` for an integer, `'t'` for a
boolean. An order against the signed-in user's id, and ids compared with a number as text. The evaluator now
leaves the first three to the database, as it does any condition it doesn't read itself, and compares ids with
numbers as numbers.

## What it cannot find

Two implementations that agree have shown that they agree. Three things limit that.

**What they share.** Both read the policy through one parser. A policy misread there is misread by both, and they
agree on it. So the evaluator is also held to answers nobody computed with code: each paragraph of the language
reference that says what an answer is has a case whose answers were worked out by hand and written down before
anything ran. And a second parser, the editors' grammar, written separately, must read every policy in the
repository as the first one does, and each night every small policy up to a size.

**What the generator never makes.** The comparison sees only the worlds it builds. Of the eleven bugs that gave
the wrong access before the first public release, ten were found by reading, and most of those were outside those
worlds: a partition made after the policy was applied, the owner's default privileges, a function's search path,
a migration run outside a transaction, a JSON Web Token without an audience. None of them is a different answer to
the same question on the same data. They are in the database around the policy, or in how something is spelled.
The harnesses have since been widened to vary some of that: the catalog, the session, the role a check runs as, a
database's locale. On its second seed, the one that does ([`around.py`](../../core/tests/around.py)) found a
grant on rowstile's own schemas that the next apply should have taken back, and didn't.

**Whether the checker would notice.** A comparison that never fails might not be looking. The way to know is to
break the code on purpose and see. Mistakes put into the compiler by hand: 64, of which the suites caught 60, and
each of the four missed got a test. Mistakes put into the evaluator: 40, of which the suites caught 26. One of the
14 missed can't change an answer. The other 13 changed answers nothing else asked for, or how the prover makes up
its worlds, and that gap is where the hand-worked answers and the conditions test came from. Since October the
mistakes are made by rule, about ten thousand of them. Up to 20 October, 2,749 of those run changed what a policy
compiles to and weren't listed as changing no answer; the suites caught 98.7% of them. Each one they miss gets a
check, or a line saying why no answer changes, or which check is still to write.

## What it costs

The evaluator is under 400 lines of Python, against about 6,400 in the three files of the compiler that write the
views, the closure tables and the rules. It has to change with the language: a new form goes into both, and into
the hand-worked cases. The comparisons run on every push, briefly. Each night they run for about three quarters of
an hour, and for about an hour and three quarters more with new seeds, in parts side by side.

For a compiler whose mistakes show up as someone seeing what they shouldn't, that has been worth it. Write the
second implementation as plainly as the problem allows, and compare the two on inputs nobody picked. Then check
the second one too, by its own answers worked out by hand and by mistakes put into it.

The compiler is [rowstile](https://rowstile.dev), which turns access rules into PostgreSQL row-level security. All
of the above is described, with every number's source, in [How rowstile is checked](../how-it-is-checked.md).
