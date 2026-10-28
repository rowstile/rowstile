# Why a query through row-level security runs on one CPU

*Salaheddine El Hssani, 2026-10-28*

Counting two million rows, a table's owner gets a plan that splits the work between processes. The same count
through a row-level security policy often runs in one, and nothing in the policy says so. Three things decide
it: how the functions the policy calls are marked, whether a subquery in it refers to the row being checked,
and, on PostgreSQL 16, where `(SELECT ...)` sits. This post shows each with one script, what each way out
costs when the query opens a single row, and the case where the way out never finishes.

## The setup

Two tables: `files (id, owner_id, name)` and `shares (file_id, user_id)`. Two million files and a thousand
users, each owning a thousandth of them. Every fourth file is shared with one of the users; every fiftieth
with user 1000, the support team. The rule: you see a file you own, or one shared with you.

Every figure below comes from one script,
[experiment.sql](row-level-security-on-one-cpu/experiment.sql), run on PostgreSQL 16, 17 and 18, each in a
container on a GitHub-hosted runner with 4 CPUs and 16 GB, with default settings and JIT off. Default settings
allow two parallel workers. The output of each run is beside the script
([16](row-level-security-on-one-cpu/run-16.txt), [17](row-level-security-on-one-cpu/run-17.txt),
[18](row-level-security-on-one-cpu/run-18.txt)). The three runs got three different processors
([runner.txt](row-level-security-on-one-cpu/runner.txt)), so compare times within a run, not across versions.
Which plans get workers is the same on all three, except where this post says otherwise. The plans shown are
18's; 16 prints a hashed subplan more briefly, `(hashed SubPlan 1)`.

Three queries are timed through each way of writing the rule:

- **user 7's count**: `SELECT count(*) FROM demo.files` as user 7, who sees 2,501 files;
- **user 1000's count**: the same as the support team, who sees 42,000;
- **one file**: `SELECT id, name FROM demo.files WHERE id = 100`, opened by user 1000.

Each number is the middle one of three runs. As the table's owner, with no policy, the count takes 36 ms with
two workers. On PostgreSQL 18:

| PostgreSQL 18 | workers | user 7's count | user 1000's count | one file |
|---|---|---|---|---|
| 1. `IN`, the user from a setting | 2 | 125 ms | 144 ms | 4.6 ms |
| 2. `IN`, the user from a function | none | 243 ms | 280 ms | 5.9 ms |
| 3. `IN`, the function marked parallel safe | 2 | 124 ms | 141 ms | 4.7 ms |
| 4. `EXISTS`, the function marked parallel safe | none | 247 ms | 284 ms | 0.018 ms |
| 5. `IN`, `(SELECT demo.uid())` in both places | 2 | 66 ms | 88 ms | 5.4 ms |
| 6. `IN`, `(SELECT demo.uid())` outside the subquery only | 2 | 72 ms | 88 ms | 4.6 ms |

## 1. A function nobody marked

The first policy reads the user from a setting:

```sql
CREATE POLICY files_select ON demo.files FOR SELECT TO demo_app USING (
  owner_id = current_setting('demo.user_id')::bigint
  OR id IN (SELECT s.file_id FROM demo.shares s WHERE s.user_id = current_setting('demo.user_id')::bigint));
```

The count gets two workers. Most policies don't read a setting directly, though. They call a function, so the
rule reads well and the setting's name is written once:

```sql
CREATE FUNCTION demo.uid() RETURNS bigint LANGUAGE sql STABLE AS $$
  SELECT current_setting('demo.user_id')::bigint $$;
```

With `demo.uid()` in place of `current_setting(...)`, the same count runs in one process and takes twice as
long. [The documentation of `CREATE FUNCTION`](https://www.postgresql.org/docs/current/sql-createfunction.html)
says why: "`PARALLEL UNSAFE` indicates that the function can't be executed in parallel mode; the presence of
such a function in an SQL statement forces a serial execution plan. This is the default." Nobody wrote
`PARALLEL UNSAFE`. The function got it by saying nothing.

The plan won't point you to it. Postgres inlines a function this small, so the plan shows the setting, as if
the first policy were still there (shortened):

```
 Aggregate (actual rows=1.00 loops=1)
   ->  Seq Scan on files (actual rows=2501.00 loops=1)
         Filter: ((owner_id = (current_setting('demo.user_id'::text))::bigint) OR (ANY (id = (hashed SubPlan 1).col1)))
         Rows Removed by Filter: 1997499
```

The function is gone from the plan, but the decision against workers was made before it went.

```sql
ALTER FUNCTION demo.uid() PARALLEL SAFE;
```

brings the workers back. Mark a function safe only when it is. The
[documentation's rule](https://www.postgresql.org/docs/current/parallel-safety.html): a function is unsafe if it
writes to the database, changes the transaction state, accesses sequences or makes persistent changes to
settings, and restricted if it accesses temporary tables, client connection state, cursors, prepared statements
"or miscellaneous backend-local state that the system cannot synchronize across workers".

## 2. A subquery that refers to the row

The usual way to write "or shared with me" is `EXISTS`:

```sql
CREATE POLICY files_select ON demo.files FOR SELECT TO demo_app USING (
  owner_id = demo.uid()
  OR EXISTS (SELECT 1 FROM demo.shares s WHERE s.file_id = files.id AND s.user_id = demo.uid()));
```

With the function marked safe, this one still gets no workers, on 16, 17 or 18. The documentation's
[list of what is always parallel restricted](https://www.postgresql.org/docs/current/parallel-safety.html)
(allowed in the leading process only) includes "Plan nodes that reference a correlated `SubPlan`". `s.file_id
= files.id` makes the subquery correlated. Postgres plans it two ways, row by row and as one hashed set, and
for the count it runs the hashed one:

```
 Aggregate (actual rows=1.00 loops=1)
   ->  Seq Scan on files (actual rows=2501.00 loops=1)
         Filter: ((owner_id = (current_setting('demo.user_id'::text))::bigint) OR (ANY (id = (hashed SubPlan 2).col1)))
         Rows Removed by Filter: 1997499
```

It is the plan `IN` got in section 1: the set built once, and no workers. Only the number differs, `SubPlan
2`. `SubPlan 1` was the row-by-row way, planned and set aside, and that it could have run was enough to keep
the count in one process.

`IN` doesn't refer to the row, so the count gets its workers. What it costs is the single file. To answer for
file 100, `IN` first collects every file shared with the support team, 40,000 of them:

```
 Index Scan using files_pkey on files (actual rows=1.00 loops=1)
   Filter: ((owner_id = (current_setting('demo.user_id'::text))::bigint) OR (ANY (id = (hashed SubPlan 1).col1)))
   SubPlan 1
     ->  Index Scan using shares_user_id_idx on shares s (actual rows=40000.00 loops=1)
```

Through `EXISTS` it is one probe of the shares' primary key: 0.018 ms against 4.7.

So the two forms suit opposite questions. A count or a list over many rows wants the set, and can then have
workers. Opening one row, and every write, which checks one row, wants to start from the row.

## 3. When the set is too big to hash

`IN` has a second cost, and it is worse. Postgres hashes the set only if it expects it to fit in memory. The
rule is in the planner (`subplan_is_hashable`, in `src/backend/optimizer/plan/subselect.c`): "The estimated
size of the subquery result must fit in hash_mem", which is `work_mem` times `hash_mem_multiplier`, 4 MB times
2 by default. At the 32 bytes a row the planner counts for one `bigint`, that is about 262,000 rows. A bigger
set is kept as a list instead, and searched for each row.

The script's last section gives user 1001, an auditor, every fifth file: 400,000 shares. Through `IN`, the
count's plan still has its workers, and no hash:

```
 Finalize Aggregate
   ->  Gather
         Workers Planned: 2
         ->  Partial Aggregate
               ->  Parallel Seq Scan on files
                     Filter: ((owner_id = (current_setting('demo.user_id'::text))::bigint) OR (ANY (id = (SubPlan 1).col1)))
                     SubPlan 1
                       ->  Materialize
                             ->  Index Scan using shares_user_id_idx on shares s
```

Two million files, each looked for in a list of 400,000. The script cancels the count after thirty seconds,
and on all three versions it is cancelled. Through `EXISTS`, the same count takes 1.68 s in one process, a
probe of the primary key per file, and opening one file 0.021 ms.

A user who sees more than a few hundred thousand rows by one path, an administrator, a support team, an
auditor, is exactly who `IN` fails. Raising `work_mem` moves the line; it doesn't remove it.

## 4. `(SELECT auth.uid())` on PostgreSQL 16

[Supabase's guide to row-level security](https://supabase.com/docs/guides/database/postgres/row-level-security#call-functions-with-select)
recommends wrapping such functions in a `SELECT`: `using ( (select auth.uid()) = user_id )` rather than
`using ( auth.uid() = user_id )`. "Wrapping the function causes an `initPlan` to be run by the Postgres
optimizer, which allows it to "cache" the results per-statement, rather than calling the function on each
row." It is good advice: in the table above, rows 5 and 6 count in about half the time of row 3.

On 16 it has a catch. [PostgreSQL 16's list](https://www.postgresql.org/docs/16/parallel-safety.html) of what
is always parallel restricted has one more item: "Plan nodes to which an `InitPlan` is attached". Written inside the shares subquery, the `(SELECT demo.uid())`
becomes an init plan attached to that subquery, and the whole count loses its workers. Written only at the top
of the policy, it keeps them. PostgreSQL 17 dropped the item ("Allow query nodes to be run in parallel in more
cases", in [its release notes](https://www.postgresql.org/docs/17/release-17.html)). User 7's count:

| user 7's count | 16 | 17 | 18 |
|---|---|---|---|
| 3. the function, unwrapped | 2 workers, 225 ms | 2 workers, 132 ms | 2 workers, 124 ms |
| 5. `(SELECT demo.uid())` in both places | none, 222 ms | 2 workers, 63 ms | 2 workers, 66 ms |
| 6. `(SELECT demo.uid())` outside the subquery only | 2 workers, 118 ms | 2 workers, 71 ms | 2 workers, 72 ms |

On 16, wrap the function at the top of the policy and not inside a subquery.

## What rowstile does

[rowstile](../../site/index.md) compiles a policy file into row-level security, and its rules are written like
the `EXISTS` policy, with their functions left unmarked. Both on purpose.

The functions read who is signed in from settings that carry a signature, and the signature includes the
connection's process id. A parallel worker is another process, where the check would fail, so they stay
unmarked. And the lookups stay `EXISTS`: opening one row is what an app does most, and `IN` stops hashing at a
few hundred thousand rows, which is where the users who see the most are.
The price is the one this post measures: a count over every row runs on one CPU.
[Speed and limits](../reference/limits.md) says so, with the reasons and rowstile's own numbers, under "Reads
through the rules run on one CPU".

If you write policies by hand, four things to check:

- **Mark what can be marked.** A function your policies call that only reads can be `PARALLEL SAFE`; `STABLE`
  alone isn't.
- **Pick the form for the question, and the size.** `IN` gets workers for counts and lists, but costs every
  single-row read the whole set, and falls off a cliff when the set outgrows `work_mem`. `EXISTS` stays fast
  for one row and for any number of rows a user may see.
- **On 16, keep `(SELECT ...)` out of a policy's subqueries.**
- **Look at the plans as the app's role.** A table's owner skips its row-level security unless the table forces
  it, so `EXPLAIN` as the owner shows a plan your users never get.
