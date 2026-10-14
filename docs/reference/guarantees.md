# How it works

## What it compiles to

- Each relation and permission becomes a view of the ids the current user holds it
  on. The app role reads only these (`authz_gen`), never raw shares or internals. <!-- checked: tests/adversarial.sh "the shares table"; tests/adversarial.sh "internal views"; tests/adversarial.sh "the public views return only carol's own ids" -->
- Inheritance becomes a closure table per set of links, kept current by triggers on
  the object table, every link table, the shares table, and any table an inheritance
  condition reads. <!-- checked: tests/difftest.py "CrossGen"; tests/scenario.sql "TRUNCATE of the link table: carol loses the Joint project at once" -->
  It is backfilled when applying; `authz.verify()` compares it with
  a rebuild. <!-- checked: tests/scenario.sql "every inheritance table matches a from-scratch rebuild" -->
  Moving a folder, or linking it, shifts the stored rows of everything below
  it to its new ancestors instead of recomputing them (unless a link loops back into
  the moved part). <!-- checked: tests/moves.sh "rows inside the moved folder were left alone" -->
- Rules become RLS policies on the row itself, so `INSERT ... RETURNING` works. Rules
  on changed columns become `BEFORE UPDATE` triggers. Each check lists its cheapest
  items first (columns, then small per-user sets, then inherited permissions), and an
  inherited permission is first checked against what the object's own columns give
  (owner, org admin): one index lookup, where users who reach a lot stop.
- Writes and `authz.can` check one object by walking its ancestors; reads and lists
  test each row and let Postgres hash the user's sets once for many rows.
- Relations read your tables live: when someone leaves a team, the next query knows.

## What it guarantees

- **Shares die with their row.** Deleting a row, changing its id or truncating its
  table removes the shares on it and to it. <!-- checked: tests/scenario.sql "so it goes with its row"; tests/scenario.sql "share on the old id is gone"; tests/governance.sh "and the shares on its rows go with them"; tests/governance.sh "emptying a table takes the shares to its rows too"; tests/principals.sh "deleting a user deletes the shares to them" -->
  `authz.share` and `authz.break_glass` lock the object and the
  subject, so a concurrent delete can't slip in between. <!-- checked: tests/concurrency.sh "the share waits for the delete, then is refused"; tests/concurrency.sh "no share is left on the deleted id"; tests/concurrency.sh "breaking the glass waits for the delete, then is refused" -->
  A delete, a new id or a `TRUNCATE` in REPEATABLE READ or SERIALIZABLE whose snapshot is older than a
  share of the row fails with a serialization error (40001), to retry, and never leaves the share. <!-- checked: tests/concurrency.sh "the writer with the older snapshot gets a serialization error"; tests/concurrency.sh "no share is left on a row that is gone"; tests/concurrency.sh "a delete with an older snapshot"; tests/concurrency.sh "a new id with an older snapshot"; tests/concurrency.sh "the user deleted with an older snapshot"; tests/concurrency.sh "TRUNCATE with an older snapshot" -->
- **Inheritance can't go stale.** <!-- checked: tests/interleave.py "inheritance tables exact after each"; tests/stress.sh "the inheritance tables match a rebuild" -->
  Writes to closure tables take a lock row per type;
  in REPEATABLE READ or SERIALIZABLE a writer with an old snapshot gets a
  serialization error to retry instead of storing stale ancestors. <!-- checked: tests/concurrency.sh "the late writer gets a serialization error (the app retries)" -->
  What they can't follow is a write made
  with the triggers off (`session_replication_role = replica`, `ALTER TABLE ... DISABLE TRIGGER`, a bulk
  load or a restore that turns them off): `authz.verify()` then says false, and `rowstile reapply --force`
  computes the tables again. <!-- checked: tests/apply.sh "a move made with the triggers off leaves the inheritance tables behind: verify() is false"; tests/apply.sh "computes them again" -->
- **What is written in replica mode isn't followed.** A superuser, or a role allowed to set
  `session_replication_role`, may write with it set to `replica`, where Postgres runs no ordinary trigger: the
  audit trail gets no line for the shares and memberships changed so, the change feed doesn't announce them, and
  the inheritance tables don't follow (above). The audit trail itself can't be changed that way: its guard holds
  in every replication role. <!-- checked: tests/governance.sh "nor by a superuser in replica role: an entry deleted"; tests/governance.sh "so a superuser in replica role still can't delete an entry" -->
- **No loops through columns**, even across several rows or two concurrent
  transactions. <!-- checked: tests/scenario.sql "moving Engineering into its own subfolder is refused"; tests/scenario.sql "also when two new folders point at each other in one statement"; tests/concurrency.sh "no loop" -->
  Loops through link tables are allowed and harmless. <!-- checked: tests/scenario.sql "a loop through links does not hang and changes nothing for carol" -->
- **Stored decisions don't depend on time or user.** Conditions that limit
  inheritance are rejected if they use the clock, the user or settings (checked in the
  text, then by Postgres when applying). <!-- checked: tests/policy_errors.py "inheritance that depends on the time"; tests/policy_errors.py "inheritance that depends on the user"; tests/policy_errors.py "inheritance calling a function that isn't IMMUTABLE" -->
  Links made by sharing can't expire. <!-- checked: tests/policy_errors.py "one that expires"; tests/policy_errors.py "and an expiry put on it later is refused too" -->
- **You can't share more than you hold**, or share what the policy doesn't declare as
  shared, or decide your own access request. <!-- checked: tests/adversarial.sh "sharing what she may only view"; tests/principals.sh "a viewer may share helper, but not grant assist, which they don't hold"; tests/adversarial.sh "sharing a relation the policy doesn't share"; tests/adversarial.sh "approving her own request" -->
- **Mistakes are reported with line numbers**, at compile time or when applying. <!-- checked: tests/fuzz_parser.py "refused without a line number"; tests/apply.sh "a condition that doesn't run names its line" -->
- **Re-applying replaces the old version**, keeps shares, removes access for roles the
  policy no longer names, and warns about cascading foreign keys and tables that lost
  their rules. <!-- checked: tests/apply.sh "a changed text is applied"; tests/apply.sh "shares and the trees stay consistent"; tests/apply.sh "takes the old one's access away"; tests/apply.sh "deletes a governed table's rows by cascade"; tests/apply.sh "warns of a table that lost its rules" -->
  Inheritance tables whose definition didn't change are kept, not rebuilt:
  a new permission or rule applies in about 0.1 s with 50k folders. <!-- checked: tests/keep.sh "a new permission keeps every inheritance table" --> <!-- unchecked: the time was measured by hand; no benchmark measures it again -->

## Security

The app role is not trusted: it may do what the rules allow and nothing else. Policy authors,
the database owner and the backend that says who is signed in are trusted. What that protects,
the attacks tried and the known limits (side channels such as `EXPLAIN ANALYZE` row counts, for
code that can run arbitrary SQL as the app role) are in [the threat model](../threat-model.md).
[How rowstile is checked](../how-it-is-checked.md) says which tests hold it to that.

**rowstile has not been audited by anyone outside the project.** It has had self-review and the
[tests](../../core/README.md#tested), including an adversarial suite and a parser fuzzer.
