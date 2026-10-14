# Governance

- **Audit trail** (`authz.audit`): who did what, as whom (the real user during
  "view as"), with the reason from `SET LOCAL authz_ctx.reason = '...'`. <!-- checked: tests/governance.sh "a changed owner column is recorded, with what it was and why"; tests/identity.sh "the audit trail has the reason" -->
  Changes to
  relationship tables and columns are recorded too (as relate/unrelate), including
  TRUNCATE, but not what is written in replica mode, where no ordinary trigger runs ([How it
  works](guarantees.md)). <!-- checked: tests/governance.sh "memberships kept in your tables are recorded too"; tests/governance.sh "emptying a link table is recorded" -->
  Nobody can update or delete rows, whatever the session sets (`session_replication_role`
  too), not even a superuser without first dropping or disabling the trigger (DDL, which DDL logging
  and event triggers see). <!-- checked: tests/governance.sh "the trail cannot be edited, even by an administrator"; tests/governance.sh "whatever the session sets"; tests/governance.sh "nor by a superuser in replica role: an entry deleted" -->
  The exceptions are `authz.trim_audit(keep)`, which removes entries older
  than that and records that it did (it disables the trigger for its delete, so it holds the trail's
  lock until the transaction ends: run it at a quiet time), and a logical replication subscription
  that copies the trail, which applies the trims made where it is published (making one is DDL too). <!-- checked: tests/governance.sh "older ones go"; tests/governance.sh "and the trim is recorded"; tests/governance.sh "and the deletes of authz.trim_audit there" -->
- **Change feed** (`authz.changes`): every object whose access may have changed (but not by
  what is written in replica mode, as above), including everything below a moved folder, with a
  position to resume from. <!-- checked: tests/governance.sh "moving a folder announces it (and what sits below it)" -->
  `{*}` means every object of that type (after a TRUNCATE). <!-- checked: tests/governance.sh "and announced for every folder"; tests/governance.sh "and announced for every file" -->
  `authz.trim_changes()`
  removes old entries; a reader behind them gets an error from `changes_since` (AZ712) and
  reads everything again. <!-- checked: tests/governance.sh "the feed keeps 7 days by default: older entries are trimmed"; tests/governance.sh "a reader behind the trimmed part is told to read everything again" -->
  A reader that starts, or starts again, first notes where the feed is,
  `SELECT greatest((SELECT max(pos) FROM authz.changes), (SELECT value::bigint FROM authz.settings WHERE key =
  'changes_trimmed_to'), 0)`, then reads everything, then follows from that position.
- **Requests and approvals**: people ask, those who may share the relation decide;
  approval makes a share that ends after the requested time. <!-- checked: tests/governance.sh "erin (who may share Secrets) sees it to decide"; tests/governance.sh "the share ends after the requested week" -->
  Requesters can't
  decide their own, and asking doesn't reveal whether a hidden object exists. <!-- checked: tests/governance.sh "carol cannot approve her own request"; tests/adversarial.sh "request_access('file', ID, 'viewer', 'curious') IS NOT NULL"; tests/governance.sh "a request for a missing object reaches no approver" -->
  A pending request goes with its requester's row and with its object's: deleting either, giving it a new id or
  emptying its table cancels the request (`status` cancelled, the `note` says why), so it never reaches whoever
  later has that id, and approving it is refused. <!-- checked: tests/governance.sh "a pending request is cancelled when its requester is deleted, its object is, or its object gets a new id, and says why"; tests/governance.sh "a later user with the id has none of the old one's requests"; tests/governance.sh "approving the old request for a later folder with the id is refused" -->
  Decided requests stay as they were. <!-- checked: tests/governance.sh "a decided one stays as it was" -->
  Applying the policy cancels those of requesters whose rows went while nothing watched them. <!-- checked: tests/governance.sh "applying the policy cancels the pending requests of requesters whose row is gone" -->
  A request made while its requester is deleted waits for the delete and is refused; a delete in REPEATABLE READ
  or SERIALIZABLE whose snapshot is older than a request on the row fails with a serialization error (40001), to
  retry. <!-- checked: tests/governance.sh "a request made while its requester is deleted waits for the delete, then is refused"; tests/governance.sh "and leaves no request behind"; tests/governance.sh "a delete with an older snapshot than a request on the folder gets a serialization error" -->
- **Break glass**: short, audited, announced self-service access for people the policy
  names with `can break_glass`. <!-- checked: tests/governance.sh "it lasts one day at most"; tests/governance.sh "the trail has it, with the reason"; tests/governance.sh "carol breaks the glass, and the alert goes out" -->
  They pick the relation, among those the policy lets be shared with a user:
  if `editor` is shared, break glass can give `editor`.
- **Access reviews**: a snapshot of an object's shares; each is kept or revoked by
  someone who could unshare it; closing applies the decisions. <!-- checked: tests/governance.sh "closing the review revokes what was marked"; tests/governance.sh "dave (not decided) kept it"; tests/governance.sh "nor revoke it in a review" -->
- **Invariants** run with the policy's tests and on demand. <!-- checked: tests/governance.sh "the policy tests fail on it"; tests/governance.sh "a Globex user owning an Acme folder breaks it" -->
- **Previewing a change**: `python3 core/compile_policy.py new.authz --diff [--users 1,2] | psql -d mydb`
  applies the new policy inside a transaction, lists every (user, object) pair that
  gains or loses each permission, readable row and masked column, then rolls back. <!-- checked: tests/governance.sh "without links, erin would lose joint-plan.md"; tests/governance.sh "and could no longer read its row"; tests/governance.sh "the preview changed nothing"; tests/masks.sh "removing the mask: a viewer gains the text" -->
  It asks as
  every user, as every service or other principal (named `service:7`, also in `--users`) and as nobody. <!-- checked: tests/principals.sh "the preview lists what a service gains"; tests/governance.sh "limits the preview" -->
- **Decision log**: `SET authz_debug.log_decisions = on` writes every `authz.can`
  decision to the server log (for debugging: the app role can turn it on and off). <!-- checked: tests/governance.sh "each decision is logged when asked" -->

## Checking the database

Reports what would let the app role get around row-level security: being a superuser
or BYPASSRLS (directly or through a role), row-level security turned off on a table with rules, owning
a governed table without FORCE ROW LEVEL SECURITY, a policy on a governed table that rowstile didn't make (Postgres joins
permissive policies with OR, so it lets through what the rules don't), TRUNCATE on governed or membership tables, their partitions (or tables
inheriting from them) used directly, a table inheriting from a governed one that was made since the last apply (it
lacks the table's row triggers until the next one), views over governed tables that run with their
owner's rights, SECURITY DEFINER functions that use them,
membership tables the app may write, relationship columns anyone who can update the
row may change, masked columns readable from the table, unique indexes that reveal
hidden rows, missing indexes on the columns permission checks look up (a type's key among them), a select rule whose permissions are
named so many times over that every read is slow to plan ([Speed and limits](limits.md)). As notes, it lists
the tables the app role may read in full: a type's table without rules, a table the policy reads for a
relation (who is in which team), and any table in the same schemas that the policy doesn't name (password
hashes, sessions: nothing filters them; fine for a lookup table). It also
reports privileges on rowstile's own schemas (`authz`, `authz_gen`, `authz_int`) that the policy doesn't
give, and a schema on the search path of rowstile's functions that run as the owner that another role may
create in. Applying takes the first back and refuses the second (AZ612). <!-- checked: tests/adversarial.sh "and the next apply takes it back"; tests/adversarial.sh "and apply refuses it" -->

Applying reports its errors and warnings as warnings, so nobody has to remember to run it. <!-- checked: tests/devx.sh "shows a warning applying gives" -->
It also
warns about a `{condition}` whose bare column a table it reads takes from the row (`m.project_id = id`,
where memberships have an `id` too): the row's is `this.id`. <!-- checked: tests/apply.sh "a bare column a subquery's table takes is warned about when applying, with this.id to write" -->

`authz.connection_check()` is the same idea for the app itself, which may call it: what is wrong with
the connection it runs on (a superuser, BYPASSRLS, the owner of a governed table, a table with rules whose
row-level security is off). <!-- checked: tests/sessions.sh "the owner's connection: an error"; tests/sessions.sh "row-level security off on a table with rules: an error"; tests/sessions.sh "the app's role: nothing to report" -->
A login that is neither the app role nor a member of it can't call it at all
(`permission denied for schema authz`): the rules apply to the app role only. <!-- checked: tests/sessions.sh "a login outside the app role can't call connection_check() at all" -->
A login that is a superuser or
the policy's owner and switched to the app role with `SET ROLE` is an error too: `RESET ROLE` leaves
row-level security, and its sessions are believed without a signature. <!-- checked: tests/sessions.sh "the owner's login, switched to the app role: an error (RESET ROLE, and settings believed unsigned)" -->
Log in as the app role. Call it when the app starts and refuse to start on an
`error`, or its tests pass without testing anything. The clients have `connection_check()` /
`connectionCheck()`.
