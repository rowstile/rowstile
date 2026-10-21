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
  Reviews are for users: a service signed in is refused each call, saying so (AZ715). <!-- checked: tests/principals.sh "authz.start_review is for users: a service is told so"; tests/principals.sh "authz.review_items is for users: a service is told so"; tests/principals.sh "authz.review_decide is for users: a service is told so"; tests/principals.sh "authz.close_review is for users: a service is told so" -->
- **Invariants** run with the policy's tests and on demand. <!-- checked: tests/governance.sh "the policy tests fail on it"; tests/governance.sh "a Globex user owning an Acme folder breaks it" -->
- **Previewing a change**: `rowstile diff new.authz [--users 1,2]`
  applies the new policy inside a transaction, lists every (user, object) pair that
  gains or loses each permission, readable row and masked column, then rolls back. <!-- checked: tests/cli.sh "diff lists who loses what"; tests/cli.sh "diff changed nothing"; tests/governance.sh "without links, erin would lose joint-plan.md"; tests/governance.sh "and could no longer read its row"; tests/governance.sh "the preview changed nothing"; tests/masks.sh "removing the mask: a viewer gains the text" -->
  It asks as
  every user, as every service or other principal (named `service:7`, also in `--users`) and as nobody. <!-- checked: tests/principals.sh "the preview lists what a service gains"; tests/governance.sh "limits the preview" -->
  A user whose id holds `:` or is `nobody` is named `user:<id>` there, as in the audit trail. <!-- checked: tests/principals.sh "the preview names them the same way"; tests/principals.sh "and the users asked for are named so: user:service:1 is that user alone" -->
- **Decision log**: `SET authz_debug.log_decisions = on` writes every `authz.can`
  decision to the server log (for debugging: the app role can turn it on and off). <!-- checked: tests/governance.sh "each decision is logged when asked" -->
  Each line names who asked as the audit trail does (`42`, `service:7`). <!-- checked: tests/principals.sh "the decision log names it as the audit trail does" -->

## Checking the database

`authz.lint()` (`rowstile lint`) reports what would let the app role get around row-level security, and what
makes reads through the rules slow. Each finding has a severity. These are errors:

- The app role doesn't exist. <!-- checked: tests/apply.sh "lint reports an app role that does not exist, and nothing more" -->
- The app role is a superuser or has BYPASSRLS, itself or through a role it is a member of. <!-- checked: tests/apply.sh "lint reports an app role that is a member of a role with BYPASSRLS: an error"; tests/apply.sh "and one that has BYPASSRLS itself" -->
- The app role is the policy's owner, or a member of it: who is signed in is believed without a signature, and
  it may read rowstile's tables and turn row-level security off. Applying refuses such an app role (AZ624), and
  lint finds one that became a member since. <!-- checked: tests/apply.sh "applying refuses the policy's owner as the app role"; tests/apply.sh "and applying refuses it, saying why"; tests/apply.sh "lint reports an app role that is a member of the policy's owner: an error" -->
- The app role owns a type's table, or is a member of a role that does. An owner skips row-level security and
  may turn it off, so `FORCE ROW LEVEL SECURITY` is no way out: the app role must not own the tables. <!-- checked: tests/governance.sh "lint finds: a governed table owned by the app role"; tests/governance.sh "and one owned by a role the app role is a member of"; tests/governance.sh "FORCE ROW LEVEL SECURITY or not, since an owner may turn it off" -->
- Row-level security is off on a table with rules. <!-- checked: tests/governance.sh "lint finds row-level security off on a table with rules: an error" -->
- A permissive policy on a table with rules that rowstile didn't make: Postgres joins permissive policies with
  OR, so it lets through what the rules don't. (A restrictive one is a note.) <!-- checked: tests/governance.sh "lint finds it: an error, with the policy's name, why it widens the rules and how to drop it"; tests/governance.sh "a restrictive one is a note" -->
- TRUNCATE on a type's table or a membership table, which skips row-level security. <!-- checked: tests/governance.sh "error app.files"; tests/governance.sh "error app.team_members" -->
- A partition of a table with rules (or a table inheriting from one) that the app role may use directly, or
  TRUNCATE. <!-- checked: tests/children.sh "lint says the app role may use it directly"; tests/children.sh "lint says the app role may empty a partition of the table a condition reads, which skips its triggers" -->
- A partition or a table inheriting from a type's table made since the last apply: it lacks the table's row and
  statement triggers until the next one. <!-- checked: tests/adversarial.sh "lint reports a table made after apply that inherits from a governed one"; tests/children.sh "lint names each, and the triggers it lacks"; tests/children.sh "lint names a partition made since of a table without rules, and the statement triggers it lacks" -->
- A view over a governed table that runs with its owner's rights (without `security_invoker`), which the app role
  may read. <!-- checked: tests/governance.sh "error app.all_files"; tests/capitals.sh "a view of Folder that skips its rules" -->
- A membership table the app role may write, without rules. <!-- checked: tests/governance.sh "of the link table, that the app role may change it (an insert is enough)" -->
- A masked column the app role may read from the table. <!-- checked: tests/masks.sh "lint reports a column readable through a role membership"; tests/masks.sh "lint reports: GRANT SELECT (body) ON mt.docs TO PUBLIC" -->
- A privilege on rowstile's own schemas (`authz`, `authz_gen`, `authz_int`) or what is in them that the policy
  doesn't give. Applying takes it back. <!-- checked: tests/adversarial.sh "lint reports a grant on rowstile's objects made after apply"; tests/adversarial.sh "and the next apply takes it back" -->
- A schema on the search path of rowstile's functions that run as the owner, which another role may create in.
  Applying refuses it (AZ612). <!-- checked: tests/adversarial.sh "lint reports a schema on the functions' search path the app role may create in"; tests/adversarial.sh "and apply refuses it" -->

These are warnings:

- A SECURITY DEFINER function the app role may call, which seems to use a governed table. <!-- checked: tests/governance.sh "and says of the function what it does" -->
- A column that gives a relation, which anyone who may update the row may change (no rule on the column). <!-- checked: tests/governance.sh "lint finds a column that gives a relation and that an editor may change" -->
- A column that moves a row under another of its type, with nothing checking where it moves to (no `after` rule). <!-- checked: tests/governance.sh "lint finds a move nothing checks the destination of" -->
- A rule for a command the app role has no privilege for: it never applies, and the statement fails with
  Postgres's own "permission denied". <!-- checked: tests/governance.sh "lint finds a delete rule the app role has no privilege for" -->
- A trigger that guards the audit trail but doesn't fire in every replication role (`ENABLE ALWAYS`), as
  `pg_restore --data-only --disable-triggers` leaves it. `rowstile reapply` puts it back. <!-- checked: tests/governance.sh "lint finds the audit trail's guard on in ordinary sessions only, and says what puts it back"; tests/governance.sh "and on in replica sessions only: lint says ordinary sessions may change the trail" -->
- A permission, or a select rule, that names others so many times over that every check of it is slow to plan
  ([Speed and limits](limits.md)). <!-- checked: tests/governance.sh "lint finds a permission no rule reads that is slow to plan"; tests/unit_test.py "test_many_expansions_are_a_lint_warning" -->

As `performance`, it names each lookup the permission checks make that no index serves (a type's key among
them), with the index to add. <!-- checked: tests/governance.sh "without it, lint names the lookup by the key, and the index to add"; tests/governance.sh "lint finds a lookup an index with a condition doesn't serve" -->
As notes, it lists:

- The tables the app role may read in full: a type's table without rules, a table the policy reads for a
  relation (who is in which team), and any table in the same schemas that the policy doesn't name (password
  hashes, sessions: nothing filters them; fine for a lookup table). <!-- checked: tests/governance.sh "nor a table the policy names (users has no rules: its own line)"; tests/capitals.sh "lint says of the link table that the app role reads it in full, and for which relation"; tests/governance.sh "lint finds a table the policy doesn't name, which the app role may read" -->
- A unique index on a table with rules, and a primary key the app role may choose: an insert that collides with
  a hidden row fails, which tells the user it exists. <!-- checked: tests/governance.sh "of the unique indexes the app role may insert against, those on tables with rules only"; tests/governance.sh "info app.files_pkey" -->
- A relation named like a type that signs in (`user`): alone in a rule, it reads like any user. <!-- checked: tests/governance.sh "lint notes a relation named like a type that signs in, with its line" -->
- A type that signs in but has no `manage_keys` permission, so nobody can make API keys for it. <!-- checked: tests/principals.sh "lint notes a principal type nobody can make keys for, with its line" -->

Applying reports its errors and warnings as warnings, so nobody has to remember to run it. <!-- checked: tests/devx.sh "shows a warning applying gives" -->
It also
warns about a `{condition}` whose bare column a table it reads takes from the row (`m.project_id = id`,
where memberships have an `id` too): the row's is `this.id`. <!-- checked: tests/apply.sh "a bare column a subquery's table takes is warned about when applying, with this.id to write" -->

`authz.connection_check()` is the same idea for the app itself, which may call it: what is wrong with
the connection it runs on (a superuser, BYPASSRLS, the policy's owner or a member of it, the owner of a table
with rules, `FORCE ROW LEVEL SECURITY` or not, a table with rules whose row-level security is off). <!-- checked: tests/sessions.sh "the owner's connection: an error"; tests/sessions.sh "that says it is the policy's owner, whose sessions are believed unsigned"; tests/sessions.sh "a login in the app role that owns a table with rules: an error, FORCE ROW LEVEL SECURITY or not"; tests/sessions.sh "a login in the app role with BYPASSRLS: an error, and the only one"; tests/sessions.sh "row-level security off on a table with rules: an error"; tests/sessions.sh "the app's role: nothing to report" -->
A login that is neither the app role nor a member of it can't call it at all
(`permission denied for schema authz`): the rules apply to the app role only. <!-- checked: tests/sessions.sh "a login outside the app role can't call connection_check() at all" -->
A login that is a superuser or
the policy's owner and switched to the app role with `SET ROLE` is an error too: `RESET ROLE` leaves
row-level security, and its sessions are believed without a signature. <!-- checked: tests/sessions.sh "the owner's login, switched to the app role: an error (RESET ROLE, and settings believed unsigned)" -->
Log in as the app role. Call it when the app starts and refuse to start on an
`error`, or its tests pass without testing anything. The clients have `connection_check()` /
`connectionCheck()`.
