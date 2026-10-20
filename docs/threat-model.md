# Threat model

What rowstile protects, from whom, where it relies on the deployment, and what it does not cover.
Checked by `core/tests/adversarial.sh` (the app role attacking the policy), `tests/identity.sh`
(identity and scopes), `tests/difftest.py` (the database agrees with an independent evaluator) and
`tests/fuzz_parser.py` (broken policies are refused cleanly). <!-- checked: tests/fuzz_parser.py "refused without a line number" -->
rowstile has not been audited by anyone
outside the project.

## What is protected

- **Rows of governed tables**: a table with `rules` in the policy. Who may read, add, change and
  delete each row, down to columns (column rules, masks).
- **Shares, roles, requests, reviews, API keys**: the `authz` tables. The app role changes them only
  through rowstile's own functions, which check that the caller may. <!-- checked: tests/adversarial.sh "writing a share directly"; tests/adversarial.sh "sharing what she may only view" -->
- **The audit trail and the change feed**: the app role can't read or change either. <!-- checked: tests/adversarial.sh "the audit trail"; tests/adversarial.sh "the change feed"; tests/governance.sh "the app role cannot trim" -->
  The audit trail is append-only for administrators too, but for `authz.trim_audit()`, which they run; the
  feed is theirs to trim (`authz.trim_changes()`). <!-- checked: tests/governance.sh "the trail cannot be edited, even by an administrator"; tests/governance.sh "nor by a superuser in replica role: an entry deleted"; tests/governance.sh "older ones go" -->
- **Correct inheritance**: the stored closure tables match the tree at every commit, whatever the
  isolation level or concurrency (`tests/interleave.py`, `tests/stress.sh`). <!-- checked: tests/interleave.py "inheritance tables exact after each"; tests/stress.sh "the inheritance tables match a rebuild" -->

## Who is trusted

| | trusted to | not trusted to |
|---|---|---|
| **Policy authors** (whoever applies it with `rowstile apply`: the tables' owner, or a superuser) | say what the rules are; their `{...}` conditions run as the policy's owner | nothing: a policy can do anything its owner can |
| **Database owner, migration role** | own the tables and apply policies | |
| **The app's backend** (the app role, or a member of it: the roles that may call `authz.act_as()`) | say who is signed in, per transaction | |
| **The app role** (`app role` in the policy; the backend connects as it) | nothing beyond the rules | read or change rows the rules don't allow, touch rowstile's internals, turn row-level security off, share more than it holds, approve its own requests |
| **Anyone signed in with an API key or JWT** | act as that user, within the key's scopes | widen the scopes, act as someone else |

The trust boundary is between the app role and everything above it. A bug in the app (say, SQL
injection) should not let an attacker read hidden rows through queries. What such an attacker can
do depends on identity:

- **On any Postgres, sign-ins are signed**: `authz.act_as()` and the logins sign who is signed in,
  the scopes, the backend and the transaction with a key the app role can't read, and nothing else is
  believed. <!-- checked: tests/sessions.sh "the key is out of the app role's reach"; tests/sessions.sh "a forged signature is an error" -->
  So the app role can't change who is signed in by setting it, widen a key's scopes, leave
  view-as, or reuse a sign-in from another transaction or connection (`tests/sessions.sh`). <!-- checked: tests/sessions.sh "changing authz.user_id after signing in is an error"; tests/sessions.sh "clearing its scopes is an error, not a way to write"; tests/sessions.sh "authz.acting_user too"; tests/sessions.sh "a signature from an earlier transaction is refused in the next one"; tests/sessions.sh "and one from another connection too" -->
- **The app role may call `authz.act_as()`**, so code running as the app role can claim to be anyone. <!-- checked: tests/sessions.sh "authz.act_as signs carol in: she sees her files" -->
  Roles other than the app role
  and its members can't sign anyone in. <!-- checked: tests/sessions.sh "a role that isn't the app role can't act_as"; tests/docs_test.sh "another role can't say who is signed in" -->
- **If the backend role itself is compromised**, the attacker can claim any user either way: the
  backend is trusted to say who is signed in. Keep that role's credentials inside the
  backend, and sign other clients in with keys or JWTs.

## What stops what

| attack (as the app role) | stopped by | checked in |
|---|---|---|
| read a hidden row, by id, by `COPY`, through a prepared statement run as another user | row-level security on every governed table; policies read the user per statement | adversarial.sh <!-- checked: tests/adversarial.sh "a hidden file by id"; tests/adversarial.sh "COPY returns only visible rows"; tests/adversarial.sh "a prepared statement follows the signed-in user" --> |
| see hidden rows through a function in `WHERE` that prints its argument | Postgres runs row-level security before functions that aren't `LEAKPROOF` (only superusers can mark them) | adversarial.sh <!-- checked: tests/adversarial.sh "a cheap leaky function in WHERE sees only visible rows" --> |
| `SET row_security = off`, disable row-level security, drop or add a policy, drop a trigger, replace a generated function | not the owner; `row_security = off` makes the query fail instead | adversarial.sh <!-- checked: tests/adversarial.sh "row_security = off is refused, not obeyed"; tests/adversarial.sh "disabling row-level security"; tests/adversarial.sh "adding a permissive policy"; tests/adversarial.sh "dropping a closure trigger"; tests/adversarial.sh "replacing a generated function" --> |
| read or write `authz_int`, `authz.shares`, `authz.audit`, `authz.changes`, the lock rows; call internal functions | no privileges on them; the app role reads only the `authz_gen` views its rules look up and calls the `authz.*` API | adversarial.sh <!-- checked: tests/adversarial.sh "the shares table"; tests/adversarial.sh "the lock rows"; tests/adversarial.sh "a closure's refresh function"; tests/adversarial.sh "the app role reads only the views its rules look up"; tests/adversarial.sh "a view no rule reads, which lists a file the rules hide" --> |
| use rowstile's tables or administrators' functions through the owner's default privileges, or a grant made since | applying takes back every privilege on rowstile's schemas the policy doesn't give; `authz.lint()` reports later ones | adversarial.sh <!-- checked: tests/adversarial.sh "the owner's default privileges: apply leaves the app role only what the policy gives"; tests/adversarial.sh "lint reports a grant on rowstile's objects made after apply"; tests/adversarial.sh "and the next apply takes it back" --> |
| run code as the owner: a function in a schema on the search path of rowstile's functions that run as the owner, taking a built-in's place | applying refuses a schema on that path that roles other than the owner may create in (AZ612); `authz.lint()` reports one opened later | adversarial.sh <!-- checked: tests/adversarial.sh "and apply refuses it"; tests/adversarial.sh "whichever schema of the applying session's path it is"; tests/adversarial.sh "lint reports a schema on the functions' search path the app role may create in" --> |
| update, delete or upsert onto a hidden row | row-level security (`UPDATE 0`, `DELETE 0`, an error for the upsert) | adversarial.sh <!-- checked: tests/adversarial.sh "updating a hidden row changes nothing"; tests/adversarial.sh "deleting a hidden row changes nothing"; tests/adversarial.sh "an upsert onto a hidden row" --> |
| take ownership, move a row where the user may not write, stop inheritance above a folder | column rules (`update owner_id : share`, `update parent_id after : parent.edit`) | adversarial.sh, scenario.sql <!-- checked: tests/adversarial.sh "bob (may edit, not share) can't take ownership"; tests/adversarial.sh "alice can't move her folder under a folder she may not edit"; tests/adversarial.sh "can't cut it off from the folders above"; tests/scenario.sql "gina cannot switch off inheritance on Design (needs share)" --> |
| share what the user can't share, a relation that isn't shared, or to widen their own access | `authz.share()` checks the relation is shared and the sharer holds what the policy asks | adversarial.sh, multi_scenario.sql <!-- checked: tests/adversarial.sh "sharing what she may only view"; tests/adversarial.sh "sharing a relation the policy doesn't share"; tests/adversarial.sh "sharing a hidden file with herself"; tests/multi_scenario.sql "cannot give the archivist role, for he does not hold archive" --> |
| learn who has access, or the shares or links on, an object they can't share | `authz.who`, `authz.list_shares` and `authz.list_links` refuse, the same way for missing objects; so does `authz.revoke_link`, whether or not the id names a link | adversarial.sh <!-- checked: tests/adversarial.sh "who may see a hidden object"; tests/adversarial.sh "listing the shares of a hidden object"; tests/adversarial.sh "listing the links of a hidden object"; tests/adversarial.sh "answers as for a missing file"; tests/multi_scenario.sql "nor turn one off, whether its id names a link or not" --> |
| approve their own access request, decide one they can't share | `authz.decide_request()` checks the decider | governance.sh, adversarial.sh <!-- checked: tests/governance.sh "carol cannot approve her own request"; tests/governance.sh "alice cannot decide it"; tests/adversarial.sh "approving her own request" --> |
| act as another user; widen a key's scopes; write during "view as" | signed sessions (above); scoped and view-as sessions are read-only where they must be | sessions.sh, identity.sh <!-- checked: tests/sessions.sh "changing authz.user_id after signing in is an error"; tests/identity.sh "a session limited to a scope cannot make a key with another"; tests/identity.sh "and cannot change anything" --> |
| a stale closure table granting access after a move | the type-wide tree lock; serialization errors in stricter isolation levels | interleave.py, stress.sh, concurrency.sh <!-- checked: tests/interleave.py "inheritance tables exact after each"; tests/stress.sh "the inheritance tables match a rebuild"; tests/concurrency.sh "the late writer gets a serialization error (the app retries)" --> |
| a policy with a mistake that silently grants too much | compile-time and apply-time checks with line numbers; conditions that decide inheritance must not depend on time or user | policy_errors.py, fuzz_parser.py <!-- checked: tests/policy_errors.py "inheritance that depends on the time"; tests/policy_errors.py "inheritance that depends on the user"; tests/fuzz_parser.py "refused without a line number" --> |

The review in CI (`rowstile review`, the GitHub action) runs on a pull request's files, which whoever
opened it wrote. An include stays in the policy's folder: no `..` out of it, no absolute path, no link
leading out (AZ108), and the policy, the tests and the lock file `rowstile.toml` names stay in the folder
`rowstile.toml` is in, the same way; so a pull request can't make the review read one of the runner's files, or
its environment, and print it in the job's log (`unit_test.py`, policy_errors.py, cli.sh). <!-- checked: tests/policy_errors.py "a file above the policy's folder"; tests/policy_errors.py "a server file"; tests/unit_test.py "test_reads_nothing_outside_the_policys_folder"; tests/cli.sh "a policy outside rowstile.toml's folder is not read"; tests/cli.sh "nor through a link out of it" -->
A `.env` beside
`rowstile.toml` is read the same way, for the variables that say where the database is and no other: a pull
request's `.env` can't set `PATH` or what `git` runs. <!-- checked: tests/unit_test.py "test_env_files_are_read_for_the_database_only"; tests/cli.sh "a .env that is a link out of the folder isn't read, and the failure says so" -->
And it isn't read when `--db` names the database, as
the review's workflow does: it can't add a host or a port to the URL the workflow gave. <!-- checked: tests/cli.sh "the files aren't read then"; tests/unit_test.py "test_env_files_are_read_for_the_database_only" -->
The review believes the pull
request's `rowstile.toml`, as CI believes its workflow files: run it on `pull_request`, where a fork's pull
request gets no secrets, not on `pull_request_target`.

## Known limits (accepted)

- **Side channels.** Code that can run arbitrary SQL as the app role can learn things it can't read:
  `EXPLAIN ANALYZE` shows how many rows row-level security removed, so an index lookup such as
  `WHERE id = 12` reveals whether a hidden row exists; timing can too. <!-- unchecked: Postgres's own behaviour, which rowstile leaves as it is -->
  Constraints tell it too, to
  any caller: a unique constraint, or a primary key the app lets callers choose (client-made ids, an
  import), refuses an insert that collides with a hidden row (`authz.lint()` lists both); a foreign key
  refuses deleting a row that hidden rows reference (a folder with a hidden file in it). <!-- checked: tests/governance.sh "info app.files_name"; tests/governance.sh "info app.files_pkey" -->
  These are
  Postgres behaviours: let the database make the ids (`GENERATED ALWAYS AS IDENTITY`, random uuids),
  delete the children the user can see first and answer "not empty" for the rest, and keep arbitrary
  SQL away from the app role (the backend decides which queries run).
- **Statistics** of governed tables are hidden from the app role by Postgres (`pg_stats` leaves out
  tables with row-level security), checked in adversarial.sh. <!-- checked: tests/adversarial.sh "table statistics of governed tables are hidden" -->
- **Tables without rules** are readable in full by the app role (`authz.lint()` says so), which suits
  directories such as users and groups. <!-- checked: tests/governance.sh "nor a table the policy names (users has no rules: its own line)" -->
- **SECURITY DEFINER functions the app adds** bypass row-level security unless their owner is subject
  to it; `authz.lint()` lists those it can see. <!-- checked: tests/governance.sh "warning app.peek(bigint)" -->
- **Conditions** read with the policy owner's rights, in rules as in permissions: a subquery sees every row of
  the tables it reads, not only those the signed-in user may ([the language](reference/language.md),
  [Speed and limits](reference/limits.md)). <!-- checked: tests/devx.sh "a rule condition that reads a governed table runs with the policy's rights, as a function"; tests/apply.sh "a condition in a permission sees every membership in its table's rules too" -->
- **Scopes limit what a token does, not what it can find out about its own user.** A scoped session
  (an API key or a JWT with scopes) is held to its scopes by the rules and by `authz.can`, `authz.list` and
  the other `authz.*` functions. <!-- checked: tests/identity.sh "files key: sees no folders (not in its scope)"; tests/identity.sh "read-only key: may view file 11, not edit it" -->
  Code that reads the `authz_gen` views the rules look up, which the app role may,
  sees the ids the user holds those permissions on, whatever the scopes: a `read` token can learn what its
  user may edit, not edit it.
- **Request context** (`authz.ctx(...)`, `authz_ctx.*` settings) is whatever the app sets: a policy that
  trusts it trusts the backend.
- **No outside audit.** rowstile has had self-review only. <!-- unchecked: a fact about the project, not about the code -->
