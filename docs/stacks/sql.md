# Any other stack: the SQL an app sends

<!-- tested: every line of code below is in docs/getting-started.md (run as written by tests/docs_test.sh) or in the SDKs' sources -->

Ruby without Rails, or a Python, Node, Go, Java or Rust app without the SDKs: rowstile needs no library. The SDKs
send the few statements on this page and translate the answers; any language that speaks to Postgres can do
the same.

## Connect as the app role

The app connects as the role the policy names (`app role app_user`), never as the tables' owner or a superuser:
row-level security doesn't apply to them, so the database would filter nothing. Check once at start, and
refuse to start on a row whose severity is `error`:

```sql
SELECT severity, problem FROM authz.connection_check()
```

## Sign in every transaction

Every transaction starts by saying who is asking. The sign-in is signed and lasts one transaction, so it is
safe with pools and poolers in transaction mode ([Behind a pooler](../operations.md#behind-a-pooler)), and code
that runs later can't change it:

```sql
BEGIN;
SELECT authz.act_as('user', '2');                   -- bo is a writer
SELECT * FROM app.notes;                            -- Chapter one
UPDATE app.notes SET body = 'Chapter one, again';   -- allowed: he may edit the project
SELECT authz.can('project', 1, 'share');            -- false
SELECT * FROM authz.explain('project', 1, 'share'); -- why not
COMMIT;
```

Another principal type of the policy (a service, a bot) signs in the same way, `authz.act_as('service', '3')`.
Nobody (only what `anyone` may see) is:

```sql
SELECT authz.act_as(NULL, NULL)
```

A transaction that forgets gets an error, not an empty page: SQLSTATE `28000`, with a hint naming
`authz.act_as`. That is a bug in the app, not the user's doing.

## Answer refusals

Every error the app meets from rowstile names its code in the HINT, `rowstile help AZ709`: branch on the code, and
`rowstile help` (or [`docs/errors/`](../errors/)) says what it means, its SQLSTATE, and the HTTP status to answer it with.

- **A refused INSERT, or an UPDATE whose new row the rules refuse**: SQLSTATE `42501`. The message names the
  table and the command (`may not insert this row into app.notes`), the constraint is `authz_<command>`, and
  the DETAIL says why, one reason per line. Answer 403 with the reason.
- **An UPDATE or DELETE that changed 0 rows**: row-level security skips rows silently. Ask why:

```sql
SELECT authz.explain_rule($1, $2, $3, NULL)
```

  with the table (`app.notes`), the command (`update` or `delete`) and the row's id. NULL means the user can't
  see the row: answer 404. Otherwise it is the reasons, the first line starting with `no`: answer 403 with
  them. A first line starting with `yes` means the rule allows it and the statement matched nothing for
  another reason (a `WHERE` with more than the key): 404 again.
- **An INSERT ... RETURNING** also needs the select rule: Postgres refuses with its own message
  (`new row violates row-level security policy`) when the user may insert the row but not read it back.

## Ask about permissions

`authz.can(type, id, perm)` for one object, and for a list's buttons one call:

```sql
SELECT id, perms FROM authz.perms_of(:t, CAST(:ids AS text[]))
```

To filter a query to the objects the user holds a permission on, join `authz.list(type, perm)`.

## Migrations

Policy changes ship as migrations for your tool: `tool = "goose"`, `"dbmate"`, `"flyway"` or `"sql"`
(numbered or timestamped files) in `rowstile.toml`. `rowstile migrate` writes the next one, and your tool
applies it with the others; `rowstile migrate --check` in CI fails if a policy change has none. The command
installs with `pip install --pre rowstile`, `npm install rowstile@next` (the newest pre-release), or
as a Docker image: [Installing](../installing.md).
