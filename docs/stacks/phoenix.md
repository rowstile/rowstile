# Phoenix: Ecto, Postgrex, Plug and Oban

<!-- tested: every line of code below is in integrations/phoenix (tests/unit_test.py checks it) -->

**Preview.** The Elixir SDK may change in any release: it is not part of what 1.0 keeps stable.

A Phoenix app on Ecto (or Postgrex alone), with Ecto's migrations and Oban's jobs. The controllers check nothing:
each request's transactions sign in as its user, the database filters what they read and refuses what they may
not write, and the SDK answers a refusal with 403 and a hidden row with 404.

Everything here comes from [`integrations/phoenix`](../../integrations/phoenix), the conformance suite: a small Phoenix app on Bandit and the
checks every supported stack passes ([`integrations/phoenix/test.sh`](../../integrations/phoenix/test.sh)).

## Install

Add the `:rowstile` package to the deps in `mix.exs` (a preview, on Hex once it is published), then:

```sh
mix deps.get
pip install --pre rowstile                    # the command (or npm install rowstile@next, or its image)
rowstile init                                 # once your migrations made the tables: a first policy from them, a test file, rowstile.toml
```

The SDK needs Postgrex, and Elixir 1.18 or newer (the suite runs on Elixir 1.20). Ecto, Plug and Oban are
optional: its modules for each are there when the app has it.

`rowstile.toml` says where the policy's names go (`[clients]`) and that its migrations are Ecto's. The
conformance app's, with its own name for the variable that holds the owner's connection:

```toml
policy   = "db/policy.authz"
tests    = ["db/tests/*.authz"]
database = "env:ROWSTILE_OWNER_URL"
[clients]
elixir = "lib/conformance/authz.ex"
[migrations]
tool = "ecto"
```

Two roles connect. The owner of the tables runs the migrations, and the app connects as the role the policy
names (`app role conf_app`), which row-level security applies to.

## Sign in every transaction

`Rowstile.Plug` makes each request act for whoever `user` says it is: `{:ok, Rowstile.user(42)}`,
`{:ok, Rowstile.principal("service", 3)}`, or `{:ok, Rowstile.nobody()}`, who sees only what `anyone` may.
`user` reads the session or the token from the request; `{:error, reason}` from it is answered 401. Here it is
`ConformanceWeb.Session.principal/1`, the app's own: yours reads your session cookie or token. The conformance
app has no sign-in, so its stands in for one, and this page doesn't show it.

```elixir
  pipeline :api do
    plug :accepts, ["json"]
    # each request acts for whoever its session or token says
    plug Rowstile.Plug, user: &ConformanceWeb.Session.principal/1
  end
```

`Rowstile.transact(Repo, fun)` runs `fun` in a transaction signed in as whoever the request acts for, as Ecto's
`Repo.transact/2` runs it: `{:ok, value}` commits, `{:error, reason}` rolls back. The sign-in lasts the
transaction alone, so pools and PgBouncer in transaction mode are safe. A list shows only the user's rows:

```elixir
    with {:ok, ids} <-
           Rowstile.transact(Repo, fn ->
             {:ok, Repo.all(from n in Note, order_by: n.id, select: n.id)}
           end) do
      json(conn, ids)
    end
```

A Postgrex connection works the same way, `Rowstile.transact(conn, fn tx -> ... end)`: `fun` gets the
transaction's connection. A sign-in lasts the whole database transaction: inside a transaction `transact`
signed in already (Ecto runs a transaction inside another in the outer one), `fun` runs as it is for the same
principal, and is refused for anyone else, before it runs (a `RuntimeError`), the outer transaction left as it was.

A background job acts for a principal of its own, whatever started it (`type service = app.services principal`
in the policy): `as:` names who.

```elixir
    Rowstile.transact(Repo, fn -> {:ok, Repo.aggregate(Project, :count)} end,
      as: Rowstile.principal("service", 1)
    )
```

An Oban job for the user who asked takes them from its arguments: the request puts them there with
`Rowstile.Oban.args`, and the worker acts for them with `Rowstile.Oban.acting_as`. A job that names no one acts
for nobody, whoever the worker ran before it.

```elixir
      |> Rowstile.Oban.args()
    Rowstile.Oban.acting_as(job, fn ->
      note = %Note{project_id: project_id, author_id: ConformanceWeb.signed_in(), body: body}
      Rowstile.transact(Repo, fn -> Repo.insert(note) end)
    end)
```

Oban's own notifications go through Erlang's process groups here (`notifier: Oban.Notifiers.PG`): a pooler in
transaction mode doesn't keep Postgres's `LISTEN`.

## Refusals

A refused insert is the database's error, which `transact` gives back as `{:error, %Rowstile.Refused{}}`, with
the table, the command, the rule's reasons (`why`) and the code (`AZ709`). The controllers hand their errors to
the SDK's fallback, which answers 403 with them as `application/problem+json`:

```elixir
      # Rowstile.transact's errors: a refusal 403, a hidden row 404, a call turned down as its code's page says
      action_fallback Rowstile.Plug.Fallback
```

An Ecto update or delete the rules refuse changes no row, and Ecto raises its `StaleEntryError`; `transact` asks
the database why, in the same transaction, and gives `{:error, %Rowstile.NotFound{}}` (the user can't see the
row: 404) or `{:error, %Rowstile.Refused{}}` (403, with the reason). So a controller needs no read first:

```elixir
    # no read first: the database says whether the row is there for this user (404) and whether they may (403)
    changed = Ecto.Changeset.change(%Note{id: String.to_integer(id)}, body: body)

    with {:ok, note} <- Rowstile.transact(Repo, fn -> Repo.update(changed) end) do
```

When the rules allow the change and it matched nothing, the row changed since it was read (an optimistic lock,
`Ecto.Changeset.optimistic_lock/3`): `{:error, %Ecto.StaleEntryError{}}`, which the fallback answers 409.
`update_all` and `delete_all` give a count: `Rowstile.expect` asks the same question when it is 0.

```elixir
    {moved, _} =
      Repo.update_all(from(f in Folder, where: f.id == ^id), set: [parent_id: parent_id])

    # 0 rows: expect asks the database why, and answers 404 (hidden) or 403 (with the reason)
    with :ok <- Rowstile.expect(Repo, moved, "app.folders", "update", id), do: {:ok, id}
```

An insert that reads the new row back (`RETURNING`, as `Repo.insert` does) also needs the select rule: if the
user may insert but not read the row, the 403 names the select rule.

A call the database turns down that is no refusal is `{:error, %Rowstile.CallError{}}`, with the status its
code's page gives and the database's words: something it names that isn't there (AZ708) 404, a missing or wrong
argument (AZ710) 400, a call that needs someone signed in (AZ714) or a login refused (AZ703) 401, a folder moved
into one of its own subfolders (AZ713) 409. Anything else raises, as it would: a 500. A query outside a signed-in
transaction raises `Rowstile.NotSignedIn`, the app's bug.

`Rowstile.error_code(e)` is rowstile's code of any database error (`rowstile help AZ702` says what it means).
`Rowstile.problem(e)` and `Rowstile.Plug.send_problem(conn, e)` give the problem body for a fallback of the app's
own.

At start-up, `Rowstile.Check` refuses a connection that skips row-level security (a superuser, BYPASSRLS, the
tables' owner): a child of the app's supervisor, after the repo.

```elixir
    children = [
      Conformance.Repo,
      # the app refuses to start on a connection that skips row-level security
      {Rowstile.Check, Conformance.Repo},
```

## The policy's names

`rowstile client elixir` writes the policy's names as a module for each type and a function for each permission
(`Conformance.Authz.Note.edit()`), in the module its path names (`lib/conformance/authz.ex` is
`Conformance.Authz`). `Rowstile.can?`, `perms_of` and `list` take only those: a misspelled name is an undefined
function, and a plain string is the compiler's type error (`mix compile --warnings-as-errors` fails on both).

```elixir
             {:ok, Rowstile.perms_of(Repo, Authz.Project.type(), ids)}
             {:ok, Rowstile.list(Repo, Authz.Project.view(), page)}
```

To filter a query to the objects the user holds a permission on, join `authz.list` in it:

```elixir
    perm = Authz.Project.edit()

    editable =
      from p in Project,
        join:
          x in fragment(
            "SELECT CAST(x AS bigint) AS id FROM authz.list(?, ?) x",
            ^perm.type,
            ^perm.name
          ),
        on: x.id == p.id,
```

## Migrations

The policy ships as Ecto migrations: `rowstile migrate` writes the next one in `priv/repo/migrations` (a module
whose `up` runs the SQL beside it, only what changed since `db/policy.lock`), and `mix ecto.migrate` applies it
with the others. `mix ecto.migrations` shows each one up; `rowstile migrate --check` in CI fails if a policy
change has no migration. Phoenix's formatter reads the migrations: rowstile's are laid out as `mix format` lays
them out.

```sh
rowstile migrate                                      # after changing the policy
mix ecto.migrate
rowstile migrate --check                              # in CI: exit 1 if a policy change has no migration
```

## Tests

`mix test --partitions N` runs the tests in N processes, each with its `MIX_TEST_PARTITION`: each partition is a
worker. `Rowstile.Testing.database_per_partition` copies the migrated test database for the partition, before the
app connects (`mix test --no-start`, then the app started), so tests that write don't meet another partition's.

```elixir
copy = Rowstile.Testing.database_per_partition(System.fetch_env!("ROWSTILE_TESTS_URL"))
{:ok, _} = Application.ensure_all_started(:conformance)
```

The copy needs nobody connected to the original. Ecto's SQL sandbox works too (`pool:
Ecto.Adapters.SQL.Sandbox`): a `transact` inside a test's sandbox runs in the test's transaction, and is rolled back with it.
`Rowstile.Testing.assert_refused(result, "update")` and `assert_not_found(result)` fail the test unless the result
is one.
