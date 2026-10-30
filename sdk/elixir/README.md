# rowstile for Elixir

**Preview.** This package may change in any release; it is not part of what 1.0 keeps stable.

rowstile for Elixir apps on [Ecto](https://hexdocs.pm/ecto_sql) or [Postgrex](https://hexdocs.pm/postgrex): every
transaction signs in as whoever the request or the job acts for, the database filters what it reads and refuses
what it may not write, and the package turns a refusal into `{:error, %Rowstile.Refused{}}` (a 403 with the
reason) and a hidden row into `{:error, %Rowstile.NotFound{}}` (a 404). It holds no rowstile logic: it calls the
`authz.*` functions the policy made, and reads their answers. Elixir 1.18 or newer.

The package is not the `rowstile` command (`rowstile init`, `migrate`, `test`, `client`): install that with
`npm install rowstile@next`, `pip install --pre rowstile` or its Docker image
([Installing](https://rowstile.dev/installing)).

```elixir
# mix.exs
{:rowstile, "~> 0.1.0-dev"}
```

```elixir
Rowstile.put_principal(Rowstile.user(42))       # Rowstile.Plug does it for each request
Rowstile.transact(MyApp.Repo, fn ->
  {changed, _} = MyApp.Repo.update_all(where(Note, id: ^id), set: [body: body])
  with :ok <- Rowstile.expect(MyApp.Repo, changed, "app.notes", "update", id), do: {:ok, id}
end)
```

| part | what |
|---|---|
| `Rowstile.transact(db, fun, opts)` | a transaction signed in (`authz.act_as`), on an Ecto repo or a Postgrex connection, as Ecto's `Repo.transact/2` runs one: `{:ok, value}` commits, `{:error, reason}` rolls back. The sign-in lasts the transaction alone, so pools and PgBouncer in transaction mode are safe. `as:` names who, else whoever the process acts for (`Rowstile.put_principal/1`), else nobody |
| refusals | `{:error, %Rowstile.Refused{}}` (the rule, why, the code), `{:error, %Rowstile.CallError{}}` (the codes a call can meet, each with its status); an Ecto update or delete of a struct that changed no row is asked about: `{:error, %Rowstile.NotFound{}}` or `{:error, %Rowstile.Refused{}}`, or Ecto's `StaleEntryError` when the rules allow it (an optimistic lock: 409) |
| `Rowstile.expect/5` | an `update_all` or `delete_all` that changed no row, asked about: `{:error, %Rowstile.NotFound{}}` or `{:error, %Rowstile.Refused{}}`, with the reason |
| `Rowstile.can?/3`, `perms_of/3`, `list/3` | take only the policy's names, which `rowstile client elixir` writes (`MyApp.Authz.Note.edit()`): a misspelled one is an undefined function, a plain string the compiler's type error |
| `Rowstile.Plug` | sets who each request acts for: `plug Rowstile.Plug, user: &MyAppWeb.Session.principal/1` |
| `Rowstile.Plug.Fallback` | `action_fallback Rowstile.Plug.Fallback`: rowstile's errors as `application/problem+json`; `Rowstile.Plug.send_problem/2` for a fallback of the app's own |
| `Rowstile.Check` | a child of the app's supervisor: the app refuses to start on a connection that skips row-level security |
| `Rowstile.Oban` | Oban jobs for the user who asked: `Rowstile.Oban.args(args)` in the request, `Rowstile.Oban.acting_as(job, fun)` in the worker; a job that names no one acts for nobody, whoever the worker ran before it |
| `Rowstile.Testing` | ExUnit: `database_per_partition/2`, a copy of the migrated test database for each `mix test --partitions` worker; `assert_refused/2`, `assert_not_found/1` |
| errors | `Rowstile.error_code/1` (`AZ709`: `rowstile help AZ709`), `translate/1`, `problem/1` |

Nothing uses a session-level `SET`, so pools and poolers in transaction mode are safe. The guide:
[Phoenix](https://rowstile.dev/stacks/phoenix); its conformance suite: `integrations/phoenix` in the repository.
