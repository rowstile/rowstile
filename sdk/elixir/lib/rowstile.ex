defmodule Rowstile do
  @moduledoc """
  rowstile for Elixir apps, on Ecto or Postgrex (a preview: it may change in any release).

  Every transaction signs in as whoever the request (or the job) acts for, with `authz.act_as()`; the database's
  refusals become `Rowstile.Refused` (a 403 with the reason), rows the user can't see `Rowstile.NotFound` (a 404),
  and the other codes the runtime answers with `Rowstile.CallError` (each with its page's status). The package
  holds no rowstile logic: it calls the `authz.*` functions the policy made, and translates their answers.

      Rowstile.put_principal(Rowstile.user(42))    # Rowstile.Plug does it for each request
      Rowstile.transact(MyApp.Repo, fn ->
        {:ok, MyApp.Repo.all(MyApp.Note)}          # only the notes user 42 may see
      end)

  `db` is an Ecto repo (`MyApp.Repo`) or a Postgrex connection. In a web app, `Rowstile.Plug` sets who each
  request acts for, and `Rowstile.Plug.Fallback` answers rowstile's errors as `application/problem+json`.
  `Rowstile.Check` refuses a connection that skips row-level security, at start-up. The policy's names come from
  `rowstile client elixir`, and `can?/3`, `perms_of/3` and `list/3` take only those.
  """

  alias Rowstile.{ConnectionProblem, Errors, NotFound, ObjectType, Permission, Principal, Refused}

  @typedoc "An Ecto repo (a module) or a Postgrex connection (inside `transact/3`, the one it gives)."
  @type db :: module() | DBConnection.conn()

  @typedoc "A row's key: a value, or a list of its columns' values for a key of several."
  @type key :: term()

  @typedoc """
  An RFC 9457 problem body: a refusal's (403, with `table`, `command`, `why` and `code`), a hidden row's (404), a
  call the database turned down (with `code`), or a row that changed since it was read (409).
  """
  @type problem :: %{
          required(:type) => String.t(),
          required(:title) => String.t(),
          required(:status) => pos_integer(),
          required(:detail) => String.t(),
          optional(:table) => String.t() | nil,
          optional(:command) => String.t() | nil,
          optional(:why) => [String.t()],
          optional(:code) => String.t()
        }

  @typedoc "What `transact/3` gives back for rowstile's errors, beside the function's own `{:error, reason}`."
  @type error :: Refused.t() | NotFound.t() | Rowstile.CallError.t() | Exception.t()

  ## Who

  @doc "The user whose id this is, whatever it holds (`\"service:3\"` too: ids come from outside)."
  @spec user(term()) :: Principal.t()
  def user(id), do: %Principal{type: "user", id: to_string(id)}

  @doc "A principal of another type the policy declares: `Rowstile.principal(\"service\", 3)`."
  @spec principal(String.t(), term()) :: Principal.t()
  def principal(type, id) when is_binary(type), do: %Principal{type: type, id: to_string(id)}

  @doc "No one signed in: only what `anyone` may see."
  @spec nobody() :: Principal.t()
  def nobody, do: %Principal{type: nil, id: nil}

  @doc """
  Makes the calling process act for `who`: every transaction `transact/3` begins in it signs in as them.
  `Rowstile.Plug` calls it for each request. A process the request starts (a `Task`) acts for no one: give it
  `as:` or call this in it.
  """
  @spec put_principal(Principal.t()) :: :ok
  def put_principal(%Principal{} = who) do
    Process.put(:rowstile_principal, who)
    :ok
  end

  @doc "Who the calling process acts for, or `nil` when nothing set it (`transact/3` then signs in as nobody)."
  @spec current() :: Principal.t() | nil
  def current, do: Process.get(:rowstile_principal)

  @doc "Runs `fun` acting for `who`, and gives back what it returns; then the process acts for whoever it did before."
  @spec acting_as(Principal.t(), (-> result)) :: result when result: term()
  def acting_as(%Principal{} = who, fun) when is_function(fun, 0) do
    before = Process.get(:rowstile_principal)
    Process.put(:rowstile_principal, who)

    try do
      fun.()
    after
      if before,
        do: Process.put(:rowstile_principal, before),
        else: Process.delete(:rowstile_principal)
    end
  end

  ## Transactions

  @doc """
  Runs `fun` in a transaction signed in as whoever the process acts for (nobody, if nothing set it; `as:` names
  someone else), as Ecto's `Repo.transact/2` runs it: `fun` returns `{:ok, value}`, which commits, or
  `{:error, reason}`, which rolls back. The sign-in lasts the transaction alone, so pools and poolers in
  transaction mode are safe.

  The database's refusals come back as `{:error, %Rowstile.Refused{}}`, the calls it turns down as
  `{:error, %Rowstile.CallError{}}`, and an Ecto update or delete of a struct that changed no row (Ecto's
  `StaleEntryError`) is asked about, in the same transaction: `{:error, %Rowstile.NotFound{}}` (the user can't see
  the row) or `{:error, %Rowstile.Refused{}}` (and why); one the rules allow changed since it was read (an
  optimistic lock): `{:error, %Ecto.StaleEntryError{}}`, a 409. Anything else raises, as it would (the
  not-signed-in error as `Rowstile.NotSignedIn`).

  `fun` takes no argument, or the transaction's `db`: the repo, or Postgrex's connection, on which to run the
  statements. Other options go to the repo's (or Postgrex's) `transaction`.

  A sign-in lasts the whole database transaction. So inside a transaction `transact` signed in already (Ecto runs
  a `Repo.transaction` inside another in the outer one; so does Postgrex, on the connection it gives), `fun` runs
  as it is when `who` is the principal it is signed in as, and is refused when it is someone else: a
  `RuntimeError`, raised before `fun` runs or anything is sent, the outer transaction left as it was. A
  transaction of its own (another process, or a Postgrex transaction on another connection) signs in as usual.
  """
  @spec transact(db(), (-> {:ok, v} | {:error, e}) | (db() -> {:ok, v} | {:error, e}), keyword()) ::
          {:ok, v} | {:error, e | error()}
        when v: term(), e: term()
  def transact(db, fun, opts \\ []) when is_function(fun, 0) or is_function(fun, 1) do
    {who, opts} = Keyword.pop_lazy(opts, :as, fn -> current() || nobody() end)
    signed = Process.get({:rowstile_signed, db})

    if signed && signed != who do
      raise "this transaction is signed in as #{signed} already, and a sign-in lasts the database transaction: " <>
              "#{who}'s work can't run inside it. Run it after, or in a transaction of its own (another connection)"
    end

    try do
      if repo?(db),
        do: db.transaction(fn -> run(db, who, fun) end, opts),
        else: Postgrex.transaction(db, &run(&1, who, fun), opts)
    rescue
      error -> failed(error, __STACKTRACE__)
    end
  end

  # the transaction's body: signed in (unless the transaction around it is), and fun's result
  defp run(tx, who, fun) do
    # inside a transaction transact signed in as who already (transact refused anyone else): as it is
    outer = Process.get({:rowstile_signed, tx})
    _ = if !outer, do: sign_in(tx, who)
    Process.put({:rowstile_signed, tx}, who)

    result =
      try do
        acting_as(who, fn -> attempt(tx, fun) end)
      after
        if !outer, do: Process.delete({:rowstile_signed, tx})
      end

    case result do
      {:ok, value} -> value
      {:error, reason} -> rollback(tx, reason)
    end
  end

  # fun's result; an Ecto update or delete that changed no row, asked about while the transaction is still open
  defp attempt(tx, fun) do
    if is_function(fun, 1), do: fun.(tx), else: fun.()
  rescue
    error ->
      case error do
        %{__struct__: Ecto.StaleEntryError, changeset: %{action: action, data: %schema{} = row}}
        when is_atom(action) ->
          %{__meta__: %{prefix: prefix, source: source}} = row

          table =
            Enum.join(Enum.reject([prefix || schema.__schema__(:prefix), source], &is_nil/1), ".")

          key = Enum.map(schema.__schema__(:primary_key), &Map.fetch!(row, &1))

          case verdict(tx, table, Atom.to_string(action), key) do
            # the rules allow it, and it matched nothing: the row changed since it was read (an optimistic lock)
            {:allowed, _} -> {:error, error}
            {_, refusal} -> {:error, refusal}
          end

        _ ->
          reraise error, __STACKTRACE__
      end
  end

  defp failed(error, stacktrace) do
    case Errors.translate(error) do
      %struct{} = known when struct in [Refused, NotFound, Rowstile.CallError] -> {:error, known}
      translated -> reraise translated, stacktrace
    end
  end

  defp sign_in(tx, %Principal{id: nil}), do: query!(tx, "SELECT authz.act_as(NULL, NULL)", [])

  defp sign_in(tx, %Principal{type: type, id: id}),
    do: query!(tx, "SELECT authz.act_as($1, $2)", [type, id])

  defp rollback(tx, reason) do
    if repo?(tx), do: tx.rollback(reason), else: Postgrex.rollback(tx, reason)
  end

  defp repo?(db),
    do: is_atom(db) and Code.ensure_loaded?(db) and function_exported?(db, :__adapter__, 0)

  # the rows of a statement, on the repo or the connection; the database's errors translated (Rowstile's own raised)
  defp query!(db, sql, params) do
    result = if repo?(db), do: db.query!(sql, params), else: Postgrex.query!(db, sql, params)
    result.rows
  rescue
    error in Postgrex.Error -> reraise Errors.translate(error), __STACKTRACE__
  end

  # the table as the policy names it (a table named without its schema is looked up on the search_path),
  # authz.explain_rule's answer, and who is signed in, in the words the database's own refusals use
  @explain_rule "SELECT authz.explain_rule(t.tbl, $2, $3, NULL), " <>
                  "coalesce((SELECT p.principal_type || ' ' || p.principal_id FROM authz.principal() p), " <>
                  "'someone not signed in'), t.tbl FROM (SELECT coalesce((SELECT n.nspname || '.' || c.relname " <>
                  "FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace " <>
                  "WHERE position('.' in $1::text) = 0 AND c.oid = pg_catalog.to_regclass(pg_catalog.quote_ident($1::text))), " <>
                  "$1::text) AS tbl) t"

  @doc """
  `:ok` when an UPDATE or DELETE changed rows (`changed`: the count `Repo.update_all/3` or `Repo.delete_all/2`
  gives, or a Postgrex result's `num_rows`). When it changed none, row-level security left the row out: `expect`
  asks the database why, in the same transaction, and gives `{:error, %Rowstile.NotFound{}}` (the user can't see
  the row, or the statement matched nothing for another reason, such as a `WHERE` with more than the key) or
  `{:error, %Rowstile.Refused{}}`, worded as the database words a refused insert: "permission denied: user 2 may
  not update row 7 of app.notes". `key`: the row's key, or a list of its columns for a key of several.

      {changed, _} = Repo.update_all(where(Note, id: ^id), set: [body: body])
      with :ok <- Rowstile.expect(Repo, changed, "app.notes", "update", id), do: {:ok, id}
  """
  @spec expect(db(), non_neg_integer(), String.t(), String.t(), key()) ::
          :ok | {:error, NotFound.t() | Refused.t()}
  def expect(_db, changed, _table, _command, _key) when changed > 0, do: :ok

  def expect(db, 0, table, command, key) do
    {_, verdict} = verdict(db, table, command, key)
    {:error, verdict}
  end

  # what authz.explain_rule says of an update or a delete that changed nothing: the row hidden (no lines), the rule
  # allowing it (its first line says yes: the statement matched nothing for another reason), or a refusal and why
  defp verdict(db, table, command, key) do
    [[why, who, named]] = query!(db, @explain_rule, [table, command, key_text(key)])

    case why do
      nil ->
        {:hidden, %NotFound{table: named, id: key_text(key)}}

      [first | _] ->
        if String.starts_with?(String.trim_leading(first), "yes") do
          {:allowed, %NotFound{table: named, id: key_text(key)}}
        else
          message =
            "permission denied: #{who} may not #{command} row #{key_text(key)} of #{named}"

          {:refused, %Refused{message: message, table: named, command: command, why: why}}
        end
    end
  end

  @doc """
  A row's key as Postgres writes it: `7`, or `(1,2)` for a key of several columns, a field quoted only where
  Postgres would (empty, or holding a comma, a quote, a backslash, a parenthesis or a space). What a message shows,
  and what `authz.explain_rule` reads back.
  """
  @spec key_text(key()) :: String.t()
  def key_text([one]), do: key_text(one)

  def key_text(fields) when is_list(fields),
    do: "(" <> Enum.map_join(fields, ",", &field_text/1) <> ")"

  def key_text(key), do: to_string(key)

  defp field_text(nil), do: ""

  defp field_text(value) do
    text = to_string(value)

    if text == "" or String.match?(text, ~r/[",\\()\s]/) do
      ~s(") <> String.replace(String.replace(text, "\\", "\\\\"), ~s("), ~s("")) <> ~s(")
    else
      text
    end
  end

  ## Questions

  @doc """
  Whether whoever `db`'s transaction signed in as holds `perm` on the object with this id:
  `Rowstile.can?(Repo, MyApp.Authz.Note.edit(), 7)`.
  """
  @spec can?(db(), Permission.t(), key()) :: boolean()
  def can?(db, %Permission{type: type, name: name}, id) do
    [[allowed]] = query!(db, "SELECT authz.can($1, $2::text, $3)", [type, key_text(id), name])
    allowed == true
  end

  @doc """
  The permissions held on each of these objects, by id as the database writes it, in one call (a list's
  buttons): `%{"1" => ["edit", "view"]}`.
  """
  @spec perms_of(db(), ObjectType.t(), [key()]) :: %{String.t() => [String.t()]}
  def perms_of(db, %ObjectType{name: type}, ids) do
    rows =
      query!(db, "SELECT id, perms FROM authz.perms_of($1, CAST($2 AS text[]))", [
        type,
        Enum.map(ids, &key_text/1)
      ])

    Map.new(rows, fn [id, perms] -> {id, perms} end)
  end

  @doc """
  The ids of the objects of `perm`'s type on which whoever `db`'s transaction signed in as holds `perm`, in key
  order. With `limit:` (and `after:`, the last id of the page before), that page alone: the database says when
  its size or its cursor is wrong (`Rowstile.CallError`, 400). To filter a query to them instead, join
  `authz.list(type, perm)` in it.
  """
  @spec list(db(), Permission.t(), keyword()) :: [String.t()]
  def list(db, %Permission{type: type, name: name}, page \\ []) do
    after_id = if Keyword.has_key?(page, :after), do: key_text(page[:after])

    rows =
      query!(db, "SELECT x FROM authz.list($1, $2, $3, $4) x", [
        type,
        name,
        after_id,
        page[:limit]
      ])

    Enum.map(rows, &hd/1)
  end

  ## Start-up

  @doc """
  `:ok` on a connection row-level security applies to, and `{:error, %Rowstile.ConnectionProblem{}}` on one that
  skips it (a superuser, BYPASSRLS, the tables' owner): call it at start-up (`Rowstile.Check` does), and refuse
  to start on an error. As nobody: there is no request yet to ask who is signed in.
  """
  @spec check_connection(db()) :: :ok | {:error, ConnectionProblem.t()}
  def check_connection(db) do
    {:ok, rows} =
      transact(
        db,
        fn tx ->
          {:ok,
           query!(tx, "SELECT problem FROM authz.connection_check() WHERE severity = 'error'", [])}
        end,
        as: nobody()
      )

    case rows do
      [] -> :ok
      problems -> {:error, %ConnectionProblem{problems: Enum.map(problems, &hd/1)}}
    end
  end

  ## Errors

  @doc """
  rowstile's code for an error (`"AZ709"`: `rowstile help AZ709` says what it means), from the HINT, where the
  runtime puts it, or the message; `nil` for an error rowstile didn't raise.
  """
  @spec error_code(term()) :: String.t() | nil
  defdelegate error_code(error), to: Errors, as: :code

  @doc """
  The error as rowstile's when it is one: a refusal `Rowstile.Refused`, the not-signed-in error (AZ701)
  `Rowstile.NotSignedIn`, a call turned down `Rowstile.CallError`; anything else as it is.
  """
  @spec translate(Exception.t()) :: Exception.t()
  defdelegate translate(error), to: Errors

  @doc """
  The problem body for an error rowstile answers: a refusal 403, a hidden row 404, a call the database turned down
  as its code's page says (AZ703, AZ714: 401; AZ708: 404; AZ710: 400; AZ713: 409), with the database's words, and
  an Ecto update the rules allow of a row that changed since it was read 409. Anything else (the not-signed-in
  error, a share the policy doesn't declare, a name not in the policy, who is signed in changed by hand) is the
  app's mistake: `:error`, for a 500.
  """
  @spec problem(term()) :: {:ok, problem()} | :error
  defdelegate problem(error), to: Errors
end
