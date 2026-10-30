defmodule Rowstile.Testing do
  @moduledoc """
  The SDK's help for an app's tests (ExUnit): a copy of the migrated test database for each test partition, and
  assertions on refusals.

      # test/test_helper.exs, with `mix test --no-start` (the copy is made before the app connects)
      copy = Rowstile.Testing.database_per_partition(System.fetch_env!("TESTS_OWNER_URL"))
      repo = Application.fetch_env!(:my_app, MyApp.Repo)
      Application.put_env(:my_app, MyApp.Repo, Keyword.put(repo, :database, copy))
      {:ok, _} = Application.ensure_all_started(:my_app)

  `mix test --partitions N` runs the tests in N processes, each with its `MIX_TEST_PARTITION`: each is a worker,
  and gets its own database, named after the one it copies and the partition. Tests of one partition share it.
  """

  import ExUnit.Assertions

  @doc """
  Copies the migrated test database `owner_url` names (with the policy) for this test partition, and gives the
  copy's name: `<database>_<partition>`. The copy is made by a role that may create databases (the owner), while
  nothing else is connected to the original. A copy an earlier run left is made again, unless `fresh: false`.
  `partition:` defaults to `MIX_TEST_PARTITION` (1 without it).
  """
  @spec database_per_partition(String.t(), keyword()) :: String.t()
  def database_per_partition(owner_url, opts \\ []) do
    uri = URI.parse(owner_url)

    template =
      case uri.path do
        "/" <> name when name != "" ->
          URI.decode(name)

        _ ->
          raise ArgumentError, "#{inspect(owner_url)} is not a URL that names a database to copy"
      end

    partition =
      Keyword.get_lazy(opts, :partition, fn -> System.get_env("MIX_TEST_PARTITION", "1") end)

    name = "#{template}_#{partition}"
    # (before the app is started: mix test --no-start)
    {:ok, _} = Application.ensure_all_started(:postgrex)
    {:ok, conn} = Postgrex.start_link(connection(uri))

    try do
      copy(conn, template, name, Keyword.get(opts, :fresh, true))
    rescue
      # something is connected to the original (Postgres has waited five seconds for it to leave)
      error in Postgrex.Error ->
        reraise held(error, template), __STACKTRACE__
    after
      GenServer.stop(conn)
    end
  end

  defp copy(conn, template, name, fresh) do
    %{rows: [[exists]]} =
      Postgrex.query!(conn, "SELECT EXISTS (SELECT FROM pg_database WHERE datname = $1)", [name])

    _ =
      if exists and fresh,
        do: Postgrex.query!(conn, "DROP DATABASE #{ident(name)} WITH (FORCE)", [])

    # CREATE DATABASE ... TEMPLATE needs no one connected to the original, this connection included
    _ =
      if fresh or not exists,
        do:
          Postgrex.query!(conn, "CREATE DATABASE #{ident(name)} TEMPLATE #{ident(template)}", [])

    name
  end

  defp held(%Postgrex.Error{postgres: %{pg_code: "55006"}} = error, template) do
    %RuntimeError{
      message:
        "#{template} can't be copied while anything is connected to it: close what holds it (the app, a " <>
          "migration, a console). Where the service keeps a connection of its own for minutes after yours (Neon " <>
          "does), a copy per partition can't be made: use one test database, where each test runs in Ecto's SQL " <>
          "sandbox, or a branch for each run: #{Exception.message(error)}"
    }
  end

  defp held(error, _template), do: error

  # Postgrex's settings from the URL, on the database every server has (the copy is made from outside it)
  defp connection(uri) do
    [user | password] = String.split(uri.userinfo || "", ":", parts: 2)

    [
      hostname: uri.host,
      port: uri.port || 5432,
      username: URI.decode(user),
      password: Enum.map(password, &URI.decode/1) |> List.first(),
      database: "postgres",
      backoff_type: :stop
    ]
    |> Keyword.reject(fn {_, value} -> value in [nil, ""] end)
  end

  defp ident(name), do: ~s(") <> String.replace(name, ~s("), ~s("")) <> ~s(")

  @doc """
  The refusal `result` must be (the test fails at once otherwise): `{:error, %Rowstile.Refused{}}`, by `command`'s
  rule unless it is `nil`. Gives the refusal.

      assert_refused(Rowstile.transact(Repo, fn -> {:ok, Repo.insert!(note)} end), "insert")
  """
  @spec assert_refused(term(), String.t() | nil) :: Rowstile.Refused.t()
  def assert_refused(result, command \\ nil) do
    case result do
      {:error, %Rowstile.Refused{} = refused} ->
        if command && !String.starts_with?(refused.command || "", command) do
          flunk(
            "expected the #{command} rule to refuse it, but: #{refused.command}: #{refused.message}"
          )
        end

        refused

      other ->
        flunk("expected a refusal, got #{inspect(other)}")
    end
  end

  @doc "The `{:error, %Rowstile.NotFound{}}` `result` must be (the test fails at once otherwise). Gives the error."
  @spec assert_not_found(term()) :: Rowstile.NotFound.t()
  def assert_not_found(result) do
    case result do
      {:error, %Rowstile.NotFound{} = not_found} -> not_found
      other -> flunk("expected NotFound, got #{inspect(other)}")
    end
  end
end
