defmodule Conformance.ChecksTest do
  # The checks that serve the app with Bandit (4, 5), compile the generated names (9), look at the test databases
  # (12), start the app (13) and change the policy (14).
  use Conformance.Case, async: false

  @here Path.expand("..", __DIR__)

  # the app, served by Bandit on a port of its own
  defp serve do
    pid =
      start_supervised!(
        {Bandit, plug: ConformanceWeb.Endpoint, ip: :loopback, port: 0, startup_log: false}
      )

    {:ok, {_, port}} = ThousandIsland.listener_info(pid)
    port
  end

  # a request over HTTP, as user (nil: nobody): the status and the JSON
  defp http(port, method, path, user, body \\ nil) do
    headers = if user, do: [{~c"x-user", String.to_charlist(user)}], else: []
    url = ~c"http://127.0.0.1:#{port}#{path}"

    request =
      if body, do: {url, headers, ~c"application/json", JSON.encode!(body)}, else: {url, headers}

    {:ok, {{_, status, _}, _, got}} = :httpc.request(method, request, [], body_format: :binary)
    {status, JSON.decode!(got)}
  end

  test "4: with a pool of one connection, a request as Ann, then one as Bob: Bob never sees Ann's rows" do
    with_pool(1, fn ->
      port = serve()

      for user <- ["1", "2", nil] do
        assert http(port, :get, "/notes", user) == {200, expected()[user]}, inspect(user)
      end

      # a transaction that commits (a folder moved where it is): a rollback undoes even a session's settings
      assert {200, _} = http(port, :patch, "/folders/2", "1", %{parent_id: 1})

      # each request signed in again, so the answers alone can't tell: the pool's one connection, as the last
      # request left it, outside a transaction anyone signed in to, holds no one (a sign-in that outlived its
      # transaction would still be ann's here)
      Repo.checkout(fn ->
        assert %{rows: [[held]]} = Repo.query!("SELECT current_setting('authz.user_id', true)")
        assert held in [nil, ""]

        error =
          assert_raise Postgrex.Error, fn -> Repo.query!("SELECT count(*) FROM app.notes") end

        # rowstile help AZ701
        assert Rowstile.error_code(error) == "AZ701"
      end)
    end)
  end

  test "5: concurrent requests never mix users" do
    port = serve()
    users = List.duplicate(["1", "2", "3", nil], 10) |> List.flatten()

    got =
      users
      |> Enum.map(&Task.async(fn -> http(port, :get, "/notes", &1) end))
      |> Task.await_many(30_000)

    assert got == Enum.map(users, &{200, expected()[&1]})
  end

  # the folders of the test build's dependencies' modules (the app's own left out), for elixirc and elixir
  defp code_paths do
    Path.join([Mix.Project.build_path(), "lib", "*", "ebin"])
    |> Path.wildcard()
    |> Enum.reject(&String.contains?(&1, "/conformance/"))
    |> Enum.flat_map(&["-pa", &1])
  end

  test "9: the generated names type-check, and a wrong permission name doesn't: in the generated names, and in the " <>
         "SDK's own calls" do
    # the committed names are the ones the policy makes (rowstile client elixir POLICY prints them, and writes nothing)
    {made, 0} =
      System.cmd(
        "python3",
        [System.fetch_env!("ROWSTILE_CLI"), "client", "elixir", "db/policy.authz"],
        cd: @here
      )

    assert made == File.read!(Path.join(@here, "lib/conformance/authz.ex")),
           "lib/conformance/authz.ex is out of date: rowstile client"

    dir = Path.join(System.tmp_dir!(), "check9-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)

    checks = %{
      "good" => """
      Rowstile.can?(repo, Conformance.Authz.Note.edit(), 1)
      Rowstile.perms_of(repo, Conformance.Authz.Project.type(), [1, 3])
      Rowstile.list(repo, Conformance.Authz.Project.view(), limit: 1)
      # a name the module has no function for, written by hand: the struct
      Rowstile.can?(repo, %Rowstile.Permission{type: "note", name: "edt"}, 1)
      """,
      "client_perm" => "Conformance.Authz.Note.edt()",
      "client_type" => "Conformance.Authz.Nte.edit()",
      # a plain string is no permission of the policy's, whatever it says
      "sdk_perm" => ~s{Rowstile.can?(repo, "edit", 1)},
      "sdk_type" => ~s{Rowstile.perms_of(repo, "project", [1])}
    }

    files =
      for {name, code} <- checks do
        file = Path.join(dir, "#{name}.ex")

        File.write!(
          file,
          "defmodule Check9.#{Macro.camelize(name)} do\n  def use(repo) do\n_ = repo\n#{code}\n  end\nend\n"
        )

        file
      end

    names = Path.join(@here, "lib/conformance/authz.ex")

    # the compiler's warnings, which mix compile --warnings-as-errors fails on, as the app's own build does (elixirc
    # prints them, and exits 0 for the checks it makes once the modules are compiled)
    {said, _} =
      System.cmd(
        "elixirc",
        ["--warnings-as-errors", "-o", dir] ++ code_paths() ++ [names | files],
        stderr_to_stdout: true
      )

    File.rm_rf!(dir)
    flagged = for {name, _} <- checks, String.contains?(said, "#{name}.ex:"), do: name
    assert Enum.sort(flagged) == ["client_perm", "client_type", "sdk_perm", "sdk_type"], said
    assert said =~ "Conformance.Authz.Note.edt/0 is undefined or private"
    assert said =~ "Conformance.Authz.Nte.edit/0 is undefined"
    assert said =~ "incompatible types given to Rowstile.can?/3"
    assert said =~ "incompatible types given to Rowstile.perms_of/3"
  end

  test "12: the framework's test database has the policy: a copy of the migrated one for each test partition" do
    partition = System.get_env("MIX_TEST_PARTITION", "1")
    assert Rows.database() == "conf_tests_#{partition}"

    assert {:ok, "conf_app"} =
             Rowstile.transact(Repo, fn -> {:ok, hd(ids("SELECT current_user"))} end)

    # under row-level security
    assert Rowstile.transact(
             Repo,
             fn -> {:ok, ids("SELECT id FROM app.projects ORDER BY id")} end,
             as: Rowstile.user(2)
           ) ==
             {:ok, projects()["2"]}

    count = fn database ->
      Rows.owner(
        &hd(hd(Postgrex.query!(&1, "SELECT count(*) FROM app.users", []).rows)),
        database
      )
    end

    # the original is left as it was migrated
    assert {count.("conf_tests"), count.(Rows.database())} == {0, 3}
    # another copy, kept with what the tests wrote (fresh: false), or copied again as migrated
    tests = System.fetch_env!("ROWSTILE_TESTS_URL")
    again = Rowstile.Testing.database_per_partition(tests, partition: "#{partition}_again")
    assert again == "conf_tests_#{partition}_again"
    Rows.owner(&Postgrex.query!(&1, "INSERT INTO app.users VALUES (1, 'ann')", []), again)

    assert Rowstile.Testing.database_per_partition(tests,
             partition: "#{partition}_again",
             fresh: false
           ) == again

    assert count.(again) == 1

    assert Rowstile.Testing.database_per_partition(tests, partition: "#{partition}_again") ==
             again

    assert count.(again) == 0
    Rows.owner(&Postgrex.query!(&1, ~s{DROP DATABASE "#{again}"}, []), "postgres")

    error =
      assert_raise ArgumentError, fn ->
        Rowstile.Testing.database_per_partition("postgres://conf_owner@localhost")
      end

    assert error.message =~ "a database to copy"
  end

  test "12: ... and a copy is refused, saying why, while something is connected to the original" do
    held = "#{Rows.database()}_held"

    Rows.owner(
      &Postgrex.query!(&1, ~s{DROP DATABASE IF EXISTS "#{held}" WITH (FORCE)}, []),
      "postgres"
    )

    Rows.owner(&Postgrex.query!(&1, ~s{CREATE DATABASE "#{held}"}, []), "postgres")
    url = Rows.owner_url(held)

    Rows.owner(
      fn _holder ->
        error =
          assert_raise RuntimeError, fn ->
            Rowstile.Testing.database_per_partition(url, partition: "x")
          end

        assert error.message =~ "can't be copied while anything is connected to it"
      end,
      held
    )

    # any other error is the database's own: a database that isn't there
    missing =
      assert_raise Postgrex.Error, fn ->
        Rowstile.Testing.database_per_partition(Rows.owner_url("none"))
      end

    assert missing.postgres.pg_code == "3D000"
    Rows.owner(&Postgrex.query!(&1, ~s{DROP DATABASE "#{held}" WITH (FORCE)}, []), "postgres")
  end

  test "13: the app refuses to start on a connection that skips row-level security" do
    start_supervised!({Conformance.OwnerRepo, url: Rows.owner_url(), pool_size: 1})

    assert {:error, %Rowstile.ConnectionProblem{} = problem} =
             Rowstile.check_connection(Conformance.OwnerRepo)

    assert Exception.message(problem) =~ "an owner skips row-level security"
    assert Enum.join(problem.problems) =~ "owner"
    # the app's role, under row-level security
    assert Rowstile.check_connection(Repo) == :ok

    # as a child of the app's supervisor: no process when it passes, the start stopped with the words when not
    assert Rowstile.Check.child_spec(Repo).start == {Rowstile.Check, :start_link, [Repo]}
    assert Rowstile.Check.start_link(Repo) == :ignore

    assert_raise Rowstile.ConnectionProblem, ~r/an owner skips row-level security/, fn ->
      Rowstile.Check.start_link(Conformance.OwnerRepo)
    end
  end

  # what the app's code does with the names the policy now makes: it names reply, and the database answers it (on
  # a Postgrex connection of the app's role, signed in by the SDK)
  @replies """
  defmodule Replies do
    def run([url, message]) do
      {:ok, _} = Application.ensure_all_started(:postgrex)
      %{host: host, port: port, path: "/" <> database} = URI.parse(url)
      {:ok, conn} = Postgrex.start_link(hostname: host, port: port, username: "conf_app", password: "app", database: database)

      # bo, to whom it is sent, may reply; ann, who sent it, may not even read it
      for user <- [2, 1] do
        {:ok, said} =
          Rowstile.transact(conn, fn tx ->
            {:ok, {Rowstile.can?(tx, Conformance.Authz.Message.reply(), message), Rowstile.can?(tx, Conformance.Authz.Message.read(), message)}}
          end, as: Rowstile.user(user))

        IO.inspect(said)
      end
    end
  end
  """

  test "14: after a policy change and a new migration, the app works with the new generated names" do
    db = "#{Rows.database()}_14"

    Rows.owner(
      &Postgrex.query!(&1, ~s{DROP DATABASE IF EXISTS "#{db}" WITH (FORCE)}, []),
      "postgres"
    )

    Rows.owner(
      &Postgrex.query!(&1, ~s{CREATE DATABASE "#{db}" TEMPLATE conf_tests}, []),
      "postgres"
    )

    work = Path.join(System.tmp_dir!(), "check14-#{System.unique_integer([:positive])}")
    File.mkdir_p!(work)

    for part <- ["db", "lib", "priv", "rowstile.toml"],
        do: File.cp_r!(Path.join(@here, part), Path.join(work, part))

    policy = Path.join(work, "db/policy.authz")

    File.write!(
      policy,
      String.replace(
        File.read!(policy),
        "  can read = recipient\n",
        "  can read = recipient\n  can reply = recipient\n"
      )
    )

    # ann sends bo a message
    message =
      Rows.owner(
        fn conn ->
          Postgrex.query!(conn, "INSERT INTO app.users VALUES (1, 'ann'), (2, 'bo')", [])

          hd(
            hd(
              Postgrex.query!(
                conn,
                "INSERT INTO app.inbox (sender_id, recipient_id, body) VALUES (1, 2, 'hi') RETURNING id",
                []
              ).rows
            )
          )
        end,
        db
      )

    # the migrations there: the new one comes after the last of them
    folder = Path.join(work, "priv/repo/migrations")
    before = folder |> File.ls!() |> Enum.filter(&String.ends_with?(&1, ".exs"))

    {_, 0} =
      System.cmd("python3", [System.fetch_env!("ROWSTILE_CLI"), "migrate"],
        cd: work,
        stderr_to_stdout: true
      )

    [new] = (folder |> File.ls!() |> Enum.filter(&String.ends_with?(&1, ".exs"))) -- before
    assert new > Enum.max(before)

    # Ecto's migrator, as mix ecto.migrate runs it, on the copy: the new migration alone is left to run
    {:ok, owner} =
      Conformance.OwnerRepo.start_link(url: Rows.owner_url(db), pool_size: 2, name: nil)

    ran =
      Ecto.Migrator.run(Conformance.OwnerRepo, folder, :up,
        all: true,
        dynamic_repo: owner,
        log: false
      )

    Supervisor.stop(owner)
    assert ran == [String.to_integer(hd(String.split(new, "_")))]

    {_, 0} =
      System.cmd("python3", [System.fetch_env!("ROWSTILE_CLI"), "client"],
        cd: work,
        stderr_to_stdout: true
      )

    assert File.read!(Path.join(work, "lib/conformance/authz.ex")) =~
             ~s(def reply, do: %Rowstile.Permission{type: "message", name: "reply"})

    # the app's code, compiled with the names the policy now makes, and run
    File.write!(Path.join(work, "replies.ex"), @replies)
    out = Path.join(work, "ebin")
    File.mkdir_p!(out)

    {said, status} =
      System.cmd(
        "elixirc",
        ["--warnings-as-errors", "-o", out] ++
          code_paths() ++
          [Path.join(work, "lib/conformance/authz.ex"), Path.join(work, "replies.ex")],
        stderr_to_stdout: true
      )

    assert status == 0, said

    run =
      ["-pa", out] ++
        code_paths() ++ ["-e", "Replies.run(System.argv())", Rows.app_url(db), to_string(message)]

    {said, status} = System.cmd("elixir", run, stderr_to_stdout: true)
    assert {status, said} == {0, "{true, true}\n{false, false}\n"}
    File.rm_rf!(work)
    Rows.owner(&Postgrex.query!(&1, ~s{DROP DATABASE "#{db}" WITH (FORCE)}, []), "postgres")
  end
end
