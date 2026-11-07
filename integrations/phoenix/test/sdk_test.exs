defmodule Conformance.SdkTest do
  # The SDK's own calls, each way they can go, beyond the conformance checks: what each promises, asked of the
  # database where there is one to ask. test.sh measures what these and the checks run of the SDK, and fails unless
  # they run every line of it.
  use Conformance.Case, async: false

  import Plug.Test, only: [conn: 2]
  import Ecto.Query, only: [from: 2]
  import Rowstile.Testing

  alias Ecto.Adapters.SQL.Sandbox
  alias Rowstile.Plug.Fallback

  defp as(user, fun),
    do: Rowstile.transact(Repo, fn -> {:ok, fun.()} end, as: Rowstile.user(user))

  # what work for who inside a transaction signed in as signed is refused with
  defp said(signed, who) do
    "this transaction is signed in as #{signed} already, and a sign-in lasts the database transaction: " <>
      "#{who}'s work can't run inside it. Run it after, or in a transaction of its own (another connection)"
  end

  test "queries by permission: a join on authz.list, and one call for a list's buttons" do
    assert json(call("GET", "/projects/editable", "3")) == [1]

    assert json(call("GET", "/projects/buttons", "3")) == %{
             "1" => ["edit", "view"],
             "3" => ["view"]
           }

    assert as(3, fn -> Rowstile.can?(Repo, Authz.Note.edit(), 4) end) == {:ok, true}
    assert as(3, fn -> Rowstile.can?(Repo, Authz.Note.edit(), 1) end) == {:ok, false}
    assert as(1, fn -> Rowstile.list(Repo, Authz.Project.view()) end) == {:ok, ["1", "3"]}

    assert as(1, fn -> Rowstile.list(Repo, Authz.Project.view(), limit: 1, after: 1) end) ==
             {:ok, ["3"]}

    # no cursor (nil, as a request's missing parameter): the first page; a cursor without a size: every id after it
    assert as(1, fn -> Rowstile.list(Repo, Authz.Project.view(), after: nil, limit: 1) end) ==
             {:ok, ["1"]}

    assert as(1, fn -> Rowstile.list(Repo, Authz.Project.view(), after: 1) end) == {:ok, ["3"]}
  end

  test "inside a transaction signed in already: the same principal's work runs, anyone else's is refused" do
    # a sign-in lasts the database transaction (Ecto runs the inner transaction in the outer one)
    seen =
      as(1, fn ->
        {:ok, inside} = as(1, &ids/0)
        ran = self()

        refused =
          assert_raise RuntimeError, fn ->
            as(2, fn ->
              send(ran, :ran)
              Repo.query!("UPDATE app.notes SET body = 'bo' WHERE id = 2")
            end)
          end

        nobody =
          assert_raise RuntimeError, fn ->
            Rowstile.transact(Repo, fn -> {:ok, send(ran, :ran)} end, as: Rowstile.nobody())
          end

        refute_received :ran
        # the outer transaction, as it was: still ann's, who writes as herself
        %{num_rows: 1} = Repo.query!("UPDATE app.notes SET body = 'ann' WHERE id = 1")
        {inside, [refused.message, nobody.message], ids()}
      end)

    assert {:ok, {inside, refused, after_it}} = seen
    assert {inside, after_it} == {expected()["1"], expected()["1"]}
    assert refused == [said("user 1", "user 2"), said("user 1", "nobody")]

    # committed as ann's, and bo's note left as it was
    bodies =
      Rows.owner(
        &Postgrex.query!(&1, "SELECT body FROM app.notes WHERE id IN (1, 2) ORDER BY id", []).rows
      )

    assert bodies == [["ann"], ["mine"]]

    # the function given the transaction's repo; acting for whoever the process acts for
    Rowstile.put_principal(Rowstile.user(3))

    assert Rowstile.transact(Repo, fn repo -> {:ok, {repo, Rowstile.current(), ids()}} end) ==
             {:ok, {Repo, Rowstile.user(3), expected()["3"]}}

    assert Rowstile.acting_as(Rowstile.user(2), &Rowstile.current/0) == Rowstile.user(2)
    assert Rowstile.current() == Rowstile.user(3)
  end

  test "inside a transaction transact didn't begin: refused before anything is sent, whoever it is for" do
    # whose sign-in can't be known (Ecto runs a transaction inside another in the outer one; so does Postgrex)
    unknown =
      "this connection is in a transaction Rowstile.transact/3 didn't begin: who it is signed in as can't be " <>
        "known, and a sign-in lasts the database transaction. Begin it with Rowstile.transact/3, or run this after it"

    ran = self()

    assert {:ok, :refused} =
             Repo.transaction(fn ->
               assert_raise RuntimeError, unknown, fn -> as(1, fn -> send(ran, :ran) end) end
               # the transaction as it was: nobody signed in to it
               setting =
                 Repo.query!("SELECT coalesce(current_setting('authz.user_id', true), '')")

               assert setting.rows == [[""]]
               :refused
             end)

    Rows.app(fn conn ->
      assert {:ok, :refused} =
               Postgrex.transaction(conn, fn tx ->
                 assert_raise RuntimeError, unknown, fn ->
                   Rowstile.transact(tx, fn _ -> {:ok, send(ran, :ran)} end, as: Rowstile.user(1))
                 end

                 :refused
               end)
    end)

    refute_received :ran

    # acting for someone else inside a transact: whom the next transact signs in as, not whom this one's run as
    assert as(1, fn -> Rowstile.acting_as(Rowstile.user(2), &ids/0) end) == {:ok, expected()["1"]}
  end

  test "{:error, reason} rolls back, and an error that isn't rowstile's raises as it would" do
    assert as(1, fn -> Repo.query!("UPDATE app.notes SET body = 'gone' WHERE id = 1") end)
           |> elem(0) == :ok

    assert Rowstile.transact(
             Repo,
             fn ->
               Repo.query!("UPDATE app.notes SET body = 'x' WHERE id = 1") && {:error, :no}
             end,
             as: Rowstile.user(1)
           ) ==
             {:error, :no}

    assert as(1, fn -> ids("SELECT body FROM app.notes WHERE id = 1") end) == {:ok, ["gone"]}
    assert_raise RuntimeError, "boom", fn -> as(1, fn -> raise "boom" end) end
    error = assert_raise Postgrex.Error, fn -> as(1, fn -> Repo.query!("SELECT 1 / 0") end) end

    assert {error.postgres.pg_code, Rowstile.translate(error), Rowstile.problem(error)} ==
             {"22012", error, :error}
  end

  test "on a Postgrex connection: the same transactions, refusals and rollbacks" do
    Rows.app(fn conn ->
      seen =
        Rowstile.transact(
          conn,
          fn tx ->
            {:ok, Postgrex.query!(tx, "SELECT id FROM app.notes ORDER BY id", []).rows}
          end,
          as: Rowstile.user(2)
        )

      assert seen == {:ok, [[2], [3]]}

      # inside it, the same principal's work runs as it is, anyone else's is refused before it runs
      nested =
        Rowstile.transact(
          conn,
          fn tx ->
            {:ok, inside} =
              Rowstile.transact(tx, fn tx -> {:ok, Rowstile.can?(tx, Authz.Note.edit(), 2)} end,
                as: Rowstile.user(2)
              )

            assert_raise RuntimeError, said("user 2", "user 1"), fn ->
              Rowstile.transact(tx, fn _ -> flunk("ran") end, as: Rowstile.user(1))
            end

            {:ok, {inside, Rowstile.can?(tx, Authz.Note.edit(), 2)}}
          end,
          as: Rowstile.user(2)
        )

      assert nested == {:ok, {true, true}}
      # a Postgrex transaction on another connection is one of its own: signed in as usual
      can_edit = fn tx -> {:ok, Rowstile.can?(tx, Authz.Note.edit(), 2)} end

      Rows.app(fn other ->
        anns = fn _ -> Rowstile.transact(other, can_edit, as: Rowstile.user(1)) end
        assert Rowstile.transact(conn, anns, as: Rowstile.user(2)) == {:ok, false}
      end)

      insert = "INSERT INTO app.notes (project_id, author_id, body) VALUES (3, 2, 'hi')"

      refused =
        assert_refused(
          Rowstile.transact(conn, fn tx -> {:ok, Postgrex.query!(tx, insert, [])} end,
            as: Rowstile.user(2)
          ),
          "insert"
        )

      assert refused.table == "app.notes"
      mine = "INSERT INTO app.notes (project_id, author_id, body) VALUES (2, 2, 'undone')"

      assert Rowstile.transact(
               conn,
               fn tx -> Postgrex.query!(tx, mine, []) && {:error, :undo} end,
               as: Rowstile.user(2)
             ) == {:error, :undo}

      assert as(2, fn -> ids("SELECT count(*) FROM app.notes WHERE body = 'undone'") end) ==
               {:ok, [0]}

      assert Rowstile.check_connection(conn) == :ok
    end)
  end

  test "an Ecto update the rules allow that matched nothing is 409: the row changed since it was read" do
    result =
      as(3, fn ->
        note = Repo.get!(Note, 4)

        Rows.owner(
          &Postgrex.query!(
            &1,
            "UPDATE app.notes SET lock_version = lock_version + 1 WHERE id = 4",
            []
          )
        )

        note
        |> Ecto.Changeset.change(body: "x")
        |> Ecto.Changeset.optimistic_lock(:lock_version)
        |> Repo.update!()
      end)

    assert {:error, %Ecto.StaleEntryError{} = stale} = result

    assert Rowstile.problem(stale) ==
             {:ok,
              %{
                type: "https://rowstile.dev/problems/conflict",
                title: "Conflict",
                status: 409,
                detail:
                  "the row changed since it was read, and the rules allow the change: read it again"
              }}

    # and an error a transaction's function raises that is no StaleEntryError, nor the database's, is raised as it is
    assert_raise ArgumentError, fn -> as(3, fn -> raise ArgumentError end) end
  end

  test "expect turns 0 rows into the database's answer" do
    assert {:ok, {:error, %Rowstile.NotFound{} = hidden}} =
             as(2, fn -> Rowstile.expect(Repo, 0, "app.notes", "delete", 1) end)

    assert Exception.message(hidden) == "app.notes 1 not found"

    assert {:ok, {:error, refused}} =
             as(3, fn ->
               {changed, _} = Repo.update_all(from(n in Note, where: n.id == 1), set: [body: "x"])
               Rowstile.expect(Repo, changed, "app.notes", "update", 1)
             end)

    assert refused.message == "permission denied: user 3 may not update row 1 of app.notes"
    assert {refused.table, refused.command, refused.code} == {"app.notes", "update", "AZ709"}

    # the rule allows it, and the statement matched nothing for another reason (a where with more than the key)
    assert {:ok, {:error, %Rowstile.NotFound{}}} =
             as(3, fn ->
               {changed, _} =
                 Repo.update_all(from(n in Note, where: n.id == 4 and n.body == "no"),
                   set: [body: "x"]
                 )

               Rowstile.expect(Repo, changed, "app.notes", "update", 4)
             end)

    assert as(3, fn -> Rowstile.expect(Repo, 1, "app.notes", "update", 4) end) == {:ok, :ok}
    # a table named without its schema is found on the search_path
    found =
      as(1, fn ->
        Repo.query!("SET LOCAL search_path = app")
        Rowstile.expect(Repo, 0, "notes", "delete", 2)
      end)

    assert {:ok, {:error, %Rowstile.NotFound{table: "app.notes"}}} = found
  end

  test "Postgres's own refusals name the rule; a 42501 that is no policy's is the app's mistake" do
    upsert =
      "INSERT INTO app.notes (id, project_id, author_id, body) VALUES (1, 1, 3, 'x') ON CONFLICT (id) DO UPDATE SET body = 'x'"

    refused =
      assert_refused(
        Rowstile.transact(Repo, fn -> {:ok, Repo.query!(upsert)} end, as: Rowstile.user(3)),
        "update"
      )

    assert refused.message =~ "ON CONFLICT DO UPDATE"

    merge =
      "MERGE INTO app.notes n USING (SELECT 1 AS id) s ON n.id = s.id WHEN MATCHED THEN UPDATE SET body = 'x'"

    merged =
      assert_refused(
        Rowstile.transact(Repo, fn -> {:ok, Repo.query!(merge)} end, as: Rowstile.user(3))
      )

    assert {merged.message =~ "MERGE matched a row", merged.table, merged.command} ==
             {true, "notes", nil}

    # a table the app role was never granted
    denied =
      assert_raise Postgrex.Error, fn ->
        as(3, fn -> Repo.query!("SELECT * FROM public.schema_migrations") end)
      end

    assert {denied.postgres.pg_code, Rowstile.error_code(denied), Rowstile.problem(denied)} ==
             {"42501", nil, :error}
  end

  test "errors: codes, words and problems" do
    refused = %Rowstile.Refused{message: "no", code: "AZ704"}
    call_error = %Rowstile.CallError{message: "x", code: "AZ710", status: 400}

    assert Enum.map([refused, call_error, %RuntimeError{}], &Rowstile.error_code/1) == [
             "AZ704",
             "AZ710",
             nil
           ]

    assert Rowstile.translate(refused) == refused
    assert {Exception.message(refused), Exception.message(call_error)} == {"no", "x"}

    assert Enum.map(
             [
               %Rowstile.NotFound{},
               %Rowstile.NotFound{table: "app.x"},
               %Rowstile.NotFound{id: "7"}
             ],
             &Exception.message/1
           ) ==
             ["not found", "app.x not found", "row 7 not found"]

    assert Exception.message(%Rowstile.ConnectionProblem{problems: ["a", "b"]}) ==
             "the app's database connection can't be used with rowstile: a; b"

    # each built as raise builds it
    assert Exception.message(Rowstile.NotFound.exception(table: "app.x", id: "7")) ==
             "app.x 7 not found"

    assert Rowstile.ConnectionProblem.exception(problems: ["a"]).problems == ["a"]

    assert Exception.message(Rowstile.NotSignedIn.exception(error: refused)) =~
             "nobody signed in to"

    assert Rowstile.problem(:nothing) == :error

    assert Enum.map([refused, %Rowstile.NotFound{}, call_error], &Plug.Exception.status/1) == [
             403,
             404,
             400
           ]

    assert Enum.map([refused, %Rowstile.NotFound{}, call_error], &Plug.Exception.actions/1) == [
             [],
             [],
             []
           ]

    assert inspect(Rowstile.principal("service", 3)) == "#Rowstile.Principal<service:3>"
  end

  test "what is read of an error: the HINT alone, AZ701 alone, and the function that raised it" do
    # Postgres's own words quote the request's input: a code there is none of rowstile's
    cast =
      assert_raise Postgrex.Error, fn ->
        as(1, fn -> Repo.query!("SELECT 'rowstile help AZ714'::bigint") end)
      end

    assert {cast.postgres.pg_code, Rowstile.error_code(cast), Rowstile.problem(cast)} ==
             {"22P02", nil, :error}

    # a 28000 without code AZ701 (Postgres's own: a login refused when connecting) is not NotSignedIn
    login =
      assert_raise Postgrex.Error, fn ->
        as(1, fn ->
          Repo.query!("DO $$BEGIN RAISE 'no pg_hba.conf entry' USING ERRCODE = '28000'; END$$")
        end)
      end

    assert {login.postgres.pg_code, Rowstile.translate(login)} == {"28000", login}

    # Postgres's own refusal on a server whose messages aren't English: told by the function that
    # raised it, not its words, the table and the rule unnamed; another 42501 is none
    words = "neue Zeile verletzt Policy für Sicherheit auf Zeilenebene für Tabelle »notes«"

    german = fn routine ->
      %Postgrex.Error{postgres: %{pg_code: "42501", message: words, routine: routine}}
    end

    assert %Rowstile.Refused{message: ^words, table: nil, command: nil, code: "AZ709"} =
             Rowstile.translate(german.("ExecWithCheckOptions"))

    assert Rowstile.translate(german.("aclcheck_error")) == german.("aclcheck_error")
  end

  test "nobody has one spelling: no id, whatever the type" do
    spellings = [
      Rowstile.user(nil),
      Rowstile.user(""),
      Rowstile.principal("service", nil),
      Rowstile.Principal.parse("service:")
    ]

    nobody = {Rowstile.nobody(), "nobody"}
    assert Enum.map(spellings, &{&1, to_string(&1)}) == [nobody, nobody, nobody, nobody]

    # nobody's work runs in a transaction begun for a principal without an id, made by hand too
    hand = %Rowstile.Principal{type: "user", id: nil}

    seen =
      Rowstile.transact(
        Repo,
        fn -> Rowstile.transact(Repo, fn -> {:ok, ids()} end, as: Rowstile.nobody()) end,
        as: hand
      )

    assert seen == {:ok, expected()[nil]}
  end

  test "keys as Postgres writes them" do
    shown =
      [
        7,
        [7],
        [1, 2],
        ["a b", "x,y"],
        ["", ~s(q"t)],
        ["b\\s", "(1)"],
        [1, nil],
        {1, "a b"},
        {7},
        nil
      ]
      |> Enum.map(&Rowstile.key_text/1)

    assert shown == [
             "7",
             "7",
             "(1,2)",
             ~s{("a b","x,y")},
             ~s{("","q""t")},
             ~s{("b\\\\s","(1)")},
             "(1,)",
             ~s{(1,"a b")},
             "7",
             nil
           ]

    # a field quoted for ASCII's six spaces alone, as Postgres does: not for a no-break space, an em space
    assert Enum.map([["\vv", "a\u00a0b"], ["\u2003\x1c", "\r\n\f"]], &Rowstile.key_text/1) ==
             [~s{("\vv",a\u00a0b)}, ~s{(\u2003\x1c,"\r\n\f")}]
  end

  test "the plug: who the request acts for, or the answer when the app refuses it" do
    assert_raise ArgumentError, fn -> Rowstile.Plug.init(user: :nobody) end
    # a token the app refuses: 401
    refused = call("GET", "/notes", nil, nil, [{"authorization", "Bearer bad"}])
    assert {refused.status, json(refused)["detail"], refused.halted} == {401, "bad token", true}

    # the principal lasts the process: in Phoenix.ConnTest, the test's, which acts for it after the request
    assert Rowstile.current() == nil
    assert call("GET", "/notes", "2").status == 200
    assert Rowstile.current() == Rowstile.user(2)
    assert Rowstile.transact(Repo, fn -> {:ok, ids()} end) == {:ok, expected()["2"]}

    answered = fn reason ->
      Rowstile.Plug.call(conn(:get, "/"), Rowstile.Plug.init(user: fn _ -> {:error, reason} end))
    end

    assert JSON.decode!(answered.(%RuntimeError{message: "expired"}).resp_body)["detail"] ==
             "expired"

    assert JSON.decode!(answered.(:expired).resp_body)["detail"] == ":expired"
    # a login the database refused: its own answer
    login = answered.(%Rowstile.CallError{message: "invalid API key", code: "AZ703", status: 401})
    assert {login.status, JSON.decode!(login.resp_body)["code"]} == {401, "AZ703"}
    assert Rowstile.Plug.send_problem(conn(:get, "/"), :nothing) == :error
    # the fallback raises what isn't rowstile's: a 500
    assert_raise RuntimeError, "no", fn ->
      Fallback.call(conn(:get, "/"), {:error, %RuntimeError{message: "no"}})
    end

    assert_raise ArgumentError, ~r/not an error rowstile answers/, fn ->
      Fallback.call(conn(:get, "/"), {:error, :no})
    end

    assert Fallback.init(:x) == :x
  end

  test "the test helpers say what was expected" do
    refused =
      Rowstile.transact(
        Repo,
        fn -> Repo.insert(%Note{project_id: 3, author_id: 3, body: "x"}) end,
        as: Rowstile.user(3)
      )

    wrong = assert_raise ExUnit.AssertionError, fn -> assert_refused(refused, "delete") end
    assert wrong.message =~ "expected the delete rule to refuse it, but: insert"
    # the rule's whole name: a part of it, or none, is no rule's
    for part <- ["ins", ""] do
      cut = assert_raise ExUnit.AssertionError, fn -> assert_refused(refused, part) end
      assert cut.message =~ "expected the #{part} rule to refuse it, but: insert"
    end

    none = assert_raise ExUnit.AssertionError, fn -> assert_refused({:ok, 1}) end
    assert none.message =~ "expected a refusal"

    assert %Rowstile.NotFound{} =
             assert_not_found(as(2, fn -> Repo.delete(%Note{id: 1}) end))

    missing = assert_raise ExUnit.AssertionError, fn -> assert_not_found({:ok, 1}) end
    assert missing.message =~ "expected NotFound"
  end

  test "in Ecto's SQL sandbox, as Phoenix's tests run: each test's writes rolled back" do
    start_supervised!(Conformance.SandboxRepo)
    :ok = Sandbox.checkout(Conformance.SandboxRepo)
    note = %Note{project_id: 1, author_id: 1, body: "in the sandbox"}

    assert {:ok, %Note{id: id}} =
             Rowstile.transact(
               Conformance.SandboxRepo,
               fn -> Conformance.SandboxRepo.insert(note) end,
               as: Rowstile.user(1)
             )

    seen =
      Rowstile.transact(
        Conformance.SandboxRepo,
        fn -> {:ok, Conformance.SandboxRepo.get(Note, id)} end,
        as: Rowstile.user(2)
      )

    assert seen == {:ok, nil}
    :ok = Sandbox.checkin(Conformance.SandboxRepo)

    assert as(1, fn -> ids("SELECT count(*) FROM app.notes WHERE body = 'in the sandbox'") end) ==
             {:ok, [0]}
  end
end
