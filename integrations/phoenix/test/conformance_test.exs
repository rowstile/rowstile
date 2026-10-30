defmodule Conformance.ConformanceTest do
  # The conformance suite (integrations/README.md): the same checks for every stack. This is Phoenix on Bandit,
  # Ecto on Postgrex. test.sh does check 11 (a fresh database: migrate, the policy's tests, then Ecto's own status
  # shows nothing left to run) and the server's half of check 13 before these run.
  use Conformance.Case, async: false

  alias Conformance.Jobs.{AddNote, Digest}

  test "1: signed in, a list shows only the user's rows" do
    for user <- ["1", "2", "3"] do
      assert json(call("GET", "/notes", user)) == expected()[user], user
    end
  end

  test "2: signed out on purpose, only what anyone may see" do
    assert json(call("GET", "/notes", nil)) == expected()[nil]
    assert json(call("GET", "/projects", nil)) == [3]
  end

  test "3: not signed in: the not-signed-in error (AZ701), naming act_as" do
    error =
      assert_raise Postgrex.Error, fn ->
        Rows.app(fn conn ->
          Postgrex.transaction(conn, fn tx ->
            Postgrex.query!(tx, "SELECT count(*) FROM app.notes", [])
          end)
        end)
      end

    assert error.postgres.pg_code == "28000"
    assert error.postgres.hint =~ "act_as"
    # rowstile help AZ701
    assert Rowstile.error_code(error) == "AZ701"
    # the SDK's calls outside a signed-in transaction: NotSignedIn, which says how, and a 500
    not_signed_in =
      assert_raise Rowstile.NotSignedIn, fn -> Rowstile.can?(Repo, Authz.Note.view(), 1) end

    assert Exception.message(not_signed_in) =~ "must begin with authz.act_as()"
    assert Rowstile.error_code(not_signed_in) == "AZ701"
    assert Rowstile.problem(not_signed_in) == :error
    assert Rowstile.problem(error) == :error
  end

  test "6: a refused insert: 403 with the problem body naming the rule" do
    conn = call("POST", "/notes", "2", %{project_id: 3, body: "hi"})
    assert conn.status == 403, conn.resp_body
    assert media(conn) == "application/problem+json"
    body = json(conn)
    # rowstile help AZ709
    assert {body["table"], body["command"], body["code"]} == {"app.notes", "insert", "AZ709"}
    assert body["detail"] =~ "user 2 may not insert this row into app.notes"
    assert Enum.any?(body["why"], &(&1 =~ "project.edit")), inspect(body["why"])
  end

  test "7: an update of a hidden row: 404; of a visible row the user may not edit: 403, with the reason" do
    hidden = call("PATCH", "/notes/1", "2", %{body: "x"})
    assert hidden.status == 404, hidden.resp_body

    assert json(hidden) == %{
             "type" => "https://rowstile.dev/problems/not-found",
             "title" => "Not Found",
             "status" => 404,
             "detail" => "app.notes 1 not found"
           }

    refused = call("PATCH", "/notes/1", "3", %{body: "x"})
    assert {refused.status, json(refused)["command"]} == {403, "update"}, refused.resp_body
    assert Enum.any?(json(refused)["why"], &(&1 =~ "edit"))
    # worded as the database words a refused insert: who, the command, the row, the table
    assert json(refused)["detail"] ==
             "permission denied: user 3 may not update row 1 of app.notes"

    mine = call("PATCH", "/notes/4", "3", %{body: "better idea"})
    assert mine.status == 200, mine.resp_body
    gone = call("DELETE", "/notes/2", "1")
    assert gone.status == 404, gone.resp_body
    no = call("DELETE", "/notes/1", "3")
    assert {no.status, json(no)["command"]} == {403, "delete"}, no.resp_body
    assert json(no)["detail"] == "permission denied: user 3 may not delete row 1 of app.notes"
    assert json(no)["why"] != []
  end

  test "7: ... and a row hidden between the read and the update is 404: the database's answer" do
    # cy's note in ann's project, which ann reads, and which is in bo's project by the time her update reaches the
    # database
    Rowstile.put_principal(Rowstile.user(1))

    result =
      Rowstile.transact(Repo, fn ->
        note = Repo.get!(Note, 4)
        Rows.owner(&Postgrex.query!(&1, "UPDATE app.notes SET project_id = 2 WHERE id = 4", []))
        Repo.update(Ecto.Changeset.change(note, body: "x"))
      end)

    assert {:ok, problem} = Rowstile.problem(elem(result, 1))
    assert problem.detail == "app.notes 4 not found"
  end

  test "8: insert, then read back, works when the select rule allows it, and is explained when not" do
    ok = call("POST", "/notes", "1", %{project_id: 1, body: "new"})
    assert ok.status == 201, ok.resp_body
    assert json(ok)["id"] > 100
    unreadable = call("POST", "/inbox", "1", %{recipient_id: 2, body: "hi bo"})

    assert {unreadable.status, json(unreadable)["command"]} == {403, "select"},
           unreadable.resp_body

    assert json(unreadable)["detail"] =~ "may not see the row as written"
    quiet = call("POST", "/inbox/quietly", "1", %{recipient_id: 2, body: "hi bo"})
    assert quiet.status == 202, quiet.resp_body
  end

  test "10: a background job signs in as a service principal" do
    # whatever started it: nobody, who sees one project; service 1 sees two (the one it is added to, the public one)
    assert Rowstile.acting_as(Rowstile.nobody(), &Conformance.Digest.run/0) == {:ok, 2}
  end

  test "10: ... on Oban's queue: a job a request starts acts for the user who asked, given to it as an argument, " <>
         "and the next job on the worker's one connection never acts for the one before" do
    with_pool(1, fn ->
      assert call("POST", "/notes/later", "1", %{project_id: 1, body: "ann's, later"}).status ==
               202

      # a job that names no one, after it: nobody, who may add no note
      {:ok, _} =
        %{project_id: 1, body: "nobody's"} |> AddNote.new() |> Oban.insert()

      # bo, in ann's project: refused, the job failed with why
      assert call("POST", "/notes/later", "2", %{project_id: 1, body: "bo's"}).status == 202
      assert %{success: 1, failure: 2} = Oban.drain_queue(queue: :default)
    end)

    said =
      Rows.owner(fn conn ->
        bodies =
          Postgrex.query!(conn, "SELECT body FROM app.notes WHERE id > 100 ORDER BY id", []).rows

        errors =
          Postgrex.query!(
            conn,
            "SELECT args->>'body', errors[1]->>'error' FROM oban_jobs ORDER BY id",
            []
          ).rows

        {bodies, errors}
      end)

    assert {[["ann's, later"]], [["ann's, later", nil], ["nobody's", nobody], ["bo's", bo]]} =
             said

    assert nobody =~ "Rowstile.Refused"
    assert bo =~ "user 2 may not insert this row into app.notes"
    # the service's job, from the queue: it acts for its service, whoever asked
    assert Oban.Testing.perform_job(Digest, %{}, repo: Repo) == {:ok, 2}
  end

  test "10: ... and only when the code names it: an id is a user's, whatever it holds (ids come from outside)" do
    assert Rowstile.user("service:1") == %Rowstile.Principal{type: "user", id: "service:1"}
    assert Rowstile.principal("service", 1) == %Rowstile.Principal{type: "service", id: "1"}

    # what to_string wrote, read back, for text the app wrote itself (a job's argument): every principal as itself
    users = [
      "service:1",
      "nobody",
      "google-oauth2:117",
      "user:5",
      "a:b",
      ":",
      "(1,a:b)",
      "(1,2)",
      "",
      "42"
    ]

    every =
      Enum.map(users, &Rowstile.user/1) ++
        [
          Rowstile.nobody(),
          Rowstile.principal("service", 1),
          Rowstile.principal("service", "3:4")
        ] ++
        [Rowstile.principal("service", "(1,2)")]

    assert Enum.map(every, &Rowstile.Principal.parse(to_string(&1))) == every

    assert Enum.map(
             [Rowstile.user("service:1"), Rowstile.user("nobody"), Rowstile.user(42)],
             &to_string/1
           ) ==
             ["user:service:1", "user:nobody", "42"]

    assert {to_string(Rowstile.principal("service", 1)), to_string(Rowstile.nobody())} ==
             {"service:1", "nobody"}
  end

  # an API key of ann's, made as the owner (in one transaction); scopes "read" for one that may only read
  defp anns_key(scopes \\ nil) do
    Rows.owner(fn conn ->
      {:ok, made} =
        Postgrex.transaction(conn, fn tx ->
          Postgrex.query!(tx, "SELECT authz.act_as('user', '1')", [])

          %{rows: [[key]]} =
            Postgrex.query!(tx, "SELECT authz.create_api_key('ci', $1)", [scopes])

          %{rows: [[id]]} =
            Postgrex.query!(tx, "SELECT max(id) FROM authz.api_keys WHERE user_id = '1'", [])

          {key, id}
        end)

      made
    end)
  end

  test "16: what a call names isn't there (AZ708): 404; a missing or wrong argument (AZ710): 400" do
    {_, key} = anns_key()
    page = call("GET", "/projects/page?limit=1", "1")
    assert {page.status, json(page)} == {200, ["1"]}, page.resp_body

    for {query, detail} <- [
          {"limit=-1", "the page size must not be negative (got -1)"},
          {"limit=1&after=x", "the page cursor 'x' is not a project id"}
        ] do
      conn = call("GET", "/projects/page?" <> query, "1")
      assert media(conn) == "application/problem+json"
      assert json(conn) == problem("bad-argument", "Bad Request", 400, detail, "AZ710")
      assert conn.status == 400
    end

    # bo's key it isn't
    others = call("DELETE", "/keys/#{key}", "2")
    revoked = call("DELETE", "/keys/#{key}", "1")
    assert revoked.status == 204, revoked.resp_body
    # revoked: there is none now
    again = call("DELETE", "/keys/#{key}", "1")

    # no refusal: for this user the key isn't there (bo's own keys don't hold it; ann's no longer do)
    for conn <- [others, again] do
      assert json(conn) ==
               problem("not-found", "Not Found", 404, "no API key #{key} of yours", "AZ708")

      assert conn.status == 404
    end
  end

  test "16: a login refused or a call that needs someone signed in 401, a move inside itself 409, a refusal by the " <>
         "database's own code 403, the app's mistakes a 500" do
    {read_only, _} = anns_key("read")
    nobody = call("POST", "/keys", nil, %{name: "k"})
    asks = call("POST", "/projects/1/requests", nil, %{relation: "member", reason: "the review"})
    bad_key = call("POST", "/keys", "1", %{name: "k"}, [{"x-api-key", "ak_nope"}])
    scoped = call("POST", "/keys", "1", %{name: "k"}, [{"x-api-key", read_only}])
    inside = call("PATCH", "/folders/1", "1", %{parent_id: 2})

    for {conn, body} <- [
          {nobody,
           problem("not-signed-in", "Unauthorized", 401, "sign in to create an API key", "AZ714")},
          {asks, problem("not-signed-in", "Unauthorized", 401, "sign in first", "AZ714")},
          {bad_key, problem("not-signed-in", "Unauthorized", 401, "invalid API key", "AZ703")},
          {inside,
           problem("conflict", "Conflict", 409, "folder 1 cannot be moved inside itself", "AZ713")}
        ] do
      assert media(conn) == "application/problem+json"
      assert json(conn) == body
      assert conn.status == body["status"]
    end

    made = call("POST", "/keys", "1", %{name: "k"})
    assert made.status == 201, made.resp_body
    assert String.starts_with?(json(made)["key"], "ak_")
    stays = call("PATCH", "/folders/2", "1", %{parent_id: 1})
    assert stays.status == 200, stays.resp_body
    # refusals, by the database's own code: 403, naming no rule
    not_shared = call("GET", "/projects/1/shares", "2")

    for {conn, detail, code} <- [
          {scoped, "this session is read-only", "AZ704"},
          {not_shared, "you cannot see the shares of project 1", "AZ705"}
        ] do
      got = json(conn)

      assert {conn.status, got["type"], got["code"]} ==
               {403, "https://rowstile.dev/problems/refused", code}

      assert String.starts_with?(got["detail"], detail), conn.resp_body
      assert {got["table"], got["command"]} == {nil, nil}
    end

    # a call that is for users, made by a service (rowstile help AZ715): a refusal too, 403
    service = call("POST", "/keys", nil, %{name: "mine"}, [{"x-service", "1"}])
    assert media(service) == "application/problem+json"

    assert json(service) == %{
             "type" => "https://rowstile.dev/problems/refused",
             "title" => "Forbidden",
             "status" => 403,
             "detail" =>
               "authz.create_api_key for oneself is for users, not services (service 1 is signed in)",
             "table" => nil,
             "command" => nil,
             "why" => [],
             "code" => "AZ715"
           }

    assert service.status == 403
    # the app's mistakes: the database's own error, a 500, not a problem
    said =
      for request <- [
            fn ->
              call("POST", "/projects/1/requests", "2", %{
                relation: "member",
                reason: "the review"
              })
            end,
            fn ->
              call("POST", "/keys", "1", %{
                name: "k",
                principal_type: "service",
                principal_id: "1"
              })
            end,
            fn -> call("GET", "/notes/as/2", "1") end
          ] do
        error = assert_raise Postgrex.Error, request
        assert Plug.Exception.status(error) == 500
        {Rowstile.error_code(error), error.postgres.pg_code, error.postgres.message}
      end

    assert Enum.map(said, fn {code, sqlstate, _} -> {code, sqlstate} end) ==
             [{"AZ706", "P0001"}, {"AZ707", "P0001"}, {"AZ702", "28000"}]

    for {words, {_, _, message}} <-
          Enum.zip(
            [
              "the policy does not allow sharing project.member with a user",
              "the policy gives service no manage_keys permission, so nobody manages its keys",
              "who is signed in was changed after signing in"
            ],
            said
          ) do
      assert message =~ words
    end
  end
end
