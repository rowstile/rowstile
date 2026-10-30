defmodule Conformance.Case do
  @moduledoc """
  What the checks share: the app's endpoint (Phoenix.ConnTest), requests as a user, the rows, and what each user
  may see. The checks read and write the same rows: no test runs beside another (async: false), and each
  partition has a database of its own (check 12).
  """

  use ExUnit.CaseTemplate

  using do
    quote do
      import Phoenix.ConnTest
      import Conformance.Case
      alias Conformance.{Authz, Folder, Message, Note, Project, Repo, Rows}

      @endpoint ConformanceWeb.Endpoint
    end
  end

  setup do
    Conformance.Rows.load!()
    :ok
  end

  @doc "The notes each may see (nil: nobody)."
  def expected, do: %{"1" => [1, 3, 4], "2" => [2, 3], "3" => [1, 3, 4], nil => [3]}

  @doc "The projects each may see."
  def projects, do: %{"1" => [1, 3], "2" => [2, 3], nil => [3]}

  @doc """
  A request to the app, as `user` (a user's id; nil: nobody), with a JSON body (nil: none) and headers. Gives the
  response.
  """
  def call(method, path, user, body \\ nil, headers \\ []) do
    conn =
      Enum.reduce(
        headers ++ if(user, do: [{"x-user", user}], else: []),
        Phoenix.ConnTest.build_conn(),
        fn {k, v}, conn ->
          Plug.Conn.put_req_header(conn, k, v)
        end
      )

    conn =
      if body, do: Plug.Conn.put_req_header(conn, "content-type", "application/json"), else: conn

    Phoenix.ConnTest.dispatch(
      conn,
      ConformanceWeb.Endpoint,
      method,
      path,
      if(body, do: JSON.encode!(body))
    )
  end

  @doc "Runs fun with the app's repo on a pool of this many connections."
  def with_pool(size, fun) do
    config = Application.fetch_env!(:conformance, Conformance.Repo)
    :ok = Supervisor.terminate_child(Conformance.Supervisor, Conformance.Repo)
    Application.put_env(:conformance, Conformance.Repo, Keyword.put(config, :pool_size, size))
    {:ok, _} = Supervisor.restart_child(Conformance.Supervisor, Conformance.Repo)

    try do
      fun.()
    after
      Application.put_env(:conformance, Conformance.Repo, config)
      :ok = Supervisor.terminate_child(Conformance.Supervisor, Conformance.Repo)
      {:ok, _} = Supervisor.restart_child(Conformance.Supervisor, Conformance.Repo)
    end
  end

  @doc "A response's JSON."
  def json(conn), do: JSON.decode!(conn.resp_body)

  @doc "A response's media type."
  def media(conn), do: conn |> Plug.Conn.get_resp_header("content-type") |> List.first()

  @doc "A problem body, as the SDK writes one."
  def problem(kind, title, status, detail, code) do
    %{
      "type" => "https://rowstile.dev/problems/" <> kind,
      "title" => title,
      "status" => status,
      "detail" => detail,
      "code" => code
    }
  end

  @doc "The ids a statement reads, in this process's transaction (or one of its own)."
  def ids(sql \\ "SELECT id FROM app.notes ORDER BY id") do
    sql |> Conformance.Repo.query!() |> Map.fetch!(:rows) |> List.flatten()
  end
end
