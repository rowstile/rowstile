defmodule Conformance.Rows do
  @moduledoc """
  The same few rows for every test: ann (1) owns project 1 (cy is a member, service 1 reads it) and the public
  project 3; bo (2) owns project 2. Ann's folder 1 has folder 2 inside it. And the suite's connections to this
  partition's database: the tables' owner's, and the app role's outside Ecto (signed in by nothing).
  """

  @rows """
  TRUNCATE oban_jobs;
  TRUNCATE app.folders, app.inbox, app.notes, app.members, app.project_services, app.projects, app.services,
    app.users CASCADE;
  INSERT INTO app.users VALUES (1, 'ann'), (2, 'bo'), (3, 'cy');
  INSERT INTO app.services VALUES (1, 'digest');
  INSERT INTO app.projects VALUES (1, 1, 'Plans', false), (2, 2, 'Bo''s', false), (3, 1, 'Open', true);
  INSERT INTO app.members VALUES (1, 3);
  INSERT INTO app.project_services VALUES (1, 1);
  INSERT INTO app.notes (id, project_id, author_id, body) VALUES
    (1, 1, 1, 'plan'), (2, 2, 2, 'mine'), (3, 3, 1, 'hello'), (4, 1, 3, 'idea');
  SELECT setval(pg_get_serial_sequence('app.notes', 'id'), 100);
  INSERT INTO app.folders VALUES (1, NULL, 1, 'top'), (2, 1, 1, 'inside');
  """

  @doc "Puts the rows back, as the owner."
  def load! do
    owner(fn conn ->
      for sql <- String.split(@rows, ";\n", trim: true), do: Postgrex.query!(conn, sql, [])
    end)
  end

  @doc "This partition's copy of the migrated test database (test/test_helper.exs made it)."
  def database, do: Application.fetch_env!(:conformance, :database)

  @doc "A URL, on another database."
  def on(url, database),
    do: url |> URI.parse() |> Map.put(:path, "/" <> database) |> URI.to_string()

  @doc "The owner's URL, on this partition's database (or another)."
  def owner_url(database \\ database()), do: on(System.fetch_env!("ROWSTILE_TESTS_URL"), database)

  @doc "The app role's URL, on this partition's database (or another)."
  def app_url(database \\ database()),
    do: on(System.fetch_env!("ROWSTILE_APP_TESTS_URL"), database)

  @doc "Runs fun with a connection of the tables' owner (straight to Postgres, as the owner always connects)."
  def owner(fun, database \\ database()), do: with_conn(owner_url(database), fun)

  @doc "Runs fun with a connection of the app's role, outside Ecto: nothing signs it in."
  def app(fun), do: with_conn(app_url(), fun)

  defp with_conn(url, fun) do
    %{host: host, port: port, userinfo: userinfo, path: "/" <> database} = URI.parse(url)
    [username, password] = String.split(userinfo, ":", parts: 2)

    {:ok, conn} =
      Postgrex.start_link(
        hostname: host,
        port: port,
        username: username,
        password: password,
        database: database,
        backoff_type: :stop
      )

    try do
      fun.(conn)
    after
      GenServer.stop(conn)
    end
  end
end
