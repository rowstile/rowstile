defmodule Rowstile.Check do
  @moduledoc """
  Refuses to start the app on a connection that skips row-level security (a superuser, BYPASSRLS, the tables'
  owner): a child of the app's supervisor, after the repo, which runs `Rowstile.check_connection/1` as the app
  starts, and stops the start with `Rowstile.ConnectionProblem` (and its words) on an error.

      children = [MyApp.Repo, {Rowstile.Check, MyApp.Repo}, MyAppWeb.Endpoint]

  It keeps no process: once the check passes, the supervisor goes on with the next child.
  """

  @doc false
  @spec child_spec(Rowstile.db()) :: Supervisor.child_spec()
  def child_spec(db),
    do: %{id: __MODULE__, start: {__MODULE__, :start_link, [db]}, restart: :temporary}

  @doc """
  Runs the check: `:ignore` when it passes (no process); it raises `Rowstile.ConnectionProblem` when not, which the
  supervisor reports with its words.
  """
  @spec start_link(Rowstile.db()) :: :ignore
  def start_link(db) do
    case Rowstile.check_connection(db) do
      :ok -> :ignore
      {:error, problem} -> raise problem
    end
  end
end
