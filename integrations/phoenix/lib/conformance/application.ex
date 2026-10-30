defmodule Conformance.Application do
  @moduledoc false
  use Application

  @impl true
  def start(_type, _args) do
    children = [
      Conformance.Repo,
      # the app refuses to start on a connection that skips row-level security
      {Rowstile.Check, Conformance.Repo},
      {Oban, Application.fetch_env!(:conformance, Oban)},
      ConformanceWeb.Endpoint
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: Conformance.Supervisor)
  end
end
