if Code.ensure_loaded?(Oban) do
  defmodule Rowstile.Oban do
    @moduledoc """
    Oban jobs that act for the user who asked for them. A job never takes who it acts for from what a request left
    behind: the request puts it in the job's arguments, and the job acts for it as it runs.

        # in the request: the job, for whoever the request acts for
        %{note_id: id} |> Rowstile.Oban.args() |> MyApp.Worker.new() |> Oban.insert()

        # in the worker
        def perform(%Oban.Job{} = job) do
          Rowstile.Oban.acting_as(job, fn -> Rowstile.transact(MyApp.Repo, fn -> ... end) end)
        end

    A job its arguments name no one for acts for nobody (only what `anyone` may see), whoever the worker ran
    before it. A job that acts for a principal of its own (a service) names it: `Rowstile.transact(repo, fun, as:
    Rowstile.principal("service", 1))`.
    """

    @key "rowstile_as"

    @doc """
    The job's arguments, with who it acts for (`who`: whoever the process acts for, by default), written as
    `Rowstile.Principal.parse/1` reads it back: `%{"rowstile_as" => "42"}`.
    """
    @spec args(map(), Rowstile.Principal.t() | nil) :: map()
    def args(args, who \\ Rowstile.current()),
      do: Map.put(args, @key, to_string(who || Rowstile.nobody()))

    @doc "Runs `fun` acting for whoever the job's arguments name (nobody, if they name no one)."
    @spec acting_as(Oban.Job.t(), (-> result)) :: result when result: term()
    def acting_as(%Oban.Job{args: args}, fun) do
      who =
        if is_binary(args[@key]),
          do: Rowstile.Principal.parse(args[@key]),
          else: Rowstile.nobody()

      Rowstile.acting_as(who, fun)
    end
  end
end
