defmodule Conformance.Jobs.AddNote do
  @moduledoc """
  A background job for the user who asked: a request puts them in its arguments (Rowstile.Oban.args), and it acts
  for them as it runs. A refused insert fails the job, with the rule and why.
  """
  use Oban.Worker, queue: :default

  alias Conformance.{Note, Repo}

  @impl Oban.Worker
  def perform(%Oban.Job{args: %{"project_id" => project_id, "body" => body}} = job) do
    Rowstile.Oban.acting_as(job, fn ->
      note = %Note{project_id: project_id, author_id: ConformanceWeb.signed_in(), body: body}
      Rowstile.transact(Repo, fn -> Repo.insert(note) end)
    end)
  end
end

defmodule Conformance.Jobs.Digest do
  @moduledoc "The digest (Conformance.Digest), on the queue: it acts for its service, whoever asked for it."
  use Oban.Worker, queue: :default

  @impl Oban.Worker
  def perform(%Oban.Job{}), do: Conformance.Digest.run()
end
