defmodule Conformance.Digest do
  @moduledoc "A background job: it signs in as service 1, whatever started it, and counts the projects it may read."

  alias Conformance.{Project, Repo}

  @spec run() :: {:ok, non_neg_integer()} | {:error, Rowstile.error()}
  def run do
    Rowstile.transact(Repo, fn -> {:ok, Repo.aggregate(Project, :count)} end,
      as: Rowstile.principal("service", 1)
    )
  end
end
