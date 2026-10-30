defmodule ConformanceWeb do
  @moduledoc """
  The conformance app: no permission checks anywhere. rowstile signs each request's transactions in, the database
  filters reads and refuses writes, and the SDK turns refusals into 403 and hidden rows into 404.
  """

  @doc "What every controller of the app uses: JSON answers, and rowstile's errors as problem details."
  defmacro __using__(:controller) do
    quote do
      use Phoenix.Controller, formats: [:json]
      import Plug.Conn
      import Ecto.Query
      import ConformanceWeb, only: [signed_in: 0]
      alias Conformance.{Authz, Folder, Message, Note, Project, Repo}

      # Rowstile.transact's errors: a refusal 403, a hidden row 404, a call turned down as its code's page says
      action_fallback Rowstile.Plug.Fallback
    end
  end

  @doc "The user the request acts for (Rowstile.Plug set it from the session), as the tables' key."
  @spec signed_in() :: integer()
  def signed_in, do: String.to_integer(Rowstile.current().id || "0")
end
