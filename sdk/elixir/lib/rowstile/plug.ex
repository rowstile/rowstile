if Code.ensure_loaded?(Plug) do
  defmodule Rowstile.Plug do
    @moduledoc """
    Makes each request act for whoever the app says it is, so every transaction `Rowstile.transact/3` begins while
    serving it signs in as them. In a Phoenix router's pipeline (or any Plug pipeline):

        plug Rowstile.Plug, user: &MyAppWeb.Session.principal/1

    `user` reads the session or the token from the request itself, and returns `{:ok, principal}`
    (`Rowstile.user(id)`, `Rowstile.principal("service", id)`, or `Rowstile.nobody()`: only what `anyone` may
    see), or `{:error, reason}` for a request it refuses (a bad token), which is answered as rowstile's error when
    it is one (a login the database refused: 401), else 401, and halted.
    """

    @behaviour Plug

    import Plug.Conn

    @type user :: (Plug.Conn.t() -> {:ok, Rowstile.Principal.t()} | {:error, term()})

    @impl true
    @spec init(keyword()) :: [user: user()]
    def init(opts) do
      user = Keyword.fetch!(opts, :user)

      if is_function(user, 1),
        do: [user: user],
        else: raise(ArgumentError, "user: a function of the request")
    end

    @impl true
    @spec call(Plug.Conn.t(), user: user()) :: Plug.Conn.t()
    def call(conn, user: user) do
      case user.(conn) do
        {:ok, %Rowstile.Principal{} = who} ->
          :ok = Rowstile.put_principal(who)
          put_private(conn, :rowstile_principal, who)

        {:error, reason} ->
          problem =
            case Rowstile.problem(reason) do
              {:ok, problem} ->
                problem

              :error ->
                %{
                  type: "https://rowstile.dev/problems/not-signed-in",
                  title: "Unauthorized",
                  status: 401,
                  detail: words(reason)
                }
            end

          conn |> send_body(problem) |> halt()
      end
    end

    defp words(reason) when is_exception(reason), do: Exception.message(reason)
    defp words(reason) when is_binary(reason), do: reason
    defp words(reason), do: inspect(reason)

    @doc """
    Answers `error` as `application/problem+json` when it is rowstile's to answer (`Rowstile.problem/1`), and gives
    `{:ok, conn}` (the response sent); `:error` for anything else, for which it sends nothing.
    """
    @spec send_problem(Plug.Conn.t(), term()) :: {:ok, Plug.Conn.t()} | :error
    def send_problem(conn, error) do
      case Rowstile.problem(error) do
        {:ok, problem} -> {:ok, send_body(conn, problem)}
        :error -> :error
      end
    end

    defp send_body(conn, problem) do
      conn
      |> put_resp_content_type("application/problem+json", nil)
      |> send_resp(problem.status, json(problem))
    end

    # the app's JSON library: Elixir's own (1.18 and newer)
    defp json(problem), do: JSON.encode!(problem)
  end

  defmodule Rowstile.Plug.Fallback do
    @moduledoc """
    A Phoenix fallback controller for actions that return `Rowstile.transact/3`'s errors:
    `action_fallback Rowstile.Plug.Fallback`. It answers rowstile's as `application/problem+json`
    (`Rowstile.Plug.send_problem/2`), and raises anything else (a 500). An app with errors of its own writes its
    fallback, calling `Rowstile.Plug.send_problem/2` first.
    """

    @behaviour Plug

    @impl true
    @spec init(term()) :: term()
    def init(opts), do: opts

    @impl true
    @spec call(Plug.Conn.t(), {:error, term()}) :: Plug.Conn.t()
    def call(conn, {:error, error}) do
      case Rowstile.Plug.send_problem(conn, error) do
        {:ok, conn} -> conn
        :error when is_exception(error) -> raise error
        :error -> raise ArgumentError, "not an error rowstile answers: #{inspect(error)}"
      end
    end
  end

  for {exception, status} <- [{Rowstile.Refused, 403}, {Rowstile.NotFound, 404}] do
    defimpl Plug.Exception, for: exception do
      @status status
      def status(_), do: @status
      def actions(_), do: []
    end
  end

  defimpl Plug.Exception, for: Rowstile.CallError do
    def status(%{status: status}), do: status
    def actions(_), do: []
  end
end
