defmodule ConformanceWeb.Session do
  @moduledoc """
  Who a request is. A real app reads its session or token here: a cookie, a bearer token, an API key. The
  conformance app has no sign-in: its checks name the user in a header, which a real app must never believe. So
  docs/stacks/phoenix.md shows the router calling this function, and never its body.
  """

  @spec principal(Plug.Conn.t()) :: {:ok, Rowstile.Principal.t()} | {:error, String.t()}
  def principal(conn) do
    case {Plug.Conn.get_req_header(conn, "authorization"),
          Plug.Conn.get_req_header(conn, "x-service"), Plug.Conn.get_req_header(conn, "x-user")} do
      # a token the app refuses: the plug answers 401
      {["Bearer bad"], _, _} -> {:error, "bad token"}
      # a service's own API calls
      {_, [service], _} -> {:ok, Rowstile.principal("service", service)}
      {_, _, [user]} -> {:ok, Rowstile.user(user)}
      _ -> {:ok, Rowstile.nobody()}
    end
  end
end
