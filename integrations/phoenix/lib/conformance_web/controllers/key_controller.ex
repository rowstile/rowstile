defmodule ConformanceWeb.KeyController do
  use ConformanceWeb, :controller

  # an API key, for the user or a principal whose keys they manage; a request that brings a key (x-api-key) signs
  # in with it first, in the same transaction: the database says who may make which
  def create(conn, params) do
    with {:ok, key} <-
           Rowstile.transact(Repo, fn -> make(get_req_header(conn, "x-api-key"), params) end) do
      conn |> put_status(:created) |> json(%{key: key})
    end
  end

  defp make(api_keys, params) do
    for key <- api_keys, do: Repo.query!("SELECT authz.login_key($1)", [key])
    made = "SELECT authz.create_api_key($1, '', NULL, CAST($2 AS text), CAST($3 AS text))"

    %{rows: [[key]]} =
      Repo.query!(made, [params["name"], params["principal_type"], params["principal_id"]])

    {:ok, key}
  end

  # one of the user's API keys: someone else's, or one that isn't there, is 404
  def delete(conn, %{"id" => id}) do
    revoke = fn ->
      {:ok, Repo.query!("SELECT 1 FROM authz.revoke_api_key($1)", [String.to_integer(id)])}
    end

    with {:ok, _} <- Rowstile.transact(Repo, revoke) do
      send_resp(conn, :no_content, "")
    end
  end
end
