defmodule ConformanceWeb.InboxController do
  use ConformanceWeb, :controller

  # reads the new row back (INSERT ... RETURNING id): only the recipient may read it
  def create(conn, %{"recipient_id" => recipient_id, "body" => body}) do
    message = %Message{sender_id: signed_in(), recipient_id: recipient_id, body: body}

    with {:ok, message} <- Rowstile.transact(Repo, fn -> Repo.insert(message) end) do
      conn |> put_status(:created) |> json(%{id: message.id})
    end
  end

  # without reading the row back
  def quietly(conn, %{"recipient_id" => recipient_id, "body" => body}) do
    row = %{sender_id: signed_in(), recipient_id: recipient_id, body: body}

    with {:ok, _} <- Rowstile.transact(Repo, fn -> {:ok, Repo.insert_all(Message, [row])} end) do
      conn |> put_status(:accepted) |> json(%{})
    end
  end
end
