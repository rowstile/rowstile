defmodule ConformanceWeb.FolderController do
  use ConformanceWeb, :controller

  # inside one of its own subfolders: 409, the database's words
  def update(conn, %{"id" => id, "parent_id" => parent_id}) do
    id = String.to_integer(id)

    with {:ok, id} <- Rowstile.transact(Repo, fn -> move(id, parent_id) end) do
      json(conn, %{id: id})
    end
  end

  defp move(id, parent_id) do
    {moved, _} =
      Repo.update_all(from(f in Folder, where: f.id == ^id), set: [parent_id: parent_id])

    # 0 rows: expect asks the database why, and answers 404 (hidden) or 403 (with the reason)
    with :ok <- Rowstile.expect(Repo, moved, "app.folders", "update", id), do: {:ok, id}
  end
end
