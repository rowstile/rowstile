defmodule ConformanceWeb.NoteController do
  use ConformanceWeb, :controller

  alias Conformance.Jobs.AddNote

  def index(conn, _params) do
    with {:ok, ids} <-
           Rowstile.transact(Repo, fn ->
             {:ok, Repo.all(from n in Note, order_by: n.id, select: n.id)}
           end) do
      json(conn, ids)
    end
  end

  def create(conn, %{"project_id" => project_id, "body" => body}) do
    note = %Note{project_id: project_id, author_id: signed_in(), body: body}

    # a refused insert: 403, with the rule and the reason
    with {:ok, note} <- Rowstile.transact(Repo, fn -> Repo.insert(note) end) do
      conn |> put_status(:created) |> json(%{id: note.id})
    end
  end

  # the same, as a background job, for the user who asked
  def later(conn, %{"project_id" => project_id, "body" => body}) do
    job =
      %{project_id: project_id, body: body}
      |> Rowstile.Oban.args()
      |> AddNote.new()

    with {:ok, job} <- Rowstile.transact(Repo, fn -> Oban.insert(job) end) do
      conn |> put_status(:accepted) |> json(%{job: job.id})
    end
  end

  def update(conn, %{"id" => id, "body" => body}) do
    # no read first: the database says whether the row is there for this user (404) and whether they may (403)
    changed = Ecto.Changeset.change(%Note{id: String.to_integer(id)}, body: body)

    with {:ok, note} <- Rowstile.transact(Repo, fn -> Repo.update(changed) end) do
      json(conn, %{id: note.id})
    end
  end

  def delete(conn, %{"id" => id}) do
    with {:ok, _} <-
           Rowstile.transact(Repo, fn -> Repo.delete(%Note{id: String.to_integer(id)}) end) do
      send_resp(conn, :no_content, "")
    end
  end

  # who is signed in, changed by hand: the database doesn't believe it (the app's bug, a 500)
  def as(conn, %{"user_id" => user_id}) do
    with {:ok, ids} <-
           Rowstile.transact(Repo, fn ->
             Repo.query!("SELECT set_config('authz.user_id', $1, true)", [user_id])
             {:ok, Repo.all(from n in Note, select: n.id)}
           end) do
      json(conn, ids)
    end
  end
end
