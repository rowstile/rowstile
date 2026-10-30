defmodule ConformanceWeb.ProjectController do
  use ConformanceWeb, :controller

  def index(conn, _params) do
    with {:ok, ids} <-
           Rowstile.transact(Repo, fn ->
             {:ok, Repo.all(from p in Project, order_by: p.id, select: p.id)}
           end) do
      json(conn, ids)
    end
  end

  # the projects the user may edit: a join on authz.list, one set lookup, with the policy's names (Authz)
  def editable(conn, _params) do
    perm = Authz.Project.edit()

    editable =
      from p in Project,
        join:
          x in fragment(
            "SELECT CAST(x AS bigint) AS id FROM authz.list(?, ?) x",
            ^perm.type,
            ^perm.name
          ),
        on: x.id == p.id,
        order_by: p.id,
        select: p.id

    with {:ok, ids} <- Rowstile.transact(Repo, fn -> {:ok, Repo.all(editable)} end) do
      json(conn, ids)
    end
  end

  # a list's buttons, in one call
  def buttons(conn, _params) do
    with {:ok, buttons} <-
           Rowstile.transact(Repo, fn ->
             ids = Repo.all(from p in Project, order_by: p.id, select: p.id)
             {:ok, Rowstile.perms_of(Repo, Authz.Project.type(), ids)}
           end) do
      json(conn, buttons)
    end
  end

  # the projects the user may see, a page at a time: the database says when the size or the cursor is wrong
  def page(conn, params) do
    page =
      [limit: String.to_integer(params["limit"])] ++
        if(params["after"], do: [after: params["after"]], else: [])

    with {:ok, ids} <-
           Rowstile.transact(Repo, fn ->
             {:ok, Rowstile.list(Repo, Authz.Project.view(), page)}
           end) do
      json(conn, ids)
    end
  end

  def shares(conn, %{"id" => id}) do
    with {:ok, %{rows: rows}} <-
           Rowstile.transact(Repo, fn ->
             {:ok, Repo.query!("SELECT subject_id FROM authz.list_shares('project', $1)", [id])}
           end) do
      json(conn, List.flatten(rows))
    end
  end

  # access asked for: the policy shares no relation of a project, so this is the app's mistake (a 500), once the
  # database knows who asks
  def ask(conn, %{"id" => id, "relation" => relation, "reason" => reason}) do
    with {:ok, %{rows: [[asked]]}} <-
           Rowstile.transact(Repo, fn ->
             {:ok,
              Repo.query!("SELECT authz.request_access('project', $1, $2, $3)", [
                id,
                relation,
                reason
              ])}
           end) do
      conn |> put_status(:created) |> json(%{id: asked})
    end
  end
end
