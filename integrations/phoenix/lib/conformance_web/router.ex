defmodule ConformanceWeb.Router do
  use Phoenix.Router

  pipeline :api do
    plug :accepts, ["json"]
    # each request acts for whoever its session or token says
    plug Rowstile.Plug, user: &ConformanceWeb.Session.principal/1
  end

  scope "/", ConformanceWeb do
    pipe_through :api

    get "/projects", ProjectController, :index
    get "/projects/editable", ProjectController, :editable
    get "/projects/buttons", ProjectController, :buttons
    get "/projects/page", ProjectController, :page
    get "/projects/:id/shares", ProjectController, :shares
    post "/projects/:id/requests", ProjectController, :ask
    post "/keys", KeyController, :create
    delete "/keys/:id", KeyController, :delete
    get "/notes", NoteController, :index
    get "/notes/as/:user_id", NoteController, :as
    post "/notes", NoteController, :create
    post "/notes/later", NoteController, :later
    patch "/notes/:id", NoteController, :update
    delete "/notes/:id", NoteController, :delete
    post "/inbox", InboxController, :create
    post "/inbox/quietly", InboxController, :quietly
    patch "/folders/:id", FolderController, :update
  end
end
