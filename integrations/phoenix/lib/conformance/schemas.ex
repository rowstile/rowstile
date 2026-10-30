defmodule Conformance.Project do
  @moduledoc "A project, with an owner and members; a public one anyone may read."
  use Ecto.Schema

  @schema_prefix "app"
  @primary_key {:id, :id, autogenerate: false}
  schema "projects" do
    field :owner_id, :integer
    field :name, :string
    field :public, :boolean
  end
end

defmodule Conformance.Note do
  @moduledoc "A note in a project, with a lock_version: Ecto's optimistic lock."
  use Ecto.Schema

  @schema_prefix "app"
  schema "notes" do
    field :project_id, :integer
    field :author_id, :integer
    field :body, :string
    field :lock_version, :integer, default: 0
  end
end

defmodule Conformance.Message do
  @moduledoc "A message in the inbox: anyone signed in may send one, only its recipient reads it."
  use Ecto.Schema

  @schema_prefix "app"
  schema "inbox" do
    field :sender_id, :integer
    field :recipient_id, :integer
    field :body, :string
  end
end

defmodule Conformance.Folder do
  @moduledoc "A folder inside a folder, which its owner and the owners of the folders above edit."
  use Ecto.Schema

  @schema_prefix "app"
  @primary_key {:id, :id, autogenerate: false}
  schema "folders" do
    field :parent_id, :integer
    field :owner_id, :integer
    field :name, :string
  end
end
