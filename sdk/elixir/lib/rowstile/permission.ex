defmodule Rowstile.Permission do
  @moduledoc """
  A permission of a type the policy declares, as `rowstile client elixir` writes them: `MyApp.Authz.Note.edit()`
  is `%Rowstile.Permission{type: "note", name: "edit"}`. `Rowstile.can?/3` and `Rowstile.list/3` take only these,
  so a misspelled name is a compile error (an undefined function), and so is a plain string (the compiler's
  types). A name the generated module has no function for is written by hand, as the struct.
  """

  @enforce_keys [:type, :name]
  defstruct [:type, :name]

  @type t :: %__MODULE__{type: String.t(), name: String.t()}
end

defmodule Rowstile.ObjectType do
  @moduledoc """
  A type the policy declares, as `rowstile client elixir` writes them: `MyApp.Authz.Project.type()` is
  `%Rowstile.ObjectType{name: "project"}`, which `Rowstile.perms_of/3` takes.
  """

  @enforce_keys [:name]
  defstruct [:name]

  @type t :: %__MODULE__{name: String.t()}
end
