defmodule Rowstile.Principal do
  @moduledoc """
  Who a transaction acts for: a user (type `"user"`), another principal type the policy declares (a service, a
  bot), or nobody (type and id `nil`: only what `anyone` may see).

  `to_string/1` writes one as text and `parse/1` reads it back, for text the app's own code wrote (a job's
  argument), never for an id that came from outside: `Rowstile.user("service:1")` is the user whose id that is.
  """

  @enforce_keys [:type, :id]
  defstruct [:type, :id]

  @type t :: %__MODULE__{type: String.t() | nil, id: String.t() | nil}

  @doc """
  What `to_string/1` wrote, read back: `"service:3"` is service 3, `"42"` and `"user:42"` user 42, `"nobody"`
  nobody. A key of several columns, `"(1,a:b)"`, is a user's.
  """
  @spec parse(String.t()) :: t()
  def parse("nobody"), do: %__MODULE__{type: nil, id: nil}

  def parse(text) when is_binary(text) do
    case {String.starts_with?(text, "("), String.split(text, ":", parts: 2)} do
      {false, [kind, id]} -> %__MODULE__{type: kind, id: id}
      _ -> %__MODULE__{type: "user", id: text}
    end
  end

  defimpl String.Chars do
    # "42", "service:3" or "nobody". A user whose id holds ":" or is "nobody" is "user:<id>", so that parse reads
    # every principal back as itself
    def to_string(%{id: nil}), do: "nobody"

    def to_string(%{type: "user", id: id}) do
      if String.contains?(id, ":") or id == "nobody", do: "user:" <> id, else: id
    end

    def to_string(%{type: type, id: id}), do: type <> ":" <> id
  end

  defimpl Inspect do
    def inspect(principal, _opts), do: "#Rowstile.Principal<#{principal}>"
  end
end
