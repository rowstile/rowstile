defmodule Rowstile.Refused do
  @moduledoc """
  The database refusing a write, and saying why: the rule (`table` and `command`), and the reasons, a line each.
  `code` is rowstile's (`rowstile help AZ709`): AZ709 for a rule's refusal, the database's own for another (AZ704:
  a read-only session, AZ705: the shares of an object one can't see, AZ715: a call for users made by a service),
  which names no rule. A 403.
  """

  defexception [:message, :table, :command, why: [], code: "AZ709"]

  @type t :: %__MODULE__{
          message: String.t(),
          table: String.t() | nil,
          command: String.t() | nil,
          why: [String.t()],
          code: String.t()
        }
end

defmodule Rowstile.NotFound do
  @moduledoc """
  A row that isn't there, or that whoever the transaction acts for can't see: both get the same answer, a 404.
  `id` is the row's key as Postgres writes it: `7`, or `(1,2)` for a key of several columns.
  """

  defexception [:table, :id]

  @type t :: %__MODULE__{table: String.t() | nil, id: String.t() | nil}

  @impl true
  def message(%{table: table, id: nil}), do: Enum.join(List.wrap(table) ++ ["not found"], " ")
  def message(%{table: table, id: id}), do: "#{table || "row"} #{id} not found"
end

defmodule Rowstile.CallError do
  @moduledoc """
  A call the database turned down that is no refusal, with the status its code's page gives (`rowstile help
  AZ708`): a login refused or a call that needs someone signed in 401 (AZ703, AZ714), something it names that
  isn't there 404 (AZ708), an argument missing or wrong 400 (AZ710), a move inside itself 409 (AZ713). `message`
  is the database's words.
  """

  defexception [:message, :code, :status]

  @type t :: %__MODULE__{message: String.t(), code: String.t(), status: 400 | 401 | 404 | 409}
end

defmodule Rowstile.NotSignedIn do
  @moduledoc """
  A query that needs to know who is asking, in a transaction nobody signed in to (AZ701): the app's bug, not the
  user's doing, so a 500. Every transaction must begin with `authz.act_as()`, as `Rowstile.transact/3` does.
  """

  defexception [:error]

  @type t :: %__MODULE__{error: Exception.t()}

  @impl true
  def message(%{error: error}) do
    "a query ran in a transaction nobody signed in to: every transaction must begin with authz.act_as() " <>
      "(Rowstile.transact does it; is this query outside it?): " <> Exception.message(error)
  end
end

defmodule Rowstile.ConnectionProblem do
  @moduledoc """
  `authz.connection_check()` finding that the app's connection skips row-level security (or worse): a superuser,
  a role with BYPASSRLS, the tables' owner.
  """

  defexception [:problems]

  @type t :: %__MODULE__{problems: [String.t()]}

  @impl true
  def message(%{problems: problems}) do
    "the app's database connection can't be used with rowstile: " <> Enum.join(problems, "; ")
  end
end

defmodule Rowstile.Errors do
  @moduledoc false
  # Reading the database's errors: rowstile's code, a refusal, a call turned down, the not-signed-in error.

  alias Rowstile.{CallError, NotSignedIn, Refused}

  # the codes of a call the database turned down that is no refusal, and the status their pages give
  @call_status %{"AZ703" => 401, "AZ708" => 404, "AZ710" => 400, "AZ713" => 409, "AZ714" => 401}

  # Postgres's own words, not rowstile's: a check of a row no rule's own refusal covers. Postgres names the table
  # without its schema
  @generic ~r/^(new|target) row violates row-level security policy (\(USING expression\) )?for table "([^"]+)"/

  @unseen "this user may not see the row as written (the select rule). An insert that reads it back " <>
            "(RETURNING), an upsert, and an update with a WHERE need to see it."

  @spec code(term()) :: String.t() | nil
  def code(%Postgrex.Error{postgres: %{} = pg}) do
    Enum.find_value([pg[:hint], pg[:message]], fn text ->
      case Regex.run(~r/rowstile help (AZ\d{3})/, text || "") do
        [_, code] -> code
        nil -> nil
      end
    end)
  end

  def code(%NotSignedIn{error: error}), do: code(error)
  def code(%Refused{code: code}), do: code
  def code(%CallError{code: code}), do: code
  def code(_), do: nil

  @spec translate(Exception.t()) :: Exception.t()
  def translate(%Postgrex.Error{postgres: %{pg_code: sqlstate} = pg} = error) do
    code = code(error)

    cond do
      refused = sqlstate == "42501" && refusal(pg, code) -> refused
      status = @call_status[code] -> %CallError{message: pg.message, code: code, status: status}
      # a login refused (AZ703) and settings changed by hand (AZ702) share the SQLSTATE, and are no such thing
      sqlstate == "28000" and code in [nil, "AZ701"] -> %NotSignedIn{error: error}
      true -> error
    end
  end

  def translate(error), do: error

  # a Refused for a 42501 that is a refusal (raised by rowstile's policies with the rule and why, or Postgres's own
  # words for a check no rule's refusal covers), else nil: another 42501 (a table the app role was never granted)
  # is the app's mistake, and sign in first (AZ714) is a 42501 too, but no refusal
  defp refusal(pg, code) do
    case Regex.run(@generic, pg.message) do
      [_, row, using, table] ->
        generic(pg.message, row, using, table)

      nil when code == nil or is_map_key(@call_status, code) ->
        nil

      nil ->
        %Refused{
          message: pg.message,
          table: table(pg),
          command: command(pg[:constraint]),
          why: String.split(pg[:detail] || "", "\n", trim: true),
          code: code
        }
    end
  end

  # Postgres's own words: which row (new, or the target of a MERGE), and whether it was the USING expression
  defp generic(message, "target", _, table) do
    # MERGE matched a row the update or the delete rule hides; Postgres doesn't say which
    %Refused{
      message:
        message <> ": MERGE matched a row the update or delete rule doesn't let this user change",
      table: table
    }
  end

  defp generic(message, "new", "", table) do
    # the select rule, on the row as written: an insert that reads it back, an upsert, or an update after which the
    # row would be out of this user's sight
    %Refused{message: message <> ": " <> @unseen, table: table, command: "select"}
  end

  defp generic(message, "new", _using, table) do
    # an upsert whose existing row this user may not update, or not see
    %Refused{
      message:
        message <>
          ": the row is there already, and the update rule (or the select rule) doesn't let this user change it " <>
          "(ON CONFLICT DO UPDATE)",
      table: table,
      command: "update"
    }
  end

  # the table the error names, with its schema when it names one too
  defp table(%{schema: schema, table: table}) when is_binary(schema) and is_binary(table),
    do: schema <> "." <> table

  defp table(pg), do: pg[:table]

  defp command("authz_" <> command), do: command
  defp command(_), do: nil

  # the problem type and title of each status a call turned down answers with
  @call_problem %{
    400 => {"bad-argument", "Bad Request"},
    401 => {"not-signed-in", "Unauthorized"},
    404 => {"not-found", "Not Found"},
    409 => {"conflict", "Conflict"}
  }

  @spec problem(term()) :: {:ok, Rowstile.problem()} | :error
  def problem(%Refused{} = r) do
    {:ok,
     %{
       type: type("refused"),
       title: "Forbidden",
       status: 403,
       detail: r.message,
       table: r.table,
       command: r.command,
       why: r.why,
       code: r.code
     }}
  end

  def problem(%Rowstile.NotFound{} = nf) do
    {:ok,
     %{type: type("not-found"), title: "Not Found", status: 404, detail: Exception.message(nf)}}
  end

  def problem(%CallError{status: status} = c) do
    {kind, title} = @call_problem[status]
    {:ok, %{type: type(kind), title: title, status: status, detail: c.message, code: c.code}}
  end

  # an Ecto update the rules allow that matched no row: the row changed since it was read (an optimistic lock)
  def problem(%{__struct__: Ecto.StaleEntryError}) do
    {:ok,
     %{
       type: type("conflict"),
       title: "Conflict",
       status: 409,
       detail: "the row changed since it was read, and the rules allow the change: read it again"
     }}
  end

  def problem(%Postgrex.Error{} = error) do
    case translate(error) do
      %Postgrex.Error{} -> :error
      translated -> problem(translated)
    end
  end

  def problem(_), do: :error

  defp type(kind), do: "https://rowstile.dev/problems/" <> kind
end
