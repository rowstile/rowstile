defmodule Conformance.OwnerRepo do
  @moduledoc "A repo of the tables' owner, which row-level security doesn't apply to (check 13 starts it)."
  use Ecto.Repo, otp_app: :conformance, adapter: Ecto.Adapters.Postgres
end

defmodule Conformance.SandboxRepo do
  @moduledoc "A repo of the app's role in Ecto's SQL sandbox, as Phoenix's tests use theirs (config/test.exs)."
  use Ecto.Repo, otp_app: :conformance, adapter: Ecto.Adapters.Postgres
end
