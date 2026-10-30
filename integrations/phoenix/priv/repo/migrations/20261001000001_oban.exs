defmodule Conformance.Repo.Migrations.Oban do
  # Oban's tables, for the background jobs, and the app role's rights on them (row-level security doesn't govern
  # them: no rule of the policy names them)
  @moduledoc false
  use Ecto.Migration

  def up do
    Oban.Migration.up(version: 14)

    execute "GRANT SELECT, INSERT, UPDATE, DELETE ON public.oban_jobs, public.oban_peers TO conf_app"

    execute "GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO conf_app"
  end

  def down do
    Oban.Migration.down(version: 1)
  end
end
