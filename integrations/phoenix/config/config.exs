import Config

config :conformance, ecto_repos: [Conformance.Repo]

config :conformance, ConformanceWeb.Endpoint,
  adapter: Bandit.PhoenixAdapter,
  render_errors: [formats: [json: ConformanceWeb.ErrorJSON], layout: false],
  # the conformance app has no sessions or cookies: nothing it signs
  secret_key_base: String.duplicate("conformance", 6)

# the background jobs' queue, in the app's database (its tables: priv/repo/migrations/*_oban.exs); its
# notifications through Erlang's process groups, not LISTEN, which a pooler in transaction mode doesn't keep
config :conformance, Oban,
  repo: Conformance.Repo,
  queues: [default: 1],
  notifier: Oban.Notifiers.PG

# Elixir's own JSON (1.18 and newer)
config :phoenix, :json_library, JSON

config :logger, level: :warning

import_config "#{config_env()}.exs"
