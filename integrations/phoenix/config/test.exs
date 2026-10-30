import Config

# the app's role, on this partition's copy of the migrated test database (test/test_helper.exs makes it, and sets
# its name here before the app starts)
config :conformance, Conformance.Repo,
  url: System.get_env("ROWSTILE_APP_TESTS_URL", "postgres://conf_app:app@localhost/conf_tests"),
  pool_size: 10

# a repo of the app on the same database, in Ecto's SQL sandbox: each test's writes are rolled back
config :conformance, Conformance.SandboxRepo,
  url: System.get_env("ROWSTILE_APP_TESTS_URL", "postgres://conf_app:app@localhost/conf_tests"),
  pool: Ecto.Adapters.SQL.Sandbox

config :conformance, ConformanceWeb.Endpoint, server: false

# jobs run when a test drains the queue (Oban.drain_queue), in the test's process
config :conformance, Oban, testing: :manual
