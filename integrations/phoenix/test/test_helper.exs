# The suite's databases (test.sh sets them): ROWSTILE_TESTS_URL, the tables' owner on the migrated test database,
# which each partition copies (check 12), and ROWSTILE_APP_TESTS_URL, the app's role on it. The copy is made before
# the app connects (mix test --no-start: mix.exs's alias), and the app's repos are set to it.
Logger.configure(level: :warning)
copy = Rowstile.Testing.database_per_partition(System.fetch_env!("ROWSTILE_TESTS_URL"))
Application.put_env(:conformance, :database, copy)

for repo <- [Conformance.Repo, Conformance.SandboxRepo] do
  config = Application.fetch_env!(:conformance, repo)

  Application.put_env(
    :conformance,
    repo,
    Keyword.update!(config, :url, &Conformance.Rows.on(&1, copy))
  )
end

{:ok, _} = Application.ensure_all_started(:conformance)
ExUnit.start(formatters: [Conformance.Checks])
