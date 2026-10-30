import Config

# Served (mix run --no-halt) or migrated (mix ecto.migrate): the database's URL, the app role's to serve, the
# owner's to migrate; and where to listen
if config_env() != :test do
  config :conformance, Conformance.Repo, url: System.fetch_env!("DATABASE_URL")

  config :conformance, ConformanceWeb.Endpoint,
    server: true,
    http: [ip: {127, 0, 0, 1}, port: String.to_integer(System.get_env("PORT", "4000"))]
end
