defmodule Conformance.MixProject do
  use Mix.Project

  def project do
    [
      app: :conformance,
      version: "0.1.0",
      elixir: "~> 1.18",
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps(),
      aliases: [test: ["test --no-start"]],
      # what the checks run of the SDK, measured by test/support/cover.ex
      test_coverage: [tool: Conformance.Cover],
      dialyzer: [plt_add_apps: [:ex_unit, :mix]]
    ]
  end

  def application do
    [
      mod: {Conformance.Application, []},
      extra_applications: [:logger | extra_applications(Mix.env())]
    ]
  end

  # the tests' HTTP client (inets) and Erlang's cover (tools)
  defp extra_applications(:test), do: [:inets, :tools]
  defp extra_applications(_), do: []

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      # the SDK, from this repository (ROWSTILE_SDK: another folder, such as the package test.sh builds)
      {:rowstile, path: System.get_env("ROWSTILE_SDK", "../../sdk/elixir")},
      {:phoenix, "~> 1.8"},
      {:bandit, "~> 1.6"},
      {:ecto_sql, "~> 3.13"},
      {:postgrex, "~> 0.20"},
      {:oban, "~> 2.19"},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end
end
