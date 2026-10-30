defmodule Rowstile.MixProject do
  use Mix.Project

  # the version rowstile's command and its other packages carry (packaging/version.py sets it)
  @version "0.1.0-dev"
  @source "https://github.com/rowstile/rowstile/tree/main/sdk/elixir"

  def project do
    [
      app: :rowstile,
      version: @version,
      elixir: "~> 1.18",
      deps: deps(),
      description:
        "The SDK for Elixir apps on a rowstile policy (preview): Ecto and Postgrex transactions signed in, " <>
          "refusals as errors, problem details for Phoenix and Plug.",
      package: package(),
      source_url: @source,
      homepage_url: "https://rowstile.dev",
      dialyzer: [
        plt_add_apps: [:ex_unit],
        flags: [:error_handling, :extra_return, :missing_return, :unmatched_returns, :underspecs]
      ]
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end

  defp deps do
    [
      {:postgrex, "~> 0.19"},
      # each optional: the modules that need one are compiled only where the app has it
      {:ecto_sql, "~> 3.10", optional: true},
      {:plug, "~> 1.14", optional: true},
      {:oban, "~> 2.17", optional: true},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end

  defp package do
    [
      name: "rowstile",
      licenses: ["Apache-2.0"],
      links: %{
        "Guide" => "https://rowstile.dev/stacks/phoenix",
        "Source" => @source,
        "Changelog" => "https://rowstile.dev/changelog"
      },
      files: ["lib", "mix.exs", "README.md", "LICENSE", ".formatter.exs"]
    ]
  end
end
