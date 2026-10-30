defmodule Conformance.Cover do
  @moduledoc """
  What the checks run of the SDK (sdk/elixir, the dependency `rowstile`), with Erlang's cover, which counts lines:
  Elixir has no branch coverage. `mix test --cover` (mix.exs's test_coverage) compiles the SDK's modules for it,
  and keeps what each partition ran in CONFORMANCE_COVERAGE (partition-N.coverdata); then test.sh reports on all of
  it: `mix run --no-start -e "Conformance.Cover.report()"`, which prints each module's lines, what no check runs,
  and fails below 100%.
  """

  @doc false
  def start(_compile_path, _opts) do
    {:ok, _} = :cover.start()
    sdk_modules() |> Enum.each(fn beam -> {:ok, _} = :cover.compile_beam(beam) end)

    out =
      Path.join(
        System.fetch_env!("CONFORMANCE_COVERAGE"),
        "partition-#{System.get_env("MIX_TEST_PARTITION", "1")}.coverdata"
      )

    fn -> :ok = :cover.export(String.to_charlist(out)) end
  end

  # the SDK's compiled modules, as the app's build holds them
  defp sdk_modules do
    Path.join([Mix.Project.build_path(), "lib", "rowstile", "ebin", "*.beam"])
    |> Path.wildcard()
    |> Enum.map(&String.to_charlist/1)
  end

  @doc false
  def report do
    # (cover says each time that the data was imported: to a device of its own)
    {:ok, quiet} = StringIO.open("")
    leader = Process.group_leader()
    Process.group_leader(self(), quiet)
    {:ok, _} = :cover.start()
    Process.group_leader(self(), leader)
    Enum.each(sdk_modules(), fn beam -> {:ok, _} = :cover.compile_beam(beam) end)
    dir = System.fetch_env!("CONFORMANCE_COVERAGE")

    for file <- Path.wildcard(Path.join(dir, "*.coverdata")),
        do: :ok = :cover.import(String.to_charlist(file))

    missed =
      for module <- Enum.sort(:cover.modules()), reduce: 0 do
        missed ->
          {:ok, lines} = :cover.analyse(module, :calls, :line)
          lines = for {{_, line}, calls} <- lines, line != 0, do: {line, calls}
          unrun = for {line, 0} <- lines, do: line

          covered =
            if lines == [], do: 100.0, else: 100 * (length(lines) - length(unrun)) / length(lines)

          file = module.module_info(:compile)[:source] |> to_string() |> Path.basename()

          IO.puts(
            :io_lib.format("~-38s ~-14s lines ~6.2f%  ~s", [
              inspect(module),
              file,
              covered,
              Enum.join(unrun, ", ")
            ])
          )

          missed + length(unrun)
      end

    if missed > 0, do: System.halt(1)
  end
end
