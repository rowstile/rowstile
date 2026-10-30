defmodule Conformance.Checks do
  @moduledoc """
  An ExUnit formatter that prints each test's line as the other suites print their checks: `ok    7: ...`, or
  `FAIL  7: ...` and why, the test's name being the check's words; then how many ran, and how many failed.
  """
  use GenServer

  @impl true
  def init(_opts), do: {:ok, %{tests: 0, failed: 0}}

  @impl true
  def handle_cast({:test_finished, %ExUnit.Test{name: name, state: state} = test}, counts) do
    "test " <> words = Atom.to_string(name)

    case state do
      nil ->
        IO.puts("ok    " <> words)
        {:noreply, %{counts | tests: counts.tests + 1}}

      {kind, failures} when kind in [:failed, :invalid] ->
        IO.puts("FAIL  " <> words)

        if kind == :failed,
          do: IO.puts(ExUnit.Formatter.format_test_failure(test, failures, 1, 120, &plain/2))

        {:noreply, %{counts | tests: counts.tests + 1, failed: counts.failed + 1}}

      _excluded_or_skipped ->
        {:noreply, counts}
    end
  end

  def handle_cast(
        {:module_finished, %ExUnit.TestModule{state: {:failed, failures}} = module},
        counts
      ) do
    IO.puts(ExUnit.Formatter.format_test_all_failure(module, failures, 1, 120, &plain/2))
    {:noreply, %{counts | failed: counts.failed + 1}}
  end

  def handle_cast({:suite_finished, _times}, counts) do
    IO.puts("#{counts.tests} checks, #{counts.failed} failed")
    {:noreply, counts}
  end

  def handle_cast(_event, counts), do: {:noreply, counts}

  defp plain(_kind, message), do: message
end
