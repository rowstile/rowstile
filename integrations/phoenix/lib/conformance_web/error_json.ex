defmodule ConformanceWeb.ErrorJSON do
  @moduledoc "What Phoenix answers for an error nothing else answered: its status, and nothing more."

  @spec render(String.t(), map()) :: map()
  def render(template, _assigns),
    do: %{errors: %{detail: Phoenix.Controller.status_message_from_template(template)}}
end
