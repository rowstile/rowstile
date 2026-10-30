defmodule ConformanceWeb.Endpoint do
  use Phoenix.Endpoint, otp_app: :conformance

  plug Plug.Parsers, parsers: [:json], json_decoder: JSON
  plug ConformanceWeb.Router
end
