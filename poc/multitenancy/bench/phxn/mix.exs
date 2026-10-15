defmodule Phxn.MixProject do
  use Mix.Project
  def project, do: [app: :phxn, version: "0.1.0", elixir: "~> 1.18", deps: deps()]
  def application, do: [extra_applications: [:logger]]
  defp deps, do: [{:phoenix, "== 1.8.15"}, {:bandit, "~> 1.6"}, {:jason, "~> 1.4"}, {:telemetry_poller, "~> 1.1"}]
end
