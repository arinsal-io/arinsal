defmodule RT.MixProject do
  use Mix.Project

  def project do
    [app: :rt, version: "0.1.0", elixir: "~> 1.18", start_permanent: true, deps: deps(),
     releases: [rt: [include_executables_for: [:unix]]]]
  end

  def application, do: [extra_applications: [:logger], mod: {RT.Application, []}]

  defp deps do
    [{:bandit, "~> 1.6"}, {:plug, "~> 1.16"}, {:jason, "~> 1.4"}, {:telemetry_poller, "~> 1.1"},
     {:arinsal, path: "../../../../packages/arinsal", only: :dev, runtime: false}]
  end
end
