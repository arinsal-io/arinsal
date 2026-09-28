defmodule ArinsalDemo.MixProject do
  use Mix.Project

  def project do
    [
      app: :arinsal_demo,
      version: "0.1.0",
      elixir: "~> 1.20",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger],
      mod: {ArinsalDemo.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:benchee, "~> 1.3", only: [:dev, :bench]},
      {:benchee_json, "~> 1.0", only: [:dev, :bench]},
      {:jason, "~> 1.4"}
    ]
  end
end
