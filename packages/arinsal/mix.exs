defmodule Arinsal.MixProject do
  use Mix.Project

  @source_url "https://github.com/arinsal-io/arinsal"

  def project do
    [
      app: :arinsal,
      version: "0.1.0",
      name: "Arinsal",
      description: "Run Mix commands with the Arinsal Erlang runtime",
      source_url: @source_url,
      elixir: "~> 1.20",
      start_permanent: Mix.env() == :prod,
      package: [
        licenses: ["Apache-2.0"],
        links: %{"GitHub" => @source_url}
      ],
      deps: []
    ]
  end

  def application do
    [extra_applications: [:logger, :inets, :ssl, :public_key]]
  end
end
