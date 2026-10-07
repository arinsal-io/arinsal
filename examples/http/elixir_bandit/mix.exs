defmodule ArinsalHttp.MixProject do
  use Mix.Project

  def project do
    [app: :arinsal_http, version: "0.1.0", elixir: "~> 1.20", start_permanent: Mix.env() == :prod,
     deps: [{:bandit, "~> 1.7"}, {:plug, "~> 1.18"}, {:jason, "~> 1.4"}]]
  end

  def application do
    [extra_applications: [:logger], mod: {ArinsalHttp.Application, []}]
  end
end
