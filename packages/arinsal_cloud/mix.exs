defmodule ArinsalCloud.MixProject do
  use Mix.Project

  def project do
    [
      app: :arinsal_cloud,
      version: "0.1.0",
      elixir: "~> 1.20",
      description: "Multi-tenant manager for Arinsal namespaces (PoC)",
      erlc_paths: ["src"],
      erlc_options: [:debug_info, :warnings_as_errors],
      start_permanent: Mix.env() == :prod,
      deps: []
    ]
  end

  def application do
    [
      mod: {:arinsal_cloud_app, []},
      applications: [:kernel, :stdlib],
      env: [
        admin_port: 7000,
        data_dir: ~c"arinsal-cloud-data",
        idle_timeout_ms: :infinity,
        backend: :auto,
        fake_mode: :same_node,
        log_lines: 1000
      ]
    ]
  end
end
