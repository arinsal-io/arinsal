defmodule Mix.Tasks.Arinsal.Start do
  use Mix.Task

  @shortdoc "Start a stopped project"
  @moduledoc """
  Starts a stopped or failed project from its last deployed release.

      mix arinsal.start --tenant acme --project shop [--url http://127.0.0.1:7000]
  """

  alias Arinsal.Cloud

  @impl Mix.Task
  def run(args) do
    {opts, _} = Cloud.parse!(args)

    case Cloud.request!(:post, opts, Cloud.project_path(opts) <> "/start") do
      %{"state" => _} = project -> Mix.shell().info(Cloud.summary(project))
      _ -> Mix.shell().info("start: #{opts[:tenant]}/#{opts[:project]} ok")
    end
  end
end
