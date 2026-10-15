defmodule Mix.Tasks.Arinsal.Stop do
  use Mix.Task

  @shortdoc "Stop a project"
  @moduledoc """
  Stops the project. Its files and logs stay; `mix arinsal.start` or a new deploy brings it back.

      mix arinsal.stop --tenant acme --project shop [--url http://127.0.0.1:7000]
  """

  alias Arinsal.Cloud

  @impl Mix.Task
  def run(args) do
    {opts, _} = Cloud.parse!(args)

    case Cloud.request!(:post, opts, Cloud.project_path(opts) <> "/stop") do
      %{"state" => _} = project -> Mix.shell().info(Cloud.summary(project))
      _ -> Mix.shell().info("stop: #{opts[:tenant]}/#{opts[:project]} ok")
    end
  end
end
