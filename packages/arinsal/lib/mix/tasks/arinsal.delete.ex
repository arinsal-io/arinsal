defmodule Mix.Tasks.Arinsal.Delete do
  use Mix.Task

  @shortdoc "Delete a project"
  @moduledoc """
  Stops the project and removes its files and logs.

      mix arinsal.delete --tenant acme --project shop [--url http://127.0.0.1:7000]
  """

  alias Arinsal.Cloud

  @impl Mix.Task
  def run(args) do
    {opts, _} = Cloud.parse!(args)

    case Cloud.request!(:delete, opts, Cloud.project_path(opts)) do
      %{"state" => _} = project -> Mix.shell().info(Cloud.summary(project))
      _ -> Mix.shell().info("delete: #{opts[:tenant]}/#{opts[:project]} ok")
    end
  end
end
