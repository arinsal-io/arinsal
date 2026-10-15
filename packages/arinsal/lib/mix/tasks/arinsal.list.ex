defmodule Mix.Tasks.Arinsal.List do
  use Mix.Task

  @shortdoc "List the projects of an Arinsal cloud manager"
  @moduledoc """
  Lists every project the manager knows.

      mix arinsal.list [--url http://127.0.0.1:7000]
  """

  alias Arinsal.Cloud

  @impl Mix.Task
  def run(args) do
    {opts, _, _} = OptionParser.parse(args, strict: [url: :string])

    case Cloud.request!(:get, opts, "/projects") do
      [] -> Mix.shell().info("No projects.")
      projects -> Enum.each(projects, &Mix.shell().info(Cloud.summary(&1)))
    end
  end
end
