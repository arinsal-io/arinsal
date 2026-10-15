defmodule Mix.Tasks.Arinsal.Logs do
  use Mix.Task

  @shortdoc "Print the logs of a project"
  @moduledoc """
  Prints the last lines the manager collected for a project.

      mix arinsal.logs --tenant acme --project shop [-n 100] [--tail]

  `--tail` keeps polling and prints new lines until interrupted.
  """

  alias Arinsal.Cloud

  @impl Mix.Task
  def run(args) do
    {opts, _} = Cloud.parse!(args, n: :integer, tail: :boolean, interval: :integer, since: :integer)
    n = opts[:n] || 100
    {lines, next} = fetch(opts, "n=#{n}")
    Enum.each(lines, &IO.puts/1)
    if opts[:tail], do: tail(opts, next)
  end

  defp tail(opts, since) do
    Process.sleep(opts[:interval] || 500)
    {lines, next} = fetch(opts, "n=100000&since=#{since}")
    Enum.each(lines, &IO.puts/1)
    tail(opts, next)
  end

  defp fetch(opts, query) do
    %{"lines" => lines, "next" => next} = Cloud.request!(:get, opts, Cloud.project_path(opts) <> "/logs?" <> query)
    {lines, next}
  end
end
