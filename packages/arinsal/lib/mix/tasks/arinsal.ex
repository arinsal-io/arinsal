defmodule Mix.Tasks.Arinsal do
  use Mix.Task

  @shortdoc "Run a Mix command with the Arinsal runtime"
  @moduledoc """
  Builds Arinsal and runs a Mix command with Arinsal's `erl` shim first on PATH.

      mix arinsal test
      mix arinsal compile
      mix arinsal run -e 'IO.puts(:hello)'

  Set `ARINSAL_PROFILE=debug` for a faster debug build. The default is release.
  """

  @impl Mix.Task
  def run([]) do
    Mix.raise("Usage: mix arinsal <mix command> [arguments...]")
  end

  def run(args) do
    Mix.Task.run("app.config")
    shim_dir = Arinsal.Mix.build_runtime!()
    mix = System.find_executable("mix") || Mix.raise("mix executable was not found on PATH")
    path_separator = if match?({:win32, _}, :os.type()), do: ";", else: ":"

    path =
      [shim_dir, System.get_env("PATH", "")]
      |> Enum.reject(&(&1 == ""))
      |> Enum.join(path_separator)

    args = if List.first(args) == "compile", do: args ++ ["--force"], else: args

    {_output, status} =
      System.cmd(mix, args,
        cd: File.cwd!(),
        env: [{"PATH", path}],
        into: IO.stream(:stdio, :line),
        stderr_to_stdout: true
      )

    if status != 0, do: System.halt(status)
  end
end
