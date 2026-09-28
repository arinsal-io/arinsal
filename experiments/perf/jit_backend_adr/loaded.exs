System.at_exit(fn _ ->
  for {_module, path} <- :code.all_loaded(), is_list(path) do
    IO.puts("BEAM_LOADED " <> List.to_string(path))
  end
end)

case System.argv() do
  ["ok"] -> :ok
  ["test"] ->
    Mix.start()
    Code.require_file("mix.exs", File.cwd!())
    Mix.Task.run("test", [])
  ["compile"] ->
    Mix.start()
    Code.require_file("mix.exs", File.cwd!())
    Mix.Task.run("compile", ["--force"])
end
