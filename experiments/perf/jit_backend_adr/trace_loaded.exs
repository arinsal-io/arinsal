:erlang.trace_pattern({:_, :_, :_}, true, [:call_count])
:erlang.trace_pattern(:on_load, true, [:call_count])

System.at_exit(fn _ ->
  for {module, path} <- :code.all_loaded(), is_list(path),
      {function, arity} <- module.module_info(:functions),
      {:call_count, count} <- [:erlang.trace_info({module, function, arity}, :call_count)],
      count > 0 do
    IO.puts("HOT_FUNC\t#{module}\t#{function}\t#{arity}\t#{count}")
  end
end)

Code.require_file("loaded.exs", __DIR__)
