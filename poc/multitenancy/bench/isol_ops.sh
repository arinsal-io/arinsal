#!/bin/zsh
# Per-request op mix on the REST tenant: sends, spawns, and calls of name-resolving functions.
export PATH=/opt/homebrew/opt/erlang@29/bin:/opt/homebrew/opt/elixir/bin:$PATH
R=${0:A:h}/rest/_build/prod/rel/rt/bin/rt
export RELEASE_DISTRIBUTION=sname RELEASE_NODE=rtprof RT_PORT=4200 RT_TENANTS=10 RT_SNAP=${0:A:h}/snap_rest
$R start > ${0:A:h}/logs/prof.log 2>&1 &
until curl -sf 127.0.0.1:4200/ready >/dev/null; do sleep 0.2; done
python3 -c "
import http.client; c=http.client.HTTPConnection('127.0.0.1',4200)
for i in range(500): c.request('GET',f'/t/{i%10+1}/items/{i%200+1}'); c.getresponse().read()"
$R rpc '
c = spawn(fn -> l = fn l, s, p -> receive do
  {:trace, _, :send, _, _} -> l.(l, s + 1, p)
  {:trace, _, :spawn, _, _} -> l.(l, s, p + 1)
  {:get, f} -> send(f, {s, p})
  _ -> l.(l, s, p) end end; l.(l, 0, 0) end)
:persistent_term.put(:prof_counter, c)
:erlang.trace(:all, true, [:send, :procs, {:tracer, c}])
for m <- [:ets, :persistent_term, :application, Application, Registry, GenServer, :gen, :erlang, :proc_lib], do: :erlang.trace_pattern({m, :_, :_}, true, [:call_count])'
python3 -c "
import http.client; c=http.client.HTTPConnection('127.0.0.1',4200)
for i in range(2000): c.request('GET',f'/t/{i%10+1}/items/{i%200+1}'); c.getresponse().read()"
$R rpc '
:erlang.trace(:all, false, [:send, :procs])
c = :persistent_term.get(:prof_counter); send(c, {:get, self()})
{s, p} = receive do x -> x end
want = [{:ets, :lookup}, {:ets, :insert}, {:ets, :select}, {:ets, :info}, {:persistent_term, :get}, {:application, :get_env},
        {Application, :get_env}, {Application, :fetch_env!}, {Registry, :lookup}, {:erlang, :whereis}, {:erlang, :apply},
        {GenServer, :call}, {:gen, :call}, {:erlang, :spawn_opt}, {:proc_lib, :spawn_link}]
calls = for {m, f} <- want, {^f, a} <- m.module_info(:exports), reduce: %{} do acc ->
  case :erlang.trace_info({m, f, a}, :call_count) do
    {:call_count, n} when is_integer(n) and n > 0 -> Map.update(acc, "#{inspect(m)}.#{f}", n, &(&1 + n))
    _ -> acc
  end
end
IO.puts("per request over 2000: sends=#{s / 2000} spawns=#{p / 2000}")
for {k, n} <- Enum.sort_by(calls, &elem(&1, 1), :desc), do: IO.puts("  #{k}: #{Float.round(n / 2000, 2)}")'
$R stop
