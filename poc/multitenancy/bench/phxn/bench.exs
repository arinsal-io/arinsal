# mix run bench.exs N SERVER(true|false)
[n, server] = System.argv()
n = String.to_integer(n); server = server == "true"

gen = fn i ->
  m = fn s -> Module.concat(["P#{i}", s]) end
  {ep, router, ctrl, pubsub} = {m.("Endpoint"), m.("Router"), m.("HealthController"), m.("PubSub")}
  Application.put_env(:phxn, ep,
    adapter: Bandit.PhoenixAdapter, http: [ip: {127, 0, 0, 1}, port: 6000 + i], server: server,
    secret_key_base: String.duplicate("a", 64), pubsub_server: pubsub)
  Code.compile_quoted(quote do
    defmodule unquote(ctrl) do
      use Phoenix.Controller, formats: [:json]
      def index(conn, _), do: json(conn, %{ok: true})
    end
    defmodule unquote(router) do
      use Phoenix.Router
      pipeline :api, do: plug(:accepts, ["json"])
      scope "/" do
        pipe_through :api
        get "/health", unquote(ctrl), :index
      end
    end
    defmodule unquote(ep) do
      use Phoenix.Endpoint, otp_app: :phxn
      plug Plug.RequestId
      plug Plug.Telemetry, event_prefix: [:phoenix, :endpoint]
      plug Plug.Parsers, parsers: [:urlencoded, :json], pass: ["*/*"], json_decoder: Jason
      plug Plug.Head
      plug Plug.Session, store: :cookie, key: "_k", signing_salt: "abcdefgh"
      plug unquote(router)
    end
  end)
  {ep, pubsub}
end

snap = fn ->
  for p <- Process.list(), do: :erlang.garbage_collect(p)
  m = :erlang.memory()
  %{procs: length(Process.list()), total: m[:total], processes: m[:processes], ets: m[:ets], code: m[:code]}
end

s0 = snap.()
projects = for i <- 1..n, do: gen.(i)
s1 = snap.()
starts =
  for {ep, pubsub} <- projects do
    children = [{:telemetry_poller, measurements: [], period: 10_000}, {Phoenix.PubSub, name: pubsub}, ep]
    {us, {:ok, sup}} = :timer.tc(fn -> Supervisor.start_link(children, strategy: :one_for_one) end)
    Process.unlink(sup)
    {us, sup}
  end
Process.sleep(1000)
s2 = snap.()

walk = fn walk, sup ->
  Supervisor.which_children(sup) |> Enum.flat_map(fn
    {_, pid, :supervisor, [mod]} when is_pid(pid) -> [mod | walk.(walk, pid)]
    {_, pid, _, [mod]} when is_pid(pid) -> [mod]
    {_, pid, _, _} when is_pid(pid) -> [:other]
    _ -> []
  end)
end
{_, sup1} = hd(starts)
by_mod = walk.(walk, sup1) |> Enum.frequencies() |> Enum.sort_by(&elem(&1, 1), :desc) |> Enum.take(8)

us = starts |> Enum.map(&elem(&1, 0)) |> Enum.sort()
kb = fn a, b, k -> div(b[k] - a[k], n * 1024) end
IO.puts(JSON.encode!(%{
  projects: n, server: server,
  unique_code_kb_per_project: kb.(s0, s1, :code),
  state_kb_per_project: kb.(s1, s2, :total), processes_kb: kb.(s1, s2, :processes), ets_kb: kb.(s1, s2, :ets),
  procs_per_project: div(s2.procs - s1.procs, n),
  start_tree_ms_p50: Float.round(Enum.at(us, div(n, 2)) / 1000, 2), start_tree_ms_max: Float.round(List.last(us) / 1000, 2),
  procs_by_module_project1: Map.new(by_mod, fn {m, c} -> {inspect(m), c} end)
}))
if server do
  {:ok, s} = :gen_tcp.connect({127, 0, 0, 1}, 6001, [:binary, active: false])
  :gen_tcp.send(s, "GET /health HTTP/1.1\r\nhost: x\r\naccept: application/json\r\n\r\n")
  {:ok, resp} = :gen_tcp.recv(s, 0, 2000)
  IO.puts("check: " <> (resp |> String.split("\r\n") |> hd()))
end
