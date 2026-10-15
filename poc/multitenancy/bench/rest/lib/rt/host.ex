defmodule RT.Host do
  @moduledoc false
  @behaviour Plug
  import Plug.Conn

  @router RT.Router.init([])

  def init(opts), do: opts

  def call(%{path_info: ["ready"]} = conn, _),
    do: send_resp(conn, if(:persistent_term.get(:rt_ready, false), do: 200, else: 503), "")

  def call(%{method: "POST", path_info: ["admin", "suspend", id]} = conn, _) do
    {us, bytes} = :timer.tc(fn -> suspend(id) end)
    send_resp(conn, 200, Jason.encode!(%{us: us, bytes: bytes}))
  end

  def call(%{path_info: ["t", id | rest]} = conn, _) do
    ctx = context(id) || (resume(id) && context(id))
    case GenServer.call(ctx.limiter, {:hit, conn.remote_ip}) do
      :ok -> conn |> put_private(:rt, ctx) |> Map.put(:path_info, rest) |> RT.Router.call(@router)
      :limited -> send_resp(conn, 429, "")
    end
  end

  def start_tenant(id, data), do: DynamicSupervisor.start_child(RT.Tenants, {RT.Tenant, {id, data}})

  defp context(id) do
    with [{_, tab}] <- Registry.lookup(RT.Registry, {:store, id}),
         [{limiter, _}] <- Registry.lookup(RT.Registry, {:limiter, id}) do
      %{id: id, tab: tab, limiter: limiter}
    else
      _ -> nil
    end
  end

  defp file(id), do: Path.join(System.get_env("RT_SNAP", "/tmp/rt_snap"), id)

  def suspend(id) do
    ctx = context(id)
    [{sup, _}] = Registry.lookup(RT.Registry, {:sup, id})
    bin = :erlang.term_to_binary({:ets.tab2list(ctx.tab), :sys.get_state(ctx.limiter)})
    {:ok, f} = :file.open(file(id), [:raw, :binary, :write])
    :ok = :file.write(f, bin)
    :ok = :file.datasync(f)
    :ok = :file.close(f)
    :ok = DynamicSupervisor.terminate_child(RT.Tenants, sup)
    byte_size(bin)
  end

  def resume(id) do
    {:ok, bin} = File.read(file(id))
    {items, limiter} = :erlang.binary_to_term(bin)
    {:ok, _} = start_tenant(id, {:restored, items, limiter})
  end
end
