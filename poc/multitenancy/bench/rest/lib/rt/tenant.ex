defmodule RT.Tenant do
  @moduledoc false
  use Supervisor

  def start_link({id, data}), do: Supervisor.start_link(__MODULE__, {id, data})

  def init({id, data}) do
    Registry.register(RT.Registry, {:sup, id}, nil)
    {items, limiter} =
      case data do
        {:fresh, n} -> {RT.Store.seed(n), %{}}
        {:restored, items, limiter} -> {items, limiter}
      end

    children = [
      {RT.Store, {id, items}},
      {RT.Limiter, {id, limiter}},
      Task.Supervisor,
      {:telemetry_poller, measurements: [{RT.Store, :measure, [id]}], period: 10_000}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end
end

defmodule RT.Store do
  @moduledoc false
  use GenServer

  def seed(n),
    do: for(i <- 1..n//1, do: {i, %{"id" => i, "name" => "item-#{i}", "price" => i * 3, "tags" => ["new", "sale"]}})

  def start_link({id, items}), do: GenServer.start_link(__MODULE__, {id, items})

  def init({id, items}) do
    tab = :ets.new(:items, [:set, :public, read_concurrency: true])
    :ets.insert(tab, items)
    Registry.register(RT.Registry, {:store, id}, tab)
    {:ok, tab}
  end

  def measure(id) do
    case Registry.lookup(RT.Registry, {:store, id}) do
      [{_, tab}] -> :telemetry.execute([:rt, :store], %{size: :ets.info(tab, :size)}, %{tenant: id})
      [] -> :ok
    end
  end
end

defmodule RT.Limiter do
  @moduledoc false
  use GenServer

  def start_link({id, state}), do: GenServer.start_link(__MODULE__, {id, state})

  def init({id, state}) do
    Registry.register(RT.Registry, {:limiter, id}, nil)
    {:ok, state}
  end

  def handle_call({:hit, key}, _from, state) do
    now = System.monotonic_time(:millisecond)
    {tokens, at} = Map.get(state, key, {100_000, now})
    tokens = min(100_000, tokens + (now - at) * 100)
    if tokens > 0, do: {:reply, :ok, Map.put(state, key, {tokens - 1, now})}, else: {:reply, :limited, state}
  end
end
