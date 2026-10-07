defmodule ArinsalDemo.Cache do
  @moduledoc "A supervised ETS-backed cache with serialized writes."
  use GenServer

  @table __MODULE__

  @doc "Starts the cache server and its protected ETS table."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []),
    do: GenServer.start_link(__MODULE__, :ok, Keyword.put_new(opts, :name, __MODULE__))

  @doc "Looks up a value directly in ETS."
  @spec get(term()) :: {:ok, term()} | :error
  def get(key) do
    case :ets.lookup(@table, key) do
      [{^key, value}] -> {:ok, value}
      [] -> :error
    end
  end

  @doc "Stores a value and returns it."
  @spec put(term(), term()) :: term()
  def put(key, value), do: GenServer.call(__MODULE__, {:put, key, value})

  @doc "Returns a cached value or computes and stores it once."
  @spec fetch_or_compute(term(), (-> term())) :: term()
  def fetch_or_compute(key, compute) when is_function(compute, 0),
    do: GenServer.call(__MODULE__, {:fetch, key, compute})

  @impl true
  def init(:ok) do
    :ets.new(@table, [:named_table, :set, :protected, read_concurrency: true])
    {:ok, nil}
  end

  @impl true
  def handle_call({:put, key, value}, _from, state) do
    true = :ets.insert(@table, {key, value})
    {:reply, value, state}
  end

  def handle_call({:fetch, key, compute}, _from, state) do
    value =
      case :ets.lookup(@table, key) do
        [{^key, value}] -> value
        [] -> compute.()
      end

    true = :ets.insert(@table, {key, value})
    {:reply, value, state}
  end
end
