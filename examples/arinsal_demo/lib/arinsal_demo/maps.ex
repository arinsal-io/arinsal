defprotocol ArinsalDemo.Describe do
  @doc "Returns a compact representation of a domain value."
  @spec describe(t()) :: term()
  def describe(value)
end

defmodule ArinsalDemo.Account do
  @moduledoc "A small account record used for protocol dispatch."
  defstruct [:id, :name]
end

defmodule ArinsalDemo.Event do
  @moduledoc "A timestamped event record used for protocol dispatch."
  defstruct [:kind, :at]
end

defmodule ArinsalDemo.Point do
  @moduledoc "A coordinate record used for protocol dispatch."
  defstruct [:x, :y]
end

defimpl ArinsalDemo.Describe, for: ArinsalDemo.Account do
  def describe(%{id: id, name: name}), do: {:account, id, name}
end

defimpl ArinsalDemo.Describe, for: ArinsalDemo.Event do
  def describe(%{kind: kind, at: at}), do: {:event, kind, at}
end

defimpl ArinsalDemo.Describe, for: ArinsalDemo.Point do
  def describe(%{x: x, y: y}), do: {:point, x, y}
end

defmodule ArinsalDemo.Maps do
  @moduledoc "Map construction, updates, structs, and protocol dispatch workloads."

  @doc "Builds a small map from key-value pairs."
  @spec small_map() :: map()
  def small_map, do: Map.new(1..16, &{String.to_atom("k#{&1}"), &1})

  @doc "Builds a larger map from integer keys."
  @spec large_map(pos_integer()) :: map()
  def large_map(size), do: Map.new(1..size, &{&1, &1 * 2})

  @doc "Increments an existing key repeatedly."
  @spec update_loop(non_neg_integer()) :: non_neg_integer()
  def update_loop(iterations),
    do:
      Enum.reduce(1..iterations//1, %{count: 0}, fn _, map ->
        Map.update!(map, :count, &(&1 + 1))
      end).count

  @doc "Dispatches three concrete structs through a shared protocol."
  @spec dispatch() :: [tuple()]
  def dispatch do
    [
      ArinsalDemo.Describe.describe(%ArinsalDemo.Account{id: 7, name: "Ada"}),
      ArinsalDemo.Describe.describe(%ArinsalDemo.Event{kind: :login, at: 123}),
      ArinsalDemo.Describe.describe(%ArinsalDemo.Point{x: 2, y: 5})
    ]
  end

  @doc "Builds a map of integer keys 1..n with Map.put/3."
  @spec put_n(pos_integer()) :: {non_neg_integer(), integer() | nil, integer() | nil}
  def put_n(n) when n > 0 do
    map = Enum.reduce(1..n, %{}, fn i, acc -> Map.put(acc, i, i) end)
    {map_size(map), Map.get(map, 1), Map.get(map, n)}
  end

  @doc "Increments integer keys 1..n with Map.update!/3."
  @spec update_all(map(), pos_integer()) :: {non_neg_integer(), term(), term()}
  def update_all(map, n) when is_map(map) and n > 0 do
    updated = Enum.reduce(1..n, map, fn i, acc -> Map.update!(acc, i, &(&1 + 1)) end)
    {map_size(updated), Map.get(updated, 1), Map.get(updated, n)}
  end

  @doc "Sums Map.get/2 for keys 1..n."
  @spec get_sum(map(), pos_integer()) :: integer()
  def get_sum(map, n) when n > 0 do
    Enum.reduce(1..n, 0, fn i, acc -> acc + Map.get(map, i) end)
  end

  @doc "Merges two maps and returns the size plus two probed values."
  @spec merge_sig(map(), map(), term(), term()) :: {non_neg_integer(), term(), term()}
  def merge_sig(left, right, left_key, right_key) do
    merged = Map.merge(left, right)
    {map_size(merged), Map.get(merged, left_key), Map.get(merged, right_key)}
  end

  @doc "Builds a map from key-value pairs with Map.new/1."
  @spec new_sig([{term(), term()}]) :: {non_neg_integer(), term(), term()}
  def new_sig(pairs) do
    map = Map.new(pairs)
    {map_size(map), Map.get(map, 1), Map.get(map, length(pairs))}
  end

  @doc "Sums fields extracted by a map-key pattern match."
  @spec match_keys([map()]) :: integer()
  def match_keys(maps) do
    Enum.reduce(maps, 0, fn %{id: id, n: n}, acc -> acc + id + n end)
  end
end
