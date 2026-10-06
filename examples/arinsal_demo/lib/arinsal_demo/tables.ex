defmodule ArinsalDemo.Tables do
  @moduledoc "Direct ETS set operations."

  @doc "Inserts keys 1..n into a fresh set and returns the table size."
  @spec insert_n(pos_integer()) :: non_neg_integer()
  def insert_n(n) when n > 0 do
    table = :ets.new(:arinsal_demo_insert, [:set, :public])

    try do
      Enum.each(1..n, fn i -> true = :ets.insert(table, {i, i}) end)
      :ets.info(table, :size)
    after
      :ets.delete(table)
    end
  end

  @doc "Creates a public set of `{i, i}` pairs for keys 1..n."
  @spec new_filled(pos_integer()) :: :ets.tid()
  def new_filled(n) when n > 0 do
    table = :ets.new(:arinsal_demo_filled, [:set, :public])
    true = :ets.insert(table, Enum.map(1..n, &{&1, &1}))
    table
  end

  @doc "Creates a public set of `{i, rem(i, 2)}` pairs for keys 1..n."
  @spec new_parity(pos_integer()) :: :ets.tid()
  def new_parity(n) when n > 0 do
    table = :ets.new(:arinsal_demo_parity, [:set, :public])
    true = :ets.insert(table, Enum.map(1..n, &{&1, rem(&1, 2)}))
    table
  end

  @doc "Sums values looked up for keys 1..n."
  @spec lookup_sum(:ets.tid(), pos_integer()) :: integer()
  def lookup_sum(table, n) when n > 0 do
    Enum.reduce(1..n, 0, fn i, acc ->
      [{^i, value}] = :ets.lookup(table, i)
      acc + value
    end)
  end

  @doc "Resets a counter and applies update_counter/3 n times."
  @spec counter_n(:ets.tid(), pos_integer()) :: integer()
  def counter_n(table, n) when n > 0 do
    true = :ets.insert(table, {:counter, 0})
    Enum.reduce(1..n, 0, fn _, _ -> :ets.update_counter(table, :counter, 1) end)
  end

  @doc "Sums even keys selected by a match specification."
  @spec select_even_sum(:ets.tid()) :: integer()
  def select_even_sum(table) do
    spec = [{{:"$1", 0}, [], [:"$1"]}]
    table |> :ets.select(spec) |> Enum.sum()
  end
end
