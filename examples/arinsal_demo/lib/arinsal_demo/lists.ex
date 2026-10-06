defmodule ArinsalDemo.Lists do
  @moduledoc "List construction, traversal, and ordering workloads."

  @doc "Doubles each integer with Enum.map/2 and sums the result."
  @spec map_sum([integer()]) :: integer()
  def map_sum(values), do: values |> Enum.map(&(&1 * 2)) |> Enum.sum()

  @doc "Counts even integers with Enum.filter/2."
  @spec filter_count([integer()]) :: non_neg_integer()
  def filter_count(values), do: values |> Enum.filter(&(rem(&1, 2) == 0)) |> length()

  @doc "Sums integers with Enum.reduce/3."
  @spec reduce_sum([integer()]) :: integer()
  def reduce_sum(values), do: Enum.reduce(values, 0, &+/2)

  @doc "Sums integers with :lists.foldl/3."
  @spec foldl_sum([integer()]) :: integer()
  def foldl_sum(values), do: :lists.foldl(fn item, acc -> item + acc end, 0, values)

  @doc "Reverses a list and returns its ends and length."
  @spec reverse_sig([integer()]) :: {integer(), integer(), non_neg_integer()}
  def reverse_sig(values) do
    reversed = Enum.reverse(values)
    {hd(reversed), List.last(reversed), length(reversed)}
  end

  @doc "Sorts integers and returns the ends plus an order-sensitive checksum."
  @spec sort_ints_sig([integer()]) :: {integer(), integer(), integer()}
  def sort_ints_sig(values) do
    sorted = Enum.sort(values)
    {hd(sorted), List.last(sorted), rolling(sorted)}
  end

  @doc "Sorts strings and returns the ends plus an order-sensitive checksum."
  @spec sort_strings_sig([String.t()]) :: {String.t(), String.t(), integer()}
  def sort_strings_sig(values) do
    sorted = Enum.sort(values)
    {hd(sorted), List.last(sorted), rolling(sorted)}
  end

  @doc "Appends n integers with the ++ operator and returns the length."
  @spec repeated_append(pos_integer()) :: non_neg_integer()
  def repeated_append(n) when n > 0 do
    Enum.reduce(1..n, [], fn i, acc -> acc ++ [i] end) |> length()
  end

  @doc "Sums squares of multiples of three using a comprehension."
  @spec comprehension_sum(pos_integer()) :: integer()
  def comprehension_sum(n) when n > 0 do
    Enum.sum(for i <- 1..n, rem(i, 3) == 0, do: i * i)
  end

  @doc "Sums both sides of Enum.zip/2."
  @spec zip_sum([integer()], [integer()]) :: integer()
  def zip_sum(left, right) do
    Enum.reduce(Enum.zip(left, right), 0, fn {a, b}, acc -> acc + a + b end)
  end

  @doc "Flattens a nested list and returns its length."
  @spec flatten_len([term()]) :: non_neg_integer()
  def flatten_len(nested), do: nested |> List.flatten() |> length()

  defp rolling(values) do
    Enum.reduce(values, 0, fn value, acc -> rem(acc * 131 + item(value), 1_000_000_007) end)
  end

  defp item(value) when is_integer(value), do: value

  defp item(value) when is_binary(value) do
    value
    |> :binary.bin_to_list()
    |> Enum.reduce(0, fn byte, acc -> rem(acc * 131 + byte, 1_000_000_007) end)
  end
end
