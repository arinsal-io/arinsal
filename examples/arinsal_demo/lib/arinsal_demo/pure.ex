defmodule ArinsalDemo.Pure do
  @moduledoc "Pure recursive, allocation, and collection workloads."
  import Bitwise

  @type body :: {float(), float(), float(), float(), float(), float(), float()}

  @doc "Returns the nth Fibonacci number using the classic recursive workload."
  @spec fib(non_neg_integer()) :: non_neg_integer()
  def fib(n) when n < 2, do: n
  def fib(n), do: fib(n - 1) + fib(n - 2)

  @doc "Runs the reference five-body position update and returns the first body."
  @spec nbody(non_neg_integer()) :: float()
  def nbody(steps) do
    [first | _] =
      Enum.reduce(1..steps//1, bodies(), fn _, current ->
        current |> Enum.map(&accelerate(&1, current)) |> Enum.map(&move/1)
      end)

    elem(first, 0)
  end

  defp bodies do
    [
      {0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 39.47},
      {4.84, -1.16, -0.10, 0.60, 2.81, -0.02, 0.037},
      {8.34, 4.12, -0.4, -1.01, 1.82, 0.008, 0.011},
      {12.89, -15.11, -0.22, 1.08, 0.86, -0.01, 0.0017},
      {15.37, -25.9, 0.17, 0.97, 0.59, -0.03, 0.002}
    ]
  end

  defp move({x, y, z, vx, vy, vz, mass}),
    do: {x + 0.01 * vx, y + 0.01 * vy, z + 0.01 * vz, vx, vy, vz, mass}

  defp accelerate({x, y, z, vx, vy, vz, mass}, bodies) do
    {vx, vy, vz} =
      Enum.reduce(bodies, {vx, vy, vz}, fn
        {^x, ^y, ^z, _ovx, _ovy, _ovz, _other_mass}, velocity ->
          velocity

        {ox, oy, oz, _ovx, _ovy, _ovz, other_mass}, {vx, vy, vz} ->
          dx = x - ox
          dy = y - oy
          dz = z - oz
          distance_squared = dx * dx + dy * dy + dz * dz
          magnitude = 0.01 / (distance_squared * :math.sqrt(distance_squared))

          {vx - dx * other_mass * magnitude, vy - dy * other_mass * magnitude,
           vz - dz * other_mass * magnitude}
      end)

    {x, y, z, vx, vy, vz, mass}
  end

  @doc "Builds and checks balanced binary trees at the reference depths."
  @spec trees(non_neg_integer()) :: non_neg_integer()
  def trees(max_depth) when max_depth < 4, do: 0

  def trees(max_depth),
    do:
      Enum.reduce(4..max_depth//2, 0, fn depth, sum ->
        sum +
          Enum.reduce(1..(1 <<< (max_depth - depth + 4)), 0, fn _, acc ->
            acc + check(tree(depth))
          end)
      end)

  defp tree(0), do: nil
  defp tree(depth), do: {tree(depth - 1), tree(depth - 1)}
  defp check(nil), do: 1
  defp check({left, right}), do: 1 + check(left) + check(right)

  @doc "Maps, filters, and reduces a range through an eager Enum pipeline."
  @spec enum_pipeline(pos_integer()) :: integer()
  def enum_pipeline(size),
    do: 1..size |> Enum.map(&(&1 * 3)) |> Enum.filter(&(rem(&1, 2) == 0)) |> Enum.reduce(0, &+/2)

  @doc "Evaluates the same collection transform lazily with Stream."
  @spec stream_pipeline(pos_integer()) :: integer()
  def stream_pipeline(size),
    do:
      1..size
      |> Stream.map(&(&1 * 3))
      |> Stream.filter(&(rem(&1, 2) == 0))
      |> Enum.reduce(0, &+/2)

  @doc "Sorts deterministic pseudo-random integers."
  @spec sort(pos_integer()) :: [integer()]
  def sort(size), do: Enum.to_list(size..1//-1) |> Enum.sort()

  @doc "Groups a range by parity and returns group sizes."
  @spec group_by(pos_integer()) :: %{boolean() => non_neg_integer()}
  def group_by(size),
    do:
      Enum.map(1..size, &{rem(&1, 2) == 0, &1})
      |> Enum.group_by(&elem(&1, 0), &elem(&1, 1))
      |> Map.new(fn {key, values} -> {key, length(values)} end)

  @doc "Counts repeated values from a bounded range."
  @spec frequencies(pos_integer()) :: %{integer() => pos_integer()}
  def frequencies(size), do: Enum.frequencies(Enum.map(1..size, &rem(&1, 13)))

  @doc "Tail-recursive sum of the integers from 1 to n."
  @spec tail_sum(non_neg_integer()) :: non_neg_integer()
  def tail_sum(n) when n >= 0, do: do_tail_sum(n, 0)

  @doc "Maps a captured factor and offset over values, then sums."
  @spec closure_sum([integer()], integer(), integer()) :: integer()
  def closure_sum(values, factor, offset) do
    values
    |> Enum.map(&(&1 * factor + offset))
    |> Enum.sum()
  end

  @doc "Sums 1..n, throwing and catching every tenth integer."
  @spec catch_throw(pos_integer()) :: integer()
  def catch_throw(n) when n > 0 do
    Enum.reduce(1..n, 0, fn i, acc ->
      try do
        maybe_throw(i, acc)
      catch
        :throw, value -> acc + value
      end
    end)
  end

  @doc "Scores mixed terms with a guard-heavy case."
  @spec guard_score([term()]) :: integer()
  def guard_score(values) do
    Enum.reduce(values, 0, fn value, acc -> acc + classify(value) end)
  end

  defp do_tail_sum(0, acc), do: acc
  defp do_tail_sum(n, acc), do: do_tail_sum(n - 1, acc + n)

  defp maybe_throw(i, _acc) when rem(i, 10) == 0, do: throw(i)
  defp maybe_throw(_i, acc), do: acc

  defp classify(value) do
    case value do
      n when is_integer(n) and n > 100 and rem(n, 2) == 0 -> 4
      n when is_integer(n) and n > 0 and rem(n, 2) == 1 -> 3
      n when is_integer(n) and n > 0 -> 2
      n when is_integer(n) and n < 0 -> 1
      bin when is_binary(bin) and byte_size(bin) > 3 -> 1
      atom when is_atom(atom) -> 1
      _ -> 0
    end
  end
end
