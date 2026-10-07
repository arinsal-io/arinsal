defmodule ArinsalDemo.Tuples do
  @moduledoc "Tuple element access, updates, structs, and record-like tuples."

  @doc "Reads every element of an integer tuple `times` times with elem/2."
  @spec elem_sum(tuple(), pos_integer()) :: integer()
  def elem_sum(tuple, times) when times > 0 do
    last = tuple_size(tuple) - 1

    Enum.reduce(1..times, 0, fn _, acc ->
      Enum.reduce(0..last, acc, fn index, inner -> inner + elem(tuple, index) end)
    end)
  end

  @doc "Writes the last element `times` times with put_elem/3."
  @spec put_elem_last(tuple(), pos_integer()) :: integer()
  def put_elem_last(tuple, times) when times > 0 do
    index = tuple_size(tuple) - 1

    1..times
    |> Enum.reduce(tuple, fn i, acc -> put_elem(acc, index, i) end)
    |> elem(index)
  end

  @doc "Updates a struct field `times` times."
  @spec update_point(pos_integer()) :: {integer(), integer()}
  def update_point(times) when times > 0 do
    point =
      Enum.reduce(1..times, %ArinsalDemo.Point{x: 0, y: 1}, fn i, point ->
        %{point | x: i}
      end)

    {point.x, point.y}
  end

  @doc "Rebuilds a tagged record tuple `times` times."
  @spec update_record(pos_integer()) :: integer()
  def update_record(times) when times > 0 do
    {:user, id, _name, _active} =
      Enum.reduce(1..times, {:user, 0, "Ada", true}, fn _i, {:user, id, name, active} ->
        {:user, id + 1, name, active}
      end)

    id
  end
end
