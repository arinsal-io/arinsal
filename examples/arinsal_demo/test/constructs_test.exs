defmodule ArinsalDemo.ConstructsTest do
  use ExUnit.Case, async: false

  test "list, tuple, binary, text, and control helpers" do
    assert ArinsalDemo.Lists.map_sum([1, 2, 3]) == 12
    assert ArinsalDemo.Lists.filter_count([1, 2, 3, 4]) == 2
    assert ArinsalDemo.Lists.reduce_sum([1, 2, 3, 4]) == 10
    assert ArinsalDemo.Lists.foldl_sum([1, 2, 3, 4]) == 10
    assert ArinsalDemo.Lists.reverse_sig([1, 2, 3]) == {3, 1, 3}
    assert ArinsalDemo.Lists.sort_ints_sig([3, 1, 2]) |> elem(0) == 1
    assert ArinsalDemo.Lists.sort_ints_sig([3, 1, 2]) |> elem(1) == 3
    assert ArinsalDemo.Lists.sort_strings_sig(["b", "a"]) |> elem(0) == "a"
    assert ArinsalDemo.Lists.repeated_append(5) == 5
    assert ArinsalDemo.Lists.comprehension_sum(6) == 45
    assert ArinsalDemo.Lists.zip_sum([1, 2], [3, 4]) == 10
    assert ArinsalDemo.Lists.flatten_len([[1, [2]], 3]) == 3

    assert ArinsalDemo.Tuples.elem_sum({1, 2, 3, 4}, 2) == 20
    assert ArinsalDemo.Tuples.put_elem_last({1, 2}, 5) == 5
    assert ArinsalDemo.Tuples.update_point(4) == {4, 1}
    assert ArinsalDemo.Tuples.update_record(4) == 4

    assert ArinsalDemo.Binary.sum_bytes(<<1, 2, 3>>) == 6
    assert ArinsalDemo.Binary.build_bytes(1) == {1, 1, 1, 1}
    assert ArinsalDemo.Binary.split_count("a,b,c", ",") == 3
    assert ArinsalDemo.Binary.iodata_bytes(1) == ArinsalDemo.Sig.bin("1,")
    assert ArinsalDemo.Binary.encode64_sig("a") == ArinsalDemo.Sig.bin("YQ==")

    assert ArinsalDemo.Text.split_count("one two") == 2
    assert ArinsalDemo.Text.unicode_length("Привіт") == 6
    assert ArinsalDemo.Text.regex_run(~r/Elixir/, "hi Elixir") == ["Elixir"]

    assert ArinsalDemo.Pure.fib(25) == 75_025
    assert ArinsalDemo.Pure.tail_sum(1_000_000) == 500_000_500_000
    assert ArinsalDemo.Pure.closure_sum([1, 2, 3], 3, 7) == 39
    assert ArinsalDemo.Pure.catch_throw(20) == 30

    assert ArinsalDemo.Pure.guard_score([200, 5, 4, -3, "abcd", :ok, "ab"]) ==
             4 + 3 + 2 + 1 + 1 + 1

    assert ArinsalDemo.Maps.put_n(4) == {4, 1, 4}
    assert ArinsalDemo.Maps.update_all(Map.new(1..3, &{&1, 0}), 3) == {3, 1, 1}
    assert ArinsalDemo.Maps.get_sum(%{1 => 2, 2 => 4}, 2) == 6
    assert ArinsalDemo.Maps.merge_sig(%{1 => 1}, %{1 => 9, 2 => 4}, 1, 2) == {2, 9, 4}
    assert ArinsalDemo.Maps.new_sig([{1, 2}, {2, 4}]) == {2, 2, 4}
    assert ArinsalDemo.Maps.match_keys([%{id: 1, n: 2, flag: true}]) == 3
  end

  test "ETS insert, lookup, update_counter, and select" do
    assert ArinsalDemo.Tables.insert_n(5) == 5
    filled = ArinsalDemo.Tables.new_filled(4)
    parity = ArinsalDemo.Tables.new_parity(10)
    counter = :ets.new(:constructs_counter, [:set, :public])

    try do
      assert ArinsalDemo.Tables.lookup_sum(filled, 4) == 10
      assert ArinsalDemo.Tables.counter_n(counter, 6) == 6
      assert ArinsalDemo.Tables.select_even_sum(parity) == 30
    after
      :ets.delete(filled)
      :ets.delete(parity)
      :ets.delete(counter)
    end
  end

  test "spawn, ping-pong, async stream, and GenServer echo" do
    assert ArinsalDemo.Work.spawn_down() == :ok
    assert ArinsalDemo.Work.message_ping_pong(20) == :ok
    assert ArinsalDemo.Work.async_stream_sum(10) == 385
    {:ok, pid} = GenServer.start_link(ArinsalDemo.Work, :ok)
    assert ArinsalDemo.Work.round_trip(pid) == :ok
    GenServer.stop(pid)
  end

  test "medium JSON document encodes and decodes" do
    document = ArinsalDemo.Json.medium_document()
    assert {:ok, encoded} = ArinsalDemo.Json.encode_document(document)
    assert ArinsalDemo.Json.decode_sig(encoded) == {"doc-100", 50, 100, 1, 100}
  end
end
