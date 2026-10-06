defmodule ArinsalDemo.BenchJobs do
  @moduledoc false

  @suites ~w(pure maps lists text binary tuples control processes ets cache work json)

  @doc "Suite names, in table order."
  def suites, do: @suites

  @doc "Returns `{scenario, function}` pairs for one suite."
  def jobs("pure") do
    [
      {"fib 20", fn -> ArinsalDemo.Pure.fib(20) end},
      {"nbody 100", fn -> ArinsalDemo.Pure.nbody(100) end},
      {"trees depth 8", fn -> ArinsalDemo.Pure.trees(8) end},
      {"Enum pipeline", fn -> ArinsalDemo.Pure.enum_pipeline(1_000) end},
      {"Stream pipeline", fn -> ArinsalDemo.Pure.stream_pipeline(1_000) end},
      {"sort 1k", fn -> ArinsalDemo.Pure.sort(1_000) end}
    ]
  end

  def jobs("maps") do
    small = Map.new(1..32, &{&1, 0})
    mid = Map.new(1..1_000, &{&1, 0})
    large = Map.new(1..10_000, &{&1, 0})
    filled_small = Map.new(1..32, &{&1, &1})
    filled_mid = Map.new(1..1_000, &{&1, &1})
    filled_large = Map.new(1..10_000, &{&1, &1})
    left_small = Map.new(1..32, &{&1, &1})
    right_small = Map.new(16..48, &{&1, &1 * 2})
    left_mid = Map.new(1..1_000, &{&1, &1})
    right_mid = Map.new(500..1_500, &{&1, &1 * 2})
    left_large = Map.new(1..10_000, &{&1, &1})
    right_large = Map.new(5_000..15_000, &{&1, &1 * 2})
    pairs_mid = Enum.map(1..1_000, &{&1, &1 * 2})
    pairs_large = Enum.map(1..10_000, &{&1, &1 * 2})
    samples = Enum.map(1..2_000, &%{id: &1, n: &1 * 3, flag: true})

    [
      {"Map.put small", fn -> ArinsalDemo.Maps.put_n(32) end},
      {"Map.put 1k", fn -> ArinsalDemo.Maps.put_n(1_000) end},
      {"Map.put 10k", fn -> ArinsalDemo.Maps.put_n(10_000) end},
      {"Map.update small", fn -> ArinsalDemo.Maps.update_all(small, 32) end},
      {"Map.update 1k", fn -> ArinsalDemo.Maps.update_all(mid, 1_000) end},
      {"Map.update 10k", fn -> ArinsalDemo.Maps.update_all(large, 10_000) end},
      {"Map.get small", fn -> ArinsalDemo.Maps.get_sum(filled_small, 32) end},
      {"Map.get 1k", fn -> ArinsalDemo.Maps.get_sum(filled_mid, 1_000) end},
      {"Map.get 10k", fn -> ArinsalDemo.Maps.get_sum(filled_large, 10_000) end},
      {"Map.merge small", fn -> ArinsalDemo.Maps.merge_sig(left_small, right_small, 1, 48) end},
      {"Map.merge 1k", fn -> ArinsalDemo.Maps.merge_sig(left_mid, right_mid, 1, 1_500) end},
      {"Map.merge 10k", fn -> ArinsalDemo.Maps.merge_sig(left_large, right_large, 1, 15_000) end},
      {"Map.new 1k", fn -> ArinsalDemo.Maps.new_sig(pairs_mid) end},
      {"Map.new 10k", fn -> ArinsalDemo.Maps.new_sig(pairs_large) end},
      {"pattern match keys", fn -> ArinsalDemo.Maps.match_keys(samples) end},
      {"small map 16", fn -> ArinsalDemo.Maps.small_map() end},
      {"large map 1k", fn -> ArinsalDemo.Maps.large_map(1_000) end},
      {"large map 10k", fn -> ArinsalDemo.Maps.large_map(10_000) end},
      {"update loop 1k", fn -> ArinsalDemo.Maps.update_loop(1_000) end},
      {"protocol dispatch", fn -> ArinsalDemo.Maps.dispatch() end}
    ]
  end

  def jobs("lists") do
    ints = Enum.to_list(1..10_000)
    reversed = Enum.reverse(ints)
    strings = Enum.map(1..1_000, &("s" <> String.pad_leading(Integer.to_string(&1), 4, "0")))
    shuffled_strings = Enum.reverse(strings)
    nested = Enum.map(1..1_000, fn i -> [i, [i, [i]]] end)
    zipped = Enum.to_list(10_000..1//-1)

    [
      {"Enum.map", fn -> ArinsalDemo.Lists.map_sum(ints) end},
      {"Enum.filter", fn -> ArinsalDemo.Lists.filter_count(ints) end},
      {"Enum.reduce", fn -> ArinsalDemo.Lists.reduce_sum(ints) end},
      {":lists.foldl", fn -> ArinsalDemo.Lists.foldl_sum(ints) end},
      {"Enum.reverse", fn -> ArinsalDemo.Lists.reverse_sig(ints) end},
      {"Enum.sort ints", fn -> ArinsalDemo.Lists.sort_ints_sig(reversed) end},
      {"Enum.sort strings", fn -> ArinsalDemo.Lists.sort_strings_sig(shuffled_strings) end},
      {"++", fn -> ArinsalDemo.Lists.repeated_append(400) end},
      {"comprehension", fn -> ArinsalDemo.Lists.comprehension_sum(5_000) end},
      {"Enum.zip", fn -> ArinsalDemo.Lists.zip_sum(ints, zipped) end},
      {"List.flatten", fn -> ArinsalDemo.Lists.flatten_len(nested) end}
    ]
  end

  def jobs("text") do
    text = String.duplicate("Привіт, Elixir 123. ", 80)
    run_regex = ~r/Elixir/u
    replace_regex = ~r/\d+/u

    [
      {"String.split", fn -> ArinsalDemo.Text.split_count(text) end},
      {"String.upcase", fn -> ArinsalDemo.Text.upcase_sig(text) end},
      {"String.replace", fn -> ArinsalDemo.Text.replace_sig(text, "Elixir", "Arinsal") end},
      {"String.length unicode", fn -> ArinsalDemo.Text.unicode_length(text) end},
      {"Regex.run", fn -> ArinsalDemo.Text.regex_run(run_regex, text) end},
      {"Regex.replace", fn -> ArinsalDemo.Text.regex_replace_sig(replace_regex, text, "#") end},
      {"Unicode split and upcase", fn -> ArinsalDemo.Text.words_upcase() end},
      {"Unicode graphemes", fn -> ArinsalDemo.Text.graphemes() end},
      {"regex scan and replace", fn -> ArinsalDemo.Text.regex_work() end},
      {"iodata conversion", fn -> ArinsalDemo.Text.iodata() end},
      {"nested inspect", fn -> ArinsalDemo.Text.inspect_nested() end}
    ]
  end

  def jobs("binary") do
    payload = :binary.copy(<<1, 2, 3, 4, 5, 6, 7, 8>>, 512)
    csv = Enum.map_join(1..200, ",", &Integer.to_string/1)
    raw = :binary.copy("arinsal", 80)
    frame = <<5::32, "hello", "tail">>
    frames = <<5::32, "hello", 4::32, "beam">>

    [
      {"byte match", fn -> ArinsalDemo.Binary.sum_bytes(payload) end},
      {"<<>> construction", fn -> ArinsalDemo.Binary.build_bytes(400) end},
      {"iolist to binary", fn -> ArinsalDemo.Binary.iodata_bytes(400) end},
      {":binary.split", fn -> ArinsalDemo.Binary.split_count(csv, ",") end},
      {"Base.encode64", fn -> ArinsalDemo.Binary.encode64_sig(raw) end},
      {"parse one frame", fn -> ArinsalDemo.Binary.parse_frame(frame) end},
      {"parse frames", fn -> ArinsalDemo.Binary.parse_frames(frames) end},
      {"CSV line", fn -> ArinsalDemo.Binary.parse_csv("42,Ada Lovelace,admin") end},
      {"CRC 4KB", fn -> ArinsalDemo.Binary.crc(:binary.copy("arinsal", 585)) end}
    ]
  end

  def jobs("tuples") do
    tuple = {1, 2, 3, 4, 5, 6, 7, 8}

    [
      {"elem", fn -> ArinsalDemo.Tuples.elem_sum(tuple, 1_000) end},
      {"put_elem", fn -> ArinsalDemo.Tuples.put_elem_last(tuple, 1_000) end},
      {"struct update", fn -> ArinsalDemo.Tuples.update_point(1_000) end},
      {"record tuple", fn -> ArinsalDemo.Tuples.update_record(1_000) end}
    ]
  end

  def jobs("control") do
    values = Enum.to_list(1..10_000)
    mixed = Enum.flat_map(1..400, fn i -> [i, -i, i * 2, "id#{i}", :ok] end)

    [
      {"fib 25", fn -> ArinsalDemo.Pure.fib(25) end},
      {"tail sum 1M", fn -> ArinsalDemo.Pure.tail_sum(1_000_000) end},
      {"closures", fn -> ArinsalDemo.Pure.closure_sum(values, 3, 7) end},
      {"try/catch/throw", fn -> ArinsalDemo.Pure.catch_throw(2_000) end},
      {"case guards", fn -> ArinsalDemo.Pure.guard_score(mixed) end}
    ]
  end

  def jobs("processes") do
    {:ok, pid} = GenServer.start_link(ArinsalDemo.Work, :ok)

    [
      {"spawn DOWN", fn -> ArinsalDemo.Work.spawn_down() end},
      {"ping-pong 10k", fn -> ArinsalDemo.Work.message_ping_pong(10_000) end},
      {"Task.async_stream 1k", fn -> ArinsalDemo.Work.async_stream_sum(1_000) end},
      {"GenServer.call round trip", fn -> ArinsalDemo.Work.round_trip(pid) end}
    ]
  end

  def jobs("ets") do
    lookup = ArinsalDemo.Tables.new_filled(2_000)
    parity = ArinsalDemo.Tables.new_parity(2_000)
    counter = :ets.new(:arinsal_demo_counter, [:set, :public])

    [
      {"ETS insert", fn -> ArinsalDemo.Tables.insert_n(500) end},
      {"ETS lookup", fn -> ArinsalDemo.Tables.lookup_sum(lookup, 2_000) end},
      {"ETS update_counter", fn -> ArinsalDemo.Tables.counter_n(counter, 500) end},
      {"ETS select", fn -> ArinsalDemo.Tables.select_even_sum(parity) end}
    ]
  end

  def jobs("cache") do
    ArinsalDemo.Cache.put(:hot, %{value: 42})

    [
      {"ETS cache hit", fn -> ArinsalDemo.Cache.get(:hot) end},
      {"cache put", fn -> ArinsalDemo.Cache.put(:hot, %{value: 42}) end},
      {"cached fetch",
       fn -> ArinsalDemo.Cache.fetch_or_compute(:hot, fn -> %{value: 42} end) end},
      {"cache compute miss",
       fn -> ArinsalDemo.Cache.fetch_or_compute(make_ref(), fn -> Enum.sum(1..100) end) end}
    ]
  end

  def jobs("work") do
    [
      {"task fan-out 8", fn -> ArinsalDemo.Work.fan_out(1..8, &(&1 * &1)) end},
      {"task fan-out 64", fn -> ArinsalDemo.Work.fan_out(1..64, &(&1 * &1)) end},
      {"Registry pub-sub 4", fn -> ArinsalDemo.Work.publish(:bench_topic, :tick, 4) end},
      {"GenServer 100 calls", fn -> ArinsalDemo.Work.ping_pong(100) end},
      {"process fan-in 100", fn -> ArinsalDemo.Work.fan_in(Enum.to_list(1..100)) end}
    ]
  end

  def jobs("json") do
    document = ArinsalDemo.Json.medium_document()
    {:ok, encoded} = Jason.encode(document)

    [
      {"Jason encode", fn -> ArinsalDemo.Json.encode() end},
      {"Jason round trip", fn -> ArinsalDemo.Json.round_trip() end},
      {"Jason encode medium", fn -> ArinsalDemo.Json.encode_document(document) end},
      {"Jason decode medium", fn -> ArinsalDemo.Json.decode_sig(encoded) end}
    ]
  end
end
