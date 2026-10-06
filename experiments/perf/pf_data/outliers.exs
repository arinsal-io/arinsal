# Run with MIX_ENV=bench mix run -e 'Code.require_file("../../experiments/perf/pf_data/outliers.exs")'
# PF_CASE selects one kernel and PF_REPS controls repeated measurements.
case_name = System.fetch_env!("PF_CASE")
reps = System.get_env("PF_REPS", "3") |> String.to_integer()

{operation, divisor} =
  case case_name do
    "ets" ->
      table = ArinsalDemo.Tables.new_filled(2_000)
      {fn -> ArinsalDemo.Tables.lookup_sum(table, 2_000) end, 2_000}

    "reverse" ->
      values = Enum.to_list(1..10_000)
      {fn -> ArinsalDemo.Lists.reverse_sig(values) end, 10_000}

    "encode64" ->
      bytes = :binary.copy("arinsal", 80)
      {fn -> ArinsalDemo.Binary.encode64_sig(bytes) end, byte_size(bytes)}

    "record" ->
      {fn -> ArinsalDemo.Tuples.update_record(1_000) end, 1_000}

    "map_get" ->
      values = Map.new(1..10_000, &{&1, &1})
      {fn -> ArinsalDemo.Maps.get_sum(values, 10_000) end, 10_000}

    "map_put" ->
      {fn -> ArinsalDemo.Maps.put_n(1_000) end, 1_000}

    "binary_split" ->
      csv = Enum.map_join(1..200, ",", &Integer.to_string/1)
      {fn -> ArinsalDemo.Binary.split_count(csv, ",") end, 199}

    "lists_foldl" ->
      values = Enum.to_list(1..10_000)
      {fn -> ArinsalDemo.Lists.foldl_sum(values) end, 10_000}

    "unicode_length" ->
      bytes = String.duplicate("Привіт, Elixir 123. ", 80)
      {fn -> ArinsalDemo.Text.unicode_length(bytes) end, byte_size(bytes)}

    "ascii_length" ->
      bytes = String.duplicate("a", 2_080)
      {fn -> ArinsalDemo.Text.unicode_length(bytes) end, byte_size(bytes)}
  end

Enum.each(1..reps, fn _ ->
  start = System.monotonic_time()
  result = operation.()
  elapsed = System.monotonic_time() - start
  IO.inspect({case_name, result, elapsed, elapsed / divisor}, limit: 8)
end)
