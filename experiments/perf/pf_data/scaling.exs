# Run with MIX_ENV=bench mix run -e 'Code.require_file("../../experiments/perf/pf_data/scaling.exs")'
case_name = System.fetch_env!("PF_CASE")

sizes =
  case case_name do
    "encode64" -> [128, 512, 2_048, 8_192]
    "record" -> [100, 1_000, 10_000]
    "map_get" -> [100, 1_000, 10_000]
    "unicode_length" -> [20, 80, 320]
  end

for size <- sizes do
  operation =
    case case_name do
      "encode64" ->
        bytes = :binary.copy("abcdefgh", div(size, 8))
        fn -> ArinsalDemo.Binary.encode64_sig(bytes) end

      "record" ->
        fn -> ArinsalDemo.Tuples.update_record(size) end

      "map_get" ->
        map = Map.new(1..size, &{&1, &1})
        fn -> ArinsalDemo.Maps.get_sum(map, size) end

      "unicode_length" ->
        bytes = String.duplicate("Привіт, Elixir 123. ", size)
        fn -> ArinsalDemo.Text.unicode_length(bytes) end
    end

  operation.()

  values =
    for _ <- 1..3 do
      start = System.monotonic_time()
      result = operation.()
      {System.monotonic_time() - start, result}
    end

  IO.inspect({case_name, size, values}, limit: :infinity)
end
