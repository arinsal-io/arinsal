defmodule ArinsalDemo.BenchSupport do
  @moduledoc false

  @doc "Checks scenario return values and/or benchmarks each suite."
  def execute(suites, mode \\ nil) do
    mode = mode || System.get_env("BENCH_MODE", "run")
    prepared = prepare(suites)

    if mode in ["check", "check_and_run"] do
      run_check!(prepared)
    end

    if mode in ["run", "check_and_run"] do
      Enum.each(prepared, fn {suite, jobs} -> benchmark(suite, jobs) end)
    end

    :ok
  end

  defp prepare(suites) do
    Enum.map(suites, fn suite ->
      jobs = ArinsalDemo.BenchJobs.jobs(suite)
      assert_unique!(suite, jobs)
      {suite, jobs}
    end)
  end

  defp assert_unique!(suite, jobs) do
    names = Enum.map(jobs, &elem(&1, 0))

    if length(names) != length(Enum.uniq(names)) do
      raise "duplicate scenario names in #{suite}"
    end
  end

  defp run_check!(prepared) do
    path = check_path()
    File.mkdir_p!(Path.dirname(path))
    File.write!(path, "")
    runtime = runtime()
    total = Enum.reduce(prepared, 0, fn {_suite, jobs}, acc -> acc + length(jobs) end)
    IO.puts("checking #{total} scenarios on #{runtime}")

    Enum.each(prepared, fn {suite, jobs} ->
      IO.puts("check #{suite}")

      lines =
        Enum.map(jobs, fn {name, fun} ->
          value = fun.()
          [suite, "\t", name, "\t", format_result(value), "\n"]
        end)

      File.write!(path, lines, [:append])
    end)

    verify_expect!(path)
  end

  # Map key order is not part of the value. Sort keys so the check does not
  # depend on either runtime's internal map representation.
  defp format_result(value), do: IO.iodata_to_binary(canonical(value))

  defp canonical(%_{} = struct) do
    ["%", inspect(struct.__struct__), "{", canonical_pairs(Map.from_struct(struct)), "}"]
  end

  defp canonical(map) when is_map(map) do
    ["%{", canonical_pairs(map), "}"]
  end

  defp canonical(list) when is_list(list) do
    ["[", Enum.map_intersperse(list, ", ", &canonical/1), "]"]
  end

  defp canonical(tuple) when is_tuple(tuple) do
    ["{", tuple |> Tuple.to_list() |> Enum.map_intersperse(", ", &canonical/1), "}"]
  end

  defp canonical(binary) when is_binary(binary), do: inspect(binary)
  defp canonical(atom) when is_atom(atom), do: inspect(atom)
  defp canonical(integer) when is_integer(integer), do: Integer.to_string(integer)

  defp canonical(float) when is_float(float) do
    :erlang.float_to_binary(float, [:compact, {:decimals, 17}])
  end

  defp canonical(other) do
    inspect(other, limit: :infinity, printable_limit: :infinity, charlists: :as_lists)
  end

  defp canonical_pairs(map) do
    map
    |> Map.to_list()
    |> Enum.sort()
    |> Enum.map_intersperse(", ", fn {key, value} ->
      [canonical(key), " => ", canonical(value)]
    end)
  end

  defp verify_expect!(actual_path) do
    case System.get_env("BENCH_EXPECT") do
      nil ->
        :ok

      "" ->
        :ok

      expect ->
        actual = actual_path |> File.read!() |> String.trim_trailing()
        expected = expect |> File.read!() |> String.trim_trailing()

        if actual != expected do
          IO.puts(:stderr, "scenario results differ between runtimes:")
          print_mismatch!(expected, actual)
          System.halt(1)
        end

        count = actual |> String.split("\n", trim: true) |> length()
        IO.puts("scenario results match across runtimes (#{count} jobs)")
    end
  end

  defp print_mismatch!(expected, actual) do
    exp = String.split(expected, "\n")
    act = String.split(actual, "\n")
    shown = 0

    Enum.reduce(0..(max(length(exp), length(act)) - 1), shown, fn index, shown ->
      left = Enum.at(exp, index)
      right = Enum.at(act, index)

      if left != right and shown < 20 do
        IO.puts(:stderr, "expected: #{left}")
        IO.puts(:stderr, "actual:   #{right}")
        shown + 1
      else
        shown
      end
    end)
    |> then(fn shown ->
      total =
        Enum.count(0..(max(length(exp), length(act)) - 1), fn index ->
          Enum.at(exp, index) != Enum.at(act, index)
        end)

      if total > shown do
        IO.puts(:stderr, "... #{total - shown} more mismatched scenarios")
      end
    end)
  end

  defp benchmark(suite, jobs) do
    runtime = runtime()
    quick? = System.get_env("BENCH_QUICK") == "1"
    cold? = runtime == "arinsal_cold"
    File.mkdir_p!("bench/out")
    IO.puts("bench #{suite} (#{runtime})")

    # Cold runs count the first iterations. Warm-up 0 skips Benchee's untimed loop
    # so JIT tiers for these jobs are not reached before measurement.
    warmup =
      cond do
        cold? -> 0
        quick? -> 0.05
        true -> 0.5
      end

    options = [
      time: if(quick?, do: 0.15, else: 1.0),
      warmup: warmup,
      memory_time: if(quick?, do: 0.05, else: 0.2),
      reduction_time: if(quick?, do: 0.05, else: 0.2),
      save: [path: "bench/out/#{suite}-#{runtime}.benchee", tag: runtime],
      formatters: [
        Benchee.Formatters.Console,
        {Benchee.Formatters.JSON, file: "bench/out/#{suite}-#{runtime}.json"}
      ]
    ]

    options =
      case System.get_env("COMPARE_WITH") do
        nil -> options
        "" -> options
        path -> Keyword.put(options, :load, path)
      end

    Benchee.run(Map.new(jobs), options)
  end

  defp runtime, do: System.get_env("RUNTIME", "erts")

  defp check_path do
    System.get_env("BENCH_CHECK_OUT") || "bench/out/check-#{runtime()}.txt"
  end
end
