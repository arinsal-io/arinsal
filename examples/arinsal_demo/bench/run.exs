Code.require_file("jobs.exs", __DIR__)
Code.require_file("support.exs", __DIR__)

suite = System.get_env("SUITE", "all")
known = ArinsalDemo.BenchJobs.suites()

selected =
  if suite in [nil, "", "all"] do
    known
  else
    if suite not in known do
      IO.puts(:stderr, "unknown suite: #{suite}")
      IO.puts(:stderr, "known suites: #{Enum.join(known, " ")}")
      System.halt(2)
    end

    [suite]
  end

runtime = System.get_env("RUNTIME", "erts")
quick? = System.get_env("BENCH_QUICK") == "1"
warmup = if(runtime == "arinsal_cold", do: 0, else: if(quick?, do: 0.05, else: 0.5))

# Benchee's warm-up is time-based, so a slow runtime gets few calls and its
# JIT may never tier up. Warm runs first call every job a fixed number of
# times (bounded by a time budget per job), identically on every runtime.
warm_calls = if(runtime == "arinsal_cold", do: 0, else: String.to_integer(System.get_env("WARM_CALLS", "2000")))
warm_budget_ms = String.to_integer(System.get_env("WARM_BUDGET_MS", "5000"))

configuration = [
  runtime: runtime,
  mix_env: System.get_env("MIX_ENV", "dev"),
  otp: :erlang.system_info(:otp_release) |> List.to_string(),
  elixir: System.version(),
  schedulers: :erlang.system_info(:schedulers),
  schedulers_online: :erlang.system_info(:schedulers_online),
  dirty_cpu_schedulers: :erlang.system_info(:dirty_cpu_schedulers),
  dirty_cpu_schedulers_online: :erlang.system_info(:dirty_cpu_schedulers_online),
  dirty_io_schedulers: :erlang.system_info(:dirty_io_schedulers),
  jit:
    if(runtime == "erts",
      do: if(:erlang.system_info(:emu_flavor) == :jit, do: "on", else: "off"),
      else: if(System.get_env("ARINSAL_JIT", "1") == "0", do: "off", else: "on")
    ),
  erl_aflags: System.get_env("ERL_AFLAGS", ""),
  erl_flags: System.get_env("ERL_FLAGS", ""),
  erl_zflags: System.get_env("ERL_ZFLAGS", ""),
  benchee_time: if(quick?, do: 0.15, else: 1.0),
  benchee_warmup: warmup,
  warm_calls: warm_calls,
  warm_budget_ms: warm_budget_ms,
  benchee_memory_time: if(quick?, do: 0.05, else: 0.2),
  benchee_reduction_time: if(quick?, do: 0.05, else: 0.2)
]

reference_file = "bench/out/config-erts.txt"

if runtime != "erts" and File.exists?(reference_file) do
  reference =
    reference_file
    |> File.read!()
    |> String.split("\n", trim: true)
    |> Map.new(fn line ->
      [key, value] = String.split(line, "=", parts: 2)
      {key, value}
    end)

  shared =
    [:mix_env, :otp, :elixir, :schedulers, :schedulers_online,
     :dirty_cpu_schedulers, :dirty_cpu_schedulers_online, :dirty_io_schedulers,
     :erl_aflags, :erl_flags, :erl_zflags, :benchee_time,
     :benchee_memory_time, :benchee_reduction_time]

  shared =
    if(runtime == "arinsal_cold",
      do: shared,
      else: [:benchee_warmup, :warm_calls, :warm_budget_ms | shared]
    )

  Enum.each(shared, fn key ->
    observed = configuration |> Keyword.fetch!(key) |> to_string()
    expected = Map.fetch!(reference, to_string(key))

    if observed != expected do
      raise "configuration mismatch #{key}: erts=#{expected}, #{runtime}=#{observed}"
    end
  end)
end

File.mkdir_p!("bench/out")
File.write!("bench/out/config-#{runtime}.txt", Enum.map(configuration, fn {key, value} ->
  "#{key}=#{value}\n"
end))
IO.puts("configuration #{runtime}: " <> Enum.map_join(configuration, ", ", fn {key, value} -> "#{key}=#{value}" end))

if warm_calls > 0 and System.get_env("BENCH_MODE", "run") in ["run", "check_and_run"] do
  Enum.each(selected, fn suite ->
    Enum.each(ArinsalDemo.BenchJobs.jobs(suite), fn {_name, job} ->
      deadline = System.monotonic_time(:millisecond) + warm_budget_ms

      Enum.reduce_while(1..warm_calls, nil, fn _, _ ->
        job.()
        if System.monotonic_time(:millisecond) < deadline, do: {:cont, nil}, else: {:halt, nil}
      end)
    end)
  end)
end

ArinsalDemo.BenchSupport.execute(selected)
