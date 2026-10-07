# Compile pf_call.erl with OTP 29 erlc into tmp/pf_data before running.
Code.prepend_path("../../tmp/pf_data")
n = System.get_env("PF_N", "100000") |> String.to_integer()

for function <- [:plain, :local, :bif], _ <- 1..3 do
  start = System.monotonic_time()
  result = apply(:pf_call, function, [n])
  elapsed = System.monotonic_time() - start
  IO.inspect({function, n, elapsed, elapsed / n, result})
end
