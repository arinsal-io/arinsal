# elixir loadgen.exs host|nodes PORT TENANTS CONNS SECONDS
[mode, port, tenants, conns, secs] = System.argv()
[port, tenants, conns, secs] = Enum.map([port, tenants, conns, secs], &String.to_integer/1)
deadline = System.monotonic_time(:millisecond) + secs * 1000

target = fn ->
  t = :rand.uniform(tenants)
  item = :rand.uniform(200)
  case mode do
    "host" -> {port, "/t/#{t}/items/#{item}"}
    "nodes" -> {port + t - 1, "/t/1/items/#{item}"}
  end
end

request = fn sock, path ->
  :ok = :gen_tcp.send(sock, ["GET ", path, " HTTP/1.1\r\nhost: x\r\n\r\n"])
  {:ok, {:http_response, _, 200, _}} = :gen_tcp.recv(sock, 0)
  len = Stream.repeatedly(fn -> :gen_tcp.recv(sock, 0) end)
        |> Enum.reduce_while(0, fn
          {:ok, {:http_header, _, :"Content-Length", _, v}}, _ -> {:cont, String.to_integer(v)}
          {:ok, {:http_header, _, _, _, _}}, acc -> {:cont, acc}
          {:ok, :http_eoh}, acc -> {:halt, acc}
        end)
  :ok = :inet.setopts(sock, packet: :raw)
  {:ok, _} = :gen_tcp.recv(sock, len)
  :ok = :inet.setopts(sock, packet: :http_bin)
end

worker = fn ->
  loop = fn loop, socks, lats ->
    if System.monotonic_time(:millisecond) >= deadline do
      lats
    else
      {p, path} = target.()
      {sock, socks} =
        case socks do
          %{^p => s} -> {s, socks}
          _ ->
            {:ok, s} = :gen_tcp.connect({127, 0, 0, 1}, p, [:binary, packet: :http_bin, active: false, nodelay: true])
            {s, Map.put(socks, p, s)}
        end
      t0 = System.monotonic_time(:microsecond)
      request.(sock, path)
      loop.(loop, socks, [System.monotonic_time(:microsecond) - t0 | lats])
    end
  end
  loop.(loop, %{}, [])
end

lats = 1..conns |> Enum.map(fn _ -> Task.async(worker) end) |> Enum.flat_map(&Task.await(&1, :infinity)) |> Enum.sort() |> List.to_tuple()
n = tuple_size(lats)
pct = fn p -> elem(lats, min(n - 1, trunc(n * p))) end
IO.puts(JSON.encode!(%{rps: div(n, secs), p50_us: pct.(0.5), p99_us: pct.(0.99), p999_us: pct.(0.999), requests: n}))
