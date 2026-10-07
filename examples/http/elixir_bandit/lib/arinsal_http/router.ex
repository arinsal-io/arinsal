defmodule ArinsalHttp.Router do
  use Plug.Router

  plug Plug.Parsers, parsers: [:json], json_decoder: Jason
  plug :match
  plug :dispatch

  get "/plaintext" do
    conn |> put_resp_header("content-type", "text/plain") |> send_resp(200, "Hello, World!")
  end

  get "/json" do
    conn |> put_resp_header("content-type", "application/json") |> send_resp(200, ~s({"message":"Hello, World!"}))
  end

  get "/work" do
    n = case Integer.parse(conn.query_params["n"] || "20") do
      {value, ""} when value >= 0 -> min(value, 1000)
      _ -> 20
    end
    items = for i <- indices(n), do: %{id: i, name: "item-#{i}", score: if(rem(i, 2) == 0, do: div(i * 3, 2), else: i * 1.5)}
    body = ~s({"n":#{n},"fib":#{fib(n)},"items":[#{Enum.map_join(items, ",", &Jason.encode!/1)}]})
    conn |> put_resp_header("content-type", "application/json") |> send_resp(200, body)
  end

  post "/echo" do
    body = Jason.encode!(conn.body_params)
    conn |> put_resp_header("content-type", "application/json") |> send_resp(200, body)
  end

  match _ do
    send_resp(conn, 404, "not found")
  end

  defp fib(n), do: fib(n, 0, 1)
  defp fib(0, a, _b), do: a
  defp fib(n, a, b), do: fib(n - 1, b, a + b)
  defp indices(0), do: []
  defp indices(n), do: 0..(n - 1)
end
