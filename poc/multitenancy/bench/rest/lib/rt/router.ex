defmodule RT.Router do
  @moduledoc false
  use Plug.Router

  plug :match
  plug Plug.Parsers, parsers: [:json], json_decoder: Jason
  plug :dispatch

  get "/health", do: send_resp(conn, 200, "ok")

  get "/items" do
    items = :ets.select(conn.private.rt.tab, [{{:_, :"$1"}, [], [:"$1"]}], 20)
    json(conn, 200, case items do
      {list, _} -> list
      :"$end_of_table" -> []
    end)
  end

  get "/items/:id" do
    case :ets.lookup(conn.private.rt.tab, String.to_integer(id)) do
      [{_, item}] -> json(conn, 200, item)
      [] -> json(conn, 404, %{"error" => "not_found"})
    end
  end

  post "/items" do
    id = :ets.info(conn.private.rt.tab, :size) + 1
    item = Map.put(conn.body_params, "id", id)
    :ets.insert(conn.private.rt.tab, {id, item})
    json(conn, 201, item)
  end

  match _, do: json(conn, 404, %{"error" => "not_found"})

  defp json(conn, status, body) do
    conn |> put_resp_content_type("application/json") |> send_resp(status, Jason.encode_to_iodata!(body))
  end
end
