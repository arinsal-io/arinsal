defmodule ArinsalDemo.Json do
  @moduledoc "JSON encode/decode work over a representative nested document."

  @doc "Returns a nested document with user, event, and metric data."
  @spec document() :: map()
  def document do
    %{
      "request_id" => "req-2026-09-25-001",
      "user" => %{"id" => 42, "name" => "Ada Lovelace", "roles" => ["admin", "reviewer"]},
      "events" => [
        %{"type" => "login", "ok" => true, "at" => "2026-09-25T12:30:00Z"},
        %{"type" => "render", "ok" => true, "duration_ms" => 18}
      ],
      "metrics" => %{"count" => 2, "ratio" => 0.875, "tags" => ["elixir", "beam", "🌍"]}
    }
  end

  @doc "Encodes the representative document to JSON."
  @spec encode() :: {:ok, binary()} | {:error, Jason.EncodeError.t()}
  def encode, do: Jason.encode(document())

  @doc "Encodes and decodes the representative document."
  @spec round_trip() :: {:ok, map()} | {:error, term()}
  def round_trip do
    with {:ok, encoded} <- encode(), do: Jason.decode(encoded)
  end

  @doc "Returns a medium nested document of users and events."
  @spec medium_document() :: map()
  def medium_document do
    %{
      "id" => "doc-100",
      "users" =>
        Enum.map(1..50, fn i ->
          %{
            "id" => i,
            "name" => "User #{i}",
            "roles" => ["reader", "editor"],
            "active" => rem(i, 2) == 0
          }
        end),
      "events" =>
        Enum.map(1..100, fn i ->
          %{"type" => "render", "ok" => true, "n" => i, "tag" => "elixir"}
        end)
    }
  end

  @doc "Encodes a caller-supplied document."
  @spec encode_document(map()) :: {:ok, binary()} | {:error, Jason.EncodeError.t()}
  def encode_document(document), do: Jason.encode(document)

  @doc "Decodes a medium document and returns a compact signature."
  @spec decode_sig(binary()) ::
          {String.t(), non_neg_integer(), non_neg_integer(), integer(), integer()}
          | {:error, term()}
  def decode_sig(encoded) do
    case Jason.decode(encoded) do
      {:ok, map} ->
        users = map["users"]
        events = map["events"]
        {map["id"], length(users), length(events), hd(users)["id"], List.last(events)["n"]}

      {:error, _} = error ->
        error
    end
  end
end
