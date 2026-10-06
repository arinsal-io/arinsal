defmodule ArinsalDemo.JsonTest do
  use ExUnit.Case, async: true

  test "nested JSON encodes and decodes to the same document" do
    assert {:ok, encoded} = ArinsalDemo.Json.encode()
    assert {:ok, decoded} = Jason.decode(encoded)
    assert decoded == ArinsalDemo.Json.document()
    assert ArinsalDemo.Json.round_trip() == {:ok, ArinsalDemo.Json.document()}
  end
end
