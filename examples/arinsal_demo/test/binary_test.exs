defmodule ArinsalDemo.BinaryTest do
  use ExUnit.Case, async: true

  test "frame, CSV, and checksum operations" do
    assert ArinsalDemo.Binary.parse_frame(<<5::32, "hello", "tail">>) == {:ok, "hello", "tail"}
    assert ArinsalDemo.Binary.parse_frame(<<0, 0>>) == {:error, :incomplete}

    assert ArinsalDemo.Binary.parse_frames(<<5::32, "hello", 4::32, "beam">>) ==
             {:ok, ["hello", "beam"]}

    assert ArinsalDemo.Binary.parse_frames(<<>>) == {:ok, []}

    assert ArinsalDemo.Binary.parse_csv("42,Ada Lovelace,admin") ==
             {:ok, {"42", "Ada Lovelace", "admin"}}

    assert ArinsalDemo.Binary.parse_csv("bad,line") == {:error, :invalid}
    assert ArinsalDemo.Binary.crc("123456789") == 3_421_780_262
  end
end
