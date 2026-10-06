defmodule ArinsalDemo.Binary do
  @moduledoc "Binary framing, CSV parsing, and CRC workloads."

  @doc "Parses a 32-bit big-endian length-prefixed frame."
  @spec parse_frame(binary()) :: {:ok, binary(), binary()} | {:error, :incomplete}
  def parse_frame(<<length::unsigned-big-32, body::binary-size(length), rest::binary>>),
    do: {:ok, body, rest}

  def parse_frame(_), do: {:error, :incomplete}

  @doc "Parses a CSV line with three unquoted fields."
  @spec parse_csv(binary()) :: {:ok, {binary(), binary(), binary()}} | {:error, :invalid}
  def parse_csv(line), do: split_csv(line, [], <<>>)

  defp split_csv(<<>>, fields, current) do
    case Enum.reverse([current | fields]) do
      [first, second, third] -> {:ok, {first, second, third}}
      _ -> {:error, :invalid}
    end
  end

  defp split_csv(<<?,, rest::binary>>, fields, current),
    do: split_csv(rest, [current | fields], <<>>)

  defp split_csv(<<byte, rest::binary>>, fields, current),
    do: split_csv(rest, fields, <<current::binary, byte>>)

  @doc "Computes the OTP CRC-32 checksum of a binary."
  @spec crc(binary()) :: non_neg_integer()
  def crc(binary), do: :erlang.crc32(binary)

  @doc "Parses a sequence of length-prefixed frames."
  @spec parse_frames(binary()) :: {:ok, [binary()]} | {:error, :incomplete}
  def parse_frames(<<>>), do: {:ok, []}

  def parse_frames(binary) do
    with {:ok, body, rest} <- parse_frame(binary),
         {:ok, bodies} <- parse_frames(rest) do
      {:ok, [body | bodies]}
    end
  end

  @doc "Sums bytes by matching one byte at a time."
  @spec sum_bytes(binary()) :: non_neg_integer()
  def sum_bytes(binary), do: sum_bytes(binary, 0)

  @doc "Appends n bytes with the binary construction syntax."
  @spec build_bytes(pos_integer()) :: ArinsalDemo.Sig.t()
  def build_bytes(n) when n > 0 do
    Enum.reduce(1..n, <<>>, fn i, acc -> <<acc::binary, rem(i, 256)::8>> end)
    |> ArinsalDemo.Sig.bin()
  end

  @doc "Builds an iolist and converts it with IO.iodata_to_binary/1."
  @spec iodata_bytes(pos_integer()) :: ArinsalDemo.Sig.t()
  def iodata_bytes(n) when n > 0 do
    parts = for i <- 1..n, do: [Integer.to_string(rem(i, 100)), ","]
    parts |> IO.iodata_to_binary() |> ArinsalDemo.Sig.bin()
  end

  @doc "Splits a binary on a separator and returns the part count."
  @spec split_count(binary(), binary()) :: non_neg_integer()
  def split_count(binary, separator), do: length(:binary.split(binary, separator, [:global]))

  @doc "Base64-encodes a binary and returns a signature of the result."
  @spec encode64_sig(binary()) :: ArinsalDemo.Sig.t()
  def encode64_sig(binary), do: binary |> Base.encode64() |> ArinsalDemo.Sig.bin()

  defp sum_bytes(<<>>, acc), do: acc
  defp sum_bytes(<<byte, rest::binary>>, acc), do: sum_bytes(rest, acc + byte)
end
