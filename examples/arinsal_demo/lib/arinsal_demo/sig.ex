defmodule ArinsalDemo.Sig do
  @moduledoc false

  @typedoc "Size plus the first, middle, and last byte."
  @type t :: {non_neg_integer(), byte(), byte(), byte()}

  @doc "Samples a binary so its bytes are part of the returned value."
  @spec bin(binary()) :: t()
  def bin(binary) when is_binary(binary) do
    size = byte_size(binary)

    if size == 0 do
      {0, 0, 0, 0}
    else
      {size, :binary.at(binary, 0), :binary.at(binary, div(size, 2)),
       :binary.at(binary, size - 1)}
    end
  end
end
