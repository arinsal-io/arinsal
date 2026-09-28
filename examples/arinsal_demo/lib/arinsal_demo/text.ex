defmodule ArinsalDemo.Text do
  @moduledoc "Unicode string, regex, iodata, and term formatting workloads."
  @text "Привіт, світе! 👋🌍 Elixir обробляє текст. Повтор: Привіт!"

  @doc "Splits Unicode text into words and uppercases each word."
  @spec words_upcase() :: [String.t()]
  def words_upcase, do: @text |> String.split() |> Enum.map(&String.upcase/1)

  @doc "Returns Unicode grapheme clusters from the sample text."
  @spec graphemes() :: [String.t()]
  def graphemes, do: String.graphemes(@text)

  @doc "Scans and replaces repeated words with a normalized marker."
  @spec regex_work() :: {[[String.t()]], String.t()}
  def regex_work do
    matches = Regex.scan(~r/Привіт|Elixir/u, @text)
    replaced = Regex.replace(~r/Повтор:.*$/u, @text, "Повтор: [omitted]")
    {matches, replaced}
  end

  @doc "Converts nested iodata to one UTF-8 binary."
  @spec iodata() :: binary()
  def iodata, do: IO.iodata_to_binary(["Привіт", [", ", ["🌍", "!"], 10]])

  @doc "Inspects a nested map with stable map ordering."
  @spec inspect_nested() :: String.t()
  def inspect_nested,
    do:
      inspect(%{user: %{name: "Ada", tags: [:vm, :elixir]}, active: true},
        pretty: true,
        sort_maps: true
      )

  @doc "Counts pieces from String.split/2."
  @spec split_count(String.t()) :: non_neg_integer()
  def split_count(text), do: text |> String.split(" ") |> length()

  @doc "Uppercases text and returns a signature of the binary."
  @spec upcase_sig(String.t()) :: ArinsalDemo.Sig.t()
  def upcase_sig(text), do: text |> String.upcase() |> ArinsalDemo.Sig.bin()

  @doc "Replaces a substring and returns a signature of the binary."
  @spec replace_sig(String.t(), String.t(), String.t()) :: ArinsalDemo.Sig.t()
  def replace_sig(text, pattern, replacement) do
    text |> String.replace(pattern, replacement) |> ArinsalDemo.Sig.bin()
  end

  @doc "Returns String.length/1, counting Unicode graphemes."
  @spec unicode_length(String.t()) :: non_neg_integer()
  def unicode_length(text), do: String.length(text)

  @doc "Runs a regex and returns the match."
  @spec regex_run(Regex.t(), String.t()) :: [String.t()] | nil
  def regex_run(regex, text), do: Regex.run(regex, text)

  @doc "Replaces regex matches and returns a signature of the binary."
  @spec regex_replace_sig(Regex.t(), String.t(), String.t()) :: ArinsalDemo.Sig.t()
  def regex_replace_sig(regex, text, replacement) do
    regex |> Regex.replace(text, replacement) |> ArinsalDemo.Sig.bin()
  end
end
