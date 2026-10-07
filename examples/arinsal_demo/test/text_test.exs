defmodule ArinsalDemo.TextTest do
  use ExUnit.Case, async: true

  test "Unicode, regex, iodata, and inspect operations" do
    assert ArinsalDemo.Text.words_upcase() == [
             "ПРИВІТ,",
             "СВІТЕ!",
             "👋🌍",
             "ELIXIR",
             "ОБРОБЛЯЄ",
             "ТЕКСТ.",
             "ПОВТОР:",
             "ПРИВІТ!"
           ]

    assert length(ArinsalDemo.Text.graphemes()) == 56
    {matches, replaced} = ArinsalDemo.Text.regex_work()
    assert matches == [["Привіт"], ["Elixir"], ["Привіт"]]
    assert replaced == "Привіт, світе! 👋🌍 Elixir обробляє текст. Повтор: [omitted]"
    assert ArinsalDemo.Text.iodata() == "Привіт, 🌍!\n"

    assert ArinsalDemo.Text.inspect_nested() ==
             "%{active: true, user: %{name: \"Ada\", tags: [:vm, :elixir]}}"
  end
end
