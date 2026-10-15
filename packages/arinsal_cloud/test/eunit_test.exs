defmodule ArinsalCloud.EunitTest do
  use ExUnit.Case, async: false

  @moduletag timeout: 300_000

  test "eunit suites" do
    for dir <- Path.wildcard(Path.join(:code.root_dir(), "lib/eunit-*/ebin")) do
      :code.add_pathz(String.to_charlist(dir))
    end

    out = Path.join(System.tmp_dir!(), "arinsal_cloud_eunit_beams")
    File.rm_rf!(out)
    File.mkdir_p!(out)

    modules =
      for file <- Path.wildcard(Path.join(__DIR__, "*.erl")) do
        {:ok, mod} =
          :compile.file(String.to_charlist(file), [:return_errors, :debug_info, outdir: String.to_charlist(out)])

        mod
      end

    true = :code.add_patha(String.to_charlist(out))
    suites = for m <- modules, String.ends_with?(Atom.to_string(m), "_tests"), do: m
    assert :ok = apply(:eunit, :test, [suites, []])
  end
end
