defmodule ArinsalCloud.EunitTest do
  use ExUnit.Case, async: false

  @moduletag timeout: 600_000

  @stock_path "/opt/homebrew/opt/erlang@29/bin:/opt/homebrew/opt/elixir/bin:/usr/bin:/bin"

  test "eunit suites" do
    for dir <- Path.wildcard(Path.join(:code.root_dir(), "lib/eunit-*/ebin")) do
      :code.add_pathz(String.to_charlist(dir))
    end

    System.put_env("ARINSAL_CLOUD_REST_RELEASE", rest_release())

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

  # A real `mix release` of poc/multitenancy/bench/rest, built once with stock OTP (compiling its
  # deps fails on Arinsal) and cached under _build. Delete _build/rest_release to rebuild.
  defp rest_release do
    case System.get_env("ARINSAL_CLOUD_REST_RELEASE") do
      nil -> build_rest_release()
      dir -> dir
    end
  end

  defp build_rest_release do
    base = Path.expand("../_build", __DIR__)
    dest = Path.join(base, "rest_release")

    unless File.dir?(Path.join(dest, "releases")) do
      src = Path.join(base, "rest_src")
      File.rm_rf!(src)
      File.mkdir_p!(base)
      # File.cp_r!/2 fails on Arinsal (NOTES-cloud.md, "Arinsal gaps")
      {_, 0} = System.cmd("cp", ["-R", Path.expand("../../../poc/multitenancy/bench/rest", __DIR__), src])
      File.rm_rf!(Path.join(src, "_build"))
      File.rm_rf!(Path.join(src, "deps"))
      arinsal = Path.expand("../../arinsal", __DIR__)
      mix_exs = Path.join(src, "mix.exs")
      File.write!(mix_exs, String.replace(File.read!(mix_exs), "../../../../packages/arinsal", arinsal))

      env = [
        {"PATH", System.get_env("STOCK_PATH", @stock_path)},
        {"ERL_ROOTDIR", nil},
        {"MIX_ENV", nil},
        {"MIX_BUILD_PATH", nil}
      ]

      {out, status} =
        System.cmd("sh", ["-c", "mix deps.get && MIX_ENV=prod mix release --overwrite --path \"$1\"", "_", dest],
          cd: src,
          env: env,
          stderr_to_stdout: true
        )

      if status != 0, do: flunk("building the bench/rest release failed:\n" <> out)
    end

    dest
  end
end
