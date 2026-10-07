defmodule Arinsal.Mix do
  @moduledoc """
  Helpers for running a Mix command with the Arinsal runtime.

  This package is currently intended to be used as a path dependency from the
  Arinsal monorepo. Its Mix task builds the runtime from the repository root.
  """

  @doc false
  def repo_root do
    package_path = Mix.Project.deps_paths() |> Map.fetch!(:arinsal)
    Path.expand("../..", package_path)
  end

  @doc false
  def profile do
    case System.get_env("ARINSAL_PROFILE", "release") do
      "debug" -> {"debug", []}
      "release" -> {"release", ["--release"]}
      other -> Mix.raise("ARINSAL_PROFILE must be debug or release, got: #{other}")
    end
  end

  @doc false
  def build_runtime! do
    root = repo_root()
    {profile, cargo_flags} = profile()
    cargo = System.find_executable("cargo") || Mix.raise("cargo was not found on PATH")

    Mix.shell().info("Building Arinsal (Cargo profile: #{profile})")

    case System.cmd(cargo, ["build" | cargo_flags] ++ ["-p", "arinsal-cli"],
           cd: root,
           into: IO.stream(:stdio, :line),
           stderr_to_stdout: true
         ) do
      {_, 0} ->
        install_erl_shim!(root, profile)

      {_, status} ->
        Mix.raise("Cargo failed to build Arinsal (exit status #{status})")
    end
  end

  defp install_erl_shim!(root, profile) do
    arinsal = Path.join([root, "target", profile, "arinsal"])
    shim_dir = Path.join([root, "target", profile, "arinsal-erl-shim"])
    erl = Path.join(shim_dir, "erl")

    unless File.regular?(arinsal) do
      Mix.raise("Arinsal binary was not produced at #{arinsal}")
    end

    File.mkdir_p!(shim_dir)
    File.rm(erl)
    File.ln_s!(arinsal, erl)
    shim_dir
  end
end
