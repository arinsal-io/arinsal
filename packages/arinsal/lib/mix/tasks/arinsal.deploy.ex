defmodule Mix.Tasks.Arinsal.Deploy do
  use Mix.Task

  @shortdoc "Release the current project and deploy it to an Arinsal cloud manager"
  @moduledoc """
  Builds a release of the current Mix project and uploads it to the manager.

      mix arinsal.deploy --tenant acme --project shop
      mix arinsal.deploy --tenant acme --url http://127.0.0.1:7000 --release rt

  The release is built with `MIX_ENV=prod mix release --overwrite` using whatever `mix` and `erl`
  come first on `PATH`, into a temporary directory. Only `lib/` and `releases/` are shipped (the
  manager runs the release on its own runtime, so `include_erts` does not matter).

  Options:

    * `--tenant` (required) and `--project` (default: the Mix app name)
    * `--url` - manager admin URL, default `http://127.0.0.1:7000`
    * `--release` - release name when the project defines several
  """

  alias Arinsal.Cloud

  @impl Mix.Task
  def run(args) do
    {opts, _} = Cloud.parse!(args, release: :string)
    tmp = Path.join(System.tmp_dir!(), "arinsal_deploy_#{System.unique_integer([:positive])}")

    try do
      tar = build_tar!(tmp, opts[:release])
      Mix.shell().info("Uploading #{byte_size(tar)} bytes to #{Cloud.base_url(opts)}")
      project = Cloud.request!(:put, opts, Cloud.project_path(opts), tar)
      Mix.shell().info(Cloud.summary(project))
    after
      File.rm_rf(tmp)
    end
  end

  defp build_tar!(tmp, release) do
    mix = System.find_executable("mix") || Mix.raise("mix executable was not found on PATH")
    rel = Path.join(tmp, "release")
    args = ["release"] ++ List.wrap(release) ++ ["--overwrite", "--path", rel]

    case System.cmd(mix, args, env: [{"MIX_ENV", "prod"}], into: IO.stream(:stdio, :line), stderr_to_stdout: true) do
      {_, 0} -> :ok
      {_, status} -> Mix.raise("mix release failed (exit status #{status})")
    end

    File.rm(Path.join([rel, "releases", "COOKIE"]))
    tar = Path.join(tmp, "release.tar.gz")

    entries = [{~c"lib", String.to_charlist(Path.join(rel, "lib"))}, {~c"releases", String.to_charlist(Path.join(rel, "releases"))}]

    :ok = :erl_tar.create(String.to_charlist(tar), entries, [:compressed, :dereference])
    File.read!(tar)
  end
end
