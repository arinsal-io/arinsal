defmodule Arinsal.Cloud do
  @moduledoc """
  Client of the `arinsal_cloud` manager's admin HTTP API, used by the `mix arinsal.*` cloud tasks.

  The manager listens on `http://127.0.0.1:7000` by default; every task takes `--url` to change it.
  Only `:inets` (`:httpc`) and the standard library are used.
  """

  @default_url "http://127.0.0.1:7000"
  @switches [tenant: :string, project: :string, url: :string]

  @doc """
  Parses `--tenant`, `--project` and `--url` plus the task's own switches.

  `--tenant` is required. `--project` defaults to the current Mix project's app name.
  """
  def parse!(args, switches \\ [], aliases \\ []) do
    {opts, rest, invalid} = OptionParser.parse(args, strict: @switches ++ switches, aliases: aliases)

    if invalid != [] do
      Mix.raise("invalid options: " <> Enum.map_join(invalid, " ", fn {k, _} -> to_string(k) end))
    end

    tenant = opts[:tenant] || Mix.raise("--tenant is required")
    project = opts[:project] || default_project()
    {Keyword.merge(opts, tenant: tenant, project: project), rest}
  end

  @doc "Base URL of the manager, without a trailing slash."
  def base_url(opts), do: String.trim_trailing(opts[:url] || @default_url, "/")

  @doc "Path of one project, e.g. `/projects/acme/shop`."
  def project_path(opts), do: "/projects/#{URI.encode(opts[:tenant])}/#{URI.encode(opts[:project])}"

  @doc """
  Sends a request. Returns `{status, decoded_json_or_text}`.

  `body` is `nil` or a binary (the release tarball for deploys).
  """
  def request(method, opts, path, body \\ nil) do
    for app <- [:public_key, :ssl, :inets], do: Mix.ensure_application!(app)
    {:ok, _} = Application.ensure_all_started(:inets)
    url = String.to_charlist(base_url(opts) <> path)

    request =
      case {method, body} do
        {m, nil} when m in [:get, :delete] -> {url, []}
        {_, nil} -> {url, [], ~c"application/octet-stream", ""}
        {_, body} -> {url, [], ~c"application/gzip", body}
      end

    case :httpc.request(method, request, [timeout: 300_000], body_format: :binary) do
      {:ok, {{_, status, _}, headers, payload}} -> {status, decode(headers, payload)}
      {:error, reason} -> Mix.raise("cannot reach the manager at #{base_url(opts)}: #{inspect(reason)}")
    end
  end

  @doc "Like `request/4` but raises on any status other than 200."
  def request!(method, opts, path, body \\ nil) do
    case request(method, opts, path, body) do
      {200, payload} -> payload
      {status, %{"error" => error}} -> Mix.raise("manager answered #{status}: #{inspect(error)}")
      {status, payload} -> Mix.raise("manager answered #{status}: #{inspect(payload)}")
    end
  end

  @doc "One-line summary of a project map."
  def summary(project) do
    ns = if project["ns"], do: " ns=#{project["ns"]}", else: ""
    url = project["url"] || "-"

    "#{project["tenant"]}/#{project["project"]}  #{project["state"]}  #{url}  v#{project["version"] || "-"}#{ns}"
  end

  defp decode(headers, payload) do
    type = for {k, v} <- headers, String.downcase(to_string(k)) == "content-type", do: to_string(v)

    case type do
      ["application/json" <> _] -> JSON.decode!(payload)
      _ -> payload
    end
  end

  defp default_project do
    case Mix.Project.config()[:app] do
      nil -> Mix.raise("--project is required outside a Mix project")
      app -> Atom.to_string(app)
    end
  end
end
