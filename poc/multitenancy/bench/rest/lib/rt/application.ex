defmodule RT.Application do
  @moduledoc false
  use Application

  def start(_type, _args) do
    port = String.to_integer(System.get_env("RT_PORT", "4000"))
    tenants = String.to_integer(System.get_env("RT_TENANTS", "1"))
    items = String.to_integer(System.get_env("RT_ITEMS", "200"))

    children = [
      {Registry, keys: :unique, name: RT.Registry},
      {DynamicSupervisor, name: RT.Tenants, strategy: :one_for_one},
      {Bandit, plug: RT.Host, ip: {127, 0, 0, 1}, port: port}
    ]

    {:ok, sup} = Supervisor.start_link(children, strategy: :one_for_one, name: RT.Sup)
    for id <- 1..tenants//1, do: {:ok, _} = RT.Host.start_tenant(Integer.to_string(id), {:fresh, items})
    :persistent_term.put(:rt_ready, true)
    {:ok, sup}
  end
end
