defmodule ArinsalHttp.Application do
  use Application

  @impl true
  def start(_type, _args) do
    port = String.to_integer(System.get_env("PORT", "8083"))
    children = [{Bandit, plug: ArinsalHttp.Router, scheme: :http, ip: {127, 0, 0, 1}, port: port, thousand_island_options: [num_acceptors: 4]}]
    Supervisor.start_link(children, strategy: :one_for_one, name: ArinsalHttp.Supervisor)
  end
end
