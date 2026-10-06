defmodule ArinsalDemo.Work do
  @moduledoc "Concurrency workloads using tasks, Registry, and GenServer."
  use GenServer

  @doc "Maps a function over inputs with bounded task concurrency."
  @spec fan_out([term()], (term() -> term())) :: [term()]
  def fan_out(inputs, function),
    do:
      inputs
      |> Task.async_stream(function, max_concurrency: 4, ordered: true)
      |> Enum.map(fn {:ok, value} -> value end)

  @doc "Publishes a message to duplicate Registry subscribers and returns deliveries."
  @spec publish(term(), term(), non_neg_integer()) :: [term()]
  def publish(topic, message, subscribers \\ 2) do
    parent = self()

    refs =
      for index <- 1..subscribers do
        spawn(fn ->
          {:ok, _} = Registry.register(ArinsalDemo.PubSub, topic, index)
          send(parent, {:ready, self()})

          receive do
            {:published, value} ->
              send(parent, {:delivered, index, value})

              receive do
                :stop -> :ok
              end

            :stop ->
              :ok
          end
        end)
      end

    Enum.each(refs, fn _ ->
      receive do
        {:ready, _pid} -> :ok
      end
    end)

    Enum.each(Registry.lookup(ArinsalDemo.PubSub, topic), fn {subscriber, _} ->
      send(subscriber, {:published, message})
    end)

    deliveries =
      for _ <- refs do
        receive do
          {:delivered, index, ^message} -> {index, message}
        after
          1_000 -> :timeout
        end
      end

    Enum.each(refs, &send(&1, :stop))
    Enum.sort(deliveries)
  end

  @doc "Runs synchronous ping-pong calls through a GenServer."
  @spec ping_pong(non_neg_integer()) :: non_neg_integer()
  def ping_pong(round_trips) do
    {:ok, pid} = GenServer.start_link(__MODULE__, 0)
    result = Enum.reduce(1..round_trips//1, 0, fn _, _ -> GenServer.call(pid, :ping) end)
    GenServer.stop(pid)
    result
  end

  @doc "Fans values into a collector process and returns their sum."
  @spec fan_in([integer()]) :: integer()
  def fan_in(values) do
    parent = self()
    collector = spawn(fn -> collect(length(values), 0, parent) end)
    Enum.each(values, &send(collector, {:value, &1}))

    receive do
      {:total, total} -> total
    end
  end

  defp collect(0, total, parent), do: send(parent, {:total, total})

  defp collect(left, total, parent) do
    receive do
      {:value, value} -> collect(left - 1, total + value, parent)
    end
  end

  @doc "Spawns one process and waits for its :DOWN message."
  @spec spawn_down() :: :ok
  def spawn_down do
    {pid, ref} = spawn_monitor(fn -> :ok end)

    receive do
      {:DOWN, ^ref, :process, ^pid, :normal} -> :ok
    after
      60_000 -> raise "spawn/DOWN timed out"
    end
  end

  @doc "Exchanges n ping-pong messages with a fresh process."
  @spec message_ping_pong(pos_integer()) :: :ok
  def message_ping_pong(n) when n > 0 do
    parent = self()
    child = spawn(fn -> pong_loop(n) end)
    ping_loop(child, parent, n)
  end

  @doc "Sums squares with Task.async_stream/3."
  @spec async_stream_sum(pos_integer()) :: integer()
  def async_stream_sum(n) when n > 0 do
    1..n
    |> Task.async_stream(&(&1 * &1),
      max_concurrency: 8,
      ordered: true,
      timeout: 120_000
    )
    |> Enum.reduce(0, fn
      {:ok, value}, acc -> acc + value
      other, _acc -> raise "async_stream failed: #{inspect(other)}"
    end)
  end

  @doc "One GenServer.call/2 round trip against an already running server."
  @spec round_trip(pid()) :: term()
  def round_trip(pid), do: GenServer.call(pid, :echo)

  defp pong_loop(0), do: :ok

  defp pong_loop(left) do
    receive do
      {:ping, from} ->
        send(from, :pong)
        pong_loop(left - 1)
    after
      120_000 -> raise "ping-pong receive timed out"
    end
  end

  defp ping_loop(_child, _parent, 0), do: :ok

  defp ping_loop(child, parent, left) do
    send(child, {:ping, parent})

    receive do
      :pong -> ping_loop(child, parent, left - 1)
    after
      120_000 -> raise "ping-pong reply timed out"
    end
  end

  @impl true
  def init(count), do: {:ok, count}
  @impl true
  def handle_call(:ping, _from, count), do: {:reply, count + 1, count + 1}
  def handle_call(:echo, _from, state), do: {:reply, state, state}
end
