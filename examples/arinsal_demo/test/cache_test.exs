defmodule ArinsalDemo.CacheTest do
  use ExUnit.Case, async: false

  test "ETS cache supports misses, puts, and compute-once reads" do
    key = make_ref()
    assert ArinsalDemo.Cache.get(key) == :error
    assert ArinsalDemo.Cache.put(key, :stored) == :stored
    assert ArinsalDemo.Cache.get(key) == {:ok, :stored}
    assert ArinsalDemo.Cache.fetch_or_compute(key, fn -> :unused end) == :stored
    other = make_ref()
    assert ArinsalDemo.Cache.fetch_or_compute(other, fn -> {:computed, 42} end) == {:computed, 42}
    assert ArinsalDemo.Cache.fetch_or_compute(other, fn -> :must_not_run end) == {:computed, 42}
    assert ArinsalDemo.Cache.get(other) == {:ok, {:computed, 42}}
  end
end
