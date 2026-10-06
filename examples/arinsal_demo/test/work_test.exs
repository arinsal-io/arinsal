defmodule ArinsalDemo.WorkTest do
  use ExUnit.Case, async: false

  test "task fan-out, Registry pub-sub, ping-pong, and fan-in" do
    assert ArinsalDemo.Work.fan_out([1, 2, 3], &(&1 * &1)) == [1, 4, 9]
    assert ArinsalDemo.Work.publish(:test_topic, :hello, 2) == [{1, :hello}, {2, :hello}]
    assert ArinsalDemo.Work.ping_pong(20) == 20
    assert ArinsalDemo.Work.fan_in([1, 2, 3, 4]) == 10
    assert ArinsalDemo.Work.fan_in([]) == 0
  end
end
