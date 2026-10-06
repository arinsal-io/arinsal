defmodule ArinsalDemo.PureTest do
  use ExUnit.Case, async: true

  test "recursive, allocation, and collection workloads have stable results" do
    assert ArinsalDemo.Pure.fib(10) == 55
    assert ArinsalDemo.Pure.nbody(0) == 0.0
    assert ArinsalDemo.Pure.nbody(10) == 8.667801075559016e-6
    assert ArinsalDemo.Pure.trees(3) == 0
    assert ArinsalDemo.Pure.trees(8) == 24_240
    assert ArinsalDemo.Pure.enum_pipeline(10) == 90
    assert ArinsalDemo.Pure.stream_pipeline(10) == 90
    assert ArinsalDemo.Pure.sort(5) == [1, 2, 3, 4, 5]
    assert ArinsalDemo.Pure.group_by(5) == %{false: 3, true: 2}

    assert ArinsalDemo.Pure.frequencies(15) == %{
             0 => 1,
             1 => 2,
             2 => 2,
             3 => 1,
             4 => 1,
             5 => 1,
             6 => 1,
             7 => 1,
             8 => 1,
             9 => 1,
             10 => 1,
             11 => 1,
             12 => 1
           }
  end
end
