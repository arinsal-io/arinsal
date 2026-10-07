defmodule ArinsalDemo.MapsTest do
  use ExUnit.Case, async: true

  test "map sizes, updates, structs, and protocol dispatch" do
    assert map_size(ArinsalDemo.Maps.small_map()) == 16
    assert ArinsalDemo.Maps.small_map().k1 == 1
    assert ArinsalDemo.Maps.large_map(1_000)[1_000] == 2_000
    assert ArinsalDemo.Maps.update_loop(100) == 100

    assert ArinsalDemo.Maps.dispatch() == [
             {:account, 7, "Ada"},
             {:event, :login, 123},
             {:point, 2, 5}
           ]
  end
end
