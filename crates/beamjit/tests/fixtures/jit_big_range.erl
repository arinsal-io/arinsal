-module(jit_big_range).
-export([t/0]).
%% Guards that compare against integer constants outside the small range (-2^59..2^59-1) stay
%% generic comparisons: OTP turns such constants into literals while reading the code, so the
%% is_int_in_range / is_ge-pair transformations do not apply to them.
inr(X) when is_integer(X), X >= -9223286400000000000, X =< 9223372036854775806 -> in;
inr(_) -> out.
ge(X) when is_integer(X), X >= 9223286400000000000 -> big;
ge(_) -> no.
mixed(X) when X >= -576460752303423488, X =< 576460752303423487 -> small;
mixed(X) when X >= -9223372036854775808, X =< 9223372036854775807 -> word;
mixed(_) -> other.
t() ->
  Vals = [0, 1, -1, 576460752303423487, 576460752303423488, -576460752303423488, -576460752303423489,
          9223286400000000000, 9223286399999999999, -9223286400000000000, -9223286400000000001,
          9223372036854775806, 9223372036854775807, 9223372036854775808, -9223372036854775808,
          -9223372036854775809, 1 bsl 80, -(1 bsl 80), 1.5e19, a, [], 3.0],
  [{V, inr(V), ge(V), mixed(V)} || V <- Vals].
