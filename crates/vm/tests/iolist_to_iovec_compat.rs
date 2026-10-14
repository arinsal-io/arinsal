use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(iolist_to_iovec_compat).
-export([run/0]).

bin(N, B) -> binary:copy(<<B>>, N).

unaligned(N, B) ->
    <<_:3, R:(N * 8)/bitstring, _/bitstring>> = <<0:3, (bin(N, B))/bitstring, 0:5>>,
    R.

cases() ->
    Large = bin(2000, 9),
    Refc = binary:part(Large, 100, 600),
    SmallPart = binary:part(Large, 3, 100),
    HugePart = binary:part(Large, 1, 1500),
    [
        {pair_64_empty_68, [bin(64, 1), <<>>, bin(68, 2)]},
        {pair_64_68, [bin(64, 1), bin(68, 2)]},
        {pair_63_65_64, [bin(63, 1), bin(65, 2), bin(64, 3)]},
        {small_binaries_merge, [bin(10, 1), bin(100, 2), bin(200, 3)]},
        {empty_between_large, [bin(513, 1), <<>>, bin(513, 2)]},
        {empty_between_large_and_small, [bin(513, 1), <<>>, bin(1, 2), <<>>, bin(513, 3)]},
        {all_empty, [<<>>, <<>>, []]},
        {nested_empty, [[<<>>], [[]], <<>>]},
        {empty_binary, <<>>},
        {empty_list, []},
        {single_empty, [<<>>]},
        {single_small, [bin(1, 7)]},
        {single_threshold, [bin(512, 7)]},
        {single_over, [bin(513, 7)]},
        {bare_small, bin(3, 4)},
        {bare_large, bin(600, 4)},
        {bare_large_refc, Refc},
        {single_refc_sub, [Refc]},

        {at_511_then_1, [bin(511, 1), bin(1, 2)]},
        {at_512_then_1, [bin(512, 1), bin(1, 2)]},
        {at_513_then_1, [bin(513, 1), bin(1, 2)]},
        {one_then_511, [bin(1, 2), bin(511, 1)]},
        {one_then_512, [bin(1, 2), bin(512, 1)]},
        {one_then_513, [bin(1, 2), bin(513, 1)]},
        {mid_511, [bin(1, 2), bin(511, 1), bin(1, 3)]},
        {mid_512, [bin(1, 2), bin(512, 1), bin(1, 3)]},
        {mid_513, [bin(1, 2), bin(513, 1), bin(1, 3)]},
        {two_512, [bin(512, 1), bin(512, 2)]},
        {two_513, [bin(513, 1), bin(513, 2)]},
        {two_511, [bin(511, 1), bin(511, 2)]},
        {mixed_511_513_512, [bin(511, 1), bin(513, 2), bin(512, 3)]},
        {mixed_513_512_513, [bin(513, 1), bin(512, 2), bin(513, 3)]},
        {large_small_large_small, [bin(600, 1), bin(2, 2), bin(600, 3), bin(2, 4)]},
        {small_large_small, [bin(2, 2), bin(600, 1), bin(2, 4)]},
        {large_first_small_tail, [bin(600, 1), bin(2, 2), bin(3, 3)]},

        {bytes_only, [1, 2, 3, 255, 0]},
        {bytes_around_large, [1, 2, bin(513, 5), 3, 4]},
        {bytes_then_large, [1, bin(513, 5)]},
        {large_then_bytes, [bin(513, 5), 1]},
        {bytes_and_small, [1, bin(5, 2), 3, bin(500, 4)]},
        {byte_at_threshold, [bin(511, 1), 7, bin(513, 2)]},

        {nested_lists, [[1, [bin(10, 2)]], [[bin(513, 3)]], [4 | bin(5, 6)]]},
        {nested_deep, [[[[[bin(513, 1)]]], 2], [[3], [bin(513, 4)]]]},
        {improper_tail_small, [1, 2 | bin(5, 3)]},
        {improper_tail_large, [1, 2 | bin(513, 3)]},
        {improper_tail_empty, [bin(513, 3) | <<>>]},
        {improper_tail_large_after_large, [bin(513, 1) | bin(513, 2)]},
        {head_is_list_tail_binary, [[bin(10, 1), bin(10, 2)] | bin(600, 3)]},
        {deep_improper, [[[bin(3, 1) | bin(600, 2)] | bin(4, 3)] | bin(5, 4)]},

        {refc_sub_large, [bin(1, 1), Refc, bin(1, 2)]},
        {refc_sub_small, [bin(1, 1), SmallPart, bin(1, 2)]},
        {refc_sub_huge, [bin(1, 1), HugePart, bin(1, 2)]},
        {refc_sub_twice, [Refc, Refc]},
        {refc_whole, [bin(1, 1), Large, bin(1, 2)]},
        {refc_sub_of_sub, [binary:part(Refc, 10, 520), bin(1, 3)]},

        {unaligned_small, [bin(1, 1), unaligned(10, 5), bin(1, 2)]},
        {unaligned_at_512, [bin(1, 1), unaligned(512, 5), bin(1, 2)]},
        {unaligned_513, [bin(513, 1), unaligned(513, 5), bin(513, 2)]},
        {unaligned_large, [bin(513, 1), unaligned(2000, 5), bin(513, 2)]},
        {unaligned_only_large, [unaligned(2000, 5)]},
        {unaligned_bare, unaligned(2000, 5)},
        {unaligned_bare_small, unaligned(5, 5)},
        {unaligned_tail, [bin(513, 1) | unaligned(600, 3)]},
        {unaligned_adjacent, [unaligned(600, 1), unaligned(600, 2)]},
        {unaligned_empty, [bin(513, 1), unaligned(0, 3), bin(513, 2)]},

        {err_improper_int, [1 | 2]},
        {err_big_byte, [256]},
        {err_neg_byte, [-1]},
        {err_float, [1.0]},
        {err_atom, [a]},
        {err_atom_bare, foo},
        {err_int_bare, 1},
        {err_tail_atom, [bin(513, 1) | foo]},
        {err_bitstring, <<1:3>>},
        {err_bitstring_list, [<<1:3>>]},
        {err_bitstring_large, [bin(513, 1), <<1:3>>]},
        {err_bitstring_after_bytes, [1, 2, <<0:11>>]},
        {err_unaligned_odd_size,
            begin
                <<_:3, Odd:13/bitstring, _/bitstring>> = <<0:3, 0:13, 0:8>>,
                [bin(5, 1), Odd]
            end},
        {err_tuple, [{a}]}
    ].

run() ->
    [{Name, result(Input)} || {Name, Input} <- cases()] ++ [{survives_gc, survives_gc()}].

survives_gc() ->
    Vec = erlang:iolist_to_iovec([bin(1, 1), bin(600, 2), 3, bin(40, 4), unaligned(700, 5), bin(9, 6)]),
    Sizes = [binary:referenced_byte_size(B) || B <- Vec],
    erlang:garbage_collect(),
    {Vec, Sizes, [binary:referenced_byte_size(B) || B <- Vec], iolist_to_binary(Vec)}.

result(Input) ->
    try erlang:iolist_to_iovec(Input) of
        Vec -> {ok, Vec, [binary:referenced_byte_size(B) || B <- Vec]}
    catch
        Class:Reason -> {Class, Reason}
    end.
"#;

#[test]
fn iolist_to_iovec_segmentation_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping iolist_to_iovec compat test");
        return;
    };
    let beam = reference
        .compile_named("iolist_to_iovec_compat", SOURCE, &[])
        .unwrap();
    reference.load("iolist_to_iovec_compat", &beam).unwrap();
    let expected = reference.call("iolist_to_iovec_compat", "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("iolist_to_iovec_compat", "run", &[], 1, None)
        .unwrap_or_else(|error| panic!("iolist_to_iovec cases: {error}"));

    similar_asserts::assert_eq!(expected, CallResult::Ok(actual.term));
}
