//! Differential coverage for long `bs_create_bin` instruction segment lists.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;
use similar_asserts::assert_eq;
use std::fmt::Write as _;

const MODULE: &str = "bs_create_bin_many_segments";

fn source() -> String {
    let mut source = String::from("-module(bs_create_bin_many_segments).\n-export([run/0]).\n");
    source.push_str("bad_size() -> -1.\n");
    source.push_str("bad_value() -> not_an_integer.\n");
    for count in [3, 90, 150, 400, 700] {
        write!(source, "make_{count}(X) -> <<").unwrap();
        for index in 0..count {
            if index != 0 {
                source.push(',');
            }
            source.push_str("X/binary");
        }
        source.push_str(">>.\n");
    }
    source.push_str(
        "bad_size_result() -> try <<1:(bad_size())>> of B -> {ok, B} catch error:R -> {error, R} end.\n\
         bad_value_result() -> try <<(bad_value()):8>> of B -> {ok, B} catch error:R -> {error, R} end.\n\
         run() -> {[byte_size(make_3(<<1>>)), byte_size(make_90(<<1>>)), byte_size(make_150(<<1>>)),\n\
                    byte_size(make_400(<<1>>)), byte_size(make_700(<<1>>))],\n\
                   bad_size_result(), bad_value_result()}.\n",
    );
    source
}

#[test]
fn long_segment_lists_and_bad_operands_match_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping differential check");
        return;
    };
    let beam = reference.compile_named(MODULE, &source(), &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm.eval_scheduled(MODULE, "run", &[], 2, None).unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}

const APPEND_MODULE: &str = "bs_create_bin_append_gc";

// `bs_create_bin` whose first segment is `append` collects with exactly `live + 1` X roots
// (erl_bits.c, erts_bs_append_checked). Loops long enough to collect inside the append
// helper; a stale register above the roots used to be evacuated and corrupt the heap.
const APPEND_SOURCE: &str = "-module(bs_create_bin_append_gc).\n\
-export([run/0]).\n\
id(X) -> X.\n\
sub_only(_, 0, Acc) -> Acc;\n\
sub_only(B, N, Acc) -> {S, _} = split_binary(B, 1),\n\
    R = [<<S/binary>> || _ <- [1,2,3,4,5,6,7,8,9]],\n\
    sub_only(B, N - 1, [length(R), byte_size(hd(R)) | Acc]).\n\
sub_tail(_, 0, Acc) -> erlang:md5(term_to_binary(Acc));\n\
sub_tail(B, N, Acc) -> {S, Rest} = split_binary(B, 1), <<Byte, Tail/binary>> = Rest,\n\
    R = [<<S/binary, (Byte bxor M), Tail/binary>> || M <- [1,2,4,8,16,32,64,128,255]],\n\
    sub_tail(B, N - 1, [R | Acc]).\n\
grow(0, Acc, Out) -> {byte_size(Acc), erlang:md5(Acc), length(Out)};\n\
grow(N, Acc, Out) -> A = <<Acc/binary, (N band 255)>>,\n\
    grow(N - 1, A, [<<A/binary>> | Out]).\n\
fresh(0, Out) -> erlang:md5(term_to_binary(Out));\n\
fresh(N, Out) -> fresh(N - 1, [<<(id(<<>>))/binary, (N band 255), (N bsr 8)>> | Out]).\n\
err(F) -> try F() of V -> {ok, V} catch error:R -> {error, R} end.\n\
run() -> B = term_to_binary(''),\n\
    {lists:sum(sub_only(B, 3000, [])), sub_tail(B, 3000, []), grow(3000, <<>>, []),\n\
     fresh(20000, []), lists:sum([byte_size(rand:bytes(N rem 32)) || N <- lists:seq(1, 5000)]),\n\
     err(fun() -> <<(id(an_atom))/binary>> end), err(fun() -> <<(id(an_atom))/binary, 1>> end),\n\
     err(fun() -> <<(id(<<1:3>>))/binary, 1>> end)}.\n";

#[test]
fn append_collects_with_live_plus_one_roots_like_erts() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping differential check");
        return;
    };
    let beam = reference
        .compile_named(APPEND_MODULE, APPEND_SOURCE, &[])
        .unwrap();
    reference.load(APPEND_MODULE, &beam).unwrap();
    let expected = reference.call(APPEND_MODULE, "run", &[]);

    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled(APPEND_MODULE, "run", &[], 2, None)
        .unwrap();
    assert_eq!(expected, CallResult::Ok(actual.term));
}
