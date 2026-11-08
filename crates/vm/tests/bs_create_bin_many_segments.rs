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
