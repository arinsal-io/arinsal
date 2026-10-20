//! `<<Bin/binary, Bin2/binary>>` followed by stores that rely on the instruction's `Alloc` words
//! (a heap bitstring of 57..64 bytes takes more than a BinRef plus SubBits).

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const MODULE: &str = "bs_append_alloc";
const SOURCE: &str = r#"
-module(bs_append_alloc).
-export([run/0]).
run() -> go(40000, []).
%% Every step appends two binaries whose sum walks through 50..70 bytes and then builds a tuple
%% and a list cell from the result, so collections land at every distance from the heap end.
go(0, L) -> 0 + lists:sum([byte_size(X) || {{X, _, _}, _, _} <- L]);
go(N, L) ->
    A = id(binary:copy(<<"a">>, 20 + N rem 30)), B = id(binary:copy(<<"b">>, 30 - (N rem 11))),
    Pad = id(lists:duplicate(N rem 37, N)),
    Acc = join(A, B),
    T = {Acc, B, A},
    go(N - 1, [T | lists:sublist(L, 5)]) + length(Pad) - length(Pad).
%% The accumulator of a loop is the shape the compiler lowers to an append.
join(Acc, B) -> {<<Acc/binary, B/binary>>, {B, Acc, B}, [B, Acc, B]}.
id(X) -> X.
"#;

#[test]
fn append_binary_reserves_the_alloc_words() {
    let reference = RefErl::start().expect("OTP 29.1.1");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    let expected = reference.call(MODULE, "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled(MODULE, "run", &[], 1, Some(82))
        .map(|outcome| CallResult::Ok(outcome.term))
        .unwrap_or_else(|error| CallResult::TransportError(format!("{error:?}")));
    assert_eq!(expected, actual);
}
