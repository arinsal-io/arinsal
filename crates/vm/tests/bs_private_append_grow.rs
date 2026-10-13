//! `bs_create_bin` private append when the source lives on the stack and the buffer must grow.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const MODULE: &str = "bs_private_append_grow";
const SOURCE: &str = r#"
-module(bs_private_append_grow).
-export([run/0]).
run() -> [pct(S) || S <- [<<"/%2f">>, <<"%2f">>, <<"/a%2f%41b">>, <<"abc%7e%7E">>]].
pct(S) -> d(S, <<>>).
%% The accumulator stays in a Y register across the calls, and the 3-byte append after a
%% 1-byte buffer takes the grow path of the private append.
d(<<$%,C0,C1,Cs/binary>>, Acc) ->
    H0 = id(C0), H1 = id(C1),
    d(Cs, <<Acc/binary,$%,H0,H1>>);
d(<<C,Cs/binary>>, Acc) -> d(Cs, <<Acc/binary, C>>);
d(<<>>, Acc) -> Acc.
id(X) when X > 0 -> X;
id(X) -> throw(X).
"#;

#[test]
fn private_append_grow_reads_the_stack_source_again() {
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
