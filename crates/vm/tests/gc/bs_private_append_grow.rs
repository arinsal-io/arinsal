//! `bs_create_bin` private append when the source lives on the stack and the buffer must grow.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const MODULE: &str = "bs_private_append_grow";
const SOURCE: &str = r#"
-module(bs_private_append_grow).
-export([run/0, x_source/0, wide/0]).
run() -> [pct(S) || S <- [<<"/%2f">>, <<"%2f">>, <<"/a%2f%41b">>, <<"abc%7e%7E">>]].
%% The accumulator stays in an X register: no call between the loads and the append.
x_source() -> [xs(S, <<>>) || S <- [<<"/%2f">>, <<"ab%2f%2fcd">>, binary:copy(<<"x%41">>, 50)]].
xs(<<$%,C0,C1,Cs/binary>>, Acc) -> xs(Cs, <<Acc/binary,$%,C0,C1>>);
xs(<<C,Cs/binary>>, Acc) -> xs(Cs, <<Acc/binary,C>>);
xs(<<>>, Acc) -> Acc.
%% Five integer segments after a Y-register accumulator, several buffer growths in a row.
wide() -> wd(lists:seq(1, 40), <<>>).
wd([], Acc) -> Acc;
wd([N | T], Acc) ->
    A = id(N), B = id(N + 1), C = id(N + 2),
    wd(T, <<Acc/binary,A,B,C,$-,N:8>>).
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
    for function in ["run", "x_source", "wide"] {
        let reference = RefErl::start().expect("OTP 29.1.1");
        let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
        reference.load(MODULE, &beam).unwrap();
        let expected = reference.call(MODULE, function, &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled(MODULE, function, &[], 1, Some(82))
            .map(|outcome| CallResult::Ok(outcome.term))
            .unwrap_or_else(|error| CallResult::TransportError(format!("{error:?}")));
        assert_eq!(expected, actual, "{function}");
    }
}
