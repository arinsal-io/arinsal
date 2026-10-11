//! A reduction yield at function entry must keep every argument register.
//!
//! `i_test_yield` stores the MFA arity in `c_p->arity`. The scheduler file is
//! sized from the interpreter module — here `xreg_small`, which never mentions
//! x8 — and floored at 8. `xreg_big:walk/10` is reached by a native call, so
//! its arguments past x7 live only in the native register array until the
//! yield is published.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::Term;
use arinsal_vm::Vm;

const SMALL: &str = r#"
-module(xreg_small).
-export([go/1]).

go(N) ->
    xreg_big:start(N).
"#;

const BIG: &str = r#"
-module(xreg_big).
-export([start/1]).

start(N) ->
    walk(1, 2, 3, 4, 5, 6, 7, 8, 9, N).

walk(A, B, C, D, E, F, G, H, I, 0) ->
    {A, B, C, D, E, F, G, H, I};
walk(A, B, C, D, E, F, G, H, I, N) ->
    walk(A, B, C, D, E, F, G, H, I, N - 1).
"#;

#[test]
fn high_arity_arguments_survive_reduction_yield() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping xreg yield test");
        return;
    };
    let small = reference.compile_named("xreg_small", SMALL, &[]).unwrap();
    let big = reference.compile_named("xreg_big", BIG, &[]).unwrap();
    reference.load("xreg_small", &small).unwrap();
    reference.load("xreg_big", &big).unwrap();
    let expected = reference.call("xreg_small", "go", &[OwnedTerm::Int(20_000)]);
    let args = [Term::small(20_000).unwrap()];
    let mut vm = Vm::new([]);
    vm.load_bytes(&small).unwrap();
    vm.load_bytes(&big).unwrap();
    let actual = vm
        .eval_scheduled("xreg_small", "go", &args, 1, None)
        .map(|result| result.term)
        .unwrap_or_else(|error| panic!("VM error {error:?}"));
    assert_eq!(expected, CallResult::Ok(actual));
}
