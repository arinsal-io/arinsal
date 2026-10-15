//! Differential test: ETS table handles and compiled match specifications survive
//! `term_to_binary/1` in a form every node accepts, so `ets:tab2file/2` output is
//! readable by `ets:file2tab/1` on stock OTP.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(ets_tid_etf_diff).
-export([tid_wire_form/0, program_wire_form/0]).
first_id(Ref) ->
  <<131, 90, N:16, 119, L, _Node:L/binary, _Creation:32, First:32, _/binary>> = term_to_binary(Ref),
  {N, First}.
tid_wire_form() ->
  T = ets:new(wire, [set, public]),
  ets:insert(T, {k, v}),
  Copy = binary_to_term(term_to_binary(T)),
  {N, First} = first_id(T),
  {N, First < (1 bsl 18), Copy =:= T, ets:lookup(Copy, k)}.
program_wire_form() ->
  MS = ets:match_spec_compile([{{'$1', '_'}, [], ['$1']}]),
  {N, First} = first_id(MS),
  {N, First < (1 bsl 18), ets:match_spec_run([{a, 1}, {b, 2}], MS)}.
"#;

#[test]
fn ets_tid_etf_matches_otp_29() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping ets_tid_etf differential scenarios");
        return;
    };
    let beam = reference
        .compile_named("ets_tid_etf_diff", SOURCE, &[])
        .unwrap();
    reference.load("ets_tid_etf_diff", &beam).unwrap();
    for function in ["tid_wire_form", "program_wire_form"] {
        let expected = reference.call("ets_tid_etf_diff", function, &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&beam).unwrap();
        let actual = vm
            .eval_scheduled("ets_tid_etf_diff", function, &[], 2, Some(81))
            .unwrap_or_else(|error| panic!("{function}: {error}"));
        assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
    }
}
