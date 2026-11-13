//! A frame keeps its Y registers when a BIF it calls traps.
//!
//! `walk/4`'s `erlang:iolist_size/1` call traps when the slice is out of reductions; the trap
//! must keep the frame's Y registers (`Count` once read as `[]`).

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::global_atoms;

const MODULE: &str = "interp_frame_trap";

const SOURCE: &str = r#"-module(interp_frame_trap).
-export([run/1, walk/4]).

run(N) ->
    Result = interp_frame_trap:walk(N, 0, [], lists:duplicate(2000, $a)),
    {ok, Result}.

%% Every call keeps N, Count, Seen and Big in Y registers across the BIF calls. The
%% first BIF charges enough reductions to empty the slice, so the second one traps at entry.
walk(0, Count, [Last | _] = Seen, _Big) ->
    {done, Count, Last, Seen == lists:duplicate(Count, Last)};
walk(N, Count, Seen, Big) ->
    Burn = erlang:iolist_size(Big),
    Size = erlang:iolist_size([<<"ab">>, "cd", [$e]]),
    Next = Count + Size - 4 + Burn - 2000,
    walk(N - 1, Next, [Size | Seen], Big).
"#;

#[test]
fn bif_trap_keeps_frame_y_registers() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping frame trap test");
        return;
    };
    let beam = reference
        .compile_named(MODULE, SOURCE, &[])
        .expect("compile interp_frame_trap");
    reference.load(MODULE, &beam).expect("load into erl");
    let want = match reference.call(MODULE, "run", &[OwnedTerm::Int(20_000)]) {
        CallResult::Ok(term) => term,
        other => panic!("{MODULE}:run on erl: {other:?}"),
    };
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let arg = arinsal_term::Term::small(20_000).unwrap();
    let actual = vm.eval_scheduled(MODULE, "run", &[arg], 2).unwrap();
    let _ = global_atoms();
    assert_eq!(format!("{:?}", actual.term), format!("{want:?}"));
}
