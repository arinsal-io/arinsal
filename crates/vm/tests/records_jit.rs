//! Differential tests (against the reference `erl`) for the native record instructions in
//! native code and for canonical record definitions. Every record operation sits in a local
//! function called from an exported entry, which is where native code takes over.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;
use std::sync::Mutex;

static TEST_LOCK: Mutex<()> = Mutex::new(());

const DEFINITION: &str = r#"
-module(rj_def).
-export([vector/0, sealed/0]).
-export_record([vector]).
-record #vector{x=0, y=0, z=0}.
-record #hidden{a=1}.

vector() -> #vector{x=1}.
sealed() -> #hidden{a=2}.
"#;

const PROBE: &str = r#"
-module(rj_probe).
-export([many_registers/0, loop_gc/0, external_ops/0, errors/0, canonical/0, accessible/0]).

-record #big{f1=1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11,f12,f13,f14=x,f15,f16}.
-record #s{a, b=[1,2,3]}.
-record #loc{x=1, y=2}.
-record #nodef{a, b=0}.

id(X) -> X.
err(F) -> try F(), no_error catch C:R -> {C, R} end.

many_registers() ->
    apply(fun make/12, [id(I) || I <- lists:seq(1, 12)]).

make(A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11,A12) ->
    R = #big{f2=A1,f3=A2,f4=A3,f5=A4,f6=A5,f7=A6,f8=A7,f9=A8,f10=A9,f11=A10,f12=A11,f13=A12,
             f15=lists:seq(1,3),f16={A1,A12}},
    R1 = R#big{f1=A12,f13=A1,f16=[A2|A11]},
    #big{f1=G1,f2=G2,f5=G5,f9=G9,f12=G12,f13=G13,f14=G14,f16=G16} = R1,
    {R, R1, {G1,G2,G5,G9,G12,G13,G14,G16}, {A1,A2,A3,A4,A5,A6,A7,A8,A9,A10,A11,A12}}.

loop_gc() -> {loop(20000, []), [#s{a=I} || I <- lists:seq(1, 200)]}.

loop(0, Acc) -> Acc;
loop(N, Acc) ->
    S = #s{a=N},
    S2 = S#s{b=[N|Acc]},
    #s{a=A,b=B} = S2,
    loop(N-1, [A+length(B)|lists:sublist(Acc, 5)]).

external_ops() ->
    V = rj_def:vector(),
    external(V).

external(V) ->
    V2 = V#rj_def:vector{y = 5},
    V3 = #rj_def:vector{z = id(9)},
    #rj_def:vector{x = X, z = Z} = V2,
    {V, V2, V3, X, Z, V2#rj_def:vector.y, V3#rj_def:vector.z,
     records:get_name(V), records:is_exported(V)}.

errors() ->
    V = rj_def:vector(),
    L = loc(),
    N = id(not_a_record),
    {err(fun() -> V#rj_def:vector{zzz = 1} end),
     err(fun() -> V#rj_def:vector.zzz end),
     err(fun() -> N#rj_def:vector.x end),
     err(fun() -> L#loc.zzz end),
     err(fun() -> N#loc.x end),
     err(fun() -> #rj_def:hidden{} end),
     err(fun() -> (id(rj_def:sealed()))#rj_def:hidden.a end),
     err(fun() -> L#loc{x = 1, zzz = 2} end)}.

loc() -> #loc{x = id(3)}.

canonical() ->
    erts_debug:set_internal_state(available_internal_state, true),
    Records = [loc(), id(#nodef{a = 1}), rj_def:vector()],
    Bin = term_to_binary(Records),
    R = [{R1 =:= R2, def(R1) =:= def(R2), erts_debug:same(def(R1), def(R2))}
         || R1 <- Records && R2 <- binary_to_term(Bin)],
    erts_debug:set_internal_state(available_internal_state, false),
    R.

def(R) -> erts_debug:get_internal_state({native_record_def, R}).

accessible() ->
    Sealed = rj_def:sealed(),
    {records:get_name(Sealed), records:is_exported(Sealed), err(fun() -> Sealed#rj_def:hidden.a end),
     records:get_name(loc())}.
"#;

fn compare(function: &str) {
    let _lock = TEST_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping native record differential test");
        return;
    };
    let definition = reference
        .compile_named("rj_def", DEFINITION, &[])
        .expect("compile definition fixture");
    let probe = reference
        .compile_named("rj_probe", PROBE, &[])
        .expect("compile probe fixture");
    reference
        .load("rj_def", &definition)
        .expect("load reference definition");
    reference
        .load("rj_probe", &probe)
        .expect("load reference probe");
    let expected = reference.call("rj_probe", function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&definition).expect("load VM definition");
    vm.load_bytes(&probe).expect("load VM probe");
    let actual = vm
        .eval_scheduled("rj_probe", function, &[], 2, None)
        .unwrap_or_else(|error| panic!("{function}: {error}"));
    assert_eq!(expected, CallResult::Ok(actual.term), "{function}");
}

#[test]
fn many_live_registers_create_update_and_extract() {
    compare("many_registers");
}

#[test]
fn record_updates_survive_collections() {
    compare("loop_gc");
}

#[test]
fn external_records_in_native_code() {
    compare("external_ops");
}

#[test]
fn record_errors_in_native_code() {
    compare("errors");
}

#[test]
fn decoded_records_share_the_canonical_definition() {
    compare("canonical");
}

#[test]
fn unexported_records_are_not_accessible_from_other_modules() {
    compare("accessible");
}
