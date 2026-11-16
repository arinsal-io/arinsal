use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{ProcessHeap, from_owned};
use num_traits::ToPrimitive;
use similar_asserts::assert_eq;

const MODULE: &str = "atomics_native_vm_diff";
const SOURCE: &str = r#"
-module(atomics_native_vm_diff).
-export([run/2, counters/1, overflow/0, concurrent/1, error_info/1]).

run(Signed, Ops) ->
    A = atomics:new(4, [{signed, Signed}]),
    Results = [capture(fun() -> case Op of
        {get, I} -> atomics:get(A, I);
        {put, I, V} -> atomics:put(A, I, V);
        {add, I, V} -> atomics:add(A, I, V);
        {add_get, I, V} -> atomics:add_get(A, I, V);
        {sub, I, V} -> atomics:sub(A, I, V);
        {sub_get, I, V} -> atomics:sub_get(A, I, V);
        {exchange, I, V} -> atomics:exchange(A, I, V);
        {compare, I, E, D} -> atomics:compare_exchange(A, I, E, D)
    end end) || Op <- Ops],
    {Results, atomics:info(A)}.

counters(Mode) ->
    C = counters:new(4, [Mode]),
    ok = counters:add(C, 1, 10),
    ok = counters:sub(C, 1, 3),
    ok = counters:put(C, 2, -8),
    {counters:get(C, 1), counters:get(C, 2), counters:info(C),
     capture(fun() -> counters:get(C, 0) end),
     capture(fun() -> counters:add(C, 1, 1.5) end)}.

overflow() ->
    {capture(fun() -> erts_internal:atomics_new(1 bsl 64, 0) end),
     capture(fun() -> erts_internal:counters_new(1 bsl 64) end)}.

concurrent(Mode) ->
    Parent = self(),
    Ref = case Mode of
        atomics -> atomics:new(1, []);
        counter_atomics -> counters:new(1, [atomics]);
        _ -> counters:new(1, [Mode])
    end,
    Workers = [spawn(fun() -> concurrent_add(Mode, Ref, 1000000), Parent ! done end)
               || _ <- lists:seq(1, 8)],
    wait(length(Workers)),
    case Mode of
        atomics -> atomics:get(Ref, 1);
        _ -> counters:get(Ref, 1)
    end.

error_info(Mode) ->
    case Mode of
        atomics -> capture_info(fun() -> atomics:new(0, []) end);
        counters -> capture_info(fun() -> counters:new(0, [write_concurrency]) end)
    end.

capture(F) -> try {ok, F()} catch Class:Reason -> {exception, Class, Reason} end.
capture_info(F) ->
    try F() of Value -> Value
    catch error:Reason:Stack ->
        {Reason, proplists:get_value(error_info, element(4, hd(Stack))),
         erl_error:format_exception(error, Reason, Stack)}
    end.

concurrent_add(_Mode, _Ref, 0) -> ok;
concurrent_add(atomics, Ref, N) -> atomics:add(Ref, 1, 1), concurrent_add(atomics, Ref, N - 1);
concurrent_add(Mode, Ref, N) -> counters:add(Ref, 1, 1), concurrent_add(Mode, Ref, N - 1).

wait(0) -> ok;
wait(N) -> receive done -> wait(N - 1) end.
"#;

#[derive(Clone, Copy)]
enum Op {
    Get(usize),
    Put(usize, i64),
    Add(usize, i64),
    AddGet(usize, i64),
    Sub(usize, i64),
    SubGet(usize, i64),
    Exchange(usize, i64),
    Compare(usize, i64, i64),
    InvalidIndex,
    InvalidValue,
}

fn random_ops() -> Vec<Op> {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    (0..5_000)
        .map(|n| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let index = (state as usize % 4) + 1;
            let value = ((state >> 16) as i32 as i64) % 10_000;
            match n % 29 {
                0 => Op::InvalidIndex,
                1 => Op::InvalidValue,
                _ => match state % 8 {
                    0 => Op::Get(index),
                    1 => Op::Put(index, value),
                    2 => Op::Add(index, value),
                    3 => Op::AddGet(index, value),
                    4 => Op::Sub(index, value),
                    5 => Op::SubGet(index, value),
                    6 => Op::Exchange(index, value),
                    _ => Op::Compare(index, value, value.wrapping_add(1)),
                },
            }
        })
        .collect()
}

fn owned_ops(ops: &[Op]) -> O {
    O::List {
        elems: ops
            .iter()
            .map(|op| match op {
                Op::Get(i) => O::Tuple(vec![O::atom("get"), O::Int(*i as i64)]),
                Op::Put(i, v) => O::Tuple(vec![O::atom("put"), O::Int(*i as i64), O::Int(*v)]),
                Op::Add(i, v) => O::Tuple(vec![O::atom("add"), O::Int(*i as i64), O::Int(*v)]),
                Op::AddGet(i, v) => {
                    O::Tuple(vec![O::atom("add_get"), O::Int(*i as i64), O::Int(*v)])
                }
                Op::Sub(i, v) => O::Tuple(vec![O::atom("sub"), O::Int(*i as i64), O::Int(*v)]),
                Op::SubGet(i, v) => {
                    O::Tuple(vec![O::atom("sub_get"), O::Int(*i as i64), O::Int(*v)])
                }
                Op::Exchange(i, v) => {
                    O::Tuple(vec![O::atom("exchange"), O::Int(*i as i64), O::Int(*v)])
                }
                Op::Compare(i, e, d) => O::Tuple(vec![
                    O::atom("compare"),
                    O::Int(*i as i64),
                    O::Int(*e),
                    O::Int(*d),
                ]),
                Op::InvalidIndex => O::Tuple(vec![O::atom("get"), O::Int(0)]),
                Op::InvalidValue => {
                    O::Tuple(vec![O::atom("put"), O::Int(1), O::atom("not_an_integer")])
                }
            })
            .collect(),
        tail: Box::new(O::Nil),
    }
}

fn setup() -> (&'static RefErl, Vec<u8>) {
    let reference = RefErl::shared().expect("OTP 29 reference node");
    let beam = reference.compile_named(MODULE, SOURCE, &[]).unwrap();
    reference.load(MODULE, &beam).unwrap();
    (reference, beam)
}

fn reference_call(reference: &RefErl, function: &str, args: &[O]) -> O {
    match reference.call(MODULE, function, args) {
        CallResult::Ok(value) => normalize(value),
        other => panic!("reference {function} failed: {other:?}"),
    }
}

fn vm_call(beam: &[u8], function: &str, args: &[O]) -> O {
    let mut heap = ProcessHeap::with_words(150_000);
    let args = args
        .iter()
        .map(|arg| from_owned(arg, &mut heap).unwrap())
        .collect::<Vec<_>>();
    let mut vm = crate::common::node();
    vm.load_bytes(beam).unwrap();
    let result = vm
        .eval_scheduled(MODULE, function, &args, 1)
        .unwrap_or_else(|error| panic!("VM {function} failed: {error:?}"));
    normalize(result.term)
}

fn normalize(term: O) -> O {
    match &term {
        O::BigInt(value) => value.to_i64().map_or_else(|| term, O::Int),
        O::List { elems, tail } => O::List {
            elems: elems.iter().cloned().map(normalize).collect(),
            tail: Box::new(normalize((**tail).clone())),
        },
        O::Tuple(values) => O::Tuple(values.iter().cloned().map(normalize).collect()),
        O::Map(entries) => O::Map(
            entries
                .iter()
                .map(|(key, value)| (normalize(key.clone()), normalize(value.clone())))
                .collect(),
        ),
        _ => term,
    }
}

#[test]
fn atomics_operations_errors_and_info_match_otp() {
    let (reference, beam) = setup();
    let ops = owned_ops(&random_ops());
    for signed in [true, false] {
        let args = [O::atom(if signed { "true" } else { "false" }), ops.clone()];
        assert_eq!(
            vm_call(&beam, "run", &args),
            reference_call(reference, "run", &args),
            "signed={signed}"
        );
    }
}

#[test]
fn counters_modes_values_errors_and_memory_match_otp() {
    let (reference, beam) = setup();
    for mode in ["atomics", "write_concurrency"] {
        let args = [O::atom(mode)];
        assert_eq!(
            vm_call(&beam, "counters", &args),
            reference_call(reference, "counters", &args),
            "mode={mode}"
        );
    }
}

#[test]
fn array_size_overflow_matches_otp() {
    let (reference, beam) = setup();
    assert_eq!(
        vm_call(&beam, "overflow", &[]),
        reference_call(reference, "overflow", &[])
    );
}

#[test]
fn concurrent_atomic_and_sharded_counter_updates_match_otp() {
    let (reference, beam) = setup();
    for mode in ["atomics", "counter_atomics", "write_concurrency"] {
        let args = [O::atom(mode)];
        assert_eq!(
            vm_call(&beam, "concurrent", &args),
            reference_call(reference, "concurrent", &args),
            "mode={mode}"
        );
    }
}

#[test]
fn atomics_and_counters_error_info_match_otp() {
    let (reference, beam) = setup();
    for mode in ["atomics", "counters"] {
        let args = [O::atom(mode)];
        let expected = reference_call(reference, "error_info", &args);
        let actual = vm_call(&beam, "error_info", &args);
        let (O::Tuple(expected), O::Tuple(actual)) = (&expected, &actual) else {
            panic!("error_info returned an unexpected value: {actual:?} vs {expected:?}");
        };
        assert_eq!(&actual[..2], &expected[..2]);
        let mut formatted = Vec::new();
        flatten_iodata(&actual[2], &mut formatted);
        let formatted = String::from_utf8(formatted).unwrap();
        assert!(
            formatted.contains("*** argument 1: out of range"),
            "{mode}: {formatted}"
        );
    }
}

fn flatten_iodata(term: &O, output: &mut Vec<u8>) {
    match term {
        O::Int(value) if (0..=255).contains(value) => output.push(*value as u8),
        O::List { elems, tail } => {
            for item in elems {
                flatten_iodata(item, output);
            }
            flatten_iodata(tail, output);
        }
        O::Nil => {}
        O::Binary(bytes) => output.extend_from_slice(bytes),
        other => panic!("invalid iodata item: {other:?}"),
    }
}
