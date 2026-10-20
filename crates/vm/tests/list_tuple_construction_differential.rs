use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm as O;
use arinsal_term::{VecHeap, from_owned};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(list_tuple_construction_differential).
-export([run/2]).

run(Function, Args) ->
    try apply(erlang, Function, Args) of
        Value -> {ok, Value}
    %% Only the BIF frame: caller frames carry checkout-dependent file paths.
    catch Class:Reason:Stack -> {Class, Reason, [F || {erlang, _, _, _} = F <- Stack]}
    end.

"#;

fn server_frame_source() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("VM crate is under crates/")
        .join("difftest/../../tools/difftest/difftest_server.erl");
    let source = include_str!("../../../tools/difftest/difftest_server.erl").replacen(
        "-export([main/0]).\n\n-record",
        &format!(
            "-export([main/0, test_call/2]).\n-file(\"{}\", 3).\n-record",
            path.display()
        ),
        1,
    );
    format!(
        r#"{source}
test_call(Function, Args) ->
    Fun = fun() -> list_tuple_construction_differential:run(Function, Args) end,
    State = start_worker(test_call, Fun, [], #state{{}}),
    [{{Ref, {{test_call, Pid, Timer}}}}] = maps:to_list(State#state.active),
        receive
            {{worker, Ref, {{ok, Value}}}} ->
                erlang:cancel_timer(Timer),
            erlang:demonitor(Ref, [flush]),
            Value;
        {{worker, Ref, Response}} -> Response;
        {{'DOWN', Ref, process, Pid, Reason}} -> {{exception, exit, Reason, undefined}}
        after 5000 ->
        exit(Pid, kill),
        timeout
    end.
"#
    )
}

fn call_vm(vm: &mut Vm, function: &str, args: &[O]) -> CallResult {
    let mut heap = VecHeap::new();
    let function = from_owned(&O::atom(function), &mut heap).expect("function atom");
    let args = from_owned(&O::list(args.to_vec()), &mut heap).expect("argument list");
    match vm.eval_scheduled(
        "difftest_server",
        "test_call",
        &[function, args],
        1,
        Some(0xD1FF),
    ) {
        Ok(outcome) => CallResult::Ok(outcome.term),
        Err(error) => CallResult::TransportError(error.to_string()),
    }
}

fn assert_matches(reference: &RefErl, vm: &mut Vm, function: &str, args: Vec<O>) {
    let expected_args = [O::atom(function), O::list(args.clone())];
    let expected = reference.call(
        "list_tuple_construction_differential",
        "run",
        &expected_args,
    );
    let actual = call_vm(vm, function, &args);
    similar_asserts::assert_eq!(actual, expected, "erlang:{function} with {args:?}");
}

#[test]
fn tuple_construction_bifs_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping tuple construction differential cases");
        return;
    };
    let beam = reference
        .compile_named("list_tuple_construction_differential", SOURCE, &[])
        .expect("compile differential wrapper");
    let server_frame = reference
        .compile_named("difftest_server", &server_frame_source(), &[])
        .expect("compile test caller frame");
    reference
        .load("list_tuple_construction_differential", &beam)
        .expect("load reference wrapper");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load test wrapper");
    vm.load_bytes(&server_frame)
        .expect("load test caller frame");

    for (function, args) in [
        ("list_to_tuple", vec![O::Nil]),
        (
            "list_to_tuple",
            vec![O::list(vec![
                O::atom("a"),
                O::Int(7),
                O::Tuple(vec![O::Int(2)]),
            ])],
        ),
        (
            "list_to_tuple",
            vec![O::List {
                elems: vec![O::Int(1), O::atom("x")],
                tail: Box::new(O::atom("tail")),
            }],
        ),
        ("list_to_tuple", vec![O::atom("not_a_list")]),
        ("make_tuple", vec![O::Int(0), O::atom("fill")]),
        ("make_tuple", vec![O::Int(3), O::atom("fill")]),
        ("make_tuple", vec![O::Int(-1), O::atom("fill")]),
        (
            "make_tuple",
            vec![
                O::Int(3),
                O::atom("fill"),
                O::list(vec![O::Tuple(vec![O::Int(2), O::atom("updated")])]),
            ],
        ),
        (
            "make_tuple",
            vec![
                O::Int(3),
                O::atom("fill"),
                O::list(vec![O::Tuple(vec![O::Int(4), O::atom("out_of_range")])]),
            ],
        ),
        (
            "make_tuple",
            vec![
                O::Int(3),
                O::atom("fill"),
                O::list(vec![O::atom("not_a_pair")]),
            ],
        ),
        (
            "append_element",
            vec![O::Tuple(vec![O::atom("a"), O::Int(2)]), O::atom("tail")],
        ),
        (
            "append_element",
            vec![O::Tuple(Vec::new()), O::atom("first")],
        ),
        ("append_element", vec![O::atom("not_a_tuple"), O::Int(1)]),
    ] {
        assert_matches(&reference, &mut vm, function, args);
    }

    let long = O::list((0..4096).map(O::Int).collect());
    assert_matches(&reference, &mut vm, "list_to_tuple", vec![long]);
    assert_matches(
        &reference,
        &mut vm,
        "append_element",
        vec![O::Tuple((0..2048).map(O::Int).collect()), O::atom("last")],
    );
}
