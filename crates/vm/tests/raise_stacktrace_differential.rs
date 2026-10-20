use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm;
use arinsal_term::{Term, VecHeap, from_owned, to_owned};
use arinsal_vm::Vm;

const SOURCE: &str = r#"
-module(raise_stacktrace_differential).
-export([explicit/0, limited/1, invalid_frame/0, error3_none/2, error3_list/2, error3_empty/2]).

explicit() ->
    try erlang:raise(error, reason,
                     [{legacy_module, legacy_function, 2},
                      {modern_module, modern_function, 1,
                       [{file, "trace.erl"}, {line, 7}]}])
    catch Class:Reason:Stack -> {Class, Reason, Stack}
    end.

limited(Depth) ->
    Old = erlang:system_flag(backtrace_depth, Depth),
    try explicit()
    after erlang:system_flag(backtrace_depth, Old)
    end.

invalid_frame() -> erlang:raise(error, reason, [invalid_frame]).

error3_none(_Left, _Right) ->
    try erlang:error(reason, none, [{error_info, #{module => raise_stacktrace_differential}}])
    catch error:reason:Stack -> hd(Stack)
    end.

error3_list(Left, Right) ->
    try erlang:error(reason, [Left, Right], [{error_info, #{module => raise_stacktrace_differential}}])
    catch error:reason:Stack -> hd(Stack)
    end.

error3_empty(_Left, _Right) ->
    try erlang:error(reason, [], [{error_info, #{module => raise_stacktrace_differential}}])
    catch error:reason:Stack -> hd(Stack)
    end.
"#;

fn vm_call(vm: &mut Vm, function: &str, args: &[OwnedTerm]) -> CallResult {
    let mut heap = VecHeap::new();
    let args = args
        .iter()
        .map(|arg| from_owned(arg, &mut heap).expect("test argument"))
        .collect::<Vec<Term>>();
    match vm.eval("raise_stacktrace_differential", function, &args) {
        Ok(outcome) => CallResult::Ok(to_owned(outcome.term).expect("test result")),
        Err(error) => CallResult::TransportError(error.to_string()),
    }
}

#[test]
fn legacy_raise_frames_and_depth_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping raise stacktrace differential test");
        return;
    };
    let beam = reference
        .compile_named("raise_stacktrace_differential", SOURCE, &[])
        .expect("compile raise_stacktrace_differential");
    reference
        .load("raise_stacktrace_differential", &beam)
        .expect("load raise_stacktrace_differential");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load test module");

    for function in ["explicit", "invalid_frame"] {
        let expected = reference.call("raise_stacktrace_differential", function, &[]);
        let actual = vm_call(&mut vm, function, &[]);
        similar_asserts::assert_eq!(actual, expected, "{function}");
    }
    for depth in [0, 1, 2, 8] {
        let args = [OwnedTerm::Int(depth)];
        let expected = reference.call("raise_stacktrace_differential", "limited", &args);
        let actual = vm_call(&mut vm, "limited", &args);
        similar_asserts::assert_eq!(actual, expected, "backtrace_depth={depth}");
    }
}

#[test]
fn error_three_argument_frames_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping error/3 stacktrace differential test");
        return;
    };
    let beam = reference
        .compile_named("raise_stacktrace_differential", SOURCE, &[])
        .expect("compile raise_stacktrace_differential");
    reference
        .load("raise_stacktrace_differential", &beam)
        .expect("load raise_stacktrace_differential");
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).expect("load test module");
    let args = [OwnedTerm::Int(11), OwnedTerm::Int(22)];

    for function in ["error3_none", "error3_list", "error3_empty"] {
        let expected = reference.call("raise_stacktrace_differential", function, &args);
        let actual = vm_call(&mut vm, function, &args);
        similar_asserts::assert_eq!(actual, expected, "{function}");
    }
}
