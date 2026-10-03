use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::{EncodeOptions, decode, encode};
use arinsal_vm::Vm;

/// binary_SUITE:error_after_yield, trimmed: a trapping BIF that fails after several yields
/// (running trace forces schedule-out/in around each) reports the original call arguments,
/// which a JIT retry must take from the trap state rather than from the X registers.
#[test]
fn trapping_bif_error_after_yield_reports_original_arguments() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping jit_trap_args differential test");
        return;
    };
    let source = r#"-module(jit_trap_args).
        -export([run/0]).
        run() -> [one(F) || F <- [l2b, iol2b, nested, b2t]].
        mk(l2b) -> [[lists:duplicate(1000000, $a), oops]];
        mk(nested) -> [[nest(300000, []), oops]];
        mk(iol2b) -> [[lists:duplicate(1000000, $a), oops]];
        mk(b2t) -> [<<131, 108, 0, 1, 0, 0, (list_to_binary(lists:duplicate(100000, 97)))/binary, 106>>].
        fn(l2b) -> list_to_binary;
        fn(iol2b) -> iolist_to_binary;
        fn(nested) -> list_to_binary;
        fn(b2t) -> binary_to_term.
        one(Kind) ->
            Tracer = self(),
            {Pid, Mon} = spawn_monitor(fun () ->
                A = mk(Kind), F = fn(Kind),
                try
                    erlang:yield(),
                    erlang:trace(self(), true, [running, {tracer, Tracer}]),
                    apply(erlang, F, A),
                    exit(unexpected_success)
                catch
                    error:badarg:Stk ->
                        erlang:trace(self(), false, [running, {tracer, Tracer}]),
                        [{erlang, F, A2, _} | _] = Stk,
                        exit({ok, A2 =:= A})
                end
            end),
            R = receive {'DOWN', Mon, process, Pid, Reason} -> Reason end,
            flush(),
            R.
        nest(0, Acc) -> Acc;
        nest(N, Acc) -> nest(N - 1, [Acc, $a]).
        flush() -> receive _ -> flush() after 0 -> ok end."#;
    let beam = reference
        .compile_named("jit_trap_args", source, &[])
        .unwrap();
    reference.load("jit_trap_args", &beam).unwrap();
    let expected = reference.call("jit_trap_args", "run", &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("jit_trap_args", "run", &[], 2, None)
        .unwrap();
    let canonical = decode(&encode(&actual.term, EncodeOptions::default())).unwrap();
    assert_eq!(expected, CallResult::Ok(canonical));
}
