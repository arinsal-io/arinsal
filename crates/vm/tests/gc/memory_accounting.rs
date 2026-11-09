//! `erlang:memory/0,1`, `system_info(allocated_areas)` and `system_info({allocator_sizes, _})`
//! have the shapes of OTP 29.1.1, the totals add up as erts_memory defines them, and queued
//! messages are accounted in `processes` (empty nodes use `MSG_REF`; nodes with combined heap
//! fragments use `MSG` blocks of eheap_alloc).
use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};
use arinsal_vm::{Vm, VmError};

const SOURCE: &str = r#"
-module(vm_memory_accounting).
-export([shapes/0, relations/0, messages/0]).

shapes() ->
    Mem = erlang:memory(),
    Areas = erlang:system_info(allocated_areas),
    Allocs = erlang:system_info(alloc_util_allocators),
    Sizes = [{A, [{N, [K || {K, _} <- I]} || {instance, N, I} <- erlang:system_info({allocator_sizes, A}), N =:= 0]}
             || A <- Allocs],
    {[K || {K, _} <- Mem],
     [list_to_tuple([element(1, E), tuple_size(E)]) || E <- Areas],
     Allocs,
     Sizes}.

relations() ->
    M = erlang:memory(),
    Get = fun(K) -> proplists:get_value(K, M) end,
    Total = Get(total), Procs = Get(processes), Sys = Get(system),
    [Total >= Get(atom),
     Procs =< Total,
     Get(processes_used) =< Procs,
     Get(atom_used) =< Get(atom),
     Sys =:= Total - Procs,
     Total >= Get(binary) + Get(code) + Get(ets),
     erlang:memory(total) > 0,
     lists:sort([K || {K, _} <- erlang:memory([total, processes, binary])]) =:= [binary, processes, total]].

messages() ->
    N = 20000,
    P = spawn(fun() -> receive stop -> ok end end),
    erlang:garbage_collect(),
    Before = erlang:memory(processes),
    lists:foreach(fun(_) -> P ! ok end, lists:seq(1, N)),
    After = erlang:memory(processes),
    {message_queue_len, Len} = erlang:process_info(P, message_queue_len),
    P ! stop,
    PerMsg = (After - Before) div N,
    {Len =:= N, PerMsg >= 32, PerMsg =< 400}.
"#;

fn eval(vm: &mut Vm, function: &str) -> CallResult {
    match vm.eval_scheduled("vm_memory_accounting", function, &[], 2, None) {
        Ok(outcome) => CallResult::Ok(outcome.term),
        Err(VmError::Raised(raised)) => CallResult::Exception {
            class: format!("{:?}", raised.class).to_lowercase(),
            reason: raised.reason,
            stack_top: Some(raised.stack),
        },
        Err(error) => CallResult::TransportError(error.to_string()),
    }
}

fn run(function: &str) {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping memory accounting differential test");
        return;
    };
    let beam = reference
        .compile_named("vm_memory_accounting", SOURCE, &[])
        .unwrap();
    reference.load("vm_memory_accounting", &beam).unwrap();
    let expected = reference.call("vm_memory_accounting", function, &[]);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = eval(&mut vm, function);
    compare(&expected, &actual, CompareMode::Exact)
        .unwrap_or_else(|error| panic!("{function}: {error}"));
}

#[test]
fn memory_and_allocator_shapes_match_otp() {
    run("shapes");
}

#[test]
fn memory_totals_add_up_like_erts_memory() {
    run("relations");
}

#[test]
fn queued_messages_are_accounted_in_processes() {
    run("messages");
}
