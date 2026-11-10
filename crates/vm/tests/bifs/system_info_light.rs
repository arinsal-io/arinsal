//! `erlang:system_info/1` and the `dt_*_tag` BIFs answered from the generated code must give what
//! `erl` gives: the process-only items, the table items, the error cases, and repeated
//! calls that allocate across garbage collections.

use arinsal_difftest::{CallResult, RefErl};
use arinsal_vm::Vm;
use similar_asserts::assert_eq;

const SOURCE: &str = r#"
-module(system_info_light).
-export([items/0, errors/0, tags/0, churn/1]).
items() ->
    Keys = [otp_release, version, wordsize, context_reductions, schedulers, schedulers_total,
            schedulers_online, logical_processors, logical_processors_online,
            logical_processors_available, dirty_cpu_schedulers, dirty_cpu_schedulers_online,
            dirty_io_schedulers, outstanding_system_requests_limit, thread_pool_size,
            process_limit, port_limit, atom_limit, ets_limit, fullsweep_after, min_heap_size,
            min_bin_vheap_size, max_heap_size, garbage_collection, machine, system_architecture,
            emu_flavor, emu_type, build_type, os_type, os_version, endian, heap_type,
            multi_scheduling, time_correction, kernel_poll, time_offset, time_warp_mode,
            smp_support, threads, hipe_architecture, constant_pool_support, ets_realloc_moves,
            ets_always_compress, compat_rel, debug_compiled, lock_checking, beam_jump_table,
            nif_version, driver_version, heap_sizes, scheduler_bind_type, max_integer,
            tolerant_timeofday, port_parallelism],
    [{K, erlang:system_info(K)} || K <- Keys].
errors() ->
    Bad = [thread_support, async_threads, no_such_item, 1, "otp_release"],
    [element(1, catch erlang:system_info(K)) || K <- Bad].
tags() ->
    {erlang:dt_spread_tag(true), erlang:dt_spread_tag(false),
     element(1, catch erlang:dt_spread_tag(other)), erlang:dt_restore_tag(true),
     element(1, catch erlang:dt_restore_tag(false)), element(1, catch erlang:dt_restore_tag(1))}.
churn(0) -> ok;
churn(N) ->
    "29" = erlang:system_info(otp_release),
    {unix, _} = erlang:system_info(os_type),
    {_, _, _} = erlang:system_info(os_version),
    [_ | _] = erlang:system_info(garbage_collection),
    L = erlang:system_info(system_architecture),
    true = is_list(L) andalso length(L) > 3,
    churn(N - 1).
"#;

fn differential(function: &str, args: &[arinsal_etf::OwnedTerm], vm_args: &[arinsal_term::Term]) {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping system_info_light differential test");
        return;
    };
    let beam = reference
        .compile_named("system_info_light", SOURCE, &[])
        .unwrap();
    reference.load("system_info_light", &beam).unwrap();
    let expected = reference.call("system_info_light", function, args);
    let mut vm = Vm::new([]);
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("system_info_light", function, vm_args, 2, None)
        .unwrap_or_else(|error| panic!("{function}: {error}"));
    assert_eq!(CallResult::Ok(actual.term), expected, "{function}");
}

#[test]
fn system_info_light_items_match_otp() {
    differential("items", &[], &[]);
}

#[test]
fn system_info_light_errors_match_otp() {
    differential("errors", &[], &[]);
}

#[test]
fn system_info_light_dt_tags_match_otp() {
    differential("tags", &[], &[]);
}

#[test]
fn system_info_light_allocation_across_gc_matches_otp() {
    differential(
        "churn",
        &[arinsal_etf::OwnedTerm::Int(20_000)],
        &[arinsal_term::Term::small(20_000).unwrap()],
    );
}
