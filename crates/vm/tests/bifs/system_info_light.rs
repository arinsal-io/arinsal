//! `erlang:system_info/1` and the `dt_*_tag` BIFs must give what `erl` gives: the process-only
//! items, the table items, the error cases, and repeated calls that allocate across garbage
//! collections.

use arinsal_difftest::{CallResult, RefErl};
use similar_asserts::assert_eq;

const SOURCE: &str = r#"
-module(system_info_light).
-export([items/0, one/1, errors/0, tags/0, churn/1, constants/0, shapes/0, added_keys/0, added_shapes/0, snifs/0, clock_sources/0]).
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
one(Key) -> erlang:system_info(Key).
errors() ->
    Bad = [thread_support, async_threads, no_such_item,
           definitely_not_a_system_info_key, 1, "otp_release"],
    [element(1, catch erlang:system_info(K)) || K <- Bad].
tags() ->
    {erlang:dt_spread_tag(true), erlang:dt_spread_tag(false),
     element(1, catch erlang:dt_spread_tag(other)), erlang:dt_restore_tag(true),
     element(1, catch erlang:dt_restore_tag(false)), element(1, catch erlang:dt_restore_tag(1)),
     erlang:dt_get_tag(), erlang:dt_get_tag_data(), erlang:dt_put_tag(<<"tag">>),
     erlang:dt_put_tag(undefined), erlang:dt_put_tag(not_a_binary),
     erlang:dt_put_tag([a | b]), erlang:dt_prepend_vm_tag_data(a),
     erlang:dt_prepend_vm_tag_data(<<"x">>), erlang:dt_append_vm_tag_data([a | b]),
     erlang:dt_append_vm_tag_data(1)}.
constants() ->
    Keys = [start_time, break_ignored, async_dist, eager_check_io, dynamic_trace,
            dynamic_trace_probes, c_compiler_used, delayed_node_table_gc, dist_buf_busy_limit],
    End = erlang:system_info(end_time),
    % A bignum: compared in Erlang, as the OwnedTerm of an i64-sized bignum differs by decoder.
    [{end_time, End =:= 8646911283000000000, is_integer(End)}
     | [{K, erlang:system_info(K)} || K <- Keys]].
shapes() ->
    Mono = erlang:monotonic_time(),
    Start = erlang:system_info(start_time),
    {is_integer(erlang:system_info(atom_count)) andalso erlang:system_info(atom_count) > 1000,
     erlang:system_info(port_count) =:= length(erlang:ports()),
     erlang:system_info(port_count) >= 1,
     is_integer(erlang:system_info(ethread_used_tse)),
     Mono >= Start andalso Mono - Start < 600000000000}.
churn(0) -> ok;
churn(N) ->
    "29" = erlang:system_info(otp_release),
    {unix, _} = erlang:system_info(os_type),
    {_, _, _} = erlang:system_info(os_version),
    [_ | _] = erlang:system_info(garbage_collection),
    L = erlang:system_info(system_architecture),
    true = is_list(L) andalso length(L) > 3,
    churn(N - 1).
added_keys() ->
    Keys = [io_thread, literal_test, lock_counting, port_tasks,
            scheduling_statistics, total_scheduling_statistics, thread_progress,
            update_cpu_info, reader_groups_map, decentralized_counter_groups_map, dist_ctrl,
            halt_flush_timeout, modified_timing_level],
    [{K, erlang:system_info(K)} || K <- Keys].
added_shapes() ->
    CI = erlang:system_info(compile_info),
    EP = erlang:system_info(embedded_3pps),
    Args = erlang:system_info(emu_args),
    {is_list(CI) andalso [K || {K, _} <- CI] =:= [ldflags, cflags, config_h],
     is_map(EP) andalso lists:sort(maps:keys(EP)) =:= [excluded, included],
     is_list(maps:get(included, EP)) andalso is_list(maps:get(excluded, EP)),
     is_list(Args) andalso lists:all(fun is_list/1, Args)}.
snifs() -> erlang:system_info(snifs).
clock_sources() ->
    {erlang:system_info(os_monotonic_time_source),
     erlang:system_info(os_system_time_source)}.
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
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    let actual = vm
        .eval_scheduled("system_info_light", function, vm_args, 2)
        .unwrap_or_else(|error| panic!("{function}: {error}"));
    let actual = CallResult::Ok(actual.term);
    if matches!(function, "items" | "constants") {
        compare_system_info_pairs(&expected, &actual, function == "constants");
    } else if function == "clock_sources" {
        compare_clock_sources(&expected, &actual);
    } else {
        assert_eq!(actual, expected, "{function}");
    }
}

fn compare_system_info_pairs(expected: &CallResult, actual: &CallResult, has_end_time_shape: bool) {
    let (
        CallResult::Ok(arinsal_etf::OwnedTerm::List {
            elems: expected, ..
        }),
        CallResult::Ok(arinsal_etf::OwnedTerm::List { elems: actual, .. }),
    ) = (expected, actual)
    else {
        assert_eq!(actual, expected);
        return;
    };
    assert_eq!(actual.len(), expected.len());
    let first_pair = usize::from(has_end_time_shape);
    if has_end_time_shape {
        assert_eq!(actual[0], expected[0]);
    }
    for (expected_pair, actual_pair) in expected[first_pair..].iter().zip(&actual[first_pair..]) {
        let (
            arinsal_etf::OwnedTerm::Tuple(expected_pair),
            arinsal_etf::OwnedTerm::Tuple(actual_pair),
        ) = (expected_pair, actual_pair)
        else {
            assert_eq!(actual_pair, expected_pair);
            continue;
        };
        let [arinsal_etf::OwnedTerm::Atom(expected_key), expected_value] = expected_pair.as_slice()
        else {
            assert_eq!(actual_pair, expected_pair);
            continue;
        };
        let [arinsal_etf::OwnedTerm::Atom(actual_key), actual_value] = actual_pair.as_slice()
        else {
            assert_eq!(actual_pair, expected_pair);
            continue;
        };
        assert_eq!(actual_key, expected_key);
        compare_system_info_value(expected_key, expected_value, actual_value, false);
    }
}

fn compare_system_info_value(
    key: &str,
    expected: &arinsal_etf::OwnedTerm,
    actual: &arinsal_etf::OwnedTerm,
    type_check_start_time: bool,
) {
    match key {
        "system_version" => compare_system_version(expected, actual),
        "system_architecture" => compare_architecture(expected, actual),
        "version" => compare_version(expected, actual),
        "build_type" | "emu_type" => compare_build_type(expected, actual),
        "kernel_poll" => compare_kernel_poll(expected, actual),
        "c_compiler_used" => compare_c_compiler(expected, actual),
        "start_time" if type_check_start_time => {
            assert!(matches!(expected, arinsal_etf::OwnedTerm::Int(_)));
            assert!(matches!(actual, arinsal_etf::OwnedTerm::Int(_)));
        }
        _ => similar_asserts::assert_eq!(actual, expected),
    }
}

fn stable_system_info_differential() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping stable system_info differential test");
        return;
    };
    let beam = reference
        .compile_named("system_info_light", SOURCE, &[])
        .unwrap();
    reference.load("system_info_light", &beam).unwrap();
    let mut vm = crate::common::node();
    vm.load_bytes(&beam).unwrap();
    for key in [
        "system_version",
        "otp_release",
        "version",
        "wordsize",
        "context_reductions",
        "start_time",
        "schedulers",
        "schedulers_online",
        "logical_processors",
        "logical_processors_online",
        "dirty_cpu_schedulers",
        "dirty_cpu_schedulers_online",
        "dirty_io_schedulers",
        "outstanding_system_requests_limit",
        "thread_pool_size",
        "process_limit",
        "atom_limit",
        "port_limit",
        "max_heap_size",
        "fullsweep_after",
        "min_heap_size",
        "min_bin_vheap_size",
        "os_version",
        "machine",
        "emu_flavor",
        "build_type",
        "os_type",
        "endian",
        "heap_type",
        "garbage_collection",
        "multi_scheduling",
        "system_architecture",
        "emu_type",
        "logical_processors_available",
        "ets_limit",
        "time_correction",
        "kernel_poll",
        "time_offset",
        "time_warp_mode",
        "smp_support",
        "constant_pool_support",
        "hipe_architecture",
        "ets_realloc_moves",
        "compat_rel",
    ] {
        let expected = reference.call(
            "system_info_light",
            "one",
            &[arinsal_etf::OwnedTerm::atom(key)],
        );
        let atom = arinsal_term::global_atoms()
            .intern(key)
            .expect("system_info selector atom");
        let actual = vm
            .eval_scheduled(
                "system_info_light",
                "one",
                &[arinsal_term::Term::atom(atom)],
                2,
            )
            .unwrap_or_else(|error| panic!("system_info({key}): {error}"));
        let actual = actual.term;
        let CallResult::Ok(expected) = expected else {
            panic!("reference system_info({key}) failed: {expected:?}");
        };
        compare_system_info_value(key, &expected, &actual, true);
    }
}

fn owned_charlist(value: &arinsal_etf::OwnedTerm) -> String {
    let arinsal_etf::OwnedTerm::List { elems, .. } = value else {
        panic!("expected charlist, got {value:?}");
    };
    elems
        .iter()
        .map(|item| match item {
            arinsal_etf::OwnedTerm::Int(code) => {
                char::from_u32(u32::try_from(*code).expect("non-negative character code"))
                    .expect("valid character code")
            }
            _ => panic!("expected integer character, got {item:?}"),
        })
        .collect()
}

fn compare_system_version(expected: &arinsal_etf::OwnedTerm, actual: &arinsal_etf::OwnedTerm) {
    let expected = owned_charlist(expected);
    let actual = owned_charlist(actual);
    let arinsal_label = format!("[arinsal {}] ", env!("CARGO_PKG_VERSION"));
    let expected_suffix = expected
        .split_once("[source] ")
        .map(|(_, suffix)| suffix)
        .expect("OTP system_version source label");
    let actual_suffix = actual
        .split_once(&arinsal_label)
        .map(|(_, suffix)| suffix)
        .expect("Arinsal system_version build label");
    assert!(actual.starts_with(&format!(
        "Erlang/OTP {} [erts-{}] {arinsal_label}",
        env!("ARINSAL_OTP_RELEASE"),
        env!("ARINSAL_ERTS_VERSION")
    )));
    similar_asserts::assert_eq!(actual_suffix, expected_suffix);
}

fn compare_clock_sources(expected: &CallResult, actual: &CallResult) {
    fn has_resolution(value: &arinsal_etf::OwnedTerm) -> bool {
        let arinsal_etf::OwnedTerm::List { elems, .. } = value else {
            return false;
        };
        elems.iter().any(|entry| {
            matches!(
                entry,
                arinsal_etf::OwnedTerm::Tuple(pair)
                    if matches!(pair.as_slice(), [arinsal_etf::OwnedTerm::Atom(name), arinsal_etf::OwnedTerm::Int(n)] if name == "resolution" && *n > 0)
            )
        })
    }
    let (
        CallResult::Ok(arinsal_etf::OwnedTerm::Tuple(expected)),
        CallResult::Ok(arinsal_etf::OwnedTerm::Tuple(actual)),
    ) = (expected, actual)
    else {
        panic!("clock source tuple format: {expected:?} / {actual:?}");
    };
    assert_eq!(expected.len(), 2);
    assert_eq!(actual.len(), 2);
    for source in expected.iter().chain(actual) {
        assert!(
            has_resolution(source),
            "clock source missing resolution: {source:?}"
        );
    }
}

fn compare_architecture(expected: &arinsal_etf::OwnedTerm, actual: &arinsal_etf::OwnedTerm) {
    let expected = owned_charlist(expected);
    let actual = owned_charlist(actual);
    assert_eq!(actual, env!("ARINSAL_SYSTEM_ARCHITECTURE"));
    assert_eq!(architecture_parts(&actual), architecture_parts(&expected));
}

fn architecture_parts(value: &str) -> (&str, &str, String) {
    let mut parts = value.splitn(3, '-');
    let cpu = parts.next().expect("architecture CPU");
    let vendor = parts.next().expect("architecture vendor");
    let os = parts.next().expect("architecture OS");
    (
        cpu,
        vendor,
        os.chars().take_while(char::is_ascii_alphabetic).collect(),
    )
}

fn compare_version(expected: &arinsal_etf::OwnedTerm, actual: &arinsal_etf::OwnedTerm) {
    let expected = owned_charlist(expected);
    let actual = owned_charlist(actual);
    assert_eq!(actual, env!("ARINSAL_ERTS_VERSION"));
    assert!(is_version(&actual));
    assert!(is_version(&expected));
}

fn is_version(value: &str) -> bool {
    !value.is_empty()
        && value
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn compare_build_type(expected: &arinsal_etf::OwnedTerm, actual: &arinsal_etf::OwnedTerm) {
    assert_eq!(
        actual,
        &arinsal_etf::OwnedTerm::Atom(env!("ARINSAL_BUILD_TYPE").into())
    );
    assert!(matches!(expected, arinsal_etf::OwnedTerm::Atom(_)));
}

fn compare_kernel_poll(expected: &arinsal_etf::OwnedTerm, actual: &arinsal_etf::OwnedTerm) {
    let built = if env!("ARINSAL_KERNEL_POLL") == "true" {
        "true"
    } else {
        "false"
    };
    assert_eq!(actual, &arinsal_etf::OwnedTerm::Atom(built.into()));
    assert!(matches!(
        expected,
        arinsal_etf::OwnedTerm::Atom(name) if name == "true" || name == "false"
    ));
}

fn compare_c_compiler(expected: &arinsal_etf::OwnedTerm, actual: &arinsal_etf::OwnedTerm) {
    let (arinsal_etf::OwnedTerm::Tuple(expected), arinsal_etf::OwnedTerm::Tuple(actual)) =
        (expected, actual)
    else {
        panic!("c_compiler_used tuple shape differs: {expected:?} / {actual:?}");
    };
    assert_eq!(expected.len(), 2);
    assert_eq!(actual.len(), 2);
    assert_eq!(
        actual[0],
        arinsal_etf::OwnedTerm::Atom(env!("ARINSAL_C_COMPILER").into())
    );
    assert!(matches!(expected[0], arinsal_etf::OwnedTerm::Atom(_)));
    let build_version = env!("ARINSAL_C_COMPILER_VERSION");
    if build_version == "undefined" {
        assert_eq!(actual[1], arinsal_etf::OwnedTerm::Atom("undefined".into()));
    } else {
        let expected = build_version
            .split(',')
            .map(|part| {
                arinsal_etf::OwnedTerm::Int(part.parse().expect("compiler version component"))
            })
            .collect::<Vec<_>>();
        let expected = if env!("ARINSAL_C_COMPILER") == "msc"
            || env!("ARINSAL_C_COMPILER") == "gnuc" && expected.len() == 1
        {
            expected[0].clone()
        } else {
            arinsal_etf::OwnedTerm::Tuple(expected)
        };
        assert_eq!(actual[1], expected);
    }
    assert!(matches!(
        expected[1],
        arinsal_etf::OwnedTerm::Tuple(_)
            | arinsal_etf::OwnedTerm::Int(_)
            | arinsal_etf::OwnedTerm::Atom(_)
    ));
}

#[test]
fn system_info_light_items_match_otp() {
    differential("items", &[], &[]);
}

#[test]
fn stable_system_info_matches_otp() {
    stable_system_info_differential();
}

#[test]
fn system_info_snifs_match_otp() {
    differential("snifs", &[], &[]);
}

#[test]
fn system_info_light_constant_items_match_otp() {
    differential("constants", &[], &[]);
}

#[test]
fn system_info_clock_sources_have_resolution() {
    differential("clock_sources", &[], &[]);
}

#[test]
fn system_info_light_counter_shapes_match_otp() {
    differential("shapes", &[], &[]);
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
fn system_info_added_keys_match_otp() {
    differential("added_keys", &[], &[]);
}

#[test]
fn system_info_added_metadata_shapes_match_otp() {
    differential("added_shapes", &[], &[]);
}

#[test]
fn system_info_saved_emu_args_keep_root_after_separator() {
    arinsal_args::configure_emu_args(vec![
        "arinsal".into(),
        "--".into(),
        "-root".into(),
        "/tmp".into(),
    ]);
    assert!(
        arinsal_args::active_emu_args()
            .windows(2)
            .any(|pair| pair == ["--", "-root"])
    );
}

#[test]
fn system_info_light_allocation_across_gc_matches_otp() {
    differential(
        "churn",
        &[arinsal_etf::OwnedTerm::Int(20_000)],
        &[arinsal_term::Term::small(20_000).unwrap()],
    );
}
