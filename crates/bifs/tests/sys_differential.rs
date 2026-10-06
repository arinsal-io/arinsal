mod support;

use arinsal_difftest::{CallResult, RefErl};
use arinsal_etf::OwnedTerm as O;
use support::{call, equivalent};

#[test]
fn stable_system_info_matches_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping system_info differential test");
        return;
    };
    // D7 (docs/differences.md): the banner names Arinsal instead of `[source]`.
    let key = [O::atom("system_version")];
    let expected = reference.call("erlang", "system_info", &key);
    let actual = call("erlang", "system_info", &key);
    let text = |term: &CallResult| match term {
        CallResult::Ok(O::List { elems, .. }) => elems
            .iter()
            .map(|e| match e {
                O::Int(c) => char::from(*c as u8),
                _ => '?',
            })
            .collect::<String>(),
        other => format!("{other:?}"),
    };
    let arinsal = format!("[arinsal {}]", env!("CARGO_PKG_VERSION"));
    assert_eq!(text(&actual).replace(&arinsal, "[source]"), text(&expected));
    for key in [
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
    ] {
        let args = [O::atom(key)];
        let expected = reference.call("erlang", "system_info", &args);
        let actual = call("erlang", "system_info", &args);
        if key == "start_time" {
            assert!(matches!(actual, CallResult::Ok(O::Int(_))));
            assert!(matches!(expected, CallResult::Ok(O::Int(_))));
        } else {
            assert!(
                equivalent(&actual, &expected),
                "system_info({key}): {actual:?} != {expected:?}"
            );
        }
        if matches!(
            key,
            "otp_release"
                | "version"
                | "wordsize"
                | "context_reductions"
                | "process_limit"
                | "atom_limit"
                | "port_limit"
                | "max_heap_size"
                | "fullsweep_after"
                | "min_heap_size"
                | "min_bin_vheap_size"
                | "os_version"
                | "machine"
                | "emu_flavor"
                | "build_type"
                | "os_type"
                | "endian"
                | "heap_type"
                | "garbage_collection"
                | "multi_scheduling"
        ) {
            assert_eq!(actual, expected, "deterministic system_info({key})");
        }
    }
    let invalid = [O::atom("definitely_not_a_system_info_key")];
    assert!(matches!(
        reference.call("erlang", "system_info", &invalid),
        CallResult::Exception { .. }
    ));
    assert!(matches!(
        call("erlang", "system_info", &invalid),
        CallResult::Exception { .. }
    ));
}

#[test]
fn os_pid_and_getenv_bifs_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping os BIF differential test");
        return;
    };
    for (name, args) in [
        ("getpid", vec![]),
        ("perf_counter", vec![]),
        ("getenv", vec![O::charlist("HOME")]),
    ] {
        let expected = reference.call("os", name, &args);
        let actual = call("os", name, &args);
        if name == "getpid" || name == "perf_counter" {
            assert!(matches!(actual, CallResult::Ok(_)), "os:{name}: {actual:?}");
            assert!(
                matches!(expected, CallResult::Ok(_)),
                "reference os:{name}: {expected:?}"
            );
        } else {
            assert!(
                equivalent(&actual, &expected),
                "os:{name}: {actual:?} != {expected:?}"
            );
            assert_eq!(actual, expected, "os:{name}");
        }
    }
    // type/0, version/0, perf_counter/1, and getenv/0 are Erlang wrappers.
    // This crate-level test calls the BIF registry directly; VM-level wrapper
    // behavior is covered by the compatibility probes.
    for key in ["os_monotonic_time_source", "os_system_time_source"] {
        let actual = call("erlang", "system_info", &[O::atom(key)]);
        let CallResult::Ok(O::List { elems, .. }) = &actual else {
            panic!("{key} should be a proplist, got {actual:?}");
        };
        assert!(
            elems.iter().any(|entry| {
                matches!(
                    entry,
                    O::Tuple(pair)
                        if matches!(
                            pair.as_slice(),
                            [O::Atom(name), O::Int(n)] if name == "resolution" && *n > 0
                        )
                )
            }),
            "{key} missing resolution: {elems:?}"
        );
    }
    let invalid = [O::Int(2)];
    let expected = reference.call("os", "getenv", &invalid);
    let actual = call("os", "getenv", &invalid);
    assert!(equivalent(&actual, &expected), "os:getenv error class");
}
