use std::collections::BTreeMap;
use std::process::Command;

use arinsal_args::{ArgsError, Limit, SchedulerCount, TimeWarp, parse};

fn environment() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("ROOTDIR".into(), "/otp/from-wrapper".into()),
        ("BINDIR".into(), "/otp/from-wrapper/erts-17.1/bin".into()),
        ("PROGNAME".into(), "erl".into()),
        ("HOME".into(), "/home/test".into()),
    ])
}

#[test]
fn typed_emulator_flags_and_launch_metadata() {
    let argv = [
        "erl",
        "+S",
        "4:3",
        "+SDcpu",
        "2:1",
        "+SDio",
        "3",
        "+P",
        "2000000",
        "+Q",
        "100000",
        "+t",
        "8192",
        "+hms",
        "233",
        "+hmbs",
        "464",
        "+zdbbl",
        "1024",
        "+C",
        "multi_time_warp",
        "+c",
        "true",
        "+Zsim",
        "42",
        "+Spool",
        "batch:2,3",
        "-boot",
        "start",
        "-mode",
        "embedded",
        "-noshell",
        "-sname",
        "worker",
        "-env",
        "PORT",
        "4321",
    ];
    let launch = parse(&argv, &environment()).unwrap();
    assert_eq!(
        launch.emulator.schedulers,
        Some(SchedulerCount {
            total: 4,
            online: Some(3)
        })
    );
    assert_eq!(
        launch.emulator.dirty_cpu_schedulers,
        Some(SchedulerCount {
            total: 2,
            online: Some(1)
        })
    );
    assert_eq!(launch.emulator.dirty_io_schedulers, Some(3));
    assert_eq!(launch.emulator.process_limit, Some(Limit::Value(2_000_000)));
    assert_eq!(launch.emulator.port_limit, Some(Limit::Value(100_000)));
    assert_eq!(launch.emulator.atom_limit, Some(8192));
    assert_eq!(launch.emulator.min_heap_size, Some(233));
    assert_eq!(launch.emulator.min_binary_heap_size, Some(464));
    assert_eq!(launch.emulator.distribution_buffer_busy_limit, Some(1024));
    assert_eq!(launch.emulator.time_warp, Some(TimeWarp::Multi));
    assert_eq!(launch.emulator.time_correction, Some(true));
    assert_eq!(launch.emulator.simulation_seed, Some(42));
    assert_eq!(launch.emulator.core_pools[0].name, "batch");
    assert_eq!(launch.emulator.core_pools[0].cpus, [2, 3]);
    assert_eq!(launch.boot_script.as_deref(), Some("start"));
    assert_eq!(launch.mode.as_deref(), Some("embedded"));
    assert!(launch.noshell);
    assert_eq!(launch.sname.as_deref(), Some("worker"));
    assert_eq!(launch.set_env.get("PORT").map(String::as_str), Some("4321"));
    assert!(launch.init.get_argument("env").is_none());
}

#[test]
fn source_order_and_plain_arguments() {
    let mut env = environment();
    env.insert("ERL_AFLAGS".into(), "-mark a -extra aflag".into());
    env.insert("ERL_FLAGS".into(), "-mark flags -extra zed".into());
    env.insert("ERL_ZFLAGS".into(), "-mark zflags".into());
    let launch = parse(&["erl", "-mark", "cli", "-extra", "one", "two"], &env).unwrap();
    let marks = launch.init.get_argument("mark").unwrap();
    assert_eq!(
        marks.iter().map(|v| v[0].as_str()).collect::<Vec<_>>(),
        ["a", "cli", "flags", "zflags"]
    );
    assert_eq!(launch.init.plain_args, ["aflag", "one", "two", "zed"]);
}

#[test]
fn rejects_unknown_and_invalid_emulator_options() {
    let env = environment();
    assert!(matches!(
        parse(&["erl", "+unknown"], &env),
        Err(ArgsError::UnknownEmulatorFlag(_))
    ));
    assert!(matches!(
        parse(&["erl", "+#", "1"], &env),
        Err(ArgsError::UnknownEmulatorFlag(_))
    ));
    assert!(matches!(
        parse(&["erl", "+Mfoo", "1"], &env),
        Err(ArgsError::UnknownEmulatorFlag(_))
    ));
    assert!(matches!(
        parse(&["erl", "+JPunknown", "true"], &env),
        Err(ArgsError::UnknownEmulatorFlag(_))
    ));
    assert!(matches!(
        parse(&["erl", "+P", "1"], &env),
        Err(ArgsError::InvalidValue { .. })
    ));
    assert!(matches!(
        parse(&["erl", "+t", "1"], &env),
        Err(ArgsError::InvalidValue { .. })
    ));
    assert!(matches!(
        parse(&["erl", "+S"], &env),
        Err(ArgsError::MissingValue(_))
    ));
    assert!(matches!(
        parse(&["erl", "-make"], &env),
        Err(ArgsError::UnsupportedOption(_))
    ));
}

#[test]
fn accepted_ignored_flags_are_reported() {
    let launch = parse(
        &[
            "erl", "+A", "8", "+K", "true", "+sbt", "db", "+Muas", "ageffcbf", "+JPcover", "false",
            "+fnu", "+ec", "+B", "i", "+L", "+v",
        ],
        &environment(),
    )
    .unwrap();
    assert_eq!(launch.emulator.ignored.len(), 10);
    assert_eq!(launch.emulator.ignored[7].value.as_deref(), Some("i"));
    assert_eq!(launch.emulator.warnings().len(), 8);
    assert!(
        launch
            .emulator
            .warnings()
            .iter()
            .all(|warning| !warning.starts_with("+A ") && !warning.starts_with("+M"))
    );
    assert_eq!(
        parse(&["erl", "+SP", "50:50"], &environment())
            .unwrap()
            .emulator
            .ignored[0]
            .name,
        "+SP"
    );
}

#[test]
fn erlexec_root_override_and_optional_time_correction() {
    let mut env = environment();
    env.insert("ERL_ROOTDIR".into(), "/otp/override".into());
    let launch = parse(&["erl", "+c", "-flag", "value"], &env).unwrap();
    assert_eq!(launch.root_dir, "/otp/override");
    assert_eq!(launch.bin_dir, "/otp/override/erts-17.1/bin");
    assert_eq!(launch.emulator.time_correction, Some(false));
    assert_eq!(
        launch.init.get_argument("flag").unwrap()[0],
        &["value".to_owned()]
    );
}

#[test]
fn code_path_follows_init_grouping() {
    let launch = parse(
        &[
            "erl", "-pa", "a", "b", "-pz", "c", "-pa", "d", "-mode", "embedded", "-path", "only",
        ],
        &environment(),
    )
    .unwrap();
    let path = launch.init.code_path();
    assert_eq!(path.prepend, ["d", "a", "b"]);
    assert_eq!(path.append, ["c"]);
    assert_eq!(path.replace, Some(vec!["only".into()]));
    assert!(!path.interactive);
    assert_eq!(launch.mode.as_deref(), Some("embedded"));
}

#[test]
fn first_node_name_and_boot_script_win() {
    let launch = parse(
        &[
            "erl",
            "-sname",
            "first",
            "-sname",
            "second",
            "-boot",
            "start",
            "-boot",
            "start_sasl",
        ],
        &environment(),
    )
    .unwrap();
    assert_eq!(launch.sname.as_deref(), Some("first"));
    assert_eq!(launch.boot_script.as_deref(), Some("start"));
}

#[test]
fn dirty_cpu_zero_is_accepted_and_not_applied_as_a_warning() {
    let launch = parse(
        &[
            "erl", "+SDcpu", "0", "+sbwt", "none", "+MBas", "aobf", "+hms", "233", "+A", "0",
        ],
        &environment(),
    )
    .unwrap();
    assert_eq!(launch.emulator.dirty_cpu_schedulers.unwrap().total, 0);
    assert_eq!(launch.emulator.min_heap_size, Some(233));
    assert!(launch.emulator.warnings().is_empty());
    assert!(launch.init.get_argument("A").is_none());
}

#[test]
fn detached_adds_noshell_and_noinput() {
    let launch = parse(&["erl", "-detached"], &environment()).unwrap();
    assert!(launch.detached);
    assert!(launch.noshell);
    assert!(launch.init.get_argument("noinput").is_some());
}

#[test]
fn emulator_acceptance_matches_otp_for_representative_flags() {
    if Command::new("erl").arg("-version").output().is_err() {
        eprintln!(
            "skipping emulator_acceptance_matches_otp_for_representative_flags: erl is unavailable"
        );
        return;
    }
    let cases: &[&[&str]] = &[
        &["+A", "1"],
        &["+K", "true"],
        &["+ec"],
        &["+Muas", "ageffcbf"],
        &["+JPcover", "false"],
        &["+fnu"],
        &["+B", "i"],
        &["+L"],
        &["+v"],
        &["+H"],
        &["+pc", "unicode"],
        &["+hms", "233"],
        &["+hmbs", "464"],
        &["+zdbbl", "1024"],
        &["+S", "4:4"],
        &["+Q", "100000"],
        &["+#", "1"],
        &["+Mfoo", "1"],
        &["+JPunknown", "true"],
        &["+sunknown", "1"],
        &["+bad"],
        &["+P", "1"],
        &["+Q", "1"],
    ];
    for options in cases {
        let mut argv = vec!["erl"];
        argv.extend_from_slice(options);
        let parsed = parse(&argv, &environment());
        let actual = Command::new("erl")
            .args(["-noshell", "-eval", "halt()."])
            .args(*options)
            .env("ERL_AFLAGS", "")
            .env("ERL_FLAGS", "")
            .env("ERL_ZFLAGS", "")
            .env("ERL_CRASH_DUMP", "/dev/null")
            .output()
            .unwrap();
        assert_eq!(
            parsed.is_ok(),
            actual.status.success(),
            "{options:?}: {}",
            String::from_utf8_lossy(&actual.stderr)
        );
    }
}
