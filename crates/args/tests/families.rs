//! Each flag family must deliver the same boot vector `erl -emu_args_exit` prints.

use std::collections::BTreeMap;
use std::process::Command;

use arinsal_args::{ArgsError, parse};

fn reference_erl() -> Command {
    arinsal_difftest::reference::erl().expect("reference OTP emulator")
}

fn erl_available() -> bool {
    arinsal_difftest::reference::erl().is_some()
}

fn setup_env() -> BTreeMap<String, String> {
    let root = arinsal_difftest::reference::otp_root()
        .expect("OTP root: set ARINSAL_OTP_ROOT or put erl on PATH")
        .to_string_lossy()
        .into_owned();
    BTreeMap::from([
        ("ROOTDIR".into(), root.clone()),
        ("BINDIR".into(), format!("{root}/erts-17.1/bin")),
        ("PROGNAME".into(), "erl".into()),
        ("HOME".into(), std::env::var("HOME").unwrap_or_default()),
    ])
}

fn apply_env(command: &mut Command, env: &BTreeMap<String, String>) {
    command.env(
        "ERL_AFLAGS",
        env.get("ERL_AFLAGS").map(String::as_str).unwrap_or(""),
    );
    command.env(
        "ERL_FLAGS",
        env.get("ERL_FLAGS").map(String::as_str).unwrap_or(""),
    );
    command.env(
        "ERL_ZFLAGS",
        env.get("ERL_ZFLAGS").map(String::as_str).unwrap_or(""),
    );
    command.env("ERL_OTP29_FLAGS", "");
    command.env("ERL_CRASH_DUMP", "/dev/null");
    command.env("HOME", env.get("HOME").map(String::as_str).unwrap_or(""));
    if let Some(port) = env.get("ERL_EPMD_PORT") {
        command.env("ERL_EPMD_PORT", port);
    } else {
        command.env_remove("ERL_EPMD_PORT");
    }
    if let Some(libs) = env.get("ERL_LIBS") {
        command.env("ERL_LIBS", libs);
    } else {
        command.env_remove("ERL_LIBS");
    }
}

fn erl_boot_vector(args: &[String], env: &BTreeMap<String, String>) -> Result<Vec<String>, String> {
    let mut command = reference_erl();
    command.arg("-emu_args_exit");
    command.args(args);
    apply_env(&mut command, env);
    let output = command.output().expect("erl executable");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        return Err(stderr);
    }
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<String> = stdout.lines().map(str::to_owned).collect();
    let split = lines
        .iter()
        .position(|line| line == "--")
        .unwrap_or_else(|| panic!("no emulator separator in {lines:?}"));
    Ok(lines[split + 1..].to_vec())
}

fn erl_failure(args: &[String], env: &BTreeMap<String, String>) -> (bool, String) {
    let mut command = reference_erl();
    command.args(args);
    apply_env(&mut command, env);
    let output = command.output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (output.status.success(), stderr)
}

fn assert_vector(label: &str, args: &[&str], env: &BTreeMap<String, String>) {
    let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
    let mut argv = vec!["erl".to_owned()];
    argv.extend(args.iter().cloned());
    let launch = parse(&argv, env).unwrap_or_else(|error| panic!("{label}: {error}"));
    let expected = erl_boot_vector(&args, env).unwrap_or_else(|error| panic!("{label}: {error}"));
    assert_eq!(launch.boot_args, expected, "{label}");
}

#[test]
fn flag_families_match_erl_boot_arguments() {
    if !erl_available() {
        eprintln!("skipping flag_families_match_erl_boot_arguments: erl is unavailable");
        return;
    }
    let env = setup_env();
    let mut with_port = env.clone();
    with_port.insert("ERL_EPMD_PORT".into(), "4371".into());
    let mut with_libs = env.clone();
    with_libs.insert("ERL_LIBS".into(), "/tmp/arinsal-erl-libs".into());

    let families: &[(&str, &[&str], &BTreeMap<String, String>)] = &[
        (
            "-s -run -eval order",
            &[
                "-noshell", "-s", "lists", "reverse", "a", "-eval", "ok.", "-run", "lists",
                "reverse", "b", "-eval", "also.",
            ],
            &env,
        ),
        (
            "-extra and plain arguments",
            &[
                "-noshell",
                "--",
                "plain",
                "-not-a-flag",
                "-extra",
                "one",
                "two",
            ],
            &env,
        ),
        (
            "-pa -pz -path -code_path_choice",
            &[
                "-noshell",
                "-pa",
                "/tmp/a",
                "/tmp/b",
                "-pz",
                "/tmp/c",
                "-pa",
                "/tmp/d",
                "-path",
                "/tmp/p1",
                "/tmp/p2",
                "-code_path_choice",
                "relaxed",
            ],
            &env,
        ),
        (
            "ERL_LIBS stays out of init arguments",
            &["-noshell", "-pa", "/tmp/a"],
            &with_libs,
        ),
        (
            "-config and -Application key value",
            &[
                "-noshell",
                "-config",
                "/tmp/demo",
                "-kernel",
                "error_logger",
                "silent",
                "-sasl",
                "errlog_type",
                "error",
            ],
            &env,
        ),
        (
            "-sname -name and epmd port",
            &["-noshell", "-sname", "short", "-name", "long@host"],
            &with_port,
        ),
        ("-detached", &["-detached"], &env),
        (
            "accepted emulator flags stay out of init arguments",
            &[
                "-noshell",
                "+A",
                "foo",
                "+SDcpu",
                "0",
                "+sbwt",
                "none",
                "+hms",
                "233abc",
                "+MBas",
                "ageffcaobf",
                "+MBatags",
                "code",
                "+MMsco",
                "true",
                "+Mlpm",
                "no",
                "+Mea",
                "max",
                "+MEsbct",
                "512",
            ],
            &env,
        ),
        ("-emu_type opt", &["-noshell", "-emu_type", "opt"], &env),
        (
            "-mode interactive and embedded",
            &["-noshell", "-mode", "interactive", "-mode", "embedded"],
            &env,
        ),
        (
            "-boot start_sasl",
            &["-noshell", "-boot", "start_sasl", "-mode", "embedded"],
            &env,
        ),
    ];
    for (label, args, env) in families {
        assert_vector(label, args, env);
    }

    let without_libs = erl_boot_vector(&["-noshell".into(), "-pa".into(), "/tmp/a".into()], &env)
        .expect("vector without ERL_LIBS");
    let with_libs_vector = erl_boot_vector(
        &["-noshell".into(), "-pa".into(), "/tmp/a".into()],
        &with_libs,
    )
    .expect("vector with ERL_LIBS");
    assert_eq!(without_libs, with_libs_vector);
}

#[test]
fn flag_family_rejections_match_erl() {
    if !erl_available() {
        eprintln!("skipping flag_family_rejections_match_erl: erl is unavailable");
        return;
    }
    let env = setup_env();
    let cases: &[&[&str]] = &[
        &["-sname"],
        &["-name"],
        &["-emu_type"],
        &["-emu_type", "nosuch"],
        &["-emu_flavor", "jit"],
        &["+A", "1025"],
        &["+A"],
        &["+sbwt", "no"],
        &["+hms", "0"],
        &["+hms", "foo"],
        &["+MBas", "no"],
        &["+MTe", "false"],
        &["+MIt", "true"],
        &["+MDfoo", "1"],
        &["+MMsco", "maybe"],
        &["+Mlpm", "maybe"],
        &["+Mea", "unknown"],
        &["+MEsbct", "-1"],
        &["+SDcpu", "1025"],
        &["+SDcpu", "2:3"],
        &["+SDcpu"],
    ];
    for args in cases {
        let owned: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
        let (erl_ok, erl_stderr) = erl_failure(&owned, &env);
        let mut argv = vec!["erl".to_owned()];
        argv.extend(owned.iter().cloned());
        let parsed = parse(&argv, &env);
        assert_eq!(parsed.is_ok(), erl_ok, "{args:?}\n{erl_stderr}");
        if !erl_ok {
            let ArgsError::ErlDiagnostic(text) = parsed.unwrap_err() else {
                panic!("{args:?}: expected an erl diagnostic, stderr {erl_stderr}");
            };
            if text.contains("Usage: beam.smp") || text.starts_with("erlexec:") {
                let mut expected = text.clone();
                if !expected.ends_with('\n') {
                    expected.push('\n');
                }
                assert_eq!(erl_stderr, expected, "{args:?}");
            } else {
                // beam.smp follows the diagnostic with its multi-screen usage text.
                assert_eq!(
                    erl_stderr.lines().next().unwrap_or(""),
                    text.lines().next().unwrap_or(""),
                    "{args:?}"
                );
            }
        }
    }
}
