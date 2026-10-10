use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use arinsal_args::{InitArgs, InitFlag, parse};
use arinsal_etf::{OwnedTerm, decode};

const PROBE: &str = "io:format(\"ARINSAL:~s~n\",[binary:encode_hex(term_to_binary({init:get_arguments(),init:get_plain_arguments()}))]),halt().";

fn reference_erl() -> Command {
    arinsal_difftest::reference::erl().expect("reference OTP emulator")
}

fn erl_available() -> bool {
    arinsal_difftest::reference::erl().is_some()
}

fn erl_output(argv: &[String], env: &BTreeMap<String, String>) -> InitArgs {
    let mut command = reference_erl();
    command.args(argv);
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
    if let Some(port) = env.get("ERL_EPMD_PORT") {
        command.env("ERL_EPMD_PORT", port);
    } else {
        command.env_remove("ERL_EPMD_PORT");
    }
    let result = command.output().expect("erl executable");
    assert!(
        result.status.success(),
        "erl {:?}: {}",
        argv,
        String::from_utf8_lossy(&result.stderr)
    );
    let stdout = String::from_utf8(result.stdout).unwrap();
    let hex = stdout
        .lines()
        .find_map(|line| line.strip_prefix("ARINSAL:"))
        .unwrap_or_else(|| panic!("no probe output for {argv:?}: {stdout}"));
    let bytes: Vec<u8> = hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    let term = decode(&bytes).unwrap();
    let OwnedTerm::Tuple(parts) = &term else {
        panic!("expected tuple")
    };
    let flags = as_list(&parts[0])
        .iter()
        .map(|entry| {
            let OwnedTerm::Tuple(pair) = entry else {
                panic!("expected flag pair: {entry:?}")
            };
            let OwnedTerm::Atom(name) = &pair[0] else {
                panic!("expected flag atom")
            };
            InitFlag {
                name: name.clone(),
                values: as_list(&pair[1]).iter().map(as_string).collect(),
            }
        })
        .collect();
    let plain_args = as_list(&parts[1]).iter().map(as_string).collect();
    InitArgs { flags, plain_args }
}

fn as_list(value: &OwnedTerm) -> &[OwnedTerm] {
    match value {
        OwnedTerm::Nil => &[],
        OwnedTerm::List { elems, tail } if **tail == OwnedTerm::Nil => elems,
        _ => panic!("expected proper list: {value:?}"),
    }
}

fn as_string(value: &OwnedTerm) -> String {
    as_list(value)
        .iter()
        .map(|v| {
            let OwnedTerm::Int(codepoint) = v else {
                panic!("expected codepoint: {v:?}")
            };
            char::from_u32(*codepoint as u32).unwrap()
        })
        .collect()
}

fn root_dir() -> String {
    arinsal_difftest::reference::otp_root()
        .expect("OTP root: set ARINSAL_OTP_ROOT or put erl on PATH")
        .to_string_lossy()
        .into_owned()
}

fn setup_env() -> BTreeMap<String, String> {
    let root = root_dir();
    BTreeMap::from([
        ("ROOTDIR".into(), root.clone()),
        ("BINDIR".into(), format!("{root}/erts-17.1/bin")),
        ("PROGNAME".into(), "erl".into()),
        ("HOME".into(), std::env::var("HOME").unwrap_or_default()),
    ])
}

fn temp_dir(suffix: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("arinsal-args-{}-{suffix}", std::process::id()));
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn differential_300_launches() {
    if !erl_available() {
        eprintln!("skipping differential_300_launches: erl is unavailable");
        return;
    }
    let env_base = setup_env();
    let directory = temp_dir("matrix");
    let file = directory.join("flags.args");
    fs::write(
        &file,
        "# comment\n-pa \"file dir\" -myflag fileflag 'quoted value'\n",
    )
    .unwrap();
    let file_name = file.to_string_lossy().into_owned();
    let mut count = 0;
    for base in 0..5 {
        for source in 0..4 {
            for tail in 0..5 {
                for emulator in 0..3 {
                    let mut env = env_base.clone();
                    let mut argv = vec!["-noshell".to_string(), "-eval".into(), PROBE.into()];
                    match base {
                        1 => argv.extend(
                            ["-noshell", "-eval", "X = 'space here', ok."].map(str::to_owned),
                        ),
                        2 => argv.extend(["-s", "lists", "reverse", "a", "b"].map(str::to_owned)),
                        3 => argv.extend(["-run", "lists", "reverse", "a", "b"].map(str::to_owned)),
                        4 => argv.extend(["-pa", "one dir", "two"].map(str::to_owned)),
                        _ => {}
                    }
                    match source {
                        1 => {
                            env.insert(
                                "ERL_FLAGS".into(),
                                "-myflag source flags -pa flag_path".into(),
                            );
                        }
                        2 => {
                            env.insert(
                                "ERL_AFLAGS".into(),
                                "-pa 'alpha beta' -myflag source aflags".into(),
                            );
                        }
                        3 => {
                            env.insert(
                                "ERL_ZFLAGS".into(),
                                "-myflag source zflags -mode interactive".into(),
                            );
                        }
                        _ => {}
                    }
                    match tail {
                        1 => argv.extend(["-extra", "alpha", "beta gamma"].map(str::to_owned)),
                        2 => argv.extend(["--", "one", "two", "-flag", "value"].map(str::to_owned)),
                        3 => {
                            env.insert("ERL_AFLAGS".into(), "-extra env_a 'two words'".into());
                        }
                        4 => argv.extend(["-args_file", &file_name].map(str::to_owned)),
                        _ => {}
                    }
                    match emulator {
                        1 => argv.extend(["+S", "4:4"].map(str::to_owned)),
                        2 => argv.extend(
                            ["+P", "2000000", "-env", "ARINSAL_TEST_VAR", "two words"]
                                .map(str::to_owned),
                        ),
                        _ => {}
                    }
                    let mut parser_argv = vec!["erl".to_string()];
                    parser_argv.extend(argv.iter().cloned());
                    let ours = parse(&parser_argv, &env)
                        .unwrap_or_else(|err| panic!("case {count}: {err}; {argv:?}"));
                    let expected = erl_output(&argv, &env);
                    assert_eq!(
                        ours.init, expected,
                        "case {count}: argv={argv:?}, env={env:?}"
                    );
                    count += 1;
                }
            }
        }
    }
    assert_eq!(count, 300);
    fs::remove_file(file).unwrap();
    fs::remove_dir(directory).unwrap();
}

#[test]
fn differential_edge_cases() {
    if !erl_available() {
        eprintln!("skipping differential_edge_cases: erl is unavailable");
        return;
    }
    let env_base = setup_env();
    let directory = temp_dir("edges");
    let nested = directory.join("nested.args");
    let outer = directory.join("outer.args");
    fs::write(
        &nested,
        "-quoted 'two words' -escaped escaped\\ space # comment\n-repeated first -repeated second",
    )
    .unwrap();
    fs::write(
        &outer,
        format!(
            "-outer x -args_file {} -extra from_file 'two words'",
            nested.display()
        ),
    )
    .unwrap();
    let nested = nested.to_string_lossy().into_owned();
    let outer = outer.to_string_lossy().into_owned();
    let name = format!("arinsal_args_{}", std::process::id());
    let cases: Vec<(Vec<String>, BTreeMap<String, String>)> = vec![
        (
            vec!["-sname".into(), name, "-setcookie".into(), "secret".into()],
            env_base.clone(),
        ),
        (
            vec![
                "-boot".into(),
                "start".into(),
                "-mode".into(),
                "interactive".into(),
            ],
            env_base.clone(),
        ),
        (
            vec![
                "-args_file".into(),
                outer.clone(),
                "-after".into(),
                "tail".into(),
            ],
            env_base.clone(),
        ),
        (
            vec![
                "-args_file".into(),
                nested.clone(),
                "-after".into(),
                "tail".into(),
            ],
            env_base.clone(),
        ),
        (
            vec![
                "-pa".into(),
                "a".into(),
                "b".into(),
                "-pz".into(),
                "c".into(),
                "d".into(),
            ],
            env_base.clone(),
        ),
        (
            vec!["-noinput".into(), "-detached".into()],
            env_base.clone(),
        ),
        (
            vec!["+c".into(), "-custom".into(), "value".into()],
            env_base.clone(),
        ),
        (
            vec![
                "+B".into(),
                "i".into(),
                "+ec".into(),
                "-custom".into(),
                "value".into(),
            ],
            env_base.clone(),
        ),
        (
            vec![
                "--".into(),
                "one".into(),
                "-flag".into(),
                "two".into(),
                "--".into(),
                "three".into(),
            ],
            env_base.clone(),
        ),
        (
            vec!["-extra".into(), "--".into(), "+S".into(), "4".into()],
            env_base.clone(),
        ),
        (
            vec![
                "-S".into(),
                "lists".into(),
                "reverse".into(),
                "one".into(),
                "two".into(),
            ],
            env_base.clone(),
        ),
        (
            vec![
                "-S".into(),
                "lists".into(),
                "reverse".into(),
                "--".into(),
                "one".into(),
            ],
            env_base.clone(),
        ),
    ];
    for (index, (args, env)) in cases.into_iter().enumerate() {
        if args.iter().any(|arg| arg == "-detached") {
            continue;
        }
        let mut argv = vec!["-noshell".to_string(), "-eval".into(), PROBE.into()];
        argv.extend(args);
        let mut parser_argv = vec!["erl".to_string()];
        parser_argv.extend(argv.iter().cloned());
        let ours = parse(&parser_argv, &env).unwrap();
        let expected = erl_output(&argv, &env);
        assert_eq!(ours.init, expected, "edge case {index}: {argv:?}");
    }
    fs::remove_file(outer).unwrap();
    fs::remove_file(nested).unwrap();
    fs::remove_dir(directory).unwrap();
}
