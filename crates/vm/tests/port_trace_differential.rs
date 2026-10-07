use std::path::{Path, PathBuf};
use std::process::Command;

use arinsal_difftest::{CallOptions, CallResult, RefErl, pretty};
use arinsal_etf::OwnedTerm;
use arinsal_term::{ProcessHeap, from_owned};
use arinsal_vm::Vm;

const MODULE: &str = "port_trace7_repro";
const CASES: [&str; 7] = [
    "set_timer",
    "command",
    "connect",
    "driver_remote_send_term",
    "driver_send_term",
    "open_close",
    "send_term",
];

fn otp_include() -> PathBuf {
    let output = Command::new("erl")
        .args([
            "-noshell",
            "-eval",
            "io:format(\"~s/usr/include\",[code:root_dir()]),halt().",
        ])
        .output()
        .expect("erl on PATH");
    assert!(output.status.success());
    PathBuf::from(String::from_utf8(output.stdout).unwrap())
}

fn compile_driver(dir: &Path) {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/otp/erts/emulator/test/port_trace_SUITE_data/echo_drv.c");
    let status = Command::new("cc")
        .args(["-shared", "-fPIC", "-undefined", "dynamic_lookup", "-I"])
        .arg(otp_include())
        .arg(source)
        .arg("-o")
        .arg(dir.join("echo_drv.so"))
        .status()
        .expect("cc");
    assert!(status.success(), "compile echo_drv.so");
}

fn string_term(value: &str) -> OwnedTerm {
    OwnedTerm::List {
        elems: value
            .bytes()
            .map(|byte| OwnedTerm::Int(i64::from(byte)))
            .collect(),
        tail: Box::new(OwnedTerm::Nil),
    }
}

fn run(reference: &RefErl, module: &str, case: &str, dir: &str) -> OwnedTerm {
    let options = CallOptions {
        timeout_ms: Some(30_000),
        ..CallOptions::default()
    };
    match reference
        .call_opts(
            module,
            "run",
            &[OwnedTerm::atom(case), string_term(dir)],
            &options,
        )
        .result
    {
        CallResult::Ok(term) => term,
        other => panic!("{module}:run({case}) on erl: {other:?}"),
    }
}

#[test]
fn port_trace_event_sequences_match_otp() {
    let Ok(reference) = RefErl::start() else {
        eprintln!("erl unavailable; skipping port trace differential test");
        return;
    };
    let dir = std::env::temp_dir().join(format!("arinsal-port-trace-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    compile_driver(&dir);

    let source = include_str!("fixtures/port_trace_repro.erl");
    let beam = reference
        .compile_named(MODULE, source, &[])
        .unwrap_or_else(|error| panic!("compile {MODULE}: {error}"));
    reference.load(MODULE, &beam).unwrap();
    let driver_dir = dir.to_str().unwrap();
    let mut vm = Vm::new([dir.clone()]);
    vm.load_bytes(&beam).unwrap();

    for case in CASES {
        let expected = run(&reference, MODULE, case, driver_dir);
        let mut heap = ProcessHeap::with_words(256);
        let args = [
            from_owned(&OwnedTerm::atom(case), &mut heap).unwrap(),
            from_owned(&string_term(driver_dir), &mut heap).unwrap(),
        ];
        let actual = vm
            .eval_scheduled(MODULE, "run", &args, 1, Some(82))
            .unwrap_or_else(|error| panic!("{MODULE}:run({case}) on Arinsal: {error}"))
            .term;
        assert_eq!(
            actual,
            expected,
            "{case} trace sequence mismatch\nOTP: {}\nArinsal: {}",
            pretty(&expected),
            pretty(&actual)
        );
    }

    drop(vm);
    drop(reference);
    std::fs::remove_dir_all(&dir).unwrap();
}
