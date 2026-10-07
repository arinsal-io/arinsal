//! Linked-in driver I/O test against erl 29.1.1: driver_select (read, write, USE,
//! USE_NO_CALLBACK, stealing, stale owners), port timers, driver_async and
//! erl_drv_consume_timeslice. Fixtures: crates/drv/tests/fixtures/{io_drv.c,drv_io.erl}.

use std::path::{Path, PathBuf};
use std::process::Command;

use arinsal_difftest::{CallOptions, CallResult, RefErl, pretty};
use arinsal_etf::OwnedTerm;
use arinsal_vm::Vm;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../drv/tests/fixtures")
}

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

fn compile_driver(dir: &Path, name: &str) {
    let status = Command::new("cc")
        .args(["-shared", "-fPIC", "-undefined", "dynamic_lookup", "-I"])
        .arg(otp_include())
        .arg(fixtures().join("io_drv.c"))
        .arg("-o")
        .arg(dir.join(format!("{name}.so")))
        .status()
        .expect("cc");
    assert!(status.success(), "compile {name}.so");
}

#[test]
fn io_driver_matches_erl() {
    let dir = std::env::temp_dir().join(format!("arinsal-drv-io-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    compile_driver(&dir, "io_drv");

    let erl = RefErl::start().expect("erl reference node");
    let source = std::fs::read_to_string(fixtures().join("drv_io.erl")).unwrap();
    let beam = erl
        .compile_named("drv_io", &source, &[])
        .unwrap_or_else(|error| panic!("compile drv_io: {error}"));
    std::fs::write(dir.join("drv_io.beam"), &beam).unwrap();
    erl.load("drv_io", &beam).unwrap();
    let main = format!(
        "-module(drv_io_main).\n-export([run/0]).\nrun() -> drv_io:run({:?}).\n",
        dir.to_str().unwrap()
    );
    let main_beam = erl
        .compile_named("drv_io_main", &main, &[])
        .unwrap_or_else(|error| panic!("compile drv_io_main: {error}"));
    std::fs::write(dir.join("drv_io_main.beam"), &main_beam).unwrap();
    erl.load("drv_io_main", &main_beam).unwrap();
    let options = CallOptions {
        timeout_ms: Some(90_000),
        ..CallOptions::default()
    };
    let expected = match erl.call_opts("drv_io_main", "run", &[], &options).result {
        CallResult::Ok(term) => term,
        other => panic!("drv_io:run/1 on erl: {other:?}"),
    };
    drop(erl);
    assert!(
        matches!(&expected, OwnedTerm::Map(entries) if entries.len() == 17),
        "erl reference run failed: {}",
        pretty(&expected)
    );
    if std::env::var_os("DRV_IO_SHOW").is_some() {
        eprintln!("{}", pretty(&expected));
    }

    let mut vm = Vm::new([dir.clone()]);
    let actual = match vm.eval_scheduled("drv_io_main", "run", &[], 2, None) {
        Ok(result) => result.term,
        Err(error) => panic!("drv_io:run/1 on Arinsal: {error}"),
    };
    let _ = std::fs::remove_dir_all(&dir);
    let sorted = |term: &OwnedTerm| match term {
        OwnedTerm::Map(entries) => {
            let mut entries = entries.clone();
            entries.sort_by(|a, b| arinsal_etf::erl_cmp(&a.0, &b.0));
            OwnedTerm::Map(entries)
        }
        other => other.clone(),
    };
    let (actual, expected) = (sorted(&actual), sorted(&expected));
    if actual != expected {
        let (OwnedTerm::Map(a), OwnedTerm::Map(e)) = (&actual, &expected) else {
            panic!(
                "expected {}\nactual   {}",
                pretty(&expected),
                pretty(&actual)
            );
        };
        let mut diffs = Vec::new();
        for (key, value) in e {
            let other = a.iter().find(|(k, _)| k == key).map(|(_, v)| v);
            if other != Some(value) {
                diffs.push(format!(
                    "{}:\n  erl      {}\n  arinsal  {}",
                    pretty(key),
                    pretty(value),
                    other.map_or("<missing>".into(), pretty)
                ));
            }
        }
        panic!("drv_io differs:\n{}", diffs.join("\n"));
    }
}
