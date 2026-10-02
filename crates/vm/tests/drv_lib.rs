//! Driver library API test against erl 29.1.1: queue, outputv, term output, process
//! monitors, threads, locks, system info, time, environment, dynamic library calls,
//! driver entries, busy ports, driver_create_port and erl_drv_init_ack.
//! Fixtures: crates/drv/tests/fixtures/{lib_drv.c,drv_lib.erl}.

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

fn compile_driver(dir: &Path, name: &str, defines: &[&str]) {
    let status = Command::new("cc")
        .args([
            "-shared",
            "-fPIC",
            "-undefined",
            "dynamic_lookup",
            "-Wno-deprecated-declarations",
            "-I",
        ])
        .arg(otp_include())
        .args(defines)
        .arg(fixtures().join("lib_drv.c"))
        .arg("-o")
        .arg(dir.join(format!("{name}.so")))
        .status()
        .expect("cc");
    assert!(status.success(), "compile {name}.so");
}

/// The term with every map sorted by key, so map order never matters.
fn canonical(term: &OwnedTerm) -> OwnedTerm {
    match term {
        OwnedTerm::Map(entries) => {
            let mut entries: Vec<_> = entries
                .iter()
                .map(|(key, value)| (canonical(key), canonical(value)))
                .collect();
            entries.sort_by(|a, b| arinsal_etf::erl_cmp(&a.0, &b.0));
            OwnedTerm::Map(entries)
        }
        OwnedTerm::Tuple(items) => OwnedTerm::Tuple(items.iter().map(canonical).collect()),
        OwnedTerm::List { elems, tail } => OwnedTerm::List {
            elems: elems.iter().map(canonical).collect(),
            tail: Box::new(canonical(tail)),
        },
        // Bignums that fit 64 bits are plain integers in a decoded reply.
        OwnedTerm::BigInt(n) => i64::try_from(n).map_or_else(|_| term.clone(), OwnedTerm::Int),
        other => other.clone(),
    }
}

/// Path to the first difference between two terms, for failure messages.
fn first_diff(a: &OwnedTerm, b: &OwnedTerm) -> String {
    match (a, b) {
        (OwnedTerm::Tuple(x), OwnedTerm::Tuple(y)) if x.len() == y.len() => x
            .iter()
            .zip(y)
            .enumerate()
            .find(|(_, (x, y))| x != y)
            .map_or_else(String::new, |(at, (x, y))| {
                format!("tuple[{at}] -> {}", first_diff(x, y))
            }),
        (OwnedTerm::List { elems: x, tail: tx }, OwnedTerm::List { elems: y, tail: ty })
            if x.len() == y.len() =>
        {
            x.iter()
                .zip(y)
                .enumerate()
                .find(|(_, (x, y))| x != y)
                .map_or_else(
                    || format!("tail -> {}", first_diff(tx, ty)),
                    |(at, (x, y))| format!("list[{at}] -> {}", first_diff(x, y)),
                )
        }
        _ => format!("{} vs {}", show(a), show(b)),
    }
}

/// Compact rendering for diffs: printable binaries as text.
fn show(term: &OwnedTerm) -> String {
    match term {
        OwnedTerm::Binary(bytes) if std::str::from_utf8(bytes).is_ok() => {
            format!("<<{:?}>>", String::from_utf8_lossy(bytes))
        }
        OwnedTerm::Tuple(items) => format!(
            "{{{}}}",
            items.iter().map(show).collect::<Vec<_>>().join(", ")
        ),
        OwnedTerm::List { elems, tail } if **tail == OwnedTerm::Nil => format!(
            "[{}]",
            elems.iter().map(show).collect::<Vec<_>>().join(", ")
        ),
        OwnedTerm::Map(entries) => format!(
            "#{{{}}}",
            entries
                .iter()
                .map(|(k, v)| format!("{} => {}", show(k), show(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        other => pretty(other),
    }
}

#[test]
fn library_api_matches_erl() {
    let dir = std::env::temp_dir().join(format!("arinsal-drv-lib-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    compile_driver(&dir, "lib_drv", &[]);
    compile_driver(
        &dir,
        "lib_noexit_drv",
        &["-DDRV_NAME=\"lib_noexit_drv\"", "-DNO_PROCESS_EXIT"],
    );
    compile_driver(
        &dir,
        "lib_ack_drv",
        &["-DDRV_NAME=\"lib_ack_drv\"", "-DACK_DRV"],
    );

    let erl = RefErl::start().expect("erl reference node");
    let source = std::fs::read_to_string(fixtures().join("drv_lib.erl")).unwrap();
    let beam = erl
        .compile_named("drv_lib", &source, &[])
        .unwrap_or_else(|error| panic!("compile drv_lib: {error}"));
    std::fs::write(dir.join("drv_lib.beam"), &beam).unwrap();
    erl.load("drv_lib", &beam).unwrap();
    let main = format!(
        "-module(drv_lib_main).\n-export([run/0]).\nrun() -> drv_lib:run({:?}).\n",
        dir.to_str().unwrap()
    );
    let main_beam = erl
        .compile_named("drv_lib_main", &main, &[])
        .unwrap_or_else(|error| panic!("compile drv_lib_main: {error}"));
    std::fs::write(dir.join("drv_lib_main.beam"), &main_beam).unwrap();
    erl.load("drv_lib_main", &main_beam).unwrap();
    let options = CallOptions {
        timeout_ms: Some(60_000),
        ..CallOptions::default()
    };
    let expected = match erl.call_opts("drv_lib_main", "run", &[], &options).result {
        CallResult::Ok(term) => term,
        other => panic!("drv_lib:run/1 on erl: {other:?}"),
    };
    drop(erl);
    assert!(
        matches!(&expected, OwnedTerm::Map(entries) if entries.len() == 23),
        "erl reference run failed: {}",
        pretty(&expected)
    );
    if std::env::var_os("DRV_LIB_SHOW").is_some() {
        eprintln!("{}", pretty(&expected));
    }

    let mut vm = Vm::new([dir.clone()]);
    let actual = match vm.eval_scheduled("drv_lib_main", "run", &[], 2, None) {
        Ok(result) => result.term,
        Err(error) => panic!("drv_lib:run/1 on Arinsal: {error}"),
    };
    let _ = std::fs::remove_dir_all(&dir);
    let (actual, expected) = (canonical(&actual), canonical(&expected));
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
                    show(value),
                    other.map_or("<missing>".into(), |other| format!(
                        "{}\n  first difference: {}",
                        show(other),
                        first_diff(value, other)
                    ))
                ));
            }
        }
        panic!("drv_lib differs:\n{}", diffs.join("\n"));
    }
}
