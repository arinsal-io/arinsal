//! Linked-in driver smoke test against erl 29.1.1: erl_ddll load/unload/info/monitor,
//! open_port, port_command (output/outputv), port_control, port_call, port_close and
//! driver failures. Fixtures: crates/drv/tests/fixtures/{smoke_drv.c,drv_smoke.erl}.

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
        .args(["-shared", "-fPIC", "-undefined", "dynamic_lookup", "-I"])
        .arg(otp_include())
        .args(defines)
        .arg(fixtures().join("smoke_drv.c"))
        .arg("-o")
        .arg(dir.join(format!("{name}.so")))
        .status()
        .expect("cc");
    assert!(status.success(), "compile {name}.so");
}

#[test]
fn smoke_driver_matches_erl() {
    let dir = std::env::temp_dir().join(format!("arinsal-drv-smoke-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    compile_driver(&dir, "smoke_drv", &[]);
    compile_driver(&dir, "smoke_v_drv", &["-DSMOKE_OUTPUTV"]);
    compile_driver(
        &dir,
        "smoke_badver_drv",
        &["-DDRV_NAME=\"smoke_badver_drv\"", "-DDRV_MAJOR=1"],
    );
    compile_driver(&dir, "smoke_badname_drv", &[]);

    let erl = RefErl::start().expect("erl reference node");
    let source = std::fs::read_to_string(fixtures().join("drv_smoke.erl")).unwrap();
    let beam = erl
        .compile_named("drv_smoke", &source, &[])
        .unwrap_or_else(|error| panic!("compile drv_smoke: {error}"));
    std::fs::write(dir.join("drv_smoke.beam"), &beam).unwrap();
    erl.load("drv_smoke", &beam).unwrap();
    let main = format!(
        "-module(drv_smoke_main).\n-export([run/0]).\nrun() -> drv_smoke:run({:?}).\n",
        dir.to_str().unwrap()
    );
    let main_beam = erl
        .compile_named("drv_smoke_main", &main, &[])
        .unwrap_or_else(|error| panic!("compile drv_smoke_main: {error}"));
    std::fs::write(dir.join("drv_smoke_main.beam"), &main_beam).unwrap();
    erl.load("drv_smoke_main", &main_beam).unwrap();
    let options = CallOptions {
        timeout_ms: Some(30_000),
        ..CallOptions::default()
    };
    let expected = match erl.call_opts("drv_smoke_main", "run", &[], &options).result {
        CallResult::Ok(term) => term,
        other => panic!("drv_smoke:run/1 on erl: {other:?}"),
    };
    drop(erl);
    assert!(
        matches!(&expected, OwnedTerm::Map(entries) if entries.len() == 25),
        "erl reference run failed: {}",
        pretty(&expected)
    );
    if std::env::var_os("DRV_SMOKE_SHOW").is_some() {
        eprintln!("{}", pretty(&expected));
    }

    let mut vm = Vm::new([dir.clone()]);
    let actual = match vm.eval_scheduled("drv_smoke_main", "run", &[], 1, Some(1)) {
        Ok(result) => result.term,
        Err(error) => panic!("drv_smoke:run/1 on Arinsal: {error}"),
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
        panic!("drv_smoke differs:\n{}", diffs.join("\n"));
    }
}
