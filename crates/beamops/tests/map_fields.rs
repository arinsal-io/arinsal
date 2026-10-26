use arinsal_beam::{BeamFile, parse};
use arinsal_beamops::transform_module;
use std::{fs, process::Command};

#[test]
fn loaded_stdlib_map_patterns_have_no_has_map_fields_specific_op() {
    let modules = ["maps", "gen_server", "ets", "dict", "sets"];
    let list = modules.join(",");
    let eval = format!(
        "Ms=[{list}], lists:foreach(fun(M) -> {{module,M}}=code:ensure_loaded(M), io:format(\"BEAM|~s|~s~n\", [M, code:which(M)]) end, Ms), halt()."
    );
    let output = match Command::new("erl")
        .args(["-noshell", "-eval", &eval])
        .output()
    {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipping OTP integration check: erl is not installed");
            return;
        }
        Err(error) => panic!("failed to run erl: {error}"),
    };
    assert!(
        output.status.success(),
        "erl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let beams = String::from_utf8(output.stdout)
        .expect("erl output is UTF-8")
        .lines()
        .filter_map(|line| {
            let mut fields = line.splitn(3, '|');
            if fields.next()? != "BEAM" {
                return None;
            }
            Some((fields.next()?.to_owned(), fields.next()?.to_owned()))
        })
        .collect::<Vec<_>>();
    assert_eq!(beams.len(), modules.len(), "erl did not load every module");
    for (module, path) in beams {
        let beam: BeamFile = parse(&fs::read(path).expect("read OTP module BEAM"))
            .unwrap_or_else(|error| panic!("parse {module}: {error}"));
        let transformed = transform_module(&beam).unwrap();
        assert!(
            transformed
                .iter()
                .flatten()
                .all(|op| op.name() != "has_map_fields"),
            "{module} retains a has_map_fields op"
        );
    }
}
