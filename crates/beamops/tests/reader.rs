//! The code reader (`beamcodereader_next` of beam_file.c) produces the generic instructions the
//! engine starts from: for every module of OTP and Elixir it reads the same instruction stream,
//! operand for operand, as the node list the current engine builds before it transforms.

use arinsal_beam::parse;
use arinsal_beamops::{legacy_generic_ops_dump, reader_dump};
use std::path::Path;

fn erl_output(expression: &str) -> Option<String> {
    let output = std::process::Command::new("erl")
        .args(["-noshell", "-eval", expression])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8(output.stdout).ok())
        .flatten()
}

fn check_dir(dir: &Path, checked: &mut usize) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|extension| extension != "beam") {
            continue;
        }
        let bytes = std::fs::read(&path).unwrap();
        let Ok(beam) = parse(&bytes) else { continue };
        let expected = legacy_generic_ops_dump(&beam);
        let actual = reader_dump(&beam);
        for (index, (want, got)) in expected.iter().zip(&actual).enumerate() {
            assert_eq!(want, got, "{} instruction {index}", path.display());
        }
        assert_eq!(expected.len(), actual.len(), "{}", path.display());
        *checked += 1;
    }
}

#[test]
fn reader_matches_the_generic_instruction_stream_of_every_module() {
    let Some(dirs) = erl_output(
        "io:format(\"~s\", [string:join([P || P <- code:get_path(), P =/= \".\"], \"\\n\")]), halt().",
    ) else {
        eprintln!("erl unavailable; skipping");
        return;
    };
    let mut checked = 0;
    for dir in dirs.lines() {
        check_dir(Path::new(dir), &mut checked);
    }
    if let Some(elixir) = std::process::Command::new("elixir")
        .args(["-e", "IO.write(:code.lib_dir(:elixir))"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
    {
        check_dir(&Path::new(&elixir).join("ebin"), &mut checked);
    }
    assert!(checked > 200, "modules checked: {checked}");
}
