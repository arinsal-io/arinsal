use arinsal_beam::parse;
use arinsal_beamops::transform_module;
use std::{fs, process::Command};

#[test]
fn no_line_info_functions_receive_nil_function_lines() {
    let dir = std::env::temp_dir().join(format!(
        "arinsal-beamops-no-line-info-{}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    let source = dir.join("no_line_info_probe.erl");
    fs::write(
        &source,
        "-module(no_line_info_probe).\n-export([first/1, second/1]).\nfirst(X) -> X + 1.\nsecond(X) -> first(X) * 2.\n",
    )
    .unwrap();
    let output = match Command::new("erlc")
        .args(["+no_line_info", "-o"])
        .arg(&dir)
        .arg(&source)
        .output()
    {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipping no-line-info fixture: erlc is not installed");
            return;
        }
        Err(error) => panic!("failed to invoke erlc: {error}"),
    };
    assert!(
        output.status.success(),
        "erlc failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let beam = parse(&fs::read(dir.join("no_line_info_probe.beam")).unwrap()).unwrap();
    let instructions = &beam.code.instructions;
    let func_info_count = instructions
        .iter()
        .filter(|instruction| instruction.op.name() == "func_info")
        .count();
    assert!(func_info_count >= 2, "fixture has too few functions");
    let no_line_function_starts = instructions
        .windows(2)
        .filter(|pair| pair[0].op.name() == "label" && pair[1].op.name() == "func_info")
        .count();
    assert_eq!(
        no_line_function_starts, func_info_count,
        "erlc +no_line_info should place func_info directly after each function label"
    );

    let functions = transform_module(&beam).unwrap();
    let starts = functions
        .iter()
        .flatten()
        .filter(|op| op.name() == "i_func_info")
        .count();
    assert_eq!(
        starts, func_info_count,
        "every func_info must be recognized"
    );
    let no_line_entries = functions
        .iter()
        .flatten()
        .filter(|op| op.name() == "empty_func_line")
        .count();
    assert_eq!(
        no_line_entries, func_info_count,
        "every missing function line must use OTP's empty_func_line rewrite"
    );
    let _ = fs::remove_dir_all(dir);
}
