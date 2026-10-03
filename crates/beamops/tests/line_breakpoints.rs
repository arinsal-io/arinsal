use arinsal_beam::parse;
use arinsal_beamops::{transform_module, transform_module_with_line_breakpoints};
use std::{fs, process::Command};

#[test]
fn debugger_line_breakpoint_rewrite_obeys_load_flag() {
    let dir = std::env::temp_dir().join(format!(
        "arinsal-beamops-line-breakpoints-{}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    let source = dir.join("debugger_rewrite_probe.erl");
    fs::write(
        &source,
        "-module(debugger_rewrite_probe).\n-export([run/1]).\nrun(true) -> ok;\nrun(false) -> error.\n",
    )
    .unwrap();
    let output = match Command::new("erlc")
        .args(["+beam_debug_info", "-o"])
        .arg(&dir)
        .arg(&source)
        .output()
    {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipping OTP differential fixture: erlc is not installed");
            return;
        }
        Err(error) => panic!("failed to invoke erlc: {error}"),
    };
    assert!(
        output.status.success(),
        "erlc failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let beam = parse(&fs::read(dir.join("debugger_rewrite_probe.beam")).unwrap()).unwrap();
    assert!(
        beam.code
            .instructions
            .iter()
            .any(|instruction| instruction.op.name() == "debug_line"),
        "OTP did not emit debug_line in the debug_info fixture: {:?}",
        beam.code
            .instructions
            .iter()
            .map(|instruction| instruction.op.name())
            .collect::<Vec<_>>()
    );

    let disabled = transform_module(&beam)
        .iter()
        .flatten()
        .map(|op| op.name().to_owned())
        .collect::<Vec<_>>();
    let enabled = transform_module_with_line_breakpoints(&beam, true)
        .iter()
        .flatten()
        .map(|op| op.name().to_owned())
        .collect::<Vec<_>>();
    assert!(!disabled.iter().any(|name| name == "i_debug_line"));
    assert!(
        !disabled
            .iter()
            .any(|name| name == "i_line_breakpoint_trampoline")
    );
    assert!(enabled.iter().any(|name| name == "i_debug_line"));
    assert!(
        enabled
            .iter()
            .any(|name| name == "i_line_breakpoint_trampoline")
    );
    let _ = fs::remove_dir_all(dir);
}
