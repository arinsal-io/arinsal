use arinsal_beam::{BeamFile, Operand, parse};
use std::{fs, path::PathBuf, process::Command};

fn has_wide_integer(operand: &Operand) -> bool {
    match operand {
        Operand::BigInt(value) => value.bits() > 64,
        Operand::List(items) => items.iter().any(has_wide_integer),
        Operand::TypedReg { reg, .. } => has_wide_integer(reg),
        _ => false,
    }
}

fn compile_fixture() -> Option<(PathBuf, PathBuf)> {
    let temp = std::env::temp_dir().join(format!("arinsal-wide-bit-size-{}", std::process::id()));
    fs::create_dir_all(&temp).ok()?;
    let source = temp.join("wide_bit_size.erl");
    fs::write(
        &source,
        "-module(wide_bit_size).\n-export([match/1]).\nmatch(<<N:8, _:16#1_0000_0000_0000_0000>>) -> N.\n",
    )
    .ok()?;
    let result = Command::new("timeout")
        .args(["30", "erlc", "-W0", "-o"])
        .arg(&temp)
        .arg(&source)
        .output()
        .ok()?;
    if !result.status.success() {
        eprintln!(
            "OTP erlc unavailable or fixture compile failed; skipping: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let _ = fs::remove_dir_all(&temp);
        return None;
    }
    Some((temp.clone(), temp.join("wide_bit_size.beam")))
}

#[test]
fn accepts_unsigned_bit_lengths_wider_than_u64() {
    let Some((temp, beam_path)) = compile_fixture() else {
        return;
    };
    let bytes = fs::read(beam_path).unwrap();
    let module: BeamFile = parse(&bytes).unwrap();
    assert!(
        module
            .code
            .instructions
            .iter()
            .flat_map(|instruction| &instruction.args)
            .any(has_wide_integer),
        "the 2^64-bit tail length must remain available as a BEAM integer"
    );
    fs::remove_dir_all(temp).unwrap();
}
