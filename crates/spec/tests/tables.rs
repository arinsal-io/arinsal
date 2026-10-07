use arinsal_spec::{BIFS, Opcode, bif_lookup};
use std::{path::PathBuf, process::Command};

#[test]
fn opcode_table_is_contiguous() {
    assert_eq!(Opcode::COUNT, 191);
    assert!(Opcode::from_u8(0).is_none());
    assert!(Opcode::from_u8(192).is_none());
    for n in 1..=191 {
        assert!(Opcode::from_u8(n).is_some());
    }
}

#[test]
fn opcode_fixture_and_live_compiler() {
    let fixture = include_str!("fixtures/opcodes.txt");
    let command = Command::new("erl").args(["-noshell", "-eval",
        "lists:foreach(fun(N) -> {Name,Arity}=beam_opcodes:opname(N), io:format(\"~B ~s ~B~n\",[N,Name,Arity]) end,lists:seq(1,191)),halt()."])
        .output();
    let Ok(output) = command else {
        eprintln!("erl absent; checking committed fixture only");
        check_opcodes(fixture);
        return;
    };
    assert!(
        output.status.success(),
        "erl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let live = String::from_utf8(output.stdout).unwrap();
    assert_eq!(live, fixture, "OTP compiler differs from committed fixture");
    check_opcodes(&live);
}
fn check_opcodes(text: &str) {
    for line in text.lines() {
        let columns: Vec<_> = line.split_whitespace().collect();
        let n: u8 = columns[0].parse().unwrap();
        let op = Opcode::from_u8(n).unwrap();
        assert_eq!(op.name(), columns[1], "opcode {n}");
        assert_eq!(op.arity(), columns[2].parse::<u8>().unwrap(), "opcode {n}");
    }
    assert_eq!(text.lines().count(), 191);
}

#[test]
fn bifs_match_live_erl() {
    assert_eq!(BIFS.len(), 553);
    let add = bif_lookup("erlang", "+", 2).unwrap();
    assert_eq!(add.name, "+");
    for (i, bif) in BIFS.iter().enumerate() {
        assert_eq!(bif.index as usize, i);
        assert_eq!(
            bif_lookup(bif.module, bif.name, bif.arity).unwrap().index,
            bif.index
        );
    }
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/otp-29.1.1/bif.tab");
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/bifs.escript");
    let output = Command::new("escript").arg(script).arg(source).output();
    let Ok(output) = output else {
        eprintln!("escript absent; skipping live BIF check");
        return;
    };
    assert!(
        output.status.success(),
        "escript failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines = String::from_utf8(output.stdout).unwrap();
    assert_eq!(lines.lines().count(), 553);
    let exceptions: Vec<_> = lines
        .lines()
        .filter_map(|line| line.strip_suffix(" false"))
        .collect();
    let recorded: Vec<_> = include_str!("fixtures/bif_not_builtin.txt")
        .lines()
        .collect();
    assert_eq!(exceptions, recorded, "is_builtin exception list changed");
}
