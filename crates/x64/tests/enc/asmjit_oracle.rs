//! Byte-for-byte comparison of `Emitter` with asmjit itself (the vendored erts 29.1.1 sources,
//! configured as erts configures them), via the C++ harness in `tests/asmjit_oracle/`.
//!
//! One test per family in [`oracle_cases::FAMILIES`]; see `oracle_cases/mod.rs` for how to add
//! cases. A case passes when both sides produce the same bytes, or both fail with the same error.

use arinsal_x64::enc::{Emitter, EncodeError};

use crate::oracle_cases::{FAMILIES, OCase};
use crate::oracle_run::{self, OracleResult};

/// The asmjit error name(s) an [`EncodeError`] corresponds to.
fn asmjit_names(err: &EncodeError) -> &'static [&'static str] {
    match err {
        EncodeError::InvalidRegister(_) => {
            &["InvalidPhysId", "InvalidInstruction", "InvalidRegType"]
        }
        EncodeError::InvalidVecRegister(_) => &["InvalidPhysId", "InvalidInstruction"],
        EncodeError::OperandSizeMismatch => &["OperandSizeMismatch"],
        EncodeError::InvalidImmediate(_) => &["InvalidImmediate"],
        EncodeError::InvalidRexPrefix => &["InvalidRexPrefix"],
        EncodeError::InvalidAddress => &["InvalidAddress"],
        EncodeError::InvalidAddressIndex => &["InvalidAddressIndex"],
        EncodeError::AmbiguousOperandSize => &["AmbiguousOperandSize"],
        EncodeError::InvalidInstruction => &["InvalidInstruction"],
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn check_family(name: &str, cases: Vec<OCase>) {
    let Some(bin) = oracle_run::oracle() else {
        return;
    };
    let lines: Vec<&str> = cases.iter().map(|c| c.text.as_str()).collect();
    let expected: Vec<OracleResult> = oracle_run::run(&bin, &lines);
    let mut failures = Vec::new();
    for (c, want) in cases.iter().zip(&expected) {
        let mut e = Emitter::new();
        let got = (c.run)(&mut e);
        let bad = match (&got, want) {
            (Ok(()), Ok(bytes)) => (e.bytes != *bytes)
                .then(|| format!("asmjit: {}\n    ours:   {}", hex(bytes), hex(&e.bytes))),
            (Err(err), Err(name)) => (!asmjit_names(err).contains(&name.as_str()))
                .then(|| format!("asmjit: error {name}\n    ours:   error {err:?}")),
            (Ok(()), Err(name)) => Some(format!(
                "asmjit: error {name}\n    ours:   {}",
                hex(&e.bytes)
            )),
            (Err(err), Ok(bytes)) => {
                Some(format!("asmjit: {}\n    ours:   error {err:?}", hex(bytes)))
            }
        };
        if let Some(b) = bad {
            failures.push(format!("{}\n    {b}", c.text));
        }
    }
    assert!(
        failures.is_empty(),
        "{name}: {} of {} cases differ from asmjit:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

macro_rules! family_tests {
    ($($name:ident),*) => {
        $(
            #[test]
            fn $name() {
                let (_, gen_cases) = FAMILIES
                    .iter()
                    .find(|(n, _)| *n == stringify!($name))
                    .expect("family registered");
                let mut cases = Vec::new();
                gen_cases(&mut cases);
                check_family(stringify!($name), cases);
            }
        )*
    };
}

family_tests!(alu, mov, avx);

/// Label-relative jumps and `align(kCode, n)` padding through the oracle. The branch families
/// (encoded by a label layer, not `Emitter`) append their cases to `oracle_cases` as `;`-separated
/// statements; these pinned bytes document asmjit's choices: a backward jump to a bound label is
/// short when it fits, a forward jump to a not-yet-bound label is always rel32 (resolved at bind),
/// and `kOptimizedAlign` pads with multi-byte nops.
#[test]
fn harness_labels_and_align() {
    let Some(bin) = oracle_run::oracle() else {
        return;
    };
    let cases: &[(&str, &str)] = &[
        ("bind L; nop; jmp L", "90ebfd"),
        ("jmp L; nop; bind L", "e90100000090"),
        ("bind L; jne L", "75fe"),
        ("jne L; bind L", "0f8500000000"),
        ("bind L; call L", "e8fbffffff"),
        ("nop; align 16", "90660f1f840000000000660f1f440000"),
        ("jmp L; align 8; bind L", "e9030000000f1f00"),
        ("lea rax, [L]; nop; bind L", "488d050100000090"),
        ("mov rax, [L+rcx*2]", "ERR InvalidAddress"),
    ];
    let lines: Vec<&str> = cases.iter().map(|(t, _)| *t).collect();
    for ((text, want), got) in cases.iter().zip(oracle_run::run(&bin, &lines)) {
        let got = match got {
            Ok(b) => b.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            Err(e) => format!("ERR {e}"),
        };
        assert_eq!(&got, want, "{text}");
    }
}
