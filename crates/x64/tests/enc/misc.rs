//! Golden bytes of the prefix, string, atomic, trap, and alignment family (E26-E27).

use arinsal_x64::enc::*;

use crate::golden::{Case, assemble, check};

#[test]
fn prefix_string_atomic_and_trap_forms() {
    let cases: &[Case] = &[
        ("xchg rax, rcx", |e| e.xchg_rr(RAX, RCX)),
        ("xchg r9, rax", |e| e.xchg_rr(R9, RAX)),
        ("xchg r8, r10", |e| e.xchg_rr(R8, R10)),
        ("xchg eax, eax", |e| e.xchg_rr(EAX, EAX)),
        ("xchg ax, ax", |e| e.xchg_rr(AX, AX)),
        ("xchg al, ah", |e| e.xchg_rr(AL, AH)),
        ("xchg sil, r10b", |e| e.xchg_rr(SIL, R10B)),
        ("xchg qword ptr [r13+8], r9", |e| {
            e.xchg_mr(qword_ptr(R13, 8), R9)
        }),
        ("xchg r8, qword ptr [rsp]", |e| {
            e.xchg_rm(R8, qword_ptr(RSP, 0))
        }),
        ("lock inc qword ptr [r13]", |e| {
            e.lock_inc_m(qword_ptr(R13, 0))
        }),
        ("stosq", |e| e.stosq()),
        ("rep stosq", |e| e.rep_stosq()),
        ("rep stosb", |e| e.rep_stosb()),
        ("ud2", |e| e.ud2()),
        ("hlt", |e| e.hlt()),
        ("int3", |e| e.int3()),
        ("nop", |e| e.nop()),
    ];
    check(cases);
}

#[test]
fn optimized_alignment_matches_gnu_as() {
    let cases: &[Case] = &[
        ("nop\n.p2align 3", |e| {
            e.nop()?;
            e.align_code(8)
        }),
        // asmjit kOptimizedAlign greedily emits the largest NOP up to nine bytes.
        (
            ".byte 0x90,0x90,0x90,0x66,0x0f,0x1f,0x84,0,0,0,0,0,0x0f,0x1f,0x40,0",
            |e| {
                e.nop()?;
                e.nop()?;
                e.nop()?;
                e.align_code(16)
            },
        ),
        (
            ".byte 0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x66,0x0f,0x1f,0x84,0,0,0,0,0,0x66,0x0f,0x1f,0x84,0,0,0,0,0,0x66,0x0f,0x1f,0x84,0,0,0,0,0,0x66,0x0f,0x1f,0x84,0,0,0,0,0,0x66,0x0f,0x1f,0x84,0,0,0,0,0,0x66,0x0f,0x1f,0x84,0,0,0,0,0,0x0f,0x1f,0",
            |e| {
                for _ in 0..7 {
                    e.nop()?;
                }
                e.align_code(64)
            },
        ),
    ];
    check(cases);
}

#[test]
fn optimized_alignment_covers_each_asmjit_nop_size() {
    const NOPS: [&[u8]; 9] = [
        &[0x90],
        &[0x66, 0x90],
        &[0x0F, 0x1F, 0x00],
        &[0x0F, 0x1F, 0x40, 0x00],
        &[0x0F, 0x1F, 0x44, 0x00, 0x00],
        &[0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00],
        &[0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00],
        &[0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
        &[0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
    ];

    for nop in NOPS {
        let prefix_len = 16 - nop.len();
        let mut emitter = Emitter::new();
        for _ in 0..prefix_len {
            emitter.nop().expect("nop encodes");
        }
        emitter.align_code(16).expect("valid code alignment");

        let mut bytes = vec![0x90; prefix_len];
        bytes.extend_from_slice(nop);
        let text = format!(
            ".byte {}",
            bytes
                .iter()
                .map(|byte| format!("0x{byte:02x}"))
                .collect::<Vec<_>>()
                .join(",")
        );
        if let Some(expected) = assemble(&[&text]) {
            assert!(
                emitter.bytes == expected[0],
                "alignment mismatch for {}-byte NOP",
                nop.len()
            );
        } else {
            eprintln!("GNU as/objcopy not found: raw-byte alignment comparison skipped");
            assert!(
                emitter.bytes == bytes,
                "alignment mismatch for {}-byte NOP",
                nop.len()
            );
        }
    }
}

#[test]
fn invalid_misc_forms_leave_emitter_unchanged() {
    let mut e = Emitter::new();
    assert!(matches!(
        e.align_code(3),
        Err(EncodeError::InvalidAlignment)
    ));
    assert!(e.is_empty());
    let mut lock_inc = Emitter::new();
    assert!(lock_inc.lock_inc_m(dword_ptr(RAX, 0)).is_ok());
    assert!(!lock_inc.is_empty());
    assert!(matches!(
        e.xchg_rr(RAX, EBX),
        Err(EncodeError::OperandSizeMismatch)
    ));
    assert!(e.is_empty());
    assert!(matches!(
        e.xchg_rr(AH, R10B),
        Err(EncodeError::InvalidRexPrefix)
    ));
    assert!(e.is_empty());
}
