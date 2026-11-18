//! Golden bytes of the shift/rotate family (E20).

use arinsal_x64::enc::*;

use crate::golden::{Case, check};

#[test]
fn shift_and_rotate_forms() {
    let cases: &[Case] = &[
        ("shl rax, 1", |e| e.shl_ri(RAX, 1)),
        ("shl r9d, 4", |e| e.shl_ri(R9D, 4)),
        ("shr rax, 1", |e| e.shr_ri(RAX, 1)),
        ("shr r12d, 7", |e| e.shr_ri(R12D, 7)),
        ("sar r15, 3", |e| e.sar_ri(R15, 3)),
        ("rol rax, 1", |e| e.rol_ri(RAX, 1)),
        ("rol r9, 8", |e| e.rol_ri(R9, 8)),
        ("ror rax, 1", |e| e.ror_ri(RAX, 1)),
        ("ror r13, 9", |e| e.ror_ri(R13, 9)),
        ("shl rax, cl", |e| e.shl_rr(RAX, CL)),
        ("shr r9d, cl", |e| e.shr_rr(R9D, CL)),
        ("sar r12, cl", |e| e.sar_rr(R12, CL)),
        ("rol r15, cl", |e| e.rol_rr(R15, CL)),
        ("ror r8d, cl", |e| e.ror_rr(R8D, CL)),
        ("shl dil, cl", |e| e.shl_rr(DIL, CL)),
        ("shl ah, 1", |e| e.shl_ri(AH, 1)),
    ];
    check(cases);
}

#[test]
fn immediate_counts_are_truncated_before_the_one_form_choice() {
    let cases: &[Case] = &[
        // asmjit masks the count to imm8 before selecting D1 versus C1.
        ("shl rax, 1", |e| e.shl_ri(RAX, 0x101)),
        ("shr rax, 0", |e| e.shr_ri(RAX, 0x100)),
    ];
    check(cases);
}

#[test]
fn shift_rejects_non_cl_register_without_emitting() {
    let mut e = Emitter::new();
    assert!(matches!(
        e.shl_rr(RAX, DL),
        Err(EncodeError::InvalidInstruction)
    ));
    assert!(e.is_empty());
}
