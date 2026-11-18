//! Golden bytes of the multiply/divide family (E19).

use arinsal_x64::enc::*;

use crate::golden::{Case, check};

#[test]
fn multiply_divide_forms() {
    let cases: &[Case] = &[
        ("mul r9", |e| e.mul_r(R9)),
        ("mul qword ptr [r13+8]", |e| e.mul_m(qword_ptr(R13, 8))),
        ("imul rax", |e| e.imul_r(RAX)),
        ("imul qword ptr [rbx]", |e| e.imul_m(qword_ptr(RBX, 0))),
        ("imul rax, rbx", |e| e.imul_rr(RAX, RBX)),
        ("imul r9, r12", |e| e.imul_rr(R9, R12)),
        ("imul rax, rbx, -7", |e| e.imul_rri(RAX, RBX, -7)),
        ("imul r9, r10, 0x12345678", |e| {
            e.imul_rri(R9, R10, 0x1234_5678)
        }),
        ("imul rax, qword ptr [r12+8], 3", |e| {
            e.imul_rmi(RAX, qword_ptr(R12, 8), 3)
        }),
        ("imul rdx, -0x1234", |e| e.imul_ri(RDX, -0x1234)),
        ("div r8", |e| e.div_r(R8)),
        ("div qword ptr [r13]", |e| e.div_m(qword_ptr(R13, 0))),
        ("idiv r9", |e| e.idiv_r(R9)),
        ("idiv qword ptr [rbx+16]", |e| e.idiv_m(qword_ptr(RBX, 16))),
        ("cqo", |e| e.cqo()),
        ("cdq", |e| e.cdq()),
    ];
    check(cases);
}

#[test]
fn multiply_divide_rejects_invalid_forms_without_emitting() {
    let mut e = Emitter::new();
    assert!(matches!(
        e.imul_rr(RAX, EBX),
        Err(EncodeError::OperandSizeMismatch)
    ));
    assert!(e.is_empty());
    assert!(matches!(
        e.imul_rri(Gp::q(16), RBX, 1),
        Err(EncodeError::InvalidRegister(_))
    ));
    assert!(e.is_empty());
    assert!(matches!(
        e.mul_r(Gp::q(16)),
        Err(EncodeError::InvalidRegister(_))
    ));
    assert!(e.is_empty());
}

#[test]
fn immediate_short_and_long_choices_match_asmjit() {
    let cases: &[Case] = &[
        // asmjit kEncodingX86Imul uses 6B for signed imm8 and 69 for imm32.
        ("imul rax, rbx, -128", |e| e.imul_rri(RAX, RBX, -128)),
        ("imul rax, rbx, 127", |e| e.imul_rri(RAX, RBX, 127)),
        ("imul rax, rbx, 128", |e| e.imul_rri(RAX, RBX, 128)),
        ("imul rax, rbx, -129", |e| e.imul_rri(RAX, RBX, -129)),
    ];
    check(cases);
}

#[test]
fn asmjit_truncates_nonrepresentable_imul_immediate_fields() {
    // kEncodingX86Imul writes the selected imm32 bytes without an additional range check.
    let cases: &[Case] = &[(".byte 0x48,0x69,0xc3,0xff,0xff,0xff,0xff", |e| {
        e.imul_rri(RAX, RBX, i64::MAX)
    })];
    check(cases);
}
