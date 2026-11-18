//! Golden-byte tests for BMI1/BMI2, LZCNT and POPCNT encodings.

use arinsal_x64::enc::*;
use similar_asserts::assert_eq;

use crate::golden::{Case, check};

#[test]
fn bmi_register_forms() {
    let cases: &[Case] = &[
        ("andn rax, rbx, rcx", |e| e.andn_rrr(RAX, RBX, RCX)),
        ("andn r8, r9, r10", |e| e.andn_rrr(R8, R9, R10)),
        ("andn rax, r9, r10", |e| e.andn_rrr(RAX, R9, R10)),
        ("andn r8, rbx, rcx", |e| e.andn_rrr(R8, RBX, RCX)),
        ("andn eax, ebx, ecx", |e| e.andn_rrr(EAX, EBX, ECX)),
        ("bzhi rax, rbx, rcx", |e| e.bzhi_rrr(RAX, RBX, RCX)),
        ("bzhi r8, r9, r10", |e| e.bzhi_rrr(R8, R9, R10)),
        ("bzhi rax, r9, r10", |e| e.bzhi_rrr(RAX, R9, R10)),
        ("bzhi r8, rbx, rcx", |e| e.bzhi_rrr(R8, RBX, RCX)),
        ("bzhi eax, ebx, ecx", |e| e.bzhi_rrr(EAX, EBX, ECX)),
        ("mulx rax, rbx, rcx", |e| e.mulx_rrr(RAX, RBX, RCX)),
        ("mulx r8, r9, r10", |e| e.mulx_rrr(R8, R9, R10)),
        ("mulx rax, r9, r10", |e| e.mulx_rrr(RAX, R9, R10)),
        ("mulx r8, rbx, rcx", |e| e.mulx_rrr(R8, RBX, RCX)),
        ("pext eax, ebx, ecx", |e| e.pext_rrr(EAX, EBX, ECX)),
        ("pext r8d, r9d, r10d", |e| e.pext_rrr(R8D, R9D, R10D)),
        ("pext eax, r9d, r10d", |e| e.pext_rrr(EAX, R9D, R10D)),
        ("pext r8d, ebx, ecx", |e| e.pext_rrr(R8D, EBX, ECX)),
        ("sarx rax, rbx, rcx", |e| e.sarx_rrr(RAX, RBX, RCX)),
        ("sarx r8, r9, r10", |e| e.sarx_rrr(R8, R9, R10)),
        ("sarx rax, r9, r10", |e| e.sarx_rrr(RAX, R9, R10)),
        ("sarx r8, rbx, rcx", |e| e.sarx_rrr(R8, RBX, RCX)),
        ("shlx rax, rbx, rcx", |e| e.shlx_rrr(RAX, RBX, RCX)),
        ("shlx r8, r9, r10", |e| e.shlx_rrr(R8, R9, R10)),
        ("shlx rax, r9, r10", |e| e.shlx_rrr(RAX, R9, R10)),
        ("shlx r8, rbx, rcx", |e| e.shlx_rrr(R8, RBX, RCX)),
        ("shrx eax, ebx, ecx", |e| e.shrx_rrr(EAX, EBX, ECX)),
        ("shrx r8d, r9d, r10d", |e| e.shrx_rrr(R8D, R9D, R10D)),
        ("shrx eax, r9d, r10d", |e| e.shrx_rrr(EAX, R9D, R10D)),
        ("shrx r8d, ebx, ecx", |e| e.shrx_rrr(R8D, EBX, ECX)),
        ("lzcnt rax, rcx", |e| e.lzcnt_rr(RAX, RCX)),
        ("lzcnt r9, r10", |e| e.lzcnt_rr(R9, R10)),
        ("lzcnt eax, ecx", |e| e.lzcnt_rr(EAX, ECX)),
        ("tzcnt rax, rcx", |e| e.tzcnt_rr(RAX, RCX)),
        ("tzcnt r9, r10", |e| e.tzcnt_rr(R9, R10)),
        ("tzcnt eax, ecx", |e| e.tzcnt_rr(EAX, ECX)),
        ("popcnt rax, rcx", |e| e.popcnt_rr(RAX, RCX)),
        ("popcnt r9, r10", |e| e.popcnt_rr(R9, R10)),
        ("popcnt eax, ecx", |e| e.popcnt_rr(EAX, ECX)),
    ];
    check(cases);
}

#[test]
fn bmi_rejects_invalid_widths_without_emitting() {
    let mut e = Emitter::new();
    assert_eq!(e.andn_rrr(AL, CL, DL), Err(EncodeError::InvalidInstruction));
    assert!(e.is_empty());
    assert_eq!(
        e.bzhi_rrr(RAX, EBX, RCX),
        Err(EncodeError::OperandSizeMismatch)
    );
    assert!(e.is_empty());
    assert_eq!(
        e.mulx_rrr(EAX, EBX, ECX),
        Err(EncodeError::InvalidInstruction)
    );
    assert!(e.is_empty());
    assert_eq!(
        e.pext_rrr(EAX, EBX, Gp::d(16)),
        Err(EncodeError::InvalidRegister(Gp::d(16)))
    );
    assert!(e.is_empty());
}
