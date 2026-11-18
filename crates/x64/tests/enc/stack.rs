//! Golden bytes of the stack instruction family (E18).

use arinsal_x64::enc::*;

use crate::golden::{Case, check};

#[test]
fn stack_forms() {
    let cases: &[Case] = &[
        ("push rax", |e| e.push_r(RAX)),
        ("push r9", |e| e.push_r(R9)),
        // asmjit accepts a 32-bit view for PUSH and encodes the native 64-bit register form.
        ("push r15", |e| e.push_r(R15D)),
        ("push ax", |e| e.push_r(AX)),
        ("push qword ptr [rsp]", |e| e.push_m(qword_ptr(RSP, 0))),
        ("push qword ptr [r13+0x20]", |e| {
            e.push_m(qword_ptr(R13, 0x20))
        }),
        ("push word ptr [rax]", |e| e.push_m(word_ptr(RAX, 0))),
        ("pop r8", |e| e.pop_r(R8)),
        ("pop bp", |e| e.pop_r(BP)),
        ("pop qword ptr [r12]", |e| e.pop_m(qword_ptr(R12, 0))),
        ("pop word ptr [r13+2]", |e| e.pop_m(word_ptr(R13, 2))),
        ("leave", |e| e.leave()),
    ];
    check(cases);
}

#[test]
fn stack_rejects_illegal_forms_without_emitting() {
    let mut e = Emitter::new();
    assert!(matches!(e.push_r(AL), Err(EncodeError::InvalidInstruction)));
    assert!(e.is_empty());
    assert!(matches!(
        e.push_m(dword_ptr(RAX, 0)),
        Err(EncodeError::InvalidInstruction)
    ));
    assert!(e.is_empty());
    assert!(matches!(
        e.pop_m(ptr(RAX, 0)),
        Err(EncodeError::AmbiguousOperandSize)
    ));
    assert!(e.is_empty());
}
