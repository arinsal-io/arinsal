use arinsal_x64::enc::*;

use crate::golden::{Case, check};

#[test]
fn indirect_call_and_jump_forms() {
    let cases: &[Case] = &[
        ("call rax", |e| e.call_r(RAX)),
        ("call r15", |e| e.call_r(R15)),
        ("jmp rbx", |e| e.jmp_r(RBX)),
        ("jmp r8", |e| e.jmp_r(R8)),
        ("call QWORD PTR [rsp]", |e| e.call_m(qword_ptr(RSP, 0))),
        ("call QWORD PTR [rbp]", |e| e.call_m(qword_ptr(RBP, 0))),
        ("call QWORD PTR [r12]", |e| e.call_m(qword_ptr(R12, 0))),
        ("call QWORD PTR [r13 + 8]", |e| e.call_m(qword_ptr(R13, 8))),
        ("call QWORD PTR [r9 + r12*4 + 305419896]", |e| {
            e.call_m(Mem::base_index(R9, R12, 2, 0x1234_5678, 8))
        }),
        ("call QWORD PTR [rip]", |e| e.call_m(Mem::rip(0, 8))),
        ("jmp QWORD PTR [rsp]", |e| e.jmp_m(qword_ptr(RSP, 0))),
        ("jmp QWORD PTR [rbp]", |e| e.jmp_m(qword_ptr(RBP, 0))),
        ("jmp QWORD PTR [r12]", |e| e.jmp_m(qword_ptr(R12, 0))),
        ("jmp QWORD PTR [r13 + 8]", |e| e.jmp_m(qword_ptr(R13, 8))),
        ("jmp QWORD PTR [r9 + r12*4 + 305419896]", |e| {
            e.jmp_m(Mem::base_index(R9, R12, 2, 0x1234_5678, 8))
        }),
        ("jmp QWORD PTR [rip]", |e| e.jmp_m(Mem::rip(0, 8))),
    ];
    check(cases);
}

#[test]
fn return_forms() {
    let cases: &[Case] = &[
        ("ret", |e| e.ret()),
        ("ret", |e| e.ret_i(0)),
        ("ret 8", |e| e.ret_i(8)),
        ("ret 65535", |e| e.ret_i(-1)),
        // asmjit writes the low imm16 unchanged, including when the input exceeds that width.
        (".byte 0xc2, 0x00, 0x00", |e| e.ret_i(65536)),
    ];
    check(cases);
}

#[test]
fn indirect_rip_targets_report_the_displacement() {
    for emit in [
        Emitter::call_m as fn(&mut Emitter, Mem) -> Result<(), EncodeError>,
        Emitter::jmp_m as fn(&mut Emitter, Mem) -> Result<(), EncodeError>,
    ] {
        let mut e = Emitter::new();
        assert!(emit(&mut e, Mem::rip(12, 8)).is_ok());
        assert!(e.last_rip_fixup() == Some(RipFixup { disp_at: 2, end: 6 }));
    }
}

#[test]
fn invalid_register_id_does_not_change_the_emitter() {
    let mut e = Emitter::new();
    assert!(matches!(
        e.call_r(Gp::q(16)),
        Err(EncodeError::InvalidRegister(_))
    ));
    assert!(e.is_empty());
}
