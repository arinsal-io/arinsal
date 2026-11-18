use arinsal_x64::enc::*;

use crate::golden::{Case, check};

macro_rules! set_case {
    ($text:literal, $cc:expr) => {
        ($text, |e: &mut Emitter| e.setcc_r($cc, AL))
    };
}

macro_rules! cmov_case {
    ($text:literal, $cc:expr) => {
        ($text, |e: &mut Emitter| e.cmovcc_rr($cc, RAX, RBX))
    };
}

#[test]
fn condition_aliases_match_asmjit() {
    assert!(CondCode::C == CondCode::B);
    assert!(CondCode::NAE == CondCode::B);
    assert!(CondCode::NC == CondCode::AE);
    assert!(CondCode::NB == CondCode::AE);
    assert!(CondCode::Z == CondCode::E);
    assert!(CondCode::NZ == CondCode::NE);
    assert!(CondCode::NA == CondCode::BE);
    assert!(CondCode::NBE == CondCode::A);
    assert!(CondCode::PE == CondCode::P);
    assert!(CondCode::PO == CondCode::NP);
    assert!(CondCode::NGE == CondCode::L);
    assert!(CondCode::NL == CondCode::GE);
    assert!(CondCode::NG == CondCode::LE);
    assert!(CondCode::NLE == CondCode::G);
    assert!(CondCode::Zero == CondCode::E);
    assert!(CondCode::UnsignedLT == CondCode::B);
}

#[test]
fn cmovcc_encodes_every_condition() {
    let cases: &[Case] = &[
        cmov_case!("cmovo rax, rbx", CondCode::O),
        cmov_case!("cmovno rax, rbx", CondCode::NO),
        cmov_case!("cmovb rax, rbx", CondCode::B),
        cmov_case!("cmovae rax, rbx", CondCode::AE),
        cmov_case!("cmove rax, rbx", CondCode::E),
        cmov_case!("cmovne rax, rbx", CondCode::NE),
        cmov_case!("cmovbe rax, rbx", CondCode::BE),
        cmov_case!("cmova rax, rbx", CondCode::A),
        cmov_case!("cmovs rax, rbx", CondCode::S),
        cmov_case!("cmovns rax, rbx", CondCode::NS),
        cmov_case!("cmovp rax, rbx", CondCode::P),
        cmov_case!("cmovnp rax, rbx", CondCode::NP),
        cmov_case!("cmovl rax, rbx", CondCode::L),
        cmov_case!("cmovge rax, rbx", CondCode::GE),
        cmov_case!("cmovle rax, rbx", CondCode::LE),
        cmov_case!("cmovg rax, rbx", CondCode::G),
        ("cmove ax, cx", |e| e.cmovcc_rr(CondCode::E, AX, CX)),
        ("cmovnz r9d, r10d", |e| e.cmovcc_rr(CondCode::NZ, R9D, R10D)),
        ("cmovl r9w, WORD PTR [r13 + 8]", |e| {
            e.cmovcc_rm(CondCode::L, R9W, word_ptr(R13, 8))
        }),
        ("cmovge r10d, DWORD PTR [r12 + r9*2 + 127]", |e| {
            e.cmovcc_rm(CondCode::GE, R10D, Mem::base_index(R12, R9, 1, 127, 4))
        }),
        ("cmovbe r9, QWORD PTR [rip]", |e| {
            e.cmovcc_rm(CondCode::BE, R9, Mem::rip(0, 8))
        }),
    ];
    check(cases);
}

#[test]
fn setcc_encodes_every_condition_and_byte_target_kind() {
    let cases: &[Case] = &[
        set_case!("seto al", CondCode::O),
        set_case!("setno al", CondCode::NO),
        set_case!("setb al", CondCode::B),
        set_case!("setae al", CondCode::AE),
        set_case!("sete al", CondCode::E),
        set_case!("setne al", CondCode::NE),
        set_case!("setbe al", CondCode::BE),
        set_case!("seta al", CondCode::A),
        set_case!("sets al", CondCode::S),
        set_case!("setns al", CondCode::NS),
        set_case!("setp al", CondCode::P),
        set_case!("setnp al", CondCode::NP),
        set_case!("setl al", CondCode::L),
        set_case!("setge al", CondCode::GE),
        set_case!("setle al", CondCode::LE),
        set_case!("setg al", CondCode::G),
        ("seta ah", |e| e.setcc_r(CondCode::A, AH)),
        ("setnz spl", |e| e.setcc_r(CondCode::NZ, SPL)),
        ("setae r8b", |e| e.setcc_r(CondCode::AE, R8B)),
        ("setne BYTE PTR [r13]", |e| {
            e.setcc_m(CondCode::NE, byte_ptr(R13, 0))
        }),
        ("setb BYTE PTR [r12 + r9*2 + 127]", |e| {
            e.setcc_m(CondCode::B, Mem::base_index(R12, R9, 1, 127, 1))
        }),
        ("setnz BYTE PTR [rip]", |e| {
            e.setcc_m(CondCode::NZ, Mem::rip(0, 1))
        }),
        // asmjit FIXUP_GPB treats a non-byte Gp as its low-byte register by id.
        ("seta al", |e| e.setcc_r(CondCode::A, RAX)),
    ];
    check(cases);
}

#[test]
fn invalid_register_ids_do_not_change_the_emitter() {
    let mut e = Emitter::new();
    assert!(matches!(
        e.cmovcc_rr(CondCode::E, Gp::q(16), RAX),
        Err(EncodeError::InvalidRegister(_))
    ));
    assert!(e.is_empty());

    assert!(matches!(
        e.setcc_r(CondCode::NE, Gp::b_hi(4)),
        Err(EncodeError::InvalidRegister(_))
    ));
    assert!(e.is_empty());
}
