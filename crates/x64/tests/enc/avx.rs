//! Golden bytes of the VEX reference family (two- and three-byte VEX selection).

use arinsal_x64::enc::*;

use crate::golden::{Case, check};

#[test]
fn vpxor_forms() {
    let cases: &[Case] = &[
        ("vpxor xmm0, xmm1, xmm2", |e| {
            e.vpxor_xxx(Xmm(0), Xmm(1), Xmm(2))
        }),
        ("vpxor xmm9, xmm1, xmm2", |e| {
            e.vpxor_xxx(Xmm(9), Xmm(1), Xmm(2))
        }),
        ("vpxor xmm0, xmm15, xmm2", |e| {
            e.vpxor_xxx(Xmm(0), Xmm(15), Xmm(2))
        }),
        ("vpxor xmm0, xmm1, xmm8", |e| {
            e.vpxor_xxx(Xmm(0), Xmm(1), Xmm(8))
        }),
        ("vpxor ymm3, ymm4, ymm5", |e| {
            e.vpxor_yyy(Ymm(3), Ymm(4), Ymm(5))
        }),
        ("vpxor ymm12, ymm13, ymm14", |e| {
            e.vpxor_yyy(Ymm(12), Ymm(13), Ymm(14))
        }),
        ("vpxor xmm0, xmm0, [rbx+0x10]", |e| {
            e.vpxor_xxm(Xmm(0), Xmm(0), xmmword_ptr(RBX, 0x10))
        }),
        ("vpxor xmm1, xmm2, [r9]", |e| {
            e.vpxor_xxm(Xmm(1), Xmm(2), xmmword_ptr(R9, 0))
        }),
        ("vpxor xmm1, xmm2, [rax+r10*8]", |e| {
            e.vpxor_xxm(Xmm(1), Xmm(2), Mem::base_index(RAX, R10, 3, 0, 16))
        }),
        ("vpxor xmm10, xmm2, [rip+0x20]", |e| {
            e.vpxor_xxm(Xmm(10), Xmm(2), Mem::rip(0x20, 16))
        }),
    ];
    check(cases);
}

#[test]
fn vex_rejects_bad_registers() {
    let mut e = Emitter::new();
    assert_eq!(
        e.vpxor_xxx(Xmm(16), Xmm(0), Xmm(0)),
        Err(EncodeError::InvalidVecRegister(16))
    );
    assert!(e.is_empty());
}
