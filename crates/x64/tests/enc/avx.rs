//! Golden-byte tests for VEX scalar and packed forms.

use arinsal_x64::enc::*;
use similar_asserts::assert_eq;

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
        ("vpxor ymm9, ymm10, ymm15", |e| {
            e.vpxor_yyy(Ymm(9), Ymm(10), Ymm(15))
        }),
        ("vpxor ymm8, ymm1, ymmword ptr [r13+0x80]", |e| {
            e.vpxor_yym(Ymm(8), Ymm(1), ymmword_ptr(R13, 0x80))
        }),
    ];
    check(cases);
}

#[test]
fn avx_scalar_forms() {
    let cases: &[Case] = &[
        ("vandpd xmm0, xmm1, xmm2", |e| {
            e.vandpd_xxx(Xmm(0), Xmm(1), Xmm(2))
        }),
        ("vandpd xmm9, xmm15, xmm8", |e| {
            e.vandpd_xxx(Xmm(9), Xmm(15), Xmm(8))
        }),
        ("vandpd xmm2, xmm3, xmmword ptr [r13+8]", |e| {
            e.vandpd_xxm(Xmm(2), Xmm(3), xmmword_ptr(R13, 8))
        }),
        ("vandpd ymm0, ymm1, ymm2", |e| {
            e.vandpd_yyy(Ymm(0), Ymm(1), Ymm(2))
        }),
        ("vandpd ymm9, ymm15, ymm8", |e| {
            e.vandpd_yyy(Ymm(9), Ymm(15), Ymm(8))
        }),
        ("vandpd ymm2, ymm3, ymmword ptr [r12+0x100]", |e| {
            e.vandpd_yym(Ymm(2), Ymm(3), ymmword_ptr(R12, 0x100))
        }),
        ("vcvtsi2sd xmm0, xmm1, rax", |e| {
            e.vcvtsi2sd_xxr(Xmm(0), Xmm(1), RAX)
        }),
        ("vcvtsi2sd xmm9, xmm15, r10", |e| {
            e.vcvtsi2sd_xxr(Xmm(9), Xmm(15), R10)
        }),
        ("vcvtsi2sd xmm8, xmm1, ecx", |e| {
            e.vcvtsi2sd_xxr(Xmm(8), Xmm(1), ECX)
        }),
        ("vcvtsi2sd xmm2, xmm3, qword ptr [r13+8]", |e| {
            e.vcvtsi2sd_xxm(Xmm(2), Xmm(3), qword_ptr(R13, 8))
        }),
        ("vucomisd xmm0, xmm1", |e| e.vucomisd_xx(Xmm(0), Xmm(1))),
        ("vucomisd xmm15, xmm8", |e| e.vucomisd_xx(Xmm(15), Xmm(8))),
        ("vucomisd xmm9, qword ptr [r12+0x80]", |e| {
            e.vucomisd_xm(Xmm(9), qword_ptr(R12, 0x80))
        }),
    ];
    check(cases);
}

#[test]
fn avx_move_forms() {
    let cases: &[Case] = &[
        ("vmovdqu xmm0, xmm1", |e| e.vmovdqu_xx(Xmm(0), Xmm(1))),
        ("vmovdqu xmm15, xmm8", |e| e.vmovdqu_xx(Xmm(15), Xmm(8))),
        ("vmovdqu xmm9, xmmword ptr [r13+8]", |e| {
            e.vmovdqu_xm(Xmm(9), xmmword_ptr(R13, 8))
        }),
        ("vmovdqu xmmword ptr [r12+16], xmm10", |e| {
            e.vmovdqu_mx(xmmword_ptr(R12, 16), Xmm(10))
        }),
        ("vmovdqu ymm0, ymm1", |e| e.vmovdqu_yy(Ymm(0), Ymm(1))),
        ("vmovdqu ymm15, ymm8", |e| e.vmovdqu_yy(Ymm(15), Ymm(8))),
        ("vmovdqu ymm9, ymmword ptr [r13+8]", |e| {
            e.vmovdqu_ym(Ymm(9), ymmword_ptr(R13, 8))
        }),
        ("vmovdqu ymmword ptr [r12+16], ymm10", |e| {
            e.vmovdqu_my(ymmword_ptr(R12, 16), Ymm(10))
        }),
        ("vmovq xmm1, rax", |e| e.vmovq_xr(Xmm(1), RAX)),
        ("vmovq xmm15, r9", |e| e.vmovq_xr(Xmm(15), R9)),
        ("vmovq xmm2, xmm3", |e| e.vmovq_xx(Xmm(2), Xmm(3))),
        ("vmovq xmm10, qword ptr [r13]", |e| {
            e.vmovq_xm(Xmm(10), qword_ptr(R13, 0))
        }),
        ("vmovq r10, xmm15", |e| e.vmovq_rx(R10, Xmm(15))),
        ("vmovq qword ptr [r12+8], xmm9", |e| {
            e.vmovq_mx(qword_ptr(R12, 8), Xmm(9))
        }),
        ("vmovsd xmm0, qword ptr [rax]", |e| {
            e.vmovsd_xm(Xmm(0), qword_ptr(RAX, 0))
        }),
        ("vmovsd xmm9, qword ptr [r13+8]", |e| {
            e.vmovsd_xm(Xmm(9), qword_ptr(R13, 8))
        }),
        ("vmovsd xmm0, xmm1, xmm2", |e| {
            e.vmovsd_xxx(Xmm(0), Xmm(1), Xmm(2))
        }),
        ("vmovsd xmm9, xmm15, xmm8", |e| {
            e.vmovsd_xxx(Xmm(9), Xmm(15), Xmm(8))
        }),
        ("vmovsd qword ptr [r12+0x80], xmm15", |e| {
            e.vmovsd_mx(qword_ptr(R12, 0x80), Xmm(15))
        }),
        ("vmovups xmm0, xmm1", |e| e.vmovups_xx(Xmm(0), Xmm(1))),
        ("vmovups xmm15, xmm8", |e| e.vmovups_xx(Xmm(15), Xmm(8))),
        ("vmovups xmm9, xmmword ptr [r13+8]", |e| {
            e.vmovups_xm(Xmm(9), xmmword_ptr(R13, 8))
        }),
        ("vmovups xmmword ptr [r12+16], xmm15", |e| {
            e.vmovups_mx(xmmword_ptr(R12, 16), Xmm(15))
        }),
        ("vmovups ymm0, ymm1", |e| e.vmovups_yy(Ymm(0), Ymm(1))),
        ("vmovups ymm15, ymm8", |e| e.vmovups_yy(Ymm(15), Ymm(8))),
        ("vmovups ymm9, ymmword ptr [r13+8]", |e| {
            e.vmovups_ym(Ymm(9), ymmword_ptr(R13, 8))
        }),
        ("vmovups ymmword ptr [r12+16], ymm15", |e| {
            e.vmovups_my(ymmword_ptr(R12, 16), Ymm(15))
        }),
    ];
    check(cases);
}

#[test]
fn avx_immediate_vector_forms() {
    let cases: &[Case] = &[
        ("vpermilpd xmm0, xmm1, 1", |e| {
            e.vpermilpd_xxi(Xmm(0), Xmm(1), 1)
        }),
        ("vpermilpd xmm15, xmm8, 3", |e| {
            e.vpermilpd_xxi(Xmm(15), Xmm(8), 3)
        }),
        ("vpermilpd xmm9, xmmword ptr [r13+8], 3", |e| {
            e.vpermilpd_xmi(Xmm(9), xmmword_ptr(R13, 8), 3)
        }),
        ("vpermilpd ymm0, ymm1, 1", |e| {
            e.vpermilpd_yyi(Ymm(0), Ymm(1), 1)
        }),
        ("vpermilpd ymm15, ymm8, 3", |e| {
            e.vpermilpd_yyi(Ymm(15), Ymm(8), 3)
        }),
        ("vpermilpd ymm9, ymmword ptr [r12+0x80], 3", |e| {
            e.vpermilpd_ymi(Ymm(9), ymmword_ptr(R12, 0x80), 3)
        }),
        ("vpermq ymm0, ymm1, 0x1b", |e| {
            e.vpermq_yyi(Ymm(0), Ymm(1), 0x1b)
        }),
        ("vpermq ymm15, ymm8, 0x1b", |e| {
            e.vpermq_yyi(Ymm(15), Ymm(8), 0x1b)
        }),
        ("vpermq ymm15, ymmword ptr [r13+0x100], 0x1b", |e| {
            e.vpermq_ymi(Ymm(15), ymmword_ptr(R13, 0x100), 0x1b)
        }),
        ("vpinsrq xmm0, xmm1, rax, 1", |e| {
            e.vpinsrq_xxri(Xmm(0), Xmm(1), RAX, 1)
        }),
        ("vpinsrq xmm9, xmm15, r10, 0", |e| {
            e.vpinsrq_xxri(Xmm(9), Xmm(15), R10, 0)
        }),
        ("vpinsrq xmm0, xmm1, qword ptr [r13+8], 1", |e| {
            e.vpinsrq_xxmi(Xmm(0), Xmm(1), qword_ptr(R13, 8), 1)
        }),
        ("vinserti128 ymm0, ymm1, xmm2, 1", |e| {
            e.vinserti128_yyxi(Ymm(0), Ymm(1), Xmm(2), 1)
        }),
        ("vinserti128 ymm9, ymm15, xmm8, 0", |e| {
            e.vinserti128_yyxi(Ymm(9), Ymm(15), Xmm(8), 0)
        }),
        ("vinserti128 ymm0, ymm1, xmmword ptr [r13+8], 1", |e| {
            e.vinserti128_yymi(Ymm(0), Ymm(1), xmmword_ptr(R13, 8), 1)
        }),
    ];
    check(cases);
}

#[test]
fn avx_test_and_upper_state_forms() {
    let cases: &[Case] = &[
        ("vptest xmm0, xmm1", |e| e.vptest_xx(Xmm(0), Xmm(1))),
        ("vptest xmm15, xmm8", |e| e.vptest_xx(Xmm(15), Xmm(8))),
        ("vptest xmm9, xmmword ptr [r13+8]", |e| {
            e.vptest_xm(Xmm(9), xmmword_ptr(R13, 8))
        }),
        ("vptest ymm0, ymm1", |e| e.vptest_yy(Ymm(0), Ymm(1))),
        ("vptest ymm15, ymm8", |e| e.vptest_yy(Ymm(15), Ymm(8))),
        ("vptest ymm9, ymmword ptr [r12+0x80]", |e| {
            e.vptest_ym(Ymm(9), ymmword_ptr(R12, 0x80))
        }),
        ("vzeroupper", |e| e.vzeroupper()),
    ];
    check(cases);
}

#[test]
fn avx_rejects_bad_registers_without_emitting() {
    let mut e = Emitter::new();
    assert_eq!(
        e.vpxor_xxx(Xmm(16), Xmm(0), Xmm(0)),
        Err(EncodeError::InvalidVecRegister(16))
    );
    assert!(e.is_empty());
    assert_eq!(
        e.vcvtsi2sd_xxr(Xmm(0), Xmm(1), AL),
        Err(EncodeError::InvalidInstruction)
    );
    assert!(e.is_empty());
    assert_eq!(
        e.vpinsrq_xxri(Xmm(0), Xmm(1), EAX, 0),
        Err(EncodeError::InvalidInstruction)
    );
    assert!(e.is_empty());
}
