//! Golden-byte tests for SSE2 scalar and packed forms.

use arinsal_x64::enc::*;
use similar_asserts::assert_eq;

use crate::golden::{Case, check};

#[test]
fn sse_scalar_forms() {
    let cases: &[Case] = &[
        ("movsd xmm0, xmm1", |e| e.movsd_xx(Xmm(0), Xmm(1))),
        ("movsd xmm15, xmm8", |e| e.movsd_xx(Xmm(15), Xmm(8))),
        ("movsd xmm9, qword ptr [r13+8]", |e| {
            e.movsd_xm(Xmm(9), qword_ptr(R13, 8))
        }),
        ("movsd qword ptr [r12+16], xmm10", |e| {
            e.movsd_mx(qword_ptr(R12, 16), Xmm(10))
        }),
        ("movq xmm4, r9", |e| e.movq_xr(Xmm(4), R9)),
        ("movq xmm15, xmm8", |e| e.movq_xx(Xmm(15), Xmm(8))),
        ("movq xmm9, qword ptr [rsp]", |e| {
            e.movq_xm(Xmm(9), qword_ptr(RSP, 0))
        }),
        ("movq r10, xmm15", |e| e.movq_rx(R10, Xmm(15))),
        ("movq qword ptr [r13-8], xmm8", |e| {
            e.movq_mx(qword_ptr(R13, -8), Xmm(8))
        }),
        ("cvtsi2sd xmm0, rcx", |e| e.cvtsi2sd_xr(Xmm(0), RCX)),
        ("cvtsi2sd xmm9, r10", |e| e.cvtsi2sd_xr(Xmm(9), R10)),
        ("cvtsi2sd xmm15, ecx", |e| e.cvtsi2sd_xr(Xmm(15), ECX)),
        ("cvtsi2sd xmm4, qword ptr [r12+0x123]", |e| {
            e.cvtsi2sd_xm(Xmm(4), qword_ptr(R12, 0x123))
        }),
        ("cvttsd2si rax, xmm1", |e| e.cvttsd2si_rx(RAX, Xmm(1))),
        ("cvttsd2si r9, xmm15", |e| e.cvttsd2si_rx(R9, Xmm(15))),
        ("cvttsd2si eax, xmm8", |e| e.cvttsd2si_rx(EAX, Xmm(8))),
        ("cvttsd2si r10, qword ptr [rbp-8]", |e| {
            e.cvttsd2si_rm(R10, qword_ptr(RBP, -8))
        }),
        ("ucomisd xmm0, xmm1", |e| e.ucomisd_xx(Xmm(0), Xmm(1))),
        ("ucomisd xmm9, qword ptr [r13+0x80]", |e| {
            e.ucomisd_xm(Xmm(9), qword_ptr(R13, 0x80))
        }),
        ("comisd xmm15, xmm8", |e| e.comisd_xx(Xmm(15), Xmm(8))),
        ("comisd xmm4, qword ptr [r12]", |e| {
            e.comisd_xm(Xmm(4), qword_ptr(R12, 0))
        }),
        ("addsd xmm0, xmm1", |e| e.addsd_xx(Xmm(0), Xmm(1))),
        ("addsd xmm9, qword ptr [r13+8]", |e| {
            e.addsd_xm(Xmm(9), qword_ptr(R13, 8))
        }),
        ("subsd xmm10, xmm15", |e| e.subsd_xx(Xmm(10), Xmm(15))),
        ("mulsd xmm4, qword ptr [rsp+0x100]", |e| {
            e.mulsd_xm(Xmm(4), qword_ptr(RSP, 0x100))
        }),
        ("divsd xmm2, xmm3", |e| e.divsd_xx(Xmm(2), Xmm(3))),
        ("sqrtsd xmm8, qword ptr [r12+0x400]", |e| {
            e.sqrtsd_xm(Xmm(8), qword_ptr(R12, 0x400))
        }),
    ];
    check(cases);
}

#[test]
fn sse_packed_forms() {
    let cases: &[Case] = &[
        ("movdqa xmm0, xmm1", |e| e.movdqa_xx(Xmm(0), Xmm(1))),
        ("movdqa xmm15, xmm8", |e| e.movdqa_xx(Xmm(15), Xmm(8))),
        ("movdqa xmm9, xmmword ptr [r13+8]", |e| {
            e.movdqa_xm(Xmm(9), xmmword_ptr(R13, 8))
        }),
        ("movdqa xmmword ptr [r12+16], xmm10", |e| {
            e.movdqa_mx(xmmword_ptr(R12, 16), Xmm(10))
        }),
        ("movdqu xmm0, xmm1", |e| e.movdqu_xx(Xmm(0), Xmm(1))),
        ("movdqu xmm15, xmm8", |e| e.movdqu_xx(Xmm(15), Xmm(8))),
        ("movdqu xmm9, xmmword ptr [rsp]", |e| {
            e.movdqu_xm(Xmm(9), xmmword_ptr(RSP, 0))
        }),
        ("movdqu xmmword ptr [r13-8], xmm8", |e| {
            e.movdqu_mx(xmmword_ptr(R13, -8), Xmm(8))
        }),
        ("pxor xmm0, xmm1", |e| e.pxor_xx(Xmm(0), Xmm(1))),
        ("pxor xmm15, xmmword ptr [r12+0x80]", |e| {
            e.pxor_xm(Xmm(15), xmmword_ptr(R12, 0x80))
        }),
        ("punpcklqdq xmm0, xmm1", |e| e.punpcklqdq_xx(Xmm(0), Xmm(1))),
        ("punpcklqdq xmm9, xmmword ptr [r13+0x123]", |e| {
            e.punpcklqdq_xm(Xmm(9), xmmword_ptr(R13, 0x123))
        }),
        ("andpd xmm2, xmm3", |e| e.andpd_xx(Xmm(2), Xmm(3))),
        ("andpd xmm15, xmmword ptr [r12]", |e| {
            e.andpd_xm(Xmm(15), xmmword_ptr(R12, 0))
        }),
        ("movups xmm0, xmm1", |e| e.movups_xx(Xmm(0), Xmm(1))),
        ("movups xmm9, xmmword ptr [r13+8]", |e| {
            e.movups_xm(Xmm(9), xmmword_ptr(R13, 8))
        }),
        ("movups xmmword ptr [r12+16], xmm15", |e| {
            e.movups_mx(xmmword_ptr(R12, 16), Xmm(15))
        }),
    ];
    check(cases);
}

#[test]
fn sse_follows_asmjit_width_and_register_field_handling() {
    let mut e = Emitter::new();
    assert!(e.cvtsi2sd_xr(Xmm(0), AL).is_ok());
    assert!(e.movq_xr(Xmm(1), RAX.r32()).is_ok());
    let mut wrapped = Emitter::new();
    assert!(wrapped.movdqu_xx(Xmm(16), Xmm(0)).is_ok());
    assert_eq!(wrapped.bytes, [0xF3, 0x0F, 0x6F, 0xC0]);
}

#[test]
fn btc_and_packed_double_forms() {
    let cases: &[Case] = &[
        ("btc rax, 63", |e| e.btc_ri(RAX, 63)),
        ("btc qword ptr [r13-8], 63", |e| {
            e.btc_mi(qword_ptr(R13, -8), 63)
        }),
        ("addpd xmm9, xmm15", |e| e.addpd_xx(Xmm(9), Xmm(15))),
        ("subpd xmm10, xmm8", |e| e.subpd_xx(Xmm(10), Xmm(8))),
        ("mulpd xmm4, xmm0", |e| e.mulpd_xx(Xmm(4), Xmm(0))),
        ("divpd xmm2, xmm3", |e| e.divpd_xx(Xmm(2), Xmm(3))),
        ("vaddpd xmm9, xmm1, xmm15", |e| {
            e.vaddpd_xxx(Xmm(9), Xmm(1), Xmm(15))
        }),
        ("vsubpd xmm10, xmm8, xmm0", |e| {
            e.vsubpd_xxx(Xmm(10), Xmm(8), Xmm(0))
        }),
        ("vmulpd xmm4, xmm7, xmm0", |e| {
            e.vmulpd_xxx(Xmm(4), Xmm(7), Xmm(0))
        }),
        ("vdivpd xmm2, xmm3, xmm15", |e| {
            e.vdivpd_xxx(Xmm(2), Xmm(3), Xmm(15))
        }),
    ];
    check(cases);
}
