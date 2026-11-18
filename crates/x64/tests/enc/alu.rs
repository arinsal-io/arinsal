//! Golden bytes of the integer ALU family (E10-E12).

use arinsal_x64::enc::*;

use crate::golden::{Case, check};

macro_rules! arith_cases {
    ($test:ident, $m:literal, $rr:ident, $ri:ident, $rm:ident, $mr:ident, $mi:ident,
     [$rax:literal, $rcx:literal, $rsp:literal]) => {
        // `$rax`/`$rcx`/`$rsp` name the register asmjit really encodes for a uint32 immediate on
        // a 64-bit register: the 32-bit view for `and` (kOptimizeForSize), the 64-bit one otherwise.
        #[test]
        fn $test() {
            let cases: &[Case] = &[
                (concat!($m, " rax, rcx"), |e| e.$rr(RAX, RCX)),
                (concat!($m, " r8, r15"), |e| e.$rr(R8, R15)),
                (concat!($m, " rsp, r12"), |e| e.$rr(RSP, R12)),
                (concat!($m, " r8d, r15d"), |e| e.$rr(R8D, R15D)),
                (concat!($m, " eax, ecx"), |e| e.$rr(EAX, ECX)),
                (concat!($m, " ax, bx"), |e| e.$rr(AX, BX)),
                (concat!($m, " r9w, r10w"), |e| e.$rr(R9W, R10W)),
                (concat!($m, " al, sil"), |e| e.$rr(AL, SIL)),
                (concat!($m, " dil, cl"), |e| e.$rr(DIL, CL)),
                (concat!($m, " ah, bl"), |e| e.$rr(AH, BL)),
                (concat!($m, " r9b, al"), |e| e.$rr(R9B, AL)),
                (concat!($m, " ", $rax, ", 1"), |e| e.$ri(RAX, 1)),
                (concat!($m, " ", $rax, ", 0x1000"), |e| e.$ri(RAX, 0x1000)),
                (concat!($m, " ", $rcx, ", 0x1000"), |e| e.$ri(RCX, 0x1000)),
                (concat!($m, " r12, -5"), |e| e.$ri(R12, -5)),
                (concat!($m, " r13, -0x80000000"), |e| {
                    e.$ri(R13, -0x8000_0000)
                }),
                (concat!($m, " ", $rsp, ", 127"), |e| e.$ri(RSP, 127)),
                (concat!($m, " ", $rsp, ", 128"), |e| e.$ri(RSP, 128)),
                (concat!($m, " eax, -1"), |e| e.$ri(EAX, 0xffff_ffff)),
                (concat!($m, " ecx, 0x7fffffff"), |e| e.$ri(ECX, 0x7fff_ffff)),
                (concat!($m, " r11d, 100"), |e| e.$ri(R11D, 100)),
                (concat!($m, " eax, 0x12345"), |e| e.$ri(EAX, 0x12345)),
                (concat!($m, " al, 5"), |e| e.$ri(AL, 5)),
                (concat!($m, " cl, 0x80"), |e| e.$ri(CL, 0x80)),
                (concat!($m, " spl, 1"), |e| e.$ri(SPL, 1)),
                (concat!($m, " ah, 3"), |e| e.$ri(AH, 3)),
                (concat!($m, " r14b, -1"), |e| e.$ri(R14B, -1)),
                (concat!($m, " ax, 0x1234"), |e| e.$ri(AX, 0x1234)),
                (concat!($m, " r10w, 0x1234"), |e| e.$ri(R10W, 0x1234)),
                (concat!($m, " dx, 7"), |e| e.$ri(DX, 7)),
                (concat!($m, " rax, [rbx+8]"), |e| {
                    e.$rm(RAX, qword_ptr(RBX, 8))
                }),
                (concat!($m, " r9d, [rsp]"), |e| {
                    e.$rm(R9D, dword_ptr(RSP, 0))
                }),
                (concat!($m, " cl, byte ptr [r13]"), |e| {
                    e.$rm(CL, byte_ptr(R13, 0))
                }),
                (concat!($m, " sil, byte ptr [rax]"), |e| {
                    e.$rm(SIL, byte_ptr(RAX, 0))
                }),
                (concat!($m, " r15, [r12+r9*8+0x400]"), |e| {
                    e.$rm(R15, Mem::base_index(R12, R9, 3, 0x400, 8))
                }),
                (concat!($m, " [rbx+16], rdx"), |e| {
                    e.$mr(qword_ptr(RBX, 16), RDX)
                }),
                (concat!($m, " [rbp-8], r10d"), |e| {
                    e.$mr(dword_ptr(RBP, -8), R10D)
                }),
                (concat!($m, " [rdi], ah"), |e| e.$mr(byte_ptr(RDI, 0), AH)),
                (concat!($m, " [r8], bx"), |e| e.$mr(word_ptr(R8, 0), BX)),
                (concat!($m, " qword ptr [rbx+16], 1"), |e| {
                    e.$mi(qword_ptr(RBX, 16), 1)
                }),
                (concat!($m, " qword ptr [r13+0x80], -0x1000"), |e| {
                    e.$mi(qword_ptr(R13, 0x80), -0x1000)
                }),
                (concat!($m, " dword ptr [r12+0x100], 0x12345"), |e| {
                    e.$mi(dword_ptr(R12, 0x100), 0x12345)
                }),
                (concat!($m, " dword ptr [rax], -1"), |e| {
                    e.$mi(dword_ptr(RAX, 0), 0xffff_ffff)
                }),
                (concat!($m, " byte ptr [rax], 0xff"), |e| {
                    e.$mi(byte_ptr(RAX, 0), 0xff)
                }),
                (concat!($m, " word ptr [rbp-8], 0x1234"), |e| {
                    e.$mi(word_ptr(RBP, -8), 0x1234)
                }),
                (concat!($m, " word ptr [rbp-8], 3"), |e| {
                    e.$mi(word_ptr(RBP, -8), 3)
                }),
            ];
            check(cases);
        }
    };
}

arith_cases!(
    add,
    "add",
    add_rr,
    add_ri,
    add_rm,
    add_mr,
    add_mi,
    ["rax", "rcx", "rsp"]
);
arith_cases!(
    or,
    "or",
    or_rr,
    or_ri,
    or_rm,
    or_mr,
    or_mi,
    ["rax", "rcx", "rsp"]
);
arith_cases!(
    adc,
    "adc",
    adc_rr,
    adc_ri,
    adc_rm,
    adc_mr,
    adc_mi,
    ["rax", "rcx", "rsp"]
);
arith_cases!(
    sbb,
    "sbb",
    sbb_rr,
    sbb_ri,
    sbb_rm,
    sbb_mr,
    sbb_mi,
    ["rax", "rcx", "rsp"]
);
arith_cases!(
    and,
    "and",
    and_rr,
    and_ri,
    and_rm,
    and_mr,
    and_mi,
    ["eax", "ecx", "esp"]
);
arith_cases!(
    sub,
    "sub",
    sub_rr,
    sub_ri,
    sub_rm,
    sub_mr,
    sub_mi,
    ["rax", "rcx", "rsp"]
);
arith_cases!(
    xor,
    "xor",
    xor_rr,
    xor_ri,
    xor_rm,
    xor_mr,
    xor_mi,
    ["rax", "rcx", "rsp"]
);
arith_cases!(
    cmp,
    "cmp",
    cmp_rr,
    cmp_ri,
    cmp_rm,
    cmp_mr,
    cmp_mi,
    ["rax", "rcx", "rsp"]
);

/// asmjit choices GNU `as` would encode differently.
#[test]
fn asmjit_specific_choices() {
    let cases: &[Case] = &[
        // kOptimizeForSize: `and r64, uint32` drops REX.W.
        ("and eax, 0xff", |e| e.and_ri(RAX, 0xff)),
        ("and r9d, 0x7f", |e| e.and_ri(R9, 0x7f)),
        // ... and keeps the imm32 even when the 32-bit value would sign-extend from imm8.
        (".byte 0x81, 0xe1, 0xff, 0xff, 0xff, 0xff", |e| {
            e.and_ri(RCX, 0xffff_ffff)
        }),
        ("and rax, -16", |e| e.and_ri(RAX, -16)),
        // Other ops keep REX.W for small positive immediates.
        ("or rax, 0xff", |e| e.or_ri(RAX, 0xff)),
        // 16-bit immediates: is_int_n<8> on the raw value, so 0xffff stays imm16.
        (".byte 0x66, 0x3d, 0xff, 0xff", |e| e.cmp_ri(AX, 0xffff)),
        (".byte 0x66, 0x81, 0xf9, 0xff, 0xff", |e| {
            e.cmp_ri(CX, 0xffff)
        }),
    ];
    check(cases);
}

#[test]
fn test_neg_not_inc_dec() {
    let cases: &[Case] = &[
        ("test rax, rcx", |e| e.test_rr(RAX, RCX)),
        ("test r8, r15", |e| e.test_rr(R8, R15)),
        ("test edx, r11d", |e| e.test_rr(EDX, R11D)),
        ("test al, al", |e| e.test_rr(AL, AL)),
        ("test ah, ch", |e| e.test_rr(AH, CH)),
        ("test sil, dil", |e| e.test_rr(SIL, DIL)),
        ("test r10w, ax", |e| e.test_rr(R10W, AX)),
        ("test [rbx+8], rcx", |e| e.test_mr(qword_ptr(RBX, 8), RCX)),
        ("test [r12], r13b", |e| e.test_mr(byte_ptr(R12, 0), R13B)),
        ("test rax, 1", |e| e.test_ri(RAX, 1)),
        ("test rcx, 1", |e| e.test_ri(RCX, 1)),
        ("test r9, -8", |e| e.test_ri(R9, -8)),
        ("test eax, 0x8000", |e| e.test_ri(EAX, 0x8000)),
        ("test edi, 3", |e| e.test_ri(EDI, 3)),
        ("test al, 7", |e| e.test_ri(AL, 7)),
        ("test bl, 0x80", |e| e.test_ri(BL, 0x80)),
        ("test ah, 1", |e| e.test_ri(AH, 1)),
        ("test spl, 15", |e| e.test_ri(SPL, 15)),
        ("test r15b, 1", |e| e.test_ri(R15B, 1)),
        ("test ax, 0x101", |e| e.test_ri(AX, 0x101)),
        ("test si, 3", |e| e.test_ri(SI, 3)),
        ("test byte ptr [rax+1], 0x3f", |e| {
            e.test_mi(byte_ptr(RAX, 1), 0x3f)
        }),
        ("test dword ptr [rsp+4], 0x100", |e| {
            e.test_mi(dword_ptr(RSP, 4), 0x100)
        }),
        ("test qword ptr [r14], 1", |e| {
            e.test_mi(qword_ptr(R14, 0), 1)
        }),
        ("test word ptr [rbx], 2", |e| e.test_mi(word_ptr(RBX, 0), 2)),
        ("neg rax", |e| e.neg_r(RAX)),
        ("neg r12", |e| e.neg_r(R12)),
        ("neg ecx", |e| e.neg_r(ECX)),
        ("neg bh", |e| e.neg_r(BH)),
        ("neg bpl", |e| e.neg_r(BPL)),
        ("neg dx", |e| e.neg_r(DX)),
        ("neg qword ptr [rbx+8]", |e| e.neg_m(qword_ptr(RBX, 8))),
        ("not eax", |e| e.not_r(EAX)),
        ("not r15", |e| e.not_r(R15)),
        ("not r8b", |e| e.not_r(R8B)),
        ("not dword ptr [r9]", |e| e.not_m(dword_ptr(R9, 0))),
        ("inc rax", |e| e.inc_r(RAX)),
        ("inc r11", |e| e.inc_r(R11)),
        ("inc ecx", |e| e.inc_r(ECX)),
        ("inc ax", |e| e.inc_r(AX)),
        ("inc dil", |e| e.inc_r(DIL)),
        ("inc qword ptr [rsp+0x10]", |e| {
            e.inc_m(qword_ptr(RSP, 0x10))
        }),
        ("inc byte ptr [r13]", |e| e.inc_m(byte_ptr(R13, 0))),
        ("dec rdx", |e| e.dec_r(RDX)),
        ("dec r14d", |e| e.dec_r(R14D)),
        ("dec al", |e| e.dec_r(AL)),
        ("dec qword ptr [rip+0x100]", |e| e.dec_m(Mem::rip(0x100, 8))),
        ("dec word ptr [rbx+rcx*2]", |e| {
            e.dec_m(Mem::base_index(RBX, RCX, 1, 0, 2))
        }),
    ];
    check(cases);
}

#[test]
fn alu_rejects_illegal_forms() {
    let mut e = Emitter::new();
    assert_eq!(e.add_rr(RAX, ECX), Err(EncodeError::OperandSizeMismatch));
    assert_eq!(e.add_rr(AH, R8B), Err(EncodeError::InvalidRexPrefix));
    assert_eq!(e.add_rr(AH, SIL), Err(EncodeError::InvalidRexPrefix));
    assert_eq!(
        e.add_ri(RAX, 0x1_0000_0000),
        Err(EncodeError::InvalidImmediate(0x1_0000_0000))
    );
    // Only the 64-bit arith form validates its immediate (x86assembler.cpp kEncodingX86Arith);
    // every other form writes the low bytes (compared with asmjit in `asmjit_oracle`).
    assert_eq!(e.add_ri(AL, 0x100), Ok(()));
    assert_eq!(e.add_ri(EAX, 0x1_0000_0000), Ok(()));
    assert_eq!(e.test_ri(RAX, 0xffff_ffff), Ok(()));
    assert_eq!(
        e.bytes,
        [
            0x04, 0x00, 0x83, 0xc0, 0x00, 0x48, 0xa9, 0xff, 0xff, 0xff, 0xff
        ]
    );
    e.bytes.clear();
    assert_eq!(
        e.add_mi(ptr(RAX, 0), 1),
        Err(EncodeError::AmbiguousOperandSize)
    );
    assert_eq!(e.inc_m(ptr(RAX, 0)), Err(EncodeError::AmbiguousOperandSize));
    assert_eq!(e.neg_r(AH.r64()), Ok(()));
    assert_eq!(
        e.inc_r(Gp::b_hi(4)),
        Err(EncodeError::InvalidRegister(Gp::b_hi(4)))
    );
    assert_eq!(
        e.inc_r(Gp::q(16)),
        Err(EncodeError::InvalidRegister(Gp::q(16)))
    );
    // Failed calls leave no bytes behind: only `neg rax` was emitted.
    assert_eq!(e.bytes, [0x48, 0xf7, 0xd8]);
}
