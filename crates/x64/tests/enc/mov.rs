//! Golden bytes of the move/address/extend family (E13-E14).

use arinsal_x64::enc::*;

use crate::golden::{Case, check};

#[test]
fn mov_forms() {
    let cases: &[Case] = &[
        ("mov rax, rcx", |e| e.mov_rr(RAX, RCX)),
        ("mov r13, rsp", |e| e.mov_rr(R13, RSP)),
        ("mov rbp, r15", |e| e.mov_rr(RBP, R15)),
        ("mov ecx, r9d", |e| e.mov_rr(ECX, R9D)),
        ("mov dx, r8w", |e| e.mov_rr(DX, R8W)),
        ("mov al, ah", |e| e.mov_rr(AL, AH)),
        ("mov sil, r10b", |e| e.mov_rr(SIL, R10B)),
        ("mov rax, [rbx+8]", |e| e.mov_rm(RAX, qword_ptr(RBX, 8))),
        ("mov r14, [r13+0x1000]", |e| {
            e.mov_rm(R14, qword_ptr(R13, 0x1000))
        }),
        ("mov eax, dword ptr [rsp+4]", |e| {
            e.mov_rm(EAX, dword_ptr(RSP, 4))
        }),
        // asmjit sizes Reg <- Mem from the register: a dword_ptr into a 64-bit register loads 8.
        ("mov rcx, qword ptr [rdi]", |e| {
            e.mov_rm(RCX, dword_ptr(RDI, 0))
        }),
        ("mov bx, word ptr [rax+rcx*2]", |e| {
            e.mov_rm(BX, Mem::base_index(RAX, RCX, 1, 0, 2))
        }),
        ("mov dil, byte ptr [r8]", |e| e.mov_rm(DIL, byte_ptr(R8, 0))),
        ("mov rax, [rip+0x40]", |e| e.mov_rm(RAX, Mem::rip(0x40, 8))),
        ("mov [rbx+16], rdx", |e| e.mov_mr(qword_ptr(RBX, 16), RDX)),
        ("mov [r12], r12", |e| e.mov_mr(qword_ptr(R12, 0), R12)),
        ("mov dword ptr [rbp-4], esi", |e| {
            e.mov_mr(dword_ptr(RBP, -4), ESI)
        }),
        ("mov word ptr [r9], ax", |e| e.mov_mr(word_ptr(R9, 0), AX)),
        ("mov byte ptr [rax], bh", |e| e.mov_mr(byte_ptr(RAX, 0), BH)),
        ("mov byte ptr [rax], spl", |e| {
            e.mov_mr(byte_ptr(RAX, 0), SPL)
        }),
        // kOptimizeForSize: uint32 into a 64-bit register uses the zero-extending 32-bit form.
        ("mov eax, 5", |e| e.mov_ri(RAX, 5)),
        ("mov r9d, 0xffffffff", |e| e.mov_ri(R9, 0xffff_ffff)),
        ("mov rcx, -1", |e| e.mov_ri(RCX, -1)),
        ("mov r15, -0x80000000", |e| e.mov_ri(R15, -0x8000_0000)),
        ("movabs rdx, 0x123456789", |e| e.mov_ri(RDX, 0x1_2345_6789)),
        ("movabs r11, -0x80000001", |e| e.mov_ri(R11, -0x8000_0001)),
        ("mov esi, 0x12345678", |e| e.mov_ri(ESI, 0x1234_5678)),
        ("mov r8d, -1", |e| e.mov_ri(R8D, -1)),
        ("mov ax, 0x1234", |e| e.mov_ri(AX, 0x1234)),
        ("mov r12w, 7", |e| e.mov_ri(R12W, 7)),
        ("mov al, 0xff", |e| e.mov_ri(AL, 0xff)),
        ("mov ch, 1", |e| e.mov_ri(CH, 1)),
        ("mov bpl, 2", |e| e.mov_ri(BPL, 2)),
        ("mov r10b, -2", |e| e.mov_ri(R10B, -2)),
        ("mov qword ptr [rbx], 0", |e| e.mov_mi(qword_ptr(RBX, 0), 0)),
        ("mov qword ptr [r13+0x58], -1", |e| {
            e.mov_mi(qword_ptr(R13, 0x58), -1)
        }),
        ("mov dword ptr [rsp+8], 0x12345678", |e| {
            e.mov_mi(dword_ptr(RSP, 8), 0x1234_5678)
        }),
        ("mov word ptr [rax], 0x1234", |e| {
            e.mov_mi(word_ptr(RAX, 0), 0x1234)
        }),
        ("mov byte ptr [rdi+1], 0x80", |e| {
            e.mov_mi(byte_ptr(RDI, 1), 0x80)
        }),
        ("mov qword ptr [rip+8], 0x10", |e| {
            e.mov_mi(Mem::rip(8, 8), 0x10)
        }),
    ];
    check(cases);
}

#[test]
fn lea_forms() {
    let cases: &[Case] = &[
        ("lea rax, [rbx+8]", |e| e.lea(RAX, qword_ptr(RBX, 8))),
        ("lea rsp, [rsp-0x18]", |e| e.lea(RSP, qword_ptr(RSP, -0x18))),
        ("lea r15, [r15+0x100]", |e| {
            e.lea(R15, qword_ptr(R15, 0x100))
        }),
        ("lea rcx, [rax+rdx*4]", |e| {
            e.lea(RCX, Mem::base_index(RAX, RDX, 2, 0, 0))
        }),
        ("lea r8, [r13+r12*8-8]", |e| {
            e.lea(R8, Mem::base_index(R13, R12, 3, -8, 8))
        }),
        ("lea rdx, [rbp+rax]", |e| {
            e.lea(RDX, Mem::base_index(RBP, RAX, 0, 0, 0))
        }),
        ("lea eax, [rcx+1]", |e| e.lea(EAX, qword_ptr(RCX, 1))),
        ("lea r9d, [r9+r9*2]", |e| {
            e.lea(R9D, Mem::base_index(R9, R9, 1, 0, 0))
        }),
        ("lea ax, [rbx+2]", |e| e.lea(AX, ptr(RBX, 2))),
        ("lea rax, [rip+0x1234]", |e| e.lea(RAX, Mem::rip(0x1234, 0))),
        ("lea r12, [rip-4]", |e| e.lea(R12, Mem::rip(-4, 0))),
        ("lea rdi, [rsi*8+0x10]", |e| {
            e.lea(
                RDI,
                Mem {
                    base: None,
                    index: Some(RSI),
                    shift: 3,
                    disp: 0x10,
                    size: 0,
                },
            )
        }),
    ];
    check(cases);
}

#[test]
fn extend_swap_forms() {
    let cases: &[Case] = &[
        ("movzx eax, cl", |e| e.movzx_rr(EAX, CL)),
        ("movzx ecx, ah", |e| e.movzx_rr(ECX, AH)),
        ("movzx r8d, sil", |e| e.movzx_rr(R8D, SIL)),
        ("movzx eax, dx", |e| e.movzx_rr(EAX, DX)),
        ("movzx rax, r9w", |e| e.movzx_rr(RAX, R9W)),
        ("movzx rdx, bl", |e| e.movzx_rr(RDX, BL)),
        ("movzx ax, r15b", |e| e.movzx_rr(AX, R15B)),
        ("movzx eax, byte ptr [rdi+3]", |e| {
            e.movzx_rm(EAX, byte_ptr(RDI, 3))
        }),
        ("movzx r10d, word ptr [rsp+2]", |e| {
            e.movzx_rm(R10D, word_ptr(RSP, 2))
        }),
        ("movzx rcx, byte ptr [r12+r13]", |e| {
            e.movzx_rm(RCX, Mem::base_index(R12, R13, 0, 0, 1))
        }),
        ("movsx rax, cx", |e| e.movsx_rr(RAX, CX)),
        ("movsx rax, dil", |e| e.movsx_rr(RAX, DIL)),
        ("movsx r11, r11b", |e| e.movsx_rr(R11, R11B)),
        ("movsx ecx, bh", |e| e.movsx_rr(ECX, BH)),
        ("movsx rdx, word ptr [rax]", |e| {
            e.movsx_rm(RDX, word_ptr(RAX, 0))
        }),
        ("movsx r9, byte ptr [rbp-1]", |e| {
            e.movsx_rm(R9, byte_ptr(RBP, -1))
        }),
        ("movsxd rax, ecx", |e| e.movsxd_rr(RAX, ECX)),
        ("movsxd r12, r13d", |e| e.movsxd_rr(R12, R13D)),
        ("movsxd rdx, dword ptr [rsi+8]", |e| {
            e.movsxd_rm(RDX, dword_ptr(RSI, 8))
        }),
        ("bswap eax", |e| e.bswap(EAX)),
        ("bswap r9d", |e| e.bswap(R9D)),
        ("bswap rcx", |e| e.bswap(RCX)),
        ("bswap r15", |e| e.bswap(R15)),
        ("movbe ax, word ptr [rdi]", |e| {
            e.movbe_rm(AX, word_ptr(RDI, 0))
        }),
        ("movbe ecx, dword ptr [r8+4]", |e| {
            e.movbe_rm(ECX, dword_ptr(R8, 4))
        }),
        ("movbe r10, qword ptr [rsp+0x20]", |e| {
            e.movbe_rm(R10, qword_ptr(RSP, 0x20))
        }),
        ("movbe qword ptr [rax], rdx", |e| {
            e.movbe_mr(qword_ptr(RAX, 0), RDX)
        }),
        ("movbe dword ptr [r13], r14d", |e| {
            e.movbe_mr(dword_ptr(R13, 0), R14D)
        }),
        ("movbe word ptr [rbx+rcx], si", |e| {
            e.movbe_mr(Mem::base_index(RBX, RCX, 0, 0, 2), SI)
        }),
    ];
    check(cases);
}

#[test]
fn mov_rejects_illegal_forms() {
    let mut e = Emitter::new();
    assert_eq!(e.mov_rr(RAX, EAX), Err(EncodeError::InvalidInstruction));
    assert_eq!(e.mov_rr(AH, R9B), Err(EncodeError::InvalidRexPrefix));
    assert_eq!(
        e.mov_rm(AH, byte_ptr(R8, 0)),
        Err(EncodeError::InvalidRexPrefix)
    );
    assert_eq!(
        e.mov_mi(ptr(RAX, 0), 1),
        Err(EncodeError::AmbiguousOperandSize)
    );
    assert_eq!(e.bswap(AL), Err(EncodeError::InvalidInstruction));
    assert_eq!(
        e.movbe_rm(AL, byte_ptr(RAX, 0)),
        Err(EncodeError::InvalidInstruction)
    );
    // asmjit validates none of the above under release settings (compared in `asmjit_oracle`).
    assert_eq!(e.movzx_rr(EAX, ECX), Ok(()));
    assert_eq!(e.mov_ri(AL, 256), Ok(()));
    assert_eq!(e.bytes, [0x0f, 0xb7, 0xc1, 0xb0, 0x00]);
}
