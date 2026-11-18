//! Golden bytes of every addressing shape through `mov r, [mem]` / `mov [mem], r`: ModRM/SIB,
//! disp0/disp8/disp32 selection, REX.R/X/B, the RBP/R13 and RSP/R12 special cases, RIP and
//! absolute addressing.

use arinsal_x64::enc::*;

use crate::golden::{Case, check};

const ALL_Q: [Gp; 16] = [
    RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15,
];

const NAMES: [&str; 16] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];

/// Every base x every displacement class x a low and a high data register; built at run time,
/// so it calls the assembler directly instead of through `Case` function pointers.
#[test]
fn every_base_and_displacement() {
    let mut lines = Vec::new();
    let mut bytes = Vec::new();
    for (b, base) in ALL_Q.iter().enumerate() {
        for disp in [0, 1, -128, 127, 128, -129, 0x12345678, i32::MIN] {
            for (r, reg) in [(1usize, RCX), (10, R10)] {
                lines.push(format!("mov {}, [{} + ({disp})]", NAMES[r], NAMES[b]));
                let mut e = Emitter::new();
                e.mov_rm(reg, qword_ptr(*base, disp)).unwrap();
                bytes.push(e.bytes);
                lines.push(format!("mov [{} + ({disp})], {}", NAMES[b], NAMES[r]));
                let mut e = Emitter::new();
                e.mov_mr(qword_ptr(*base, disp), reg).unwrap();
                bytes.push(e.bytes);
            }
        }
    }
    compare(&lines, &bytes);
}

/// Every base x every index (except rsp) x every scale, with disp 0 and disp8.
#[test]
fn every_base_index_scale() {
    let mut lines = Vec::new();
    let mut bytes = Vec::new();
    for (b, base) in ALL_Q.iter().enumerate() {
        for (i, index) in ALL_Q.iter().enumerate() {
            if i == 4 {
                continue;
            }
            for shift in 0..4u8 {
                for disp in [0, 8, 0x400] {
                    lines.push(format!(
                        "mov rax, [{} + {}*{} + {disp}]",
                        NAMES[b],
                        NAMES[i],
                        1 << shift
                    ));
                    let mut e = Emitter::new();
                    e.mov_rm(RAX, Mem::base_index(*base, *index, shift, disp, 8))
                        .unwrap();
                    bytes.push(e.bytes);
                }
            }
        }
    }
    compare(&lines, &bytes);
}

fn compare(lines: &[String], bytes: &[Vec<u8>]) {
    let texts: Vec<&str> = lines.iter().map(String::as_str).collect();
    let Some(expected) = crate::golden::assemble(&texts) else {
        eprintln!("GNU as/objcopy not found: golden bytes not compared");
        return;
    };
    let bad: Vec<_> = (0..lines.len())
        .filter(|&i| expected[i] != bytes[i])
        .map(|i| {
            format!(
                "{}: as {:02x?} emitter {:02x?}",
                lines[i], expected[i], bytes[i]
            )
        })
        .collect();
    assert!(
        bad.is_empty(),
        "{} mismatches:\n{}",
        bad.len(),
        bad.join("\n")
    );
}

#[test]
fn rip_index_only_and_absolute() {
    let cases: &[Case] = &[
        ("mov rax, [rip+0]", |e| e.mov_rm(RAX, Mem::rip(0, 8))),
        ("mov r9, [rip-0x80]", |e| e.mov_rm(R9, Mem::rip(-0x80, 8))),
        ("mov [rip+0x7fffffff], r15", |e| {
            e.mov_mr(Mem::rip(i32::MAX, 8), R15)
        }),
        ("mov rax, [r9*4+0]", |e| {
            e.mov_rm(
                RAX,
                Mem {
                    base: None,
                    index: Some(R9),
                    shift: 2,
                    disp: 0,
                    size: 8,
                },
            )
        }),
        ("mov rcx, qword ptr ds:0x1000", |e| {
            e.mov_rm(RCX, Mem::abs(0x1000, 8))
        }),
        ("mov rcx, qword ptr ds:-8", |e| {
            e.mov_rm(RCX, Mem::abs(-8, 8))
        }),
        ("mov eax, dword ptr ds:0x10", |e| {
            e.mov_rm(EAX, Mem::abs(0x10, 4))
        }),
        ("add qword ptr ds:0x20, 1", |e| {
            e.add_mi(Mem::abs(0x20, 8), 1)
        }),
    ];
    check(cases);
}

#[test]
fn rip_fixup_points_at_displacement() {
    let mut e = Emitter::new();
    e.mov_ri(RAX, 1).unwrap();
    assert_eq!(e.last_rip_fixup(), None);
    let start = e.len();
    // cmp qword ptr [rip+disp], imm8: the displacement is followed by an immediate.
    e.cmp_mi(Mem::rip(0x11223344, 8), 5).unwrap();
    let fix = e.last_rip_fixup().expect("rip operand");
    assert_eq!(fix.end, e.len());
    assert_eq!(fix.disp_at, start + 3);
    assert_eq!(
        e.bytes[fix.disp_at..fix.disp_at + 4],
        0x11223344i32.to_le_bytes()
    );
    assert_eq!(e.bytes[fix.end - 1], 5);
    e.lea(R12, Mem::rip(0, 0)).unwrap();
    let fix = e.last_rip_fixup().expect("rip operand");
    assert_eq!((fix.disp_at, fix.end), (e.len() - 4, e.len()));
    e.mov_rr(RAX, RCX).unwrap();
    assert_eq!(e.last_rip_fixup(), None);
}

#[test]
fn illegal_addresses() {
    let mut e = Emitter::new();
    let rsp_index = Mem::base_index(RAX, RSP, 0, 0, 8);
    assert_eq!(
        e.mov_rm(RAX, rsp_index),
        Err(EncodeError::InvalidAddressIndex)
    );
    let wide_scale = Mem::base_index(RAX, RCX, 4, 0, 8);
    assert_eq!(
        e.mov_rm(RAX, wide_scale),
        Err(EncodeError::InvalidAddressIndex)
    );
    let index32 = Mem::base_index(RAX, ECX, 0, 0, 8);
    assert_eq!(
        e.mov_rm(RAX, index32),
        Err(EncodeError::InvalidAddressIndex)
    );
    assert_eq!(
        e.mov_rm(RAX, qword_ptr(EAX, 0)),
        Err(EncodeError::InvalidAddress)
    );
    let rip_index = Mem {
        index: Some(RCX),
        ..Mem::rip(0, 8)
    };
    assert_eq!(e.mov_rm(RAX, rip_index), Err(EncodeError::InvalidAddress));
    assert!(e.is_empty());
}
