//! Case table of the asmjit oracle test (`asmjit_oracle.rs`).
//!
//! A case is the text asmjit's oracle assembles (syntax in `tests/asmjit_oracle/oracle.cpp`) plus
//! the `Emitter` call that must produce the same bytes (or the same error). To add a family:
//! create `oracle_cases/<family>.rs` with `pub fn cases(out: &mut Vec<OCase>)`, add `mod <family>;`
//! and one `("<family>", <family>::cases)` line to [`FAMILIES`]. Use the helpers below to cover
//! every register view, immediate boundary and addressing mode.

use arinsal_x64::enc::*;

mod alu;
mod avx;
mod bmi;
mod branch;
mod cond;
mod evex;
mod misc;
mod mov;
mod muldiv;
mod shift;
mod sse;
mod stack;

/// The emitter side of a case.
pub type EmitFn = Box<dyn Fn(&mut Emitter) -> Result<(), EncodeError>>;

/// Case generator of one family.
pub type Generator = fn(&mut Vec<OCase>);

/// One oracle case: asmjit text and the emitter call(s) that must encode to the same bytes.
pub struct OCase {
    /// Statements separated by `;` (`add rax, 1`, `jmp L; bind L`, `align 16`).
    pub text: String,
    /// Emits the same sequence through `Emitter`.
    pub run: EmitFn,
}

/// Builds a case.
pub fn case(
    text: impl Into<String>,
    run: impl Fn(&mut Emitter) -> Result<(), EncodeError> + 'static,
) -> OCase {
    OCase {
        text: text.into(),
        run: Box::new(run),
    }
}

/// Instruction families: name (test name) and case generator.
pub const FAMILIES: &[(&str, Generator)] = &[
    ("alu", alu::cases),
    ("mov", mov::cases),
    ("branch", branch::cases),
    ("cond", cond::cases),
    ("stack", stack::cases),
    ("muldiv", muldiv::cases),
    ("shift", shift::cases),
    ("misc", misc::cases),
    ("bmi", bmi::cases),
    ("sse", sse::cases),
    ("avx", avx::cases),
    ("evex", evex::cases),
];

const Q: [&str; 16] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];
const D: [&str; 16] = [
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d",
    "r13d", "r14d", "r15d",
];
const W: [&str; 16] = [
    "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w",
    "r14w", "r15w",
];
const B: [&str; 16] = [
    "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil", "r8b", "r9b", "r10b", "r11b", "r12b",
    "r13b", "r14b", "r15b",
];
const BH: [&str; 4] = ["ah", "ch", "dh", "bh"];

/// Register views by operand size in bytes (1 includes `ah`..`bh`).
pub fn gps(size: u8) -> Vec<(String, Gp)> {
    let (names, ctor): (&[&str], fn(u8) -> Gp) = match size {
        1 => (&B, Gp::b),
        2 => (&W, Gp::w),
        4 => (&D, Gp::d),
        _ => (&Q, Gp::q),
    };
    let mut v: Vec<_> = names
        .iter()
        .enumerate()
        .map(|(i, n)| (n.to_string(), ctor(i as u8)))
        .collect();
    if size == 1 {
        v.extend(
            BH.iter()
                .enumerate()
                .map(|(i, n)| (n.to_string(), Gp::b_hi(i as u8))),
        );
    }
    v
}

/// A representative subset of [`gps`]: low ids, the rsp/rbp/r12/r13 ModRM special cases, r8+.
pub fn gps_few(size: u8) -> Vec<(String, Gp)> {
    let keep = ["rax", "rcx", "rsp", "rbp", "r8", "r12", "r13", "r15"];
    gps(size)
        .into_iter()
        .filter(|(n, g)| {
            let q = if g.kind == GpKind::B8Hi {
                n.as_str()
            } else {
                Q[g.id as usize]
            };
            keep.contains(&q) || g.kind == GpKind::B8Hi && n == "ah"
        })
        .collect()
}

/// Size keyword asmjit's oracle parses for `Mem::size`.
pub fn size_kw(size: u8) -> &'static str {
    match size {
        1 => "byte ptr ",
        2 => "word ptr ",
        4 => "dword ptr ",
        8 => "qword ptr ",
        16 => "xmmword ptr ",
        32 => "ymmword ptr ",
        _ => "",
    }
}

/// Memory operands (text, operand) of access size `size` covering every ModRM/SIB/displacement
/// shape: rsp/r12 (SIB), rbp/r13 (no-disp), disp8/disp32 boundaries, index, rip, absolute,
/// no-base index, and `[rax+rsp*2]` which asmjit rejects. 32-bit addressing (`[eax]`, address-size
/// prefix 67h) is not covered: erts never uses it and `Emitter` does not support it.
pub fn mems(size: u8) -> Vec<(String, Mem)> {
    let k = size_kw(size);
    let mut v: Vec<(String, Mem)> = Vec::new();
    let mut add = |t: String, m: Mem| v.push((format!("{k}[{t}]"), m));
    for (name, base) in [
        ("rax", RAX),
        ("rcx", RCX),
        ("rsp", RSP),
        ("rbp", RBP),
        ("r8", R8),
        ("r12", R12),
        ("r13", R13),
    ] {
        for disp in [
            0,
            1,
            -1,
            127,
            128,
            -128,
            -129,
            0x1000,
            0x7fff_ffff,
            -0x8000_0000,
        ] {
            add(format!("{name}{disp:+}"), Mem::base_disp(base, disp, size));
        }
    }
    for (bn, base) in [
        ("rax", RAX),
        ("rbp", RBP),
        ("rsp", RSP),
        ("r13", R13),
        ("r12", R12),
    ] {
        for (xn, index) in [
            ("rcx", RCX),
            ("rbp", RBP),
            ("r8", R8),
            ("r12", R12),
            ("r15", R15),
        ] {
            for (shift, sc) in [(0u8, 1), (2, 4), (3, 8)] {
                for disp in [0, 8, 0x200] {
                    add(
                        format!("{bn}+{xn}*{sc}{disp:+}"),
                        Mem::base_index(base, index, shift, disp, size),
                    );
                }
            }
        }
    }
    for disp in [0, 4, -4, 0x1234, 0x7fff_ffff, -0x8000_0000] {
        add(format!("rip{disp:+}"), Mem::rip(disp, size));
        add(format!("{disp}"), Mem::abs(disp, size));
    }
    for (xn, index) in [("rcx", RCX), ("r9", R9), ("rbp", RBP)] {
        for (shift, sc) in [(0u8, 1), (1, 2), (3, 8)] {
            for disp in [0, 0x10] {
                add(
                    format!("{xn}*{sc}{disp:+}"),
                    Mem {
                        base: None,
                        index: Some(index),
                        shift,
                        disp,
                        size,
                    },
                );
            }
        }
    }
    // Invalid addresses.
    add("rax+rsp*2".into(), Mem::base_index(RAX, RSP, 1, 0, size));
    v
}

/// Immediate boundaries: every width edge, signed and unsigned.
pub const IMMS: [i64; 26] = [
    0,
    1,
    -1,
    0x7f,
    0x80,
    -0x80,
    -0x81,
    0xff,
    0x100,
    -0x100,
    0x7fff,
    0x8000,
    -0x8000,
    -0x8001,
    0xffff,
    0x1_0000,
    0x1234,
    0x7fff_ffff,
    0x8000_0000,
    -0x8000_0000,
    -0x8000_0001,
    0xffff_ffff,
    0x1_0000_0000,
    0x1234_5678_9abc,
    i64::MAX,
    i64::MIN,
];
