use arinsal_a64::buf::CodeBuffer;
use arinsal_a64::enc::{Cond, Gpr, Shift};
use arinsal_a64::exec::CodeMemory;

fn disp(words: &[u32], index: usize, shift: u8, bits: u8) -> i64 {
    let raw = (words[index] >> shift) & ((1_u32 << bits) - 1);
    let sign = 1_u32 << (bits - 1);
    let signed = ((raw ^ sign) as i32 - sign as i32) as i64;
    signed * 4
}

fn adr_disp(word: u32) -> i64 {
    let raw = ((word >> 29) & 3) | (((word >> 5) & 0x7ffff) << 2);
    (((raw << 11) as i32) >> 11) as i64
}

#[test]
fn forward_and_backward_fixups_cover_each_branch_form() {
    let mut b = CodeBuffer::new();
    let forward = b.new_label();
    b.b(forward).unwrap();
    b.bl(forward).unwrap();
    b.b_cond(Cond::Eq, forward).unwrap();
    b.cbz(Gpr::x(0), forward).unwrap();
    b.cbnz(Gpr::w(1), forward).unwrap();
    b.tbz(Gpr::x(2), 4, forward).unwrap();
    b.tbnz(Gpr::w(3), 7, forward).unwrap();
    b.adr(Gpr::x(4), forward).unwrap();
    b.word(0xd503_201f);
    b.bind(forward).unwrap();
    let backward = b.new_label();
    b.bind(backward).unwrap();
    b.b(backward).unwrap();
    b.bl(backward).unwrap();
    b.b_cond(Cond::Ne, backward).unwrap();
    b.cbz(Gpr::x(0), backward).unwrap();
    b.cbnz(Gpr::w(1), backward).unwrap();
    b.tbz(Gpr::x(2), 4, backward).unwrap();
    b.tbnz(Gpr::w(3), 7, backward).unwrap();
    b.adr(Gpr::x(4), backward).unwrap();
    let (words, labels) = b.finish_with_labels().unwrap();
    let f = labels[&forward] as i64;
    for index in 0..7 {
        assert_eq!(
            disp(
                &words,
                index,
                if index < 2 { 0 } else { 5 },
                if index == 0 || index == 1 {
                    26
                } else if index < 5 {
                    19
                } else {
                    14
                }
            ),
            f - (index * 4) as i64
        );
    }
    assert_eq!(adr_disp(words[7]), 8); // ADR to forward label.
    let back = labels[&backward] as i64;
    assert_eq!(disp(&words, 9, 0, 26), back - 36);
    assert_eq!(disp(&words, 11, 5, 19), back - 44);
    assert_eq!(disp(&words, 14, 5, 14), back - 56);
    assert_eq!(adr_disp(words[16]), back - 64);
}

#[test]
fn short_branch_uses_veneer_when_target_is_too_far() {
    let mut b = CodeBuffer::new();
    let target = b.new_label();
    b.tbz(Gpr::x(0), 1, target).unwrap();
    for i in 0..10_000 {
        b.word(0xd503_201f);
        if i % 768 == 767 {
            b.check_pending_stubs().unwrap();
        }
    }
    b.check_pending_stubs().unwrap();
    b.bind(target).unwrap();
    let words = b.finish().unwrap();
    let veneer_delta = disp(&words, 0, 5, 14);
    assert!(veneer_delta.abs() < 32 * 1024);
    let veneer = veneer_delta as usize / 4;
    assert_eq!(words[veneer] & 0xfc00_0000, 0x1400_0000);
    assert!(disp(&words, veneer, 0, 26).abs() < 128 * 1024 * 1024);
}

#[test]
fn conditional_branch_uses_veneer_past_one_megabyte() {
    let mut b = CodeBuffer::new();
    let target = b.new_label();
    b.b_cond(Cond::Eq, target).unwrap();
    for i in 0..270_000 {
        b.word(0xd503_201f);
        if i % 1024 == 1023 {
            b.check_pending_stubs().unwrap();
        }
    }
    b.bind(target).unwrap();
    let words = b.finish().unwrap();
    let veneer = disp(&words, 0, 5, 19) as usize / 4;
    assert_eq!(words[veneer] & 0xfc00_0000, 0x1400_0000);
    assert!(disp(&words, veneer, 0, 26).abs() < 128 * 1024 * 1024);
}

#[test]
fn literal_pool_stays_in_range_after_more_than_one_megabyte() {
    let mut b = CodeBuffer::new();
    b.ldr_literal(Gpr::x(0), 0x1234_5678_9abc_def0).unwrap();
    for i in 0..270_000 {
        b.word(0xd503_201f);
        if i % 1024 == 1023 {
            b.check_pending_stubs().unwrap();
        }
    }
    let words = b.finish().unwrap();
    let pool_off = disp(&words, 0, 5, 19);
    assert!(pool_off.abs() < 1 << 20);
    let pool_index = pool_off as usize / 4;
    assert_eq!(
        words[pool_index] as u64 | ((words[pool_index + 1] as u64) << 32),
        0x1234_5678_9abc_def0
    );
}

#[cfg(target_arch = "aarch64")]
#[test]
fn generated_function_executes_forward_branch_loop_and_literal() {
    let mut b = CodeBuffer::new();
    let init = b.new_label();
    let loop_label = b.new_label();
    b.b(init).unwrap();
    b.word(0xd420_0000); // unreachable BRK
    b.bind(loop_label).unwrap();
    b.emit(|e| e.sub_reg(Gpr::x(0), Gpr::x(0), Gpr::x(1), Shift::Lsl, 0))
        .unwrap();
    b.cbnz(Gpr::x(0), loop_label).unwrap();
    b.emit(|e| {
        e.ret(Gpr::x(30))?;
        Ok(())
    })
    .unwrap();
    b.bind(init).unwrap();
    b.emit(|e| e.mov_const(Gpr::x(0), 3)).unwrap();
    b.ldr_literal(Gpr::x(1), 1).unwrap();
    b.b(loop_label).unwrap();
    let words = b.finish().unwrap();
    let mut memory = CodeMemory::new(words.len() * 4).unwrap();
    let offset = memory.alloc(words.len() * 4).unwrap();
    memory
        .write_bytes(
            offset,
            &words
                .iter()
                .flat_map(|w| w.to_le_bytes())
                .collect::<Vec<_>>(),
        )
        .unwrap();
    // SAFETY: the generated function uses the AArch64 C ABI with no arguments and returns u64.
    let f: extern "C" fn() -> u64 = memory.entry(offset).get();
    assert_eq!(f(), 0);
}
