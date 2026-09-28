//! Minimal AArch64 template emitter for the experiment's generic operation set.

use super::{Compiled, Op, State, slow};
use std::ffi::c_void;
use std::time::{Duration, Instant};

struct Patch {
    at: usize,
    target: usize,
    conditional: bool,
}

/// Executable mapping retained for the duration of calls into generated code.
pub struct Code {
    memory: *mut c_void,
    capacity: usize,
    /// Number of emitted machine-code bytes.
    pub bytes: usize,
}

impl Drop for Code {
    fn drop(&mut self) {
        // SAFETY: This mapping was returned by mmap and has no callers after Code drops.
        unsafe {
            libc::munmap(self.memory, self.capacity);
        }
    }
}

unsafe extern "C" {
    fn sys_icache_invalidate(start: *mut c_void, len: usize);
}

fn load(words: &mut Vec<u32>, register: u32, slot: u8) {
    let offset = std::mem::offset_of!(State, regs) as u32 / 8 + u32::from(slot);
    words.push(0xf940_0260 | register | (offset << 10));
}

fn store(words: &mut Vec<u32>, register: u32, slot: u8) {
    let offset = std::mem::offset_of!(State, regs) as u32 / 8 + u32::from(slot);
    words.push(0xf900_0260 | register | (offset << 10));
}

fn move_imm(words: &mut Vec<u32>, register: u32, value: u32) {
    assert!(value <= u16::MAX as u32);
    words.push(0xd280_0000 | (value << 5) | register);
}

fn helper(words: &mut Vec<u32>, opcode: u32, dst: u32, src: u32) {
    words.push(0xaa13_03e0); // mov x0, x19
    move_imm(words, 1, opcode);
    move_imm(words, 2, dst);
    move_imm(words, 3, src);
    let address = slow as *const () as usize as u64;
    words.push(0xd280_0010 | (((address & 0xffff) as u32) << 5));
    for (shift, base) in [(16, 0xf2a0_0010), (32, 0xf2c0_0010), (48, 0xf2e0_0010)] {
        words.push(base | ((((address >> shift) & 0xffff) as u32) << 5));
    }
    words.push(0xd63f_0200); // blr x16
}

fn branch(words: &mut Vec<u32>, patches: &mut Vec<Patch>, target: usize, condition: Option<u32>) {
    let at = words.len();
    words.push(condition.map_or(0x1400_0000, |c| 0x5400_0000 | c));
    patches.push(Patch {
        at,
        target,
        conditional: condition.is_some(),
    });
}

/// Emit one native body for a sequence of modeled operations.
pub fn compile(code: &[Op]) -> (Code, Compiled, Duration) {
    let started = Instant::now();
    let mut words = vec![0xa9bf_7bf3, 0xaa00_03f3]; // save x19/lr; state pointer in x19
    let mut labels = vec![0; code.len() + 2];
    let mut patches = Vec::new();
    let halt_label = code.len();
    let ret_label = code.len() + 1;
    let return_points: Vec<_> = code
        .iter()
        .enumerate()
        .filter_map(|(i, op)| matches!(op, Op::Call(_)).then_some(i + 1))
        .collect();
    for (ip, op) in code.iter().enumerate() {
        labels[ip] = words.len();
        match *op {
            Op::Move(d, s) => {
                load(&mut words, 1, s);
                store(&mut words, 1, d);
            }
            Op::Add(d, a, b) => {
                load(&mut words, 1, a);
                load(&mut words, 2, b);
                words.push(0x8b02_0021); // add x1,x1,x2
                store(&mut words, 1, d);
            }
            Op::AddImm(d, a, k) => {
                assert!(k.unsigned_abs() <= 4095);
                load(&mut words, 1, a);
                words.push(
                    if k >= 0 { 0x9100_0021 } else { 0xd100_0021 }
                        | ((k.unsigned_abs() as u32) << 10),
                );
                store(&mut words, 1, d);
            }
            Op::BranchZero(r, t) => {
                load(&mut words, 1, r);
                words.push(0xf100_003f);
                branch(&mut words, &mut patches, t, Some(0));
            }
            Op::BranchGe(a, b, t) => {
                load(&mut words, 1, a);
                load(&mut words, 2, b);
                words.push(0xeb02_003f);
                branch(&mut words, &mut patches, t, Some(10));
            }
            Op::BranchNeImm(r, k, t) => {
                assert!((0..=4095).contains(&k));
                load(&mut words, 1, r);
                words.push(0xf100_003f | ((k as u32) << 10));
                branch(&mut words, &mut patches, t, Some(1));
            }
            Op::BranchLtImm(r, k, t) => {
                assert!((0..=4095).contains(&k));
                load(&mut words, 1, r);
                words.push(0xf100_003f | ((k as u32) << 10));
                branch(&mut words, &mut patches, t, Some(11));
            }
            Op::Jump(t) => branch(&mut words, &mut patches, t, None),
            Op::ListLoad(d, i) => helper(&mut words, 0, u32::from(d), u32::from(i)),
            Op::ListStore(i, r) => helper(&mut words, 1, u32::from(i), u32::from(r)),
            Op::TupleSet(r) => helper(&mut words, 2, 0, u32::from(r)),
            Op::TupleGet(d) => helper(&mut words, 3, u32::from(d), 0),
            Op::ByteLoad(d, i) => helper(&mut words, 4, u32::from(d), u32::from(i)),
            Op::Call(t) => {
                helper(&mut words, 5, (ip + 1) as u32, t as u32);
                branch(&mut words, &mut patches, t, None);
            }
            Op::Ret => {
                helper(&mut words, 6, 0, 0);
                words.push(0x1100_0401); // add w1,w0,#1; zero means outer return
                let at = words.len();
                words.push(0x3400_0001);
                patches.push(Patch {
                    at,
                    target: ret_label,
                    conditional: true,
                });
                for &point in &return_points {
                    assert!(point <= 4095);
                    words.push(0x7100_001f | ((point as u32) << 10)); // cmp w0,#point
                    branch(&mut words, &mut patches, point, Some(0));
                }
                branch(&mut words, &mut patches, ret_label, None);
            }
            Op::Halt => branch(&mut words, &mut patches, halt_label, None),
            Op::Nop => {}
            Op::FusedDecIncJump(a, c, t) => {
                load(&mut words, 1, a);
                words.push(0xd100_0421);
                store(&mut words, 1, a);
                load(&mut words, 1, c);
                words.push(0x9100_0421);
                store(&mut words, 1, c);
                branch(&mut words, &mut patches, t, None);
            }
        }
    }
    labels[halt_label] = words.len();
    load(&mut words, 0, 1);
    words.extend([0xa8c1_7bf3, 0xd65f_03c0]);
    labels[ret_label] = words.len();
    load(&mut words, 0, 0);
    words.extend([0xa8c1_7bf3, 0xd65f_03c0]);
    for patch in patches {
        let distance = labels[patch.target] as isize - patch.at as isize;
        let old = words[patch.at];
        if patch.conditional {
            assert!((-(1 << 18)..(1 << 18)).contains(&distance));
            words[patch.at] = old | (((distance as i32 as u32) & 0x7ffff) << 5);
        } else {
            assert!((-(1 << 25)..(1 << 25)).contains(&distance));
            words[patch.at] = old | ((distance as i32 as u32) & 0x3ff_ffff);
        }
    }
    let bytes = words.len() * 4;
    let capacity = bytes.next_multiple_of(16384);
    // SAFETY: MAP_JIT allocates a private executable mapping. Code retains and frees it.
    let memory = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            capacity,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_JIT,
            -1,
            0,
        )
    };
    assert_ne!(
        memory,
        libc::MAP_FAILED,
        "mmap: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: This thread exclusively populates the new mapping before publishing the function.
    unsafe {
        libc::pthread_jit_write_protect_np(0);
        std::ptr::copy_nonoverlapping(words.as_ptr() as *const u8, memory as *mut u8, bytes);
        libc::pthread_jit_write_protect_np(1);
        sys_icache_invalidate(memory, bytes);
    }
    let owner = Code {
        memory,
        capacity,
        bytes,
    };
    // SAFETY: The mapping contains an AArch64 function with the declared C ABI.
    let callable: Compiled = unsafe { std::mem::transmute(memory) };
    (owner, callable, started.elapsed())
}
