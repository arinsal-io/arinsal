//! Runtime ABI for BeamAsm native code.

#![deny(unsafe_code)]

pub mod arith;
pub mod bif;
pub mod bs_construct;
pub mod bs_match;
pub mod catch;
pub mod construct;
pub mod dispatch;
mod dump;
pub mod float;
pub mod fun;
pub mod guard;
pub mod map;
pub mod misc;
pub mod module;
pub mod receive;
pub mod records;
#[allow(unsafe_code)]
pub mod rt;
pub mod select;

use arinsal_a64::{
    buf::{BufferError, CodeBuffer},
    enc::Gpr,
};
use core::ffi::c_void;

pub use dump::{DumpError, write_global_note};

/// C-layout prefix consumed directly by BeamAsm generated code.
#[repr(C)]
#[derive(Debug, Default)]
pub struct ProcessHeader {
    /// Current young heap allocation pointer.
    pub htop: *mut u64,
    /// Erlang stack pointer, growing toward lower addresses.
    pub stop: *mut u64,
    /// Young heap start.
    pub heap: *mut u64,
    /// Young heap end.
    pub hend: *mut u64,
    /// Reductions remaining in the current slice.
    pub fcalls: i32,
    pub _fcalls_pad: u32,
    /// Exception reason term.
    pub freason: u64,
    /// Exception value term.
    pub fvalue: u64,
    /// Exception trace pointer.
    pub ftrace: *mut c_void,
    /// Number of active catch tags in the process stack.
    pub catches: usize,
    /// Next instruction or native code pointer.
    pub i: *const c_void,
    /// Current function arity.
    pub arity: u8,
    pub _arity_pad: [u8; 7],
    /// Current function metadata pointer.
    pub current: *const c_void,
    /// Process flags.
    pub flags: u64,
    /// Current process identifier consumed by the inline `self/0` emitter.
    pub self_pid: u64,
    /// First heap address safe for destructive tuple updates, published at offset 0x70.
    /// Fields before this extension retain their established BeamAsm ABI offsets.
    pub high_water: *mut u64,
}

const _: () = assert!(std::mem::offset_of!(ProcessHeader, high_water) == 0x70);

/// Register backing storage addressed by BeamAsm's x19.
#[repr(C)]
pub struct SchedulerRegisters {
    /// X register array; x19 points to element zero.
    pub x_reg_array: [u64; 1024],
    /// Floating point register array.
    pub f_reg_array: [f64; 1024],
    /// Scratch words accessed by runtime fragments; word 6 records the pc of a native error.
    pub tmp_mem: [u64; 8],
}

impl Default for SchedulerRegisters {
    fn default() -> Self {
        Self {
            x_reg_array: [0; 1024],
            f_reg_array: [0.0; 1024],
            tmp_mem: [0; 8],
        }
    }
}

/// BeamAsm register assignments on arm64.
pub mod register {
    /// Scheduler X register array base.
    pub const SCHEDULER_REGISTERS: &str = "x19";
    /// Erlang stack pointer.
    pub const E: &str = "x20";
    /// Process header.
    pub const C_P: &str = "x21";
    /// Remaining reductions.
    pub const FCALLS: &str = "w22";
    /// Young heap bump pointer.
    pub const HTOP: &str = "x23";
    /// Active code generation index.
    pub const ACTIVE_CODE_IX: &str = "x24";
    /// Register backed X registers, in logical order.
    pub const XREGS: [&str; 6] = ["x25", "x26", "x27", "x28", "x15", "x16"];
    /// Float registers.
    pub const FREGS: [&str; 8] = ["d8", "d9", "d10", "d11", "d12", "d13", "d14", "d15"];
    /// Runtime helper arguments and return value.
    pub const ARG: [&str; 6] = ["x0", "x1", "x2", "x3", "x4", "x5"];
    /// Scratch registers.
    pub const TMP: [&str; 6] = ["x8", "x9", "x10", "x11", "x12", "x13"];
}

/// Native execution outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    /// Native code returned with reductions remaining.
    Returned,
    /// Native code returned after exhausting reductions.
    Yield,
    /// Native code requested interpretation at the supplied instruction pointer.
    CallUnported { target_pc: usize, resume_pc: usize },
    /// Native execution is unavailable on this target architecture.
    Unsupported,
}

/// Selects process fields synchronized at a native/runtime boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Update(u8);

impl Update {
    /// No state synchronization (erts: an empty update set).
    pub const NONE: Self = Self(0);
    /// Synchronize the Erlang stack pointer.
    pub const STACK: Self = Self(1 << 0);
    /// Synchronize the young heap pointer.
    pub const HEAP: Self = Self(1 << 1);
    /// Synchronize reductions.
    pub const REDUCTIONS: Self = Self(1 << 2);
    /// Synchronize the six register-backed X values.
    pub const X_REGS: Self = Self(1 << 4);
    /// Synchronize stack and heap pointers together.
    pub const HEAP_ALLOC: Self = Self(Self::HEAP.0 | Self::STACK.0);

    /// Combines synchronization flags.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// Publishes register-backed state before a runtime or scheduler call.
// Port of erts/emulator/beam/jit/arm/beam_asm.hpp:459-536, OTP-29.1.1
/// Machine registers caching X0..X5.
const X_REG_CACHE: [u8; 6] = [25, 26, 27, 28, 15, 16];

/// X registers a runtime call saves and restores, paired for `stp`/`ldp`.
///
/// X4 and X5 live in the caller-saved x15/x16, so they are kept across every call whatever the
/// live count: like erts, X registers past `live` must survive untouched (a failure path may
/// still read an immediate there).
fn cached_x_regs(live: usize, update: Update) -> Vec<(usize, Option<usize>)> {
    let mut indexes = Vec::with_capacity(6);
    if update.contains(Update::X_REGS) {
        indexes.extend(0..live.min(4));
    }
    indexes.extend([4, 5]);
    let mut pairs = Vec::with_capacity(3);
    let mut iter = indexes.into_iter().peekable();
    while let Some(first) = iter.next() {
        if first % 2 == 0 && iter.peek() == Some(&(first + 1)) {
            iter.next();
            pairs.push((first, Some(first + 1)));
        } else {
            pairs.push((first, None));
        }
    }
    pairs
}

pub fn emit_enter_runtime(
    code: &mut CodeBuffer,
    live: usize,
    update: Update,
) -> Result<(), BufferError> {
    code.emit(|e| {
        let frame_pointer_slot = std::mem::offset_of!(SchedulerRegisters, tmp_mem) as u32 + 2 * 8;
        e.str_uoff(Gpr::x(29), Gpr::x(19), frame_pointer_slot)?;
        if update.contains(Update::STACK) && update.contains(Update::HEAP) {
            e.stp(Gpr::x(23), Gpr::x(20), Gpr::x(21), 0)?;
        } else {
            if update.contains(Update::STACK) {
                e.str_uoff(Gpr::x(20), Gpr::x(21), 8)?;
            }
            if update.contains(Update::HEAP) {
                e.str_uoff(Gpr::x(23), Gpr::x(21), 0)?;
            }
        }
        if update.contains(Update::REDUCTIONS) {
            e.str_uoff(Gpr::w(22), Gpr::x(21), 32)?;
        }
        for (first, second) in cached_x_regs(live, update) {
            let offset = (first as u32) * 8;
            match second {
                Some(second) => e.stp(
                    Gpr::x(X_REG_CACHE[first]),
                    Gpr::x(X_REG_CACHE[second]),
                    Gpr::x(19),
                    offset as i16,
                )?,
                None => e.str_uoff(Gpr::x(X_REG_CACHE[first]), Gpr::x(19), offset)?,
            }
        }
        Ok(())
    })
}

/// Reloads state changed by a runtime or scheduler call.
// Port of erts/emulator/beam/jit/arm/beam_asm.hpp:539-601, OTP-29.1.1
pub fn emit_leave_runtime(
    code: &mut CodeBuffer,
    live: usize,
    update: Update,
) -> Result<(), BufferError> {
    code.emit(|e| {
        let frame_pointer_slot = std::mem::offset_of!(SchedulerRegisters, tmp_mem) as u32 + 2 * 8;
        e.ldr_uoff(Gpr::x(29), Gpr::x(19), frame_pointer_slot)?;
        if update.contains(Update::STACK) && update.contains(Update::HEAP) {
            e.ldp(Gpr::x(23), Gpr::x(20), Gpr::x(21), 0)?;
        } else {
            if update.contains(Update::HEAP) {
                e.ldr_uoff(Gpr::x(23), Gpr::x(21), 0)?;
            }
            if update.contains(Update::STACK) {
                e.ldr_uoff(Gpr::x(20), Gpr::x(21), 8)?;
            }
        }
        if update.contains(Update::REDUCTIONS) {
            e.ldr_uoff(Gpr::w(22), Gpr::x(21), 32)?;
        }
        for (first, second) in cached_x_regs(live, update) {
            let offset = (first as u32) * 8;
            match second {
                Some(second) => e.ldp(
                    Gpr::x(X_REG_CACHE[first]),
                    Gpr::x(X_REG_CACHE[second]),
                    Gpr::x(19),
                    offset as i16,
                )?,
                None => e.ldr_uoff(Gpr::x(X_REG_CACHE[first]), Gpr::x(19), offset)?,
            }
        }
        Ok(())
    })?;
    emit_validate_native_cursor(code)
}

/// Emits the JIT_HARD_DEBUG heap and stack cursor invariant check when requested.
// Port of erts/emulator/beam/jit/arm/instr_common.cpp:160-177, OTP-29.1.1.
pub fn emit_validate_native_cursor(code: &mut CodeBuffer) -> Result<(), BufferError> {
    if std::env::var_os("ARINSAL_BEAMASM_VALIDATE").is_none() {
        return Ok(());
    }

    let failed = code.new_label();
    let valid = code.new_label();
    let instruction = (code.offset() / 4) as u16;
    let trace_instruction = std::env::var("ARINSAL_BEAMASM_VALIDATE_TRACE")
        .ok()
        .map(|value| {
            value
                .split(',')
                .filter_map(|item| item.trim().parse::<u16>().ok())
                .collect::<Vec<_>>()
        });
    if trace_instruction
        .as_ref()
        .is_some_and(|instructions| instructions.contains(&instruction))
    {
        code.emit(|e| {
            e.stp_pre(Gpr::x(0), Gpr::x(1), Gpr::sp(), -80)?;
            e.stp(Gpr::x(2), Gpr::x(3), Gpr::sp(), 16)?;
            e.stp(Gpr::x(4), Gpr::x(30), Gpr::sp(), 32)?;
            e.stp(Gpr::x(5), Gpr::x(6), Gpr::sp(), 48)?;
            e.stp(Gpr::x(15), Gpr::x(16), Gpr::sp(), 64)?;
            e.mov_const(Gpr::x(0), u64::from(instruction))?;
            e.mov_reg(Gpr::x(1), Gpr::x(20))?;
            e.mov_reg(Gpr::x(2), Gpr::x(23))?;
            e.mov_reg(Gpr::x(5), Gpr::x(25))?;
            e.mov_reg(Gpr::x(6), Gpr::x(26))?;
            e.ldr_uoff(Gpr::x(3), Gpr::x(21), 16)?;
            e.ldr_uoff(Gpr::x(4), Gpr::x(21), 24)?;
            e.mov_reg(Gpr::x(7), Gpr::x(30))?;
            e.mov_const(Gpr::x(17), report_native_cursor as *const () as u64)?;
            e.blr(Gpr::x(17))?;
            e.ldp(Gpr::x(15), Gpr::x(16), Gpr::sp(), 64)?;
            e.ldp(Gpr::x(4), Gpr::x(30), Gpr::sp(), 32)?;
            e.ldp(Gpr::x(2), Gpr::x(3), Gpr::sp(), 16)?;
            e.ldp(Gpr::x(5), Gpr::x(6), Gpr::sp(), 48)?;
            e.ldp_post(Gpr::x(0), Gpr::x(1), Gpr::sp(), 80)
        })?;
    }
    code.emit(|e| e.tst_imm(Gpr::x(20), 7))?;
    code.b_cond(arinsal_a64::enc::Cond::Ne, failed)?;
    code.emit(|e| e.cmp_reg(Gpr::x(20), Gpr::x(23), arinsal_a64::enc::Shift::Lsl, 0))?;
    code.b_cond(arinsal_a64::enc::Cond::Cc, failed)?;
    code.emit(|e| e.ldr_uoff(Gpr::x(8), Gpr::x(21), 16))?;
    code.emit(|e| e.cmp_reg(Gpr::x(23), Gpr::x(8), arinsal_a64::enc::Shift::Lsl, 0))?;
    code.b_cond(arinsal_a64::enc::Cond::Cc, failed)?;
    code.emit(|e| e.ldr_uoff(Gpr::x(8), Gpr::x(21), 24))?;
    code.emit(|e| e.cmp_reg(Gpr::x(20), Gpr::x(8), arinsal_a64::enc::Shift::Lsl, 0))?;
    code.b_cond(arinsal_a64::enc::Cond::Hi, failed)?;
    code.b(valid)?;
    code.bind(failed)?;
    code.emit(|e| {
        e.mov_const(Gpr::x(0), u64::from(instruction))?;
        e.mov_reg(Gpr::x(1), Gpr::x(20))?;
        e.mov_reg(Gpr::x(2), Gpr::x(23))?;
        e.ldr_uoff(Gpr::x(3), Gpr::x(21), 16)?;
        e.ldr_uoff(Gpr::x(4), Gpr::x(21), 24)?;
        e.mov_reg(Gpr::x(5), Gpr::x(25))?;
        e.mov_reg(Gpr::x(6), Gpr::x(26))?;
        e.mov_reg(Gpr::x(7), Gpr::x(30))?;
        e.mov_const(Gpr::x(17), report_native_cursor_failure as *const () as u64)?;
        e.blr(Gpr::x(17))?;
        e.udf(instruction);
        Ok(())
    })?;
    code.bind(valid)
}

extern "C" fn report_native_cursor_failure(
    instruction: u64,
    stack: u64,
    heap_top: u64,
    heap_start: u64,
    heap_end: u64,
    x0: u64,
    x1: u64,
    instruction_pc: u64,
) {
    eprintln!(
        "BeamAsm cursor invariant failed at native instruction {instruction} (LR={instruction_pc:#x}): E={stack:#x}, HTOP={heap_top:#x}, heap=[{heap_start:#x}, {heap_end:#x}], X0={x0:#x}, X1={x1:#x}"
    );
}

extern "C" fn report_native_cursor(
    instruction: u64,
    stack: u64,
    heap_top: u64,
    heap_start: u64,
    heap_end: u64,
    x0: u64,
    x1: u64,
    instruction_pc: u64,
) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static REPORTS: AtomicUsize = AtomicUsize::new(0);
    if REPORTS.fetch_add(1, Ordering::Relaxed) >= 24 {
        return;
    }
    eprintln!(
        "BeamAsm cursor at native instruction {instruction} (LR={instruction_pc:#x}): E={stack:#x}, HTOP={heap_top:#x}, heap=[{heap_start:#x}, {heap_end:#x}], X0={x0:#x}, X1={x1:#x}"
    );
}

pub use rt::enter_native_raw;

/// Enters finalized generated code through the reviewed native ABI bridge.
pub fn enter_native(
    header: &mut ProcessHeader,
    regs: &mut SchedulerRegisters,
    entry: &NativeEntry<'_>,
) -> ExitReason {
    rt::enter_native(header, regs, entry)
}

/// A native function whose executable mapping is kept alive by this borrow.
pub struct NativeEntry<'a> {
    pub(crate) memory: &'a arinsal_a64::exec::CodeMemory,
    pub(crate) offset: usize,
}

// ProcessHeader is a fixed prefix copied from the OTP Process offsets used by BeamAsm.
const _: () = {
    assert!(core::mem::offset_of!(ProcessHeader, htop) == 0x00);
    assert!(core::mem::offset_of!(ProcessHeader, stop) == 0x08);
    assert!(core::mem::offset_of!(ProcessHeader, heap) == 0x10);
    assert!(core::mem::offset_of!(ProcessHeader, hend) == 0x18);
    assert!(core::mem::offset_of!(ProcessHeader, fcalls) == 0x20);
    assert!(core::mem::offset_of!(ProcessHeader, freason) == 0x28);
    assert!(core::mem::offset_of!(ProcessHeader, fvalue) == 0x30);
    assert!(core::mem::offset_of!(ProcessHeader, ftrace) == 0x38);
    assert!(core::mem::offset_of!(ProcessHeader, catches) == 0x40);
    assert!(core::mem::offset_of!(ProcessHeader, i) == 0x48);
    assert!(core::mem::offset_of!(ProcessHeader, arity) == 0x50);
    assert!(core::mem::offset_of!(ProcessHeader, current) == 0x58);
    assert!(core::mem::offset_of!(ProcessHeader, flags) == 0x60);
    assert!(core::mem::offset_of!(ProcessHeader, self_pid) == 0x68);
    assert!(core::mem::offset_of!(SchedulerRegisters, x_reg_array) == 0);
    assert!(core::mem::offset_of!(SchedulerRegisters, f_reg_array) == 8192);
    assert!(core::mem::offset_of!(SchedulerRegisters, tmp_mem) == 16384);
};
