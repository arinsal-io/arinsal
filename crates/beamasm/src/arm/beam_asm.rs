//! Port of erts/emulator/beam/jit/arm/beam_asm.hpp (register assignments, `emit_enter_runtime`,
//! `emit_leave_runtime`) and erts/emulator/beam/jit/arm/instr_common.cpp (`emit_validate`),
//! OTP-29.1.1.

use arinsal_a64::{
    buf::{BufferError, CodeBuffer},
    enc::Gpr,
};

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

    pub(crate) const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// Publishes register-backed state before a runtime or scheduler call.
// Port of erts/emulator/beam/jit/arm/beam_asm.hpp:459-536, OTP-29.1.1
/// Machine registers caching X0..X5.
const X_REG_CACHE: [u8; 6] = [25, 26, 27, 28, 15, 16];

/// X registers a runtime call saves and restores, paired for `stp`/`ldp`.
///
/// X4 and X5 live in the caller-saved x15/x16. As in erts, only the registers below `live` are
/// saved: with `Update::X_REGS` the callee-saved X0..X3 as well, otherwise just the fragile ones.
/// Registers at or above `live` are dead across the call, so a caller that still needs them
/// passes a larger count (erts defaults to all six).
fn cached_x_regs(live: usize, update: Update) -> impl Iterator<Item = (usize, Option<usize>)> {
    // The saved registers are the contiguous run `start..end` of the six cached ones (X0..X3
    // when `X_REGS`, then X4 and X5), so there are three pairs at most and no list is needed.
    let start = if update.contains(Update::X_REGS) {
        0
    } else {
        4
    };
    let end = live.min(6).max(start);
    let mut next = start;
    std::iter::from_fn(move || {
        if next >= end {
            return None;
        }
        let first = next;
        if first % 2 == 0 && first + 1 < end {
            next += 2;
            Some((first, Some(first + 1)))
        } else {
            next += 1;
            Some((first, None))
        }
    })
}

pub fn emit_enter_runtime(
    code: &mut CodeBuffer,
    live: usize,
    update: Update,
) -> Result<(), BufferError> {
    code.emit(|e| {
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

fn validate_trace_instructions() -> &'static [u16] {
    static TRACE: std::sync::OnceLock<Vec<u16>> = std::sync::OnceLock::new();
    TRACE.get_or_init(|| {
        std::env::var("ARINSAL_BEAMASM_VALIDATE_TRACE")
            .ok()
            .map(|value| {
                value
                    .split(',')
                    .filter_map(|item| item.trim().parse::<u16>().ok())
                    .collect()
            })
            .unwrap_or_default()
    })
}

/// Emits the JIT_HARD_DEBUG heap and stack cursor invariant check when requested.
// Port of erts/emulator/beam/jit/arm/instr_common.cpp (emit_validate), OTP-29.1.1.
pub fn emit_validate_native_cursor(code: &mut CodeBuffer) -> Result<(), BufferError> {
    if !native_cursor_validation_enabled() {
        return Ok(());
    }

    let failed = code.new_label();
    let valid = code.new_label();
    let instruction = (code.offset() / 4) as u16;
    if validate_trace_instructions().contains(&instruction) {
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

/// Reports whether optional native cursor checks are enabled for this process.
pub(crate) fn native_cursor_validation_enabled() -> bool {
    static VALIDATE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *VALIDATE.get_or_init(|| std::env::var_os("ARINSAL_BEAMASM_VALIDATE").is_some())
}

static CURSOR_FAILURE_HOOK: std::sync::OnceLock<extern "C" fn()> = std::sync::OnceLock::new();

/// Debug aid: a function the cursor validation failure report calls after its message.
pub fn set_cursor_failure_hook(hook: extern "C" fn()) {
    let _ = CURSOR_FAILURE_HOOK.set(hook);
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
    if let Some(hook) = CURSOR_FAILURE_HOOK.get() {
        hook();
    }
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
