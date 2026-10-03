//! BIF, export, and apply call emission for BeamAsm modules.

use arinsal_a64::enc::Gpr;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::module::{ArgVal, BeamModuleAssembler, ModuleError};
use crate::{Update, emit_enter_runtime, emit_leave_runtime};

/// BIF target supplied by the runtime.
pub type BifTarget = extern "C" fn(*mut crate::ProcessHeader, u64, u64, u64, u32) -> u64;

/// Runtime hook calling the BIF named by an export identity. Arguments: process, identity, then
/// up to three argument terms. Zero means an exception is pending in `freason`.
pub type BifIdentityHelper = extern "C" fn(*mut crate::ProcessHeader, u64, u64, u64, u64) -> u64;

/// Apply resolver supplied by the runtime; zero means the target could not be resolved.
pub type ApplyResolver = extern "C" fn(*mut crate::ProcessHeader, u64, u32, u32) -> usize;

/// Number of code indexes (`ERTS_NUM_CODE_IX`): active, staging and the one being retired.
// Port of erts/emulator/beam/code_ix.h:72-78, OTP-29.1.1.
pub const ERTS_NUM_CODE_IX: usize = 3;
/// Length of an export's address vector: one slot per code index plus the save_calls slot.
pub const ERTS_ADDRESSV_SIZE: usize = ERTS_NUM_CODE_IX + 1;
/// Code index of a process with `process_flag(save_calls, N > 0)`: every remote call lands in
/// the save_calls dispatch fragment.
pub const ERTS_SAVE_CALLS_CODE_IX: usize = ERTS_ADDRESSV_SIZE - 1;

/// Mutable indirection used by external calls: one address per code index (`ErtsDispatchable`).
/// Native code calls `addresses[active_code_ix]`.
// Port of erts/emulator/beam/jit/arm/beam_asm.hpp:394-401 and erts/emulator/beam/code_ix.h:91-95
// (ErtsDispatchable), OTP-29.1.1.
#[repr(C)]
pub struct ExportEntry {
    /// Native entry addresses indexed by code index; the last slot is the save_calls entry.
    pub addresses: [AtomicUsize; ERTS_ADDRESSV_SIZE],
}

// erts calls `i_bif*` with only `Update::eReductions` (instr_bif.cpp:47-64) because its guard
// BIFs never allocate on the process heap. This port's BIFs may build terms on the heap, so the
// call also publishes and reloads HTOP and E.
const PLAIN_BIF_UPDATE: Update = Update::HEAP_ALLOC.union(Update::REDUCTIONS);

impl ExportEntry {
    /// Creates an export entry whose every code index, the save_calls one included, enters
    /// `address`.
    pub const fn new(address: usize) -> Self {
        Self::with_save_calls(address, address)
    }

    /// Creates an export entry entering `address` in every code index and `save_calls` in
    /// `ERTS_SAVE_CALLS_CODE_IX`.
    // Port of erts/emulator/beam/export.c:73-98 (export_init), OTP-29.1.1.
    pub const fn with_save_calls(address: usize, save_calls: usize) -> Self {
        Self {
            addresses: [
                AtomicUsize::new(address),
                AtomicUsize::new(address),
                AtomicUsize::new(address),
                AtomicUsize::new(save_calls),
            ],
        }
    }

    /// The address entered in code index `ix`.
    pub fn address(&self, ix: usize) -> usize {
        self.addresses[ix].load(Ordering::Acquire)
    }

    /// Sets the address entered in code index `ix`.
    pub fn set_address(&self, ix: usize, address: usize) {
        self.addresses[ix].store(address, Ordering::Release);
    }

    /// Copies the address of code index `src` into `dst` when a staging area opens.
    // Port of erts/emulator/beam/export.c:100-106 (export_stage), OTP-29.1.1.
    pub fn stage(&self, src: usize, dst: usize) {
        self.set_address(dst, self.address(src));
    }
}

const XREGS: [Gpr; 6] = [
    Gpr::x(25),
    Gpr::x(26),
    Gpr::x(27),
    Gpr::x(28),
    Gpr::x(10 + 5),
    Gpr::x(10 + 6),
];
const E: Gpr = Gpr::x(20);
/// The process's code index (`active_code_ix`), loaded on every entry into native code.
const ACTIVE_CODE_IX: Gpr = Gpr::x(24);

impl BeamModuleAssembler {
    /// Calls a lightweight BIF with the supplied X-register arguments.
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:595-610, OTP-29.1.1
    pub fn emit_call_light_bif(
        &mut self,
        bif: BifTarget,
        args: &[ArgVal],
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        self.emit_bif_call(
            bif,
            args,
            dst,
            args.len() as u32,
            None,
            3,
            Update::HEAP_ALLOC
                .union(Update::REDUCTIONS)
                .union(Update::X_REGS),
        )
    }

    /// Calls a BIF resolved from an MFA by the runtime.
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:819-839, OTP-29.1.1
    pub fn emit_call_bif_mfa(
        &mut self,
        bif: BifTarget,
        args: &[ArgVal],
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        self.emit_bif_call(
            bif,
            args,
            dst,
            args.len() as u32,
            None,
            6,
            Update::HEAP_ALLOC
                .union(Update::REDUCTIONS)
                .union(Update::X_REGS),
        )
    }

    /// Emits `i_bif1` and branches to a supplied BEAM label on a false result.
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:110-120, OTP-29.1.1
    pub fn emit_i_bif1(
        &mut self,
        src1: ArgVal,
        fail: Option<u32>,
        bif: BifTarget,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        self.emit_bif_call(bif, &[src1], dst, 1, fail, 6, PLAIN_BIF_UPDATE)
    }

    /// Emits `i_bif2` and branches to a supplied BEAM label on a false result.
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:122-133, OTP-29.1.1
    pub fn emit_i_bif2(
        &mut self,
        src1: ArgVal,
        src2: ArgVal,
        fail: Option<u32>,
        bif: BifTarget,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        self.emit_bif_call(bif, &[src1, src2], dst, 2, fail, 6, PLAIN_BIF_UPDATE)
    }

    /// Emits `i_bif3` and branches to a supplied BEAM label on a false result.
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:135-151, OTP-29.1.1
    pub fn emit_i_bif3(
        &mut self,
        src1: ArgVal,
        src2: ArgVal,
        src3: ArgVal,
        fail: Option<u32>,
        bif: BifTarget,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        self.emit_bif_call(bif, &[src1, src2, src3], dst, 3, fail, 6, PLAIN_BIF_UPDATE)
    }

    /// Emits `i_gc_bif1`, passing the live X-register count to the runtime.
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:154-175, OTP-29.1.1
    pub fn emit_i_gc_bif1(
        &mut self,
        src1: ArgVal,
        fail: Option<u32>,
        bif: BifTarget,
        live: u32,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        self.emit_bif_call(
            bif,
            &[src1],
            dst,
            live,
            fail,
            live as usize,
            Update::HEAP_ALLOC
                .union(Update::REDUCTIONS)
                .union(Update::X_REGS),
        )
    }

    /// Emits `i_gc_bif2`, passing the live X-register count to the runtime.
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:177-200, OTP-29.1.1
    pub fn emit_i_gc_bif2(
        &mut self,
        src1: ArgVal,
        src2: ArgVal,
        fail: Option<u32>,
        bif: BifTarget,
        live: u32,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        self.emit_bif_call(
            bif,
            &[src1, src2],
            dst,
            live,
            fail,
            live as usize,
            Update::HEAP_ALLOC
                .union(Update::REDUCTIONS)
                .union(Update::X_REGS),
        )
    }

    /// Emits `i_gc_bif3`, passing the live X-register count to the runtime.
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:202-228, OTP-29.1.1
    #[allow(clippy::too_many_arguments)]
    pub fn emit_i_gc_bif3(
        &mut self,
        src1: ArgVal,
        src2: ArgVal,
        src3: ArgVal,
        fail: Option<u32>,
        bif: BifTarget,
        live: u32,
        dst: ArgVal,
    ) -> Result<(), ModuleError> {
        self.emit_bif_call(
            bif,
            &[src1, src2, src3],
            dst,
            live,
            fail,
            live as usize,
            Update::HEAP_ALLOC
                .union(Update::REDUCTIONS)
                .union(Update::X_REGS),
        )
    }

    /// Emits an external call through the current address in an export entry.
    // Port of erts/emulator/beam/jit/arm/instr_call.cpp:150-155, OTP-29.1.1
    pub fn emit_i_call_ext(&mut self, export: &'static ExportEntry) -> Result<(), ModuleError> {
        self.emit_export_call(export, false)
    }

    /// Emits an external tail call through the current export-entry address.
    // Port of erts/emulator/beam/jit/arm/instr_call.cpp:157-164, OTP-29.1.1
    pub fn emit_i_call_ext_only(
        &mut self,
        export: &'static ExportEntry,
    ) -> Result<(), ModuleError> {
        self.emit_export_call(export, true)
    }

    /// Deallocates a Y frame and tail-calls an external export.
    // Port of erts/emulator/beam/jit/arm/instr_call.cpp:166-170, OTP-29.1.1
    pub fn emit_i_call_ext_last(
        &mut self,
        export: &'static ExportEntry,
        deallocate: u32,
    ) -> Result<(), ModuleError> {
        self.deallocate(deallocate)?;
        self.emit_i_call_ext_only(export)
    }

    /// Calls the target resolved from X0 and arity X1, retaining a caller continuation.
    // Port of erts/emulator/beam/jit/arm/instr_call.cpp:246-249, OTP-29.1.1
    pub fn emit_i_apply(&mut self, resolver: ApplyResolver, live: u32) -> Result<(), ModuleError> {
        self.emit_apply(resolver, live, false, false)
    }

    /// Deallocates a Y frame and tail-calls the target resolved from X0 and arity X1.
    // Port of erts/emulator/beam/jit/arm/instr_call.cpp:251-254, OTP-29.1.1
    pub fn emit_i_apply_last(
        &mut self,
        resolver: ApplyResolver,
        live: u32,
        deallocate: u32,
    ) -> Result<(), ModuleError> {
        self.deallocate(deallocate)?;
        self.emit_apply(resolver, live, true, true)
    }

    /// Tail-calls the target resolved from X0 and arity X1.
    // Port of erts/emulator/beam/jit/arm/instr_call.cpp:256-260, OTP-29.1.1
    pub fn emit_i_apply_only(
        &mut self,
        resolver: ApplyResolver,
        live: u32,
    ) -> Result<(), ModuleError> {
        self.emit_apply(resolver, live, true, true)
    }

    /// Calls a fun target resolved from X0 and arity X1.
    // Port of erts/emulator/beam/jit/arm/instr_fun.cpp:330-333, OTP-29.1.1
    pub fn emit_i_apply_fun(
        &mut self,
        resolver: ApplyResolver,
        live: u32,
    ) -> Result<(), ModuleError> {
        self.emit_apply(resolver, live, false, false)
    }

    /// Deallocates a Y frame and tail-calls a fun target resolved from X0 and X1.
    // Port of erts/emulator/beam/jit/arm/instr_fun.cpp:335-338, OTP-29.1.1
    pub fn emit_i_apply_fun_last(
        &mut self,
        resolver: ApplyResolver,
        live: u32,
        deallocate: u32,
    ) -> Result<(), ModuleError> {
        self.deallocate(deallocate)?;
        self.emit_apply(resolver, live, true, true)
    }

    /// Tail-calls a fun target resolved from X0 and X1.
    // Port of erts/emulator/beam/jit/arm/instr_fun.cpp:340-342, OTP-29.1.1
    pub fn emit_i_apply_fun_only(
        &mut self,
        resolver: ApplyResolver,
        live: u32,
    ) -> Result<(), ModuleError> {
        self.emit_apply(resolver, live, true, true)
    }

    /// Calls a BIF through its export identity (`i_bif1/2/3`, `nofail_bif1/2`).
    ///
    /// With a nonzero `fail` label an exception raised by the BIF is discarded and control
    /// branches to the label instead, like `bif1 Fail Bif ...` in a guard.
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:110-200, OTP-29.1.1
    pub fn emit_bif_by_identity(
        &mut self,
        identity: usize,
        args: &[ArgVal],
        fail: u32,
        dst: ArgVal,
        helper: BifIdentityHelper,
    ) -> Result<(), ModuleError> {
        if args.len() > 3 {
            return Err(ModuleError::InvalidOperand("BIF arity exceeds three"));
        }
        let mut regs = [Gpr::xzr(); 3];
        for (i, arg) in args.iter().copied().enumerate() {
            let source = self.source_reg(arg)?;
            regs[i] = Gpr::x(10 + i as u8);
            self.code.emit(|e| e.mov_reg(regs[i], source))?;
        }
        let update = Update::HEAP_ALLOC
            .union(Update::REDUCTIONS)
            .union(Update::X_REGS);
        emit_enter_runtime(&mut self.code, 6, update)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(0), Gpr::x(21))?;
            e.mov_const(Gpr::x(1), identity as u64)?;
            for (index, reg) in regs.iter().copied().enumerate() {
                if index < args.len() {
                    e.mov_reg(Gpr::x(index as u8 + 2), reg)?;
                }
            }
            e.mov_const(Gpr::x(17), helper as usize as u64)?;
            e.str_uoff(Gpr::x(30), Gpr::x(21), 72)?;
            e.blr(Gpr::x(17))
        })?;
        emit_leave_runtime(&mut self.code, 6, update)?;
        self.code.emit(|e| {
            e.ldr_uoff(Gpr::x(30), Gpr::x(21), 72)?;
            e.ldr_uoff(Gpr::x(9), Gpr::x(21), 40)
        })?;
        let ok = self.code.new_label();
        self.code.cbz(Gpr::x(9), ok)?;
        if fail != 0 {
            let label = self.label(fail);
            self.code.emit(|e| e.str_uoff(Gpr::xzr(), Gpr::x(21), 40))?;
            self.code.b(label)?;
        } else {
            self.branch_error()?;
        }
        self.code.bind(ok)?;
        self.store_bif_result(dst, Gpr::x(0))
    }

    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:110-151, OTP-29.1.1
    #[allow(clippy::too_many_arguments)]
    fn emit_bif_call(
        &mut self,
        bif: BifTarget,
        args: &[ArgVal],
        dst: ArgVal,
        live: u32,
        fail: Option<u32>,
        state_live: usize,
        update: Update,
    ) -> Result<(), ModuleError> {
        if args.len() > 3 || live > 6 {
            return Err(ModuleError::InvalidOperand(
                "invalid BIF arity or live count",
            ));
        }
        let mut regs = [Gpr::xzr(); 3];
        for (i, arg) in args.iter().copied().enumerate() {
            let source = self.source_reg(arg)?;
            regs[i] = Gpr::x(10 + i as u8);
            self.code.emit(|e| e.mov_reg(regs[i], source))?;
        }
        self.code
            .emit(|e| e.mov_const(Gpr::x(13), u64::from(live)))?;
        self.emit_bif_runtime_call(
            bif as usize,
            &[regs[0], regs[1], regs[2], Gpr::x(13)],
            state_live,
            update,
        )?;
        if let Some(label) = fail {
            self.code.emit(|e| e.mov_reg(Gpr::x(14), Gpr::x(0)))?;
            let target = self.label(label);
            self.code.cbz(Gpr::x(14), target)?;
        }
        self.store_bif_result(dst, Gpr::x(0))?;
        Ok(())
    }

    fn store_bif_result(&mut self, dst: ArgVal, src: Gpr) -> Result<(), ModuleError> {
        match dst {
            ArgVal::X(i) if i < 6 => self.code.emit(|e| e.mov_reg(XREGS[i as usize], src))?,
            ArgVal::Y(i) => self.code.emit(|e| {
                e.str_uoff(
                    src,
                    E,
                    i.checked_mul(8)
                        .ok_or(arinsal_a64::enc::EncodeError::InvalidRegister(E))?,
                )
            })?,
            _ => {
                return Err(ModuleError::InvalidOperand(
                    "BIF destination must be X or Y",
                ));
            }
        }
        Ok(())
    }

    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:47-65, OTP-29.1.1
    fn emit_bif_runtime_call(
        &mut self,
        target: usize,
        args: &[Gpr],
        live: usize,
        update: Update,
    ) -> Result<(), ModuleError> {
        emit_enter_runtime(&mut self.code, live, update)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(0), Gpr::x(21))?;
            for (index, arg) in args.iter().copied().enumerate() {
                e.mov_reg(Gpr::x(index as u8 + 1), arg)?;
            }
            e.mov_const(Gpr::x(17), target as u64)?;
            e.str_uoff(Gpr::x(30), Gpr::x(21), 72)?;
            e.blr(Gpr::x(17))
        })?;
        emit_leave_runtime(&mut self.code, live, update)?;
        self.code.emit(|e| {
            e.ldr_uoff(Gpr::x(30), Gpr::x(21), 72)?;
            e.ldr_uoff(Gpr::x(9), Gpr::x(21), 40)
        })?;
        self.error_if_nonzero(Gpr::x(9))?;
        Ok(())
    }

    // Port of erts/emulator/beam/jit/arm/instr_call.cpp:150-170, OTP-29.1.1
    fn emit_export_call(
        &mut self,
        export: &'static ExportEntry,
        tail: bool,
    ) -> Result<(), ModuleError> {
        let target = Gpr::x(14);
        self.code.emit(|e| {
            e.mov_const(Gpr::x(13), export as *const ExportEntry as u64)?;
            e.ldr_regoff(target, Gpr::x(13), ACTIVE_CODE_IX, 3)?;
            e.mov_reg(Gpr::x(0), Gpr::x(21))?;
            e.mov_reg(Gpr::x(1), Gpr::x(13))?;
            if tail {
                e.ldr_post(Gpr::x(30), E, 8)?;
                e.br(target)
            } else {
                e.blr(target)
            }
        })?;
        Ok(())
    }

    // Port of erts/emulator/beam/jit/arm/instr_call.cpp:220-260, OTP-29.1.1
    fn emit_apply(
        &mut self,
        resolver: ApplyResolver,
        live: u32,
        _include_i: bool,
        tail: bool,
    ) -> Result<(), ModuleError> {
        if live > 6 {
            return Err(ModuleError::InvalidOperand(
                "apply live count exceeds X registers",
            ));
        }
        let continuation = self.code.new_label();
        if tail {
            self.record_call_site()?;
        } else {
            self.record_return_site(continuation)?;
        }
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(10), XREGS[0])?;
            e.mov_reg(Gpr::x(11), XREGS[1])?;
            e.mov_const(Gpr::x(12), u64::from(live))
        })?;
        let update = Update::HEAP_ALLOC
            .union(Update::REDUCTIONS)
            .union(Update::X_REGS);
        self.emit_bif_runtime_call(
            resolver as usize,
            &[Gpr::x(10), Gpr::x(11), Gpr::x(12)],
            live as usize,
            update,
        )?;
        let resolved = self.code.new_label();
        self.code.cbnz(Gpr::x(0), resolved)?;
        self.branch_error()?;
        self.code.bind(resolved)?;
        self.code.emit(|e| {
            e.mov_reg(Gpr::x(14), Gpr::x(0))?;
            if tail {
                e.ldr_post(Gpr::x(30), E, 8)?;
                e.br(Gpr::x(14))
            } else {
                e.blr(Gpr::x(14))
            }
        })?;
        if !tail {
            self.code.bind(continuation)?;
        }
        Ok(())
    }
}
