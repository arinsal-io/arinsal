//! Selective receive, mailbox markers, and receive timeout emitters.

use arinsal_a64::enc::{Cond, Gpr};

use crate::{
    ProcessHeader,
    module::{ArgVal, BeamModuleAssembler, ModuleError},
};

const XREG0: Gpr = Gpr::x(25);
const FCALLS: Gpr = Gpr::w(22);

/// Runtime callback which reserves a receive marker and returns its term.
pub type RecvMarkerReserveHook = extern "C" fn(*mut ProcessHeader) -> u64;
/// Runtime callback which binds a marker to a reference.
pub type RecvMarkerBindHook = extern "C" fn(*mut ProcessHeader, u64, u64);
/// Runtime callback which clears a marker reference.
pub type RecvMarkerClearHook = extern "C" fn(*mut ProcessHeader, u64);
/// Runtime callback which restores a saved mailbox position for a reference.
pub type RecvMarkerUseHook = extern "C" fn(*mut ProcessHeader, u64);
/// Runtime callback which peeks the next message, returning zero for an empty queue.
pub type LoopRecHook = extern "C" fn(*mut ProcessHeader) -> u64;
/// Runtime callback which removes the current message and returns reductions left.
pub type RemoveMessageHook = extern "C" fn(*mut ProcessHeader, i32, usize) -> i32;
/// Runtime callback which advances the saved mailbox pointer.
pub type SetSaveNextHook = extern "C" fn(*mut ProcessHeader);
/// Runtime callback which starts a wait at a native destination.
pub type WaitHook = extern "C" fn(*mut ProcessHeader, usize);
/// Runtime callback which takes the receive lock.
pub type TakeReceiveLockHook = extern "C" fn(*mut ProcessHeader);
/// Runtime callback which waits for a message or timeout.
pub type WaitTimeoutHook = extern "C" fn(*mut ProcessHeader, u64, usize) -> i32;
/// Runtime callback which clears a locked receive timeout.
pub type TimeoutHook = extern "C" fn(*mut ProcessHeader);

/// Typed runtime ABI used by native receive instructions.
#[derive(Clone, Copy)]
pub struct ReceiveHooks {
    /// Reserves a receive marker.
    pub recv_marker_reserve: RecvMarkerReserveHook,
    /// Binds a marker to a reference.
    pub recv_marker_bind: RecvMarkerBindHook,
    /// Clears a marker reference.
    pub recv_marker_clear: RecvMarkerClearHook,
    /// Restores the saved position for a reference.
    pub recv_marker_use: RecvMarkerUseHook,
    /// Peeks a message at the saved mailbox position.
    pub loop_rec: LoopRecHook,
    /// Removes the current message.
    pub remove_message: RemoveMessageHook,
    /// Advances the saved mailbox position.
    pub set_save_next: SetSaveNextHook,
    /// Waits with the message queue lock in the supplied state.
    pub wait_unlocked: WaitHook,
    /// Waits while retaining the message queue lock.
    pub wait_locked: WaitHook,
    /// Takes the receive lock before a timeout wait.
    pub take_receive_lock: TakeReceiveLockHook,
    /// Waits for a message or timeout.
    pub wait_timeout: WaitTimeoutHook,
    /// Handles a locked timeout.
    pub timeout_locked: TimeoutHook,
    /// Handles timeout after the queue lock is released.
    pub timeout: TimeoutHook,
}

impl BeamModuleAssembler {
    /// Reserves a receive marker and writes its reference term to the destination.
    // Port of erts/emulator/beam/jit/arm/instr_msg.cpp:25-34, OTP-29.1.1
    pub fn emit_recv_marker_reserve(
        &mut self,
        dst: ArgVal,
        hooks: ReceiveHooks,
    ) -> Result<(), ModuleError> {
        self.emit_runtime_hook_with(
            hooks.recv_marker_reserve as usize,
            &[],
            6,
            crate::Update::HEAP_ALLOC,
        )?;
        match dst {
            ArgVal::X(index) if index < 6 => {
                self.code.emit(|e| {
                    e.mov_reg(Gpr::x([25, 26, 27, 28, 15, 16][index as usize]), Gpr::x(0))
                })?;
                Ok(())
            }
            ArgVal::Y(index) => {
                let offset = index
                    .checked_mul(8)
                    .ok_or(ModuleError::InvalidOperand("Y register offset overflow"))?;
                self.code
                    .emit(|e| e.str_uoff(Gpr::x(0), Gpr::x(20), offset))?;
                Ok(())
            }
            _ => Err(ModuleError::InvalidOperand(
                "receive marker destination must be X or Y",
            )),
        }
    }

    /// Binds a receive marker to a reference.
    // Port of erts/emulator/beam/jit/arm/instr_msg.cpp:36-49, OTP-29.1.1
    pub fn emit_recv_marker_bind(
        &mut self,
        marker: ArgVal,
        reference: ArgVal,
        hooks: ReceiveHooks,
    ) -> Result<(), ModuleError> {
        let marker = self.source_reg(marker)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(12), marker))?;
        let reference = self.source_reg_into(reference, Gpr::x(17))?;
        self.code.emit(|e| e.mov_reg(Gpr::x(10), reference))?;
        self.emit_runtime_hook_with(
            hooks.recv_marker_bind as usize,
            &[Gpr::x(12), Gpr::x(10)],
            6,
            crate::Update::NONE,
        )
    }

    /// Clears the receive marker associated with a reference.
    // Port of erts/emulator/beam/jit/arm/instr_msg.cpp:51-60, OTP-29.1.1
    pub fn emit_recv_marker_clear(
        &mut self,
        reference: ArgVal,
        hooks: ReceiveHooks,
    ) -> Result<(), ModuleError> {
        let reference = self.source_reg(reference)?;
        self.emit_runtime_hook_with(
            hooks.recv_marker_clear as usize,
            &[reference],
            6,
            crate::Update::NONE,
        )
    }

    /// Restores the saved receive position associated with a reference.
    // Port of erts/emulator/beam/jit/arm/instr_msg.cpp:62-71, OTP-29.1.1
    pub fn emit_recv_marker_use(
        &mut self,
        reference: ArgVal,
        hooks: ReceiveHooks,
    ) -> Result<(), ModuleError> {
        let reference = self.source_reg(reference)?;
        self.emit_runtime_hook_with(
            hooks.recv_marker_use as usize,
            &[reference],
            6,
            crate::Update::NONE,
        )
    }

    /// Peeks the next message and branches to the wait label when the queue is empty.
    // Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp:109-238 and instr_msg.cpp:127-133, OTP-29.1.1
    pub fn emit_i_loop_rec(&mut self, wait: u32, hooks: ReceiveHooks) -> Result<(), ModuleError> {
        self.emit_runtime_hook_with(hooks.loop_rec as usize, &[], 6, crate::Update::NONE)?;
        let wait = self.label(wait);
        self.code.cbz(Gpr::x(0), wait)?;
        self.code.emit(|e| e.mov_reg(XREG0, Gpr::x(0)))?;
        Ok(())
    }

    /// Removes the current message and updates the reduction count.
    // Port of erts/emulator/beam/jit/arm/instr_msg.cpp:135-149, OTP-29.1.1
    pub fn emit_remove_message(&mut self, hooks: ReceiveHooks) -> Result<(), ModuleError> {
        self.emit_runtime_hook_with(
            hooks.remove_message as usize,
            &[Gpr::x(22), Gpr::x(24)],
            6,
            crate::Update::NONE,
        )?;
        self.code.emit(|e| e.mov_reg(FCALLS, Gpr::w(0)))?;
        Ok(())
    }

    /// Advances the saved position and branches to the next receive loop pass.
    // Port of erts/emulator/beam/jit/arm/instr_msg.cpp:151-164, OTP-29.1.1
    pub fn emit_loop_rec_end(&mut self, dest: u32, hooks: ReceiveHooks) -> Result<(), ModuleError> {
        self.emit_runtime_hook_with(hooks.set_save_next as usize, &[], 0, crate::Update::NONE)?;
        self.code.emit(|e| e.subs_imm(FCALLS, FCALLS, 1, false))?;
        let dest = self.label(dest);
        self.code.b_cond(Cond::Pl, dest)?;
        // Out of reductions: yield and resume at the next receive iteration.
        self.code.adr(Gpr::x(8), dest)?;
        self.code.emit(|e| e.str_uoff(Gpr::x(8), Gpr::x(21), 72))?;
        self.emit_yield_live(0)?;
        self.code.b(self.yield_label)?;
        Ok(())
    }

    /// Waits with the queue unlocked, then returns to the scheduler.
    // Port of erts/emulator/beam/jit/arm/instr_msg.cpp:166-180, OTP-29.1.1
    pub fn emit_wait_unlocked(
        &mut self,
        dest: u32,
        hooks: ReceiveHooks,
    ) -> Result<(), ModuleError> {
        self.emit_wait(hooks.wait_unlocked, dest)
    }

    /// Waits with the queue lock held, then returns to the scheduler.
    // Port of erts/emulator/beam/jit/arm/instr_msg.cpp:182-198, OTP-29.1.1
    pub fn emit_wait_locked(&mut self, dest: u32, hooks: ReceiveHooks) -> Result<(), ModuleError> {
        self.emit_wait(hooks.wait_locked, dest)
    }

    // Port of erts/emulator/beam/jit/arm/instr_msg.cpp:271-295, OTP-29.1.1.
    // The hook records the wait for the scheduler; the process then leaves native code as
    // a yield that resumes at `dest` (the `loop_rec` label of the receive).
    fn emit_wait(&mut self, hook: WaitHook, dest: u32) -> Result<(), ModuleError> {
        let dest = self.label(dest);
        self.code.adr(Gpr::x(9), dest)?;
        self.emit_runtime_hook_with(hook as usize, &[Gpr::x(9)], 0, crate::Update::NONE)?;
        self.code.adr(Gpr::x(8), dest)?;
        self.code.emit(|e| e.str_uoff(Gpr::x(8), Gpr::x(21), 72))?;
        self.emit_yield_live(0)?;
        self.code.b(self.yield_label)?;
        Ok(())
    }

    /// Takes the receive lock, then uses the locked timeout wait path.
    // Port of erts/emulator/beam/jit/arm/instr_msg.cpp:200-210, OTP-29.1.1
    pub fn emit_wait_timeout_unlocked(
        &mut self,
        timeout: ArgVal,
        dest: u32,
        hooks: ReceiveHooks,
    ) -> Result<(), ModuleError> {
        self.emit_runtime_hook_with(
            hooks.take_receive_lock as usize,
            &[],
            0,
            crate::Update::NONE,
        )?;
        self.emit_wait_timeout_locked(timeout, dest, hooks)
    }

    /// Waits for a message or timeout while holding the receive lock.
    // Port of erts/emulator/beam/jit/arm/instr_msg.cpp:212-243, OTP-29.1.1
    pub fn emit_wait_timeout_locked(
        &mut self,
        timeout: ArgVal,
        dest: u32,
        hooks: ReceiveHooks,
    ) -> Result<(), ModuleError> {
        let timeout = self.source_reg(timeout)?;
        self.code.emit(|e| e.mov_reg(Gpr::x(9), timeout))?;
        let next = self.code.new_label();
        self.code.adr(Gpr::x(10), next)?;
        self.emit_runtime_hook_with(
            hooks.wait_timeout as usize,
            &[Gpr::x(9), Gpr::x(10)],
            0,
            crate::Update::NONE,
        )?;
        let wait = self.code.new_label();
        self.code.emit(|e| e.cmp_imm(Gpr::x(0), 1, false))?;
        self.code.b_cond(Cond::Eq, wait)?;
        self.code.emit(|e| e.cmp_imm(Gpr::x(0), 0, false))?;
        self.code.b_cond(Cond::Eq, next)?;
        self.branch_error()?;
        self.code.bind(wait)?;
        self.emit_wait_locked(dest, hooks)?;
        self.code.bind(next)?;
        Ok(())
    }

    /// Clears a timeout while the receive lock is held.
    // Port of erts/emulator/beam/jit/arm/instr_msg.cpp:245-254, OTP-29.1.1
    pub fn emit_timeout_locked(&mut self, hooks: ReceiveHooks) -> Result<(), ModuleError> {
        self.emit_runtime_hook_with(hooks.timeout_locked as usize, &[], 0, crate::Update::NONE)
    }

    /// Clears a receive timeout.
    // Port of erts/emulator/beam/jit/arm/instr_msg.cpp:256-265, OTP-29.1.1
    pub fn emit_timeout(&mut self, hooks: ReceiveHooks) -> Result<(), ModuleError> {
        self.emit_runtime_hook_with(hooks.timeout as usize, &[], 0, crate::Update::NONE)
    }
}
