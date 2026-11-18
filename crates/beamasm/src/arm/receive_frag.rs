//! Process-wide receive fragments shared by every compiled module.

use arinsal_a64::{
    buf::{BufferError, CodeBuffer},
    enc::{Cond, Gpr},
    exec::{CodeMemory, ExecError},
};

use crate::{
    Update,
    arm::beam_asm::tmp_mem_ref,
    emit_enter_runtime, emit_leave_runtime,
    receive::{ReceiveHelperHook, WaitHook},
};

const SCHEDULER_REGS: Gpr = Gpr::x(19);
const C_P: Gpr = Gpr::x(21);
const FCALLS: Gpr = Gpr::w(22);
const XREG0: Gpr = Gpr::x(25);
const XREG1: Gpr = Gpr::x(26);
const XREG2: Gpr = Gpr::x(27);
const ARG1: Gpr = Gpr::x(0);
const ARG2: Gpr = Gpr::x(1);
const ARG3: Gpr = Gpr::x(2);
const ARG4: Gpr = Gpr::x(3);
const TMP1: Gpr = Gpr::x(8);
const TMP2: Gpr = Gpr::x(9);
const SUPER_TMP: Gpr = Gpr::x(17);
const PROCESS_I: u32 = 72;
const PROCESS_ARITY: u16 = 80;
/// `message_ptr` (TMP_MEM2q): where the receive helper leaves the message it made available.
const MESSAGE_PTR: u32 = tmp_mem_ref(1);
/// `get_out` (TMP_MEM3q): nonzero when the process must schedule out.
const GET_OUT: u32 = tmp_mem_ref(2);

/// The process fields `i_loop_rec_shared` reads whose offsets the VM provides
/// (`sig_qs.save`, `ErtsMessage.m[0]`): the architecture-neutral
/// [`crate::common::process_offsets::ProcessOffsets`].
pub use crate::common::process_offsets::ProcessOffsets as MsgOffsets;

/// `offsetof(Process, flags)`: part of the fixed native prefix.
const PROCESS_FLAGS: u32 = core::mem::offset_of!(crate::ProcessHeader, flags) as u32;

/// Receive fragments: `i_loop_rec_shared`, `wait_unlocked_shared` and `wait_locked_shared`.
pub struct ReceiveFragments {
    memory: CodeMemory,
    loop_rec_offset: usize,
    wait_unlocked_offset: usize,
    wait_locked_offset: usize,
}

/// `c_p->flags &= ~F_DELAY_GC` (instr_msg.cpp: ldr w / and / str w).
fn clear_delay_gc(code: &mut CodeBuffer, flags: u32) -> Result<(), BufferError> {
    code.emit(|e| {
        e.ldr_uoff(Gpr::w(8), C_P, flags)?;
        e.and_imm(
            Gpr::w(8),
            Gpr::w(8),
            u64::from(!arinsal_term::pflags::F_DELAY_GC),
        )?;
        e.str_uoff(Gpr::w(8), C_P, flags)
    })
}

impl ReceiveFragments {
    /// Emits the shared receive fragments once for the VM. `receive_helper` is
    /// `erts_proc_sig_receive_helper`; `context_switch` is the entry of the shared
    /// `context_switch_simplified` fragment the schedule-out paths branch to.
    // Port of erts/emulator/beam/jit/arm/instr_msg.cpp (emit_i_loop_rec_shared,
    // emit_wait_unlocked, emit_wait_locked), OTP-29.1.1.
    pub fn new(
        receive_helper: ReceiveHelperHook,
        wait_unlocked: WaitHook,
        wait_locked: WaitHook,
        context_switch: usize,
        offsets: MsgOffsets,
    ) -> Result<Self, ExecError> {
        let mut code = CodeBuffer::new();
        let fail = |_: BufferError| ExecError::InvalidSize("receive fragment");
        let loop_rec_label = code.new_label();
        let wait_unlocked_label = code.new_label();
        let wait_locked_label = code.new_label();
        let schedule_out = code.new_label();
        let done = code.new_label();

        // Port of erts/emulator/beam/jit/arm/instr_msg.cpp (emit_i_loop_rec_shared),
        // OTP-29.1.1. The wait address erts keeps in TMP_MEM1q stays in XREG2, which no
        // runtime call clobbers; the loop_rec has no live X registers.
        code.bind(loop_rec_label).map_err(fail)?;
        code.emit(|e| {
            e.mov_reg(XREG1, Gpr::x(30))?;
            e.ldr_uoff(Gpr::w(8), C_P, PROCESS_FLAGS)?;
            e.orr_imm(
                Gpr::w(8),
                Gpr::w(8),
                u64::from(arinsal_term::pflags::F_DELAY_GC),
            )?;
            e.str_uoff(Gpr::w(8), C_P, PROCESS_FLAGS)?;
            e.str_uoff(ARG1, C_P, PROCESS_I)?;
            e.mov_reg(XREG2, ARG2)?;
            e.cmp_imm(FCALLS, 0, false)
        })
        .map_err(fail)?;
        code.b_cond(Cond::Le, schedule_out).map_err(fail)?;

        // "Peek next message".
        code.emit(|e| {
            e.ldr_uoff(TMP1, C_P, offsets.sig_qs_save)?;
            e.ldr_uoff(ARG1, TMP1, 0)
        })
        .map_err(fail)?;
        code.cbnz(ARG1, done).map_err(fail)?;
        // Inner queue empty, fetch more from the outer and middle queues.
        emit_enter_runtime(&mut code, 0, Update::REDUCTIONS.union(Update::HEAP_ALLOC))
            .map_err(fail)?;
        code.emit(|e| {
            e.str_uoff(Gpr::xzr(), SCHEDULER_REGS, MESSAGE_PTR)?;
            e.mov_reg(ARG1, C_P)?;
            e.mov_reg(Gpr::w(1), FCALLS)?;
            e.mov_const(ARG3, 0)?;
            // `lea(ARG4, TMP_MEM2q); lea(ARG5, TMP_MEM3q)`
            e.add_imm(ARG4, SCHEDULER_REGS, MESSAGE_PTR as u16, false)?;
            e.add_imm(Gpr::x(4), SCHEDULER_REGS, GET_OUT as u16, false)?;
            e.mov_const(SUPER_TMP, receive_helper as *const () as u64)?;
            e.blr(SUPER_TMP)
        })
        .map_err(fail)?;
        // The helper only inspects FCALLS; the consumed reductions come back in ARG1.
        emit_leave_runtime(&mut code, 0, Update::HEAP_ALLOC).map_err(fail)?;
        code.emit(|e| {
            e.sub_reg(FCALLS, FCALLS, Gpr::w(0), arinsal_a64::enc::Shift::Lsl, 0)?;
            e.ldr_uoff(ARG1, SCHEDULER_REGS, MESSAGE_PTR)
        })
        .map_err(fail)?;
        code.cbnz(ARG1, done).map_err(fail)?;
        // Did we receive a signal or run out of reductions?
        code.emit(|e| e.ldr_uoff(Gpr::w(8), SCHEDULER_REGS, GET_OUT))
            .map_err(fail)?;
        code.cbnz(Gpr::w(8), schedule_out).map_err(fail)?;
        // The queue is empty and the process neither yields nor exits: on to the wait.
        clear_delay_gc(&mut code, PROCESS_FLAGS).map_err(fail)?;
        code.emit(|e| e.br(XREG2)).map_err(fail)?;

        // Out of reductions or a signal to act on: schedule out at the `loop_rec`, whose
        // address (`c_p->i`) was set on entry.
        code.bind(schedule_out).map_err(fail)?;
        clear_delay_gc(&mut code, PROCESS_FLAGS).map_err(fail)?;
        code.emit(|e| {
            e.mov_const(TMP2, 0)?;
            e.strb_uoff(TMP2, C_P, PROCESS_ARITY)?;
            e.mov_const(SUPER_TMP, context_switch as u64)?;
            e.br(SUPER_TMP)
        })
        .map_err(fail)?;

        // ARG1 holds the message node.
        code.bind(done).map_err(fail)?;
        code.emit(|e| {
            e.ldr_uoff(XREG0, ARG1, offsets.message_term)?;
            e.ret(XREG1)
        })
        .map_err(fail)?;

        for (label, hook) in [
            (wait_unlocked_label, wait_unlocked),
            (wait_locked_label, wait_locked),
        ] {
            code.bind(label).map_err(fail)?;
            emit_enter_runtime(&mut code, 0, Update::NONE).map_err(fail)?;
            code.emit(|e| {
                e.mov_reg(XREG2, ARG1)?;
                e.mov_reg(ARG2, ARG1)?;
                e.mov_reg(ARG1, C_P)?;
                e.mov_const(SUPER_TMP, hook as *const () as u64)?;
                e.blr(SUPER_TMP)
            })
            .map_err(fail)?;
            emit_leave_runtime(&mut code, 0, Update::NONE).map_err(fail)?;
            code.emit(|e| {
                e.and_imm(TMP1, XREG2, !1)?;
                e.str_uoff(TMP1, C_P, PROCESS_I)?;
                e.mov_const(TMP2, 0)?;
                e.strb_uoff(TMP2, C_P, PROCESS_ARITY)?;
                e.mov_const(SUPER_TMP, context_switch as u64)?;
                e.br(SUPER_TMP)
            })
            .map_err(fail)?;
        }

        let (words, labels) = code.finish_with_labels().map_err(fail)?;
        let bytes = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let mut memory = CodeMemory::new(bytes.len().max(4))?;
        let offset = memory.alloc(bytes.len().max(4))?;
        memory.write_bytes(offset, &bytes)?;
        Ok(Self {
            memory,
            loop_rec_offset: labels[&loop_rec_label],
            wait_unlocked_offset: labels[&wait_unlocked_label],
            wait_locked_offset: labels[&wait_locked_label],
        })
    }

    /// Entry of `i_loop_rec_shared`: x0 holds the restart address (the call site), x1 the wait
    /// label; the caller's `x30` is the return address. A message is returned in X0.
    pub fn loop_rec_shared(&self) -> usize {
        self.memory.ptr_at(self.loop_rec_offset) as usize
    }

    /// Entry of the unlocked wait: x0 holds the resume address, bit 0 set when the wait is its
    /// own resume target.
    pub fn wait_unlocked_shared(&self) -> usize {
        self.memory.ptr_at(self.wait_unlocked_offset) as usize
    }

    /// Entry of the locked wait: x0 holds the resume address, bit 0 set when the wait is its
    /// own resume target.
    pub fn wait_locked_shared(&self) -> usize {
        self.memory.ptr_at(self.wait_locked_offset) as usize
    }
}
