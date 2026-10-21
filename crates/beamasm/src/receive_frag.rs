//! Process-wide receive fragments shared by every compiled module.

use arinsal_a64::{
    buf::{BufferError, CodeBuffer},
    enc::{Cond, Gpr},
    exec::{CodeMemory, ExecError},
};

use crate::{
    Update, emit_enter_runtime, emit_leave_runtime,
    receive::{LOOP_REC_FETCH, LoopRecHook, WaitHook},
};

const C_P: Gpr = Gpr::x(21);
const FCALLS: Gpr = Gpr::w(22);
const XREG0: Gpr = Gpr::x(25);
const XREG1: Gpr = Gpr::x(26);
const XREG2: Gpr = Gpr::x(27);
const ARG1: Gpr = Gpr::x(0);
const ARG2: Gpr = Gpr::x(1);
const TMP1: Gpr = Gpr::x(8);
const TMP2: Gpr = Gpr::x(9);
const SUPER_TMP: Gpr = Gpr::x(17);
const PROCESS_I: u32 = 72;
const PROCESS_ARITY: u16 = 80;

/// Where `i_loop_rec_shared` finds the message at the save position without a call, as erts'
/// `emit_i_loop_rec_shared` loads `*c_p->sig_qs.save`: byte offsets from the process.
#[derive(Clone, Copy)]
pub struct InlinePeek {
    /// The address of the term of the message at the save position, 0 when there is none.
    pub save_term_offset: u32,
    /// The `F_DELAY_GC` byte set while a receive looks at a message.
    pub delay_gc_offset: u16,
}

/// Receive fragments: `i_loop_rec_shared`, `wait_unlocked_shared` and `wait_locked_shared`.
pub struct ReceiveFragments {
    memory: CodeMemory,
    loop_rec_offset: usize,
    wait_unlocked_offset: usize,
    wait_locked_offset: usize,
}

impl ReceiveFragments {
    /// Emits the shared receive fragments once for the VM. `context_switch` is the entry of
    /// the shared `context_switch_simplified` fragment the schedule-out paths branch to.
    // Port of erts/emulator/beam/jit/arm/instr_msg.cpp (emit_i_loop_rec_shared,
    // emit_wait_unlocked, emit_wait_locked), OTP-29.1.1.
    pub fn new(
        loop_rec: LoopRecHook,
        wait_unlocked: WaitHook,
        wait_locked: WaitHook,
        context_switch: usize,
        inline_peek: Option<InlinePeek>,
    ) -> Result<Self, ExecError> {
        let mut code = CodeBuffer::new();
        let fail = |_: BufferError| ExecError::InvalidSize("receive fragment");
        let loop_rec_label = code.new_label();
        let wait_unlocked_label = code.new_label();
        let wait_locked_label = code.new_label();
        let schedule_out = code.new_label();
        let done = code.new_label();
        let wait = code.new_label();

        code.bind(loop_rec_label).map_err(fail)?;
        code.emit(|e| {
            e.mov_reg(XREG1, Gpr::x(30))?;
            e.mov_reg(XREG2, ARG2)?;
            e.str_uoff(ARG1, C_P, PROCESS_I)?;
            e.cmp_imm(FCALLS, 0, false)
        })
        .map_err(fail)?;
        code.b_cond(Cond::Le, schedule_out).map_err(fail)?;
        if let Some(peek) = inline_peek {
            // Port of erts/emulator/beam/jit/arm/instr_msg.cpp (emit_i_loop_rec_shared, "Peek
            // next message"), OTP-29.1.1: load the message at the save position; only an empty
            // message queue calls the receive helper.
            let fetch = code.new_label();
            code.emit(|e| e.ldr_uoff(TMP1, C_P, peek.save_term_offset))
                .map_err(fail)?;
            code.cbz(TMP1, fetch).map_err(fail)?;
            code.emit(|e| {
                e.ldr_uoff(XREG0, TMP1, 0)?;
                e.mov_const(TMP2, 1)?;
                e.strb_uoff(TMP2, C_P, peek.delay_gc_offset)?;
                e.ret(XREG1)
            })
            .map_err(fail)?;
            code.bind(fetch).map_err(fail)?;
        }
        emit_enter_runtime(&mut code, 0, Update::HEAP_ALLOC.union(Update::REDUCTIONS))
            .map_err(fail)?;
        code.emit(|e| {
            e.mov_reg(ARG1, C_P)?;
            e.mov_const(SUPER_TMP, loop_rec as *const () as u64)?;
            e.blr(SUPER_TMP)
        })
        .map_err(fail)?;
        emit_leave_runtime(&mut code, 0, Update::HEAP_ALLOC.union(Update::REDUCTIONS))
            .map_err(fail)?;
        code.emit(|e| e.cmp_imm(ARG1, LOOP_REC_FETCH, false))
            .map_err(fail)?;
        code.b_cond(Cond::Hi, done).map_err(fail)?;
        // A fetch the hook did not finish in place runs the helper on the scheduler side,
        // which charges its own four reductions; an empty inner queue is charged here.
        code.cbnz(ARG1, schedule_out).map_err(fail)?;
        code.emit(|e| e.subs_imm(FCALLS, FCALLS, 4, false))
            .map_err(fail)?;
        code.b(wait).map_err(fail)?;

        code.bind(schedule_out).map_err(fail)?;
        code.emit(|e| {
            e.mov_const(TMP2, 0)?;
            e.strb_uoff(TMP2, C_P, PROCESS_ARITY)?;
            e.mov_const(SUPER_TMP, context_switch as u64)?;
            e.br(SUPER_TMP)
        })
        .map_err(fail)?;

        code.bind(wait).map_err(fail)?;
        code.emit(|e| e.br(XREG2)).map_err(fail)?;

        code.bind(done).map_err(fail)?;
        code.emit(|e| {
            e.mov_reg(XREG0, ARG1)?;
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
        memory.flush_all()?;
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
