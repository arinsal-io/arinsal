//! Process-wide context-switch and garbage-collection fragments shared by every compiled
//! module.

use arinsal_a64::{
    buf::{BufferError, CodeBuffer},
    enc::{Cond, Gpr, Shift},
    exec::{CodeMemory, ExecError},
};

use crate::{Update, emit_enter_runtime, rt::arinsal_enter_native_return};

const C_P: Gpr = Gpr::x(21);
const HTOP: Gpr = Gpr::x(23);
const FCALLS: Gpr = Gpr::w(22);
const ARG1: Gpr = Gpr::x(0);
const ARG5: Gpr = Gpr::w(4);
const TMP1: Gpr = Gpr::w(8);
const SUPER_TMP: Gpr = Gpr::x(17);
const SCHEDULER_REGS: Gpr = Gpr::x(19);
const ARG2: Gpr = Gpr::x(1);
const ARG3: Gpr = Gpr::x(2);
const TMP2: Gpr = Gpr::x(9);
const PROCESS_I: u32 = 72;
const PROCESS_ARITY: u16 = 80;
const PROCESS_CURRENT: u32 = 88;
const CODE_MFA_BYTES: u16 = 24;
const CODE_MFA_ARITY: u32 = 16;

/// Bytes between a function's entry and the instruction after its `i_test_yield`: the
/// breakpoint trampoline (`str`, `b`, `bl`) and the `adr`, `subs`, `b.le` of the test itself.
// Port of erts/emulator/beam/jit/arm/instr_common.cpp (TEST_YIELD_RETURN_OFFSET),
// OTP-29.1.1.
pub(crate) const TEST_YIELD_RETURN_OFFSET: usize = 24;

/// Entry-relative offset of the `i_test_yield` of a function: right after its trampoline.
pub(crate) const FUNC_PROLOGUE_SIZE: usize = 12;

/// `ga->get_*()` entries every module calls: `dispatch_return`, `i_test_yield_shared`,
/// `context_switch_simplified`, `do_schedule` and `garbage_collect`.
pub struct YieldFragments {
    memory: CodeMemory,
    dispatch_return_offset: usize,
    test_yield_offset: usize,
    context_switch_offset: usize,
    do_schedule_offset: usize,
    garbage_collect_offset: usize,
}

/// Addresses a module assembler calls in [`YieldFragments`] (`ga->get_*()`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct YieldEntries {
    /// `dispatch_return`.
    pub dispatch_return: usize,
    /// `i_test_yield_shared`.
    pub i_test_yield_shared: usize,
    /// `context_switch_simplified`.
    pub context_switch: usize,
    /// `garbage_collect`.
    pub garbage_collect: usize,
}

impl YieldFragments {
    /// Emits the shared yield fragments once for the VM.
    // Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp (emit_context_switch_simplified),
    // erts/emulator/beam/jit/arm/instr_call.cpp (emit_dispatch_return) and
    // erts/emulator/beam/jit/arm/instr_common.cpp (emit_i_test_yield_shared),
    // OTP-29.1.1.
    ///
    /// `garbage_collect_nobump` is `erts_garbage_collect_nobump` (erl_gc.c): `int (Process *p,
    /// Uint need, Eterm *objv, int nobj, int fcalls)`, the reductions spent. `process_state` is
    /// `offsetof(Process, state)`.
    // Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp:99-134 (emit_garbage_collect) and
    // erts/emulator/beam/jit/arm/process_main.cpp:306-317 (`do_schedule`), OTP-29.1.1.
    pub fn new(garbage_collect_nobump: usize, process_state: u32) -> Result<Self, ExecError> {
        let mut code = CodeBuffer::new();
        let fail = |_: BufferError| ExecError::InvalidSize("yield fragment");
        let context_switch = code.new_label();
        let dispatch_return = code.new_label();
        let test_yield = code.new_label();
        let do_schedule = code.new_label();
        let garbage_collect = code.new_label();

        // ARG3 = HTOP + S_RESERVED + bytes needed, ARG4 = live X registers.
        code.bind(garbage_collect).map_err(fail)?;
        code.emit(|e| {
            // emit_enter_runtime_frame.
            e.stp_pre(Gpr::x(29), Gpr::x(30), Gpr::sp(), -16)?;
            // The words needed, without the S_RESERVED the check added: the collector adds it
            // itself.
            e.sub_reg(ARG2, ARG3, HTOP, Shift::Lsl, 0)?;
            e.lsr_imm(ARG2, ARG2, 3)?;
            e.sub_imm(ARG2, ARG2, arinsal_term::S_RESERVED as u16, false)?;
            // Where the process was if it crashes in the collection.
            e.str_uoff(Gpr::x(30), C_P, PROCESS_I)
        })
        .map_err(fail)?;
        let update = Update::HEAP_ALLOC.union(Update::X_REGS);
        emit_enter_runtime(&mut code, 6, update).map_err(fail)?;
        code.emit(|e| {
            e.mov_reg(ARG1, C_P)?;
            crate::arm::beam_asm::load_x_reg_array(e, ARG3)?;
            // ARG4 (live) is already loaded.
            e.mov_reg(ARG5, FCALLS)?;
            e.mov_const(SUPER_TMP, garbage_collect_nobump as u64)?;
            e.blr(SUPER_TMP)?;
            e.sub_reg(FCALLS, FCALLS, Gpr::w(0), Shift::Lsl, 0)
        })
        .map_err(fail)?;
        crate::emit_leave_runtime(&mut code, 6, update).map_err(fail)?;
        code.emit(|e| {
            // emit_leave_runtime_frame.
            e.ldp_post(Gpr::x(29), Gpr::x(30), Gpr::sp(), 16)?;
            e.ldr_uoff(TMP1, C_P, process_state)?;
            e.tst_imm(
                TMP1,
                u64::from(crate::common::process_offsets::ERTS_PSFLG_EXITING),
            )
        })
        .map_err(fail)?;
        code.b_cond(Cond::Ne, do_schedule).map_err(fail)?;
        code.emit(|e| e.ret(Gpr::x(30))).map_err(fail)?;

        // `do_schedule`: `c_p->i` is set (erts_set_self_exiting points it at `beam_exit`) and
        // no X register is kept, so the process leaves through the context switch with
        // ARG3 = `c_p->i` and arity 0, as context_switch_simplified's exiting branch does
        // (process_main.cpp:137-143).
        code.bind(do_schedule).map_err(fail)?;
        code.emit(|e| {
            e.ldr_uoff(ARG3, C_P, PROCESS_I)?;
            e.strb_uoff(Gpr::wzr(), C_P, PROCESS_ARITY)
        })
        .map_err(fail)?;
        code.b(context_switch).map_err(fail)?;

        code.bind(dispatch_return).map_err(fail)?;
        code.emit(|e| {
            // `context_switch_simplified` receives the resume PC in ARG3.
            e.mov_reg(ARG3, Gpr::x(30))?;
            e.str_uoff(Gpr::xzr(), C_P, PROCESS_CURRENT)?;
            e.mov_const(TMP2, 1)?;
            e.strb_uoff(TMP2, C_P, PROCESS_ARITY)
        })
        .map_err(fail)?;
        code.b(context_switch).map_err(fail)?;

        code.bind(test_yield).map_err(fail)?;
        code.emit(|e| {
            e.sub_imm(ARG2, ARG3, CODE_MFA_BYTES, false)?;
            e.add_imm(ARG3, ARG3, TEST_YIELD_RETURN_OFFSET as u16, false)?;
            e.str_uoff(ARG3, C_P, PROCESS_I)?;
            e.str_uoff(ARG2, C_P, PROCESS_CURRENT)?;
            e.ldr_uoff(Gpr::w(9), ARG2, CODE_MFA_ARITY)?;
            e.strb_uoff(TMP2, C_P, PROCESS_ARITY)
        })
        .map_err(fail)?;

        code.bind(context_switch).map_err(fail)?;
        emit_enter_runtime(
            &mut code,
            6,
            Update::HEAP_ALLOC
                .union(Update::REDUCTIONS)
                .union(Update::X_REGS),
        )
        .map_err(fail)?;
        // Port of erts/emulator/beam/jit/arm/process_main.cpp:124-162
        // (context_switch_simplified_local), OTP-29.1.1.
        code.emit(|e| {
            e.str_uoff(ARG3, C_P, PROCESS_I)?;
            e.mov_const(Gpr::x(0), 1)?;
            e.str_uoff(
                Gpr::x(0),
                SCHEDULER_REGS,
                crate::arm::beam_asm::tmp_mem_ref(3),
            )?;
            e.mov_const(Gpr::x(30), arinsal_enter_native_return as *const () as u64)?;
            e.ret(Gpr::x(30))
        })
        .map_err(fail)?;

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
            dispatch_return_offset: labels[&dispatch_return],
            test_yield_offset: labels[&test_yield],
            context_switch_offset: labels[&context_switch],
            do_schedule_offset: labels[&do_schedule],
            garbage_collect_offset: labels[&garbage_collect],
        })
    }

    /// The entries a module assembler calls (`BeamModuleAssembler::set_yield_fragments`).
    pub fn entries(&self) -> YieldEntries {
        YieldEntries {
            dispatch_return: self.dispatch_return(),
            i_test_yield_shared: self.i_test_yield_shared(),
            context_switch: self.context_switch(),
            garbage_collect: self.garbage_collect(),
        }
    }

    /// Entry of `do_schedule`: `c_p->i` is where the process continues; no X register is live.
    pub fn do_schedule(&self) -> usize {
        self.memory.ptr_at(self.do_schedule_offset) as usize
    }

    /// Entry of `garbage_collect`: ARG3 (x2) is `HTOP` plus `S_RESERVED` plus the bytes
    /// needed, ARG4 (x3) the live X register count. Returns to x30 unless the collection
    /// made the process exit.
    pub fn garbage_collect(&self) -> usize {
        self.memory.ptr_at(self.garbage_collect_offset) as usize
    }

    /// Entry of `context_switch_simplified`: ARG3 is stored in `c_p->i`; live X count is in
    /// `c_p->arity`.
    pub fn context_switch(&self) -> usize {
        self.memory.ptr_at(self.context_switch_offset) as usize
    }

    /// Entry of `dispatch_return`: the caller's `x30` is the return address to resume at.
    pub fn dispatch_return(&self) -> usize {
        self.memory.ptr_at(self.dispatch_return_offset) as usize
    }

    /// Entry of `i_test_yield_shared`: x2 holds the function's entry address.
    pub fn i_test_yield_shared(&self) -> usize {
        self.memory.ptr_at(self.test_yield_offset) as usize
    }
}
