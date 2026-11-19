//! JIT-only runtime helpers.
//!
//! Port of erts/emulator/beam/jit/beam_jit_common.cpp, OTP-29.1.1: the functions generated
//! native code calls by address, under their erts names and C signatures.

use arinsal_beamasm::ProcessHeader;
use arinsal_term::Term;

/// `ErtsBifFunc`: a BIF body called with `(Process *, Eterm *, ErtsCodePtr)`.
pub type ErtsBifFunc = crate::bif_table::Bif;

/// Calls a BIF body and performs the post-call collection required by BeamAsm.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp:588-616 (`beam_jit_call_bif`), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn beam_jit_call_bif(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    instruction: usize,
    vbf: ErtsBifFunc,
    arity: usize,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return arinsal_term::THE_NON_VALUE;
    };
    process.heap.note_bif_entry();
    let live_hf_end = process.heap.bif_live_hf_end();

    let result = vbf(c_p, reg, instruction as u64);

    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return result;
    };
    if process.heap.gc_after_bif_desired() {
        return crate::raw::gc_ffi::erts_gc_after_bif_call_lhf(
            c_p,
            live_hf_end,
            result,
            reg,
            arity as u64,
        );
    }
    result
}

/// Returns the first non-trace continuation address at or below the stack pointer `E`.
// Port of erts/emulator/beam/beam_common.c:413-435 (`erts_printable_return_address`),
// OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_printable_return_address(p: *const ProcessHeader, e: *const u64) -> usize {
    crate::raw::beam_common_ffi::printable_return_address(p, e)
}

/// `static void i_emit_nyi(char *msg)`: the JIT hit an instruction it cannot emit.
// Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:397-399 (i_emit_nyi),
// OTP-29.1.1: `erts_exit(ERTS_ERROR_EXIT, "NYI: %s\n", msg)`.
#[unsafe(no_mangle)]
pub extern "C" fn i_emit_nyi(msg: *const core::ffi::c_char) {
    let text = crate::raw::jit_ffi::c_str_lossy(msg);
    eprintln!("NYI: {text}");
    crate::erts_exit(1);
}

/// `Eterm beam_jit_build_argument_list(Process *c_p, const Eterm *regs, int arity)`: the
/// list `[regs[0], ..., regs[arity-1]]` on the process heap.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp:1292-1305, OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn beam_jit_build_argument_list(
    c_p: *mut ProcessHeader,
    regs: *const u64,
    arity: i32,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return Term::NIL.tagged_word();
    };
    let args = crate::raw::jit_ffi::reg_words(regs, arity as usize);
    let args: smallvec::SmallVec<[Term; 8]> = args
        .iter()
        .map(|&w| crate::native_hooks::from_raw(w))
        .collect();
    // HAlloc cannot fail in erts.
    arinsal_term::TermBuilder::new(&mut crate::ProcessHeapHandle(&mut process.heap))
        .list_from_iter(args)
        .map(crate::native_hooks::raw)
        .unwrap_or_else(|_| crate::erts_exit(1))
}

/// `const Export *beam_jit_handle_unloaded_fun(Process *c_p, Eterm *reg, int arity,
/// Eterm fun_thing, ErtsCodeIndex code_ix)`: the export to call (an address), or 0 with
/// `c_p->freason` set. `reg[0..4]` become `Module, Fun, Args, []` for the handler.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp:1307-1365, OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn beam_jit_handle_unloaded_fun(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    arity: i32,
    fun_thing: u64,
    _code_ix: u32,
) -> usize {
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(c_p, reg) else {
        return 0;
    };
    let fun = crate::native_hooks::from_raw(fun_thing);
    let Some(arinsal_term::FunRef::Local { entry, .. }) = crate::native_hooks::fun_view(fun) else {
        return 0;
    };
    // erts tests `fe->pend_purge_address` first: during a purge the entry's address is
    // `beam_unloaded_fun` even though the old code still exists.
    if entry
        .pend_purge_address
        .load(std::sync::atomic::Ordering::Acquire)
        != 0
    {
        return pending_purge_lambda(process, registers, entry.module, fun, arity as u32);
    }
    unloaded_fun_error_handler(process, registers, entry.module, fun, arity as u32)
}

/// A call of a local fun whose module has no current code: `error_handler:undefined_lambda/3`
/// with X0..X3 set up, `badfun` when the module is loaded without the fun, `undef` without an
/// error handler.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp (beam_jit_handle_unloaded_fun),
// OTP-29.1.1.
fn unloaded_fun_error_handler(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    module: arinsal_term::Atom,
    fun: Term,
    arity: u32,
) -> usize {
    let code_ix = registers.active_code_ix as usize;
    let Some(runtime) = process.runtime.as_ref() else {
        crate::native_hooks::set_error(process, "undef");
        return 0;
    };
    if runtime.with_active_code(|_, tables| tables.loaded.get(&module).is_some()) {
        // EXC_BADFUN with the fun as its value: the error term is {badfun, Fun}.
        process.heap.abi.current = std::ptr::null();
        let reason =
            arinsal_term::TermBuilder::new(&mut crate::ProcessHeapHandle(&mut process.heap))
                .tuple(&[Term::atom(arinsal_term::atoms::BADFUN), fun]);
        match reason {
            Ok(reason) => {
                process.heap.abi.exc.freason = arinsal_beamasm::exc::EXC_ERROR;
                process.heap.abi.exc.fvalue = crate::native_hooks::raw(reason);
            }
            Err(_) => crate::native_hooks::set_error(process, "system_limit"),
        }
        return 0;
    }
    let handler = process
        .cold
        .as_ref()
        .and_then(|cold| cold.flags.error_handler)
        .and_then(Term::as_atom)
        .unwrap_or(arinsal_term::atoms::ERROR_HANDLER);
    let Ok(undefined_lambda) = arinsal_term::global_atoms().intern("undefined_lambda") else {
        crate::native_hooks::set_error(process, "undef");
        return 0;
    };
    let Some(handler_export) = runtime
        .export_entry((handler, undefined_lambda, 3), code_ix)
        .filter(|ep| {
            !crate::export::is_export_trampoline_active(ep, code_ix)
                || crate::export::has_export_breakpoint(ep)
        })
    else {
        process.heap.abi.current = std::ptr::null();
        crate::native_hooks::set_error(process, "undef");
        return 0;
    };
    lambda_handler_call(process, registers, handler_export, module, fun, arity)
}

/// The call of a fun in code being purged: the caller suspends until the purge completes or
/// aborts, then `erts_code_purger:pending_purge_lambda/3` retries the call.
// Port of erts/emulator/beam/beam_bif_load.c:1977-2008
// (erts_suspend_process_on_pending_purge_lambda) and jit/beam_jit_common.cpp
// (beam_jit_handle_unloaded_fun, `fe->pend_purge_address`), OTP-29.1.1.
fn pending_purge_lambda(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    module: arinsal_term::Atom,
    fun: Term,
    arity: u32,
) -> usize {
    let code_ix = registers.active_code_ix as usize;
    let Some(runtime) = process.runtime else {
        crate::native_hooks::set_error(process, "undef");
        return 0;
    };
    if let (Some(pid), Some(name)) = (process.self_pid, arinsal_term::global_atoms().text(module))
        && crate::natives::code::erts_purge_state().suspend_on_pending_lambda(name, pid)
    {
        crate::suspend::suspend_self(process);
        // ERTS_VBUMP_ALL_REDS: the callee's reduction check leaves the scheduler.
        if process.heap.abi.fcalls > 0 {
            process.virtual_reds = process
                .virtual_reds
                .saturating_add(process.heap.abi.fcalls as u32);
        }
        process.heap.abi.fcalls = 0;
    }
    let (Ok(purger), Ok(function)) = (
        arinsal_term::global_atoms().intern("erts_code_purger"),
        arinsal_term::global_atoms().intern("pending_purge_lambda"),
    ) else {
        crate::native_hooks::set_error(process, "undef");
        return 0;
    };
    let Some(export) = runtime.export_entry((purger, function, 3), code_ix) else {
        crate::native_hooks::set_error(process, "undef");
        return 0;
    };
    lambda_handler_call(process, registers, export, module, fun, arity)
}

/// X0..X3 = Module, Fun, Args, [] for `handler(Module, Fun, Args)` and its address.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp (beam_jit_handle_unloaded_fun: the
// argument list and `reg[0..3]`), OTP-29.1.1.
fn lambda_handler_call(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    handler_export: &arinsal_term::ExportEntry,
    module: arinsal_term::Atom,
    fun: Term,
    arity: u32,
) -> usize {
    let arity = arity as usize;
    // The fun is rooted above the arguments while the list is built.
    registers.x_reg_array[arity] = fun;
    if process
        .ensure_objv(arity * 2, &mut registers.x_reg_array[..arity + 1])
        .is_err()
    {
        crate::native_hooks::set_error(process, "system_limit");
        return 0;
    }
    let fun = registers.x_reg_array[arity];
    let list = beam_jit_build_argument_list(
        std::ptr::from_mut(process).cast(),
        registers.x_reg_array.as_ptr().cast(),
        arity as i32,
    );
    registers.x_reg_array[0] = Term::atom(module);
    registers.x_reg_array[1] = fun;
    registers.x_reg_array[2] = crate::native_hooks::from_raw(list);
    registers.x_reg_array[3] = Term::NIL;
    handler_export as *const arinsal_term::ExportEntry as usize
}

/// Removes the current message from the mailbox (`remove_message`).
#[unsafe(no_mangle)]
pub extern "C" fn beam_jit_remove_message(
    header: *mut ProcessHeader,
    fcalls: i32,
    _htop: *mut u64,
    _e: *mut u64,
    active_code_ix: u32,
) -> i32 {
    let Some(process) = crate::native_hooks::enter_runtime(header) else {
        return fcalls;
    };
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:1087-1089 (beam_jit_remove_message),
    // OTP-29.1.1.
    if active_code_ix as usize == crate::code_ix::ERTS_SAVE_CALLS_CODE_IX {
        crate::trace::save_call(process, crate::trace::SavedCall::Receive);
    } else {
        match process.remove_first_message() {
            Ok(true) => return remove_message_leave_reds(process, fcalls),
            Ok(false) => {}
            Err(_) => {
                crate::native_hooks::set_error(process, "system_limit");
                return fcalls;
            }
        }
    }
    // A message carrying a seq_trace token emits its `receive` event on the receiver's own
    // heap here (the tracer may be the receiver itself), so the native HTOP and stack
    // pointer must round-trip like in every other allocating helper.
    let result = process.remove_message(None);
    if result.is_err() {
        crate::native_hooks::set_error(process, "system_limit");
    }
    remove_message_leave_reds(process, fcalls)
}

/// Port of erts/emulator/beam/jit/beam_jit_common.cpp (beam_jit_remove_message), OTP-29.1.1:
/// when the received message's fragments outgrew the free young area or the off-heap binary
/// overhead passed its limit, a collection is wanted soon, so only a few reductions are left
/// to let the message turn into garbage (ERTS_IS_GC_DESIRED_INTERNAL, then
/// ERTS_VBUMP_LEAVE_REDS_INTERNAL).
fn remove_message_leave_reds(process: &mut crate::Process, fcalls: i32) -> i32 {
    const REDS_LEFT_BEFORE_GC: i32 = 5;
    let free_words =
        (process.heap.abi.stop as usize).wrapping_sub(process.heap.abi.htop as usize) / 8;
    let desired = free_words < process.heap.mbuf_size() || process.heap.bin_vheap_gc_due();
    if desired && fcalls > REDS_LEFT_BEFORE_GC {
        process.virtual_reds = process
            .virtual_reds
            .saturating_add((fcalls - REDS_LEFT_BEFORE_GC) as u32);
        return REDS_LEFT_BEFORE_GC;
    }
    fcalls
}

/// Records that the process waits for a message; the scheduler puts it to sleep.
#[unsafe(no_mangle)]
pub extern "C" fn beam_jit_wait_locked(header: *mut ProcessHeader, resume: usize) {
    if let Some(process) = crate::native_hooks::enter_runtime(header) {
        // Port of erts/emulator/beam/emu/msg_instrs.tab:110 (wait clears F_DELAY_GC), OTP-29.1.1.
        process.set_delay_gc(false);
        let timeout = process.native_wait_timeout.take();
        process.native_wait = Some(timeout);
        process.native_wait_self = resume & 1 != 0;
        process.native_exit_kind = crate::proc_create::NativeExit::Wait;
    }
}

/// Takes the receive lock; the private queue needs no lock here.
#[unsafe(no_mangle)]
pub extern "C" fn beam_jit_take_receive_lock(_header: *mut ProcessHeader) {}

/// `beam_jit_wait_locked` after taking the receive lock.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp:1203-1206, OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn beam_jit_wait_unlocked(header: *mut ProcessHeader, resume: usize) {
    beam_jit_take_receive_lock(header);
    beam_jit_wait_locked(header, resume);
}

/// Starts a timed wait: zero means the timeout already expired, one that the process waits.
#[unsafe(no_mangle)]
pub extern "C" fn beam_jit_wait_timeout(
    header: *mut ProcessHeader,
    timeout: u64,
    next: usize,
) -> i32 {
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:1208-1222
    // (beam_jit_wait_timeout), OTP-29.1.1: timeout setup updates process wait state but does
    // not access the process heap or stack cursors.
    let Some(process) = crate::native_hooks::enter_runtime(header) else {
        return 2;
    };
    match process.wait_timeout(crate::native_hooks::from_raw(timeout)) {
        Ok(Some(0)) => 0,
        Ok(remaining) => {
            if remaining.is_some() {
                // `c_p->def_arg_reg[0] = next`: the timeout label a timed-out schedule-in
                // continues at.
                process.receive_timeout_next = next;
            }
            process.native_wait_timeout = remaining;
            1
        }
        Err(_) => {
            crate::native_hooks::set_error(process, "timeout_value");
            // RET_badarg (RET_next=0, RET_wait=1, RET_badarg=2), as in instr_msg.cpp.
            2
        }
    }
}

/// Clears the receive timeout state.
#[unsafe(no_mangle)]
pub extern "C" fn beam_jit_timeout(header: *mut ProcessHeader) {
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:1242-1251
    // (beam_jit_timeout), OTP-29.1.1: timeout cleanup does not access heap or stack cursors.
    if let Some(process) = crate::native_hooks::process_from_header(header) {
        process.timeout();
        // Port of erts/emulator/beam/jit/beam_jit_common.cpp:1246-1248 (beam_jit_timeout),
        // OTP-29.1.1.
        if crate::trace::saves_calls(process) {
            crate::trace::save_call(process, crate::trace::SavedCall::Timeout);
        }
        if crate::trace::active() {
            process.slice_mut().native_timeout_trace = true;
            process.native_exit_kind = crate::proc_create::NativeExit::TimeoutTrace;
        }
    }
}

/// `beam_jit_timeout` after releasing the receive lock.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp:1253-1256, OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn beam_jit_timeout_locked(header: *mut ProcessHeader) {
    beam_jit_timeout(header);
}

/// Gets the requested map elements from loader operands and stores them in X/Y registers.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp:706-760 (beam_jit_get_map_elements), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn beam_jit_get_map_elements(
    map: u64,
    reg: *mut u64,
    stack: *mut u64,
    n: u64,
    fs: *mut u64,
) -> u64 {
    let Ok(n) = usize::try_from(n) else {
        return 0;
    };
    let map = crate::native_hooks::from_raw(map);
    let result = arinsal_maps::get_map_elements_with(
        map,
        n,
        |index| {
            crate::native_hooks::from_raw(crate::raw::beam_common_ffi::read_word(fs, index * 3))
        },
        |index| crate::raw::beam_common_ffi::read_word(fs, index * 3 + 2),
        |index, value| {
            raw::write_destination(
                crate::raw::beam_common_ffi::read_word(fs, index * 3 + 1),
                value,
                reg,
                stack,
            )
        },
    );
    match result {
        Ok(true) => 1,
        Ok(false) | Err(_) => 0,
    }
}

mod raw {
    //! Raw operand table access for the `beam_jit_get_map_elements` C ABI.
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:706-760, OTP-29.1.1.

    const LOADER_TAG_MASK: u64 = 0x0f;
    const LOADER_TAG_SIZE: u32 = 4;
    const LOADER_X_REG: u64 = 0x3;
    const LOADER_Y_REG: u64 = 0x7;

    /// Stores a matched map value to the loader-tagged destination register.
    pub(super) fn write_destination(
        descriptor: u64,
        value: arinsal_term::Term,
        reg: *mut u64,
        stack: *mut u64,
    ) -> bool {
        let index = (descriptor >> LOADER_TAG_SIZE) as usize;
        let destination = match descriptor & LOADER_TAG_MASK {
            LOADER_X_REG => reg,
            LOADER_Y_REG => stack,
            _ => return false,
        };
        if destination.is_null() {
            return false;
        }
        crate::raw::beam_common_ffi::write_word(
            destination.wrapping_add(index),
            value.tagged_word(),
        )
    }
}

/// The runtime symbols native code calls keep their erts names and C signatures: a type
/// mismatch is a compile error here, and `no_mangle` keeps the erts name for the linker.
#[cfg(test)]
mod tests {
    use arinsal_beamasm::ProcessHeader as P;
    use std::sync::atomic::{AtomicU64, Ordering};

    static BIF_INSTRUCTION: AtomicU64 = AtomicU64::new(0);

    extern "C" fn return_first_argument(_c_p: *mut P, reg: *mut u64, instruction: u64) -> u64 {
        BIF_INSTRUCTION.store(instruction, Ordering::Relaxed);
        crate::native_hooks::raw(crate::bif_table::bif_args::<1>(reg)[0])
    }

    #[test]
    fn beam_jit_call_bif_runs_the_body_and_gc_epilogue() {
        let mut process = crate::Process::new();
        let value =
            arinsal_term::TermBuilder::new(&mut crate::ProcessHeapHandle(&mut process.heap))
                .tuple(&[
                    arinsal_term::Term::small(37).unwrap(),
                    arinsal_term::Term::small(91).unwrap(),
                ])
                .unwrap();
        let mut registers = arinsal_beamasm::SchedulerRegisters::default();
        registers.x_reg_array[0] = value;
        process.heap.set_force_gc(true);
        let collections_before = process.stats.gc.collections;
        let instruction = 0x1234_5678;

        let result = super::beam_jit_call_bif(
            std::ptr::from_mut(process.native_header()),
            registers.x_reg_array.as_mut_ptr().cast(),
            instruction,
            return_first_argument,
            1,
        );

        similar_asserts::assert_eq!(BIF_INSTRUCTION.load(Ordering::Relaxed), instruction as u64);
        similar_asserts::assert_eq!(
            crate::native_hooks::from_raw(result).classify(),
            arinsal_term::TermKind::Tuple
        );
        assert!(process.stats.gc.collections > collections_before);
    }

    #[test]
    fn printable_return_address_skips_a_trace_frame() {
        let continuation = 0x1234_5678_u64;
        for kind in [
            crate::trace::TraceFrameKind::ReturnTrace,
            crate::trace::TraceFrameKind::ExceptionTrace,
            crate::trace::TraceFrameKind::ReturnToTrace,
            crate::trace::TraceFrameKind::CallTraceReturn,
        ] {
            let mut stack = vec![kind.address() as u64];
            stack.resize(1 + kind.data_words(), 0);
            stack.push(continuation);
            let process = P {
                hend: stack.as_mut_ptr().wrapping_add(stack.len()),
                ..P::default()
            };

            similar_asserts::assert_eq!(
                super::erts_printable_return_address(&process, stack.as_ptr()),
                continuation as usize
            );
        }
    }

    #[test]
    fn erts_runtime_symbols_have_erts_signatures() {
        let _: extern "C" fn(*const core::ffi::c_char) = super::i_emit_nyi;
        let _: extern "C" fn(*mut P, *mut u64, usize, super::ErtsBifFunc, usize) -> u64 =
            super::beam_jit_call_bif;
        let _: extern "C" fn(*const P, *const u64) -> usize = super::erts_printable_return_address;
        let _: extern "C" fn(*mut P, *const u64, i32) -> u64 = super::beam_jit_build_argument_list;
        let _: extern "C" fn(*mut P, *mut u64, i32, u64, u32) -> usize =
            super::beam_jit_handle_unloaded_fun;
        let _: extern "C" fn(*mut P, i32, *mut u64, *mut u64, u32) -> i32 =
            super::beam_jit_remove_message;
        let _: extern "C" fn(*mut P) = super::beam_jit_take_receive_lock;
        let _: extern "C" fn(*mut P, usize) = super::beam_jit_wait_locked;
        let _: extern "C" fn(*mut P, usize) = super::beam_jit_wait_unlocked;
        let _: extern "C" fn(*mut P, u64, usize) -> i32 = super::beam_jit_wait_timeout;
        let _: extern "C" fn(*mut P) = super::beam_jit_timeout;
        let _: extern "C" fn(*mut P) = super::beam_jit_timeout_locked;
        let _: extern "C" fn(u64, *mut f64) -> i32 = crate::big::big_to_double;
        let _: extern "C" fn(u64, u64, u64, *mut P) -> i32 = crate::exceptions::raw_raise;
        let _: extern "C" fn(*mut P, u64) -> u64 = crate::exceptions::build_stacktrace;
        let _: extern "C" fn(*mut P, u64) -> u64 = crate::erl_bits::erts_bs_init_writable;
        let _: extern "C" fn(*mut P) -> u64 = crate::receive::erts_msgq_recv_marker_insert;
        let _: extern "C" fn(*mut P, u64, u64) = crate::receive::erts_msgq_recv_marker_bind;
        let _: extern "C" fn(*mut P, u64) = crate::receive::erts_msgq_recv_marker_clear;
        let _: extern "C" fn(*mut P, u64) = crate::receive::erts_msgq_recv_marker_set_save;
        let _: extern "C" fn(*mut P) = crate::receive::erts_msgq_set_save_next;
        let _: extern "C" fn(*mut P, i32, i32, *mut u64, *mut i32) -> i32 =
            crate::receive::erts_proc_sig_receive_helper;
        let _: extern "C" fn(u64, *mut u64, *mut u64, u64, *mut u64) -> u64 =
            super::beam_jit_get_map_elements;
    }
}

/// Calls the NIF of a `call_nif` sequence: `fp` of library `nif_mod`, for the function whose
/// code (or `ErtsNifBeamStub` code) `I` is.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp:623-677 (beam_jit_call_nif), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn beam_jit_call_nif(
    c_p: *mut ProcessHeader,
    i: usize,
    reg: *mut u64,
    fp: usize,
    nif_mod: usize,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(c_p, reg) else {
        return arinsal_term::THE_NON_VALUE;
    };
    // erts_code_to_codemfa(I); `current` is set to please handle_error.
    let codemfa = i - std::mem::size_of::<arinsal_term::ErtsCodeMfa>();
    process.heap.abi.current = codemfa as *const std::ffi::c_void;
    let arity = crate::natives::raw::code_mfa(codemfa).arity as usize;
    let value = crate::natives::nif::beam_jit_call_nif(
        process,
        (fp, nif_mod),
        &mut registers.x_reg_array,
        arity,
    );
    // THE_NON_VALUE leaves `c_p->freason`: an exception for handle_error, or TRAP with
    // `c_p->i` at the trampoline erts_nfunc_schedule set up.
    if value.is_non_value() {
        return arinsal_term::THE_NON_VALUE;
    }
    crate::native_hooks::raw(value)
}

/// `enum beam_jit_nif_load_ret`.
// Port of erts/emulator/beam/jit/beam_jit_common.hpp:517, OTP-29.1.1.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeamJitNifLoadRet {
    /// `RET_NIF_success`.
    Success = 0,
    /// `RET_NIF_error`.
    Error = 1,
    /// `RET_NIF_yield`.
    Yield = 2,
}

/// `i_load_nif`: loads the NIF library of the module whose code `I` is in, holding the code
/// modification permission; a process not given it yields and retries the instruction.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp:679-704 (beam_jit_load_nif), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn beam_jit_load_nif(
    c_p: *mut ProcessHeader,
    i: usize,
    reg: *mut u64,
) -> BeamJitNifLoadRet {
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(c_p, reg) else {
        return BeamJitNifLoadRet::Error;
    };
    let (Some(runtime), Some(pid)) = (process.runtime, process.self_pid) else {
        return BeamJitNifLoadRet::Error;
    };
    if !crate::natives::code::try_seize_code_mod_permission(runtime, process, pid) {
        // Yield and try again.
        process.heap.abi.current = std::ptr::null();
        process.heap.abi.arity = 2;
        return BeamJitNifLoadRet::Yield;
    }
    let (path, info) = (registers.x_reg_array[0], registers.x_reg_array[1]);
    let result = crate::process::sched_data::with_sched_data(process, |vm, process, _ctx| {
        crate::natives::nif::erts_load_nif(vm, process, i, path, info)
    })
    .expect("native code runs inside an executor slice, which publishes its scheduler data");
    crate::natives::code::release_code_mod_permission(runtime);
    match result {
        Ok(value) => {
            registers.x_reg_array[0] = value;
            BeamJitNifLoadRet::Success
        }
        Err(_) => {
            process.heap.abi.exc.freason = arinsal_term::exc::EXC_BADARG;
            BeamJitNifLoadRet::Error
        }
    }
}

/// `beam_jit_decode_dist(c_p, msgp)`: decode the external message `loop_rec` found at the save
/// pointer; a corrupt one is unlinked and freed and `NULL` is returned, so the receive loop
/// restarts at the next message.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp:1059-1075 (beam_jit_decode_dist),
// OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn beam_jit_decode_dist(
    c_p: *mut ProcessHeader,
    msgp: *mut arinsal_beamasm::ErtsMessage,
) -> *mut arinsal_beamasm::ErtsMessage {
    let Some(process) = crate::native_hooks::enter_runtime(c_p) else {
        return std::ptr::null_mut();
    };
    debug_assert_eq!(
        process
            .inbox
            .entries
            .peek_node()
            .map(|node| node.as_ptr() as usize),
        Some(msgp as usize),
        "loop_rec decodes the message at the save pointer"
    );
    let runtime = process.runtime;
    let decoded = process
        .inbox
        .entries
        .peek_mut()
        .is_some_and(|event| match &mut event.payload {
            arinsal_sched::Payload::Message(message) => {
                crate::process::erts_proc_sig_decode_dist(runtime, message, false)
            }
            _ => false,
        });
    if !decoded {
        // A corrupt distribution message that we weren't able to decode; remove it...
        // (erts_msgq_unlink_msg, then erts_cleanup_messages).
        drop(process.inbox.entries.unlink_at_save());
        return std::ptr::null_mut();
    }
    msgp
}
