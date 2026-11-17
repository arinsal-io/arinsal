//! Runtime helper bodies called by BeamAsm generated code.

#[path = "native_helpers/bs_construct_raw.rs"]
pub(crate) mod bs_construct_raw;

use arinsal_beamasm::ProcessHeader;
use arinsal_bits::MatchOps;
use arinsal_term::{HeapAlloc, PreparedWritableAppend, Term, TermBuilder};

use crate::beamasm_integration::ExportDispatch;

struct StaticNif {
    module: String,
    function: String,
    arity: u8,
    entry: arinsal_bifs::BifFn,
}

/// Restores the class saved with an OTP raw stacktrace for native `raise/2`.
// Port of erts/emulator/beam/jit/arm/instr_common.cpp:3018-3030, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_raise_class(
    header: *mut ProcessHeader,
    trace_raw: u64,
    _value_raw: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let trace = crate::native_hooks::from_raw(trace_raw);
    // erts_sanitize_freason treats NIL as a trace produced in native code: there is
    // no saved class to restore, so handle_error must save a fresh trace.
    if trace == Term::NIL {
        return arinsal_beamasm::exc::EXC_ERROR;
    }
    let empty_class = crate::exceptions::empty_trace_class(trace);
    let raw_class = crate::stacktrace::raw_class(process, trace);
    let class = empty_class.or(raw_class).or(process.exc_class).or_else(|| {
        // x3 of `reg` holds the class atom a catch put there (found_catch).
        let reg = crate::process::sched_data::sched_registers(process)?;
        crate::exceptions::parse_class(reg[3])
    });
    // Port of erts/emulator/beam/beam_common.c (erts_sanitize_freason), OTP-29.1.1: a valid
    // stacktrace is re-raised as is.
    let reraise = arinsal_beamasm::catch::RERAISE;
    match class {
        Some(arinsal_bifs::Class::Error) => reraise | arinsal_beamasm::exc::EXTAG_ERROR,
        Some(arinsal_bifs::Class::Exit) => reraise | arinsal_beamasm::exc::EXTAG_EXIT,
        Some(arinsal_bifs::Class::Throw) => reraise | arinsal_beamasm::exc::EXTAG_THROWN,
        None => {
            process.heap.abi.exc.fvalue =
                crate::native_hooks::raw(Term::atom(arinsal_term::atoms::BADARG));
            arinsal_beamasm::exc::EXC_ERROR
        }
    }
}

/// Stores the class, value, and already saved trace used by OTP's raw_raise.
// Port of erts/emulator/beam/beam_common.c:1148-1178 (`raw_raise`), OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_raw_raise(
    header: *mut ProcessHeader,
    trace_raw: u64,
    class_raw: u64,
    value_raw: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(header) else {
        return 1;
    };
    let class_term = crate::native_hooks::from_raw(class_raw);
    let class = match class_term.as_atom() {
        Some(atom) if atom == arinsal_term::atoms::ERROR => arinsal_bifs::Class::Error,
        Some(atom) if atom == arinsal_term::atoms::EXIT => arinsal_bifs::Class::Exit,
        Some(atom) if atom == arinsal_term::atoms::THROW => arinsal_bifs::Class::Throw,
        _ => return 1,
    };
    let trace = crate::native_hooks::from_raw(trace_raw);
    // `get_freason_ptr_from_exc` updates saved traces and tolerates NIL through its dummy word.
    crate::stacktrace::set_raw_class(process, trace, class);
    process.heap.abi.exc.freason =
        crate::stacktrace::class_to_freason(Some(class)) & !arinsal_beamasm::exc::EXF_SAVETRACE;
    process.heap.abi.exc.fvalue = value_raw;
    process.heap.abi.exc.ftrace = trace_raw;
    0
}

/// Materializes a process-owned raw trace on the process heap.
// Port of erts/emulator/beam/jit/arm/instr_common.cpp:3046-3055, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_build_stacktrace(
    header: *mut ProcessHeader,
    trace_raw: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let trace = crate::native_hooks::from_raw(trace_raw);
    match crate::exceptions::materialize(process, trace) {
        // The fragment places the value in X0 (instr_common.cpp:3054).
        Ok(value) => crate::native_hooks::raw(value),
        Err(_) => {
            crate::native_hooks::set_error(process, "system_limit");
            0
        }
    }
}

/// Pairs an error reason with its materialized stacktrace for a native `catch_end`.
// Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp (emit_catch_end_shared) and
// erts/emulator/beam/beam_common.c (add_stacktrace), OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_add_stacktrace(
    header: *mut ProcessHeader,
    reason_raw: u64,
    trace_raw: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let reason = crate::native_hooks::from_raw(reason_raw);
    let trace = crate::native_hooks::from_raw(trace_raw);
    let result = crate::exceptions::materialize(process, trace).and_then(|stacktrace| {
        arinsal_term::TermBuilder::new(&mut crate::ProcessHeapHandle(&mut process.heap))
            .tuple(&[reason, stacktrace])
            .map_err(|error| crate::VmError::Unsupported(format!("stacktrace tuple {error:?}")))
    });
    match result {
        Ok(value) => crate::native_hooks::raw(value),
        Err(_) => {
            // The catch-end fragment stores this word and builds `{'EXIT', Word}`.
            // A zero return is not a term and the fragment loads through it.
            arinsal_term::TermBuilder::new(&mut crate::ProcessHeapHandle(&mut process.heap))
                .tuple(&[reason, arinsal_term::Term::NIL])
                .map(crate::native_hooks::raw)
                .unwrap_or_else(|_| crate::native_hooks::raw(reason))
        }
    }
}

/// Converts a bignum to IEEE-754 bits for a native `fconv`, raising `badarith` on overflow.
// Port of erts/emulator/beam/jit/arm/instr_float.cpp:103-195 (fconv), OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_big_to_float(header: *mut ProcessHeader, term_raw: u64) -> u64 {
    let Some(process) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let term = crate::native_hooks::from_raw(term_raw);
    match crate::native_hooks::integer_float(term) {
        Ok(value) => value.to_bits(),
        Err(_) => {
            crate::native_hooks::set_error(process, "badarith");
            0
        }
    }
}

/// Creates the empty writable binary for a native `bs_init_writable`.
// Port of erts/emulator/beam/jit/arm/instr_bs.cpp:985-1000 and erl_bits.c:2002
// (erts_bs_init_writable), OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_bs_init_writable(header: *mut ProcessHeader, size: u64) -> u64 {
    let Some(process) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let size = crate::native_hooks::from_raw(size).as_small();
    if process.ensure_objv(8, &mut []).is_err() {
        crate::native_hooks::set_error(process, "system_limit");
        return 0;
    }
    let result = arinsal_bits::init_writable_with_size(size, &mut process.heap);
    match result {
        Ok(value) => crate::native_hooks::raw(value),
        Err(_) => {
            crate::native_hooks::set_error(process, "system_limit");
            0
        }
    }
}

// Port of erts/emulator/beam/jit/arm/instr_msg.cpp:25-295 (receive instructions), OTP-29.1.1.
// The hooks operate on the process mailbox owned by the VM; blocking is delegated to the
// scheduler through `ColdState::native_wait`.

/// Reserves a receive marker (`recv_marker_reserve`).
pub extern "C" fn arinsal_beamasm_recv_marker_reserve(header: *mut ProcessHeader) -> u64 {
    let Some(process) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    // Port of erts/emulator/beam/erl_proc_sig_queue.h:2226 (erts_msgq_recv_marker_insert),
    // OTP-29.1.1: the outer queue is fetched before the marker is inserted. Signals waiting
    // there (or a process without a probe yet) send the instruction to the scheduler, which
    // fetches and reruns it.
    let pending = process
        .signal_probe()
        .is_none_or(arinsal_sched::SignalProbe::has_pending);
    if pending {
        process.native_exit_kind = crate::proc_create::NativeExit::ReserveFetch;
        return u64::from(arinsal_beamasm::receive::RECV_MARKER_FETCH);
    }
    match process.reserve_receive_marker() {
        Ok(marker) => crate::native_hooks::raw(marker),
        Err(_) => {
            crate::native_hooks::set_error(process, "system_limit");
            0
        }
    }
}

/// Binds a receive marker to a reference (`recv_marker_bind`).
pub extern "C" fn arinsal_beamasm_recv_marker_bind(
    header: *mut ProcessHeader,
    marker: u64,
    reference: u64,
) {
    if let Some(process) = crate::native_hooks::enter_runtime(header) {
        process.bind_receive_marker(
            crate::native_hooks::from_raw(marker),
            crate::native_hooks::from_raw(reference),
        );
    }
}

/// Clears the marker of a reference (`recv_marker_clear`).
pub extern "C" fn arinsal_beamasm_recv_marker_clear(header: *mut ProcessHeader, reference: u64) {
    if let Some(process) = crate::native_hooks::enter_runtime(header) {
        process.clear_receive_marker(crate::native_hooks::from_raw(reference));
    }
}

/// Moves the save pointer to the marker of a reference (`recv_marker_use`).
pub extern "C" fn arinsal_beamasm_recv_marker_use(header: *mut ProcessHeader, reference: u64) {
    if let Some(process) = crate::native_hooks::enter_runtime(header) {
        process.use_receive_marker(crate::native_hooks::from_raw(reference));
    }
}

/// Peeks the message at the save pointer (`i_loop_rec`). Zero means the process waits;
/// [`arinsal_beamasm::receive::LOOP_REC_FETCH`] that the outer signal queue must be fetched
/// first.
// Port of erts/emulator/beam/jit/arm/instr_msg.cpp:131-176 (emit_i_loop_rec_shared peek)
// and erts/emulator/beam/erl_proc_sig_queue.c:7730-7790 (erts_proc_sig_receive_helper),
// OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_loop_rec(header: *mut ProcessHeader) -> u64 {
    let Some(process) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    // Port of erts/emulator/beam/jit/arm/instr_msg.cpp:116-118, 179, 191 (F_DELAY_GC set on
    // entry, cleared on the wait and schedule-out exits), OTP-29.1.1.
    process.delay_gc = true;
    if let Some(message) = process.inbox.peek() {
        return crate::native_hooks::raw(*message);
    }
    // The message queue is exhausted. Signals left unhandled in the middle queue, or sent
    // since the last fetch (by this process or any other) to the outer queue, go to the
    // receive helper on the scheduler side. A process without a probe yet fetches once, which
    // installs it.
    if !process.sig_cont_empty() {
        process.delay_gc = false;
        process.native_exit_kind = crate::proc_create::NativeExit::SignalFetch;
        return u64::from(arinsal_beamasm::receive::LOOP_REC_FETCH);
    }
    let pending = process
        .signal_probe()
        .is_none_or(arinsal_sched::SignalProbe::has_pending);
    if !pending {
        process.delay_gc = false;
        return 0;
    }
    // Port of erts/emulator/beam/jit/arm/instr_msg.cpp:131-176 (erts_proc_sig_receive_helper
    // call under eHeapAlloc), OTP-29.1.1: fetch messages in place and peek again.
    let fetched = process.fetch_messages_in_place();
    if fetched.is_ok()
        && let Some(message) = process.inbox.peek()
    {
        // Port of erts/emulator/beam/erl_proc_sig_queue.c (erts_proc_sig_receive_helper,
        // `consumed_reds += 4` per fetch), OTP-29.1.1: the call site published FCALLS
        // (Update::REDUCTIONS) and reloads it afterwards.
        process.heap.abi.fcalls = process.heap.abi.fcalls.saturating_sub(4);
        return crate::native_hooks::raw(*message);
    }
    process.delay_gc = false;
    // Everything fetched was scanned: wait. A non-message signal left at the head of the
    // outer queue is handled by the scheduler.
    if fetched.is_ok()
        && process
            .signal_probe()
            .is_some_and(|probe| !probe.has_pending())
    {
        return 0;
    }
    process.native_exit_kind = crate::proc_create::NativeExit::SignalFetch;
    u64::from(arinsal_beamasm::receive::LOOP_REC_FETCH)
}

/// Removes the current message from the mailbox (`remove_message`).
pub extern "C" fn arinsal_beamasm_remove_message(
    header: *mut ProcessHeader,
    fcalls: i32,
    active_code_ix: usize,
) -> i32 {
    let Some(process) = crate::native_hooks::enter_runtime(header) else {
        return fcalls;
    };
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:1087-1089 (beam_jit_remove_message),
    // OTP-29.1.1.
    if active_code_ix == crate::code_ix::ERTS_SAVE_CALLS_CODE_IX {
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

/// Advances the save pointer (`loop_rec_end`).
pub extern "C" fn arinsal_beamasm_set_save_next(header: *mut ProcessHeader) {
    if let Some(process) = crate::native_hooks::enter_runtime(header) {
        process.loop_rec_end();
    }
}

/// Records that the process waits for a message; the scheduler puts it to sleep.
pub extern "C" fn arinsal_beamasm_wait(header: *mut ProcessHeader, resume: usize) {
    if let Some(process) = crate::native_hooks::enter_runtime(header) {
        // Port of erts/emulator/beam/emu/msg_instrs.tab:110 (wait clears F_DELAY_GC), OTP-29.1.1.
        process.delay_gc = false;
        let timeout = process.native_wait_timeout.take();
        process.native_wait = Some(timeout);
        process.native_wait_self = resume & 1 != 0;
        process.native_exit_kind = crate::proc_create::NativeExit::Wait;
    }
}

/// Takes the receive lock; the private queue needs no lock here.
pub extern "C" fn arinsal_beamasm_take_receive_lock(_header: *mut ProcessHeader) {}

/// Starts a timed wait: zero means the timeout already expired, one that the process waits.
pub extern "C" fn arinsal_beamasm_wait_timeout(
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

/// Clears the receive timeout state (`timeout`, `timeout_locked`).
pub extern "C" fn arinsal_beamasm_timeout(header: *mut ProcessHeader) {
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

// Adapter for erts/emulator/beam/jit/arm/instr_bs.cpp:2387-2400, OTP-29.1.1:
// this table retains module string bytes used by `am_string` segments.
fn match_strings() -> &'static std::sync::RwLock<Vec<std::sync::Arc<[u8]>>> {
    static STRINGS: std::sync::OnceLock<std::sync::RwLock<Vec<std::sync::Arc<[u8]>>>> =
        std::sync::OnceLock::new();
    STRINGS.get_or_init(|| std::sync::RwLock::new(Vec::new()))
}

/// Registers a string-table constant matched by `i_bs_match_string` and returns its handle.
// Adapter for erts/emulator/beam/jit/arm/instr_bs.cpp:2387-2400, OTP-29.1.1.
pub(crate) fn register_match_string(bytes: &[u8]) -> u64 {
    let mut strings = match_strings().write().unwrap_or_else(|e| e.into_inner());
    strings.push(std::sync::Arc::from(bytes));
    (strings.len() - 1) as u64
}

fn static_nifs() -> &'static std::sync::Mutex<std::collections::HashMap<usize, StaticNif>> {
    static NIFS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<usize, StaticNif>>,
    > = std::sync::OnceLock::new();
    NIFS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

static NEXT_STATIC_NIF: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);

pub(crate) fn register_static_nif(
    module: String,
    function: String,
    arity: u8,
    entry: arinsal_bifs::BifFn,
) -> usize {
    let identity = NEXT_STATIC_NIF.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    static_nifs().lock().unwrap().insert(
        identity,
        StaticNif {
            module,
            function,
            arity,
            entry,
        },
    );
    identity
}

/// Identity in `native_dirty_nif` of a call-NIF body bound by `load_nif`: the process's
/// `nif_pending` carries the library and function. Static NIF identities start at 1.
pub(crate) const BOUND_NIF: usize = 0;

/// The call-NIF body of a function of native code that `load_nif` may replace. The body is
/// compiled with the address of its site and calls [`arinsal_beamasm_call_nif`] with it.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:956-992 (emit_call_nif embeds Func, NifMod
// and DirtyFunc in the function's code) and erl_nif.c:5149-5160 (load_nif_1st_finisher
// copies them there), OTP-29.1.1: the site of the function holds the operands itself.
pub(crate) struct NativeNifSite {
    arity: u8,
    /// The `call_nif` operands, written once by `load_nif` before the body is enabled.
    call: std::sync::OnceLock<crate::natives::nif::NativeFn>,
}

impl NativeNifSite {
    pub(crate) fn new(_module: String, _function: String, arity: u8) -> Box<Self> {
        Box::new(Self {
            arity,
            call: std::sync::OnceLock::new(),
        })
    }

    /// Writes the operands; a site is bound once, like the code of one module instance.
    pub(crate) fn bind(&self, native: crate::natives::nif::NativeFn) -> bool {
        self.call.set(native).is_ok()
    }
}

/// The static NIF `identity` with the arguments in `process.x` as a dirty job; the
/// executor's [`run_static_nif`] takes its result.
///
/// Port of erts/emulator/beam/erl_nif.c:426 (erts_call_dirty_nif), OTP-29.1.1.
pub(crate) fn static_nif_job(
    process: &mut crate::Process,
    identity: usize,
) -> Option<arinsal_sched::DirtyJob> {
    let (module, arity, entry) = static_nifs().lock().ok().and_then(|nifs| {
        let nif = nifs.get(&identity)?;
        Some((nif.module.clone(), nif.arity, nif.entry))
    })?;
    // The job runs on this thread; NIF services find the process through these.
    crate::natives::nif::refresh_hub_native(process);
    if module == "prim_tty" {
        crate::natives::tty::note_caller_native(process);
    }
    let args = process.x.get(..usize::from(arity))?.to_vec();
    let fcalls = process.heap.abi.fcalls;
    let pinned_caller = (module == "zstd" || module == "zlib")
        .then(|| process.self_pid.and_then(|pid| pid.to_term()));
    Some(crate::dirty::static_nif_job(move |heap| {
        heap.abi.fcalls = fcalls;
        let mut run = || {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                crate::calls::call_bif(heap, entry, &args)
            }))
            .unwrap_or_else(|_| {
                Err(arinsal_bifs::BifError::Error(Term::atom(
                    arinsal_term::atoms::ERROR,
                )))
            })
        };
        match pinned_caller {
            Some(caller) => arinsal_nif_zlib::with_caller(caller, run),
            None => run(),
        }
    }))
}

/// Runs a static NIF with the arguments in `reg`, for a dirty NIF call the executor
/// performs on a dirty scheduler, or takes the result of its dirty job. [`BOUND_NIF`]
/// resumes the call of a NIF bound by `load_nif` that the process carries.
pub(crate) fn run_static_nif(
    process: &mut crate::Process,
    reg: &[Term],
    identity: usize,
) -> Result<Term, crate::VmError> {
    if identity == BOUND_NIF {
        return run_bound_nif(process, reg);
    }
    let nif = static_nifs().lock().ok().and_then(|nifs| {
        let nif = nifs.get(&identity)?;
        Some((
            nif.module.clone(),
            nif.function.clone(),
            nif.arity,
            nif.entry,
        ))
    });
    let Some((module, function, arity, entry)) = nif else {
        return Err(crate::VmError::Trap(crate::exceptions::Trap::error(
            Term::atom(arinsal_term::atoms::UNDEF),
        )));
    };
    crate::natives::nif::refresh_hub_native(process);
    if module == "prim_tty" {
        crate::natives::tty::note_caller_native(process);
    }
    let args = reg[..usize::from(arity)].to_vec();
    let pending = process
        .cold
        .as_mut()
        .and_then(|cold| cold.nif_pending.take().map(|boxed| *boxed));
    let done = process
        .cold
        .as_mut()
        .and_then(|cold| cold.static_nif_done.take());
    let result = match done {
        Some(result) => result,
        None => std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match pending {
            Some(pending) => crate::natives::nif::resume_pending(&mut process.heap, pending),
            None => crate::calls::call_bif(&mut process.heap, entry, &args),
        }))
        .unwrap_or_else(|_| {
            Err(arinsal_bifs::BifError::Error(Term::atom(
                arinsal_term::atoms::ERROR,
            )))
        }),
    };
    result.map_err(|error| crate::exceptions::bif_error(process, &module, &function, &args, error))
}

/// Resumes the dirty call or continuation of a NIF bound by `load_nif` that native code
/// handed to the executor.
// Port of erts/emulator/beam/erl_nif.c:426-520 (erts_call_dirty_nif), OTP-29.1.1.
fn run_bound_nif(process: &mut crate::Process, reg: &[Term]) -> Result<Term, crate::VmError> {
    let Some(pending) = process
        .cold
        .as_mut()
        .and_then(|cold| cold.nif_pending.take().map(|boxed| *boxed))
    else {
        return Err(crate::VmError::Trap(crate::exceptions::Trap::error(
            Term::atom(arinsal_term::atoms::UNDEF),
        )));
    };
    let (module, function, arity) = {
        let (module, function, arity) = pending.trace_mfa();
        (module.to_owned(), function.to_owned(), usize::from(arity))
    };
    crate::natives::nif::refresh_hub_native(process);
    let args = reg.get(..arity).unwrap_or_default().to_vec();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::natives::nif::resume_pending(&mut process.heap, pending)
    }))
    .unwrap_or_else(|_| {
        Err(arinsal_bifs::BifError::Error(Term::atom(
            arinsal_term::atoms::ERROR,
        )))
    });
    result.map_err(|error| crate::exceptions::bif_error(process, &module, &function, &args, error))
}

/// Returns the result of a native call-NIF body to native code: the result term, a trap to
/// the dirty scheduler executor or an exception.
fn leave_native_nif(
    process: &mut crate::Process,
    reg: &mut [Term],
    result: std::thread::Result<Result<Term, arinsal_bifs::BifError>>,
    (identity, arity): (usize, u8),
) -> u64 {
    match result {
        Ok(Ok(value)) => {
            reg[0] = value;
            crate::native_hooks::raw(value)
        }
        Ok(Err(arinsal_bifs::BifError::Dirty(class))) => {
            // Port of erts/emulator/beam/erl_nif.c:3460 (static_schedule_dirty_nif) and
            // erl_nif.c:3540 (enif_schedule_nif), OTP-29.1.1: the call traps to a
            // continuation the executor runs on a scheduler of `class`.
            if let Some(pending) = crate::natives::nif::take_rescheduled() {
                process.cold_mut().nif_pending = Some(Box::new(pending));
            }
            trap_to_dirty_nif(process, identity, class, arity)
        }
        Ok(Err(error)) => {
            let args = reg[..usize::from(arity)].to_vec();
            let bif_mfa = crate::beamasm_integration::export_dispatch(identity)
                .map_or(0, |export| std::ptr::from_ref(export.mfa()) as usize);
            set_native_bif_error(process, bif_mfa, &args, error);
            0
        }
        Err(_) => {
            crate::native_hooks::set_error(process, "error");
            0
        }
    }
}

/// Calls a static NIF body through the same BIF function used by NativeBody.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:863-900, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_static_nif(
    header: *mut ProcessHeader,
    identity: u64,
    reg: *mut u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(header, reg) else {
        return 0;
    };
    // `reg`: the NIF's arguments, as beam_jit_call_nif passes them.
    let reg = &mut registers.x_reg_array;
    let Some(nif) = static_nifs().lock().ok().and_then(|nifs| {
        let nif = nifs.get(&(identity as usize))?;
        Some(StaticNif {
            module: nif.module.clone(),
            function: nif.function.clone(),
            arity: nif.arity,
            entry: nif.entry,
        })
    }) else {
        crate::native_hooks::set_error(process, "undef");
        return 0;
    };
    // Port of erts/emulator/beam/erl_nif.c (schedule_dirty_nif / erts_call_dirty_nif),
    // OTP-29.1.1: a dirty NIF called on a normal scheduler first moves the process to a
    // dirty scheduler; the executor runs it there and returns to this body's caller.
    if let Some(class) = moves_to_dirty(process, &nif.module, &nif.function, nif.arity) {
        return trap_to_dirty_nif(process, identity as usize, class, nif.arity);
    }
    // Like the interpreter's NativeBody, the body reads the scheduler hub, which run_native
    // installed when the process was scheduled in.
    if nif.module == "prim_tty" {
        crate::natives::tty::note_caller_native(process);
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::calls::call_bif(&mut process.heap, nif.entry, &reg[..usize::from(nif.arity)])
    }));
    leave_native_nif(process, reg, result, (identity as usize, nif.arity))
}

/// Calls the NIF that `load_nif` bound to a native call-NIF body.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:863-900 (call_nif_shared loads Func and
// NifMod from the function's code) and erts/emulator/beam/jit/beam_jit_common.cpp:623-677
// (beam_jit_call_nif), OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_call_nif(
    header: *mut ProcessHeader,
    site: u64,
    reg: *mut u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(header, reg) else {
        return 0;
    };
    // `reg`: the NIF's arguments, as beam_jit_call_nif passes them.
    let reg = &mut registers.x_reg_array;
    // SAFETY: `site` is the address this call-NIF body was compiled with: a boxed
    // `NativeNifSite` owned by the `CompiledVersion` whose code is executing, which keeps the
    // box until it frees that code.
    let site = unsafe { &*(site as usize as *const NativeNifSite) };
    let Some(native) = site.call.get() else {
        crate::native_hooks::set_error(process, "undef");
        return 0;
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::natives::nif::call_native(&mut process.heap, native, &reg[..usize::from(site.arity)])
    }));
    leave_native_nif(process, reg, result, (BOUND_NIF, site.arity))
}

/// The dirty scheduler class static NIF `module:function/arity` is flagged with in its library's
/// `nif_funcs` table (`ERL_NIF_DIRTY_JOB_IO_BOUND` or `ERL_NIF_DIRTY_JOB_CPU_BOUND`).
pub(crate) fn static_nif_dirty_class(
    module: &str,
    function: &str,
    arity: u8,
) -> Option<arinsal_bifs::SchedulerClass> {
    use arinsal_bifs::SchedulerClass;
    match module {
        "prim_tty" => arinsal_nif_tty::dirty_io(function, arity).then_some(SchedulerClass::DirtyIo),
        "prim_file" => {
            arinsal_nif_file::dirty_io(function, arity).then_some(SchedulerClass::DirtyIo)
        }
        "prim_socket" | "prim_net" => {
            arinsal_nif_socket::dirty_io(module, function, arity).then_some(SchedulerClass::DirtyIo)
        }
        "zstd" => {
            arinsal_nif_zlib::dirty_cpu(module, function, arity).then_some(SchedulerClass::DirtyCpu)
        }
        _ => None,
    }
}

/// The dirty scheduler class a call of static NIF `module:function/arity` first moves `process`
/// to, if any.
///
/// Port of erts/emulator/beam/erl_nif.c:3437-3477 (static_schedule_dirty_nif and
/// static_schedule_dirty_io_nif), OTP-29.1.1. A process outside a scheduler (`Vm::eval`) has no
/// dirty scheduler to move to and runs the NIF in place.
pub(crate) fn moves_to_dirty(
    process: &crate::Process,
    module: &str,
    function: &str,
    arity: u8,
) -> Option<arinsal_bifs::SchedulerClass> {
    use arinsal_bifs::SchedulerClass;
    let class = static_nif_dirty_class(module, function, arity)?;
    let current = arinsal_sched::current_scheduler_type();
    let already = match class {
        SchedulerClass::DirtyIo => current == arinsal_sched::SchedulerType::DirtyIo,
        SchedulerClass::DirtyCpu => current == arinsal_sched::SchedulerType::DirtyCpu,
        SchedulerClass::Normal => true,
    };
    (!already && (module == "prim_tty" || process.runtime.is_some())).then_some(class)
}

/// Leave native code through the dirty NIF dispatch trap; the executor runs NIF
/// `identity` (or the process's pending continuation) on a scheduler of `class` and
/// resumes after the native call with the result in x0.
fn trap_to_dirty_nif(
    process: &mut crate::Process,
    identity: usize,
    class: arinsal_bifs::SchedulerClass,
    arity: u8,
) -> u64 {
    process.slice_mut().native_dirty_nif = Some((identity, 0, class));
    process.heap.abi.arity = arity;
    process.gc_live = usize::from(arity);
    process.heap.abi.i =
        arinsal_beamasm::dispatch::DIRTY_NIF_DISPATCH_IDENTITY as *const u8 as *const _;
    process.heap.abi.exc.freason = 1 << 10;
    0
}

/// Dispatches a BIF export from the shared export trampoline.
// Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp:164-210, OTP-29.1.1.
pub(crate) extern "C" fn arinsal_beamasm_export_trampoline(
    header: *mut ProcessHeader,
    identity: u64,
    export: Option<ExportDispatch>,
    reg: *mut u64,
) -> u64 {
    // THE_NON_VALUE raises, 1 hands the call to the interpreter, any term word is the result.
    let raw = invoke_dispatch_bif(header, reg, identity as usize, 0, export, true).unwrap_or(1);
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp (beam_jit_call_bif:
    // ERTS_IS_GC_AFTER_BIF_DESIRED, then erts_gc_after_bif_call_lhf with `reg`), OTP-29.1.1:
    // the export entry's BIF call collects after the BIF, for a value or the non-value.
    if raw != 1
        && let Some(export) = export
        && let Some((process, registers)) =
            crate::native_hooks::enter_runtime_after_bif(header, reg)
        && process.heap.gc_after_bif_desired()
    {
        return gc_after_bif_call(process, registers, export, raw);
    }
    raw
}

/// `call_error_handler` of the export trampoline: the export of
/// `error_handler:undefined_function/3` (the process's error handler module), with X0..X2 set
/// to the stub's module, function and argument list; zero when there is no such function.
// Port of erts/emulator/beam/beam_common.c:1294-1345 (call_error_handler), OTP-29.1.1.
pub(crate) extern "C" fn arinsal_beamasm_call_error_handler(
    header: *mut ProcessHeader,
    export: Option<ExportDispatch>,
    reg: *mut u64,
) -> usize {
    let Some(stub) = export else {
        return 0;
    };
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(header, reg) else {
        return 0;
    };
    let Some(runtime) = process.runtime.as_ref() else {
        return 0;
    };
    let handler = process
        .cold
        .as_ref()
        .and_then(|cold| cold.flags.error_handler)
        .and_then(Term::as_atom)
        .unwrap_or(arinsal_term::atoms::ERROR_HANDLER);
    let Ok(undefined_function) = arinsal_term::global_atoms().intern("undefined_function") else {
        return 0;
    };
    let code_ix = registers.active_code_ix as usize;
    // erts_find_function: an export whose trampoline is active (and not a breakpoint) is
    // not loaded.
    let Some(handler_export) = runtime
        .export_entry((handler, undefined_function, 3), code_ix)
        .filter(|ep| {
            !crate::export::is_export_trampoline_active(ep, code_ix)
                || crate::export::has_export_breakpoint(ep)
        })
    else {
        return 0;
    };
    let arity = usize::from(stub.arity);
    if process
        .ensure_objv(arity * 2, &mut registers.x_reg_array[..arity])
        .is_err()
    {
        return 0;
    }
    let args: smallvec::SmallVec<[Term; 8]> =
        smallvec::SmallVec::from_slice(&registers.x_reg_array[..arity]);
    let Ok(list) = arinsal_term::TermBuilder::new(&mut crate::ProcessHeapHandle(&mut process.heap))
        .list_from_iter(args)
    else {
        return 0;
    };
    registers.x_reg_array[0] = Term::atom(stub.module_atom);
    registers.x_reg_array[1] = Term::atom(stub.function_atom);
    registers.x_reg_array[2] = list;
    std::ptr::from_ref(handler_export) as usize
}

/// Records the remote call of a process saving calls (the export entry is `identity`) and
/// returns the address the call continues with.
// Port of erts/emulator/beam/jit/arm/instr_call.cpp:123-148 (emit_dispatch_save_calls_export),
// OTP-29.1.1.
pub(crate) extern "C" fn arinsal_beamasm_save_calls_export(
    header: *mut ProcessHeader,
    _identity: u64,
    export: Option<ExportDispatch>,
) -> u64 {
    if let Some(export) = export
        && let Some(process) = crate::native_hooks::enter_runtime(header)
    {
        crate::trace::save_call(
            process,
            crate::trace::SavedCall::Mfa(export.module_atom, export.function_atom, export.arity),
        );
    }
    crate::beamasm_integration::save_calls_continuation(export) as u64
}

/// Runs a light BIF through the shared BeamAsm fragment.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-471, OTP-29.1.1.
// The call site passes the export's descriptor like erts passes the Export*; the send and
// breakpoint identities pass none.
pub(crate) extern "C" fn arinsal_beamasm_call_light_bif_shared(
    header: *mut ProcessHeader,
    identity: u64,
    site: u64,
    export: Option<ExportDispatch>,
    reg: *mut u64,
) -> u64 {
    // `site` is only meaningful for the breakpoint trampoline.
    call_light_bif_body(header, reg, identity, site, export)
}

/// The shared fragment's general path. Out of line so a counter BIF does not
/// pay this function's prologue.
#[inline(never)]
fn call_light_bif_body(
    header: *mut ProcessHeader,
    reg: *mut u64,
    identity: u64,
    site: u64,
    export: Option<ExportDispatch>,
) -> u64 {
    invoke_dispatch_bif(header, reg, identity as usize, site as usize, export, false).unwrap_or(0)
}

/// `persistent_term:get/1` from the export's function pointer.
// Port of erts/emulator/beam/erl_bif_persistent.c:380 (`persistent_term_get_1`), OTP-29.1.1.
pub(crate) extern "C" fn persistent_term_get_1_light(
    header: *mut ProcessHeader,
    regs: *mut u64,
    _i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(header) else {
        return 0;
    };
    let [key] = crate::bif_table::bif_args::<1>(regs);
    let found = process.persistent_terms.get(key);
    match found {
        Some(value) => crate::native_hooks::raw(value),
        None => {
            crate::native_hooks::set_error(process, "badarg");
            0
        }
    }
}

/// `persistent_term:get/2` from the export's function pointer.
// Port of erts/emulator/beam/erl_bif_persistent.c:390 (`persistent_term_get_2`), OTP-29.1.1.
pub(crate) extern "C" fn persistent_term_get_2_light(
    header: *mut ProcessHeader,
    regs: *mut u64,
    _i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(header) else {
        return 0;
    };
    let [key, default] = crate::bif_table::bif_args::<2>(regs);
    let value = process.persistent_terms.get(key).unwrap_or(default);
    crate::native_hooks::raw(value)
}

/// Returns through the trace frame of kind `kind` (passed by its return stub) and resumes at
/// the caller's return address. A return_trace or return_to event needs the scheduler's
/// tracer context: the return then leaves native code like a trapped call.
// Port of erts/emulator/beam/jit/arm/instr_trace.cpp (emit_return_trace,
// emit_i_return_to_trace, emit_i_call_trace_return), OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_native_trace_return(
    header: *mut ProcessHeader,
    kind: u64,
    reg: *mut u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(header, reg) else {
        return 0;
    };
    let Some(kind) = crate::trace::TraceFrameKind::from_index(kind) else {
        return 0;
    };
    let Some((event, caller)) = crate::trace::return_through_trace_frame(
        process,
        registers.x_reg_array[0],
        kind,
        |p, words| {
            p.heap
                .set_stack_pointer(p.heap.abi.stop.wrapping_add(words));
        },
    ) else {
        return 0;
    };
    if let Some(event) = event {
        process.cold_mut().native_return_events = Some(Box::new(event));
        registers.tmp_mem[0] = arinsal_beamasm::dispatch::RETURN_TO_DISPATCH_IDENTITY as u64;
        registers.tmp_mem[1] = caller.tagged_word();
        registers.tmp_mem[3] = 2;
        return arinsal_beamasm::rt::arinsal_enter_native_return as *const () as usize as u64;
    }
    caller.tagged_word()
}

/// Collects from the native heap and stack cursors published by generated code.
// Port of erts/emulator/beam/jit/arm/instr_common.cpp:90-122 and beam_asm_global.cpp:102-140, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_gc_sync(
    header: *mut ProcessHeader,
    scheduler_registers: *mut arinsal_beamasm::SchedulerRegisters,
    need_words: usize,
    live: usize,
    fcalls: i32,
) -> i32 {
    let Some((process, registers)) =
        crate::native_hooks::enter_runtime_reg(header, scheduler_registers.cast::<u64>())
    else {
        return 0;
    };
    // The generated code holds FCALLS in a register; a delayed collection reads what is left.
    process.heap.abi.fcalls = fcalls;
    // The emitter passes the full checked free-space gap, including CP and
    // S_RESERVED. Process::ensure uses that gap to decide whether to collect.
    // `process.x` is the scheduler's X register array: the live prefix is rooted and moved in
    // place, as in erts_garbage_collect_nobump on `reg`.
    let Some(objv) = registers.x_reg_array.get_mut(..live) else {
        crate::native_hooks::set_error(process, "system_limit");
        return 0;
    };
    let result = process.ensure_uncharged(need_words, objv);
    if result.is_err() {
        crate::native_hooks::set_error(process, "system_limit");
    }
    // Port of erts/emulator/beam/erl_gc.c (erts_garbage_collect_nobump), OTP-29.1.1:
    // the collection's cost, at most the reductions left, is what the generated code
    // subtracts from FCALLS. A delayed collection costs all the reductions left
    // (erl_gc.c:588-597, delay_garbage_collection), so the process yields at its next
    // reduction check.
    i32::try_from(result.unwrap_or(0))
        .unwrap_or(i32::MAX)
        .min(fcalls.max(0))
}

/// `ERTS_VBUMP_REDS`: take `reds` from the slice without counting them in the process's own
/// reductions; the part beyond what is left ends the slice.
// Port of erts/emulator/beam/bif.h:85 (ERTS_VBUMP_REDS), OTP-29.1.1.
pub(crate) fn vbump_reds(process: &mut crate::Process, reds: i32) {
    if process.heap.abi.fcalls >= reds {
        process.heap.abi.fcalls -= reds;
        process.virtual_reds = process.virtual_reds.saturating_add(reds as u32);
    } else {
        if process.heap.abi.fcalls > 0 {
            process.virtual_reds = process
                .virtual_reds
                .saturating_add(process.heap.abi.fcalls as u32);
        }
        process.heap.abi.fcalls = 0;
    }
}

/// Prepares the live X registers and handler arguments for a native line-breakpoint call.
// Port of erts/emulator/beam/beam_bp.c:1821-1865
// (erts_line_breakpoint_hit__prepare_call), OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_line_breakpoint_prepare(
    header: *mut ProcessHeader,
    pc: u64,
    live: u64,
    reg: *mut u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(header, reg) else {
        return 0;
    };
    let Ok(live) = usize::try_from(live) else {
        return 0;
    };
    if live > registers.x_reg_array.len() {
        return 0;
    }
    let Some(function) = crate::native_function_at(pc as usize) else {
        return 0;
    };
    let Some((_, line)) = function.line_at(pc as usize) else {
        return 0;
    };
    if (function.module, function.function, function.arity) == ("erts_internal", "breakpoint", 4) {
        return 0;
    }
    let Some(export) =
        crate::beamasm_integration::line_breakpoint_export(registers.active_code_ix as usize)
    else {
        return 0;
    };

    for index in 0..live {
        if !process.heap.stack_set(index, registers.x_reg_array[index]) {
            crate::native_hooks::set_error(process, "system_limit");
            return 0;
        }
    }
    let args = [
        Term::atom(function.module_atom),
        Term::atom(function.function_atom),
        Term::small(i64::from(function.arity)).expect("arity is a small integer"),
        Term::small(i64::from(line)).expect("debug line is a small integer"),
    ];
    registers.x_reg_array[..4].copy_from_slice(&args);
    process.heap.abi.arity = 4;
    export as *const arinsal_beamasm::bif::ExportEntry as usize as u64
}

/// Restores the live X register prefix from the stack below a returning breakpoint handler.
// Port of erts/emulator/beam/beam_bp.c:1868-1882
// (erts_line_breakpoint_hit__cleanup), OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_line_breakpoint_cleanup(
    header: *mut ProcessHeader,
    reg: *mut u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(header, reg) else {
        return 0;
    };
    let mut live = 0usize;
    while let Some(value) = process.heap.stack_get(live) {
        if crate::native_bridge::is_native_continuation(value.tagged_word() as usize) {
            break;
        }
        let Some(destination) = registers.x_reg_array.get_mut(live) else {
            break;
        };
        *destination = value;
        live += 1;
    }
    live as u64
}

/// The function `call_light_bif_shared` branches to for this export.
///
/// Port of erts/emulator/beam/erl_bif_table.c (`bif_table[].f`), OTP-29.1.1: each BIF
/// has one function pointer, chosen when the export is created. Calls enter that pointer
/// directly; trace and save_calls dispatch it through the export path.
pub(crate) fn light_entry(export: ExportDispatch) -> Option<usize> {
    if let Some(func) = crate::bif_table::special(&export.module, &export.function, export.arity) {
        return Some(func);
    }
    // The kind is fixed when the export is created (`bif_table[].f`). The call
    // fragment branches to that pointer; it does not walk `invoke_dispatch_bif`.
    if export.light_process_bif.is_some() {
        return Some(
            crate::natives::thin_entry(&export.module, &export.function, export.arity)
                .unwrap_or(crate::bif_table::bif!(process_bif_light)),
        );
    }
    if export.direct_ets.is_some() {
        return Some(crate::bif_table::bif!(direct_bif_light));
    }
    if export.runs_in_executor() {
        return Some(crate::bif_table::bif!(yield_executor_bif));
    }
    if let Some(entry) = crate::bif_table::entry(&export.module, &export.function, export.arity) {
        return Some(entry.plain);
    }
    let bif = export.is_bif_export()
        || matches!(
            export.class,
            arinsal_loader::ImportClass::Pure
                | arinsal_loader::ImportClass::Native
                | arinsal_loader::ImportClass::Dynamic
                | arinsal_loader::ImportClass::Fun
                | arinsal_loader::ImportClass::Unsupported
        );
    if bif {
        Some(crate::bif_table::bif!(yield_executor_bif))
    } else {
        None
    }
}

/// A BIF the executor still owns. `THE_NON_VALUE` with the trap reason, so the
/// fragment context-switches. This is not [`invoke_dispatch_bif`].
pub(crate) extern "C" fn yield_executor_bif(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    i: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (descriptor, identity) = crate::bif_table::current_export(header);
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp (call_light_bif_shared passes the
    // call's entry address `I`), OTP-29.1.1: the export trampoline passes none.
    let light_call = i != 0;
    let Some(process) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    park_executor(process, export, identity, light_call)
}

/// `THE_NON_VALUE` + trap reason. The fragment context-switches into the executor.
fn park_executor(
    process: &mut crate::Process,
    export: ExportDispatch,
    identity: u64,
    light_call: bool,
) -> u64 {
    process.native_light_bif_call = light_call;
    process.heap.abi.arity = export.arity;
    process.heap.abi.i = identity as *const u8 as *const _;
    process.heap.abi.exc.freason = 1 << 10;
    0
}

/// `bif_table[].f` of one plain BIF: the body is this entry's own callee.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:434-445 (`dynamic_runtime_call<3>(ARG8)`
// calls `BIF(c_p, reg, I)` of that one BIF), OTP-29.1.1.
pub(crate) extern "C" fn plain_bif_entry<B: arinsal_bifs::BifBody>(
    header: *mut ProcessHeader,
    regs: *mut u64,
    instruction: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (descriptor, _) = crate::bif_table::current_export(header);
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(header, regs) else {
        return 0;
    };
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    call_plain_bif_word(process, registers, export, |process, args| {
        B::call_word(process, args, instruction as usize)
    })
}

/// A process BIF (`c_p` plus the register array), chosen when the export was created.
pub(crate) extern "C" fn process_bif_light(
    header: *mut ProcessHeader,
    regs: *mut u64,
    _i: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (descriptor, identity) = crate::bif_table::current_export(header);
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(header, regs) else {
        return 0;
    };
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    let Some(bif) = export.light_process_bif else {
        return park_executor(process, export, identity, false);
    };
    match call_process_bif(process, registers, export, bif, false) {
        Some(raw) => raw,
        // The entry declined before any side effect: the executor runs the whole BIF.
        None => park_executor(process, export, identity, false),
    }
}

/// A process BIF whose success path returns in registers: no `Result<Term, Trap>` is moved
/// unless the BIF fails, and the export is not read unless it does.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-471 (call_light_bif_shared), OTP-29.1.1:
// the BIF is called with `c_p` and the X registers, a value returns in x0 and `THE_NON_VALUE`
// is the error path.
pub(crate) extern "C" fn thin_bif_light<B: crate::natives::ThinProcessBif>(
    header: *mut ProcessHeader,
    regs: *mut u64,
    _i: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let descriptor = crate::bif_table::current_info(header);
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(header, regs) else {
        return 0;
    };
    match B::call(process, &registers.x_reg_array[..B::ARITY]) {
        Ok(value) => {
            registers.x_reg_array[0] = value;
            crate::native_hooks::raw(value)
        }
        Err(trap) => thin_bif_failed(process, registers, descriptor, *trap),
    }
}

/// A thin process BIF's exception, run through the same path as a [`ProcessBif`]'s.
#[cold]
#[inline(never)]
fn thin_bif_failed(
    process: &mut crate::Process,
    _registers: &mut arinsal_beamasm::SchedulerRegisters,
    descriptor: u64,
    trap: crate::exceptions::Trap,
) -> u64 {
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    process_bif_result(process, export, Err(trap))
}

/// An ETS or process-dictionary BIF whose body is `direct_ets`.
pub(crate) extern "C" fn direct_bif_light(
    header: *mut ProcessHeader,
    regs: *mut u64,
    _i: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (descriptor, identity) = crate::bif_table::current_export(header);
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(header, regs) else {
        return 0;
    };
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    if let Some(raw) = call_direct_bif(process, registers, export, false) {
        return raw;
    }
    process.heap.abi.arity = export.arity;
    process.heap.abi.i = identity as *const u8 as *const _;
    process.heap.abi.exc.freason = 1 << 10;
    0
}

// `export_call`: reached through an export entry, whose BIF trampoline charges the call one
// reduction (erts/emulator/beam/jit/arm/instr_bif.cpp:399, OTP-29.1.1); a light BIF call
// site has already charged it.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-471 (call_light_bif_shared), OTP-29.1.1:
// a plain BIF is called straight away; save_calls, tracing and the
// breakpoint and send identities branch off to the slow path.
#[inline(always)]
fn invoke_dispatch_bif(
    header: *mut ProcessHeader,
    reg: *mut u64,
    identity: usize,
    site: usize,
    export: Option<ExportDispatch>,
    export_call: bool,
) -> Option<u64> {
    let (process, registers) = crate::native_hooks::enter_runtime_reg(header, reg)?;
    if let Some(export) = export {
        if export_call {
            // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:729-745:
            // call_bif_shared stores the export's MFA in c_p->current before the BIF call.
            process.heap.abi.current = if export.is_bif_export() {
                std::ptr::from_ref(export.mfa()).cast()
            } else {
                std::ptr::null()
            };
        }
        // The light-BIF fragment already loaded `Export.is_bif_traced` and compared
        // `active_code_ix` (instr_bif.cpp:391-397). An export-entry call has not.
        // ETS and the process dictionary run here so a `call_ext` does not trap back
        // into the executor once per key.
        if export.direct_ets.is_some()
            && let Some(raw) = call_direct_bif(process, registers, export, export_call)
        {
            return Some(raw);
        }
    }
    if let Some(export) = export
        && let Some(bif) = export.light_process_bif
        && !(export_call
            && (registers.active_code_ix == crate::code_ix::ERTS_SAVE_CALLS_CODE_IX as u64
                || export.is_bif_traced()))
        // Port of erl_gc.c:987-990: an on-heap queue with signals still in the
        // outer queue is fetched before the collection. That fetch needs the
        // scheduler context, so this call leaves native code. An empty outer
        // queue stays on the light path.
        && !((bif as usize)
            == (crate::natives::sys::garbage_collect_bif as *const () as usize)
            && process.gc_outer_queue_pending())
        && let Some(raw) = call_process_bif(process, registers, export, bif, export_call)
    {
        return Some(raw);
    }
    invoke_dispatch_bif_slow(process, registers, identity, site, export, export_call)
}

/// Checks heap cursors and the pending trap arguments before a trap changes execution tiers.
pub(crate) fn debug_assert_native_heap(_process: &crate::Process) {
    #[cfg(debug_assertions)]
    {
        let (heap, end) = _process.heap.heap_bounds();
        let (htop, stop) = _process.heap.heap_cursor();
        let (heap, htop, stop, end) = (heap as usize, htop as usize, stop as usize, end as usize);
        debug_assert!(heap <= htop && htop <= stop && stop <= end);
        if let Some(pending) = _process
            .cold
            .as_deref()
            .and_then(|cold| cold.bif_trap.as_ref())
        {
            debug_assert!(pending.arity <= pending.args.len());
            for term in pending.args[..pending.arity].iter().copied() {
                arinsal_term::validate::check_if_active(&_process.heap, term);
            }
        }
    }
}

/// Runs the breakpoint of the traced function at `site` in native code when it only counts
/// calls and accounts call time or memory: the return frame is pushed and the call goes on.
// Port of erts/emulator/beam/jit/arm/instr_trace.cpp:62-95 (the trampoline fragment calls
// erts_generic_breakpoint and resumes), OTP-29.1.1.
fn native_breakpoint_accounted(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    site: usize,
) -> bool {
    let Some(pid) = process.self_pid else {
        return false;
    };
    let Some(hit) = crate::trace_bp::native_breakpoint_accounting(process, pid, site) else {
        return false;
    };
    let Some(action) = hit.action else {
        return true;
    };
    // The header holds the live reduction counter of the native code; publishing the header
    // below must not rewind it.
    // The frame may need a collection, whose roots are the function's arguments.
    if crate::trace::push_native_trace_frame(
        process,
        site,
        std::slice::from_ref(&action),
        &mut registers.x_reg_array[..usize::from(hit.arity)],
    )
    .is_err()
    {
        crate::native_hooks::set_error(process, "system_limit");
    }
    // A delayed collection moves the stack and its frame pointer chain.
    true
}

#[cold]
#[inline(never)]
fn invoke_dispatch_bif_slow(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    identity: usize,
    site: usize,
    export: Option<ExportDispatch>,
    export_call: bool,
) -> Option<u64> {
    if identity == arinsal_beamasm::dispatch::BREAKPOINT_DISPATCH_IDENTITY
        && !export_call
        && native_breakpoint_accounted(process, registers, site)
    {
        // Port of erts/emulator/beam/jit/arm/instr_trace.cpp:62-95 (call erts_generic_breakpoint
        // from the trampoline fragment), OTP-29.1.1: nothing to report, so the call goes on in
        // native code with every register as it was.
        return Some(0);
    }
    if identity == arinsal_beamasm::dispatch::BREAKPOINT_DISPATCH_IDENTITY {
        // The breakpoint traps like a BIF so the executor delivers its trace events.
        process.heap.abi.i = identity as *const u8 as *const _;
        process.heap.abi.exc.freason = 1 << 10;
        return None;
    }
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:388-397 (call_light_bif_shared), OTP-29.1.1:
    // a process saving calls dispatches a light BIF through its export, which records it.
    let saving_calls =
        !export_call && registers.active_code_ix == crate::code_ix::ERTS_SAVE_CALLS_CODE_IX as u64;
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-471 (call_light_bif_shared gets the
    // export and its BIF from the call site), OTP-29.1.1.
    let export = export?;
    if saving_calls {
        crate::trace::save_call(
            process,
            crate::trace::SavedCall::Mfa(export.module_atom, export.function_atom, export.arity),
        );
    }

    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-471 (call_light_bif), OTP-29.1.1:
    // the table BIFs run on the process heap straight from the generated code; anything the
    // direct path declines is redone through the scheduler. The hot helper already ran a
    // direct BIF that accepted the call.
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:391 (call_light_bif_shared),
    // OTP-29.1.1: `Export.is_bif_traced` is the only decision, read once; the export's
    // breakpoint (the executor, which has the trace context) matches the call itself.
    let bif_traced = export.is_bif_traced();
    if export.runs_in_executor() || bif_traced {
        // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:388-397
        // (call_light_bif_shared), OTP-29.1.1: a traced BIF branches to the
        // export breakpoint before the ordinary FCALL decrement.
        if export_call && !bif_traced {
            charge_bif_reductions(process, 1);
        }
        process.heap.abi.arity = export.arity;
        process.heap.abi.i = identity as *const u8 as *const _;
        process.heap.abi.exc.freason = 1 << 10;
        process.native_light_bif_call = !export_call;
        return None;
    }
    park_executor(process, export, identity as u64, !export_call);
    None
}

/// Runs an ETS or process-dictionary BIF from native code.
///
/// `None` means the direct body declined (or a trace pattern is active) and the
/// scheduler path must run the call.
fn call_direct_bif(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    export: ExportDispatch,
    export_call: bool,
) -> Option<u64> {
    let direct = export.direct_ets?;
    if export.is_bif_traced() {
        return None;
    }
    let arity = usize::from(export.arity).min(4);
    let args = [
        registers.x_reg_array[0],
        registers.x_reg_array[1],
        registers.x_reg_array[2],
        registers.x_reg_array[3],
    ];
    let value = direct(
        process,
        &args[..arity],
        export.module_atom,
        export.function_atom,
    )?;
    if export_call {
        charge_bif_reductions(process, 1);
    }
    // Port of erts/emulator/beam/bif.h (BIF_ERROR) and jit/arm/instr_bif.cpp
    // (call_light_bif_shared), OTP-29.1.1: a failed BIF returns THE_NON_VALUE with only
    // `freason`/`fvalue` set; the call is not redone. `handle_error` builds the top frame from
    // `bif_mfa` (`c_p->current`) and the arguments still in the X registers.
    if value.is_non_value() {
        process.heap.abi.current = std::ptr::from_ref(export.mfa()).cast();
        // Port of erl_gc.c (erts_gc_after_bif_call_lhf), OTP-29.1.1: the GC-desired test runs
        // before the result is looked at, so a failed BIF collects too, with its arguments live.
        if process.heap.gc_after_bif_desired() {
            direct_bif_error_gc(process, registers, usize::from(export.arity));
        }
        return Some(0);
    }
    registers.x_reg_array[0] = value;
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp (call_light_bif_shared) and
    // beam_jit_common.cpp (beam_jit_call_bif), OTP-29.1.1: the BIF only returns its result.
    // The one collection after it is the caller's `erts_gc_after_bif_call_lhf`, with the
    // result as its root: the light fragment's test, or the export trampoline's
    // `gc_after_bif_call`.
    Some(crate::native_hooks::raw(value))
}

/// Collects after a direct BIF that failed: the argument registers and the failure words are
/// the roots. A failed collection replaces the failure with `system_limit`.
// Port of erts/emulator/beam/erl_gc.c (erts_gc_after_bif_call_lhf, with `c_p->fvalue` and
// `c_p->ftrace` as process roots), OTP-29.1.1.
#[cold]
#[inline(never)]
fn direct_bif_error_gc(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    arity: usize,
) {
    let ftrace = process.heap.abi.exc.ftrace;
    let mut roots = [
        crate::native_hooks::from_raw(process.heap.abi.exc.fvalue),
        if ftrace == 0 {
            Term::NIL
        } else {
            crate::native_hooks::from_raw(ftrace)
        },
    ];
    match process.collect_heap_roots_objv(&mut registers.x_reg_array[..arity], &mut roots, 0) {
        Ok(stats) => {
            process.heap.abi.exc.fvalue = crate::native_hooks::raw(roots[0]);
            if ftrace != 0 {
                process.heap.abi.exc.ftrace = crate::native_hooks::raw(roots[1]);
            }
            crate::natives::sys::after_collection(
                process,
                stats.collections,
                stats.words_reclaimed,
            );
            process.charge_gc_stats(&stats);
        }
        Err(_) => {
            process.heap.abi.exc.ftrace = 0;
            crate::native_hooks::set_error(process, "system_limit");
        }
    }
}

/// Everything after a light BIF that did not just return a value: a continuation the body
/// deferred, an error, or a collection that is due. Out of line so the value path keeps few
/// live registers, as erts keeps these cases in the shared fragment behind one
/// `THE_NON_VALUE` test.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-523 (call_light_bif_shared error and
// trap tails), OTP-29.1.1.
#[cold]
#[inline(never)]
fn plain_bif_slow(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    export: ExportDispatch,
    result: Result<Term, arinsal_bifs::BifError>,
) -> u64 {
    let arity = usize::from(export.arity);
    plain_bif_result(process, registers, export, arity, result)
}

/// The table adapter for a BIF function that returns one word, a term or the non-value with
/// its failure in the context. The word is the value path's whole result, so
/// it is tested once; failures and deferred continuations take [`plain_bif_slow`].
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-523 (call_light_bif_shared tests the
// returned word against THE_NON_VALUE), OTP-29.1.1.
#[inline(always)]
fn call_plain_bif_word(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    export: ExportDispatch,
    bif: impl Fn(&mut arinsal_bifs::Ctx<'_>, &[Term]) -> u64,
) -> u64 {
    let arity = usize::from(export.arity);
    let mut fragment = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let mut call = arinsal_bifs::BifCall::default();
    let mut ctx = arinsal_bifs::Ctx::with_failure(&mut fragment, &mut call);
    let word = bif(&mut ctx, &registers.x_reg_array[..arity]);
    if word != arinsal_term::THE_NON_VALUE {
        return word;
    }
    let error = ctx.take_error();
    plain_bif_word_slow(process, registers, export, word, error)
}

/// The tail of [`call_plain_bif_word`] for a failure, a trap or a due collection, out of line
/// like [`plain_bif_slow`].
#[cold]
#[inline(never)]
fn plain_bif_word_slow(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    export: ExportDispatch,
    word: u64,
    error: Option<arinsal_bifs::BifError>,
) -> u64 {
    // A migrated body left its failure in the process' exit words; an adapted `Result` body
    // left it in the context. Decoding clears the words, which are rewritten below.
    let error = if word == arinsal_term::THE_NON_VALUE {
        error.or_else(|| decode_failure(&mut process.heap.abi.exc))
    } else {
        error
    };
    let result = if word == arinsal_term::THE_NON_VALUE {
        Err(error.unwrap_or(arinsal_bifs::BifError::BADARG))
    } else {
        Ok(crate::native_hooks::from_raw(word))
    };
    plain_bif_slow(process, registers, export, result)
}

/// The `BifError` a word-returning body left in the process' failure words, which are then
/// cleared. `None` when no failure is recorded or it is a `TRAP`.
// Inverse of `arinsal_bifs`'s `encode_failure`; port of the class and index decoding of
// erts/emulator/beam/error.h (GET_EXC_CLASS, GET_EXC_INDEX), OTP-29.1.1.
pub(crate) fn decode_failure(
    exc: &mut arinsal_term::exc::ExcFields,
) -> Option<arinsal_bifs::BifError> {
    use arinsal_bifs::BifError;
    use arinsal_term::exc::{EXF_ARGLIST, EXF_HAS_EXT_INFO, TRAP, exc_index};
    let freason = std::mem::take(&mut exc.freason);
    if freason == 0 {
        return None;
    }
    let (fvalue, ftrace) = (
        crate::native_hooks::from_raw(exc.fvalue),
        crate::native_hooks::from_raw(std::mem::take(&mut exc.ftrace)),
    );
    if freason == TRAP {
        let class = match ftrace.word() {
            1 => arinsal_bifs::SchedulerClass::Normal,
            2 => arinsal_bifs::SchedulerClass::DirtyCpu,
            3 => arinsal_bifs::SchedulerClass::DirtyIo,
            _ => return None,
        };
        return Some(BifError::Dirty(class));
    }
    let class = crate::stacktrace::class_from_freason(freason)?;
    // beam_common.c handle_error: EXF_ARGLIST (set only by error/2,3) carries
    // `{Reason, Args[, ErrorInfo]}` in fvalue; the reason is its first element and the
    // caller's frame takes Args (the executor reads them from the BIF arguments).
    let fvalue = if freason & EXF_ARGLIST != 0
        && let Ok(tuple) = arinsal_term::raw::Tuple::try_from(fvalue)
        && tuple.arity()
            == if freason & EXF_HAS_EXT_INFO != 0 {
                3
            } else {
                2
            } {
        if freason & EXF_HAS_EXT_INFO != 0
            && let Some(info) = tuple.get(2)
        {
            exc.fvalue = crate::native_hooks::raw(info);
        }
        tuple.get(0)?
    } else {
        fvalue
    };
    Some(match exc_index(freason) {
        3 => BifError::Badarg {
            cause: (freason & EXF_HAS_EXT_INFO != 0).then_some(ftrace),
        },
        4 => BifError::Badarith,
        15 => BifError::SystemLimit,
        9 => BifError::Unsupported("undef"),
        0 if freason & EXF_ARGLIST != 0 || !ftrace.is_non_value() => BifError::Raise {
            class,
            reason: fvalue,
            stacktrace: (!ftrace.is_non_value()).then_some(ftrace),
        },
        0 if class != arinsal_bifs::Class::Error => BifError::Raise {
            class,
            reason: fvalue,
            stacktrace: None,
        },
        0 => BifError::Error(fvalue),
        _ => BifError::BADARG,
    })
}

/// Calls a BIF that needs its process (`c_p`) straight from native code.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-471 (call_light_bif_shared), OTP-29.1.1:
// the BIF gets `c_p` and reads its arguments from the register array; its result is handled
// like any light BIF's.
#[inline(always)]
fn call_process_bif(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    export: ExportDispatch,
    bif: crate::natives::ProcessBif,
    export_call: bool,
) -> Option<u64> {
    if export_call {
        charge_bif_reductions(process, 1);
    }
    let arity = usize::from(export.arity);
    // `garbage_collect` moves the heap. The light fragment reloads heap bounds from the
    // process header on the way out (`RUNTIME_UPDATE`).
    let collects =
        (bif as usize) == (crate::natives::sys::garbage_collect_bif as *const () as usize);
    let result = bif(process, &registers.x_reg_array[..arity])?;
    if collects {
        // The heap block moved. Heap indices from before the call belong to the
        // old block, so the post-BIF free-space check does not apply.
        return Some(match result {
            Ok(value) => {
                registers.x_reg_array[0] = value;
                crate::native_hooks::raw(value)
            }
            Err(error) => process_bif_result(process, export, Err(error)),
        });
    }
    // The light fragment tests the collection after its call (instr_bif.cpp:488-523).
    if let Ok(value) = &result
        && (!export_call
            || (process.heap.stack_index() - process.heap.heap_top_index()
                >= process.heap.mbuf_size()
                && !process.heap.bin_vheap_gc_due()))
    {
        let value = *value;
        registers.x_reg_array[0] = value;
        return Some(crate::native_hooks::raw(value));
    }
    Some(process_bif_result(process, export, result))
}

/// A process BIF's exception, or a value after which a collection is desired.
// Port of erts/emulator/beam/erl_gc.c:418-478 (erts_gc_after_bif_call_lhf), OTP-29.1.1: the
// argument registers stay live across the collection.
#[cold]
#[inline(never)]
fn process_bif_result(
    process: &mut crate::Process,
    export: ExportDispatch,
    result: Result<Term, crate::exceptions::Trap>,
) -> u64 {
    // The collection after the BIF is the caller's (erts_gc_after_bif_call_lhf in the call
    // fragment, beam_jit_call_bif, or the executor's call site), not this epilogue's.
    match result {
        // The call fragment stores the value in x0.
        Ok(value) => crate::native_hooks::raw(value),
        Err(trap) => process_bif_error(process, export, trap),
    }
}

/// `BIF_TRAP*` to an Erlang export: THE_NON_VALUE with `TRAP`; the fragment context-switches
/// to `beam_bif_export_trap`.
// Port of erts/emulator/beam/bif.h:316-326 (BIF_TRAP*) and
// jit/arm/beam_asm_global.cpp:145-155 (emit_bif_export_trap), OTP-29.1.1.
fn bif_trap_export(
    process: &mut crate::Process,
    export: ExportDispatch,
    export_trap: crate::ExportTrap,
    identity: usize,
) -> u64 {
    // erl_gc.c:430-436 (erts_gc_after_bif_call_lhf): the first trap with F_DISABLE_GC saves
    // live_hf_end. The fragment tests GC only after a value, so the trap epilogue does it.
    if !process.heap.gc_enabled {
        process.heap.save_live_frags_mark();
    }
    // BIF_TRAP's arguments replace the BIF arguments in X0 onwards and set `c_p->arity`: they
    // are the live roots of the collection the caller runs after the BIF.
    // `install_export_trap` writes them to the registers.
    let arity = export_trap.args.len();
    process.gc_live = arity;
    process.heap.abi.arity = arity as u8;
    crate::bif_traps::install_export_trap(
        process,
        identity,
        (export.module_atom, export.function_atom),
        &export_trap,
        true,
    );
    crate::bif_traps::arm_export_trap(process);
    process.heap.abi.exc.freason = 1 << 10;
    0
}

/// The shared BIF epilogue for a BIF body that reports its result as `Result<Term, VmError>`:
/// a value, `BIF_ERROR`, or `BIF_TRAP*` complete here, in native code, as erts'
/// `call_light_bif_shared` / `call_bif_shared` complete them; GC after the BIF is the call
/// site's (`erts_gc_after_bif_call_lhf` with `reg`). An outcome only the scheduler completes (ERTS_BIF_YIELD, a dirty
/// BIF on a normal scheduler, hibernation, a VM failure) is THE_NON_VALUE with
/// `TRAP` to the call itself; the scheduler takes the stored outcome instead of calling the
/// BIF again.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-536 (call_light_bif_shared,
// emit_bif_nif_epilogue) and bif.h (BIF_ERROR, BIF_TRAP*, ERTS_BIF_YIELD*), OTP-29.1.1.
pub(crate) fn bif_return(
    process: &mut crate::Process,
    export: ExportDispatch,
    identity: u64,
    light_call: bool,
    result: Result<Term, crate::VmError>,
) -> u64 {
    let result = match result {
        Ok(value) => Ok(value),
        Err(crate::VmError::Trap(trap)) => Err(trap),
        Err(crate::VmError::TrapExport(trap)) => {
            return bif_trap_export(process, export, trap, identity as usize);
        }
        Err(crate::VmError::Exception { reason, frame }) => {
            let reg: &[Term] =
                crate::process::sched_data::sched_registers(process).map_or(&[], |reg| &*reg);
            match crate::process::legacy_exception_trap(process, reg, &reason, &frame) {
                Ok(trap) => Err(trap),
                Err(error) => {
                    return bif_scheduler_outcome(process, export, identity, light_call, error);
                }
            }
        }
        Err(error) => return bif_scheduler_outcome(process, export, identity, light_call, error),
    };
    process_bif_result(process, export, result)
}

/// [`bif_return`] of a `bif_table[].f` body's failure: `BIF_ERROR`, `BIF_TRAP*` or an outcome
/// the scheduler completes. The export is the one the call fragment named in `c_p->current`.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-536 (call_light_bif_shared: the
// THE_NON_VALUE arm, `c_p->current` = `&exp->info.mfa`), OTP-29.1.1.
#[cold]
#[inline(never)]
pub(crate) fn bif_return_current(header: *mut ProcessHeader, i: u64, error: crate::VmError) -> u64 {
    let (descriptor, identity) = crate::bif_table::current_export(header);
    let Some(process) = crate::native_hooks::process_from_header(header) else {
        return 0;
    };
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    bif_return(process, export, identity, i != 0, Err(error))
}

/// An outcome of a BIF called from native code that the scheduler completes.
#[cold]
#[inline(never)]
fn bif_scheduler_outcome(
    process: &mut crate::Process,
    export: ExportDispatch,
    identity: u64,
    light_call: bool,
    error: crate::VmError,
) -> u64 {
    process.cold_mut().bif_outcome = Some(Box::new(error));
    park_executor(process, export, identity, light_call)
}

/// A BIF body that runs with its scheduler's data: the executor's VM view and the slice
/// context, reached through the process as erts reaches `esdp` (`erts_proc_sched_data`).
pub(crate) trait SchedBif {
    /// Arguments in X0 onwards.
    const ARITY: usize;
    /// The body.
    const BODY: crate::natives::DirectNative;
}

/// `bif_table[].f` of a [`SchedBif`]: called by `call_light_bif_shared` and the export
/// trampoline's `call_bif` with `c_p` and the X registers; the result goes through
/// [`bif_return`].
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-471 (call_light_bif_shared) and
// 729-776 (call_bif_shared), OTP-29.1.1.
pub(crate) extern "C" fn sched_bif_light<B: SchedBif>(
    header: *mut ProcessHeader,
    regs: *mut u64,
    i: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (descriptor, identity) = crate::bif_table::current_export(header);
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(header, regs) else {
        return 0;
    };
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    // The light fragment passes the call's entry address `I`; the export trampoline none.
    let light_call = i != 0;
    let mut args = [Term::NIL; 4];
    args[..B::ARITY].copy_from_slice(&registers.x_reg_array[..B::ARITY]);
    process.gc_live = B::ARITY;
    // The call site a raising or suspending BIF names (`c_p->i` at the call).
    process.native_call_pc = registers.tmp_mem[6] as usize;
    let result = crate::process::sched_data::with_sched_data(process, |vm, process, ctx| {
        // The executor's VM view follows the active code index before a BIF reads it
        // (function_exported/3, module_loaded/1, ...).
        vm.refresh_code();
        (B::BODY)(vm, process, ctx, &args[..B::ARITY])
    })
    .expect("native code runs inside an executor slice, which publishes its scheduler data");
    process.native_call_pc = 0;
    bif_return(process, export, identity, light_call, result)
}

/// `BIF_ERROR` of a process BIF: `bif_mfa` is the BIF; its arguments stay in the X registers.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:729-745 (call_bif_shared stores the MFA in
// `c_p->current`), OTP-29.1.1.
fn process_bif_error(
    process: &mut crate::Process,
    export: ExportDispatch,
    trap: crate::exceptions::Trap,
) -> u64 {
    let mut export = export;
    // ERTS_BIF_PREP_ERROR_TRAPPED1/2/3(p, reason, bif, args...): a continuation's error names
    // the original BIF: `c_p->current = &bif->info.mfa` and the arguments go back to X0...
    if let Some(crate::stacktrace::TopFrame::Bif {
        module,
        function,
        args,
        ..
    }) = &trap.top
        && let Some(terms) = args.inline_terms()
        && (*module, *function, terms.len())
            != (
                export.module_atom,
                export.function_atom,
                usize::from(export.arity),
            )
    {
        let atoms = arinsal_term::global_atoms();
        if let (Some(m), Some(f)) = (atoms.text(*module), atoms.text(*function))
            && let Some(bif) = crate::beamasm_integration::bif_mfa_export(m, f, terms.len() as u8)
        {
            if let Some(reg) = crate::process::sched_data::sched_registers(process) {
                reg[..terms.len()].copy_from_slice(terms);
            }
            export = bif;
        }
    }
    process.heap.abi.current = std::ptr::from_ref(export.mfa()).cast();
    bif_error(process, trap)
}

/// `BIF_ERROR` from a native BIF body: writes only `freason`, `fvalue` and `ftrace` and
/// returns THE_NON_VALUE. `handle_error` → `save_stacktrace` builds the top frame from
/// `bif_mfa` (`c_p->current`) and the argument registers; an `error_info` cause travels in
/// `fvalue` with `EXF_HAS_EXT_INFO`. An exception the process cannot catch (an exit signal
/// to itself) kills its catches first.
// Port of erts/emulator/beam/bif.h (BIF_ERROR, ERTS_BIF_EXITED: KILL_CATCHES), bif.c
// (raise_3: `c_p->ftrace`) and beam_common.c (save_stacktrace, EXF_HAS_EXT_INFO), OTP-29.1.1.
pub(crate) fn bif_error(process: &mut crate::Process, trap: crate::exceptions::Trap) -> u64 {
    use crate::stacktrace::{BifErrorInfo, TopFrame};
    if trap.untrappable {
        // `KILL_CATCHES(p)`: `handle_error` finds no catch, on either resolver.
        process.heap.abi.catches = 0;
    }
    let (freason, fvalue, ftrace) = match (&trap.top, trap.trace) {
        (
            Some(
                TopFrame::Bif {
                    info: BifErrorInfo::Cause(cause) | BifErrorInfo::Map(cause),
                    ..
                }
                | TopFrame::BifRegisters {
                    info: BifErrorInfo::Cause(cause) | BifErrorInfo::Map(cause),
                    ..
                },
            ),
            _,
        ) => (
            arinsal_beamasm::exc::EXC_BADARG | arinsal_beamasm::exc::EXF_HAS_EXT_INFO,
            *cause,
            0,
        ),
        (_, Some(trace)) => (
            crate::stacktrace::class_to_freason(Some(trap.class)),
            trap.reason,
            crate::native_hooks::raw(trace),
        ),
        (_, None) => (
            crate::stacktrace::class_to_freason(Some(trap.class)),
            trap.reason,
            0,
        ),
    };
    process.heap.abi.exc.freason = freason;
    process.heap.abi.exc.fvalue = crate::native_hooks::raw(fvalue);
    process.heap.abi.exc.ftrace = ftrace;
    0
}

/// An error, or a value after which a collection is desired.
#[cold]
#[inline(never)]
fn plain_bif_result(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    export: ExportDispatch,
    arity: usize,
    mut result: Result<Term, arinsal_bifs::BifError>,
) -> u64 {
    let collected = process.heap.gc_after_bif_desired();
    if collected && !gc_after_plain_bif(process, &mut registers.x_reg_array[..arity], &mut result) {
        return 0;
    }
    match result {
        Ok(value) => {
            let value = crate::native_hooks::raw(value);
            // Port of erts/emulator/beam/jit/arm/instr_bif.cpp (call_light_bif,
            // ERTS_IS_GC_AFTER_BIF_DESIRED), OTP-29.1.1: one test, so at most one collection.
            registers.x_reg_array[0] = crate::native_hooks::from_raw(value);
            value
        }
        Err(error) => plain_bif_error(process, registers, export, error),
    }
}

/// The light-BIF fragment's collection, run when its inline GC-desired test fails.
/// `value` is the BIF's result term; `descriptor` is the export's `Export.info`.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:549-570 (gc_after_bif_call) and
// erl_gc.c:418-478 (erts_gc_after_bif_call_lhf), OTP-29.1.1: the result is the only root
// and the collection keeps the BIF's arguments live.
#[cold]
#[inline(never)]
pub(crate) extern "C" fn arinsal_beamasm_light_bif_gc(
    header: *mut ProcessHeader,
    regs: *mut u64,
    value: u64,
    descriptor: u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime_after_bif(header, regs)
    else {
        return 0;
    };
    // The BIF's charge is in FCALLS; the sync below writes `reductions` back to it.
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    gc_after_bif_call(process, registers, export, value)
}

/// `erts_gc_after_bif_call_lhf(c_p, live_hf_end, result, reg, arity)`: the result (a term or
/// the non-value) after the BIF of `export`, collected with `reg` as the roots.
// Port of erts/emulator/beam/erl_gc.c:418-478 (erts_gc_after_bif_call_lhf), OTP-29.1.1.
fn gc_after_bif_call(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    export: ExportDispatch,
    value: u64,
) -> u64 {
    // erl_gc.c:428-445 (erts_gc_after_bif_call_lhf): with F_DISABLE_GC the result is returned
    // without a collection.
    if !process.heap.gc_enabled {
        if value != arinsal_term::THE_NON_VALUE {
            registers.x_reg_array[0] = crate::native_hooks::from_raw(value);
        }
        return value;
    }
    let arity = usize::from(export.arity);
    if value == arinsal_term::THE_NON_VALUE {
        return gc_after_failed_bif(process, registers, arity);
    }
    plain_bif_result(
        process,
        registers,
        export,
        arity,
        Ok(crate::native_hooks::from_raw(value)),
    )
}

/// `erts_gc_after_bif_call_lhf` for a BIF that returned the non-value: the exception (or
/// trap) stays in `freason`/`fvalue`/`ftrace`, which the collection roots, and the live X
/// registers are the BIF's arguments (`arity`), or `c_p->arity` after a BIF_TRAP.
// Port of erts/emulator/beam/erl_gc.c:454-459 (erts_gc_after_bif_call_lhf), OTP-29.1.1.
#[cold]
#[inline(never)]
fn gc_after_failed_bif(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    arity: usize,
) -> u64 {
    let live = if process.heap.abi.exc.freason == arinsal_term::exc::TRAP {
        usize::from(process.heap.abi.arity)
    } else {
        arity
    };
    match process.collect_heap_roots_objv(&mut registers.x_reg_array[..live], &mut [], 0) {
        Ok(stats) => {
            crate::natives::sys::after_collection(
                process,
                stats.collections,
                stats.words_reclaimed,
            );
            process.charge_gc_stats(&stats);
        }
        Err(_) => crate::native_hooks::set_error(process, "system_limit"),
    }
    arinsal_term::THE_NON_VALUE
}

/// Collects after a BIF whose heap fragments outgrew the free heap; false when the
/// collection failed and the call raised.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:549-570 (gc_after_bif_call), OTP-29.1.1:
// erts_gc_after_bif_call_lhf keeps the argument registers live and moves them in `reg`.
#[cold]
#[inline(never)]
fn gc_after_plain_bif(
    process: &mut crate::Process,
    reg: &mut [Term],
    result: &mut Result<Term, arinsal_bifs::BifError>,
) -> bool {
    let collected = crate::calls::gc_after_bif(process, reg, result);
    if collected.is_err() {
        crate::native_hooks::set_error(process, "system_limit");
        return false;
    }
    true
}

#[cold]
#[inline(never)]
fn plain_bif_error(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    export: ExportDispatch,
    error: arinsal_bifs::BifError,
) -> u64 {
    let args = registers.x_reg_array[..usize::from(export.arity)].to_vec();
    set_native_bif_export_error(process, export, &args, error);
    0
}

/// Charges the reductions a BIF reported against FCALLS, which the call site reloads.
// Port of erts/emulator/beam/bif.h (BUMP_REDS), OTP-29.1.1.
fn charge_bif_reductions(process: &mut crate::Process, reductions: u32) {
    process.heap.abi.fcalls = process
        .heap
        .abi
        .fcalls
        .saturating_sub(reductions.min(i32::MAX as u32) as i32);
}

/// Raises `error:{Tag, Value}` from a native helper.
fn set_tagged_error(process: &mut crate::Process, tag: &str, value: Term) {
    let tuple = arinsal_term::TermBuilder::new(&mut crate::ProcessHeapHandle(&mut process.heap))
        .tuple(&[crate::atom_cache::put(tag), value]);
    match tuple {
        Ok(reason) => {
            process.heap.abi.exc.freason = arinsal_beamasm::exc::EXC_ERROR;
            process.heap.abi.exc.fvalue = crate::native_hooks::raw(reason);
        }
        Err(_) => crate::native_hooks::set_error(process, "system_limit"),
    }
}

/// Store a bit-syntax error and its extended map in the process failure words.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp:911-1010 (`beam_jit_bs_construct_fail_info`), OTP-29.1.1.
pub(crate) fn set_native_error_info(
    process: &mut crate::Process,
    reason: &str,
    info: Option<Box<arinsal_etf::OwnedTerm>>,
) {
    process.heap.abi.exc.freason = match reason {
        "badarg" => arinsal_beamasm::exc::EXC_BADARG,
        "system_limit" => arinsal_beamasm::exc::EXC_SYSTEM_LIMIT,
        _ => arinsal_beamasm::exc::EXC_ERROR,
    };
    let Some(info) = info else {
        process.heap.abi.exc.fvalue = crate::native_hooks::raw(crate::atom_cache::put(reason));
        return;
    };
    let Ok(info) = arinsal_term::from_owned(
        &info,
        &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
    ) else {
        crate::native_hooks::set_error(process, "system_limit");
        return;
    };
    process.heap.abi.exc.freason |= arinsal_beamasm::exc::EXF_HAS_EXT_INFO;
    process.heap.abi.exc.fvalue = crate::native_hooks::raw(info);
}

/// Raises `{badfun,Fun}` or `{badarity,{Fun,Args}}` for a native fun call.
// Port of erts/emulator/beam/beam_common.c:750-770 (expand_error_value) and
// erts/emulator/beam/jit/arm/instr_fun.cpp:84-100, OTP-29.1.1.
fn set_call_fun_error(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    fun: Term,
    arity: u32,
) {
    let arity = arity as usize;
    if arity >= crate::proc_create::ATTACHED_X_REGS {
        crate::native_hooks::set_error(process, "system_limit");
        return;
    }
    // `apply/2` may pass more arguments than the module's registers (erts raises badarity with
    // all of them): the scheduler array holds them.
    registers.x_reg_array[arity] = fun;
    match crate::funs::call_error_reason(process, &mut registers.x_reg_array, fun, arity) {
        Ok(reason) => {
            process.heap.abi.exc.freason = arinsal_beamasm::exc::EXC_ERROR;
            process.heap.abi.exc.fvalue = crate::native_hooks::raw(reason);
        }
        Err(_) => crate::native_hooks::set_error(process, "system_limit"),
    }
}

/// Records a native BIF failure so the scheduler raises it with the BIF as the top frame.
pub(crate) fn set_native_bif_error(
    process: &mut crate::Process,
    bif_mfa: usize,
    args: &[Term],
    error: arinsal_bifs::BifError,
) {
    set_light_bif_error(process, &error);
    set_native_bif_context(process, bif_mfa, args);
}

/// Records a BIF failure whose arguments are in the live scheduler registers.
// Port of erts/emulator/beam/jit/arm/instr_arith.cpp, OTP-29.1.1.
pub(crate) fn set_native_bif_register_error(
    process: &mut crate::Process,
    bif_mfa: usize,
    error: arinsal_bifs::BifError,
) {
    set_light_bif_error(process, &error);
    set_native_bif_context(process, bif_mfa, &[]);
}

/// Leaves the failing export's MFA and argument registers for `handle_error`.
fn set_native_bif_export_error(
    process: &mut crate::Process,
    export: ExportDispatch,
    args: &[Term],
    error: arinsal_bifs::BifError,
) {
    set_light_bif_error(process, &error);
    // A `raise/3` with an immediate stacktrace is complete in `freason`, `fvalue` and `ftrace`,
    // as in erts: no record of the failing call is kept for it.
    if process.heap.abi.exc.freason
        & (arinsal_beamasm::exc::EXF_ARGLIST | arinsal_beamasm::exc::EXF_HAS_EXT_INFO)
        == 0
        && process.heap.abi.exc.ftrace != 0
    {
        return;
    }
    set_native_bif_context(process, std::ptr::from_ref(export.mfa()) as usize, args);
}

fn set_native_bif_context(process: &mut crate::Process, bif_mfa: usize, args: &[Term]) {
    if bif_mfa != 0 {
        process.heap.abi.current = bif_mfa as *const std::ffi::c_void;
    }
    if let Some(reg) = crate::process::sched_data::sched_registers(process) {
        let count = args.len().min(reg.len());
        reg[..count].copy_from_slice(&args[..count]);
    }
}

fn set_light_bif_error(process: &mut crate::Process, error: &arinsal_bifs::BifError) {
    use arinsal_beamasm::exc;
    use arinsal_bifs::BifError;
    // `fvalue` also carries the reason for the coded failures: erts rebuilds it from the
    // code, and the stacktrace saver matches the pending BIF frame by the pair.
    // Deviation: `Unsupported` raises `undef` (`EXC_UNDEF`) and `Dirty`, which NIF bodies
    // turn into a trap to the dirty export before reaching here, is `EXC_NOTSUP`.
    let (freason, reason, ftrace) = match error {
        BifError::Badarg { cause } => (
            exc::EXC_BADARG
                | if cause.is_some() {
                    exc::EXF_HAS_EXT_INFO
                } else {
                    0
                },
            cause.unwrap_or_else(|| Term::atom(arinsal_term::atoms::BADARG)),
            0,
        ),
        BifError::Badarith => (
            exc::EXC_BADARITH,
            Term::atom(arinsal_term::atoms::BADARITH),
            0,
        ),
        BifError::SystemLimit => (
            exc::EXC_SYSTEM_LIMIT,
            Term::atom(arinsal_term::atoms::SYSTEM_LIMIT),
            0,
        ),
        BifError::Error(reason) => (exc::EXC_ERROR, *reason, 0),
        BifError::Raise {
            class,
            reason,
            stacktrace,
        } => (
            crate::stacktrace::class_to_freason(Some(*class))
                | if stacktrace.is_none() {
                    exc::EXF_ARGLIST
                } else {
                    0
                },
            *reason,
            stacktrace.map_or(0, Term::word),
        ),
        BifError::Unsupported(_) => (exc::EXC_UNDEF, Term::atom(arinsal_term::atoms::UNDEF), 0),
        BifError::Dirty(_) => (exc::EXC_NOTSUP, Term::atom(arinsal_term::atoms::NOTSUP), 0),
        BifError::DirtyTrap => unreachable!("dirty BIF trap is handled by process apply"),
    };
    process.heap.abi.exc.freason = freason;
    process.heap.abi.exc.fvalue = crate::native_hooks::raw(reason);
    process.heap.abi.exc.ftrace = ftrace;
}

/// The `raise/3` list for this failure, copied back onto the heap.
///
/// Port of erts/emulator/beam/bif.c:1643 (`c_p->ftrace = stacktrace` when the
/// list is already a stacktrace), OTP-29.1.1. The catch's `build_stacktrace`
/// then returns that list instead of walking native frames.
fn take_explicit_raise(process: &mut crate::Process) -> Option<Term> {
    if process.heap.abi.exc.freason
        & (arinsal_beamasm::exc::EXF_ARGLIST | arinsal_beamasm::exc::EXF_HAS_EXT_INFO)
        == 0
        && process.heap.abi.exc.ftrace != 0
    {
        let trace = crate::native_hooks::from_raw(process.heap.abi.exc.ftrace);
        process.heap.abi.exc.ftrace = 0;
        return Some(trace);
    }
    None
}

/// Resolves a native exception to the innermost catch handler, or 0 to let the scheduler exit.
///
/// Port of erts/emulator/beam/beam_common.c:449 (`handle_error`) and
/// jit/arm/beam_asm_global.cpp:300 (`raise_exception_shared`), OTP-29.1.1.
/// A caught error stays in native code: save a raw stacktrace, scan for the catch
/// tag, and return the handler. The symbolic list is built later, only if the
/// handler executes `build_stacktrace`.
pub extern "C" fn arinsal_beamasm_exception_resolver(
    header: *mut ProcessHeader,
    reg: *mut arinsal_beamasm::SchedulerRegisters,
    _stack: *mut u64,
    bif_info: u64,
) -> usize {
    let Some(process) = crate::native_hooks::process_from_header(header) else {
        return 0;
    };
    let freason = process.heap.abi.exc.freason;
    let error_arglist = is_error_arglist(process, bif_info, freason);
    let Some(class) = native_exception_class(freason, error_arglist) else {
        return 0;
    };
    // `handle_error` removes error/2,3's encoded argument tuple before saving the trace.
    // The live BIF registers remain the roots for Args while fvalue carries error_info.
    let arglist = if error_arglist {
        let Some(arglist) = unpack_error_arglist(process, freason) else {
            return 0;
        };
        Some(arglist)
    } else {
        None
    };
    // Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp:300-318 (`raise_exception_shared`),
    // OTP-29.1.1. The shared fragment already ran `emit_enter_runtime` and stored HTOP and E
    // into `c_p`. `handle_error` runs once from that entry; it does not enter again.
    // The heap indexes are those stored cursors (`c_p->htop`, `c_p->stop`).
    // `handle_error(c_p, pc, reg, bif_mfa)`: the BIF arguments are read from the register array
    // the fragment passed, the one the failing BIF or instruction was called with.
    let Some((process, registers)) = crate::native_hooks::scheduler_registers_at(process, reg)
    else {
        return 0;
    };
    // Port of erts/emulator/beam/beam_common.c:449-570 (`handle_error`), OTP-29.1.1, in its
    // order: save the trace when EXF_SAVETRACE is set, expand the value, write the catch
    // registers, `next_catch`.
    let trace = if freason & arinsal_beamasm::exc::EXF_SAVETRACE == 0 {
        // `raw_raise` already stored the saved trace and cleared EXF_SAVETRACE.
        crate::native_hooks::from_raw(process.heap.abi.exc.ftrace)
    } else if let Some(explicit) = take_explicit_raise(process) {
        // `erlang:raise/3` already built the list the catch must see (`bif.c:1643`).
        // A native walk would name `eval_external_handler` instead of that list.
        if explicit == Term::NIL {
            // `raise(Class, Reason, [])`, which is what `throw/1` compiles to: the empty
            // trace of that class, with nothing saved.
            crate::exceptions::empty_trace_handle(class)
        } else if let Ok(trace) = crate::stacktrace::save_explicit(process, class, explicit, 8) {
            trace
        } else {
            return 0;
        }
    } else {
        // The light-BIF fragment and `error_label` spill the raising pc at `tmp_mem[6]`
        // (erts' `pc` argument to `save_stacktrace`). `p.ip()` is the last interpreter
        // instruction and names the wrong function while native code is running. The raw
        // pc is resolved against the code ranges only if the trace is ever built.
        let raising_pc = registers.tmp_mem[6] as usize;
        let top = native_bif_top(process, bif_info, &registers.x_reg_array);
        let input = crate::stacktrace::StackTraceSave {
            class,
            depth: crate::stacktrace::runtime_backtrace_depth(process, 8),
            freason,
            native_pc: (raising_pc != 0).then_some(raising_pc),
            top: top.as_ref().map(crate::stacktrace::SaveTop::Live),
        };
        let Ok(trace) = crate::stacktrace::save_stacktrace(process, input, &registers.x_reg_array)
        else {
            return 0;
        };
        trace
    };
    // `save_stacktrace` leaves the trace in `c_p->ftrace`, a root while the value expands.
    process.heap.abi.exc.ftrace = crate::native_hooks::raw(trace);
    // Port of beam_common.c:742 (`expand_error_value`): only an indexed reason or an
    // `error_info` value needs expanding; the rest is `fvalue` itself.
    let reason = if let Some((reason, _args)) = arglist {
        reason
    } else if freason
        & (arinsal_beamasm::exc::EXC_INDEXBITS | arinsal_beamasm::exc::EXF_HAS_EXT_INFO)
        == 0
    {
        crate::native_hooks::from_raw(process.heap.abi.exc.fvalue)
    } else {
        match expand_error_value(process) {
            Some(reason) => reason,
            None => return 0,
        }
    };
    let trace = crate::native_hooks::from_raw(process.heap.abi.exc.ftrace);
    // The fragment branches to the handler, so no scheduler resume record is written.
    crate::native_bridge::native_found_catch(
        process,
        &mut registers.x_reg_array,
        class,
        reason,
        trace,
    )
    .unwrap_or(0)
}

/// `GET_EXC_CLASS(freason)` for a failure `handle_error` completes in native code, or `None`
/// for one the scheduler completes.
///
/// The scheduler keeps: TRAP; `function_clause` (its top frame is built from the current
/// function's arguments); re-raise words carrying `EXF_RESTORE_NFUNC` or a class atom; and
/// generic `EXF_HAS_EXT_INFO` errors. The native resolver takes the generic codes
/// (`EXC_ERROR`, `EXC_EXIT`, `EXC_THROWN`, optionally with `EXF_ARGLIST`), `error/3`'s encoded
/// argument tuple, indexed errors (`(index << 10) | EXC_ERROR`, optionally with
/// `EXF_HAS_EXT_INFO`), and a `raw_raise` re-raise (a class code without `EXF_SAVETRACE`).
#[inline]
fn native_exception_class(freason: u64, error_arglist: bool) -> Option<arinsal_bifs::Class> {
    use arinsal_beamasm::exc::{
        EXC_ERROR, EXC_EXIT, EXC_INDEXBITS, EXC_THROWN, EXF_ARGLIST, EXF_HAS_EXT_INFO,
        EXF_SAVETRACE,
    };
    if freason == arinsal_beamasm::module::EXC_FUNCTION_CLAUSE {
        return None;
    }
    let handled = if freason & EXC_INDEXBITS != 0 {
        freason & !(EXC_INDEXBITS | EXF_HAS_EXT_INFO) == EXC_ERROR
    } else if freason & EXF_HAS_EXT_INFO != 0 {
        error_arglist && freason == EXC_ERROR | EXF_ARGLIST | EXF_HAS_EXT_INFO
    } else {
        matches!(freason & !EXF_ARGLIST, EXC_ERROR | EXC_EXIT | EXC_THROWN)
            || matches!(freason | EXF_SAVETRACE, EXC_ERROR | EXC_EXIT | EXC_THROWN)
                && freason & EXF_SAVETRACE == 0
    };
    if handled {
        crate::stacktrace::class_from_freason(freason)
    } else {
        None
    }
}

/// Identifies `error/2,3`'s encoded arglist using the same BIF MFA passed to `handle_error`.
pub(crate) fn is_error_arglist(_process: &crate::Process, _bif_info: u64, freason: u64) -> bool {
    // beam_common.c handle_error: `if (c_p->freason & EXF_ARGLIST)` — only error/2,3 set it.
    use arinsal_beamasm::exc::{EXC_ERROR, EXF_ARGLIST, EXF_HAS_EXT_INFO};
    freason & EXF_ARGLIST != 0 && freason & !(EXF_ARGLIST | EXF_HAS_EXT_INFO) == EXC_ERROR
}

/// Unpacks the `Value = {Reason, Args[, ErrorInfo]}` used by `erlang:error/2,3`.
// Port of erts/emulator/beam/beam_common.c (`handle_error`), OTP-29.1.1.
pub(crate) fn unpack_error_arglist(
    process: &mut crate::Process,
    freason: u64,
) -> Option<(Term, Term)> {
    use arinsal_term::raw::Tuple;
    let value = crate::native_hooks::from_raw(process.heap.abi.exc.fvalue);
    let tuple = Tuple::try_from(value).ok()?;
    let has_error_info = freason & arinsal_beamasm::exc::EXF_HAS_EXT_INFO != 0;
    if tuple.arity() != if has_error_info { 3 } else { 2 } {
        return None;
    }
    let reason = tuple.get(0)?;
    let args = tuple.get(1)?;
    if has_error_info {
        process.heap.abi.exc.fvalue = crate::native_hooks::raw(tuple.get(2)?);
    }
    Some((reason, args))
}

/// Supplies erts' `bif_mfa` input to `save_stacktrace`, with arguments in the live X registers.
// Port of erts/emulator/beam/beam_common.c:899-925 (`save_stacktrace`), OTP-29.1.1.
fn native_bif_top(
    process: &crate::Process,
    bif_info: u64,
    registers: &[Term],
) -> Option<crate::stacktrace::TopFrame> {
    use crate::stacktrace::TopFrame;
    let freason = process.heap.abi.exc.freason;
    let bif_info = if bif_info == 0 {
        process.heap.abi.current as usize as u64
    } else {
        bif_info
    };
    if bif_info == 0 {
        let info = crate::native_hooks::from_raw(process.heap.abi.exc.fvalue);
        return (freason & arinsal_beamasm::exc::EXF_HAS_EXT_INFO != 0
            && info.classify() == arinsal_term::TermKind::Map)
            .then_some(TopFrame::CurrentArgsInfoTerm(None, info));
    }
    let (module, function, arity) = arinsal_beamasm::bif::static_bif_mfa(bif_info)?;
    if module == arinsal_term::atoms::ERLANG {
        if (function == arinsal_term::atoms::ERROR
            || function == arinsal_term::atoms::EXIT
            || function == arinsal_term::atoms::THROW)
            && arity == 1
        {
            return None;
        }
        if function == arinsal_term::atoms::ERROR && arity >= 2 {
            let args = registers.get(1).copied();
            return match registers
                .get(2)
                .filter(|_| arity > 2)
                .and_then(|options| crate::exceptions::error_info_term(*options))
            {
                Some(info) => Some(TopFrame::CurrentArgsInfoTerm(args, info)),
                None => args.map(TopFrame::CurrentArgs),
            };
        }
    }
    let info = native_bif_error_info(freason, process.heap.abi.exc.fvalue);
    Some(TopFrame::BifRegisters {
        module,
        function,
        arity: usize::from(arity),
        info,
    })
}

fn native_bif_error_info(freason: u64, fvalue: u64) -> crate::stacktrace::BifErrorInfo {
    if freason & arinsal_beamasm::exc::EXF_HAS_EXT_INFO == 0 {
        return crate::stacktrace::BifErrorInfo::Plain;
    }
    let value = crate::native_hooks::from_raw(fvalue);
    if value.classify() == arinsal_term::TermKind::Map {
        // Port of erts/emulator/beam/beam_common.c:1015-1018 (`save_stacktrace`): an extended
        // info map in fvalue is already complete and is attached directly to the BIF frame.
        crate::stacktrace::BifErrorInfo::Map(value)
    } else {
        crate::stacktrace::BifErrorInfo::Cause(value)
    }
}

/// Port of erts/emulator/beam/beam_common.c:742 (`expand_error_value`), OTP-29.1.1.
pub(crate) fn expand_error_value(process: &mut crate::Process) -> Option<arinsal_term::Term> {
    let index = process.heap.abi.exc.freason >> 10;
    let value = crate::native_hooks::from_raw(process.heap.abi.exc.fvalue);
    if index == 0 {
        return Some(value);
    }
    // erts uses the predefined `am_*` atoms (`error.h` / `expand_error_value`).
    // Interning the name hashes and takes the atom-table lock on every raise.
    let tag = Term::atom(match index {
        3 => arinsal_term::atoms::BADARG,
        4 => arinsal_term::atoms::BADARITH,
        5 => arinsal_term::atoms::BADMATCH,
        6 => arinsal_term::atoms::FUNCTION_CLAUSE,
        7 => arinsal_term::atoms::CASE_CLAUSE,
        8 => arinsal_term::atoms::IF_CLAUSE,
        9 => arinsal_term::atoms::UNDEF,
        10 => arinsal_term::atoms::BADFUN,
        11 => arinsal_term::atoms::BADARITY,
        15 => arinsal_term::atoms::SYSTEM_LIMIT,
        16 => arinsal_term::atoms::TRY_CLAUSE,
        17 => arinsal_term::atoms::NOTSUP,
        18 => arinsal_term::atoms::BADMAP,
        19 => arinsal_term::atoms::BADKEY,
        20 => arinsal_term::atoms::BADRECORD,
        21 => arinsal_term::atoms::BADFIELD,
        22 => arinsal_term::atoms::NOVALUE,
        _ => return None,
    });
    if matches!(index, 5 | 7 | 10 | 11 | 16 | 18 | 19 | 20 | 21 | 22) {
        arinsal_term::TermBuilder::new(&mut crate::ProcessHeapHandle(&mut process.heap))
            .tuple(&[tag, value])
            .ok()
    } else {
        Some(tag)
    }
}

/// Resolves a fun call that missed the local-dispatch fast path.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp:1307-1365
// (beam_jit_handle_unloaded_fun) and instr_fun.cpp:77-140, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_fun_resolver(
    header: *mut ProcessHeader,
    fun_raw: u64,
    arity: u32,
    reg: *mut u64,
) -> usize {
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(header, reg) else {
        return 0;
    };
    let fun = crate::native_hooks::from_raw(fun_raw);
    let view = crate::native_hooks::fun_view(fun);
    match view {
        Some(arinsal_term::FunRef::Local { entry, .. }) => {
            if u32::from(entry.arity) != arity {
                set_call_fun_error(process, registers, fun, arity);
                return 0;
            }
            let code_ix =
                (registers.active_code_ix as usize).min(arinsal_term::ERTS_NUM_CODE_IX - 1);
            // erts tests `fe->pend_purge_address` first: during a purge the entry's address is
            // `beam_unloaded_fun` even though the old code still exists.
            if entry
                .pend_purge_address
                .load(std::sync::atomic::Ordering::Acquire)
                != 0
            {
                return pending_purge_lambda(process, registers, entry.module, fun, arity);
            }
            if let Some(target) = entry.fun_code(code_ix) {
                return target;
            }
            unloaded_fun_error_handler(process, registers, entry.module, fun, arity)
        }
        Some(arinsal_term::FunRef::Export { entry }) => {
            if u32::from(entry.arity) != arity {
                set_call_fun_error(process, registers, fun, arity);
                return 0;
            }
            // Port of erts/emulator/beam/jit/arm/instr_fun.cpp (emit_i_call_fun: the export's
            // `addresses[code_ix]`), OTP-29.1.1: a stub's address is the export trampoline,
            // which calls the error handler; a process saving calls enters
            // `beam_save_calls_export`. The fragment passes the Export* in ARG1.
            let code_ix = registers.active_code_ix as usize;
            let export = process.runtime.as_ref().and_then(|runtime| {
                runtime
                    .export_entry((entry.module, entry.function, entry.arity), code_ix)
                    .or_else(|| {
                        crate::export::export_entry_or_stub((
                            entry.module,
                            entry.function,
                            entry.arity,
                        ))
                        .map(|export| &**export)
                    })
            });
            match export {
                Some(export) if std::ptr::eq(export, entry) => export.address(code_ix),
                _ => {
                    // A fun of another node's (or no node's) export entry: the fragment's ARG1
                    // is that entry, not this node's, so it cannot be dispatched through.
                    crate::native_hooks::set_error(process, "undef");
                    0
                }
            }
        }
        None => {
            set_call_fun_error(process, registers, fun, arity);
            0
        }
    }
}

/// A tail apply of error/exit/throw restores the calling function's native CP, so the
/// stacktrace shows the caller. False when the stack could not grow (`system_limit` set).
// Port of erts/emulator/beam/beam_common.c:1345-1427 (apply_bif_error_adjustment), OTP-29.1.1.
fn apply_bif_error_adjustment(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    mfa: (arinsal_term::Atom, arinsal_term::Atom, u8),
    return_ip: u64,
    stack_offset: u32,
) -> bool {
    let needs_error_cp = matches!(
        mfa,
        (
            arinsal_term::atoms::ERLANG,
            arinsal_term::atoms::ERROR,
            1..=3
        ) | (arinsal_term::atoms::ERLANG, arinsal_term::atoms::EXIT, 1)
            | (arinsal_term::atoms::ERLANG, arinsal_term::atoms::THROW, 1)
    );
    if return_ip == 0 || !needs_error_cp {
        return true;
    }
    let apply_only = stack_offset == 0;
    let need = (stack_offset as usize / std::mem::size_of::<u64>()).max(1);
    if process
        .ensure_objv(need, &mut registers.x_reg_array[..usize::from(mfa.2) + 2])
        .is_err()
    {
        crate::native_hooks::set_error(process, "system_limit");
        return false;
    }
    let continuation = crate::proc_create::native_continuation_term(return_ip as usize);
    // `apply_only` has no frame of its own: the CP goes into a new slot. Otherwise the frame's
    // CP slot is overwritten before the stack grows.
    let stored = if apply_only {
        let reserved = process.heap.reserve_stack(need);
        reserved && process.heap.stack_set(0, continuation)
    } else {
        let set = process.heap.stack_set(0, continuation);
        set && process.heap.reserve_stack(need)
    };
    if !stored {
        crate::native_hooks::set_error(process, "system_limit");
    }
    stored
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
    lambda_handler_call(
        process,
        registers,
        handler_export,
        code_ix,
        module,
        fun,
        arity,
    )
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
        && runtime
            .code_indexes()
            .purge_state
            .suspend_on_pending_lambda(name, pid)
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
    lambda_handler_call(process, registers, export, code_ix, module, fun, arity)
}

/// X0..X3 = Module, Fun, Args, [] for `handler(Module, Fun, Args)` and its address.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp (beam_jit_handle_unloaded_fun: the
// argument list and `reg[0..3]`), OTP-29.1.1.
fn lambda_handler_call(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    handler_export: &arinsal_beamasm::bif::ExportEntry,
    code_ix: usize,
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
    let args: smallvec::SmallVec<[Term; 8]> =
        smallvec::SmallVec::from_slice(&registers.x_reg_array[..arity]);
    let Ok(list) = arinsal_term::TermBuilder::new(&mut crate::ProcessHeapHandle(&mut process.heap))
        .list_from_iter(args)
    else {
        crate::native_hooks::set_error(process, "system_limit");
        return 0;
    };
    registers.x_reg_array[0] = Term::atom(module);
    registers.x_reg_array[1] = fun;
    registers.x_reg_array[2] = list;
    registers.x_reg_array[3] = Term::NIL;
    handler_export.address(code_ix)
}

/// Resolves `apply Arity` to a BIF export (called through its dispatch address with the
/// Export* in ARG1), a native entry, or the fragment that lets the interpreter apply.
// Port of erts/emulator/beam/jit/arm/instr_call.cpp:263-320 (emit_fixed_apply) and
// erts/emulator/beam/beam_common.c (fixed_apply), OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_apply_resolver(
    header: *mut ProcessHeader,
    arity: u32,
    return_ip: u64,
    stack_offset: u32,
    reg: *mut u64,
) -> arinsal_beamasm::misc::ApplyResolution {
    use arinsal_beamasm::misc::ApplyResolution;
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(header, reg) else {
        return ApplyResolution::default();
    };
    let arity = arity as usize;
    if arity + 1 >= registers.x_reg_array.len() {
        return apply_error(
            process,
            registers,
            Term::NIL,
            Term::NIL,
            Term::NIL,
            arinsal_bifs::BifError::SystemLimit,
        );
    }
    let module = registers.x_reg_array[arity];
    let function = registers.x_reg_array[arity + 1];
    let (Some(module_atom), Some(function_atom)) = (module.as_atom(), function.as_atom()) else {
        // Port of erts/emulator/beam/beam_common.c:1540-1552 (fixed_apply, `error`), OTP-29.1.1.
        if process
            .ensure_objv(arity * 2, &mut registers.x_reg_array[..arity + 2])
            .is_err()
        {
            return apply_error(
                process,
                registers,
                module,
                function,
                Term::NIL,
                arinsal_bifs::BifError::SystemLimit,
            );
        }
        let (module, function) = (
            registers.x_reg_array[arity],
            registers.x_reg_array[arity + 1],
        );
        let args: smallvec::SmallVec<[Term; 8]> =
            smallvec::SmallVec::from_slice(&registers.x_reg_array[..arity]);
        let Ok(list) =
            arinsal_term::TermBuilder::new(&mut crate::ProcessHeapHandle(&mut process.heap))
                .list_from_iter(args)
        else {
            return apply_error(
                process,
                registers,
                module,
                function,
                Term::NIL,
                arinsal_bifs::BifError::SystemLimit,
            );
        };
        return apply_error(
            process,
            registers,
            module,
            function,
            list,
            arinsal_bifs::BifError::Badarg { cause: None },
        );
    };
    // Port of erts/emulator/beam/beam_common.c:1554-1557 (fixed_apply), OTP-29.1.1: an
    // apply of erlang:apply/3 is a plain apply/3 of its arguments.
    if arity == 3
        && module_atom == arinsal_term::atoms::ERLANG
        && function_atom == arinsal_term::atoms::APPLY
    {
        return apply3(process, registers, return_ip, stack_offset);
    }
    let code_ix = registers.active_code_ix as usize;
    // Port of erts/emulator/beam/beam_common.c:1559-1566 (fixed_apply:
    // erts_export_get_or_make_stub, apply_bif_error_adjustment), OTP-29.1.1: the JIT calls
    // the export's `addresses[code_ix]` with the Export* in ARG1.
    let mfa = (module_atom, function_atom, arity as u8);
    let Some(export) = process.runtime.as_ref().and_then(|runtime| {
        runtime
            .export_entry(mfa, code_ix)
            .or_else(|| crate::export::export_entry_or_stub(mfa).map(|export| &**export))
    }) else {
        return apply_error(
            process,
            registers,
            module,
            function,
            Term::NIL,
            arinsal_bifs::BifError::Badarg { cause: None },
        );
    };
    if !apply_bif_error_adjustment(process, registers, mfa, return_ip, stack_offset) {
        return ApplyResolution::default();
    }
    ApplyResolution {
        export: std::ptr::from_ref(export) as u64,
        target: export.address(code_ix) as u64,
    }
}

/// An apply that raises: the reason, X0..X2 set to its module, function and arguments, and
/// `current` erlang:apply/3, which the JIT raises with (`emit_raise_exception(&apply3_mfa)`).
// Port of erts/emulator/beam/beam_common.c:1450-1460 (apply: error, error2) and
// jit/arm/instr_call.cpp:205-244 (emit_variable_apply), OTP-29.1.1.
fn apply_error(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    module: Term,
    function: Term,
    args: Term,
    reason: arinsal_bifs::BifError,
) -> arinsal_beamasm::misc::ApplyResolution {
    set_light_bif_error(process, &reason);
    registers.x_reg_array[0] = module;
    registers.x_reg_array[1] = function;
    registers.x_reg_array[2] = args;
    // Port of erts/emulator/beam/jit/arm/instr_call.cpp:211 (`static ErtsCodeMFA apply3_mfa`).
    static APPLY3_MFA: std::sync::OnceLock<arinsal_term::ErtsCodeMfa> = std::sync::OnceLock::new();
    let mfa = APPLY3_MFA.get_or_init(|| arinsal_term::ErtsCodeMfa {
        module: Term::atom(arinsal_term::atoms::ERLANG).word(),
        function: Term::atom(arinsal_term::atoms::APPLY).word(),
        arity: 3,
    });
    process.heap.abi.current = std::ptr::from_ref(mfa).cast();
    arinsal_beamasm::misc::ApplyResolution::default()
}

/// Resolves `apply/3` to a native entry with the arguments moved into the X registers, or to
/// the fragment that lets the interpreter apply (and raise) with X0..X2 untouched.
// Port of erts/emulator/beam/jit/arm/instr_call.cpp:205-244 (emit_variable_apply) and
// erts/emulator/beam/beam_common.c:1434-1530 (apply), OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_apply3_resolver(
    header: *mut ProcessHeader,
    return_ip: u64,
    stack_offset: u32,
    reg: *mut u64,
) -> arinsal_beamasm::misc::ApplyResolution {
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(header, reg) else {
        return arinsal_beamasm::misc::ApplyResolution::default();
    };
    apply3(process, registers, return_ip, stack_offset)
}

// Port of erts/emulator/beam/beam_common.c:1434-1530 (apply), OTP-29.1.1.
fn apply3(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    return_ip: u64,
    stack_offset: u32,
) -> arinsal_beamasm::misc::ApplyResolution {
    use arinsal_beamasm::misc::ApplyResolution;
    let (mut module, mut function, mut args) = (
        registers.x_reg_array[0],
        registers.x_reg_array[1],
        registers.x_reg_array[2],
    );
    // Port of erts/emulator/beam/beam_common.c:1462-1495 (nested apply loop), OTP-29.1.1.
    while module.as_atom() == Some(arinsal_term::atoms::ERLANG)
        && function.as_atom() == Some(arinsal_term::atoms::APPLY)
    {
        let Some((nested_module, rest)) = crate::lists::split(args) else {
            break;
        };
        let Some((nested_function, rest)) = crate::lists::split(rest) else {
            break;
        };
        let Some((nested_args, rest)) = crate::lists::split(rest) else {
            break;
        };
        if rest != Term::NIL {
            break;
        }
        (module, function, args) = (nested_module, nested_function, nested_args);
    }
    let (Some(module_atom), Some(function_atom)) = (module.as_atom(), function.as_atom()) else {
        return apply_error(
            process,
            registers,
            module,
            function,
            args,
            arinsal_bifs::BifError::Badarg { cause: None },
        );
    };
    let mut arity = 0_usize;
    let mut list = args;
    while let Some((_, tail)) = crate::lists::split(list) {
        arity += 1;
        if arity >= registers.x_reg_array.len() - 1 {
            return apply_error(
                process,
                registers,
                module,
                function,
                args,
                arinsal_bifs::BifError::SystemLimit,
            );
        }
        list = tail;
    }
    if list != Term::NIL {
        return apply_error(
            process,
            registers,
            module,
            function,
            args,
            arinsal_bifs::BifError::Badarg { cause: None },
        );
    }
    let Ok(arity) = u8::try_from(arity) else {
        return apply_error(
            process,
            registers,
            module,
            function,
            args,
            arinsal_bifs::BifError::SystemLimit,
        );
    };
    let (module, function) = (module_atom, function_atom);
    // Port of erts/emulator/beam/beam_common.c:1497-1530 (apply: the export of the MFA, whose
    // `addresses[code_ix]` the JIT calls with the Export* in ARG1; a stub's address is the
    // export trampoline, a process saving calls enters `beam_save_calls_export`), OTP-29.1.1.
    let code_ix = registers.active_code_ix as usize;
    // Port of erts/emulator/beam/beam_common.c:1518-1520, OTP-29.1.1: a function not found
    // gets a stub entry, which calls the error handler.
    let Some(export) = process.runtime.as_ref().and_then(|runtime| {
        runtime
            .export_entry((module, function, arity), code_ix)
            .or_else(|| {
                crate::export::export_entry_or_stub((module, function, arity))
                    .map(|export| &**export)
            })
    }) else {
        return apply_error(
            process,
            registers,
            Term::atom(module),
            Term::atom(function),
            args,
            arinsal_bifs::BifError::Badarg { cause: None },
        );
    };
    let target = export.address(code_ix);
    let mut list = args;
    for slot in registers.x_reg_array.iter_mut() {
        let Some((head, tail)) = crate::lists::split(list) else {
            break;
        };
        *slot = head;
        list = tail;
    }
    if !apply_bif_error_adjustment(
        process,
        registers,
        (module, function, arity),
        return_ip,
        stack_offset,
    ) {
        return ApplyResolution::default();
    }
    ApplyResolution {
        export: std::ptr::from_ref(export) as u64,
        target: target as u64,
    }
}

/// Builds a map from the staged key/value vector.
// Port of erts/emulator/beam/jit/arm/instr_map.cpp:228-256 (emit_new_map_shared), OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_map_new(
    header: *mut ProcessHeader,
    source: u64,
    _registers: u64,
    live: u64,
    count: u64,
    reg: *mut u64,
) -> u64 {
    arinsal_beamasm_map_change(header, reg, source, live, count, MapChange::New)
}

/// Applies associative updates from the staged key/value vector.
// Port of erts/emulator/beam/jit/arm/instr_map.cpp:543-559 (emit_update_map_assoc_shared),
// OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_map_assoc(
    header: *mut ProcessHeader,
    source: u64,
    _registers: u64,
    live: u64,
    count: u64,
    reg: *mut u64,
) -> u64 {
    arinsal_beamasm_map_change(header, reg, source, live, count, MapChange::Assoc)
}

/// Applies exact updates from the staged key/value vector.
// Port of erts/emulator/beam/jit/arm/instr_map.cpp:604-648 (emit_update_map_exact_guard_shared
// and emit_update_map_exact_body_shared), OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_map_exact(
    header: *mut ProcessHeader,
    source: u64,
    _registers: u64,
    live: u64,
    count: u64,
    reg: *mut u64,
) -> u64 {
    arinsal_beamasm_map_change(header, reg, source, live, count, MapChange::Exact)
}

/// `Map#{Key => Value}` with a single pair: `erts_maps_put` without the register array.
// Port of erts/emulator/beam/jit/arm/instr_map.cpp:561-577
// (emit_update_map_single_assoc_shared), OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_map_put_single(
    header: *mut ProcessHeader,
    key: u64,
    value: u64,
    map: u64,
    _unused: u64,
    reg: *mut u64,
) -> u64 {
    map_single::<false>(header, key, value, map, 0, reg)
}

/// `Map#{Key := Value}` with a single pair and no failure label: `erts_maps_update`; returns
/// its status and writes the updated map through the scheduler's `TMP_MEM1` slot.
// Port of erts/emulator/beam/jit/arm/instr_map.cpp:650-683
// (emit_update_map_single_exact_body_shared), OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_map_update_single(
    header: *mut ProcessHeader,
    key: u64,
    value: u64,
    map: u64,
    result_pointer: u64,
    reg: *mut u64,
) -> u64 {
    map_single::<true>(header, key, value, map, result_pointer, reg)
}

#[inline(always)]
fn put_single_native(process: &mut crate::Process, key: u64, value: u64, map: u64) -> Option<u64> {
    let mut top = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let (key, value, map) = (
        crate::native_hooks::from_raw(key),
        crate::native_hooks::from_raw(value),
        crate::native_hooks::from_raw(map),
    );
    match arinsal_maps::put(map, key, value, &mut top) {
        Ok(term) => Some(crate::native_hooks::raw(term)),
        Err(error) => put_single_failed(error),
    }
}

/// `erts_maps_put` asserts that its operand is a map; the compiler guards every single-pair put
/// with `is_map`, and the shared fragment returns without looking for a pending error.
// Port of erts/emulator/beam/erl_map.c, erts_maps_put (ASSERT(is_map(map))), OTP-29.1.1.
#[cold]
#[inline(never)]
fn put_single_failed(error: arinsal_maps::MapError) -> ! {
    panic!("single-pair map put failed after the is_map guard: {error:?}")
}

#[inline(always)]
fn map_single<const EXACT: bool>(
    header: *mut ProcessHeader,
    key: u64,
    value: u64,
    map: u64,
    result_pointer: u64,
    reg: *mut u64,
) -> u64 {
    // erts_maps_put/erts_maps_update consume their operands from arguments and
    // do not read the X register array.
    // Port of erts/emulator/beam/jit/arm/instr_map.cpp:579-598,686-694,
    // OTP-29.1.1.
    if !EXACT {
        let Some(process) = crate::native_hooks::process_from_header(header) else {
            return 0;
        };
        // HAllocX on `c_p->htop`.
        if let Some(raw) = put_single_native(process, key, value, map) {
            return raw;
        }
    }
    map_single_generic::<EXACT>(header, key, value, map, result_pointer, reg)
}

/// The heap-fragment path of a single-pair map update: used by the exact update and when the
/// put cannot allocate on the native heap top.
#[inline(never)]
fn map_single_generic<const EXACT: bool>(
    header: *mut ProcessHeader,
    key: u64,
    value: u64,
    map: u64,
    result_pointer: u64,
    reg: *mut u64,
) -> u64 {
    // Two monomorphic helpers: the put entry carries no exact-update state.
    let exact = EXACT;
    let (process, registers) = if exact {
        let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(header, reg) else {
            return 0;
        };
        (process, Some(registers))
    } else {
        let Some(process) = crate::native_hooks::enter_heap_runtime(header) else {
            return 0;
        };
        (process, None)
    };
    let (key, value, map) = (
        crate::native_hooks::from_raw(key),
        crate::native_hooks::from_raw(value),
        crate::native_hooks::from_raw(map),
    );
    let mut heap = crate::ProcessHeapHandle(&mut process.heap);
    let result = if exact {
        arinsal_maps::update(map, key, value, &mut heap)
    } else {
        arinsal_maps::put(map, key, value, &mut heap)
    };
    match result {
        Ok(term) => {
            if exact {
                let registers =
                    registers.expect("exact map update enters with scheduler registers");
                debug_assert_eq!(
                    result_pointer,
                    registers.tmp_mem.as_mut_ptr() as usize as u64
                );
                registers.tmp_mem[0] = crate::native_hooks::raw(term);
                1
            } else {
                crate::native_hooks::raw(term)
            }
        }
        Err(arinsal_maps::MapError::Badkey(_)) if exact => {
            // `erts_maps_update` returns its zero status without setting exception fields; the
            // exact-update fragment uses the saved TMP_MEM2 key to raise BADKEY.
            0
        }
        Err(error) if !exact => put_single_failed(error),
        Err(error) => map_result(process, Err(error), exact, false),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MapChange {
    New,
    Assoc,
    Exact,
}

// Port of erts/emulator/beam/beam_common.c:1863-2344 (erts_gc_new_map,
// erts_gc_update_map_assoc, erts_gc_update_map_exact), OTP-29.1.1. The emitter stages the
// key/value vector at X{max(live, 6)}.. and the source map right after it; the vector is
// read from the register array after any collection, like erts' GET_TERM.
fn arinsal_beamasm_map_change(
    header: *mut ProcessHeader,
    reg: *mut u64,
    source: u64,
    live: u64,
    count: u64,
    change: MapChange,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(header, reg) else {
        return 0;
    };
    let Some(n) = usize::try_from(count).ok().and_then(|c| c.checked_mul(2)) else {
        return 0;
    };
    let has_fail_label = live >> 32 != 0;
    let Ok(live) = usize::try_from(live & 0xffff_ffff) else {
        return 0;
    };
    let base = live.max(6);
    let source_slot = base + n;
    if source_slot >= crate::proc_create::ATTACHED_X_REGS {
        return 0;
    }
    registers.x_reg_array[source_slot] = crate::native_hooks::from_raw(source);
    let map = crate::native_hooks::from_raw(source);
    let need = match change {
        MapChange::New => arinsal_maps::new_map_need(n),
        MapChange::Assoc => arinsal_maps::update_map_assoc_need(map, n),
        MapChange::Exact => arinsal_maps::update_map_exact_need(map),
    };
    if process.heap.words_left() < need {
        // X registers between the live prefix and the staged vector are dead and may hold
        // stale words; they must not become GC roots.
        registers.x_reg_array[live..base].fill(Term::NIL);
        if crate::native_hooks::collect_native(process, registers, need, source_slot + 1).is_err() {
            crate::native_hooks::set_error(process, "system_limit");
            return 0;
        }
    }
    let x = &registers.x_reg_array;
    let arg = |i: usize| x[base + i];
    let map = x[source_slot];
    let mut heap = crate::ProcessHeapHandle(&mut process.heap);
    let result = match change {
        MapChange::New => arinsal_maps::gc_new_map(n, arg, &mut heap),
        MapChange::Assoc => arinsal_maps::gc_update_map_assoc(map, n, arg, &mut heap),
        MapChange::Exact => arinsal_maps::gc_update_map_exact(map, n, arg, &mut heap),
    };
    map_result(process, result, change == MapChange::Exact, has_fail_label)
}

fn map_result(
    process: &mut crate::Process,
    result: arinsal_maps::MapResult<Term>,
    exact: bool,
    has_fail_label: bool,
) -> u64 {
    // The error tuples below allocate, so the native header is published after them.
    match result {
        Ok(term) => crate::native_hooks::raw(term),
        Err(arinsal_maps::MapError::Badkey(_)) if exact && has_fail_label => 0,
        Err(arinsal_maps::MapError::Badkey(key)) => {
            set_tagged_error(process, "badkey", key);
            0
        }
        Err(arinsal_maps::MapError::Badmap(map)) => {
            set_tagged_error(process, "badmap", map);
            0
        }
        Err(arinsal_maps::MapError::Allocation) => {
            crate::native_hooks::set_error(process, "system_limit");
            0
        }
        Err(_) => {
            crate::native_hooks::set_error(process, "badarg");
            0
        }
    }
}

/// Generic fallback lookup for non-flatmap keys.
// Port of erts/emulator/beam/beam_common.c:1775-1800 (get_map_element), OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_map_get(
    header: *mut ProcessHeader,
    map: u64,
    key: u64,
    hash: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let map = crate::native_hooks::from_raw(map);
    let key = crate::native_hooks::from_raw(key);
    let result = if hash == 0 {
        arinsal_maps::get(map, key)
    } else {
        arinsal_maps::get_with_hash(map, key, hash)
    };
    match result {
        Ok(Some(value)) => crate::native_hooks::raw(value),
        Ok(None) | Err(arinsal_maps::MapError::Badkey(_)) => 0,
        Err(arinsal_maps::MapError::Badmap(_)) => {
            crate::native_hooks::set_error(process, "badmap");
            0
        }
        Err(_) => {
            crate::native_hooks::set_error(process, "badarg");
            0
        }
    }
}

/// Generic fallback for a batch of map lookups staged at X6.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp:706-760, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_map_get_elements(
    header: *mut ProcessHeader,
    map: u64,
    module_handle: u64,
    table_index: u64,
    stack_pointer: u64,
    reg: *mut u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(header, reg) else {
        return 0;
    };
    let Ok(table_index) = usize::try_from(table_index) else {
        return 0;
    };
    let Some(module) = crate::beamasm_integration::map_lookup_version(module_handle) else {
        return 0;
    };
    process
        .heap
        .set_stack_pointer(stack_pointer as usize as *mut u64);
    let heap = &mut process.heap;
    let x_registers = &mut registers.x_reg_array;
    let Some(table) = module.map_lookups.get(table_index) else {
        return 0;
    };
    let found = matches!(
        arinsal_maps::get_map_elements_with(
            crate::native_hooks::from_raw(map),
            table.entries.len(),
            |index| crate::native_hooks::from_raw(table.entries[index].key),
            |index| table.entries[index].hash,
            |index, value| match table.entries[index].destination {
                arinsal_beamasm::map::MapLookupDestination::X(register) => {
                    let Some(destination) = x_registers.get_mut(register as usize) else {
                        return false;
                    };
                    *destination = value;
                    true
                }
                arinsal_beamasm::map::MapLookupDestination::Y(offset) => {
                    heap.stack_set(offset as usize, value)
                }
            },
        ),
        Ok(true)
    );
    if !found {
        return 0;
    }
    1
}

/// Starts `bs_create_bin` append and publishes its writable buffer to native stores.
// Port of erts/emulator/beam/erl_bits.c:1744-1818 (`erts_bs_append_checked` error fields), OTP-29.1.1.
fn set_bs_append_error(process: &mut crate::Process, detail: &str, reason: &str) {
    process.heap.abi.exc.freason = match reason {
        "system_limit" => arinsal_beamasm::exc::EXC_SYSTEM_LIMIT,
        _ => arinsal_beamasm::exc::EXC_BADARG,
    };
    process.heap.abi.exc.fvalue = crate::native_hooks::raw(crate::atom_cache::put(detail));
}

// Port of erts/emulator/beam/erl_bits.c:1725-1917 (`erts_bs_append_checked`), OTP-29.1.1.
// The source is `reg[live]` and every collection here keeps exactly `live + 1` X roots, the
// source or its `sb->orig` included. `reg` is the process's X file (`process.x`), the array the
// collector rewrites: erts passes the same `reg` to `erts_garbage_collect`. Reading the
// registers through any other handle that the compiler may assume unaliased (a `&mut
// SchedulerRegisters`) would let it reuse the pre-collection `reg[live]`.
pub(crate) fn bs_append_checked(
    process_header: *mut ProcessHeader,
    ebs: &mut [u64; 2],
    x: &mut [Term],
    extra_bits: u64,
    unit: u64,
    live: u64,
    alloc: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(process_header) else {
        return 0;
    };
    let extra_bits = extra_bits as usize;
    let unit = unit as usize;
    let live = live as usize;
    let alloc = alloc as usize;
    arinsal_term::validate::check_heap_bits_if_active(&process.heap, "bs_append_checked entry");
    let source = x[live];
    // erl_bits.c:1744-1756: anything but a boxed bitstring is a type error, before any GC.
    if source.classify() != arinsal_term::TermKind::Bitstring {
        set_bs_append_error(process, "type", "badarg");
        return 0;
    }
    let mut prepared = PreparedWritableAppend::default();
    match TermBuilder::prepare_writable_append(
        &mut process.heap,
        source,
        extra_bits,
        unit,
        &mut prepared,
    ) {
        Ok(true) if extra_bits == 0 => {
            // erl_bits.c:1782-1793: collect if the caller's words do not fit, then return
            // `reg[live]` itself with a cursor that crashes on use.
            if process.heap.reserve_native_halloc(0, alloc).is_none()
                && process
                    .ensure_native_roots(alloc, &mut x[..live + 1])
                    .is_err()
            {
                set_bs_append_error(process, "size", "system_limit");
                return 0;
            }
            *ebs = [0, 5];
            crate::native_hooks::raw(x[live])
        }
        Ok(true) => {
            // erl_bits.c:1832-1842: `reg[live] = sb->orig`, collect once if the HAlloc
            // reservation is short, then build the successor directly at `htop`.
            x[live] = prepared.bin_ref();
            let used_words: usize = 5;
            let heap_need = used_words.wrapping_add(alloc);
            let reservation = match process.heap.reserve_native_halloc(used_words, alloc) {
                Some(reservation) => reservation,
                None => {
                    if process
                        .ensure_native_roots(heap_need, &mut x[..live + 1])
                        .is_err()
                    {
                        set_bs_append_error(process, "size", "system_limit");
                        return 0;
                    }
                    process
                        .heap
                        .reserve_native_halloc(used_words, alloc)
                        .expect("GC leaves the requested HeapWordsLeft reservation")
                }
            };
            let owner = x[live];
            let mut term = Term::NIL;
            TermBuilder::<arinsal_term::ProcessHeap>::finish_writable_append(
                reservation,
                Term::NIL,
                owner,
                prepared,
                extra_bits,
                &mut term,
            );
            let offset_bits = prepared.offset_bits(extra_bits);
            *ebs = [prepared.data_address() as u64, offset_bits as u64];
            arinsal_term::validate::check_heap_bits_if_active(
                &process.heap,
                "bs_append_checked writable exit",
            );
            // Port of `BUMP_REDS` in erts/emulator/beam/bif.h:71-77, OTP-29.1.1.
            let reds = ((if prepared.grew() { offset_bits } else { 0 }) / (8 * 1024)) as i32;
            process.heap.abi.fcalls = process.heap.abi.fcalls.wrapping_sub(reds).max(0);
            crate::native_hooks::raw(term)
        }
        Ok(false) => {
            // erl_bits.c:1854-1866 (`not_writable`): ERL_REFC_BITS_SIZE + extra_words, with
            // the source kept in `reg[live]` across the collection.
            let reservation = match process.heap.reserve_native_halloc(8, alloc) {
                Some(reservation) => Some(reservation),
                None => {
                    let fresh_request = 8_usize.wrapping_add(alloc);
                    if process
                        .ensure_native_roots(fresh_request, &mut x[..live + 1])
                        .is_err()
                    {
                        set_bs_append_error(process, "size", "system_limit");
                        return 0;
                    }
                    None
                }
            };
            let source = x[live];
            if extra_bits == 0 {
                // erl_bits.c:1871-1883: only the unit is checked; the source itself is the
                // result and no writable binary is built.
                let bits = arinsal_term::raw::BinRef::try_from(source)
                    .map(arinsal_term::raw::BinRef::bit_len)
                    .unwrap_or(0);
                if unit > 1 && !bits.is_multiple_of(unit) {
                    set_bs_append_error(process, "unit", "badarg");
                    return 0;
                }
                *ebs = [0, 5];
                return crate::native_hooks::raw(source);
            }
            let reservation = match reservation {
                Some(reservation) => reservation,
                None => process
                    .heap
                    .reserve_native_halloc(8, alloc)
                    .expect("GC leaves the requested HeapWordsLeft reservation"),
            };
            match TermBuilder::<arinsal_term::ProcessHeap>::append_nonwritable(
                reservation,
                source,
                extra_bits,
                unit,
            ) {
                Ok((term, data_address, offset_bits)) => {
                    *ebs = [data_address as u64, offset_bits as u64];
                    // Port of `BUMP_REDS` in erts/emulator/beam/bif.h:71-77, OTP-29.1.1.
                    let reds = (offset_bits / (8 * 1024)) as i32;
                    process.heap.abi.fcalls = process.heap.abi.fcalls.wrapping_sub(reds).max(0);
                    crate::native_hooks::raw(term)
                }
                Err(arinsal_term::TermError::HeapFull) => {
                    set_bs_append_error(process, "size", "system_limit");
                    0
                }
                Err(error) => {
                    let (detail, reason) = if error == arinsal_term::TermError::SystemLimit {
                        ("size", "system_limit")
                    } else if unit > 1 {
                        ("unit", "badarg")
                    } else {
                        ("type", "badarg")
                    };
                    set_bs_append_error(process, detail, reason);
                    0
                }
            }
        }
        Err(error) => {
            let (detail, reason) = if error == arinsal_term::TermError::SystemLimit {
                ("size", "system_limit")
            } else if unit > 1 {
                ("unit", "badarg")
            } else {
                ("type", "badarg")
            };
            set_bs_append_error(process, detail, reason);
            0
        }
    }
}

/// Runs the checked private append and charges its writable-binary overhead on the process.
// Port of erts/emulator/beam/erl_bits.c:1928-2017 (`erts_bs_private_append_checked`), OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_bs_private_append_checked(
    ebs: *mut u64,
    process_header: *mut ProcessHeader,
    bin: u64,
    extra_bits: u64,
) -> u64 {
    // BeamAsm already committed native cursors before the direct C-style helper call.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1865-1880 and erl_bits.c:1928-1983,
    // OTP-29.1.1.
    let Some(process) = crate::native_hooks::enter_runtime(process_header) else {
        return 0;
    };
    let update = arinsal_term::erts_bs_private_append_checked_with_heap(
        ebs,
        bin,
        extra_bits,
        &mut process.heap,
    );
    if update.result != 0 && update.result != u64::MAX {
        process.heap.update_writable_binary_overhead_at(
            crate::native_hooks::from_raw(bin),
            update.bin_ref,
            update.old_size_bits,
            update.new_size_bits,
        );
        process.heap.abi.fcalls = process
            .heap
            .abi
            .fcalls
            .saturating_sub((update.copied_bits / (8 * 1024)).min(i32::MAX as usize) as i32);
    }
    update.result
}

/// Runs one field-decoding `bs_match` command. The context and operands are staged as terms in
/// the scheduler registers' match staging area; the result is the extracted term,
/// `[]` for a successful test, or zero when the match fails.
// Port of erts/emulator/beam/jit/arm/instr_bs.cpp:3024-3210 and beam_jit_bs.cpp, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_bs_match_command(
    header: *mut ProcessHeader,
    kind: u64,
    live: u64,
    reg: *mut u64,
) -> u64 {
    use arinsal_bits::{BitsError, MatchOps, SegFlags};
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(header, reg) else {
        return 0;
    };
    let base = live as usize;
    let Some(root_live) = base
        .checked_add(4)
        .filter(|&count| count <= registers.x_reg_array.len())
    else {
        crate::native_hooks::set_error(process, "system_limit");
        return 0;
    };
    // The live X prefix and staged operands (the context among them) form the exact GC root
    // prefix. Registers beyond `live` are dead and may contain non-term scratch values.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp (emit_gc_test_preserve), OTP-29.1.1.
    for (index, slot) in registers.match_staging.iter().enumerate() {
        registers.x_reg_array[base + index] = crate::native_hooks::from_raw(*slot);
    }
    let small = |term: Term| term.as_small().and_then(|n| usize::try_from(n).ok());
    let mut result: Option<Result<Option<Term>, BitsError>> = None;
    let mut request = 8usize;
    for _ in 0..8 {
        let ctx = registers.x_reg_array[base];
        let outcome = match kind {
            // integer / binary: flags, size, unit
            0 | 1 => {
                let bits = small(registers.x_reg_array[base + 2])
                    .zip(small(registers.x_reg_array[base + 3]))
                    .and_then(|(size, unit)| size.checked_mul(unit));
                match bits {
                    None => Ok(None),
                    Some(bits) if kind == 0 => {
                        let flags = small(registers.x_reg_array[base + 1]).unwrap_or(0);
                        ctx.get_integer(
                            bits,
                            SegFlags {
                                little: flags & 2 != 0,
                                signed: flags & 4 != 0,
                                native: flags & 16 != 0,
                            },
                            &mut process.heap,
                        )
                    }
                    Some(bits) => ctx.get_binary(bits, &mut process.heap),
                }
            }
            2 => match small(registers.x_reg_array[base + 1]) {
                Some(unit) => ctx.get_tail_unit(unit, &mut process.heap),
                None => Ok(None),
            },
            _ => {
                let expected = registers.x_reg_array[base + 2];
                match small(registers.x_reg_array[base + 1]) {
                    None => Ok(None),
                    Some(bits) => {
                        if let Some(value) = expected
                            .as_small()
                            .and_then(|n| u64::try_from(n).ok())
                            .filter(|_| bits <= 64)
                        {
                            Ok(ctx.match_integer(bits, value).then_some(Term::NIL))
                        } else {
                            let saved = ctx.position();
                            match ctx.get_integer(bits, SegFlags::default(), &mut process.heap) {
                                Ok(Some(term)) if arinsal_term::exact_eq(term, expected) => {
                                    Ok(Some(Term::NIL))
                                }
                                Ok(_) => {
                                    ctx.set_position(saved);
                                    Ok(None)
                                }
                                Err(error) => {
                                    ctx.set_position(saved);
                                    Err(error)
                                }
                            }
                        }
                    }
                }
            }
        };
        match outcome {
            Err(BitsError::HeapFull { need_words }) => {
                request = need_words.max(request.saturating_mul(2));
                if process
                    .ensure_objv(request, &mut registers.x_reg_array[..root_live])
                    .is_err()
                {
                    crate::native_hooks::set_error(process, "system_limit");
                    return 0;
                }
            }
            other => {
                result = Some(other);
                break;
            }
        }
    }
    for (index, slot) in registers.match_staging.iter_mut().enumerate() {
        *slot = crate::native_hooks::raw(registers.x_reg_array[base + index]);
    }
    match result {
        Some(Ok(Some(term))) => crate::native_hooks::raw(term),
        Some(Ok(None)) => 0,
        Some(Err(BitsError::SystemLimit { .. })) => {
            crate::native_hooks::set_error(process, "system_limit");
            0
        }
        _ => {
            crate::native_hooks::set_error(process, "badarg");
            0
        }
    }
}

/// Runs a match-context allocation in heap space that the emitted code reserved with the
/// instruction's live registers (emit_gc_test_preserve), so it never collects.
// Port of the Update::eHeapOnlyAlloc runtime calls in erts/emulator/beam/jit/arm/instr_bs.cpp,
// OTP-29.1.1.
fn heap_only<T>(
    process: &mut crate::Process,
    context: Term,
    operation: impl FnOnce(Term, &mut arinsal_term::ProcessHeap) -> Result<T, arinsal_bits::BitsError>,
) -> Option<T> {
    match operation(context, &mut process.heap) {
        Ok(value) => Some(value),
        Err(arinsal_bits::BitsError::HeapFull { .. }) => {
            crate::native_hooks::set_error(process, "system_limit");
            None
        }
        Err(_) => None,
    }
}

/// Runs the common BeamAsm match-context operations used by bit syntax emitters.
// Port of erts/emulator/beam/jit/arm/instr_bs.cpp:134-255, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_bs_match(
    header: *mut ProcessHeader,
    op: u32,
    context: u64,
    value: u64,
    _unit: u64,
) -> u64 {
    // Every operation here is a HeapOnlyAlloc runtime call: the operands arrive as
    // arguments, the heap space was reserved by the preceding heap test, nothing collects and
    // the X registers are not read.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:170-182 (emit_enter_runtime with
    // Update::eHeapOnlyAlloc), OTP-29.1.1.
    let Some(process) = crate::native_hooks::enter_heap_runtime(header) else {
        return 0;
    };
    let context = crate::native_hooks::from_raw(context);
    let value = crate::native_hooks::from_raw(value);
    let result = match op {
        0 => heap_only(process, context, arinsal_bits::start_match).flatten(),
        3 => heap_only(process, context, arinsal_bits::get_position),
        4 => arinsal_bits::set_position_term(context, value).then_some(Term::NIL),
        6 => {
            let bits = value
                .as_small()
                .and_then(|n| usize::try_from(n).ok())
                .and_then(|n| {
                    usize::try_from(_unit)
                        .ok()
                        .and_then(|unit| n.checked_mul(unit))
                });
            bits.and_then(|bits| {
                heap_only(process, context, |context, heap| {
                    context.get_binary(bits, heap)
                })
                .flatten()
            })
        }
        10 => heap_only(process, context, |context, heap| context.get_tail(heap)),
        // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:191-234 (i_bs_match_string): compare
        // the next `_unit` bits with the registered constant, 64 bits at a time.
        9 => {
            let saved = context.position();
            let expected = value.as_small().and_then(|handle| {
                match_strings()
                    .read()
                    .ok()?
                    .get(usize::try_from(handle).ok()?)
                    .cloned()
            });
            expected
                .filter(|expected| {
                    let bits = _unit as usize;
                    let mut done = 0;
                    let matched = loop {
                        if done >= bits {
                            break true;
                        }
                        let chunk = (bits - done).min(64);
                        let bytes = chunk.div_ceil(8);
                        let Some(slice) = expected.get(done / 8..done / 8 + bytes) else {
                            break false;
                        };
                        let word = slice
                            .iter()
                            .fold(0_u64, |acc, byte| (acc << 8) | u64::from(*byte));
                        let word = word >> (bytes * 8 - chunk);
                        if !context.match_integer(chunk, word) {
                            break false;
                        }
                        done += chunk;
                    };
                    if !matched {
                        context.set_position(saved);
                    }
                    matched
                })
                .map(|_| Term::NIL)
        }
        // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:712-929 (UTF-8 and UTF-16 segments),
        // OTP-29.1.1.
        11 => context.get_utf8(),
        12 => {
            let flags = value.as_small().unwrap_or(0);
            context.get_utf16(arinsal_bits::SegFlags {
                little: flags & 2 != 0,
                signed: flags & 4 != 0,
                native: flags & 16 != 0,
            })
        }
        // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:578-617 (i_bs_get_float2); `_unit`
        // is `(Unit << 3) | Flags` as built by gen.get_float2.
        13 => {
            let bits = value
                .as_small()
                .and_then(|n| usize::try_from(n).ok())
                .and_then(|n| n.checked_mul(usize::try_from(_unit >> 3).ok()?));
            let flags = _unit & 7;
            bits.and_then(|bits| {
                heap_only(process, context, |context, heap| {
                    context.get_float(
                        bits,
                        arinsal_bits::SegFlags {
                            little: flags & 2 != 0,
                            signed: flags & 4 != 0,
                            native: false,
                        },
                        heap,
                    )
                })
                .flatten()
            })
        }
        _ => None,
    };
    result.map(crate::native_hooks::raw).unwrap_or(0)
}

/// `erlang:process_info/2` light entry. The caller's own items are built by
/// `natives::proc::process_info_light`, the same builder the executor uses. Anything it declines
/// (a foreign pid, queued signals, a VM-dependent item, an error) takes the executor.
// Port of erts/emulator/beam/erl_bif_info.c:1274-1330 (process_info_bif, c_p == rp), OTP-29.1.1.
pub(crate) extern "C" fn process_info_2_light(
    header: *mut ProcessHeader,
    regs: *mut u64,
    i: u64,
) -> u64 {
    if let Some(raw) = process_info_2_self(header, regs) {
        return raw;
    }
    yield_executor_bif(header, regs, i)
}

fn process_info_2_self(header: *mut ProcessHeader, regs: *mut u64) -> Option<u64> {
    let process = crate::native_hooks::enter_runtime(header)?;
    let [pid, item] = crate::bif_table::bif_args::<2>(regs);
    let pid = arinsal_sched::Pid::from_term(pid)?;
    let result = crate::natives::proc::process_info_light(process, pid, item);
    // The builder allocates on the process heap. Write the cursor back on every outcome, so an
    // executor fallback re-enters from the header with the same heap.
    match result {
        Some(Ok(term)) => {
            // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:488-523 (call_light_bif_shared,
            // ERTS_IS_GC_AFTER_BIF_DESIRED), OTP-29.1.1: a result that spilled into heap
            // fragments larger than the free young area is collected right after the BIF, with
            // the result as the only root.
            if process.heap.gc_after_bif_desired() {
                let mut result = Ok(term);
                // A value roots only itself (erl_gc.c:460-464).
                if !gc_after_plain_bif(process, &mut [], &mut result) {
                    return Some(0);
                }
                let Ok(term) = result else { return Some(0) };
                crate::bif_table::set_bif_arg(regs, 0, term);
                return Some(crate::native_hooks::raw(term));
            }
            Some(crate::native_hooks::raw(term))
        }
        _ => None,
    }
}
