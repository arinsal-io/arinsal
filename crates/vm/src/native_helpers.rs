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
    let Some((process, _registers)) = crate::native_hooks::enter_runtime(header) else {
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
    let class = empty_class
        .or(raw_class)
        .or(process.exc_class)
        .or_else(|| crate::exceptions::parse_class(process.x[3]));
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
    let Some((process, _registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let trace = crate::native_hooks::from_raw(trace_raw);
    match crate::exceptions::materialize(process, trace) {
        Ok(value) => {
            process.x[0] = value;
            crate::native_hooks::raw(value)
        }
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
    let Some((process, _registers)) = crate::native_hooks::enter_runtime(header) else {
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
    let Some((process, _registers)) = crate::native_hooks::enter_runtime(header) else {
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
    let Some((process, _registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let size = crate::native_hooks::from_raw(size).as_small();
    if process.ensure(8, 0).is_err() {
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
    let Some((process, _registers)) = crate::native_hooks::enter_runtime(header) else {
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
    if let Some((process, _registers)) = crate::native_hooks::enter_runtime(header) {
        process.bind_receive_marker(
            crate::native_hooks::from_raw(marker),
            crate::native_hooks::from_raw(reference),
        );
    }
}

/// Clears the marker of a reference (`recv_marker_clear`).
pub extern "C" fn arinsal_beamasm_recv_marker_clear(header: *mut ProcessHeader, reference: u64) {
    if let Some((process, _registers)) = crate::native_hooks::enter_runtime(header) {
        process.clear_receive_marker(crate::native_hooks::from_raw(reference));
    }
}

/// Moves the save pointer to the marker of a reference (`recv_marker_use`).
pub extern "C" fn arinsal_beamasm_recv_marker_use(header: *mut ProcessHeader, reference: u64) {
    if let Some((process, _registers)) = crate::native_hooks::enter_runtime(header) {
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
    let Some((process, _registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    // Port of erts/emulator/beam/jit/arm/instr_msg.cpp:116-118, 179, 191 (F_DELAY_GC set on
    // entry, cleared on the wait and schedule-out exits), OTP-29.1.1.
    process.delay_gc = true;
    if let Some(message) = process.inbox.get(process.inbox.save()) {
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
        && let Some(message) = process.inbox.get(process.inbox.save())
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
    let Some((process, _registers)) = crate::native_hooks::enter_runtime(header) else {
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
    if let Some((process, _registers)) = crate::native_hooks::enter_runtime(header) {
        process.loop_rec_end();
    }
}

/// Records that the process waits for a message; the scheduler puts it to sleep.
pub extern "C" fn arinsal_beamasm_wait(header: *mut ProcessHeader, resume: usize) {
    if let Some((process, _registers)) = crate::native_hooks::enter_runtime(header) {
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
    let Some((process, _registers)) = crate::native_hooks::enter_runtime(header) else {
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

/// Runs a static NIF with the arguments in `process.x`, for a dirty NIF call the executor
/// performs on a dirty scheduler, or takes the result of its dirty job. [`BOUND_NIF`]
/// resumes the call of a NIF bound by `load_nif` that the process carries.
pub(crate) fn run_static_nif(
    process: &mut crate::Process,
    identity: usize,
) -> Result<Term, crate::VmError> {
    if identity == BOUND_NIF {
        return run_bound_nif(process);
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
    let args = process.x[..usize::from(arity)].to_vec();
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
fn run_bound_nif(process: &mut crate::Process) -> Result<Term, crate::VmError> {
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
    let args = process.x.get(..arity).unwrap_or_default().to_vec();
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
    result: std::thread::Result<Result<Term, arinsal_bifs::BifError>>,
    (identity, arity): (usize, u8),
) -> u64 {
    match result {
        Ok(Ok(value)) => {
            process.x[0] = value;
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
            let args = process.x[..usize::from(arity)].to_vec();
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
pub extern "C" fn arinsal_beamasm_static_nif(header: *mut ProcessHeader, identity: u64) -> u64 {
    let Some((process, _registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
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
        crate::calls::call_bif(
            &mut process.heap,
            nif.entry,
            &process.x[..usize::from(nif.arity)],
        )
    }));
    leave_native_nif(process, result, (identity as usize, nif.arity))
}

/// Calls the NIF that `load_nif` bound to a native call-NIF body.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:863-900 (call_nif_shared loads Func and
// NifMod from the function's code) and erts/emulator/beam/jit/beam_jit_common.cpp:623-677
// (beam_jit_call_nif), OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_call_nif(header: *mut ProcessHeader, site: u64) -> u64 {
    let Some((process, _registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    // SAFETY: `site` is the address this call-NIF body was compiled with: a boxed
    // `NativeNifSite` owned by the `CompiledVersion` whose code is executing, which keeps the
    // box until it frees that code.
    let site = unsafe { &*(site as usize as *const NativeNifSite) };
    let Some(native) = site.call.get() else {
        crate::native_hooks::set_error(process, "undef");
        return 0;
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::natives::nif::call_native(
            &mut process.heap,
            native,
            &process.x[..usize::from(site.arity)],
        )
    }));
    leave_native_nif(process, result, (BOUND_NIF, site.arity))
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
) -> u64 {
    // THE_NON_VALUE raises, 1 hands the call to the interpreter, any term word is the result.
    invoke_dispatch_bif(header, identity as usize, 0, export, true).unwrap_or(1)
}

/// `call_error_handler` of the export trampoline: the export of
/// `error_handler:undefined_function/3` (the process's error handler module), with X0..X2 set
/// to the stub's module, function and argument list; zero when there is no such function.
// Port of erts/emulator/beam/beam_common.c:1294-1345 (call_error_handler), OTP-29.1.1.
pub(crate) extern "C" fn arinsal_beamasm_call_error_handler(
    header: *mut ProcessHeader,
    export: Option<ExportDispatch>,
) -> usize {
    let Some(stub) = export else {
        return 0;
    };
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
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
    if process.ensure(arity * 2, arity).is_err() {
        return 0;
    }
    let args: smallvec::SmallVec<[Term; 8]> = smallvec::SmallVec::from_slice(&process.x[..arity]);
    let Ok(list) = arinsal_term::TermBuilder::new(&mut crate::ProcessHeapHandle(&mut process.heap))
        .list_from_iter(args)
    else {
        return 0;
    };
    process.x[0] = Term::atom(stub.module_atom);
    process.x[1] = Term::atom(stub.function_atom);
    process.x[2] = list;
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
        && let Some((process, _registers)) = crate::native_hooks::enter_runtime(header)
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
) -> u64 {
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:421-447 (call_light_bif_shared's
    // dynamic_runtime_call of the BIF pointer), OTP-29.1.1: make_ref/0 and
    // unique_integer/0,1 are the BIF, not the dispatcher that selects them.
    // A traced call or a process saving calls still goes through the export.
    if let Some(export) = export
        && export.scheduler_counter.is_some()
        && !crate::trace_bp::any_pattern()
    {
        return scheduler_counter_entry(header, identity, site, export);
    }
    // `site` is only meaningful for the breakpoint trampoline.
    call_light_bif_body(header, identity, site, export)
}

/// The shared fragment's general path. Out of line so a counter BIF does not
/// pay this function's prologue.
#[inline(never)]
fn call_light_bif_body(
    header: *mut ProcessHeader,
    identity: u64,
    site: u64,
    export: Option<ExportDispatch>,
) -> u64 {
    invoke_dispatch_bif(header, identity as usize, site as usize, export, false).unwrap_or(0)
}

/// `make_ref/0` and `unique_integer/0,1` from the light-BIF fragment.
///
/// Port of erts/emulator/beam/erl_bif_unique.c:821-871, OTP-29.1.1. The fragment
/// has already stored HTOP, E and FCALLS; this only runs the BIF.
#[inline(never)]
fn scheduler_counter_entry(
    header: *mut ProcessHeader,
    identity: u64,
    site: u64,
    export: ExportDispatch,
) -> u64 {
    {
        let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
            return 0;
        };
        if registers.active_code_ix != crate::code_ix::ERTS_SAVE_CALLS_CODE_IX as u64 {
            return fast_scheduler_bif(process, registers, export, false).unwrap_or(0);
        }
    }
    call_light_bif_body(header, identity, site, Some(export))
}

/// `persistent_term:get/1` from the export's function pointer.
// Port of erts/emulator/beam/erl_bif_persistent.c:380 (`persistent_term_get_1`), OTP-29.1.1.
pub(crate) extern "C" fn persistent_term_get_1_light(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    _i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(header) else {
        return 0;
    };
    let Some(key) = process.x.first().copied() else {
        return 0;
    };
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
    _regs: *mut u64,
    _i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(header) else {
        return 0;
    };
    let Some(key) = process.x.first().copied() else {
        return 0;
    };
    let Some(default) = process.x.get(1).copied() else {
        return 0;
    };
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
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let Some(kind) = crate::trace::TraceFrameKind::from_index(kind) else {
        return 0;
    };
    let Some((event, caller)) =
        crate::trace::return_through_trace_frame(process, kind, |p, words| {
            p.heap
                .set_stack_pointer(p.heap.abi.stop.wrapping_add(words));
        })
    else {
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
    if scheduler_registers.is_null() {
        return 0;
    }
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    if !std::ptr::eq(registers, scheduler_registers) {
        return 0;
    }
    // The generated code holds FCALLS in a register; a delayed collection reads what is left.
    process.heap.abi.fcalls = fcalls;
    // The emitter passes the full checked free-space gap, including CP and
    // S_RESERVED. Process::ensure uses that gap to decide whether to collect.
    // `process.x` is the scheduler's X register array: the live prefix is rooted and moved in
    // place, as in erts_garbage_collect_nobump on `reg`.
    let result = process.ensure_uncharged(need_words, live);
    if result.is_err() {
        crate::native_hooks::set_error(process, "system_limit");
    }
    // Port of erts/emulator/beam/erl_gc.c:588-597 and 975-980 (a delayed collection
    // returns the reductions left), OTP-29.1.1: FCALLS runs out and the process yields at
    // its next reduction check.
    if process.force_yield() {
        return fcalls.max(0);
    }
    // Port of erts/emulator/beam/erl_gc.c (erts_garbage_collect_nobump), OTP-29.1.1:
    // the collection's cost, at most the reductions left, is what the generated code
    // subtracts from FCALLS.
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

/// `send` from its own fragment. A traced send, a port id, or a registered port
/// returns to the scheduler; a local pid or process name is delivered here.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:612-624 and bif.c:2458 (do_send), OTP-29.1.1.
fn dispatch_native_send(process: &mut crate::Process, saving_calls: bool) -> Option<u64> {
    if saving_calls {
        crate::trace::save_call_send_export(process);
    }
    // A port id may suspend the sender (bif.c:2581). A registered name is resolved
    // once inside the send; a port name comes back here to be redone by the scheduler.
    let target = process.x[0];
    let message = process.x[1];
    let idle = crate::trace::send_hooks_idle(process);
    let result = if (!idle && crate::trace::traces_sends(process)) || target.as_port().is_some() {
        Err(crate::VmError::Unsupported(
            crate::process::REMOTE_SEND_NEEDS_CONTEXT.into(),
        ))
    } else if target.as_atom().is_some() {
        process.send_message_native(target, message)
    } else if idle && let Some(pid) = arinsal_sched::Pid::from_term(target) {
        process.send_to_pid_idle(pid, message)
    } else {
        process.send_message(target, message)
    };
    match result {
        Ok(value) => {
            // Port of erts/emulator/beam/bif.c:2861-2864 (erl_send: ERTS_VBUMP_REDS(p, 4) after a
            // completed send) and bif.h:85 (ERTS_VBUMP_REDS), OTP-29.1.1: a send takes four
            // virtual reductions out of the slice that are not the process's own work, so a
            // sender yields to the receivers it fed after about a third of the sends.
            vbump_reds(process, 4);
            // Port of erts/emulator/beam/bif.c:2451-2452 (erl_send: save_calls(p, &exp_send)),
            // OTP-29.1.1.
            if !idle && crate::trace::saves_calls(process) {
                crate::trace::save_call(process, crate::trace::SavedCall::Send);
            }
            let raw = crate::native_hooks::raw(value);
            // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:612-624 (emit_send jumps into
            // call_light_bif_shared) and 488-523 (ERTS_IS_GC_AFTER_BIF_DESIRED), OTP-29.1.1:
            // a send that left heap fragments or virtual binary heap over its limit collects
            // with the result as the only root.
            if process.heap.gc_after_bif_desired() {
                let mut result = Ok(value);
                if !gc_after_plain_bif(process, 2, &mut result) {
                    return Some(0);
                }
                let Ok(value) = result else { return Some(0) };
                let raw = crate::native_hooks::raw(value);
                process.x[0] = crate::native_hooks::from_raw(raw);
                return Some(raw);
            }
            process.x[0] = value;
            Some(raw)
        }
        Err(crate::VmError::Unsupported(message))
            if message == crate::process::REMOTE_SEND_NEEDS_CONTEXT =>
        {
            if crate::trace::saves_calls(process) {
                crate::trace::save_call(process, crate::trace::SavedCall::Send);
            }
            process.heap.abi.arity = 2;
            process.heap.abi.i =
                arinsal_beamasm::dispatch::SEND_DISPATCH_IDENTITY as *const u8 as *const _;
            process.heap.abi.exc.freason = 1 << 10;
            None
        }
        Err(_) => {
            crate::native_hooks::set_error(process, "badarg");
            Some(0)
        }
    }
}

/// Prepares the live X registers and handler arguments for a native line-breakpoint call.
// Port of erts/emulator/beam/beam_bp.c:1821-1865
// (erts_line_breakpoint_hit__prepare_call), OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_line_breakpoint_prepare(
    header: *mut ProcessHeader,
    pc: u64,
    live: u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
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
    let Some(runtime) = process.runtime.as_ref() else {
        return 0;
    };
    let Some(export) = crate::beamasm_integration::line_breakpoint_export(
        runtime.code_scope,
        registers.active_code_ix as usize,
    ) else {
        return 0;
    };

    for index in 0..live {
        if !process.heap.stack_set(index, process.x[index]) {
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
    process.x[..4].copy_from_slice(&args);
    process.heap.abi.arity = 4;
    export as *const arinsal_beamasm::bif::ExportEntry as usize as u64
}

/// Restores the live X register prefix from the stack below a returning breakpoint handler.
// Port of erts/emulator/beam/beam_bp.c:1868-1882
// (erts_line_breakpoint_hit__cleanup), OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_line_breakpoint_cleanup(header: *mut ProcessHeader) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
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
/// has one function pointer, chosen when the export is created. Bodies that are
/// their own C function come from [`crate::bif_table::special`]. Every other BIF
/// uses the adapter for its kind. None of those pointers enter `invoke_dispatch_bif`.
pub(crate) fn light_entry(export: ExportDispatch) -> Option<usize> {
    if let Some(func) = crate::bif_table::special(&export.module, &export.function, export.arity) {
        return Some(func);
    }
    // `trap_entry` clears `light_bif`, but keyfind/member/++/-- still run the
    // plain body and trap only when the slice counter runs out. The export
    // fragment calls this pointer directly, so the slice check has to be here
    // rather than only in `invoke_dispatch_bif`.
    if export.list_slice {
        if matches!(
            (
                export.module.as_str(),
                export.function.as_str(),
                export.arity
            ),
            ("erlang", "++" | "append", 2)
        ) && let Some(entry) =
            crate::bif_table::append_entry(&export.module, &export.function, export.arity)
        {
            return Some(entry);
        }
        let own = crate::bif_table::entry(&export.module, &export.function, export.arity);
        if crate::bif_table::never_allocates(&export.module, &export.function, export.arity) {
            return Some(own.map_or(crate::bif_table::bif!(plain_bif_light), |e| {
                e.list_slice_nonalloc
            }));
        }
        return Some(own.map_or(crate::bif_table::bif!(plain_bif_light), |e| e.list_slice));
    }
    // The kind is fixed when the export is created (`bif_table[].f`). The call
    // fragment branches to that pointer; it does not walk `invoke_dispatch_bif`.
    if export.light_bif.is_some() {
        let own = crate::bif_table::entry(&export.module, &export.function, export.arity);
        return Some(own.map_or(crate::bif_table::bif!(plain_bif_light), |e| e.plain));
    }
    if export.light_process_bif.is_some() {
        return Some(
            crate::natives::thin_entry(&export.module, &export.function, export.arity)
                .unwrap_or(crate::bif_table::bif!(process_bif_light)),
        );
    }
    if export.direct_ets.is_some() {
        return Some(crate::bif_table::bif!(direct_bif_light));
    }
    if export.light_trap_bif.is_some() {
        if let Some(func) =
            crate::bif_table::trap_entry(&export.module, &export.function, export.arity)
        {
            return Some(func);
        }
        return Some(crate::bif_table::bif!(trap_bif_light));
    }
    let bif = export.bif.is_some()
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

/// `process_flag(trap_exit, Bool)` without leaving native code.
///
/// Port of erts/emulator/beam/bif.c (`process_flag_2`, the `trap_exit` arm), OTP-29.1.1.
/// Any other flag is `BIF_TRAP`: the executor runs `process_flag_2`.
pub(crate) extern "C" fn process_flag_light(
    header: *mut ProcessHeader,
    regs: *mut u64,
    i: u64,
) -> u64 {
    if let Some(raw) = trap_exit_flag(header, regs) {
        return raw;
    }
    // `save_calls` must return in this native invocation. Trapping to the executor
    // re-enters with `ERTS_SAVE_CALLS_CODE_IX` before the next call, which erts does
    // not record (bif.c:1936, the BIF returns and the code index changes at the next
    // schedule). FCALLS is already 0, so the next BIF's reduction check yields.
    if let Some(raw) = save_calls_flag_light(header, regs) {
        return raw;
    }
    if let Some(raw) = process_flag_ctxfree_light(header) {
        return raw;
    }
    yield_executor_bif(header, regs, i)
}

/// `process_flag/2` for the flags that need no scheduler context.
fn process_flag_ctxfree_light(header: *mut ProcessHeader) -> Option<u64> {
    let (process, _) = crate::native_hooks::enter_runtime(header)?;
    let (name, value) = (process.x[0], process.x[1]);
    let previous = crate::natives::proc::process_flag_ctxfree(process, name, value)?;
    process.x[0] = previous;
    Some(crate::native_hooks::raw(previous))
}

/// `erlang:self/0`. `c_p->common.id`, already the tagged pid on the header.
// Port of erts/emulator/beam/bif.c (`self_0`), OTP-29.1.1.
pub(crate) extern "C" fn self_light(header: *mut ProcessHeader, _regs: *mut u64, _i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(header) else {
        return 0;
    };
    process.heap.abi.self_pid
}

/// `erlang:send_after/3,4` (`SEND_AFTER`) and `erlang:start_timer/3,4` from the light-BIF
/// fragment. The timer is started on the calling scheduler's wheel; anything the fast path
/// declines (bad arguments, a thread without a normal scheduler) is redone by the executor.
// Port of erts/emulator/beam/erl_hl_timer.c:1804-1850 (erts_create_bif_timer reaches the wheel
// of `esdp`), OTP-29.1.1.
pub(crate) extern "C" fn timer_start_light<const SEND_AFTER: bool>(
    header: *mut ProcessHeader,
    regs: *mut u64,
    i: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (descriptor, _identity) = crate::bif_table::current_export(header);
    if let Some(raw) = timer_start_native(header, descriptor, SEND_AFTER) {
        return raw;
    }
    yield_executor_bif(header, regs, i)
}

fn timer_start_native(
    header: *mut ProcessHeader,
    descriptor: u64,
    send_after: bool,
) -> Option<u64> {
    let (process, _) = crate::native_hooks::enter_runtime(header)?;
    let export = crate::beamasm_integration::export_from_info(descriptor)?;
    let arity = usize::from(export.arity);
    let mut args = [Term::NIL; 4];
    args[..arity].copy_from_slice(&process.x[..arity]);
    let mut sink = crate::signals::NativeTimers(process.self_pid?, process.native_handle());
    let term =
        crate::signals::start_timer_bif(process, &mut sink, &args[..arity], send_after).ok()?;
    process.x[0] = term;
    Some(crate::native_hooks::raw(term))
}

/// `erlang:cancel_timer/1,2` (`CANCEL`) and `erlang:read_timer/1,2` from the light-BIF fragment.
/// The synchronous form answers here when the timer lives on the calling scheduler's wheel;
/// when another scheduler owns it the caller waits for the reply in the executor, and the
/// asynchronous form is the executor's.
// Port of erts/emulator/beam/erl_hl_timer.c:2083-2200 (bif_timer_access_request,
// erts_cancel_bif_timer / erts_read_bif_timer), OTP-29.1.1.
pub(crate) extern "C" fn timer_query_light<const CANCEL: bool>(
    header: *mut ProcessHeader,
    regs: *mut u64,
    i: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (descriptor, _identity) = crate::bif_table::current_export(header);
    if let Some(raw) = timer_query_native(header, descriptor, CANCEL) {
        return raw;
    }
    yield_executor_bif(header, regs, i)
}

fn timer_query_native(header: *mut ProcessHeader, descriptor: u64, cancel: bool) -> Option<u64> {
    let (process, _) = crate::native_hooks::enter_runtime(header)?;
    let export = crate::beamasm_integration::export_from_info(descriptor)?;
    let info = if export.arity == 2 {
        let options = crate::signals::timer_query_options(process.x[1], cancel).ok()?;
        if options.asynchronous {
            return None;
        }
        options.info
    } else {
        true
    };
    let reference = process.x[0];
    // Port of erts/emulator/beam/erl_hl_timer.c:2237 (access_bif_timer): a reference made on
    // this scheduler names a timer on its own wheel, which answers without any request.
    if let Some(key) = crate::signals::ref_id(reference)
        && let Some(remaining) = process
            .native_handle()
            .and_then(|handle| handle.access_timer(key, cancel))
    {
        let term = if !info {
            Term::atom(arinsal_term::atoms::OK)
        } else {
            remaining
                .and_then(|ms| Term::small(ms as i64))
                .unwrap_or_else(|| Term::atom(arinsal_term::atoms::FALSE))
        };
        process.x[0] = term;
        return Some(crate::native_hooks::raw(term));
    }
    let term = crate::signals::timer_query_sync(
        process,
        process.self_pid?,
        reference,
        cancel,
        info,
        false,
    )
    .ok()?;
    process.x[0] = term;
    Some(crate::native_hooks::raw(term))
}

/// `erlang:group_leader/0`: the calling process's group leader, an immediate pid.
// Port of erts/emulator/beam/bif.c (`group_leader_0`: `BIF_RET(BIF_P->group_leader)`),
// OTP-29.1.1.
pub(crate) extern "C" fn group_leader_0_light(
    header: *mut ProcessHeader,
    regs: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(header) else {
        return 0;
    };
    if let Some(pid) = process.self_pid
        && let Some(leader) = process.group_leader_pid(pid).to_term()
    {
        return crate::native_hooks::raw(leader);
    }
    yield_executor_bif(header, regs, i)
}

/// `erlang:node/0`.
// Port of erts/emulator/beam/dist.c:6230 (`node_0`), OTP-29.1.1.
pub(crate) extern "C" fn node_light(_header: *mut ProcessHeader, _regs: *mut u64, _i: u64) -> u64 {
    crate::native_hooks::raw(crate::natives::node::node_0_term())
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
    let Some((process, _)) = crate::native_hooks::enter_runtime(header) else {
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

fn save_calls_flag_light(header: *mut ProcessHeader, regs: *mut u64) -> Option<u64> {
    if regs.is_null() {
        return None;
    }
    let process = crate::native_hooks::process_from_header(header)?;
    let name = process.x.first().copied()?;
    if name != save_calls_atom() {
        return None;
    }
    let value = process.x.get(1).copied()?;
    match crate::natives::proc::save_calls_flag(process, value) {
        Ok(term) => Some(crate::native_hooks::raw(term)),
        Err(_) => {
            crate::native_hooks::set_error(process, "badarg");
            Some(0)
        }
    }
}

fn save_calls_atom() -> Term {
    static ATOM: std::sync::OnceLock<Term> = std::sync::OnceLock::new();
    *ATOM.get_or_init(|| {
        Term::atom(
            arinsal_term::global_atoms()
                .intern("save_calls")
                .expect("save_calls"),
        )
    })
}

fn trap_exit_flag(header: *mut ProcessHeader, regs: *mut u64) -> Option<u64> {
    if regs.is_null() {
        return None;
    }
    // `reg[0]` and `reg[1]` are BIF_ARG_1 and BIF_ARG_2. The scheduler file is
    // that array for the duration of native code (`x_reg`).
    let process = crate::native_hooks::process_from_header(header)?;
    let name = process.x.first().copied()?;
    let value = process.x.get(1).copied()?;
    if name != trap_exit_atom() {
        return None;
    }
    let enabled = if value == bool_atom(true) {
        true
    } else if value == bool_atom(false) {
        false
    } else {
        return None;
    };
    let old = process.trap_exit;
    process.trap_exit = enabled;
    Some(crate::native_hooks::raw(bool_atom(old)))
}

fn bool_atom(value: bool) -> Term {
    Term::atom(if value {
        arinsal_term::atoms::TRUE
    } else {
        arinsal_term::atoms::FALSE
    })
}

/// `atom_to_list/1` as the BIF `call_light_bif_shared` branches to.
// Port of erts/emulator/beam/bif.c:3186-3210 (`atom_to_list_1`) and
// erl_unicode.c:1388-1395 (`erts_atom_to_string`: latin1 names are
// `buf_to_intlist` of the atom bytes), OTP-29.1.1.
pub(crate) extern "C" fn atom_to_list_light(
    header: *mut ProcessHeader,
    regs: *mut u64,
    _i: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (descriptor, _) = crate::bif_table::current_export(header);
    if let Some(raw) = atom_to_list_latin1(header) {
        return raw;
    }
    allocating_bif(header, regs, descriptor, 1, |heap, arg| {
        arinsal_bifs::atom_to_list_term(heap, arg)
    })
}

/// ASCII / single-byte latin1: one `HAlloc` and `buf_to_intlist`. `None` is a
/// non-atom, a multi-byte name, or a heap that needs a fragment.
fn atom_to_list_latin1(header: *mut ProcessHeader) -> Option<u64> {
    let process = crate::native_hooks::process_from_header(header)?;
    let arg = process.x.first().copied()?;
    let text = arinsal_term::global_atoms().text(arg.as_atom()?)?;
    let bytes = text.as_bytes();
    // Atoms are stored as UTF-8. `latin1_chars == len` is exactly the
    // single-byte case: each byte is already the code point, so
    // `buf_to_intlist` matches `erts_utf8_to_list`.
    if bytes.iter().any(|byte| *byte >= 0x80) {
        return None;
    }
    if bytes.is_empty() {
        return Some(crate::native_hooks::raw(Term::NIL));
    }
    // The fragment stored HTOP. Commit it so `HAlloc` bumps the same index,
    // then publish the new pointer for `emit_leave_runtime`.
    let term = arinsal_term::TermBuilder::new(&mut process.heap)
        .byte_string_list(bytes)
        .ok()?;
    Some(crate::native_hooks::raw(term))
}

/// `integer_to_binary/1` as the BIF `call_light_bif_shared` branches to.
// Port of erts/emulator/beam/binary.c:80-127 (integer_to_binary), OTP-29.1.1.
pub(crate) extern "C" fn integer_to_binary_light(
    header: *mut ProcessHeader,
    regs: *mut u64,
    _i: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (descriptor, _) = crate::bif_table::current_export(header);
    allocating_bif(header, regs, descriptor, 1, |heap, arg| {
        arinsal_arith::integer_to_binary_decimal(arg, heap).map_err(arith_bif_error)
    })
}

fn binary_guard_apply(
    process: &mut crate::Process,
    guard: crate::bif_table::BinaryGuard,
    args: &[Term],
) -> Result<Term, arinsal_bifs::BifError> {
    use crate::bif_table::BinaryGuard;
    match guard {
        BinaryGuard::ByteSize | BinaryGuard::BitSize => {
            let bits = arinsal_bifs::bitstring_bit_len(args[0])?;
            let value = if matches!(guard, BinaryGuard::ByteSize) {
                bits.div_ceil(8)
            } else {
                bits
            };
            let mut fragment = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
            arinsal_term::TermBuilder::new(&mut fragment)
                .int_from_u64(value as u64)
                .map_err(|_| arinsal_bifs::BifError::SystemLimit)
        }
        BinaryGuard::BinaryPart3 => binary_part_3_apply(process, args),
        BinaryGuard::BinaryPart2 => {
            let (result, reductions) = {
                let mut fragment = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
                let mut call = arinsal_bifs::BifCall::default();
                let mut ctx = arinsal_bifs::Ctx::new(&mut fragment, &mut call);
                let result = arinsal_bifs::binary_part_2(&mut ctx, args);
                (result, ctx.reductions())
            };
            charge_bif_reductions(process, reductions);
            result
        }
    }
}

// Port of erts/emulator/beam/erl_bif_binary.c:1954-2038 (`erts_binary_part`), OTP-29.1.1.
fn binary_part_3_apply(
    process: &mut crate::Process,
    args: &[Term],
) -> Result<Term, arinsal_bifs::BifError> {
    let mut position = args[1]
        .as_small()
        .ok_or(arinsal_bifs::BifError::Badarg { cause: None })?;
    let mut length = args[2]
        .as_small()
        .ok_or(arinsal_bifs::BifError::Badarg { cause: None })?;
    if length < 0 {
        length = length
            .checked_neg()
            .ok_or(arinsal_bifs::BifError::Badarg { cause: None })?;
        if length > position {
            return Err(arinsal_bifs::BifError::Badarg { cause: None });
        }
        position -= length;
    }
    if position < 0 || length < 0 || position.checked_add(length).is_none() {
        return Err(arinsal_bifs::BifError::Badarg { cause: None });
    }
    let start = usize::try_from(position)
        .ok()
        .and_then(|value| value.checked_mul(8))
        .ok_or(arinsal_bifs::BifError::Badarg { cause: None })?;
    let length = usize::try_from(length)
        .ok()
        .and_then(|value| value.checked_mul(8))
        .ok_or(arinsal_bifs::BifError::Badarg { cause: None })?;
    let mut fragment = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    arinsal_term::TermBuilder::new(&mut fragment)
        .sub_binary_bif(args[0], start, length)
        .map_err(|error| match error {
            arinsal_term::TermError::BadArg => arinsal_bifs::BifError::Badarg { cause: None },
            _ => arinsal_bifs::BifError::SystemLimit,
        })
}

fn binary_guard_result(
    process: &mut crate::Process,
    export: ExportDispatch,
    guard: crate::bif_table::BinaryGuard,
    args: &[Term],
    light: bool,
) -> u64 {
    let result = binary_guard_apply(process, guard, args);
    match result {
        Ok(value) => {
            if light {
                process.x[0] = value;
            }
            crate::native_hooks::raw(value)
        }
        Err(error) => {
            set_native_bif_export_error(process, export, args, error);
            0
        }
    }
}

fn binary_guard_light(
    header: *mut ProcessHeader,
    descriptor: u64,
    guard: crate::bif_table::BinaryGuard,
    arity: usize,
) -> u64 {
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    let Some((process, _)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let mut args = [Term::NIL; 3];
    args[..arity].copy_from_slice(&process.x[..arity]);
    binary_guard_result(process, export, guard, &args[..arity], true)
}

/// `i_bif*` entry of a binary guard: the guard kind is the function, bound at load time.
fn binary_guard_i_bif(
    header: *mut ProcessHeader,
    export: Option<ExportDispatch>,
    guard: crate::bif_table::BinaryGuard,
    arity: usize,
    args: [u64; 3],
) -> u64 {
    let Some(export) = export else {
        return 0;
    };
    let Some((process, _)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let args = args.map(crate::native_hooks::from_raw);
    binary_guard_result(process, export, guard, &args[..arity], false)
}

macro_rules! binary_guard_i_bif {
    ($(#[$doc:meta])* $name:ident, $guard:ident, $arity:literal) => {
        $(#[$doc])*
        pub(crate) extern "C" fn $name(
            header: *mut ProcessHeader,
            export: Option<ExportDispatch>,
            first: u64,
            second: u64,
            third: u64,
        ) -> u64 {
            binary_guard_i_bif(
                header,
                export,
                crate::bif_table::BinaryGuard::$guard,
                $arity,
                [first, second, third],
            )
        }
    };
}

binary_guard_i_bif!(
    /// `i_bif1` of `byte_size/1`.
    // Port of erts/emulator/beam/erl_bif_guard.c:376 (`byte_size_1`), OTP-29.1.1.
    byte_size_guard, ByteSize, 1
);
binary_guard_i_bif!(
    /// `i_bif1` of `bit_size/1`.
    // Port of erts/emulator/beam/erl_bif_guard.c:354 (`bit_size_1`), OTP-29.1.1.
    bit_size_guard, BitSize, 1
);
binary_guard_i_bif!(
    /// `i_bif2` of `binary_part/2`.
    // Port of erts/emulator/beam/erl_bif_binary.c:1954-2038 (`erts_binary_part`), OTP-29.1.1.
    binary_part_2_guard, BinaryPart2, 2
);
binary_guard_i_bif!(
    /// `i_bif3` of `binary_part/3`.
    // Port of erts/emulator/beam/erl_bif_binary.c:1954-2038 (`erts_binary_part`), OTP-29.1.1.
    binary_part_3_guard, BinaryPart3, 3
);

/// Dedicated BeamAsm entry for `byte_size/1` and its guard form.
// Port of erts/emulator/beam/erl_bif_guard.c:376 (`byte_size_1`), OTP-29.1.1.
pub(crate) extern "C" fn byte_size_light(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    _i: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (descriptor, _) = crate::bif_table::current_export(header);
    binary_guard_light(
        header,
        descriptor,
        crate::bif_table::BinaryGuard::ByteSize,
        1,
    )
}

/// Dedicated BeamAsm entry for `bit_size/1` and its guard form.
// Port of erts/emulator/beam/erl_bif_guard.c:354 (`bit_size_1`), OTP-29.1.1.
pub(crate) extern "C" fn bit_size_light(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    _i: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (descriptor, _) = crate::bif_table::current_export(header);
    binary_guard_light(
        header,
        descriptor,
        crate::bif_table::BinaryGuard::BitSize,
        1,
    )
}

/// Dedicated BeamAsm entry for `binary_part/2` and `binary:part/2`.
// Port of erts/emulator/beam/erl_bif_binary.c:1954-2038 (`erts_binary_part`), OTP-29.1.1.
pub(crate) extern "C" fn binary_part_2_light(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    _i: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (descriptor, _) = crate::bif_table::current_export(header);
    binary_guard_light(
        header,
        descriptor,
        crate::bif_table::BinaryGuard::BinaryPart2,
        2,
    )
}

/// Dedicated BeamAsm entry for `binary_part/3` and `binary:part/3`.
// Port of erts/emulator/beam/erl_bif_binary.c:1954-2038 (`erts_binary_part`), OTP-29.1.1.
pub(crate) extern "C" fn binary_part_3_light(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    _i: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (descriptor, _) = crate::bif_table::current_export(header);
    let Some((process, _)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let args = [process.x[0], process.x[1], process.x[2]];
    let result = binary_part_3_apply(process, &args);
    match result {
        Ok(value) => {
            process.x[0] = value;
            crate::native_hooks::raw(value)
        }
        Err(error) => {
            let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
                return 0;
            };
            set_native_bif_export_error(process, export, &args, error);
            0
        }
    }
}

/// Sync the native cursors, run an allocating BIF, and publish HTOP.
fn allocating_bif(
    header: *mut ProcessHeader,
    regs: *mut u64,
    descriptor: u64,
    arity: usize,
    body: impl FnOnce(
        &mut arinsal_bifs::ProcessHeapHandle<'_>,
        Term,
    ) -> Result<Term, arinsal_bifs::BifError>,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    // The caller (call_light_bif or the export fragment) already charged FCALLS.
    // reg[0] is BIF_ARG_1, whether the fragment passed `regs` or left it in the
    // scheduler file `enter_runtime` already resolved.
    let _ = regs;
    let arg = process.x[0];
    let result = {
        let mut fragment = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        body(&mut fragment, arg)
    };
    // The light fragment tests the collection after this call (instr_bif.cpp:488-523).
    if let Ok(value) = &result {
        let value = *value;
        process.x[0] = value;
        return crate::native_hooks::raw(value);
    }
    // The fragment passed `Export.info`; the descriptor is the export, so no table lookup.
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        crate::native_hooks::set_error(process, "badarg");
        return 0;
    };
    plain_bif_result(process, registers, export, arity, result)
}

fn arith_bif_error(error: arinsal_arith::ArithError) -> arinsal_bifs::BifError {
    match error {
        arinsal_arith::ArithError::Badarg | arinsal_arith::ArithError::Badarith => {
            arinsal_bifs::BifError::BADARG
        }
        arinsal_arith::ArithError::SystemLimit | arinsal_arith::ArithError::HeapFull { .. } => {
            arinsal_bifs::BifError::SystemLimit
        }
    }
}

fn trap_exit_atom() -> Term {
    static ATOM: std::sync::OnceLock<Term> = std::sync::OnceLock::new();
    *ATOM.get_or_init(|| {
        Term::atom(
            arinsal_term::global_atoms()
                .intern("trap_exit")
                .expect("trap_exit"),
        )
    })
}

/// `setelement/3`: one bump and a copy of the tuple.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:151-166 (emit_i_bif) and
// erts/emulator/beam/bif.c:2976-3003 (setelement_3), OTP-29.1.1.
pub(crate) extern "C" fn setelement_light(
    header: *mut ProcessHeader,
    regs: *mut u64,
    i: u64,
) -> u64 {
    match setelement_write(header, regs) {
        Some(raw) => raw,
        None => plain_bif_light(header, regs, i),
    }
}

/// `Some` is the new tuple. `None` sends errors through the generic BIF body.
fn setelement_write(header: *mut ProcessHeader, regs: *mut u64) -> Option<u64> {
    if header.is_null() || regs.is_null() {
        return None;
    }
    // SAFETY: reg[0..2] are BIF_ARG_1..3. A tuple's header is the word at the
    // untagged pointer. HTOP was stored by `emit_enter_runtime`.
    unsafe {
        let index = crate::native_hooks::from_raw(*regs);
        let tuple = crate::native_hooks::from_raw(*regs.add(1));
        let value = *regs.add(2);
        let ix = index.as_small().filter(|ix| *ix >= 1)?;
        let hdr = tuple.header()?;
        if hdr & 63 != 0 {
            return None;
        }
        let arity = (hdr >> 6) as usize;
        let slot = ix as usize;
        if slot > arity {
            return None;
        }
        let src = tuple.raw_ptr();
        let size = arity + 1;
        let process = &mut *header.cast::<crate::Process>();
        let htop = process.heap.abi.htop;
        let stop = process.heap.abi.stop;
        let top = htop as usize;
        let limit = (stop as usize).saturating_sub(arinsal_term::S_REDZONE * 8);
        if htop.is_null() || stop.is_null() || top.saturating_add(size.saturating_mul(8)) > limit {
            return None;
        }
        std::ptr::copy_nonoverlapping(src, htop, size);
        htop.add(slot).write(value);
        let next = htop.add(size);
        process.heap.abi.htop = next;
        Some((htop as u64) | 2)
    }
}

/// `make_ref/0`. `HAlloc` of three words and `esdp->ref++`, then the term.
// Port of erts/emulator/beam/erl_bif_unique.c:821-833 (`make_ref_0`) and
// erl_bif_unique.h:190-198 (`erts_sched_make_ref_in_buffer`), OTP-29.1.1.
pub(crate) extern "C" fn make_ref_light(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    _i: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (descriptor, _) = crate::bif_table::current_export(header);
    if header.is_null() {
        return 0;
    }
    // SAFETY: the light-BIF fragment passes c_p. HTOP and E were stored by
    // `emit_enter_runtime`. The reference cell belongs to this scheduler thread.
    unsafe {
        let process = &mut *header.cast::<crate::Process>();
        let htop = process.heap.abi.htop;
        let stop = process.heap.abi.stop;
        let top = htop as usize;
        let limit = (stop as usize).saturating_sub(arinsal_term::S_REDZONE * 8);
        let Some(state) = process.scheduler_ref_state else {
            return make_ref_cold(header, descriptor);
        };
        if htop.is_null() || stop.is_null() || top.saturating_add(24) > limit {
            return make_ref_cold(header, descriptor);
        }
        let ids = state.bump_ref_words();
        // ErtsORefThing: header, then the three 32-bit numbers packed as
        // `Term::local_ref` writes them.
        *htop = (2 << 6) | 0x10;
        *htop.add(1) = ((ids[0] as u64) << 32) | 0xffff_ffff;
        *htop.add(2) = ((ids[2] as u64) << 32) | (ids[1] as u64);
        let next = htop.add(3);
        process.heap.abi.htop = next;
        (htop as u64) | 2
    }
}

#[cold]
fn make_ref_cold(header: *mut ProcessHeader, descriptor: u64) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    make_ref_0(process, registers, export, false)
}

/// `unique_integer/0` from the export's function pointer.
pub(crate) extern "C" fn unique_integer_0_light(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    _i: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (descriptor, _) = crate::bif_table::current_export(header);
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    unique_integer_n(process, registers, export, false, &[])
}

/// `unique_integer/1` from the export's function pointer.
pub(crate) extern "C" fn unique_integer_1_light(
    header: *mut ProcessHeader,
    regs: *mut u64,
    _i: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (descriptor, _) = crate::bif_table::current_export(header);
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    let _ = regs;
    let arg = process.x[0];
    unique_integer_n(process, registers, export, false, &[arg])
}

/// A plain BIF: call `bif_table[].f` and return. Trace and save_calls already
/// branched to the helper in the fragment.
// Port of erts/emulator/beam/beam_jit_common.cpp:588-621 (`beam_jit_call_bif`), OTP-29.1.1.
pub(crate) extern "C" fn plain_bif_light(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    _i: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (descriptor, identity) = crate::bif_table::current_export(header);
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    // The fragment loaded `Export.info` into this argument, so the slot is not hashed.
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    // `lists:member/2`, `keyfind/3` and the other slice BIFs are this same body
    // (`erl_bif_lists.c` `lists_member_2` / `keyfind`). The light entry used to
    // scan without `ERTS_BIF_REDS_LEFT` and never trap.
    if export.list_slice
        && let Some(bif) = export.bif
    {
        return call_list_slice_bif(process, registers, identity as usize, export, bif, false)
            .unwrap_or(0);
    }
    let Some(bif) = export.light_bif else {
        return park_executor(process, export, identity, false);
    };
    call_plain_bif(process, registers, identity as usize, export, bif, false)
}

/// `bif_table[].f` of one plain BIF: the body is this entry's own callee.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:434-445 (`dynamic_runtime_call<3>(ARG8)`
// calls `BIF(c_p, reg, I)` of that one BIF), OTP-29.1.1.
pub(crate) extern "C" fn plain_bif_entry<B: arinsal_bifs::BifBody>(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    instruction: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (descriptor, identity) = crate::bif_table::current_export(header);
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    call_plain_bif_word(
        process,
        registers,
        identity as usize,
        export,
        |process, args| B::call_word(process, args, instruction as usize),
    )
}

/// `bif_table[].f` of one list BIF that traps on the reduction budget
/// (`lists_member_2`, `keyfind`, ...).
// Port of erts/emulator/beam/erl_bif_lists.c:1108,1302 (the BIF runs with
// `ERTS_BIF_REDS_LEFT` and `BIF_TRAP`s through its export), OTP-29.1.1.
/// A list BIF that never allocates (`lists:keyfind/3`, `member/2`, `keymember/3`): the common
/// call reads the arguments and returns without converting the native heap cursors, as erts
/// reads HTOP and STOP as pointers. A trap, an error or a deferred scan converts them and
/// takes the full path.
// Port of erts/emulator/beam/erl_bif_lists.c:1108,1302 (the BIF runs with ERTS_BIF_REDS_LEFT
// and returns its value), OTP-29.1.1.
pub(crate) extern "C" fn list_slice_nonalloc_entry<B: arinsal_bifs::BifBody>(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    _i: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (descriptor, identity) = crate::bif_table::current_export(header);
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    if let Some(raw) = nonalloc_list_fast(process, export, B::call) {
        return raw;
    }
    call_list_slice_bif(
        process,
        registers,
        identity as usize,
        export,
        B::call,
        false,
    )
    .unwrap_or(0)
}

/// `lists:member/2`'s BIF-table entry. The successful call needs no export lookup.
// Port of erts/emulator/beam/erl_bif_lists.c:1108-1142 and bif.h:71-84, OTP-29.1.1.
pub(crate) extern "C" fn list_member_entry(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    _i: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (descriptor, identity) = crate::bif_table::current_export(header);
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let args = [process.x[0], process.x[1]];
    let (result, deferred) = {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        let mut call = arinsal_bifs::BifCall::default();
        let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut call);
        let result = arinsal_bifs::lists_member_bif(&mut ctx, &args);
        (result, ctx.take_deferred())
    };
    if let Some(trap) = deferred {
        let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
            return 0;
        };
        if crate::bif_traps::install_deferred_trap(
            process,
            identity as usize,
            (export.module_atom, export.function_atom),
            export.function.as_str(),
            &args,
            trap,
        )
        .is_err()
        {
            crate::native_hooks::set_error(process, "system_limit");
            return 0;
        }
        debug_assert_native_heap(process);
        crate::bif_traps::arm_export_trap(process);
        process.heap.abi.exc.freason = 1 << 10;
        return 0;
    }
    match result {
        Ok(value) => {
            process.x[0] = value;
            crate::native_hooks::raw(value)
        }
        Err(error) => {
            let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
                return 0;
            };
            plain_bif_result(process, registers, export, 2, Err(error))
        }
    }
}

/// The value of a non-allocating list BIF, or `None` when it traps or fails (the caller then
/// converts the cursors and runs the full path).
#[inline(always)]
fn nonalloc_list_fast(
    process: &mut crate::Process,
    export: ExportDispatch,
    bif: impl Fn(&mut arinsal_bifs::Ctx<'_>, &[Term]) -> Result<Term, arinsal_bifs::BifError>,
) -> Option<u64> {
    let arity = usize::from(export.arity);
    let value = {
        let mut fragment = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        let mut call = arinsal_bifs::BifCall::default();
        let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut fragment, &mut call);
        let result = bif(&mut ctx, &process.x[..arity]);
        if ctx.take_deferred().is_some() {
            return None;
        }
        result.ok()?
    };
    process.x[0] = value;
    Some(crate::native_hooks::raw(value))
}

pub(crate) extern "C" fn list_slice_bif_entry<B: arinsal_bifs::BifBody>(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    _i: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (descriptor, identity) = crate::bif_table::current_export(header);
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    call_list_slice_bif(
        process,
        registers,
        identity as usize,
        export,
        B::call,
        false,
    )
    .unwrap_or(0)
}

/// `erlang:'++'/2`: the on-heap copy runs first, straight on the young heap; everything else
/// takes the general list BIF entry.
pub(crate) extern "C" fn list_append_entry<B: arinsal_bifs::BifBody>(
    header: *mut ProcessHeader,
    regs: *mut u64,
    i: u64,
) -> u64 {
    if let Some((process, _)) = crate::native_hooks::enter_runtime(header)
        && let Some(value) =
            arinsal_bifs::append_onheap_direct(&mut process.heap, process.x[0], process.x[1])
    {
        return crate::native_hooks::raw(value);
    }
    list_slice_bif_entry::<B>(header, regs, i)
}

/// A process BIF (`c_p` plus the register array), chosen when the export was created.
pub(crate) extern "C" fn process_bif_light(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    _i: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (descriptor, identity) = crate::bif_table::current_export(header);
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    let Some(bif) = export.light_process_bif else {
        return park_executor(process, export, identity, false);
    };
    match call_process_bif(process, registers, export, bif, false, identity as usize) {
        Some(raw) => raw,
        // The entry declined before any side effect: the executor runs the whole BIF.
        None => park_executor(process, export, identity, false),
    }
}

/// `send_3`'s local fast path returns in registers; only a declined call enters the executor.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-471 (call_light_bif_shared), OTP-29.1.1.
pub(crate) extern "C" fn send3_bif_light(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    _i: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (descriptor, identity) = crate::bif_table::current_export(header);
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let args = &registers.x_reg_array[..3];
    if crate::signals::send3_light_eligible(process, args) {
        return match crate::signals::send3_light_call(process, args) {
            Ok(value) => {
                process.x[0] = value;
                crate::native_hooks::raw(value)
            }
            Err(trap) => thin_bif_failed(process, registers, descriptor, *trap, identity as usize),
        };
    }
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    park_executor(process, export, identity, false)
}

/// A process BIF whose success path returns in registers: no `Result<Term, Trap>` is moved
/// unless the BIF fails, and the export is not read unless it does.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-471 (call_light_bif_shared), OTP-29.1.1:
// the BIF is called with `c_p` and the X registers, a value returns in x0 and `THE_NON_VALUE`
// is the error path.
pub(crate) extern "C" fn thin_bif_light<B: crate::natives::ThinProcessBif>(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    _i: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (descriptor, identity) = crate::bif_table::current_export(header);
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    match B::call(process, &registers.x_reg_array[..B::ARITY]) {
        Ok(value) => {
            process.x[0] = value;
            crate::native_hooks::raw(value)
        }
        Err(trap) => thin_bif_failed(process, registers, descriptor, *trap, identity as usize),
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
    identity: usize,
) -> u64 {
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    process_bif_result(
        process,
        export,
        usize::from(export.arity),
        Err(trap),
        identity,
    )
}

/// An ETS or process-dictionary BIF whose body is `direct_ets`.
pub(crate) extern "C" fn direct_bif_light(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    _i: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (descriptor, identity) = crate::bif_table::current_export(header);
    let Some((process, _)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    if let Some(raw) = call_direct_bif(process, export, false) {
        return raw;
    }
    process.heap.abi.arity = export.arity;
    process.heap.abi.i = identity as *const u8 as *const _;
    process.heap.abi.exc.freason = 1 << 10;
    0
}

/// A trapping BIF. A value returns here; a trap is `THE_NON_VALUE`.
pub(crate) extern "C" fn trap_bif_light(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    _i: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (descriptor, identity) = crate::bif_table::current_export(header);
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    let Some(entry) = export.light_trap_bif else {
        return park_executor(process, export, identity, false);
    };
    call_trap_bif(process, registers, identity as usize, export, entry, false).unwrap_or(0)
}

// `export_call`: reached through an export entry, whose BIF trampoline charges the call one
// reduction (erts/emulator/beam/jit/arm/instr_bif.cpp:399, OTP-29.1.1); a light BIF call
// site has already charged it.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-471 (call_light_bif_shared), OTP-29.1.1:
// a plain BIF is called straight away; save_calls, tracing, trapping BIFs and the
// breakpoint and send identities branch off to the slow path.
#[inline(always)]
fn invoke_dispatch_bif(
    header: *mut ProcessHeader,
    identity: usize,
    site: usize,
    export: Option<ExportDispatch>,
    export_call: bool,
) -> Option<u64> {
    // The BIF reads its arguments from the register array; only the paths that work on
    // `process.x` (send, the direct table BIFs) load it.
    let (process, registers) = crate::native_hooks::enter_runtime(header)?;
    // `send` is its own fragment (instr_bif.cpp:612), not a failed BIF dispatch.
    if identity == arinsal_beamasm::dispatch::SEND_DISPATCH_IDENTITY {
        let saving_calls = !export_call
            && registers.active_code_ix == crate::code_ix::ERTS_SAVE_CALLS_CODE_IX as u64;
        return dispatch_native_send(process, saving_calls);
    }
    if let Some(export) = export {
        if export_call {
            // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:729-745:
            // call_bif_shared stores the export's MFA in c_p->current before the BIF call.
            process.heap.abi.current = if export.bif.is_some() {
                std::ptr::from_ref(export.mfa()).cast()
            } else {
                std::ptr::null()
            };
        }
        // The light-BIF fragment already loaded `Export.is_bif_traced` and compared
        // `active_code_ix` (instr_bif.cpp:391-397). An export-entry call has not.
        let export_checks = export_call
            && (registers.active_code_ix == crate::code_ix::ERTS_SAVE_CALLS_CODE_IX as u64
                || crate::trace_bp::any_pattern());
        // trap_entry makes runs_in_executor() true, which clears light_bif. The
        // list scan still uses export.bif; trap state is built only when its
        // counter runs out. `list_slice` is one byte set at intern.
        if export.list_slice
            && !export_checks
            && let Some(bif) = export.bif
        {
            return call_list_slice_bif(process, registers, identity, export, bif, export_call);
        }
        if let Some(bif) = export.light_bif
            && !export_checks
            && !export.trap_entry
        {
            return Some(call_plain_bif(
                process,
                registers,
                identity,
                export,
                bif,
                export_call,
            ));
        }
        // ETS and the process dictionary run here so a `call_ext` does not trap back
        // into the executor once per key.
        if export.direct_ets.is_some()
            && let Some(raw) = call_direct_bif(process, export, export_call)
        {
            return Some(raw);
        }
    }
    if let Some(export) = export
        && let Some(bif) = export.light_process_bif
        && !(export_call
            && (registers.active_code_ix == crate::code_ix::ERTS_SAVE_CALLS_CODE_IX as u64
                || crate::trace_bp::any_pattern()))
        && !export.trap_entry
        // Port of erl_gc.c:987-990: an on-heap queue with signals still in the
        // outer queue is fetched before the collection. That fetch needs the
        // scheduler context, so this call leaves native code. An empty outer
        // queue stays on the light path.
        && !((bif as usize)
            == (crate::natives::sys::garbage_collect_bif as *const () as usize)
            && process.gc_outer_queue_pending())
    {
        if (bif as usize) == (crate::signals::send3_light as *const () as usize) {
            if let Some(raw) = call_send3_bif_light(process, registers, export, identity) {
                return Some(raw);
            }
        } else if let Some(raw) =
            call_process_bif(process, registers, export, bif, export_call, identity)
        {
            return Some(raw);
        }
    }
    // The export trampoline has a separate interpreted-call sentinel. Only the light-BIF
    // fragment turns THE_NON_VALUE with TRAP into `context_switch_simplified`.
    if let Some(export) = export
        && let Some(entry) = export.light_trap_bif
        && !export_call
        && registers.active_code_ix != crate::code_ix::ERTS_SAVE_CALLS_CODE_IX as u64
        && !crate::trace_bp::any_pattern()
        && process
            .cold
            .as_ref()
            .is_none_or(|cold| cold.bif_trap.is_none())
    {
        return call_trap_bif(process, registers, identity, export, entry, export_call);
    }
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:447 (dynamic_runtime_call of
    // monitor_2 / demonitor_1), OTP-29.1.1: those BIFs return in the caller. A
    // Native-class export otherwise traps back into the executor.
    let saving_calls =
        !export_call && registers.active_code_ix == crate::code_ix::ERTS_SAVE_CALLS_CODE_IX as u64;
    if !saving_calls
        && !crate::trace_bp::any_pattern()
        && let Some(export) = export
        && let Some(raw) = try_light_monitor(process, registers, export, export_call)
    {
        return Some(raw);
    }
    invoke_dispatch_bif_slow(process, registers, identity, site, export, export_call)
}

/// `monitor/2` of the caller and `demonitor` of a ref that is not a monitor.
///
/// `None` means this call needs the executor (another process, a remote monitor,
/// a port monitor, a traced call). Port of erts/emulator/beam/bif.c:782-784 and
/// bif.c:437-454, OTP-29.1.1.
fn try_light_monitor(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    export: ExportDispatch,
    export_call: bool,
) -> Option<u64> {
    if export.module_atom != arinsal_term::atoms::ERLANG {
        return None;
    }
    let monitor = export.function_atom == arinsal_term::atoms::MONITOR;
    if !monitor && export.function_atom != arinsal_term::atoms::DEMONITOR {
        return None;
    }
    let arity = usize::from(export.arity);
    let result =
        crate::signals::light_monitor_bif(process, monitor, &registers.x_reg_array[..arity])?;
    if export_call {
        charge_bif_reductions(process, 1);
    }
    // The light fragment tests the collection after its call (instr_bif.cpp:488-523); the
    // export trampoline has no such test and checks it here.
    if let Ok(value) = &result
        && (!export_call
            || (process.heap.stack_index() - process.heap.heap_top_index()
                >= process.heap.mbuf_size()
                && !process.heap.bin_vheap_gc_due()))
    {
        let value = *value;
        process.x[0] = value;
        return Some(crate::native_hooks::raw(value));
    }
    Some(process_bif_result(process, export, arity, result, 0))
}

/// Calls a trapping BIF straight from native code; `None` when it trapped.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp (call_light_bif_shared), OTP-29.1.1:
// the BIF's value or error is handled like any light BIF's; THE_NON_VALUE with
// `freason == TRAP` pushes the return address and context-switches to `c_p->i`, which the
// scheduler resumes from the trap state.
#[inline(never)]
fn call_trap_bif(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    identity: usize,
    export: ExportDispatch,
    entry: &'static crate::bif_traps::Entry,
    export_call: bool,
) -> Option<u64> {
    if export_call {
        charge_bif_reductions(process, 1);
    }
    let arity = usize::from(export.arity);
    if entry.reserves_heap()
        && let Ok(bits) = arinsal_bifs::bitstring_bit_len(process.x[0])
        && bits.is_multiple_of(8)
        && let Some(reserve) = (bits / 8).checked_mul(2).and_then(|n| n.checked_add(64))
    {
        // The decoder builds on the heap it reserved, with collection off until it is
        // done; the arguments stay live across the reservation.
        let ensured = process.ensure(reserve, arity);
        // A collection moved the heap: publish every cursor, not just HTOP.
        if ensured.is_err() {
            crate::native_hooks::set_error(process, "system_limit");
            return Some(0);
        }
    }
    let mut args = [Term::NIL; 4];
    args[..arity].copy_from_slice(&process.x[..arity]);
    let callee = (export.module_atom, export.function_atom);
    let outcome = crate::bif_traps::call_light(process, entry, identity, callee, &args[..arity]);
    match outcome {
        crate::bif_traps::LightTrap::Returned(result) => Some(light_trap_result(
            process,
            registers,
            export,
            arity,
            export_call,
            result,
        )),
        crate::bif_traps::LightTrap::Trapped => arm_light_trap(process),
    }
}

/// A trapping BIF's result. A light call's value returns straight to the fragment, which
/// tests the collection itself (instr_bif.cpp:488-523); an export call and an error take
/// the collecting path.
#[inline(always)]
fn light_trap_result(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    export: ExportDispatch,
    arity: usize,
    export_call: bool,
    result: Result<Term, arinsal_bifs::BifError>,
) -> u64 {
    match result {
        Ok(value) if !export_call => crate::native_hooks::raw(value),
        result => plain_bif_result(process, registers, export, arity, result),
    }
}

/// The trap state of a light BIF that yielded (`BIF_TRAP`): the caller resumes through the
/// continuation export when the scheduler runs the process again.
// Port of erts/emulator/beam/bif.h:316-326 (ERTS_BIF_PREP_TRAP), OTP-29.1.1.
fn arm_light_trap(process: &mut crate::Process) -> Option<u64> {
    debug_assert_native_heap(process);
    // BIF_TRAP sets c_p->i to beam_bif_export_trap. The fragment loads that
    // address and context-switches; schedule-in calls the continuation export.
    crate::bif_traps::arm_export_trap(process);
    process.heap.abi.exc.freason = 1 << 10;
    None
}

/// The light entry of one trapping BIF, compiled for its body `T` when the export is
/// created (`bif_table`). It has the signature of `trap_bif_light`.
// Port of erts/emulator/beam/erl_bif_table.c (`bif_table[].f`), OTP-29.1.1: a BIF with its own
// C function is called from the fragment directly; BIF_TRAP is taken only when the body yields.
pub(crate) extern "C" fn trap_bif_entry<T: crate::bif_traps::TrapBody>(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    instruction: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (descriptor, identity) = crate::bif_table::current_export(header);
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let arity = if let Some(arity) = T::ARITY {
        Some(arity)
    } else {
        let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
            return 0;
        };
        if export.light_trap_bif.is_none() {
            return park_executor(process, export, identity, false);
        }
        Some(usize::from(export.arity))
    };
    let Some(arity) = arity else { return 0 };
    trap_body_call::<T>(
        process,
        registers,
        identity as usize,
        instruction as usize,
        descriptor,
        arity,
    )
    .unwrap_or(0)
}

/// `lists:reverse/2` as its own light entry. The common call runs the body directly and
/// returns the list; a partial result (budget spent) takes the handler's yield path.
// Port of erts/emulator/beam/erl_bif_lists.c:1144-1263 (lists_reverse_2), OTP-29.1.1: the BIF
// is one function with its own budget, and BIF_TRAP is taken only when the budget runs out.
pub(crate) extern "C" fn list_reverse_entry(
    header: *mut ProcessHeader,
    regs: *mut u64,
    i: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (descriptor, identity) = crate::bif_table::current_export(header);
    // lists_reverse_2: the on-heap loop runs first, straight on the young heap. The fragment
    // installs the result in X0, so only the return value is produced.
    if let Some((process, _)) = crate::native_hooks::enter_runtime(header)
        && let Some(value) =
            arinsal_bifs::reverse_onheap_direct(&mut process.heap, process.x[0], process.x[1])
    {
        return crate::native_hooks::raw(value);
    }
    list_reverse_general(header, regs, i, descriptor, identity)
}

/// The rest of `lists:reverse/2`: trap, error and heap-fragment paths.
#[inline(never)]
fn list_reverse_general(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    _i: u64,
    descriptor: u64,
    identity: u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    if export.light_trap_bif.is_none() {
        return park_executor(process, export, identity, false);
    }
    let gc_was_enabled = process.heap.gc_enabled;
    let reds = process.heap.abi.fcalls.clamp(0, 4000) as usize;
    let max_cells = reds
        .saturating_mul(arinsal_bifs::REVERSE_ONHEAP_CELLS_PER_RED)
        .max(1);
    let args = [process.x[0], process.x[1]];
    let step = {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        let mut call = arinsal_bifs::BifCall::default();
        let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut call);
        arinsal_bifs::lists_reverse(&mut ctx, args[0], args[1], max_cells)
    };
    let result = match step {
        Ok(arinsal_bifs::ReverseStep::Done(value)) => {
            process.set_gc_enabled(gc_was_enabled);
            process.x[0] = value;
            return crate::native_hooks::raw(value);
        }
        Ok(arinsal_bifs::ReverseStep::Trap(cont)) => Ok(crate::bif_traps::HandlerResult::Yield {
            continuation: "lists:reverse/2",
            // erts keeps lists:reverse/2's arguments in X registers and allocates no magic bin.
            state: arinsal_term::MagicRef::with_orig_size(std::sync::Mutex::new(cont), 0),
            reductions: 0,
        }),
        Err(error) => Err(error),
    };
    let callee = (export.module_atom, export.function_atom);
    match crate::bif_traps::finish_light(
        process,
        identity as usize,
        callee,
        &args,
        gc_was_enabled,
        result,
    ) {
        crate::bif_traps::LightTrap::Returned(result) => {
            light_trap_result(process, registers, export, 2, false, result)
        }
        crate::bif_traps::LightTrap::Trapped => {
            // Port of erts/emulator/beam/jit/arm/instr_bif.cpp (call_light_bif_shared) and erl_gc.c
            // (erts_gc_after_bif_call_lhf runs before the trap is taken, with the trap's
            // arguments as the live registers), OTP-29.1.1.
            if process.collect_bin_vheap_if_due(0).is_err() {
                crate::native_hooks::set_error(process, "system_limit");
                return 0;
            }
            arm_light_trap(process).unwrap_or(0)
        }
    }
}

/// [`call_trap_bif`] for a body known at compile time: a finished run returns at once.
#[inline(always)]
fn trap_body_call<T: crate::bif_traps::TrapBody>(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    identity: usize,
    instruction: usize,
    descriptor: u64,
    arity: usize,
) -> Option<u64> {
    // A call that needs no trap state returns its value at once.
    if registers.active_code_ix != crate::code_ix::ERTS_SAVE_CALLS_CODE_IX as u64
        && let Some(value) = T::direct(process, &registers.x_reg_array[..arity])
    {
        return Some(crate::native_hooks::raw(value));
    }
    let gc_was_enabled = process.heap.gc_enabled;
    let pid = process.self_pid;
    // The body reads its arguments in place; a copy is taken only when a trap must keep them.
    match T::run(
        process,
        &registers.x_reg_array[..arity],
        instruction,
        pid,
        gc_was_enabled,
    ) {
        Ok(crate::bif_traps::HandlerResult::Done { value, reductions }) => {
            process.set_gc_enabled(gc_was_enabled);
            crate::bif_traps::charge_light(process, reductions);
            if registers.active_code_ix == crate::code_ix::ERTS_SAVE_CALLS_CODE_IX as u64 {
                // The save-calls entry branches through the export and does not return to the
                // shared light-BIF fragment, so run that fragment's single epilogue here.
                // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:388-397 and :488-523,
                // OTP-29.1.1.
                Some(plain_bif_result(
                    process,
                    registers,
                    crate::beamasm_integration::export_from_info(descriptor)?,
                    arity,
                    Ok(value),
                ))
            } else {
                // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:488-523, OTP-29.1.1:
                // the native shared fragment performs its inline GC check on this return.
                Some(crate::native_hooks::raw(value))
            }
        }
        other => trap_body_finish(
            process,
            registers,
            identity,
            descriptor,
            arity,
            gc_was_enabled,
            other,
        ),
    }
}

/// The yield or error tail of [`trap_body_call`]: out of line, so the direct return stays small.
#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn trap_body_finish(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    identity: usize,
    descriptor: u64,
    arity: usize,
    gc_was_enabled: bool,
    other: Result<crate::bif_traps::HandlerResult, arinsal_bifs::BifError>,
) -> Option<u64> {
    let export = crate::beamasm_integration::export_from_info(descriptor)?;
    let mut args = [Term::NIL; 3];
    args[..arity].copy_from_slice(&process.x[..arity]);
    let callee = (export.module_atom, export.function_atom);
    match crate::bif_traps::finish_light(
        process,
        identity,
        callee,
        &args[..arity],
        gc_was_enabled,
        other,
    ) {
        crate::bif_traps::LightTrap::Returned(result) => Some(light_trap_result(
            process, registers, export, arity, false, result,
        )),
        crate::bif_traps::LightTrap::Trapped => arm_light_trap(process),
    }
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
fn native_breakpoint_accounted(process: &mut crate::Process, site: usize) -> bool {
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
        usize::from(hit.arity),
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
        && native_breakpoint_accounted(process, site)
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
    if export.runs_in_executor()
        // Port of erts/emulator/beam/jit/arm/instr_bif.cpp (bif trace trampolines),
        // OTP-29.1.1: a traced BIF runs in the executor, which has the trace context.
        || (crate::trace_bp::any_pattern()
            && crate::trace_bp::selects(process, &export.module, &export.function, export.arity))
    {
        if export_call {
            charge_bif_reductions(process, 1);
        }
        process.heap.abi.arity = export.arity;
        process.heap.abi.i = identity as *const u8 as *const _;
        process.heap.abi.exc.freason = 1 << 10;
        process.native_light_bif_call = !export_call;
        return None;
    }
    let bif = export.bif?;
    Some(call_plain_bif(
        process,
        registers,
        identity,
        export,
        bif,
        export_call,
    ))
}

/// Runs an ETS or process-dictionary BIF from native code.
///
/// `None` means the direct body declined (or a trace pattern is active) and the
/// scheduler path must run the call.
fn call_direct_bif(
    process: &mut crate::Process,
    export: ExportDispatch,
    export_call: bool,
) -> Option<u64> {
    let direct = export.direct_ets?;
    if crate::trace_bp::any_pattern() {
        return None;
    }
    let arity = usize::from(export.arity).min(4);
    let args = [process.x[0], process.x[1], process.x[2], process.x[3]];
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
            direct_bif_error_gc(process, usize::from(export.arity));
        }
        return Some(0);
    }
    process.x[0] = value;
    let mut raw = crate::native_hooks::raw(value);
    // The light fragment tests the collection after this call (instr_bif.cpp:488-523).
    if export_call && (process.heap.gc_desired() || process.heap.bin_vheap_gc_due()) {
        if process.collect_bin_vheap_if_due(1).is_err() {
            crate::native_hooks::set_error(process, "system_limit");
            return Some(0);
        }
        raw = crate::native_hooks::raw(process.x[0]);
        // The collection moved the heap: publish every bound.
        return Some(raw);
    }
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp (call_light_bif_shared,
    // emit_leave_runtime<eReductions | eHeap | eStack | eXRegs>), OTP-29.1.1: a BIF that did not
    // collect only moved HTOP and the reduction counter; the heap bounds and stack are unchanged.
    Some(raw)
}

/// Collects after a direct BIF that failed: the argument registers and the failure words are
/// the roots. A failed collection replaces the failure with `system_limit`.
// Port of erts/emulator/beam/erl_gc.c (erts_gc_after_bif_call_lhf, with `c_p->fvalue` and
// `c_p->ftrace` as process roots), OTP-29.1.1.
#[cold]
#[inline(never)]
fn direct_bif_error_gc(process: &mut crate::Process, arity: usize) {
    let ftrace = process.heap.abi.exc.ftrace;
    let mut roots = [
        crate::native_hooks::from_raw(process.heap.abi.exc.fvalue),
        if ftrace == 0 {
            Term::NIL
        } else {
            crate::native_hooks::from_raw(ftrace)
        },
    ];
    match process.collect_heap_roots(arity, &mut roots, 0) {
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

/// `make_ref/0` and `unique_integer/0,1` on the scheduler that is already running
/// the process: bump that scheduler's counter and write the term.
///
/// Port of erts/emulator/beam/erl_bif_unique.c:821-871 (`make_ref_0`,
/// `unique_integer_0`, `unique_integer_1`), OTP-29.1.1. Other BIFs return `None`
/// and take the generic path.
#[inline(always)]
fn fast_scheduler_bif(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    export: ExportDispatch,
    export_call: bool,
) -> Option<u64> {
    use crate::beamasm_integration::SchedulerCounterBif;
    Some(match export.scheduler_counter? {
        SchedulerCounterBif::MakeRef => make_ref_0(process, registers, export, export_call),
        SchedulerCounterBif::Unique0 => {
            unique_integer_n(process, registers, export, export_call, &[])
        }
        SchedulerCounterBif::Unique1 => {
            let arg = process.x[0];
            unique_integer_n(process, registers, export, export_call, &[arg])
        }
    })
}

/// Port of erts/emulator/beam/erl_bif_unique.c:821-833 (`make_ref_0`) and
/// erl_bif_unique.h:190-198 (`erts_sched_make_ref_in_buffer`), OTP-29.1.1.
///
/// `HAlloc` of `ERTS_REF_THING_SIZE` words, then the scheduler counter is
/// incremented and written into that buffer. No global atomic.
#[inline(never)]
fn make_ref_0(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    export: ExportDispatch,
    export_call: bool,
) -> u64 {
    let words = arinsal_bifs::next_ref_words();
    // Common path is the young-heap bump (`HAlloc` when `HeapWordsLeft` is enough).
    // A full heap takes a fragment, as `HAlloc` calls `erts_heap_alloc`.
    let result = match Term::local_ref(&mut process.heap, words) {
        Ok(term) => Ok(term),
        Err(_) => make_ref_in_fragment(process, words),
    };
    finish_counter_bif(process, registers, export, export_call, result)
}

/// A full young heap: `HAlloc` falls through to `erts_heap_alloc`.
#[cold]
#[inline(never)]
fn make_ref_in_fragment(
    process: &mut crate::Process,
    words: [u32; 3],
) -> Result<Term, arinsal_bifs::BifError> {
    let mut fragment = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    Term::local_ref(&mut fragment, words).map_err(|_| arinsal_bifs::BifError::SystemLimit)
}

/// Port of erts/emulator/beam/erl_bif_unique.c:835-871 (`unique_integer_0` /
/// `unique_integer_1`), OTP-29.1.1.
#[inline(never)]
fn unique_integer_n(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    export: ExportDispatch,
    export_call: bool,
    args: &[Term],
) -> u64 {
    let result = match arinsal_bifs::eval_unique_integer(args) {
        Ok(arinsal_bifs::UniqueInt::Small(value)) => {
            Ok(Term::small(value).expect("unique integer"))
        }
        Ok(arinsal_bifs::UniqueInt::Big(value)) => {
            let mut fragment = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
            arinsal_term::TermBuilder::new(&mut fragment)
                .int_from_bigint(&value)
                .map_err(|_| arinsal_bifs::BifError::SystemLimit)
        }
        Err(error) => Err(error),
    };
    finish_counter_bif(process, registers, export, export_call, result)
}

#[inline(always)]
fn finish_counter_bif(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    export: ExportDispatch,
    export_call: bool,
    result: Result<Term, arinsal_bifs::BifError>,
) -> u64 {
    if export_call {
        charge_bif_reductions(process, 1);
    }
    // ERTS_IS_GC_DESIRED_INTERNAL: a value with no collection desired goes straight
    // back to XREG0. The check is the one `call_light_bif_shared` does after the BIF.
    if let Ok(value) = &result
        && (!export_call
            || (process.heap.stack_index() - process.heap.heap_top_index()
                >= process.heap.mbuf_size()
                && !process.heap.bin_vheap_gc_due()))
    {
        let value = *value;
        process.x[0] = value;
        return crate::native_hooks::raw(value);
    }
    plain_bif_result(
        process,
        registers,
        export,
        usize::from(export.arity),
        result,
    )
}

/// Same return as [`call_plain_bif`] when the slice finishes. `None` when the BIF
/// deferred a continuation and this call context-switches.
#[inline(always)]
fn call_list_slice_bif(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    identity: usize,
    export: ExportDispatch,
    bif: impl Fn(&mut arinsal_bifs::Ctx<'_>, &[Term]) -> Result<Term, arinsal_bifs::BifError>,
    export_call: bool,
) -> Option<u64> {
    if export_call {
        charge_bif_reductions(process, 1);
    }
    let arity = usize::from(export.arity);
    let mut fragment = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let mut call = arinsal_bifs::BifCall::default();
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut fragment, &mut call);
    let result = bif(&mut ctx, &process.x[..arity]);
    if let Some(trap) = ctx.take_deferred() {
        let mut args = [Term::NIL; 3];
        args[..arity].copy_from_slice(&process.x[..arity]);
        if crate::bif_traps::install_deferred_trap(
            process,
            identity,
            (export.module_atom, export.function_atom),
            export.function.as_str(),
            &args[..arity],
            trap,
        )
        .is_err()
        {
            crate::native_hooks::set_error(process, "system_limit");
            return Some(0);
        }
        debug_assert_native_heap(process);
        crate::bif_traps::arm_export_trap(process);
        process.heap.abi.exc.freason = 1 << 10;
        return None;
    }
    if let Ok(value) = &result
        && (!export_call
            || (process.heap.stack_index() - process.heap.heap_top_index()
                >= process.heap.mbuf_size()
                && !process.heap.bin_vheap_gc_due()))
    {
        let value = *value;
        process.x[0] = value;
        return Some(crate::native_hooks::raw(value));
    }
    Some(plain_bif_result(process, registers, export, arity, result))
}

/// Calls a BIF that runs on the scheduler straight from native code.
#[inline(always)]
fn call_plain_bif(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    identity: usize,
    export: ExportDispatch,
    bif: arinsal_bifs::BifFn,
    export_call: bool,
) -> u64 {
    if let Some(raw) = fast_scheduler_bif(process, registers, export, export_call) {
        return raw;
    }
    call_plain_bif_body(process, registers, identity, export, bif, export_call)
}

/// [`call_plain_bif`] once the BIF is known not to be a scheduler counter.
#[inline(always)]
fn call_plain_bif_body(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    identity: usize,
    export: ExportDispatch,
    bif: impl Fn(&mut arinsal_bifs::Ctx<'_>, &[Term]) -> Result<Term, arinsal_bifs::BifError>,
    export_call: bool,
) -> u64 {
    if export_call {
        process.heap.abi.fcalls = process.heap.abi.fcalls.saturating_sub(1);
    }
    let arity = usize::from(export.arity);
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-471 (call_light_bif_shared),
    // OTP-29.1.1: the BIF reads its arguments from the register array (BIF_ARG_n is reg[n]).
    // A BIF leaves E alone, so only HTOP is read back after it.
    // The result is matched where the BIF wrote it: moving it first would read it back with
    // wider loads than the BIF's stores.
    let mut fragment = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let mut call = arinsal_bifs::BifCall::default();
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut fragment, &mut call);
    let result = bif(&mut ctx, &process.x[..arity]);
    let deferred = ctx.take_deferred();
    // ERTS_IS_GC_DESIRED_INTERNAL: a value goes straight back in x0, and the native
    // light-BIF fragment tests the collection itself (instr_bif.cpp:488-523). The
    // fragment installs x0 in the cached X register, so the result need not also be
    // copied to the scheduler register array. Only the export trampoline, which has no
    // such test, checks collection here.
    if deferred.is_none()
        && let Ok(value) = &result
        && (!export_call
            || (process.heap.stack_index() - process.heap.heap_top_index()
                >= process.heap.mbuf_size()
                && !process.heap.bin_vheap_gc_due()))
    {
        let value = *value;
        if export_call {
            process.x[0] = value;
        }
        return crate::native_hooks::raw(value);
    }
    plain_bif_slow(process, registers, identity, export, result, deferred)
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
    identity: usize,
    export: ExportDispatch,
    result: Result<Term, arinsal_bifs::BifError>,
    deferred: Option<Box<arinsal_bifs::DeferredTrap>>,
) -> u64 {
    let arity = usize::from(export.arity);
    if let Some(trap) = deferred {
        let mut args = [Term::NIL; 3];
        args[..arity].copy_from_slice(&process.x[..arity]);
        return install_deferred_bif_trap(process, identity, export, &args[..arity], trap);
    }
    plain_bif_result(process, registers, export, arity, result)
}

/// [`call_plain_bif_body`] for a BIF function that returns one word, a term or the
/// non-value with its failure in the context. The word is the value path's whole result, so
/// it is tested once; failures and deferred continuations take [`plain_bif_slow`].
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-523 (call_light_bif_shared tests the
// returned word against THE_NON_VALUE), OTP-29.1.1.
#[inline(always)]
fn call_plain_bif_word(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    identity: usize,
    export: ExportDispatch,
    bif: impl Fn(&mut arinsal_bifs::Ctx<'_>, &[Term]) -> u64,
) -> u64 {
    let arity = usize::from(export.arity);
    let mut fragment = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let mut call = arinsal_bifs::BifCall::default();
    let mut ctx = arinsal_bifs::Ctx::with_failure(&mut fragment, &mut call);
    let word = bif(&mut ctx, &process.x[..arity]);
    if word != arinsal_term::THE_NON_VALUE {
        return word;
    }
    let deferred = ctx.take_deferred();
    let error = ctx.take_error();
    // Port of erts/emulator/beam/bif.c (raise_3, error_1, exit_1, throw_1), OTP-29.1.1: the BIF
    // set `freason`, `fvalue` and (raise/3) `ftrace` itself and returned THE_NON_VALUE. They go
    // to handle_error as they are: `raise/3` with an immediate stacktrace, or `error/1`,
    // `exit/1` and `throw/1` with exactly `EXC_ERROR` / `EXC_EXIT` / `EXC_THROWN`.
    if deferred.is_none()
        && error.is_none()
        && (process.heap.abi.exc.ftrace != 0
            && process.heap.abi.exc.freason
                & (arinsal_beamasm::exc::EXF_ARGLIST | arinsal_beamasm::exc::EXF_HAS_EXT_INFO)
                == 0
            || export.arity == 1
                && export.module_atom == arinsal_term::atoms::ERLANG
                && matches!(
                    export.function_atom,
                    arinsal_term::atoms::ERROR
                        | arinsal_term::atoms::EXIT
                        | arinsal_term::atoms::THROW
                )
                && process.heap.abi.exc.ftrace == 0
                && matches!(
                    process.heap.abi.exc.freason,
                    arinsal_beamasm::exc::EXC_ERROR
                        | arinsal_beamasm::exc::EXC_EXIT
                        | arinsal_beamasm::exc::EXC_THROWN
                ))
    {
        // ERTS_IS_GC_DESIRED_INTERNAL runs before the THE_NON_VALUE test
        // (instr_bif.cpp:486-523); the failure words stay as the BIF wrote them.
        if process.heap.gc_after_bif_desired() {
            return gc_after_raised_bif(process, arity);
        }
        return 0;
    }
    plain_bif_word_slow(process, registers, identity, export, word, deferred, error)
}

/// The collection after a BIF that raised with its failure already in `freason`, `fvalue`
/// and `ftrace`: those are process roots, as are the BIF's argument registers.
// Port of erts/emulator/beam/erl_gc.c:418-478 (erts_gc_after_bif_call_lhf: a non-value result
// collects with `arity` live registers), OTP-29.1.1.
#[cold]
#[inline(never)]
fn gc_after_raised_bif(process: &mut crate::Process, arity: usize) -> u64 {
    match process.collect_heap_roots(arity, &mut [], 0) {
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
    0
}

/// The tail of [`call_plain_bif_word`] for a failure, a trap or a due collection, out of line
/// like [`plain_bif_slow`].
#[cold]
#[inline(never)]
fn plain_bif_word_slow(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    identity: usize,
    export: ExportDispatch,
    word: u64,
    deferred: Option<Box<arinsal_bifs::DeferredTrap>>,
    error: Option<arinsal_bifs::BifError>,
) -> u64 {
    // A migrated body left its failure in the process' exit words; an adapted `Result` body
    // left it in the context. Decoding clears the words, which are rewritten below.
    let error = if word == arinsal_term::THE_NON_VALUE {
        error.or_else(|| decode_failure(&mut process.heap.abi.exc))
    } else {
        error
    };
    // `raise/3` with an immediate stacktrace (`throw/1` compiles to it) is complete in the
    // failure words: set them and return the non-value, as erts' `raise_3` does.
    let result = if word == arinsal_term::THE_NON_VALUE {
        Err(error.unwrap_or(arinsal_bifs::BifError::BADARG))
    } else {
        Ok(crate::native_hooks::from_raw(word))
    };
    plain_bif_slow(process, registers, identity, export, result, deferred)
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

/// Installs a BIF continuation after its process-bound context has returned.
fn install_deferred_bif_trap(
    process: &mut crate::Process,
    identity: usize,
    export: ExportDispatch,
    args: &[Term],
    trap: Box<arinsal_bifs::DeferredTrap>,
) -> u64 {
    if crate::bif_traps::install_deferred_trap(
        process,
        identity,
        (export.module_atom, export.function_atom),
        export.function.as_str(),
        args,
        trap,
    )
    .is_err()
    {
        crate::native_hooks::set_error(process, "system_limit");
        return 0;
    }
    debug_assert_native_heap(process);
    crate::bif_traps::arm_export_trap(process);
    process.heap.abi.exc.freason = 1 << 10;
    0
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
    identity: usize,
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
                process.x[0] = value;
                // A collection handed to a dirty scheduler must leave this one before
                // the next call. `leave_runtime` reloads FCALLS, and the next
                // `call_light_bif` yields when it is exhausted.
                // Port of erl_gc.c:588-597 (`force_reschedule`), OTP-29.1.1.
                if process.force_yield() {
                    process.heap.abi.fcalls = 0;
                }
                crate::native_hooks::raw(value)
            }
            Err(error) => process_bif_result(process, export, arity, Err(error), identity),
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
        process.x[0] = value;
        return Some(crate::native_hooks::raw(value));
    }
    Some(process_bif_result(process, export, arity, result, identity))
}

/// Run `send_3` from an export entry without materializing its declining `Option<Result<…>>`.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-471 (call_light_bif_shared), OTP-29.1.1.
#[inline(always)]
fn call_send3_bif_light(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    export: ExportDispatch,
    identity: usize,
) -> Option<u64> {
    let args = &registers.x_reg_array[..3];
    if !crate::signals::send3_light_eligible(process, args) {
        return None;
    }
    Some(match crate::signals::send3_light_call(process, args) {
        Ok(value) => {
            process.x[0] = value;
            crate::native_hooks::raw(value)
        }
        Err(trap) => process_bif_result(process, export, 3, Err(*trap), identity),
    })
}

/// A process BIF's exception, or a value after which a collection is desired.
// Port of erts/emulator/beam/erl_gc.c:418-478 (erts_gc_after_bif_call_lhf), OTP-29.1.1: the
// argument registers stay live across the collection.
#[cold]
#[inline(never)]
fn process_bif_result(
    process: &mut crate::Process,
    export: ExportDispatch,
    arity: usize,
    mut result: Result<Term, crate::exceptions::Trap>,
    identity: usize,
) -> u64 {
    if let Err(trap) = &mut result
        && let Some(export_trap) = trap.export.take()
    {
        return bif_trap_export(process, export, *export_trap, identity);
    }
    let collected = process.heap.gc_after_bif_desired();
    if collected {
        let mut args = argument_registers(process, arity);
        let (value, raised) = match &mut result {
            Ok(value) => (Some(value), None),
            Err(trap) => (None, Some(trap)),
        };
        let gc = crate::calls::gc_after_native_parts(process, &mut args, value, raised);
        if gc.is_err() {
            crate::native_hooks::set_error(process, "system_limit");
            return 0;
        }
    }
    match result {
        Ok(value) => {
            let value = crate::native_hooks::raw(value);
            process.x[0] = crate::native_hooks::from_raw(value);
            value
        }
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
    mut export_trap: crate::ExportTrap,
    identity: usize,
) -> u64 {
    // BIF_TRAP's arguments replace the BIF arguments in X0 onwards and are the live roots
    // while the process is parked in `beam_bif_export_trap`.
    if crate::calls::gc_after_native_parts(process, &mut export_trap.args, None, None).is_err() {
        crate::native_hooks::set_error(process, "system_limit");
        return 0;
    }
    let arity = export_trap.args.len();
    process.x.ensure_x(arity);
    process.x[..arity].copy_from_slice(&export_trap.args);
    process.gc_live = arity;
    crate::bif_traps::install_export_trap(
        process,
        identity,
        (export.module_atom, export.function_atom),
        &export_trap,
    );
    crate::bif_traps::arm_export_trap(process);
    process.heap.abi.exc.freason = 1 << 10;
    0
}

/// The shared BIF epilogue for a BIF body that reports its result as `Result<Term, VmError>`:
/// a value, `BIF_ERROR`, or `BIF_TRAP*` complete here, in native code, as erts'
/// `call_light_bif_shared` / `call_bif_shared` complete them; GC after the BIF is
/// [`process_bif_result`]'s. An outcome only the scheduler completes (ERTS_BIF_YIELD, a dirty
/// BIF on a normal scheduler, a busy port, hibernation, a VM failure) is THE_NON_VALUE with
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
    let arity = usize::from(export.arity);
    let result = match result {
        Ok(value) => Ok(value),
        Err(crate::VmError::Trap(trap)) if !crate::port::busy_suspend_pending() => Err(trap),
        Err(crate::VmError::TrapExport(trap)) => {
            return bif_trap_export(process, export, trap, identity as usize);
        }
        Err(crate::VmError::Exception { reason, frame }) => {
            match crate::process::legacy_exception_trap(process, &reason, &frame) {
                Ok(trap) => Err(trap),
                Err(error) => {
                    return bif_scheduler_outcome(process, export, identity, light_call, error);
                }
            }
        }
        Err(error) => return bif_scheduler_outcome(process, export, identity, light_call, error),
    };
    process_bif_result(process, export, arity, result, identity as usize)
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
    _regs: *mut u64,
    i: u64,
) -> u64 {
    // Port of erts/emulator/beam/bif.h (BIF_ALIST: `c_p, reg, I`), OTP-29.1.1: the BIF
    // finds its export through `c_p->current`, which the call fragment set.
    let (descriptor, identity) = crate::bif_table::current_export(header);
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
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
    debug_assert!(trap.export.is_none(), "a BIF_TRAP is not a BIF_ERROR");
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

/// A copy of the first `arity` X registers, for a cold path that hands the arguments to a
/// function that also takes the process.
fn argument_registers(process: &crate::Process, arity: usize) -> smallvec::SmallVec<[Term; 8]> {
    process.x[..arity].iter().copied().collect()
}

/// An error, or a value after which a collection is desired.
#[cold]
#[inline(never)]
fn plain_bif_result(
    process: &mut crate::Process,
    _registers: &mut arinsal_beamasm::SchedulerRegisters,
    export: ExportDispatch,
    arity: usize,
    mut result: Result<Term, arinsal_bifs::BifError>,
) -> u64 {
    let collected = process.heap.gc_after_bif_desired();
    if collected && !gc_after_plain_bif(process, arity, &mut result) {
        return 0;
    }
    match result {
        Ok(value) => {
            let value = crate::native_hooks::raw(value);
            // Port of erts/emulator/beam/jit/arm/instr_bif.cpp (call_light_bif,
            // ERTS_IS_GC_AFTER_BIF_DESIRED), OTP-29.1.1: one test, so at most one collection.
            process.x[0] = crate::native_hooks::from_raw(value);
            value
        }
        Err(error) => plain_bif_error(process, export, error),
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
    _regs: *mut u64,
    value: u64,
    descriptor: u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime_after_bif(header) else {
        return 0;
    };
    // The BIF's charge is in FCALLS; the sync below writes `reductions` back to it.
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    // erl_gc.c:428-445 (erts_gc_after_bif_call_lhf): with F_DISABLE_GC the result is returned
    // without a collection.
    if !process.heap.gc_enabled {
        process.x[0] = crate::native_hooks::from_raw(value);
        return value;
    }
    let arity = usize::from(export.arity);
    plain_bif_result(
        process,
        registers,
        export,
        arity,
        Ok(crate::native_hooks::from_raw(value)),
    )
}

/// Collects after a BIF whose heap fragments outgrew the free heap; false when the
/// collection failed and the call raised.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:549-570 (gc_after_bif_call), OTP-29.1.1:
// erts_gc_after_bif_call_lhf keeps the argument registers live and moves them in `reg`.
#[cold]
#[inline(never)]
fn gc_after_plain_bif(
    process: &mut crate::Process,
    arity: usize,
    result: &mut Result<Term, arinsal_bifs::BifError>,
) -> bool {
    let mut args = argument_registers(process, arity);
    let collected = crate::calls::gc_after_bif(process, &mut args, result);
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
    export: ExportDispatch,
    error: arinsal_bifs::BifError,
) -> u64 {
    let args = process.x[..usize::from(export.arity)].to_vec();
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

/// Calls a plain BIF named by its export's descriptor word (`i_bif1/2/3`, `nofail_bif1/2`).
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:110-200, OTP-29.1.1.
pub(crate) extern "C" fn arinsal_beamasm_bif_by_identity(
    header: *mut ProcessHeader,
    export: Option<ExportDispatch>,
    first: u64,
    second: u64,
    third: u64,
) -> u64 {
    // A guard BIF never collects (erts calls it with only Update::eReductions).
    let Some((process, _registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let all_args = [first, second, third].map(crate::native_hooks::from_raw);
    let Some((bif, arity)) = export.and_then(|export| Some((export.bif?, export.arity))) else {
        crate::native_hooks::set_error(process, "undef");
        return 0;
    };
    let args = &all_args[..usize::from(arity).min(all_args.len())];
    // Matched where the BIF wrote it, like the light BIF path.
    let mut fragment = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let mut call = arinsal_bifs::BifCall::default();
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut fragment, &mut call);
    let result = bif(&mut ctx, args);
    match result {
        Ok(value) => crate::native_hooks::raw(value),
        Err(error) => {
            // Port of erts/emulator/beam/jit/arm/instr_bif.cpp (i_bif: the failing BIF and its
            // arguments are the top frame), OTP-29.1.1.
            match export {
                // `i_bif*` passes each operand explicitly; a literal BIF operand need not
                // be present in X0..X2 when the scheduler expands the saved error.
                Some(export) => set_native_bif_export_error(process, export, args, error),
                None => set_light_bif_error(process, &error),
            }
            0
        }
    }
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
fn set_call_fun_error(process: &mut crate::Process, fun: Term, arity: u32) {
    let arity = arity as usize;
    if arity >= crate::proc_create::ATTACHED_X_REGS {
        crate::native_hooks::set_error(process, "system_limit");
        return;
    }
    // `apply/2` may pass more arguments than the module's registers (erts raises badarity with
    // all of them): the scheduler array holds them.
    process.x[arity] = fun;
    match crate::funs::call_error_reason(process, fun, arity) {
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
    let count = args.len().min(process.x.len());
    process.x[..count].copy_from_slice(&args[..count]);
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
    _registers: *mut arinsal_beamasm::SchedulerRegisters,
    _stack: *mut u64,
    bif_info: u64,
) -> usize {
    let Some(process) = crate::native_hooks::process_from_header(header) else {
        return 0;
    };
    let freason = process.heap.abi.exc.freason;
    let Some(class) = native_exception_class(freason) else {
        return 0;
    };
    // Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp:300-318 (`raise_exception_shared`),
    // OTP-29.1.1. The shared fragment already ran `emit_enter_runtime` and stored HTOP and E
    // into `c_p`. `handle_error` runs once from that entry; it does not enter again.
    // The heap indexes are those stored cursors (`c_p->htop`, `c_p->stop`).
    let Some((process, registers)) = crate::native_hooks::scheduler_registers(process) else {
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
        let Ok(trace) =
            crate::stacktrace::save_stacktrace(process, input, Some(&registers.x_reg_array))
        else {
            return 0;
        };
        trace
    };
    // `save_stacktrace` leaves the trace in `c_p->ftrace`, a root while the value expands.
    process.heap.abi.exc.ftrace = crate::native_hooks::raw(trace);
    // Port of beam_common.c:742 (`expand_error_value`): only an indexed reason or an
    // `error_info` value needs expanding; the rest is `fvalue` itself.
    let reason = if freason
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
    crate::native_bridge::native_found_catch(process, class, reason, trace).unwrap_or(0)
}

/// `GET_EXC_CLASS(freason)` for a failure `handle_error` completes in native code, or `None`
/// for one the scheduler completes.
///
/// The scheduler keeps: TRAP; `function_clause` (its top frame is built from the current
/// function's arguments); re-raise words carrying `EXF_RESTORE_NFUNC` or a class atom;
/// `error/2,3` failures with `EXF_HAS_EXT_INFO` and no index. The native resolver takes
/// the generic codes (`EXC_ERROR`, `EXC_EXIT`, `EXC_THROWN`, optionally with
/// `EXF_ARGLIST`), the indexed errors (`(index << 10) | EXC_ERROR`, optionally with
/// `EXF_HAS_EXT_INFO`), and a `raw_raise` re-raise (a class code without `EXF_SAVETRACE`).
#[inline]
fn native_exception_class(freason: u64) -> Option<arinsal_bifs::Class> {
    use arinsal_beamasm::exc::{
        EXC_ERROR, EXC_EXIT, EXC_INDEXBITS, EXC_THROWN, EXF_ARGLIST, EXF_HAS_EXT_INFO,
        EXF_SAVETRACE,
    };
    if freason == arinsal_beamasm::module::EXC_FUNCTION_CLAUSE {
        return None;
    }
    let handled = if freason & EXC_INDEXBITS != 0 {
        freason & !(EXC_INDEXBITS | EXF_HAS_EXT_INFO) == EXC_ERROR
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
) -> usize {
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let fun = crate::native_hooks::from_raw(fun_raw);
    let view = crate::native_hooks::fun_view(fun);
    match view {
        Some(arinsal_term::FunRef::Local { entry, .. }) => {
            if u32::from(entry.arity) != arity {
                set_call_fun_error(process, fun, arity);
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
                set_call_fun_error(process, fun, arity);
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
                        crate::export::export_entry_or_stub(
                            runtime.code_scope,
                            (entry.module, entry.function, entry.arity),
                        )
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
            set_call_fun_error(process, fun, arity);
            0
        }
    }
}

/// A tail apply of error/exit/throw restores the calling function's native CP, so the
/// stacktrace shows the caller. False when the stack could not grow (`system_limit` set).
// Port of erts/emulator/beam/beam_common.c:1345-1427 (apply_bif_error_adjustment), OTP-29.1.1.
fn apply_bif_error_adjustment(
    process: &mut crate::Process,
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
    if process.ensure(need, usize::from(mfa.2) + 2).is_err() {
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
    lambda_handler_call(process, handler_export, code_ix, module, fun, arity)
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
    lambda_handler_call(process, export, code_ix, module, fun, arity)
}

/// X0..X3 = Module, Fun, Args, [] for `handler(Module, Fun, Args)` and its address.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp (beam_jit_handle_unloaded_fun: the
// argument list and `reg[0..3]`), OTP-29.1.1.
fn lambda_handler_call(
    process: &mut crate::Process,
    handler_export: &arinsal_beamasm::bif::ExportEntry,
    code_ix: usize,
    module: arinsal_term::Atom,
    fun: Term,
    arity: u32,
) -> usize {
    let arity = arity as usize;
    // The fun is rooted above the arguments while the list is built.
    process.x[arity] = fun;
    if process.ensure(arity * 2, arity + 1).is_err() {
        crate::native_hooks::set_error(process, "system_limit");
        return 0;
    }
    let fun = process.x[arity];
    let args: smallvec::SmallVec<[Term; 8]> = smallvec::SmallVec::from_slice(&process.x[..arity]);
    let Ok(list) = arinsal_term::TermBuilder::new(&mut crate::ProcessHeapHandle(&mut process.heap))
        .list_from_iter(args)
    else {
        crate::native_hooks::set_error(process, "system_limit");
        return 0;
    };
    process.x[0] = Term::atom(module);
    process.x[1] = fun;
    process.x[2] = list;
    process.x[3] = Term::NIL;
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
) -> arinsal_beamasm::misc::ApplyResolution {
    use arinsal_beamasm::misc::ApplyResolution;
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return ApplyResolution::default();
    };
    let arity = arity as usize;
    if arity + 1 >= registers.x_reg_array.len() {
        return apply_error(
            process,
            Term::NIL,
            Term::NIL,
            Term::NIL,
            arinsal_bifs::BifError::SystemLimit,
        );
    }
    let module = process.x[arity];
    let function = process.x[arity + 1];
    let (Some(module_atom), Some(function_atom)) = (module.as_atom(), function.as_atom()) else {
        // Port of erts/emulator/beam/beam_common.c:1540-1552 (fixed_apply, `error`), OTP-29.1.1.
        if process.ensure(arity * 2, arity + 2).is_err() {
            return apply_error(
                process,
                module,
                function,
                Term::NIL,
                arinsal_bifs::BifError::SystemLimit,
            );
        }
        let (module, function) = (process.x[arity], process.x[arity + 1]);
        let args: smallvec::SmallVec<[Term; 8]> =
            smallvec::SmallVec::from_slice(&process.x[..arity]);
        let Ok(list) =
            arinsal_term::TermBuilder::new(&mut crate::ProcessHeapHandle(&mut process.heap))
                .list_from_iter(args)
        else {
            return apply_error(
                process,
                module,
                function,
                Term::NIL,
                arinsal_bifs::BifError::SystemLimit,
            );
        };
        return apply_error(
            process,
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
        runtime.export_entry(mfa, code_ix).or_else(|| {
            crate::export::export_entry_or_stub(runtime.code_scope, mfa).map(|export| &**export)
        })
    }) else {
        return apply_error(
            process,
            module,
            function,
            Term::NIL,
            arinsal_bifs::BifError::Badarg { cause: None },
        );
    };
    if !apply_bif_error_adjustment(process, mfa, return_ip, stack_offset) {
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
    module: Term,
    function: Term,
    args: Term,
    reason: arinsal_bifs::BifError,
) -> arinsal_beamasm::misc::ApplyResolution {
    set_light_bif_error(process, &reason);
    process.x[0] = module;
    process.x[1] = function;
    process.x[2] = args;
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
) -> arinsal_beamasm::misc::ApplyResolution {
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
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
    let (mut module, mut function, mut args) = (process.x[0], process.x[1], process.x[2]);
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
            module,
            function,
            args,
            arinsal_bifs::BifError::Badarg { cause: None },
        );
    }
    let Ok(arity) = u8::try_from(arity) else {
        return apply_error(
            process,
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
                crate::export::export_entry_or_stub(runtime.code_scope, (module, function, arity))
                    .map(|export| &**export)
            })
    }) else {
        return apply_error(
            process,
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
    if !apply_bif_error_adjustment(process, (module, function, arity), return_ip, stack_offset) {
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
) -> u64 {
    arinsal_beamasm_map_change(header, source, live, count, MapChange::New)
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
) -> u64 {
    arinsal_beamasm_map_change(header, source, live, count, MapChange::Assoc)
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
) -> u64 {
    arinsal_beamasm_map_change(header, source, live, count, MapChange::Exact)
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
) -> u64 {
    map_single::<false>(header, key, value, map, 0)
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
) -> u64 {
    map_single::<true>(header, key, value, map, result_pointer)
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
    map_single_generic::<EXACT>(header, key, value, map, result_pointer)
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
) -> u64 {
    // Two monomorphic helpers: the put entry carries no exact-update state.
    let exact = EXACT;
    let (process, registers) = if exact {
        let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
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
    source: u64,
    live: u64,
    count: u64,
    change: MapChange,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
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
    process.x[source_slot] = crate::native_hooks::from_raw(source);
    let map = crate::native_hooks::from_raw(source);
    let need = match change {
        MapChange::New => arinsal_maps::new_map_need(n),
        MapChange::Assoc => arinsal_maps::update_map_assoc_need(map, n),
        MapChange::Exact => arinsal_maps::update_map_exact_need(map),
    };
    if process.heap.words_left() < need {
        // X registers between the live prefix and the staged vector are dead and may hold
        // stale words; they must not become GC roots.
        process.x[live..base].fill(Term::NIL);
        if crate::native_hooks::collect_native(process, registers, need, source_slot + 1).is_err() {
            crate::native_hooks::set_error(process, "system_limit");
            return 0;
        }
    }
    let x = &process.x;
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
        Err(arinsal_maps::MapError::HeapFull { .. }) => {
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
    let Some((process, _registers)) = crate::native_hooks::enter_runtime(header) else {
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
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
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
    let source = process.x[live];
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
                && process.ensure_native_roots(alloc, live + 1).is_err()
            {
                set_bs_append_error(process, "size", "system_limit");
                return 0;
            }
            *ebs = [0, 5];
            crate::native_hooks::raw(process.x[live])
        }
        Ok(true) => {
            // erl_bits.c:1832-1842: `reg[live] = sb->orig`, collect once if the HAlloc
            // reservation is short, then build the successor directly at `htop`.
            process.x[live] = prepared.bin_ref();
            let used_words: usize = 5;
            let heap_need = used_words.wrapping_add(alloc);
            let reservation = match process.heap.reserve_native_halloc(used_words, alloc) {
                Some(reservation) => reservation,
                None => {
                    if process.ensure_native_roots(heap_need, live + 1).is_err() {
                        set_bs_append_error(process, "size", "system_limit");
                        return 0;
                    }
                    process
                        .heap
                        .reserve_native_halloc(used_words, alloc)
                        .expect("GC leaves the requested HeapWordsLeft reservation")
                }
            };
            let owner = process.x[live];
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
                        .ensure_native_roots(fresh_request, live + 1)
                        .is_err()
                    {
                        set_bs_append_error(process, "size", "system_limit");
                        return 0;
                    }
                    None
                }
            };
            let source = process.x[live];
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
    let Some((process, _registers)) = crate::native_hooks::enter_runtime(process_header) else {
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
) -> u64 {
    use arinsal_bits::{BitsError, MatchOps, SegFlags};
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let base = live as usize;
    let Some(root_live) = base
        .checked_add(4)
        .filter(|&count| count <= process.x.len())
    else {
        crate::native_hooks::set_error(process, "system_limit");
        return 0;
    };
    // The live X prefix and staged operands (the context among them) form the exact GC root
    // prefix. Registers beyond `live` are dead and may contain non-term scratch values.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp (emit_gc_test_preserve), OTP-29.1.1.
    for (index, slot) in registers.match_staging.iter().enumerate() {
        process.x[base + index] = crate::native_hooks::from_raw(*slot);
    }
    let small = |term: Term| term.as_small().and_then(|n| usize::try_from(n).ok());
    let mut result: Option<Result<Option<Term>, BitsError>> = None;
    let mut request = 8usize;
    for _ in 0..8 {
        let ctx = process.x[base];
        let outcome = match kind {
            // integer / binary: flags, size, unit
            0 | 1 => {
                let bits = small(process.x[base + 2])
                    .zip(small(process.x[base + 3]))
                    .and_then(|(size, unit)| size.checked_mul(unit));
                match bits {
                    None => Ok(None),
                    Some(bits) if kind == 0 => {
                        let flags = small(process.x[base + 1]).unwrap_or(0);
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
            2 => match small(process.x[base + 1]) {
                Some(unit) => ctx.get_tail_unit(unit, &mut process.heap),
                None => Ok(None),
            },
            _ => {
                let expected = process.x[base + 2];
                match small(process.x[base + 1]) {
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
                if process.ensure(request, root_live).is_err() {
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
        *slot = crate::native_hooks::raw(process.x[base + index]);
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
    if let Some(raw) = process_info_2_self(header) {
        return raw;
    }
    yield_executor_bif(header, regs, i)
}

fn process_info_2_self(header: *mut ProcessHeader) -> Option<u64> {
    let (process, _) = crate::native_hooks::enter_runtime(header)?;
    let pid = arinsal_sched::Pid::from_term(process.x.first().copied()?)?;
    let item = process.x.get(1).copied()?;
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
                if !gc_after_plain_bif(process, 2, &mut result) {
                    return Some(0);
                }
                let Ok(term) = result else { return Some(0) };
                process.x[0] = term;
                return Some(crate::native_hooks::raw(term));
            }
            Some(crate::native_hooks::raw(term))
        }
        _ => None,
    }
}
