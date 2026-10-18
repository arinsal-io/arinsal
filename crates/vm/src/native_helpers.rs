//! Runtime helper bodies called by BeamAsm generated code.

use arinsal_beamasm::ProcessHeader;
use arinsal_bits::MatchOps;
use arinsal_term::{HeapAlloc, Term};

use crate::beamasm_integration::ExportDispatch;

struct StaticNif {
    module: String,
    function: String,
    arity: u8,
    entry: arinsal_bifs::BifFn,
}

fn native_fun_owners() -> &'static std::sync::Mutex<
    std::collections::HashMap<usize, std::sync::Weak<arinsal_term::FunEntry>>,
> {
    static OWNERS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<usize, std::sync::Weak<arinsal_term::FunEntry>>>,
    > = std::sync::OnceLock::new();
    OWNERS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

pub(crate) fn register_native_fun_owner(entry: &std::sync::Arc<arinsal_term::FunEntry>) {
    native_fun_owners().lock().unwrap().insert(
        std::sync::Arc::as_ptr(entry) as usize,
        std::sync::Arc::downgrade(entry),
    );
}

/// Retains a native-created closure's shared owner on the process heap.
// Port of erts/emulator/beam/jit/arm/instr_fun.cpp:211-251, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_retain_fun_owner(
    header: *mut ProcessHeader,
    identity: u64,
) -> u64 {
    let Some((process, _registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let owner = native_fun_owners().lock().ok().and_then(|owners| {
        owners
            .get(&(identity as usize))
            .and_then(std::sync::Weak::upgrade)
    });
    let Some(owner) = owner else {
        crate::native_hooks::set_error(process, "system_limit");
        process.sync_native_header();
        return 0;
    };
    arinsal_term::HeapAlloc::retain_fun(&mut process.heap, owner);
    process.sync_native_header();
    1
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
        Some(arinsal_bifs::Class::Error) => reraise | 1,
        Some(arinsal_bifs::Class::Exit) => reraise | 2,
        Some(arinsal_bifs::Class::Throw) => reraise | 3,
        None => {
            process.header.fvalue = crate::native_hooks::raw(crate::signals::atom("badarg"));
            1
        }
    }
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
    match crate::exceptions::materialize(None, process, trace) {
        Ok(value) => {
            process.x[0] = value;
            process.sync_native_header();
            crate::native_hooks::raw(value)
        }
        Err(_) => {
            crate::native_hooks::set_error(process, "system_limit");
            process.sync_native_header();
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
    let result = crate::exceptions::materialize(None, process, trace).and_then(|stacktrace| {
        arinsal_term::TermBuilder::new(&mut crate::ProcessHeapHandle(&mut process.heap))
            .tuple(&[reason, stacktrace])
            .map_err(|error| crate::VmError::Unsupported(format!("stacktrace tuple {error:?}")))
    });
    match result {
        Ok(value) => {
            process.sync_native_header();
            crate::native_hooks::raw(value)
        }
        Err(_) => {
            // The catch-end fragment stores this word and builds `{'EXIT', Word}`.
            // A zero return is not a term and the fragment loads through it.
            let fallback =
                arinsal_term::TermBuilder::new(&mut crate::ProcessHeapHandle(&mut process.heap))
                    .tuple(&[reason, arinsal_term::Term::NIL])
                    .map(crate::native_hooks::raw)
                    .unwrap_or_else(|_| crate::native_hooks::raw(reason));
            process.sync_native_header();
            fallback
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
            process.sync_native_header();
            0
        }
    }
}

/// Creates the empty writable binary for a native `bs_init_writable`.
// Port of erts/emulator/beam/jit/arm/instr_bs.cpp:985-1000 and erl_bits.c:2002
// (erts_bs_init_writable), OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_bs_init_writable(header: *mut ProcessHeader, size: u64) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let size = crate::native_hooks::from_raw(size).as_small();
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
    if process.ensure(8, 0).is_err() {
        crate::native_hooks::set_error(process, "system_limit");
        process.sync_native_header();
        return 0;
    }
    let result = arinsal_bits::init_writable_with_size(size, &mut process.heap);
    process.sync_native_header();
    match result {
        Ok(value) => crate::native_hooks::raw(value),
        Err(_) => {
            crate::native_hooks::set_error(process, "system_limit");
            process.sync_native_header();
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
        .cold
        .as_ref()
        .and_then(|cold| cold.signal_probe.as_ref())
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
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    // Port of erts/emulator/beam/jit/arm/instr_msg.cpp:116-118, 179, 191 (F_DELAY_GC set on
    // entry, cleared on the wait and schedule-out exits), OTP-29.1.1.
    process.delay_gc = true;
    if let Some(message) = process.inbox.get(process.receive_cursor) {
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
        .cold
        .as_ref()
        .and_then(|cold| cold.signal_probe.as_ref())
        .is_none_or(arinsal_sched::SignalProbe::has_pending);
    if !pending {
        process.delay_gc = false;
        return 0;
    }
    // Port of erts/emulator/beam/jit/arm/instr_msg.cpp:131-176 (erts_proc_sig_receive_helper
    // call under eHeapAlloc), OTP-29.1.1: fetch messages in place and peek again.
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
    let fetched = process.fetch_messages_in_place();
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
    process.sync_native_header();
    if fetched.is_ok()
        && let Some(message) = process.inbox.get(process.receive_cursor)
    {
        return crate::native_hooks::raw(*message);
    }
    process.delay_gc = false;
    // Everything fetched was scanned: wait. A non-message signal left at the head of the
    // outer queue is handled by the scheduler.
    if fetched.is_ok()
        && process
            .cold
            .as_ref()
            .and_then(|cold| cold.signal_probe.as_ref())
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
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return fcalls;
    };
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:1087-1089 (beam_jit_remove_message),
    // OTP-29.1.1.
    if active_code_ix == crate::code_ix::ERTS_SAVE_CALLS_CODE_IX {
        crate::trace::save_call(process, crate::trace::SavedCall::Receive);
    }
    // A message carrying a seq_trace token emits its `receive` event on the receiver's own
    // heap here (the tracer may be the receiver itself), so the native HTOP and stack
    // pointer must round-trip like in every other allocating helper.
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
    let result = process.remove_message(None);
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
    process.sync_native_header();
    if result.is_err() {
        crate::native_hooks::set_error(process, "system_limit");
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
        let cold = process.cold_mut();
        let timeout = cold.native_wait_timeout.take();
        cold.native_wait = Some(timeout);
        cold.native_wait_self = resume & 1 != 0;
        process.native_exit_kind = crate::proc_create::NativeExit::Wait;
    }
}

/// Takes the receive lock; the private queue needs no lock here.
pub extern "C" fn arinsal_beamasm_take_receive_lock(_header: *mut ProcessHeader) {}

/// Starts a timed wait: zero means the timeout already expired, one that the process waits.
pub extern "C" fn arinsal_beamasm_wait_timeout(
    header: *mut ProcessHeader,
    timeout: u64,
    _next: usize,
) -> i32 {
    let Some((process, _registers)) = crate::native_hooks::enter_runtime(header) else {
        return -1;
    };
    match process.wait_timeout(crate::native_hooks::from_raw(timeout)) {
        Ok(Some(0)) => 0,
        Ok(remaining) => {
            process.cold_mut().native_wait_timeout = remaining;
            1
        }
        Err(_) => {
            crate::native_hooks::set_error(process, "timeout_value");
            -1
        }
    }
}

/// Clears the receive timeout state (`timeout`, `timeout_locked`).
pub extern "C" fn arinsal_beamasm_timeout(header: *mut ProcessHeader) {
    if let Some((process, _registers)) = crate::native_hooks::enter_runtime(header) {
        process.timeout();
        // Port of erts/emulator/beam/jit/beam_jit_common.cpp:1246-1248 (beam_jit_timeout),
        // OTP-29.1.1.
        if crate::trace::saves_calls(process) {
            crate::trace::save_call(process, crate::trace::SavedCall::Timeout);
        }
        if crate::trace::active() {
            process.cold_mut().native_timeout_trace = true;
            process.native_exit_kind = crate::proc_create::NativeExit::TimeoutTrace;
        }
    }
}

fn match_strings() -> &'static std::sync::RwLock<Vec<std::sync::Arc<[u8]>>> {
    static STRINGS: std::sync::OnceLock<std::sync::RwLock<Vec<std::sync::Arc<[u8]>>>> =
        std::sync::OnceLock::new();
    STRINGS.get_or_init(|| std::sync::RwLock::new(Vec::new()))
}

/// Registers a string-table constant matched by `i_bs_match_string` and returns its handle.
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
    module: String,
    function: String,
    arity: u8,
    /// The `call_nif` operands, written once by `load_nif` before the body is enabled.
    call: std::sync::OnceLock<crate::natives::nif::NativeFn>,
}

impl NativeNifSite {
    pub(crate) fn new(module: String, function: String, arity: u8) -> Box<Self> {
        Box::new(Self {
            module,
            function,
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
    let fcalls = process.reductions;
    let zstd_caller = (module == "zstd").then(|| process.self_pid.and_then(|pid| pid.to_term()));
    Some(crate::dirty::static_nif_job(move |heap| {
        let mut fcalls = fcalls;
        let mut run = || {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                crate::calls::call_bif(heap, &mut fcalls, entry, &args)
            }))
            .unwrap_or_else(|_| Err(arinsal_bifs::BifError::Error(crate::signals::atom("error"))))
        };
        match zstd_caller {
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
            crate::signals::atom("undef"),
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
        .and_then(|cold| cold.nif_pending.take());
    let done = process
        .cold
        .as_mut()
        .and_then(|cold| cold.static_nif_done.take());
    let result = match done {
        Some(result) => result,
        None => std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match pending {
            Some(pending) => crate::natives::nif::resume_pending(
                &mut process.heap,
                &mut process.reductions,
                pending,
            ),
            None => {
                crate::calls::call_bif(&mut process.heap, &mut process.reductions, entry, &args)
            }
        }))
        .unwrap_or_else(|_| Err(arinsal_bifs::BifError::Error(crate::signals::atom("error")))),
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
        .and_then(|cold| cold.nif_pending.take())
    else {
        return Err(crate::VmError::Trap(crate::exceptions::Trap::error(
            crate::signals::atom("undef"),
        )));
    };
    let (module, function, arity) = {
        let (module, function, arity) = pending.trace_mfa();
        (module.to_owned(), function.to_owned(), usize::from(arity))
    };
    crate::natives::nif::refresh_hub_native(process);
    let args = process.x.get(..arity).unwrap_or_default().to_vec();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::natives::nif::resume_pending(&mut process.heap, &mut process.reductions, pending)
    }))
    .unwrap_or_else(|_| Err(arinsal_bifs::BifError::Error(crate::signals::atom("error"))));
    result.map_err(|error| crate::exceptions::bif_error(process, &module, &function, &args, error))
}

/// Moves the arguments of a native call-NIF body into `process.x`.
fn enter_native_nif(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    arity: u8,
) {
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
    process.reductions = process.header.fcalls;
    process.x.ensure_x(usize::from(arity));
}

/// Returns the result of a native call-NIF body to native code: the result term, a trap to
/// the dirty scheduler executor or an exception.
fn leave_native_nif(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    result: std::thread::Result<Result<Term, arinsal_bifs::BifError>>,
    (identity, module, function, arity): (usize, &str, &str, u8),
) -> u64 {
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
    match result {
        Ok(Ok(value)) => {
            process.x[0] = value;
            process.sync_native_header();
            crate::native_hooks::raw(value)
        }
        Ok(Err(arinsal_bifs::BifError::Dirty(class))) => {
            // Port of erts/emulator/beam/erl_nif.c:3460 (static_schedule_dirty_nif) and
            // erl_nif.c:3540 (enif_schedule_nif), OTP-29.1.1: the call traps to a
            // continuation the executor runs on a scheduler of `class`.
            if let Some(pending) = crate::natives::nif::take_rescheduled() {
                process.cold_mut().nif_pending = Some(pending);
            }
            trap_to_dirty_nif(process, identity, class, arity)
        }
        Ok(Err(error)) => {
            let args = process.x[..usize::from(arity)].to_vec();
            set_native_bif_error(process, module, function, &args, error);
            process.sync_native_header();
            0
        }
        Err(_) => {
            crate::native_hooks::set_error(process, "error");
            process.sync_native_header();
            0
        }
    }
}

/// Calls a static NIF body through the same BIF function used by NativeBody.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:863-900, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_static_nif(header: *mut ProcessHeader, identity: u64) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
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
    enter_native_nif(process, registers, nif.arity);
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
            &mut process.reductions,
            nif.entry,
            &process.x[..usize::from(nif.arity)],
        )
    }));
    leave_native_nif(
        process,
        registers,
        result,
        (identity as usize, &nif.module, &nif.function, nif.arity),
    )
}

/// Calls the NIF that `load_nif` bound to a native call-NIF body.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:863-900 (call_nif_shared loads Func and
// NifMod from the function's code) and erts/emulator/beam/jit/beam_jit_common.cpp:623-677
// (beam_jit_call_nif), OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_call_nif(header: *mut ProcessHeader, site: u64) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
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
    enter_native_nif(process, registers, site.arity);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::natives::nif::call_native(
            &mut process.heap,
            &mut process.reductions,
            native,
            &process.x[..usize::from(site.arity)],
        )
    }));
    leave_native_nif(
        process,
        registers,
        result,
        (BOUND_NIF, &site.module, &site.function, site.arity),
    )
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
    process.cold_mut().native_dirty_nif = Some((identity, 0, class));
    process.header.arity = arity;
    process.gc_live = usize::from(arity);
    process.header.i =
        arinsal_beamasm::dispatch::DIRTY_NIF_DISPATCH_IDENTITY as *const u8 as *const _;
    process.header.freason = 1 << 10;
    process.sync_native_header();
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

/// Reads the active process dictionary for native `i_get` / `bif get` instructions.
// Port of erts/emulator/beam/erl_process_dict.c:463-471 (`erts_pd_hash_get`) and
// jit/arm/instr_common.cpp:319-329 (`emit_i_get`), OTP-29.1.1.
// The call is `Spec = 0`: HTOP is not stored, and the lookup does not allocate,
// so the heap index is left where the last allocating call put it. A boxed key
// is followed by its own pointer (`EQ`), not by that index.
pub extern "C" fn arinsal_beamasm_process_dictionary_get(
    header: *mut ProcessHeader,
    key: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(header) else {
        return 0;
    };
    dictionary_get(process, crate::native_hooks::from_raw(key))
}

/// `erlang:get/1` from the export's function pointer.
// Port of erts/emulator/beam/erl_process_dict.c:324-330 (`get_1`), OTP-29.1.1.
pub(crate) extern "C" fn get_1_light(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    _i: u64,
    _entry: u64,
    _identity: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(header) else {
        return 0;
    };
    // `x1` is the register array. Reading it through the scheduler file avoids a
    // fresh pointer load: `enter_runtime` would also commit HTOP, which `get_1` does not.
    let Some(key) = process.x.first().copied() else {
        return 0;
    };
    dictionary_get(process, key)
}

/// `persistent_term:get/1` from the export's function pointer.
// Port of erts/emulator/beam/erl_bif_persistent.c:380 (`persistent_term_get_1`), OTP-29.1.1.
pub(crate) extern "C" fn persistent_term_get_1_light(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    _i: u64,
    _entry: u64,
    _identity: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(header) else {
        return 0;
    };
    let Some(key) = process.x.first().copied() else {
        return 0;
    };
    let found = process._persistent_terms.store().get(key);
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
    _entry: u64,
    _identity: u64,
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
    let value = process
        ._persistent_terms
        .store()
        .get(key)
        .unwrap_or(default);
    crate::native_hooks::raw(value)
}

fn dictionary_get(process: &crate::Process, key: Term) -> u64 {
    let value = process
        .dictionary
        .as_ref()
        .and_then(|dictionary| dictionary.get(key))
        .unwrap_or_else(undefined_atom);
    crate::native_hooks::raw(value)
}

fn undefined_atom() -> Term {
    static UNDEFINED: std::sync::OnceLock<Term> = std::sync::OnceLock::new();
    *UNDEFINED.get_or_init(|| {
        Term::atom(
            arinsal_term::global_atoms()
                .intern("undefined")
                .expect("built-in atom"),
        )
    })
}

/// Completes a traced native return and resumes its saved caller continuation.
// Port of erts/emulator/beam/jit/arm/instr_trace.cpp:152-195, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_native_trace_return(header: *mut ProcessHeader) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let value = process.x[0];
    let Some((frames, saved_caller)) =
        crate::trace::pop_native_trace_frames(process, |p, words| {
            p.heap.set_stack_pointer(p.header.stop.wrapping_add(words));
            p.sync_native_header();
        })
    else {
        return process
            .heap
            .stack_get(0)
            .map_or(0, |word| word.tagged_word());
    };
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
    if frames
        .iter()
        .all(|(_, actions)| actions.iter().all(|action| action.acc.is_some()))
        && let Some(pid) = process.self_pid
    {
        // Port of erts/emulator/beam/emu/trace_instrs.tab:54-70 (i_call_trace_return calls
        // erts_call_trace_return), OTP-29.1.1: call time and memory accounting needs no tracer
        // context, so the return stays in native code.
        for (_, actions) in &frames {
            for action in actions.iter().rev() {
                if let Some(acc) = action.acc {
                    crate::trace::call_acc_return(
                        process,
                        pid,
                        action.session,
                        acc.flags,
                        acc.prev,
                    );
                }
            }
        }
        return saved_caller.tagged_word();
    }
    if frames.iter().any(|(_, actions)| !actions.is_empty()) {
        // The return events need the scheduler's tracer context (and the return_to event the
        // caller), so the return leaves native code like a trapped call and resumes at the
        // caller.
        // Port of erts/emulator/beam/emu/trace_instrs.tab:25-105 (return_trace,
        // i_return_to_trace), OTP-29.1.1.
        process.cold_mut().native_return_events = Some((frames, value));
        registers.tmp_mem[0] = arinsal_beamasm::dispatch::RETURN_TO_DISPATCH_IDENTITY as u64;
        registers.tmp_mem[1] = saved_caller.tagged_word();
        registers.tmp_mem[3] = 2;
        return arinsal_beamasm::rt::arinsal_enter_native_return as *const () as usize as u64;
    }
    saved_caller.tagged_word()
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
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
    // emit_enter_runtime just stored the live HTOP and E. The heap indices
    // still describe the last runtime exit; collecting from them treats the
    // native frames as empty and sync_native_header publishes that cursor.
    process.heap.set_native_cursors_at(
        process.header.heap,
        process.header.htop,
        process.header.stop,
    );
    // The emitter passes the full checked free-space gap, including CP and
    // S_RESERVED. Process::ensure uses that gap to decide whether to collect.
    // `process.x` is the scheduler's X register array: the live prefix is rooted and moved in
    // place, as in erts_garbage_collect_nobump on `reg`.
    let result = process.ensure_uncharged(need_words, live);
    if result.is_err() {
        crate::native_hooks::set_error(process, "system_limit");
    }
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
    process.sync_native_header();
    // Port of erts/emulator/beam/erl_gc.c:588-597 and 975-980 (a delayed collection
    // returns the reductions left), OTP-29.1.1: FCALLS runs out and the process yields at
    // its next reduction check.
    if process.force_yield {
        return fcalls.max(0);
    }
    // Port of erts/emulator/beam/erl_gc.c (erts_garbage_collect_nobump), OTP-29.1.1:
    // the collection's cost, at most the reductions left, is what the generated code
    // subtracts from FCALLS.
    i32::try_from(result.unwrap_or(0))
        .unwrap_or(i32::MAX)
        .min(fcalls.max(0))
}

/// `send` from its own fragment. A traced send, a port id, or a registered port
/// returns to the scheduler; a local pid or process name is delivered here.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:612-624 and bif.c:2458 (do_send), OTP-29.1.1.
fn dispatch_native_send(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    saving_calls: bool,
) -> Option<u64> {
    if saving_calls {
        crate::trace::save_call_send_export(process);
    }
    process.reductions = process.header.fcalls;
    // A port id may suspend the sender (bif.c:2581). A registered name is resolved
    // once inside the send; a port name comes back here to be redone by the scheduler.
    let target = registers.x_reg_array[0];
    let message = registers.x_reg_array[1];
    let result = if crate::trace::traces_sends(process) || target.as_port().is_some() {
        Err(crate::VmError::Unsupported(
            crate::process::REMOTE_SEND_NEEDS_CONTEXT.into(),
        ))
    } else if target.as_atom().is_some() {
        process.send_message_native(target, message)
    } else {
        process.send_message(target, message)
    };
    match result {
        Ok(value) => {
            // Port of erts/emulator/beam/bif.c:2451-2452 (erl_send: save_calls(p, &exp_send)),
            // OTP-29.1.1.
            if crate::trace::saves_calls(process) {
                crate::trace::save_call(process, crate::trace::SavedCall::Send);
            }
            let raw = crate::native_hooks::raw(value);
            registers.x_reg_array[0] = value;
            process.sync_native_header();
            Some(raw)
        }
        Err(crate::VmError::Unsupported(message))
            if message == crate::process::REMOTE_SEND_NEEDS_CONTEXT =>
        {
            if crate::trace::saves_calls(process) {
                crate::trace::save_call(process, crate::trace::SavedCall::Send);
            }
            process.header.arity = 2;
            process.header.i =
                arinsal_beamasm::dispatch::SEND_DISPATCH_IDENTITY as *const u8 as *const _;
            process.header.freason = 1 << 10;
            process.sync_native_header();
            None
        }
        Err(_) => {
            crate::native_hooks::set_error(process, "badarg");
            process.sync_native_header();
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
    if (
        function.module.as_str(),
        function.function.as_str(),
        function.arity,
    ) == ("erts_internal", "breakpoint", 4)
    {
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
        if !process.heap.stack_set(index, registers.x_reg_array[index]) {
            crate::native_hooks::set_error(process, "system_limit");
            process.sync_native_header();
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
    process.header.arity = 4;
    process.sync_native_header();
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
    process.sync_native_header();
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
        let own = crate::bif_table::entry(&export.module, &export.function, export.arity);
        if crate::bif_table::never_allocates(&export.module, &export.function, export.arity) {
            return Some(own.map_or(plain_bif_light as *const () as usize, |e| {
                e.list_slice_nonalloc
            }));
        }
        return Some(own.map_or(plain_bif_light as *const () as usize, |e| e.list_slice));
    }
    // The kind is fixed when the export is created (`bif_table[].f`). The call
    // fragment branches to that pointer; it does not walk `invoke_dispatch_bif`.
    if export.light_bif.is_some() {
        let own = crate::bif_table::entry(&export.module, &export.function, export.arity);
        return Some(own.map_or(plain_bif_light as *const () as usize, |e| e.plain));
    }
    if export.light_process_bif.is_some() {
        return Some(
            crate::natives::thin_entry(&export.module, &export.function, export.arity)
                .unwrap_or(process_bif_light as *const () as usize),
        );
    }
    if export.direct_ets.is_some() {
        return Some(direct_bif_light as *const () as usize);
    }
    if export.light_trap_bif.is_some() {
        if let Some(func) =
            crate::bif_table::trap_entry(&export.module, &export.function, export.arity)
        {
            return Some(func);
        }
        return Some(trap_bif_light as *const () as usize);
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
        Some(yield_executor_bif as *const () as usize)
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
    entry: u64,
    identity: u64,
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
    yield_executor_bif(header, regs, i, entry, identity)
}

/// `process_flag/2` for the flags that need no scheduler context.
fn process_flag_ctxfree_light(header: *mut ProcessHeader) -> Option<u64> {
    let (process, registers) = crate::native_hooks::enter_runtime(header)?;
    let (name, value) = (registers.x_reg_array[0], registers.x_reg_array[1]);
    let previous = crate::natives::proc::process_flag_ctxfree(process, name, value)?;
    registers.x_reg_array[0] = previous;
    Some(crate::native_hooks::raw(previous))
}

/// `erlang:self/0`. `c_p->common.id`, already the tagged pid on the header.
// Port of erts/emulator/beam/bif.c (`self_0`), OTP-29.1.1.
pub(crate) extern "C" fn self_light(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    _i: u64,
    _entry: u64,
    _identity: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(header) else {
        return 0;
    };
    process.header.self_pid
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
    descriptor: u64,
    identity: u64,
) -> u64 {
    if let Some(raw) = timer_start_native(header, descriptor, SEND_AFTER) {
        return raw;
    }
    yield_executor_bif(header, regs, i, descriptor, identity)
}

fn timer_start_native(
    header: *mut ProcessHeader,
    descriptor: u64,
    send_after: bool,
) -> Option<u64> {
    let (process, registers) = crate::native_hooks::enter_runtime(header)?;
    let export = crate::beamasm_integration::export_from_info(descriptor)?;
    let arity = usize::from(export.arity);
    let mut args = [Term::NIL; 4];
    args[..arity].copy_from_slice(&registers.x_reg_array[..arity]);
    let mut sink = crate::signals::NativeTimers(process.self_pid?);
    let term =
        crate::signals::start_timer_bif(process, &mut sink, &args[..arity], send_after).ok()?;
    let top = process.heap.heap_top_index();
    process.header.htop = native_htop(process, top);
    registers.x_reg_array[0] = term;
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
    descriptor: u64,
    identity: u64,
) -> u64 {
    if let Some(raw) = timer_query_native(header, descriptor, CANCEL) {
        return raw;
    }
    yield_executor_bif(header, regs, i, descriptor, identity)
}

fn timer_query_native(header: *mut ProcessHeader, descriptor: u64, cancel: bool) -> Option<u64> {
    let (process, registers) = crate::native_hooks::enter_runtime(header)?;
    let export = crate::beamasm_integration::export_from_info(descriptor)?;
    let info = if export.arity == 2 {
        let options = crate::signals::timer_query_options(registers.x_reg_array[1], cancel).ok()?;
        if options.asynchronous {
            return None;
        }
        options.info
    } else {
        true
    };
    let reference = registers.x_reg_array[0];
    // Port of erts/emulator/beam/erl_hl_timer.c:2237 (access_bif_timer): a reference made on
    // this scheduler names a timer on its own wheel, which answers without any request.
    if process.pending_signal_waiter.is_none()
        && let Some(key) = crate::signals::ref_id(reference)
        && let Some(remaining) =
            arinsal_sched::native_access_timer::<crate::process::Message>(key, cancel)
    {
        let term = if !info {
            crate::signals::atom("ok")
        } else {
            remaining
                .and_then(|ms| Term::small(ms as i64))
                .unwrap_or_else(|| crate::signals::atom("false"))
        };
        registers.x_reg_array[0] = term;
        return Some(crate::native_hooks::raw(term));
    }
    let term =
        crate::signals::timer_query_sync(process, process.self_pid?, reference, cancel, info)
            .ok()?;
    let top = process.heap.heap_top_index();
    process.header.htop = native_htop(process, top);
    registers.x_reg_array[0] = term;
    Some(crate::native_hooks::raw(term))
}

/// `erlang:group_leader/0`: the calling process's group leader, an immediate pid.
// Port of erts/emulator/beam/bif.c (`group_leader_0`: `BIF_RET(BIF_P->group_leader)`),
// OTP-29.1.1.
pub(crate) extern "C" fn group_leader_0_light(
    header: *mut ProcessHeader,
    regs: *mut u64,
    i: u64,
    descriptor: u64,
    identity: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(header) else {
        return 0;
    };
    if let Some(pid) = process.self_pid
        && let Some(leader) = process.group_leader_pid(pid).to_term()
    {
        return crate::native_hooks::raw(leader);
    }
    yield_executor_bif(header, regs, i, descriptor, identity)
}

/// `erlang:node/0`.
// Port of erts/emulator/beam/dist.c:6230 (`node_0`), OTP-29.1.1.
pub(crate) extern "C" fn node_light(
    _header: *mut ProcessHeader,
    _regs: *mut u64,
    _i: u64,
    _entry: u64,
    _identity: u64,
) -> u64 {
    crate::native_hooks::raw(crate::natives::node::node_0_term())
}

/// A BIF the executor still owns. `THE_NON_VALUE` with the trap reason, so the
/// fragment context-switches. This is not [`invoke_dispatch_bif`].
pub(crate) extern "C" fn yield_executor_bif(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    _i: u64,
    descriptor: u64,
    identity: u64,
) -> u64 {
    let Some((process, _)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    park_executor(process, export, identity)
}

/// `THE_NON_VALUE` + trap reason. The fragment context-switches into the executor.
fn park_executor(process: &mut crate::Process, export: ExportDispatch, identity: u64) -> u64 {
    process.header.arity = export.arity;
    process.reductions = process.header.fcalls;
    process.header.i = identity as *const u8 as *const _;
    process.header.freason = 1 << 10;
    process.sync_native_header();
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

/// `put/2` from `call_bif_shared`: the process dictionary, no executor.
// Port of erts/emulator/beam/erl_process_dict.c:353-360 (put_2), OTP-29.1.1.
pub(crate) extern "C" fn put_2_light(header: *mut ProcessHeader, regs: *mut u64, _i: u64) -> u64 {
    if regs.is_null() {
        return 0;
    }
    let Some(process) = crate::native_hooks::process_from_header(header) else {
        return 0;
    };
    let (Some(key), Some(value)) = (process.x.first().copied(), process.x.get(1).copied()) else {
        return 0;
    };
    // The export fragment already subtracted the call from FCALLS.
    process.reductions = process.header.fcalls;
    crate::native_hooks::raw(crate::natives::proc::dict_put(process, key, value))
}

/// `erase/1` from `call_bif_shared`.
// Port of erts/emulator/beam/erl_process_dict.c:373-379 (erase_1), OTP-29.1.1.
pub(crate) extern "C" fn erase_1_light(header: *mut ProcessHeader, regs: *mut u64, _i: u64) -> u64 {
    if regs.is_null() {
        return 0;
    }
    let Some(process) = crate::native_hooks::process_from_header(header) else {
        return 0;
    };
    let Some(key) = process.x.first().copied() else {
        return 0;
    };
    process.reductions = process.header.fcalls;
    crate::native_hooks::raw(crate::natives::proc::dict_erase(process, key))
}

/// `atom_to_list/1` as the BIF `call_light_bif_shared` branches to.
// Port of erts/emulator/beam/bif.c:3186-3210 (`atom_to_list_1`) and
// erl_unicode.c:1388-1395 (`erts_atom_to_string`: latin1 names are
// `buf_to_intlist` of the atom bytes), OTP-29.1.1.
pub(crate) extern "C" fn atom_to_list_light(
    header: *mut ProcessHeader,
    regs: *mut u64,
    _i: u64,
    descriptor: u64,
    _identity: u64,
) -> u64 {
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
    process.reductions = process.header.fcalls;
    if bytes.is_empty() {
        return Some(crate::native_hooks::raw(Term::NIL));
    }
    // The fragment stored HTOP. Commit it so `HAlloc` bumps the same index,
    // then publish the new pointer for `emit_leave_runtime`.
    process.heap.set_native_cursors_at(
        process.header.heap,
        process.header.htop,
        process.header.stop,
    );
    let term = arinsal_term::TermBuilder::new(&mut process.heap)
        .byte_string_list(bytes)
        .ok()?;
    let top = process.heap.heap_top_index();
    process.header.htop = native_htop(process, top);
    Some(crate::native_hooks::raw(term))
}

/// `integer_to_binary/1` as the BIF `call_light_bif_shared` branches to.
// Port of erts/emulator/beam/binary.c:80-127 (integer_to_binary), OTP-29.1.1.
pub(crate) extern "C" fn integer_to_binary_light(
    header: *mut ProcessHeader,
    regs: *mut u64,
    _i: u64,
    descriptor: u64,
    _identity: u64,
) -> u64 {
    allocating_bif(header, regs, descriptor, 1, |heap, arg| {
        arinsal_arith::integer_to_binary_decimal(arg, heap).map_err(arith_bif_error)
    })
}

fn binary_guard_apply(
    process: &mut crate::Process,
    export: ExportDispatch,
    args: &[Term],
) -> Result<Term, arinsal_bifs::BifError> {
    match crate::bif_table::binary_guard(&export.module, &export.function, export.arity) {
        Some(crate::bif_table::BinaryGuard::ByteSize | crate::bif_table::BinaryGuard::BitSize) => {
            let is_byte_size = matches!(
                crate::bif_table::binary_guard(&export.module, &export.function, export.arity),
                Some(crate::bif_table::BinaryGuard::ByteSize)
            );
            let bits = arinsal_bifs::bitstring_bit_len(args[0]);
            match bits {
                Ok(bits) => {
                    let value = if is_byte_size { bits.div_ceil(8) } else { bits };
                    let mut fragment = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
                    arinsal_term::TermBuilder::new(&mut fragment)
                        .int_from_u64(value as u64)
                        .map_err(|_| arinsal_bifs::BifError::SystemLimit)
                }
                Err(error) => Err(error),
            }
        }
        Some(crate::bif_table::BinaryGuard::BinaryPart) => {
            if export.arity == 3 {
                return binary_part_3_apply(process, args);
            }
            let (result, reductions) = {
                let mut fragment = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
                let mut ctx = arinsal_bifs::Ctx::new(&mut fragment);
                let result = arinsal_bifs::binary_part_2(&mut ctx, args);
                (result, ctx.reductions())
            };
            charge_bif_reductions(process, reductions);
            result
        }
        None => Err(arinsal_bifs::BifError::Badarg { cause: None }),
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
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    export: ExportDispatch,
    args: &[Term],
    light: bool,
) -> u64 {
    process.reductions = process.header.fcalls;
    let entry_top = process.heap.heap_top_index();
    let result = binary_guard_apply(process, export, args);
    let top = process.heap.heap_top_index();
    if top != entry_top {
        process.header.htop = process.heap.word_address(top);
    }
    if process.header.fcalls != process.reductions {
        process.header.fcalls = process.reductions;
    }
    match result {
        Ok(value) => {
            if light {
                registers.x_reg_array[0] = value;
                process.sync_native_header();
            }
            crate::native_hooks::raw(value)
        }
        Err(error) => {
            set_native_bif_error(process, &export.module, &export.function, args, error);
            process.sync_native_header();
            0
        }
    }
}

fn binary_guard_light(header: *mut ProcessHeader, descriptor: u64, arity: usize) -> u64 {
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    if usize::from(export.arity) != arity {
        return 0;
    }
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let mut args = [Term::NIL; 3];
    args[..arity].copy_from_slice(&registers.x_reg_array[..arity]);
    binary_guard_result(process, registers, export, &args[..arity], true)
}

/// Dedicated BeamAsm entry for `byte_size/1` and its guard form.
// Port of erts/emulator/beam/erl_bif_guard.c:376 (`byte_size_1`), OTP-29.1.1.
pub(crate) extern "C" fn byte_size_light(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    _i: u64,
    descriptor: u64,
    _identity: u64,
) -> u64 {
    binary_guard_light(header, descriptor, 1)
}

/// Dedicated BeamAsm entry for `bit_size/1` and its guard form.
// Port of erts/emulator/beam/erl_bif_guard.c:354 (`bit_size_1`), OTP-29.1.1.
pub(crate) extern "C" fn bit_size_light(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    _i: u64,
    descriptor: u64,
    _identity: u64,
) -> u64 {
    binary_guard_light(header, descriptor, 1)
}

/// Dedicated BeamAsm entry for `binary_part/2` and `binary:part/2`.
// Port of erts/emulator/beam/erl_bif_binary.c:1954-2038 (`erts_binary_part`), OTP-29.1.1.
pub(crate) extern "C" fn binary_part_2_light(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    _i: u64,
    descriptor: u64,
    _identity: u64,
) -> u64 {
    binary_guard_light(header, descriptor, 2)
}

/// Dedicated BeamAsm entry for `binary_part/3` and `binary:part/3`.
// Port of erts/emulator/beam/erl_bif_binary.c:1954-2038 (`erts_binary_part`), OTP-29.1.1.
pub(crate) extern "C" fn binary_part_3_light(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    _i: u64,
    descriptor: u64,
    _identity: u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    process.reductions = process.header.fcalls;
    let args = [
        registers.x_reg_array[0],
        registers.x_reg_array[1],
        registers.x_reg_array[2],
    ];
    let entry_top = process.heap.heap_top_index();
    let result = binary_part_3_apply(process, &args);
    let top = process.heap.heap_top_index();
    if top != entry_top {
        process.header.htop = process.heap.word_address(top);
    }
    if process.header.fcalls != process.reductions {
        process.header.fcalls = process.reductions;
    }
    match result {
        Ok(value) => {
            registers.x_reg_array[0] = value;
            process.sync_native_header();
            crate::native_hooks::raw(value)
        }
        Err(error) => {
            let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
                return 0;
            };
            set_native_bif_error(process, &export.module, &export.function, &args, error);
            process.sync_native_header();
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
    process.reductions = process.header.fcalls;
    // reg[0] is BIF_ARG_1, whether the fragment passed `regs` or left it in the
    // scheduler file `enter_runtime` already resolved.
    let _ = regs;
    let arg = registers.x_reg_array[0];
    let entry_top = process.heap.heap_top_index();
    let result = {
        let mut fragment = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        body(&mut fragment, arg)
    };
    let top = process.heap.heap_top_index();
    // The light fragment tests the collection after this call (instr_bif.cpp:488-523).
    if let Ok(value) = &result {
        let value = *value;
        registers.x_reg_array[0] = value;
        if top != entry_top {
            process.header.htop = native_htop(process, top);
        }
        return crate::native_hooks::raw(value);
    }
    // The fragment passed `Export.info`; the descriptor is the export, so no table lookup.
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        crate::native_hooks::set_error(process, "badarg");
        process.sync_native_header();
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
// Port of erts/emulator/beam/bif.c:2976-3003 (setelement_3), OTP-29.1.1.
pub(crate) extern "C" fn setelement_light(
    header: *mut ProcessHeader,
    regs: *mut u64,
    i: u64,
    entry: u64,
    identity: u64,
) -> u64 {
    match setelement_write(header, regs) {
        Some(raw) => raw,
        None => plain_bif_light(header, regs, i, entry, identity),
    }
}

/// `Some` is the new tuple. `None` means the generic BIF body must run.
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
        let src = tuple.raw_ptr();
        let hdr = *src;
        if hdr & 63 != 0 {
            return None;
        }
        let arity = (hdr >> 6) as usize;
        let slot = ix as usize;
        if slot > arity {
            return None;
        }
        let size = arity + 1;
        let process = &mut *header.cast::<crate::Process>();
        let htop = process.header.htop;
        let stop = process.header.stop;
        let top = htop as usize;
        let limit = (stop as usize).saturating_sub(arinsal_term::S_REDZONE * 8);
        if htop.is_null() || stop.is_null() || top.saturating_add(size.saturating_mul(8)) > limit {
            return None;
        }
        std::ptr::copy_nonoverlapping(src, htop, size);
        htop.add(slot).write(value);
        let next = htop.add(size);
        process.header.htop = next;
        process.heap.note_native_alloc(size);
        process.reductions = process.header.fcalls;
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
    descriptor: u64,
    _identity: u64,
) -> u64 {
    if header.is_null() {
        return 0;
    }
    // SAFETY: the light-BIF fragment passes c_p. HTOP and E were stored by
    // `emit_enter_runtime`. The reference cell belongs to this scheduler thread.
    unsafe {
        let process = &mut *header.cast::<crate::Process>();
        let htop = process.header.htop;
        let stop = process.header.stop;
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
        process.header.htop = next;
        process.heap.note_native_alloc(3);
        process.reductions = process.header.fcalls;
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
    descriptor: u64,
    _identity: u64,
) -> u64 {
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
    descriptor: u64,
    _identity: u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    let _ = regs;
    let arg = registers.x_reg_array[0];
    unique_integer_n(process, registers, export, false, &[arg])
}

/// A plain BIF: call `bif_table[].f` and return. Trace and save_calls already
/// branched to the helper in the fragment.
// Port of erts/emulator/beam/beam_jit_common.cpp:588-621 (`beam_jit_call_bif`), OTP-29.1.1.
pub(crate) extern "C" fn plain_bif_light(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    _i: u64,
    descriptor: u64,
    identity: u64,
) -> u64 {
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
        return park_executor(process, export, identity);
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
    descriptor: u64,
    identity: u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    call_plain_bif_body(
        process,
        registers,
        identity as usize,
        export,
        |process, args| B::call_process(process, args, instruction as usize),
        false,
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
    descriptor: u64,
    identity: u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime_no_cursors(header) else {
        return 0;
    };
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    if let Some(raw) = nonalloc_list_fast(process, registers, export, B::call) {
        return raw;
    }
    crate::native_hooks::convert_native_cursors(process);
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
    descriptor: u64,
    identity: u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime_no_cursors(header) else {
        return 0;
    };
    let args = [registers.x_reg_array[0], registers.x_reg_array[1]];
    let (result, deferred) = {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut process.header.fcalls);
        let result = arinsal_bifs::lists_member_bif(&mut ctx, &args);
        (result, ctx.take_deferred())
    };
    if let Some(trap) = deferred {
        process.reductions = process.header.fcalls;
        let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
            return 0;
        };
        crate::native_hooks::convert_native_cursors(process);
        crate::bif_traps::install_deferred_trap(
            process,
            identity as usize,
            (export.module_atom, export.function_atom),
            export.function.as_str(),
            &args,
            trap,
        );
        process
            .heap
            .set_frame_pointer(registers.tmp_mem[2] as usize);
        debug_assert_native_heap(process);
        crate::bif_traps::arm_export_trap(process);
        process.header.freason = 1 << 10;
        process.sync_native_header();
        return 0;
    }
    match result {
        Ok(value) => {
            registers.x_reg_array[0] = value;
            crate::native_hooks::raw(value)
        }
        Err(error) => {
            process.reductions = process.header.fcalls;
            let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
                return 0;
            };
            crate::native_hooks::convert_native_cursors(process);
            plain_bif_result(process, registers, export, 2, Err(error))
        }
    }
}

/// The value of a non-allocating list BIF, or `None` when it traps or fails (the caller then
/// converts the cursors and runs the full path).
#[inline(always)]
fn nonalloc_list_fast(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    export: ExportDispatch,
    bif: impl Fn(&mut arinsal_bifs::Ctx<'_>, &[Term]) -> Result<Term, arinsal_bifs::BifError>,
) -> Option<u64> {
    let arity = usize::from(export.arity);
    let value = {
        let mut fragment = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut fragment, &mut process.header.fcalls);
        let result = bif(&mut ctx, &registers.x_reg_array[..arity]);
        if ctx.take_deferred().is_some() {
            return None;
        }
        result.ok()?
    };
    registers.x_reg_array[0] = value;
    Some(crate::native_hooks::raw(value))
}

pub(crate) extern "C" fn list_slice_bif_entry<B: arinsal_bifs::BifBody>(
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

/// A process BIF (`c_p` plus the register array), chosen when the export was created.
pub(crate) extern "C" fn process_bif_light(
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
    let Some(bif) = export.light_process_bif else {
        return park_executor(process, export, identity);
    };
    match call_process_bif(process, registers, export, bif, false) {
        Some(raw) => raw,
        // The entry declined before any side effect: the executor runs the whole BIF.
        None => park_executor(process, export, identity),
    }
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
    descriptor: u64,
    _identity: u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    process.reductions = process.header.fcalls;
    let entry_top = process.heap.heap_top_index();
    match B::call(process, &registers.x_reg_array[..B::ARITY]) {
        Ok(value) => {
            registers.x_reg_array[0] = value;
            let top = process.heap.heap_top_index();
            if top != entry_top {
                process.header.htop = native_htop(process, top);
            }
            if process.header.fcalls != process.reductions {
                process.header.fcalls = process.reductions;
            }
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
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    descriptor: u64,
    trap: crate::exceptions::Trap,
) -> u64 {
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    process_bif_result(
        process,
        registers,
        export,
        usize::from(export.arity),
        Err(trap),
    )
}

/// An ETS or process-dictionary BIF whose body is `direct_ets`.
pub(crate) extern "C" fn direct_bif_light(
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
    if let Some(raw) = call_direct_bif(process, registers, export, false) {
        return raw;
    }
    process.header.arity = export.arity;
    process.header.i = identity as *const u8 as *const _;
    process.header.freason = 1 << 10;
    process.sync_native_header();
    0
}

/// A trapping BIF. A value returns here; a trap is `THE_NON_VALUE`.
pub(crate) extern "C" fn trap_bif_light(
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
    let Some(entry) = export.light_trap_bif else {
        return park_executor(process, export, identity);
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
    // The frame pointer matters only to a collection, so the paths that may collect publish
    // it themselves; a plain BIF leaves E (x29) as it was, like erts.
    let (process, registers) = crate::native_hooks::enter_runtime(header)?;
    // `send` is its own fragment (instr_bif.cpp:612), not a failed BIF dispatch.
    if identity == arinsal_beamasm::dispatch::SEND_DISPATCH_IDENTITY {
        let saving_calls = !export_call
            && registers.active_code_ix == crate::code_ix::ERTS_SAVE_CALLS_CODE_IX as u64;
        return dispatch_native_send(process, registers, saving_calls);
    }
    if let Some(export) = export {
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
            && let Some(raw) = call_direct_bif(process, registers, export, export_call)
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
        && let Some(raw) = call_process_bif(process, registers, export, bif, export_call)
    {
        return Some(raw);
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
    let (entry_top, stop) = (process.heap.heap_top_index(), process.heap.stack_index());
    let result =
        crate::signals::light_monitor_bif(process, monitor, &registers.x_reg_array[..arity])?;
    process.reductions = process.header.fcalls;
    if export_call {
        charge_bif_reductions(process, 1);
    }
    let top = process.heap.heap_top_index();
    // The light fragment tests the collection after its call (instr_bif.cpp:488-523); the
    // export trampoline has no such test and checks it here.
    if let Ok(value) = &result
        && (!export_call
            || (stop - top >= process.heap.mbuf_size() && !process.heap.bin_vheap_gc_due()))
    {
        let value = *value;
        registers.x_reg_array[0] = value;
        if top != entry_top {
            process.header.htop = process.heap.word_address(top);
        }
        if process.header.fcalls != process.reductions {
            process.header.fcalls = process.reductions;
        }
        return Some(crate::native_hooks::raw(value));
    }
    Some(process_bif_result(
        process, registers, export, arity, result,
    ))
}

/// Calls a trapping BIF straight from native code; `None` when it trapped.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-540 (call_light_bif_shared), OTP-29.1.1:
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
    process.reductions = process.header.fcalls;
    if export_call {
        charge_bif_reductions(process, 1);
    }
    let arity = usize::from(export.arity);
    if entry.reserves_heap()
        && let Ok(bits) = arinsal_bifs::bitstring_bit_len(registers.x_reg_array[0])
        && bits.is_multiple_of(8)
        && let Some(reserve) = (bits / 8).checked_mul(2).and_then(|n| n.checked_add(64))
    {
        // The decoder builds on the heap it reserved, with collection off until it is
        // done; the arguments stay live across the reservation.
        process
            .heap
            .set_frame_pointer(registers.tmp_mem[2] as usize);
        let ensured = process.ensure(reserve, arity);
        registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
        // A collection moved the heap: publish every cursor, not just HTOP.
        process.sync_native_header();
        if ensured.is_err() {
            crate::native_hooks::set_error(process, "system_limit");
            process.sync_native_header();
            return Some(0);
        }
    }
    let entry_top = process.heap.heap_top_index();
    let mut args = [Term::NIL; 4];
    args[..arity].copy_from_slice(&registers.x_reg_array[..arity]);
    let callee = (export.module_atom, export.function_atom);
    let outcome = crate::bif_traps::call_light(process, entry, identity, callee, &args[..arity]);
    match outcome {
        crate::bif_traps::LightTrap::Returned(result) => Some(light_trap_result(
            process,
            registers,
            export,
            arity,
            entry_top,
            export_call,
            result,
        )),
        crate::bif_traps::LightTrap::Trapped => arm_light_trap(process, registers, export),
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
    entry_top: usize,
    export_call: bool,
    result: Result<Term, arinsal_bifs::BifError>,
) -> u64 {
    match result {
        Ok(value) if !export_call => light_value_return(process, registers, entry_top, value),
        result => plain_bif_result(process, registers, export, arity, result),
    }
}

/// The fast return of a light BIF's value: X0, the heap top if it moved, and FCALLS.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:518-523 (call_light_bif_shared returns X0
// to the call site), OTP-29.1.1.
#[inline(always)]
fn light_value_return(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    entry_top: usize,
    value: Term,
) -> u64 {
    registers.x_reg_array[0] = value;
    let top = process.heap.heap_top_index();
    if top != entry_top {
        process.header.htop = native_htop(process, top);
    }
    if process.header.fcalls != process.reductions {
        process.header.fcalls = process.reductions;
    }
    crate::native_hooks::raw(value)
}

/// The trap state of a light BIF that yielded (`BIF_TRAP`): the caller resumes through the
/// continuation export when the scheduler runs the process again.
// Port of erts/emulator/beam/bif.h:316-326 (ERTS_BIF_PREP_TRAP), OTP-29.1.1.
fn arm_light_trap(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    export: ExportDispatch,
) -> Option<u64> {
    {
        // The scheduler resumes the caller's frame chain from the process.
        process
            .heap
            .set_frame_pointer(registers.tmp_mem[2] as usize);
        debug_assert_native_heap(process);
        debug_assert_eq!(
            process.heap.frame_pointer(),
            registers.tmp_mem[2] as usize,
            "light trapping BIF frame pointer is outside its process heap: mfa={}:{}/{}, candidate={:#x}, heap={:#x}..{:#x}, live_stack={:#x}..{:#x}, module={}, ip={:#x}",
            export.module,
            export.function,
            export.arity,
            registers.tmp_mem[2],
            process.heap.heap_bounds().0 as usize,
            process.heap.heap_bounds().1 as usize,
            process.heap.heap_cursor().1 as usize,
            process.heap.heap_bounds().1 as usize,
            process.module,
            process.ip,
        );
        // BIF_TRAP sets c_p->i to beam_bif_export_trap. The fragment loads that
        // address and context-switches; schedule-in calls the continuation export.
        crate::bif_traps::arm_export_trap(process);
        process.header.freason = 1 << 10;
        process.sync_native_header();
        None
    }
}

/// The light entry of one trapping BIF, compiled for its body `T` when the export is
/// created (`bif_table`). It has the signature of `trap_bif_light`.
// Port of erts/emulator/beam/erl_bif_table.c (`bif_table[].f`), OTP-29.1.1: a BIF with its own
// C function is called from the fragment directly; BIF_TRAP is taken only when the body yields.
pub(crate) extern "C" fn trap_bif_entry<T: crate::bif_traps::TrapBody>(
    header: *mut ProcessHeader,
    _regs: *mut u64,
    instruction: u64,
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
        return park_executor(process, export, identity);
    }
    trap_body_call::<T>(
        process,
        registers,
        identity as usize,
        instruction as usize,
        export,
    )
    .unwrap_or(0)
}

/// `lists:reverse/2` as its own light entry. The common call runs the body directly and
/// returns the list; a partial result (budget spent) takes the handler's yield path.
// Port of erts/emulator/beam/erl_bif_lists.c:1144-1263 (lists_reverse_2), OTP-29.1.1: the BIF
// is one function with its own budget, and BIF_TRAP is taken only when the budget runs out.
pub(crate) extern "C" fn list_reverse_entry(
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
        return park_executor(process, export, identity);
    }
    let entry_top = process.heap.heap_top_index();
    let gc_was_enabled = process.heap.gc_enabled;
    let reds = process.header.fcalls.clamp(0, 4000) as usize;
    let max_cells = reds
        .saturating_mul(arinsal_bifs::REVERSE_ONHEAP_CELLS_PER_RED)
        .max(1);
    let args = [registers.x_reg_array[0], registers.x_reg_array[1]];
    let step = {
        let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
        let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut heap, &mut process.header.fcalls);
        arinsal_bifs::lists_reverse(&mut ctx, args[0], args[1], max_cells)
    };
    let result = match step {
        Ok(arinsal_bifs::ReverseStep::Done(value)) => {
            process.set_gc_enabled(gc_was_enabled);
            registers.x_reg_array[0] = value;
            let top = process.heap.heap_top_index();
            if top != entry_top {
                process.header.htop = native_htop(process, top);
            }
            return crate::native_hooks::raw(value);
        }
        Ok(arinsal_bifs::ReverseStep::Trap(cont)) => Ok(crate::bif_traps::HandlerResult::Yield {
            continuation: "lists:reverse/2",
            state: arinsal_term::MagicRef::new(std::sync::Mutex::new(cont)),
            reductions: 0,
        }),
        Err(error) => Err(error),
    };
    process.reductions = process.header.fcalls;
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
            light_trap_result(process, registers, export, 2, entry_top, false, result)
        }
        crate::bif_traps::LightTrap::Trapped => {
            arm_light_trap(process, registers, export).unwrap_or(0)
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
    export: ExportDispatch,
) -> Option<u64> {
    process.reductions = process.header.fcalls;
    let arity = usize::from(export.arity);
    let entry_top = process.heap.heap_top_index();
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
            Some(light_value_return(process, registers, entry_top, value))
        }
        other => {
            let mut args = [Term::NIL; 3];
            args[..arity].copy_from_slice(&registers.x_reg_array[..arity]);
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
                    process, registers, export, arity, entry_top, false, result,
                )),
                crate::bif_traps::LightTrap::Trapped => arm_light_trap(process, registers, export),
            }
        }
    }
}

/// Checks heap cursors and the published native frame before a trap changes execution tiers.
pub(crate) fn debug_assert_native_heap(_process: &crate::Process) {
    #[cfg(debug_assertions)]
    {
        let (heap, end) = _process.heap.heap_bounds();
        let (htop, stop) = _process.heap.heap_cursor();
        let (heap, htop, stop, end) = (heap as usize, htop as usize, stop as usize, end as usize);
        debug_assert!(heap <= htop && htop <= stop && stop <= end);
        let frame_pointer = _process.heap.frame_pointer();
        debug_assert!(
            frame_pointer == 0 || (stop <= frame_pointer && frame_pointer < end),
            "native frame pointer {frame_pointer:#x} is outside the live stack {stop:#x}..{end:#x}"
        );
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
    if hit.actions.is_empty() {
        return true;
    }
    // The header holds the live reduction counter of the native code; publishing the header
    // below must not rewind it.
    process.reductions = process.header.fcalls;
    // The frame may need a collection, whose roots are the function's arguments.
    if crate::trace::push_native_trace_frame(process, site, &hit.actions, usize::from(hit.arity))
        .is_err()
    {
        crate::native_hooks::set_error(process, "system_limit");
    }
    // A delayed collection moves the stack and its frame pointer chain.
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
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
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
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
        process.header.i = identity as *const u8 as *const _;
        process.header.freason = 1 << 10;
        process.sync_native_header();
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
        process.reductions = process.header.fcalls;
        if export_call {
            charge_bif_reductions(process, 1);
        }
        process.header.arity = export.arity;
        process.header.i = identity as *const u8 as *const _;
        process.header.freason = 1 << 10;
        process.sync_native_header();
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
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    export: ExportDispatch,
    export_call: bool,
) -> Option<u64> {
    let direct = export.direct_ets?;
    if crate::trace_bp::any_pattern() {
        return None;
    }
    let arity = usize::from(export.arity).min(4);
    let args = [
        registers.x_reg_array[0],
        registers.x_reg_array[1],
        registers.x_reg_array[2],
        registers.x_reg_array[3],
    ];
    let value = direct(process, &args[..arity])?;
    process.reductions = process.header.fcalls;
    if export_call {
        charge_bif_reductions(process, 1);
    }
    // A direct BIF that failed has parked its exception (freason/fvalue set, as an erts
    // BIF returns THE_NON_VALUE); the call is not redone.
    if process.header.freason != 0 {
        process.sync_native_header();
        return Some(0);
    }
    registers.x_reg_array[0] = value;
    let mut raw = crate::native_hooks::raw(value);
    // The light fragment tests the collection after this call (instr_bif.cpp:488-523).
    if export_call && (process.heap.gc_desired() || process.heap.bin_vheap_gc_due()) {
        if process.collect_bin_vheap_if_due(1).is_err() {
            crate::native_hooks::set_error(process, "system_limit");
            process.sync_native_header();
            return Some(0);
        }
        raw = crate::native_hooks::raw(registers.x_reg_array[0]);
    }
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
    process.sync_native_header();
    Some(raw)
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
            let arg = registers.x_reg_array[0];
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
    let (entry_top, stop) = (process.heap.heap_top_index(), process.heap.stack_index());
    let words = arinsal_bifs::next_ref_words();
    // Common path is the young-heap bump (`HAlloc` when `HeapWordsLeft` is enough).
    // A full heap takes a fragment, as `HAlloc` calls `erts_heap_alloc`.
    let result = match Term::local_ref(&mut process.heap, words) {
        Ok(term) => Ok(term),
        Err(_) => make_ref_in_fragment(process, words),
    };
    finish_counter_bif(
        process,
        registers,
        export,
        export_call,
        entry_top,
        stop,
        result,
    )
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
    let (entry_top, stop) = (process.heap.heap_top_index(), process.heap.stack_index());
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
    finish_counter_bif(
        process,
        registers,
        export,
        export_call,
        entry_top,
        stop,
        result,
    )
}

#[inline(always)]
fn finish_counter_bif(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    export: ExportDispatch,
    export_call: bool,
    entry_top: usize,
    stop: usize,
    result: Result<Term, arinsal_bifs::BifError>,
) -> u64 {
    process.reductions = process.header.fcalls;
    if export_call {
        charge_bif_reductions(process, 1);
    }
    let top = process.heap.heap_top_index();
    // ERTS_IS_GC_DESIRED_INTERNAL: a value with no collection desired goes straight
    // back to XREG0. The check is the one `call_light_bif_shared` does after the BIF.
    if let Ok(value) = &result
        && (!export_call
            || (stop - top >= process.heap.mbuf_size() && !process.heap.bin_vheap_gc_due()))
    {
        let value = *value;
        registers.x_reg_array[0] = value;
        if top != entry_top {
            process.header.htop = process.heap.word_address(top);
        }
        if process.header.fcalls != process.reductions {
            process.header.fcalls = process.reductions;
        }
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
    process.reductions = process.header.fcalls;
    if export_call {
        charge_bif_reductions(process, 1);
    }
    let arity = usize::from(export.arity);
    let (entry_top, stop) = (process.heap.heap_top_index(), process.heap.stack_index());
    let mut fragment = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut fragment, &mut process.header.fcalls);
    let result = bif(&mut ctx, &registers.x_reg_array[..arity]);
    if let Some(trap) = ctx.take_deferred() {
        drop(ctx);
        process.reductions = process.header.fcalls;
        let mut args = [Term::NIL; 3];
        args[..arity].copy_from_slice(&registers.x_reg_array[..arity]);
        crate::bif_traps::install_deferred_trap(
            process,
            identity,
            (export.module_atom, export.function_atom),
            export.function.as_str(),
            &args[..arity],
            trap,
        );
        process
            .heap
            .set_frame_pointer(registers.tmp_mem[2] as usize);
        debug_assert_native_heap(process);
        crate::bif_traps::arm_export_trap(process);
        process.header.freason = 1 << 10;
        process.sync_native_header();
        return None;
    }
    drop(ctx);
    let top = process.heap.heap_top_index();
    if let Ok(value) = &result
        && (!export_call
            || (stop - top >= process.heap.mbuf_size() && !process.heap.bin_vheap_gc_due()))
    {
        let value = *value;
        registers.x_reg_array[0] = value;
        if top != entry_top {
            process.header.htop = native_htop(process, top);
        }
        return Some(crate::native_hooks::raw(value));
    }
    process.reductions = process.header.fcalls;
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
        process.header.fcalls = process.header.fcalls.saturating_sub(1);
    }
    let arity = usize::from(export.arity);
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-471 (call_light_bif_shared),
    // OTP-29.1.1: the BIF reads its arguments from the register array (BIF_ARG_n is reg[n]).
    // A BIF leaves E alone, so only HTOP is read back after it.
    let (entry_top, stop) = (process.heap.heap_top_index(), process.heap.stack_index());
    // The result is matched where the BIF wrote it: moving it first would read it back with
    // wider loads than the BIF's stores.
    let mut fragment = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut fragment, &mut process.header.fcalls);
    let result = bif(&mut ctx, &registers.x_reg_array[..arity]);
    let deferred = ctx.take_deferred();
    drop(ctx);
    if let Some(trap) = deferred {
        let mut args = [Term::NIL; 3];
        args[..arity].copy_from_slice(&registers.x_reg_array[..arity]);
        return install_deferred_bif_trap(
            process,
            registers,
            identity,
            export,
            &args[..arity],
            trap,
        );
    }
    let top = process.heap.heap_top_index();
    // ERTS_IS_GC_DESIRED_INTERNAL: a value goes straight back to XREG0, and the native
    // light-BIF fragment tests the collection itself (instr_bif.cpp:488-523). Only the
    // export trampoline, which has no such test, checks it here.
    if let Ok(value) = &result
        && (!export_call
            || (stop - top >= process.heap.mbuf_size() && !process.heap.bin_vheap_gc_due()))
    {
        let value = *value;
        registers.x_reg_array[0] = value;
        if top != entry_top {
            process.header.htop = native_htop(process, top);
        }
        return crate::native_hooks::raw(value);
    }
    process.reductions = process.header.fcalls;
    plain_bif_result(process, registers, export, arity, result)
}

/// Installs a BIF continuation after its process-bound context has returned.
fn install_deferred_bif_trap(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    identity: usize,
    export: ExportDispatch,
    args: &[Term],
    trap: Box<arinsal_bifs::DeferredTrap>,
) -> u64 {
    process.reductions = process.header.fcalls;
    crate::bif_traps::install_deferred_trap(
        process,
        identity,
        (export.module_atom, export.function_atom),
        export.function.as_str(),
        args,
        trap,
    );
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
    debug_assert_native_heap(process);
    crate::bif_traps::arm_export_trap(process);
    process.header.freason = 1 << 10;
    process.sync_native_header();
    0
}

/// `c_p->htop` after a BIF advanced the young heap by `index` words.
#[inline(always)]
fn native_htop(process: &crate::Process, index: usize) -> *mut u64 {
    let base = process.header.heap;
    if base.is_null() {
        process.heap.word_address(index)
    } else {
        base.wrapping_add(index)
    }
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
    process.reductions = process.header.fcalls;
    if export_call {
        charge_bif_reductions(process, 1);
    }
    let arity = usize::from(export.arity);
    // `garbage_collect` moves the heap and rebases the frame pointer. The light
    // fragment stored the Erlang frame in `tmp_mem[2]` and reloads heap bounds
    // from the process header on the way out (`RUNTIME_UPDATE`).
    let collects =
        (bif as usize) == (crate::natives::sys::garbage_collect_bif as *const () as usize);
    if collects {
        process
            .heap
            .set_frame_pointer(registers.tmp_mem[2] as usize);
    }
    let entry_top = process.heap.heap_top_index();
    let result = bif(process, &registers.x_reg_array[..arity])?;
    if collects {
        // The heap block moved. Heap indices from before the call belong to the
        // old block, so the post-BIF free-space check does not apply.
        registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
        process.sync_native_header();
        return Some(match result {
            Ok(value) => {
                registers.x_reg_array[0] = value;
                // A collection handed to a dirty scheduler must leave this one before
                // the next call. `leave_runtime` reloads FCALLS, and the next
                // `call_light_bif` yields when it is exhausted.
                // Port of erl_gc.c:588-597 (`force_reschedule`), OTP-29.1.1.
                if process.force_yield {
                    process.reductions = 0;
                    process.header.fcalls = 0;
                }
                crate::native_hooks::raw(value)
            }
            Err(error) => process_bif_result(process, registers, export, arity, Err(error)),
        });
    }
    let top = process.heap.heap_top_index();
    // The light fragment tests the collection after its call (instr_bif.cpp:488-523).
    if let Ok(value) = &result
        && (!export_call
            || (process.heap.stack_index() - top >= process.heap.mbuf_size()
                && !process.heap.bin_vheap_gc_due()))
    {
        let value = *value;
        registers.x_reg_array[0] = value;
        if top != entry_top {
            process.header.htop = native_htop(process, top);
        }
        if process.header.fcalls != process.reductions {
            process.header.fcalls = process.reductions;
        }
        return Some(crate::native_hooks::raw(value));
    }
    Some(process_bif_result(
        process, registers, export, arity, result,
    ))
}

/// A process BIF's exception, or a value after which a collection is desired.
// Port of erts/emulator/beam/erl_gc.c:418-478 (erts_gc_after_bif_call_lhf), OTP-29.1.1: the
// argument registers stay live across the collection.
#[cold]
#[inline(never)]
fn process_bif_result(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    export: ExportDispatch,
    arity: usize,
    mut result: Result<Term, crate::exceptions::Trap>,
) -> u64 {
    let collected = process.heap.gc_after_bif_desired();
    if collected {
        process
            .heap
            .set_frame_pointer(registers.tmp_mem[2] as usize);
        let mut args = argument_registers(process, arity);
        let (value, raised) = match &mut result {
            Ok(value) => (Some(value), None),
            Err(trap) => (None, Some(trap)),
        };
        let gc = crate::calls::gc_after_native_parts(process, &mut args, value, raised);
        registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
        if gc.is_err() {
            crate::native_hooks::set_error(process, "system_limit");
            process.sync_native_header();
            return 0;
        }
    }
    match result {
        Ok(value) => {
            let value = crate::native_hooks::raw(value);
            process.x[0] = crate::native_hooks::from_raw(value);
            if collected {
                process.sync_native_header();
            } else {
                process.sync_native_cursors();
            }
            value
        }
        Err(trap) => {
            let args = argument_registers(process, arity);
            process_bif_error(process, export, &args, trap)
        }
    }
}

/// Parks a process BIF's exception, with the BIF as its top frame, for the native exit.
// Port of erts/emulator/beam/beam_common.c:880-930 (save_stacktrace), OTP-29.1.1: BIF_ERROR
// reports the failing BIF and its arguments.
fn process_bif_error(
    process: &mut crate::Process,
    export: ExportDispatch,
    args: &[Term],
    mut trap: crate::exceptions::Trap,
) -> u64 {
    if trap.class == arinsal_bifs::Class::Error && trap.top.is_none() && trap.trace.is_none() {
        let Ok(args) = crate::stacktrace::BifArgs::from_terms(args) else {
            crate::native_hooks::set_error(process, "system_limit");
            process.sync_native_header();
            return 0;
        };
        trap.top = Some(crate::stacktrace::TopFrame::Bif {
            module: export.module_atom,
            function: export.function_atom,
            args,
            info: crate::stacktrace::BifErrorInfo::Plain,
        });
    }
    let freason = match trap.class {
        arinsal_bifs::Class::Error => 1,
        arinsal_bifs::Class::Exit => 2,
        arinsal_bifs::Class::Throw => 3,
    };
    let fvalue = crate::native_hooks::raw(trap.reason);
    process.header.freason = freason;
    process.header.fvalue = fvalue;
    process.cold_mut().native_trap = Some(crate::proc_create::NativeTrap {
        trap,
        freason,
        fvalue,
    });
    process.sync_native_header();
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
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    export: ExportDispatch,
    arity: usize,
    mut result: Result<Term, arinsal_bifs::BifError>,
) -> u64 {
    let collected = process.heap.gc_after_bif_desired();
    if collected && !gc_after_plain_bif(process, registers, arity, &mut result) {
        return 0;
    }
    match result {
        Ok(value) => {
            let value = crate::native_hooks::raw(value);
            // Port of erts/emulator/beam/jit/arm/instr_bif.cpp (call_light_bif,
            // ERTS_IS_GC_AFTER_BIF_DESIRED), OTP-29.1.1: one test, so at most one collection.
            process.x[0] = crate::native_hooks::from_raw(value);
            if collected {
                process.sync_native_header();
            } else {
                process.sync_native_cursors();
            }
            value
        }
        Err(error) => {
            let args = argument_registers(process, arity);
            plain_bif_error(process, export, &args, error)
        }
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
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    // The BIF's charge is in FCALLS; the sync below writes `reductions` back to it.
    process.reductions = process.header.fcalls;
    let Some(export) = crate::beamasm_integration::export_from_info(descriptor) else {
        return 0;
    };
    // erl_gc.c:428-445 (erts_gc_after_bif_call_lhf): with F_DISABLE_GC the result is returned
    // without a collection.
    if !process.heap.gc_enabled {
        registers.x_reg_array[0] = crate::native_hooks::from_raw(value);
        process.sync_native_cursors();
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
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    arity: usize,
    result: &mut Result<Term, arinsal_bifs::BifError>,
) -> bool {
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
    let mut args = argument_registers(process, arity);
    let collected = crate::calls::gc_after_bif(process, &mut args, result);
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
    if collected.is_err() {
        crate::native_hooks::set_error(process, "system_limit");
        process.sync_native_header();
        return false;
    }
    true
}

#[cold]
#[inline(never)]
fn plain_bif_error(
    process: &mut crate::Process,
    export: ExportDispatch,
    args: &[Term],
    error: arinsal_bifs::BifError,
) -> u64 {
    set_native_bif_export_error(process, export, args, error);
    process.sync_native_header();
    0
}

/// Charges the reductions a BIF reported against FCALLS, which the call site reloads.
// Port of erts/emulator/beam/bif.h (BUMP_REDS), OTP-29.1.1.
fn charge_bif_reductions(process: &mut crate::Process, reductions: u32) {
    process.reductions = process
        .reductions
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
    // A guard BIF never collects (erts calls it with only Update::eReductions), so E (x29)
    // and the frame pointer stay as they were.
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let all_args = [first, second, third].map(crate::native_hooks::from_raw);
    if let Some(export) = export
        && crate::bif_table::binary_guard(&export.module, &export.function, export.arity).is_some()
    {
        let args = &all_args[..usize::from(export.arity).min(all_args.len())];
        return binary_guard_result(process, registers, export, args, false);
    }
    let Some((bif, arity)) = export.and_then(|export| Some((export.bif?, export.arity))) else {
        crate::native_hooks::set_error(process, "undef");
        return 0;
    };
    let args = &all_args[..usize::from(arity).min(all_args.len())];
    let entry_top = process.heap.heap_top_index();
    // Matched where the BIF wrote it, like the light BIF path.
    let mut fragment = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    let mut ctx = arinsal_bifs::Ctx::with_fcalls(&mut fragment, &mut process.header.fcalls);
    let result = bif(&mut ctx, args);
    drop(ctx);
    let top = process.heap.heap_top_index();
    if top != entry_top {
        process.header.htop = process.heap.word_address(top);
    }
    match result {
        Ok(value) => crate::native_hooks::raw(value),
        Err(error) => {
            // Port of erts/emulator/beam/jit/arm/instr_bif.cpp (i_bif: the failing BIF and its
            // arguments are the top frame), OTP-29.1.1.
            process.reductions = process.header.fcalls;
            match export {
                // `i_bif*` passes each operand explicitly; a literal BIF operand need not
                // be present in X0..X2 when the scheduler expands the saved error.
                Some(export) => {
                    set_native_bif_error(process, &export.module, &export.function, args, error)
                }
                None => set_light_bif_error(process, &error),
            }
            process.sync_native_header();
            0
        }
    }
}

/// Raises `error:{Tag, Value}` from a native helper.
fn set_tagged_error(process: &mut crate::Process, tag: &str, value: Term) {
    let tuple = arinsal_term::TermBuilder::new(&mut crate::ProcessHeapHandle(&mut process.heap))
        .tuple(&[crate::signals::atom(tag), value]);
    match tuple {
        Ok(reason) => {
            process.header.freason = 1;
            process.header.fvalue = crate::native_hooks::raw(reason);
        }
        Err(_) => crate::native_hooks::set_error(process, "system_limit"),
    }
    process.sync_native_header();
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
    // `apply/2` may pass more arguments than the module's register file holds (erts raises
    // badarity with all of them, instr_fun.cpp:253-328).
    process.x.ensure_x(arity + 1);
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
    process.x[arity] = fun;
    match crate::funs::call_error_reason(process, fun, arity) {
        Ok(reason) => {
            process.header.freason = 1;
            process.header.fvalue = crate::native_hooks::raw(reason);
        }
        Err(_) => crate::native_hooks::set_error(process, "system_limit"),
    }
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
}

/// Records a native BIF failure so the scheduler raises it with the BIF as the top frame.
pub(crate) fn set_native_bif_error(
    process: &mut crate::Process,
    module: &str,
    function: &str,
    args: &[Term],
    error: arinsal_bifs::BifError,
) {
    set_light_bif_error(process, &error);
    // A caught native failure still returns to the scheduler, which raises with this
    // record (`native_bif_error`). The pending frame is `s->current` if a later
    // `save_stacktrace` runs in-process (beam_common.c:903-925, OTP-29.1.1).
    if process.header.catches > 0 {
        crate::stacktrace::note_caught_bif_frame(process, module, function, args, &error);
    }
    let (freason, fvalue) = (process.header.freason, process.header.fvalue);
    process.cold_mut().native_bif_error = Some(crate::proc_create::NativeBifError {
        call: crate::proc_create::NativeBifCall::Owned {
            module: module.to_owned(),
            function: function.to_owned(),
            args: args.to_vec(),
        },
        error,
        freason,
        fvalue,
    });
}

/// Retains the export entry; its descriptor owns the BIF MFA while X registers own the arguments.
fn set_native_bif_export_error(
    process: &mut crate::Process,
    export: ExportDispatch,
    args: &[Term],
    error: arinsal_bifs::BifError,
) {
    set_light_bif_error(process, &error);
    if process.header.catches > 0 {
        crate::stacktrace::note_caught_bif_frame(
            process,
            &export.module,
            &export.function,
            args,
            &error,
        );
    }
    let (freason, fvalue) = (process.header.freason, process.header.fvalue);
    process.cold_mut().native_bif_error = Some(crate::proc_create::NativeBifError {
        call: crate::proc_create::NativeBifCall::Export(export),
        error,
        freason,
        fvalue,
    });
}

fn set_light_bif_error(process: &mut crate::Process, error: &arinsal_bifs::BifError) {
    use arinsal_bifs::{BifError, Class};
    // A new failure replaces any BIF frame left by the previous one.
    crate::stacktrace::clear_pending_top(process);
    // `raise/3`'s list is copied off-heap before `freason` changes, so a later
    // collection cannot move the words the catch still has to return.
    let explicit = match error {
        BifError::Raise {
            stacktrace: Some(trace),
            ..
        } => arinsal_term::to_owned(*trace).ok(),
        _ => None,
    };
    let (class, reason) = match error {
        BifError::Badarg { .. } => (1, crate::signals::atom("badarg")),
        BifError::Badarith => (1, crate::signals::atom("badarith")),
        BifError::SystemLimit => (1, crate::signals::atom("system_limit")),
        BifError::Error(reason) => (1, *reason),
        BifError::Raise { class, reason, .. } => (
            match *class {
                Class::Error => 1,
                Class::Exit => 2,
                Class::Throw => 3,
            },
            *reason,
        ),
        BifError::Unsupported(_) => (1, crate::signals::atom("undef")),
        // NIF bodies trap to the executor before reaching here (`trap_to_dirty_nif`).
        BifError::Dirty(_) => (1, crate::signals::atom("notsup")),
    };
    process.header.freason = class;
    process.header.fvalue = crate::native_hooks::raw(reason);
    let freason = process.header.freason;
    let fvalue = process.header.fvalue;
    process.cold_mut().explicit_raise = explicit.map(|trace| (freason, fvalue, trace));
}

/// The `raise/3` list for this failure, copied back onto the heap.
///
/// Port of erts/emulator/beam/bif.c:1643 (`c_p->ftrace = stacktrace` when the
/// list is already a stacktrace), OTP-29.1.1. The catch's `build_stacktrace`
/// then returns that list instead of walking native frames.
fn take_explicit_raise(process: &mut crate::Process) -> Option<Term> {
    let owned = {
        let cold = process.cold.as_mut()?;
        let matches = cold
            .explicit_raise
            .as_ref()
            .is_some_and(|(freason, fvalue, _)| {
                *freason == process.header.freason && *fvalue == process.header.fvalue
            });
        if !matches {
            return None;
        }
        cold.explicit_raise.take().map(|(_, _, trace)| trace)?
    };
    arinsal_term::from_owned(
        &owned,
        &mut arinsal_bifs::ProcessHeapHandle(&mut process.heap),
    )
    .ok()
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
) -> usize {
    let Some(process) = crate::native_hooks::process_from_header(header) else {
        return 0;
    };
    let (freason, catches) = (process.header.freason, process.header.catches);
    // TRAP and raw re-raises stay on the scheduler. Primary classes are 1, 2, 3.
    // Expanded errors (`badmatch`, `function_clause`, `case_clause`, …) use erts'
    // `(index << 10) | EXC_ERROR`.
    let primary = matches!(freason, 1..=3);
    let expanded = freason > 3 && freason & 0x3ff == 0x50 && freason & 4 == 0;
    if catches == 0 || (!primary && !expanded) {
        return 0;
    }
    // Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp:300-318 (`raise_exception_shared`),
    // OTP-29.1.1. The shared fragment already ran `emit_enter_runtime` and stored HTOP and E
    // into `c_p`. `handle_error` runs once from that entry; it does not enter again.
    // The heap indexes are those stored cursors (`c_p->htop`, `c_p->stop`).
    process.heap.set_native_cursors_at(
        process.header.heap,
        process.header.htop,
        process.header.stop,
    );
    let Some((process, registers)) = crate::native_hooks::scheduler_registers(process) else {
        return 0;
    };
    // Port of erts/emulator/beam/beam_common.c:580-648 (`next_catch` reads the stack, and
    // writes `stop` only at `found_catch`), OTP-29.1.1. Resolve the catch once before saving
    // the trace; a miss or a caller catch remains with the scheduler's unwind.
    let raising_pc = registers.tmp_mem[6] as usize;
    let Some(found) = crate::native_bridge::current_native_catch(process, raising_pc) else {
        process.sync_native_header();
        return 0;
    };
    let (class, reason) = if primary {
        let class = match freason {
            1 => arinsal_bifs::Class::Error,
            2 => arinsal_bifs::Class::Exit,
            _ => arinsal_bifs::Class::Throw,
        };
        (class, crate::native_hooks::from_raw(process.header.fvalue))
    } else {
        match expand_error_value(process) {
            Some(reason) => (arinsal_bifs::Class::Error, reason),
            None => {
                process.sync_native_header();
                return 0;
            }
        }
    };
    // The light-BIF fragment and `error_label` spill the raising pc at `tmp_mem[6]`
    // (erts' `pc` argument to `save_stacktrace`). `p.ip` is the last interpreter
    // instruction and names the wrong function while native code is running.
    // The raising pc is stored raw. `build_stacktrace` resolves it; a registry
    // lookup here is not part of erts' `save_stacktrace`.
    // Port of beam_common.c:880-925 (`save_stacktrace`), OTP-29.1.1: `pc` stays raw
    // until `build_stacktrace` resolves it against the active native ranges table.
    let native_pc = (raising_pc != 0).then_some(raising_pc);
    // `erlang:raise/3` already built the list the catch must see (`bif.c:1643`).
    // A native walk would name `eval_external_handler` instead of that list.
    let trace = if let Some(trace) = take_explicit_raise(process) {
        let Ok(trace) = crate::stacktrace::save_explicit(process, class, trace) else {
            process.sync_native_header();
            return 0;
        };
        trace
    } else {
        let Ok(trace) = crate::stacktrace::save_lazy(process, class, native_pc) else {
            process.sync_native_header();
            return 0;
        };
        trace
    };
    let handler = match crate::native_bridge::commit_catch(process, found, class, reason, trace) {
        crate::native_bridge::CatchHandler::Native(handler) => handler,
        crate::native_bridge::CatchHandler::Interpreted => {
            process.sync_native_header();
            return 0;
        }
    };
    crate::stacktrace::clear_pending_top(process);
    // The branch below resumes the handler. The scheduler must not treat
    // the next native exit as a continuation resume.
    process.native_continuation_resume = false;
    handler
}

/// Port of erts/emulator/beam/beam_common.c:742 (`expand_error_value`), OTP-29.1.1.
fn expand_error_value(process: &mut crate::Process) -> Option<arinsal_term::Term> {
    let index = process.header.freason >> 10;
    let value = crate::native_hooks::from_raw(process.header.fvalue);
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
    let unported = crate::beamasm_integration::call_fun_unported_entry();
    match view {
        Some(arinsal_term::FunRef::Local { entry, .. }) => {
            if u32::from(entry.arity) != arity {
                set_call_fun_error(process, registers, fun, arity);
                process.sync_native_header();
                return 0;
            }
            let code_ix =
                (registers.active_code_ix as usize).min(arinsal_term::ERTS_NUM_CODE_IX - 1);
            if let Some(target) = entry.fun_code(code_ix) {
                process.sync_native_header();
                return target;
            }
            process.header.arity = arity.min(u8::MAX as u32) as u8;
            if let Some(slot) = process.x.get_mut(arity as usize) {
                *slot = fun;
            }
            process.sync_native_header();
            if unported == 0 {
                set_call_fun_error(process, registers, fun, arity);
                process.sync_native_header();
                return 0;
            }
            unported
        }
        Some(arinsal_term::FunRef::Export { entry }) => {
            if u32::from(entry.arity) != arity {
                set_call_fun_error(process, registers, fun, arity);
                process.sync_native_header();
                return 0;
            }
            let Some(_module) = arinsal_term::global_atoms().text(entry.module) else {
                set_call_fun_error(process, registers, fun, arity);
                process.sync_native_header();
                return 0;
            };
            let Some(_function) = arinsal_term::global_atoms().text(entry.function) else {
                set_call_fun_error(process, registers, fun, arity);
                process.sync_native_header();
                return 0;
            };
            let code_ix = registers.active_code_ix as usize;
            let export = process.runtime.as_ref().and_then(|runtime| {
                runtime.export_entry((entry.module, entry.function, entry.arity), code_ix)
            });
            let target = export.map(|export| export.address(code_ix));
            if code_ix != crate::code_ix::ERTS_SAVE_CALLS_CODE_IX
                && let Some(target) = target
                && target != crate::beamasm_integration::export_trampoline()
            {
                process.sync_native_header();
                return target;
            }
            process.header.arity = arity.min(u8::MAX as u32) as u8;
            if let Some(slot) = process.x.get_mut(arity as usize) {
                *slot = fun;
            }
            process.sync_native_header();
            if unported == 0 {
                crate::native_hooks::set_error(process, "undef");
                process.sync_native_header();
                return 0;
            }
            unported
        }
        None => {
            set_call_fun_error(process, registers, fun, arity);
            process.sync_native_header();
            0
        }
    }
}

/// Resolves `apply Arity` to a native entry, or to the fragment that lets the interpreter apply.
// Port of erts/emulator/beam/jit/arm/instr_call.cpp:263-320 (emit_fixed_apply) and
// erts/emulator/beam/beam_common.c (fixed_apply), OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_apply_resolver(header: *mut ProcessHeader, arity: u32) -> usize {
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let arity = arity as usize;
    let fragment = crate::beamasm_integration::apply_fixed_unported_entry();
    if fragment == 0 || arity + 1 >= registers.x_reg_array.len() {
        crate::native_hooks::set_error(process, "system_limit");
        process.sync_native_header();
        return 0;
    }
    let module = registers.x_reg_array[arity];
    let function = registers.x_reg_array[arity + 1];
    // Port of erts/emulator/beam/beam_common.c:1554-1557 (fixed_apply), OTP-29.1.1: an
    // apply of erlang:apply/3 is a plain apply/3 of its arguments.
    if arity == 3
        && module.as_atom() == Some(arinsal_term::atoms::ERLANG)
        && function.as_atom() == Some(arinsal_term::atoms::APPLY)
    {
        let apply3 = crate::beamasm_integration::apply3_unported_entry();
        if apply3 != 0 {
            return apply3;
        }
    }
    if registers.active_code_ix == crate::code_ix::ERTS_SAVE_CALLS_CODE_IX as u64 {
        process.header.arity = arity.min(u8::MAX as usize) as u8;
        process.sync_native_header();
        return fragment;
    }
    if let (Some(module), Some(function)) = (module.as_atom(), function.as_atom()) {
        let target = process.runtime.as_ref().and_then(|runtime| {
            runtime.export_address(
                (module, function, arity as u8),
                registers.active_code_ix as usize,
            )
        });
        if let Some(target) =
            target.filter(|target| *target != crate::beamasm_integration::export_trampoline())
        {
            return target;
        }
    }
    // Not natively compiled (or invalid): the interpreter applies and raises errors.
    process.header.arity = arity.min(u8::MAX as usize) as u8;
    process.sync_native_header();
    fragment
}

/// Resolves `apply/3` to a native entry with the arguments moved into the X registers, or to
/// the fragment that lets the interpreter apply (and raise) with X0..X2 untouched.
// Port of erts/emulator/beam/jit/arm/instr_call.cpp:205-244 (emit_variable_apply) and
// erts/emulator/beam/beam_common.c:1434-1530 (apply), OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_apply3_resolver(header: *mut ProcessHeader) -> usize {
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let fallback = crate::beamasm_integration::apply3_unported_entry();
    // A process saving calls records the call through the export, which the interpreter does.
    if registers.active_code_ix == crate::code_ix::ERTS_SAVE_CALLS_CODE_IX as u64 {
        return fallback;
    }
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
    let (Some(module), Some(function)) = (module.as_atom(), function.as_atom()) else {
        return fallback;
    };
    let mut arity = 0_usize;
    let mut list = args;
    while let Some((_, tail)) = crate::lists::split(list) {
        arity += 1;
        if arity >= registers.x_reg_array.len() - 1 {
            return fallback;
        }
        list = tail;
    }
    if list != Term::NIL {
        return fallback;
    }
    let Ok(arity) = u8::try_from(arity) else {
        return fallback;
    };
    let Some(target) = process.runtime.as_ref().and_then(|runtime| {
        runtime.export_address((module, function, arity), registers.active_code_ix as usize)
    }) else {
        return fallback;
    };
    if target == crate::beamasm_integration::export_trampoline() {
        return fallback;
    }
    let mut list = args;
    for slot in registers.x_reg_array.iter_mut() {
        let Some((head, tail)) = crate::lists::split(list) else {
            break;
        };
        *slot = head;
        list = tail;
    }
    target
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
    let mut top = crate::native_top_heap::NativeTopHeap::new(process)?;
    let (key, value, map) = (
        crate::native_hooks::from_raw(key),
        crate::native_hooks::from_raw(value),
        crate::native_hooks::from_raw(map),
    );
    match arinsal_maps::put(map, key, value, &mut top) {
        Ok(term) => Some(crate::native_hooks::raw(term)),
        Err(error) => {
            top.commit();
            Some(map_result(process, Err(error), false, false))
        }
    }
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
        // HAllocX on `c_p->htop`: the word-index cursors are only brought up to date when the
        // put leaves the fast path.
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
            // HAlloc advances HTOP; the map update leaves E unchanged.
            process.header.htop = process.heap.heap_cursor().0;
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
            process.header.htop = process.heap.heap_cursor().0;
            0
        }
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
    if source_slot >= process.x.len() {
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
            process.sync_native_header();
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
    let raw = match result {
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
    };
    process.sync_native_header();
    raw
}

/// Generic fallback lookup for non-flatmap keys.
pub extern "C" fn arinsal_beamasm_map_get(
    header: *mut ProcessHeader,
    map: u64,
    key: u64,
    _hash: u64,
) -> u64 {
    let Some((process, _registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let result = arinsal_maps::get(
        crate::native_hooks::from_raw(map),
        crate::native_hooks::from_raw(key),
    );
    process.sync_native_header();
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
    let (Ok(module_id), Ok(table_index)) =
        (usize::try_from(module_handle), usize::try_from(table_index))
    else {
        return 0;
    };
    let Some(runtime) = process.runtime.as_ref() else {
        return 0;
    };
    process
        .heap
        .set_stack_pointer(stack_pointer as usize as *mut u64);
    let active_code_ix = registers.active_code_ix as usize;
    let heap = &mut process.heap;
    let x_registers = &mut registers.x_reg_array;
    let found = runtime.with_beamasm_module(active_code_ix, module_id, |module| {
        let Some(table) = module.map_lookups.get(table_index) else {
            return false;
        };
        matches!(
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
        )
    });
    if !matches!(found, Some(true)) {
        return 0;
    }
    process.sync_native_header();
    1
}

/// Builds the binary of a native `bs_create_bin` from the segments the emitted code staged in
/// the X register array (six terms per segment starting at X6), then leaves the result in X0.
// Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1442-1600 and erl_bits.c:1523, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_bs_create_bin(
    header: *mut ProcessHeader,
    count: u64,
    live: u64,
    alloc: u64,
) -> u64 {
    use arinsal_bits::{BitsError, SegFlags, SegSize, SegType, Segment, SegmentValue};
    let Some((process, registers)) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    process.reductions = process.header.fcalls;
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
    let has_fail_label = live >> 32 != 0;
    let (count, live, alloc) = (
        count as usize,
        (live & 0xffff_ffff) as usize,
        alloc as usize,
    );
    let base_slot = live.max(6);
    let root_live = base_slot + count * 7;
    if root_live > process.x.len() {
        crate::native_hooks::set_error(process, "system_limit");
        return 0;
    }
    // Dead X registers below the staged segments must not become GC roots.
    process.x[live..base_slot].fill(Term::NIL);
    let all = crate::signals::atom("all");
    let parse = |process: &crate::Process| -> Option<Vec<Segment<'static>>> {
        let mut segments = Vec::with_capacity(count);
        for index in 0..count {
            let base = base_slot + index * 7;
            let small = |offset: usize| {
                process.x[base + offset]
                    .as_small()
                    .and_then(|n| u64::try_from(n).ok())
            };
            let ty = match small(0)? {
                0 => SegType::Integer,
                1 => SegType::Float,
                2 => SegType::Binary,
                3 => SegType::Append,
                4 => SegType::PrivateAppend,
                5 => SegType::Utf8,
                6 => SegType::Utf16,
                7 => SegType::Utf32,
                _ => return None,
            };
            let flags = small(3)?;
            let size_term = process.x[base + 6];
            let size = if small(4)? != 0 {
                SegSize::Units(size_term.as_small().and_then(|n| u64::try_from(n).ok())?)
            } else if size_term == all {
                SegSize::All
            } else {
                SegSize::Term(size_term)
            };
            segments.push(Segment {
                ty,
                index: usize::try_from(small(1)?).ok()?,
                unit: u8::try_from(small(2)?).ok()?,
                flags: SegFlags {
                    little: flags & 2 != 0,
                    signed: flags & 4 != 0,
                    native: flags & 16 != 0,
                },
                value: SegmentValue::Term(process.x[base + 5]),
                size,
            });
        }
        Some(segments)
    };
    let Some(initial) = parse(process) else {
        crate::native_hooks::set_error(process, "badarg");
        return 0;
    };
    let fragment_only_append = initial.first().is_some_and(|segment| {
        segment.ty == SegType::PrivateAppend && matches!(segment.size, SegSize::All)
    });
    let mut request = match arinsal_bits::create_bin_size(&initial) {
        Ok(_) if fragment_only_append => 0,
        Ok(size) => size.heap_words + alloc,
        Err(error) => {
            let (reason, info) = crate::bits::native_error(error);
            if !has_fail_label {
                process.cold_mut().native_error_info = info;
            }
            crate::native_hooks::set_error(process, &reason);
            return 0;
        }
    };
    let copy_reductions = match arinsal_bits::create_bin_reductions(&initial) {
        Ok(reductions) => reductions,
        Err(error) => {
            let (reason, info) = crate::bits::native_error(error);
            if !has_fail_label {
                process.cold_mut().native_error_info = info;
            }
            crate::native_hooks::set_error(process, &reason);
            return 0;
        }
    };
    drop(initial);
    let result = loop {
        if request != 0 && process.ensure(request, root_live).is_err() {
            crate::native_hooks::set_error(process, "system_limit");
            registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
            return 0;
        }
        registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
        let Some(segments) = parse(process) else {
            crate::native_hooks::set_error(process, "badarg");
            return 0;
        };
        match arinsal_bits::create_bin(&segments, &mut process.heap) {
            Err(BitsError::HeapFull { need_words }) => {
                request = need_words.max(request.saturating_mul(2));
            }
            other => break other,
        }
    };
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
    if result.is_ok() {
        process.reductions = process
            .reductions
            .saturating_sub(copy_reductions.min(i32::MAX as usize) as i32);
    }
    process.sync_native_header();
    match result {
        Ok(term) => crate::native_hooks::raw(term),
        Err(error) => {
            // Port of erts/emulator/beam/erl_bits.c (bs_create_bin error_info), OTP-29.1.1.
            let (reason, info) = crate::bits::native_error(error);
            if !has_fail_label {
                process.cold_mut().native_error_info = info;
            }
            crate::native_hooks::set_error(process, &reason);
            0
        }
    }
}

/// Runs the no-growth private append and charges its writable-binary overhead on the process.
// Port of erts/emulator/beam/erl_bits.c:1961-1983 (`erts_bs_private_append_checked`), OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_bs_private_append_fast(
    ebs: *mut u64,
    process_header: *mut ProcessHeader,
    bin: u64,
    extra_bits: u64,
) -> u64 {
    private_append(process_header, ebs, bin, extra_bits, false)
}

/// Runs the reallocating private append outside the byte-copy loop and updates process accounting.
// Port of erts/emulator/beam/erl_bits.c:1928-1934 and 1961-1983, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_bs_private_append_checked(
    ebs: *mut u64,
    process_header: *mut ProcessHeader,
    bin: u64,
    extra_bits: u64,
) -> u64 {
    private_append(process_header, ebs, bin, extra_bits, true)
}

#[inline(always)]
fn private_append(
    process_header: *mut ProcessHeader,
    ebs: *mut u64,
    bin: u64,
    extra_bits: u64,
    checked: bool,
) -> u64 {
    // BeamAsm already committed native cursors before the direct C-style helper call.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp:1865-1880 and erl_bits.c:1928-1983,
    // OTP-29.1.1.
    let Some(process) = crate::native_hooks::process_from_header(process_header) else {
        return 0;
    };
    let update = if checked {
        arinsal_term::erts_bs_private_append_checked_with_update(ebs, bin, extra_bits)
    } else {
        arinsal_term::erts_bs_private_append_fast_with_update(ebs, bin, extra_bits)
    };
    if update.result != 0 && update.result != u64::MAX {
        process.heap.update_writable_binary_overhead_at(
            crate::native_hooks::from_raw(bin),
            update.bin_ref,
            update.old_size_bits,
            update.new_size_bits,
        );
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
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
    let base = (live as usize).max(6);
    let root_live = base + 4;
    // The X registers below `base` and the staged operands (the context among them) are the
    // roots of a collection; the staged copies follow the registers in `process.x`, which is
    // the scheduler's array.
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
                    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
                    return 0;
                }
                registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
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
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
    process.sync_native_header();
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
    // HeapOnlyAlloc advances HTOP; the stack is untouched.
    process.header.htop = process.heap.heap_cursor().0;
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
    descriptor: u64,
    identity: u64,
) -> u64 {
    if let Some(raw) = process_info_2_self(header) {
        return raw;
    }
    yield_executor_bif(header, regs, i, descriptor, identity)
}

fn process_info_2_self(header: *mut ProcessHeader) -> Option<u64> {
    let (process, _registers) = crate::native_hooks::enter_runtime(header)?;
    let pid = arinsal_sched::Pid::from_term(process.x.first().copied()?)?;
    let item = process.x.get(1).copied()?;
    let result = crate::natives::proc::process_info_light(process, pid, item);
    // The builder allocates on the process heap. Write the cursor back on every outcome, so an
    // executor fallback re-enters from the header with the same heap.
    let top = process.heap.heap_top_index();
    process.header.htop = native_htop(process, top);
    match result {
        Some(Ok(term)) => Some(crate::native_hooks::raw(term)),
        _ => None,
    }
}
