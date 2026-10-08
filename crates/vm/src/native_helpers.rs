//! Runtime helper bodies called by BeamAsm generated code.

use arinsal_beamasm::ProcessHeader;
use arinsal_bits::MatchOps;
use arinsal_term::Term;

struct StaticNif {
    module: String,
    function: String,
    arity: u8,
    // None until `load_nif` binds a reserved call-NIF body.
    entry: Option<arinsal_bifs::BifFn>,
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
    let Some((process, _registers)) = crate::native_hooks::process_and_registers(header) else {
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
    let Some((process, _registers)) = crate::native_hooks::process_and_registers(header) else {
        return 0;
    };
    let trace = crate::native_hooks::from_raw(trace_raw);
    let class = crate::exceptions::empty_trace_class(trace)
        .or_else(|| crate::stacktrace::raw_class(process, trace))
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

/// Returns the current local node atom for the native `node` instruction.
// Port of erts/emulator/beam/jit/arm/instr_common.cpp:701-705, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_local_node(_header: *mut ProcessHeader) -> u64 {
    let name = crate::node_tables::lock().local_identity().0.to_owned();
    arinsal_term::global_atoms()
        .intern(&name)
        .map(|atom| crate::native_hooks::raw(Term::atom(atom)))
        .unwrap_or(0)
}

/// Materializes a process-owned raw trace on the process heap.
// Port of erts/emulator/beam/jit/arm/instr_common.cpp:3046-3055, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_build_stacktrace(
    header: *mut ProcessHeader,
    trace_raw: u64,
) -> u64 {
    let Some((process, _registers)) = crate::native_hooks::process_and_registers(header) else {
        return 0;
    };
    let trace = crate::native_hooks::from_raw(trace_raw);
    match crate::exceptions::materialize(process, trace) {
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
    let Some((process, _registers)) = crate::native_hooks::process_and_registers(header) else {
        return 0;
    };
    let reason = crate::native_hooks::from_raw(reason_raw);
    let trace = crate::native_hooks::from_raw(trace_raw);
    let result = crate::exceptions::materialize(process, trace).and_then(|stacktrace| {
        arinsal_term::TermBuilder::new(&mut crate::FragmentingHeap(&mut process.heap))
            .tuple(&[reason, stacktrace])
            .map_err(|error| crate::VmError::Unsupported(format!("stacktrace tuple {error:?}")))
    });
    match result {
        Ok(value) => {
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

/// Converts a bignum to IEEE-754 bits for a native `fconv`, raising `badarith` on overflow.
// Port of erts/emulator/beam/jit/arm/instr_float.cpp:103-195 (fconv), OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_big_to_float(header: *mut ProcessHeader, term_raw: u64) -> u64 {
    let Some((process, _registers)) = crate::native_hooks::process_and_registers(header) else {
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
pub extern "C" fn arinsal_beamasm_bs_init_writable(header: *mut ProcessHeader, _size: u64) -> u64 {
    let Some((process, registers)) = crate::native_hooks::process_and_registers(header) else {
        return 0;
    };
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
    let result = arinsal_bits::init_writable(&mut crate::FragmentingHeap(&mut process.heap));
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
    let Some((process, _registers)) = crate::native_hooks::process_and_registers(header) else {
        return 0;
    };
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
    if let Some((process, _registers)) = crate::native_hooks::process_and_registers(header) {
        process.bind_receive_marker(
            crate::native_hooks::from_raw(marker),
            crate::native_hooks::from_raw(reference),
        );
    }
}

/// Clears the marker of a reference (`recv_marker_clear`).
pub extern "C" fn arinsal_beamasm_recv_marker_clear(header: *mut ProcessHeader, reference: u64) {
    if let Some((process, _registers)) = crate::native_hooks::process_and_registers(header) {
        process.clear_receive_marker(crate::native_hooks::from_raw(reference));
    }
}

/// Moves the save pointer to the marker of a reference (`recv_marker_use`).
pub extern "C" fn arinsal_beamasm_recv_marker_use(header: *mut ProcessHeader, reference: u64) {
    if let Some((process, _registers)) = crate::native_hooks::process_and_registers(header) {
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
    let Some((process, _registers)) = crate::native_hooks::process_and_registers(header) else {
        return 0;
    };
    if let Some(message) = process.inbox.get(process.receive_cursor) {
        return crate::native_hooks::raw(*message);
    }
    // The inner queue is exhausted. Signals sent since the last fetch (by this process or
    // any other) wait in the outer queue; the scheduler fetches and handles them. A process
    // without a probe yet fetches once, which installs it.
    let pending = process
        .cold
        .as_ref()
        .and_then(|cold| cold.signal_probe.as_ref())
        .is_none_or(arinsal_sched::SignalProbe::has_pending);
    if !pending {
        return 0;
    }
    process.cold_mut().native_signal_fetch = true;
    u64::from(arinsal_beamasm::receive::LOOP_REC_FETCH)
}

/// Removes the current message from the mailbox (`remove_message`).
pub extern "C" fn arinsal_beamasm_remove_message(
    header: *mut ProcessHeader,
    fcalls: i32,
    active_code_ix: usize,
) -> i32 {
    let Some((process, registers)) = crate::native_hooks::process_and_registers(header) else {
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
    if let Some((process, _registers)) = crate::native_hooks::process_and_registers(header) {
        process.loop_rec_end();
    }
}

/// Records that the process waits for a message; the scheduler puts it to sleep.
pub extern "C" fn arinsal_beamasm_wait(header: *mut ProcessHeader, resume: usize) {
    if let Some((process, _registers)) = crate::native_hooks::process_and_registers(header) {
        let cold = process.cold_mut();
        let timeout = cold.native_wait_timeout.take();
        cold.native_wait = Some(timeout);
        cold.native_wait_self = resume & 1 != 0;
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
    let Some((process, _registers)) = crate::native_hooks::process_and_registers(header) else {
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
    if let Some((process, _registers)) = crate::native_hooks::process_and_registers(header) {
        process.timeout();
        // Port of erts/emulator/beam/jit/beam_jit_common.cpp:1246-1248 (beam_jit_timeout),
        // OTP-29.1.1.
        if crate::trace::saves_calls(process) {
            crate::trace::save_call(process, crate::trace::SavedCall::Timeout);
        }
        if crate::trace::active() {
            process.cold_mut().native_timeout_trace = true;
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
            entry: Some(entry),
        },
    );
    identity
}

/// Reserves the identity of a native call-NIF body that `load_nif` may bind later.
pub(crate) fn reserve_nif_slot(module: String, function: String, arity: u8) -> usize {
    let identity = NEXT_STATIC_NIF.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    static_nifs().lock().unwrap().insert(
        identity,
        StaticNif {
            module,
            function,
            arity,
            entry: None,
        },
    );
    identity
}

/// Binds the NIF a reserved call-NIF body runs.
pub(crate) fn bind_nif_slot(identity: usize, entry: arinsal_bifs::BifFn) -> bool {
    static_nifs()
        .lock()
        .unwrap()
        .get_mut(&identity)
        .map(|nif| nif.entry = Some(entry))
        .is_some()
}

/// Forgets the call-NIF bodies of a purged native module version.
pub(crate) fn release_nif_slots(identities: impl IntoIterator<Item = usize>) {
    let mut nifs = static_nifs().lock().unwrap();
    for identity in identities {
        nifs.remove(&identity);
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
        Some((nif.module.clone(), nif.arity, nif.entry?))
    })?;
    // The job runs on this thread; NIF services find the process through these.
    crate::natives::nif::refresh_hub_native(process);
    if module == "prim_tty" {
        crate::natives::tty::note_caller_native(process);
    }
    let args = process.x.get(..usize::from(arity))?.to_vec();
    Some(crate::dirty::static_nif_job(move |heap| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::calls::call_bif(heap, entry, &args)
        }))
        .unwrap_or_else(|_| Err(arinsal_bifs::BifError::Error(crate::signals::atom("error"))))
    }))
}

/// Runs a static NIF with the arguments in `process.x`, for a dirty NIF call the executor
/// performs on a dirty scheduler, or takes the result of its dirty job.
pub(crate) fn run_static_nif(
    process: &mut crate::Process,
    identity: usize,
) -> Result<Term, crate::VmError> {
    let nif = static_nifs().lock().ok().and_then(|nifs| {
        let nif = nifs.get(&identity)?;
        Some((
            nif.module.clone(),
            nif.function.clone(),
            nif.arity,
            nif.entry?,
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
            Some(pending) => crate::natives::nif::resume_pending(&mut process.heap, pending),
            None => crate::calls::call_bif(&mut process.heap, entry, &args),
        }))
        .unwrap_or_else(|_| Err(arinsal_bifs::BifError::Error(crate::signals::atom("error")))),
    };
    result.map_err(|error| crate::exceptions::bif_error(process, &module, &function, &args, error))
}

/// Calls a static NIF body through the same BIF function used by NativeBody.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:863-900, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_static_nif(header: *mut ProcessHeader, identity: u64) -> u64 {
    let Some((process, registers)) = crate::native_hooks::process_and_registers(header) else {
        return 0;
    };
    let Some((nif, entry)) = static_nifs().lock().ok().and_then(|nifs| {
        let nif = nifs.get(&(identity as usize))?;
        Some((
            StaticNif {
                module: nif.module.clone(),
                function: nif.function.clone(),
                arity: nif.arity,
                entry: nif.entry,
            },
            nif.entry?,
        ))
    }) else {
        crate::native_hooks::set_error(process, "undef");
        return 0;
    };
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
    process.reductions = process.header.fcalls;
    // The arguments live in the native X register array, not in `process.x`, when native code
    // reaches the NIF body directly (local or tail call).
    if process.x.len() < usize::from(nif.arity) {
        let mut x = process.x.to_vec();
        x.resize(usize::from(nif.arity), Term::NIL);
        process.x = x.into_boxed_slice();
    }
    for (destination, raw) in process
        .x
        .iter_mut()
        .zip(registers.x_reg_array.iter().copied())
        .take(usize::from(nif.arity))
    {
        *destination = crate::native_hooks::from_raw(raw);
    }
    // Port of erts/emulator/beam/erl_nif.c (schedule_dirty_nif / erts_call_dirty_nif),
    // OTP-29.1.1: a dirty NIF called on a normal scheduler first moves the process to a
    // dirty scheduler; the executor runs it there and returns to this body's caller.
    if nif.module == "prim_tty"
        && arinsal_nif_tty::dirty_io(&nif.function, nif.arity)
        && arinsal_sched::current_scheduler_type() != arinsal_sched::SchedulerType::DirtyIo
    {
        return trap_to_dirty_nif(
            process,
            identity as usize,
            arinsal_bifs::SchedulerClass::DirtyIo,
        );
    }
    // Like the interpreter's NativeBody: every static NIF body reads the scheduler hub.
    crate::natives::nif::refresh_hub_native(process);
    if nif.module == "prim_tty" {
        crate::natives::tty::note_caller_native(process);
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::calls::call_bif(
            &mut process.heap,
            entry,
            &process.x[..usize::from(nif.arity)],
        )
    }));
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
    match result {
        Ok(Ok(value)) => {
            process.x[0] = value;
            publish_dispatch_x(process, registers);
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
            trap_to_dirty_nif(process, identity as usize, class)
        }
        Ok(Err(error)) => {
            let args = process.x[..usize::from(nif.arity)].to_vec();
            set_native_bif_error(process, &nif.module, &nif.function, &args, error);
            publish_dispatch_x(process, registers);
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

/// Leave native code through the dirty NIF dispatch trap; the executor runs NIF
/// `identity` (or the process's pending continuation) on a scheduler of `class` and
/// resumes after the native call with the result in x0.
fn trap_to_dirty_nif(
    process: &mut crate::Process,
    identity: usize,
    class: arinsal_bifs::SchedulerClass,
) -> u64 {
    process.cold_mut().native_dirty_nif = Some((identity, 0, class));
    process.header.i =
        arinsal_beamasm::dispatch::DIRTY_NIF_DISPATCH_IDENTITY as *const u8 as *const _;
    process.header.freason = 1 << 10;
    process.sync_native_header();
    0
}

/// Dispatches a BIF export from the shared export trampoline.
// Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp:164-210, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_export_trampoline(
    header: *mut ProcessHeader,
    identity: u64,
) -> u64 {
    // THE_NON_VALUE raises, 1 hands the call to the interpreter, any term word is the result.
    invoke_dispatch_bif(header, identity as usize, 0, true).unwrap_or(1)
}

/// Records the remote call of a process saving calls (the export entry is `identity`) and
/// returns the address the call continues with.
// Port of erts/emulator/beam/jit/arm/instr_call.cpp:123-148 (emit_dispatch_save_calls_export),
// OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_save_calls_export(
    header: *mut ProcessHeader,
    identity: u64,
) -> u64 {
    let identity = identity as usize;
    if let Some(export) = crate::beamasm_integration::export_dispatch(identity)
        && let Some((process, _registers)) = crate::native_hooks::process_and_registers(header)
    {
        crate::trace::save_call(
            process,
            crate::trace::SavedCall::Mfa(export.module_atom, export.function_atom, export.arity),
        );
    }
    crate::beamasm_integration::save_calls_continuation(identity) as u64
}

/// Runs a light BIF through the shared BeamAsm fragment.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-471, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_call_light_bif_shared(
    header: *mut ProcessHeader,
    identity: u64,
    site: u64,
) -> u64 {
    // `site` is only meaningful for the breakpoint trampoline; other callers leave x2 alone.
    invoke_dispatch_bif(header, identity as usize, site as usize, false).unwrap_or(0)
}

/// Reads the active process dictionary for native `i_get` instructions.
// Port of erts/emulator/beam/jit/arm/instr_common.cpp:319-329, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_process_dictionary_get(
    header: *mut ProcessHeader,
    key: u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::process_and_registers(header) else {
        return 0;
    };
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
    let key = crate::native_hooks::from_raw(key);
    let value = process
        .cold
        .as_ref()
        .and_then(|cold| {
            cold.dictionary
                .iter()
                .find(|(stored, _)| arinsal_term::exact_eq(*stored, key))
                .map(|(_, value)| *value)
        })
        .unwrap_or_else(|| {
            Term::atom(
                arinsal_term::global_atoms()
                    .intern("undefined")
                    .expect("built-in atom"),
            )
        });
    process.sync_native_header();
    crate::native_hooks::raw(value)
}

/// Completes a traced native return and resumes its saved caller continuation.
// Port of erts/emulator/beam/jit/arm/instr_trace.cpp:152-195, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_native_trace_return(header: *mut ProcessHeader) -> u64 {
    let Some((process, registers)) = crate::native_hooks::process_and_registers(header) else {
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
    let Some((process, registers)) = crate::native_hooks::process_and_registers(header) else {
        return 0;
    };
    if !std::ptr::eq(registers, scheduler_registers) {
        return 0;
    }
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
    // The emitter passes the full checked free-space gap, including CP and
    // S_RESERVED. Process::ensure uses that gap to decide whether to collect.
    // X registers above the register cache live in the X register array. Those below `live`
    // are roots and move with the collection, so they round-trip through `process.x`.
    let synced = live.clamp(6, registers.x_reg_array.len());
    if process.x.len() < synced {
        let mut x = process.x.to_vec();
        x.resize(synced, Term::NIL);
        process.x = x.into_boxed_slice();
    }
    for index in 6..synced {
        process.x[index] = crate::native_hooks::from_raw(registers.x_reg_array[index]);
    }
    let result = process.ensure(need_words, live);
    if result.is_err() {
        crate::native_hooks::set_error(process, "system_limit");
    }
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
    // Only the live prefix moved; X registers past it stay untouched, as in erts.
    for (destination, term) in registers
        .x_reg_array
        .iter_mut()
        .zip(process.x.iter())
        .take(live)
    {
        *destination = crate::native_hooks::raw(*term);
    }
    process.sync_native_header();
    // Port of erts/emulator/beam/erl_gc.c:588-597 and 975-980 (a delayed collection
    // returns the reductions left), OTP-29.1.1: FCALLS runs out and the process yields at
    // its next reduction check.
    if process.force_yield {
        return fcalls.max(0);
    }
    0
}

// `export_call`: reached through an export entry, whose BIF trampoline charges the call one
// reduction (erts/emulator/beam/jit/arm/instr_bif.cpp:399, OTP-29.1.1); a light BIF call
// site has already charged it.
fn invoke_dispatch_bif(
    header: *mut ProcessHeader,
    identity: usize,
    site: usize,
    export_call: bool,
) -> Option<u64> {
    let (process, registers) = crate::native_hooks::process_and_registers(header)?;
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
    if identity == arinsal_beamasm::dispatch::BREAKPOINT_DISPATCH_IDENTITY
        && !export_call
        && crate::trace::native_breakpoint_is_noop(process, site)
    {
        // Port of erts/emulator/beam/jit/arm/instr_trace.cpp:62-95 (call erts_generic_breakpoint
        // from the trampoline fragment), OTP-29.1.1: nothing to report, so the call goes on in
        // native code with every register as it was.
        return Some(0);
    }
    if identity == arinsal_beamasm::dispatch::BREAKPOINT_DISPATCH_IDENTITY
        || arinsal_beamasm::dispatch::decode_line_breakpoint_identity(identity).is_some()
    {
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
    if identity == arinsal_beamasm::dispatch::SEND_DISPATCH_IDENTITY {
        if saving_calls {
            crate::trace::save_call_send_export(process);
        }
        process.reductions = process.header.fcalls;
        // Traced sends run in the scheduler, which evaluates send trace patterns.
        // A port send may suspend the sender on a busy port (bif.c:2581): the scheduler
        // runs it, as it can park and redo the send.
        let result = if crate::trace::traces_sends(process)
            || crate::port::is_port_target(process, process.x[0])
        {
            Err(crate::VmError::Unsupported(
                crate::process::REMOTE_SEND_NEEDS_CONTEXT.into(),
            ))
        } else {
            process.send_message(process.x[0], process.x[1])
        };
        match result {
            Ok(value) => {
                // Port of erts/emulator/beam/bif.c:2451-2452 (erl_send: save_calls(p, &exp_send)),
                // OTP-29.1.1.
                if crate::trace::saves_calls(process) {
                    crate::trace::save_call(process, crate::trace::SavedCall::Send);
                }
                let raw = crate::native_hooks::raw(value);
                process.x[0] = value;
                publish_dispatch_x(process, registers);
                process.sync_native_header();
                return Some(raw);
            }
            // A remote destination is sent by the scheduler, which has the context the
            // distribution output needs; the send resumes the native caller like a BIF trap.
            Err(crate::VmError::Unsupported(message))
                if message == crate::process::REMOTE_SEND_NEEDS_CONTEXT =>
            {
                if crate::trace::saves_calls(process) {
                    crate::trace::save_call(process, crate::trace::SavedCall::Send);
                }
                process.header.arity = 2;
                process.header.i = identity as *const u8 as *const _;
                process.header.freason = 1 << 10;
                process.sync_native_header();
                return None;
            }
            Err(_) => {
                crate::native_hooks::set_error(process, "badarg");
                publish_dispatch_x(process, registers);
                process.sync_native_header();
                return Some(0);
            }
        }
    }
    let export = crate::beamasm_integration::export_dispatch(identity)?;
    if saving_calls {
        crate::trace::save_call(
            process,
            crate::trace::SavedCall::Mfa(export.module_atom, export.function_atom, export.arity),
        );
    }

    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-471 (call_light_bif), OTP-29.1.1:
    // the table BIFs run on the process heap straight from the generated code; anything the
    // direct path declines is redone through the scheduler.
    if let Some(direct) = export.direct_ets
        && !crate::trace_bp::any_pattern()
    {
        let arity = usize::from(export.arity).min(4);
        let args = [
            registers.x_reg_array[0],
            registers.x_reg_array[1],
            registers.x_reg_array[2],
            registers.x_reg_array[3],
        ]
        .map(crate::native_hooks::from_raw);
        if let Some(value) = direct(process, &args[..arity]) {
            process.reductions = process.header.fcalls;
            if export_call {
                charge_bif_reductions(process, 1);
            }
            // A direct BIF that failed has parked its exception (freason/fvalue set, as an erts
            // BIF returns THE_NON_VALUE); the call is not redone.
            if process.header.freason != 0 {
                publish_dispatch_x(process, registers);
                process.sync_native_header();
                return Some(0);
            }
            process.x[0] = value;
            let mut raw = crate::native_hooks::raw(value);
            if process.heap.gc_desired() || process.heap.bin_vheap_gc_due() {
                if process.collect_bin_vheap_if_due(1).is_err() {
                    crate::native_hooks::set_error(process, "system_limit");
                    publish_dispatch_x(process, registers);
                    process.sync_native_header();
                    return Some(0);
                }
                raw = crate::native_hooks::raw(process.x[0]);
            }
            registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
            publish_dispatch_x(process, registers);
            process.sync_native_header();
            return Some(raw);
        }
    }

    // Trapping BIFs keep continuation state that only the executor's call site handles.
    if matches!(
        export.class,
        arinsal_loader::ImportClass::Native
            | arinsal_loader::ImportClass::Dynamic
            | arinsal_loader::ImportClass::Fun
    ) || export.trap_entry
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
    let (bif, arity) = (export.bif?, export.arity);
    process.reductions = process.header.fcalls;
    if export_call {
        charge_bif_reductions(process, 1);
    }
    // Static NIF bodies read the scheduler hub like the interpreter's NativeBody does.
    crate::natives::nif::refresh_hub_native(process);
    let arity = usize::from(arity);
    if arity > process.x.len() {
        crate::native_hooks::set_error(process, "system_limit");
        return Some(0);
    }
    for (destination, raw) in process
        .x
        .iter_mut()
        .zip(registers.x_reg_array.iter().copied())
        .take(6)
    {
        *destination = crate::native_hooks::from_raw(raw);
    }
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-471 (call_light_bif), OTP-29.1.1:
    // the BIF reads its arguments from the register file; no per-call allocation.
    let mut inline_args = [Term::NIL; 8];
    let mut overflow_args = Vec::new();
    let args: &mut [Term] = if arity <= inline_args.len() {
        for (destination, raw) in inline_args.iter_mut().zip(&registers.x_reg_array[..arity]) {
            *destination = crate::native_hooks::from_raw(*raw);
        }
        &mut inline_args[..arity]
    } else {
        overflow_args.extend(
            registers.x_reg_array[..arity]
                .iter()
                .copied()
                .map(crate::native_hooks::from_raw),
        );
        &mut overflow_args
    };
    let (mut result, reductions) = crate::calls::call_bif_metered(&mut process.heap, bif, args);
    charge_bif_reductions(process, reductions);
    if crate::calls::gc_after_bif(process, args, &mut result).is_err() {
        crate::native_hooks::set_error(process, "system_limit");
        publish_dispatch_x(process, registers);
        process.sync_native_header();
        return Some(0);
    }
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
    match result {
        Ok(value) => {
            let mut value = crate::native_hooks::raw(value);
            process.x[0] = value_term(value);
            // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-471 (call_light_bif,
            // ERTS_IS_GC_AFTER_BIF_DESIRED), OTP-29.1.1: collect with the result as only root.
            if process.heap.gc_desired() || process.heap.bin_vheap_gc_due() {
                if process.collect_bin_vheap_if_due(1).is_err() {
                    crate::native_hooks::set_error(process, "system_limit");
                    publish_dispatch_x(process, registers);
                    process.sync_native_header();
                    return Some(0);
                }
                registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
                value = crate::native_hooks::raw(process.x[0]);
            }
            publish_dispatch_x(process, registers);
            process.sync_native_header();
            Some(value)
        }
        Err(error) => {
            set_native_bif_error(process, &export.module, &export.function, args, error);
            publish_dispatch_x(process, registers);
            process.sync_native_header();
            Some(0)
        }
    }
}

/// Charges the reductions a BIF reported against FCALLS, which the call site reloads.
// Port of erts/emulator/beam/bif.h (BUMP_REDS), OTP-29.1.1.
fn charge_bif_reductions(process: &mut crate::Process, reductions: u32) {
    process.reductions = process
        .reductions
        .saturating_sub(reductions.min(i32::MAX as u32) as i32);
}

/// Calls a plain BIF named by its export identity (`i_bif1/2/3`, `nofail_bif1/2`).
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:110-200, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_bif_by_identity(
    header: *mut ProcessHeader,
    identity: u64,
    first: u64,
    second: u64,
    third: u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::process_and_registers(header) else {
        return 0;
    };
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
    let Some((bif, arity)) = crate::beamasm_integration::dispatch_bif(identity as usize) else {
        crate::native_hooks::set_error(process, "undef");
        return 0;
    };
    let all_args = [first, second, third].map(crate::native_hooks::from_raw);
    let args = &all_args[..usize::from(arity).min(all_args.len())];
    process.reductions = process.header.fcalls;
    let (result, reductions) = crate::calls::call_bif_metered(&mut process.heap, bif, args);
    charge_bif_reductions(process, reductions);
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
    process.sync_native_header();
    match result {
        Ok(value) => crate::native_hooks::raw(value),
        Err(error) => {
            // Port of erts/emulator/beam/jit/arm/instr_bif.cpp (i_bif: the failing BIF and its
            // arguments are the top frame), OTP-29.1.1.
            match crate::beamasm_integration::export_dispatch(identity as usize) {
                Some(export) => {
                    set_native_bif_error(process, &export.module, &export.function, args, error)
                }
                None => set_light_bif_error(process, error),
            }
            process.sync_native_header();
            0
        }
    }
}

/// Raises `error:{Tag, Value}` from a native helper.
fn set_tagged_error(process: &mut crate::Process, tag: &str, value: Term) {
    let tuple = arinsal_term::TermBuilder::new(&mut crate::FragmentingHeap(&mut process.heap))
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
    if arity >= process.x.len() {
        crate::native_hooks::set_error(process, "system_limit");
        return;
    }
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
    // The arguments are still in the native X register array.
    for (destination, raw) in process
        .x
        .iter_mut()
        .zip(registers.x_reg_array.iter().copied())
        .take(arity)
    {
        *destination = crate::native_hooks::from_raw(raw);
    }
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

fn publish_dispatch_x(
    process: &crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
) {
    for (destination, term) in registers
        .x_reg_array
        .iter_mut()
        .zip(process.x.iter())
        .take(6)
    {
        *destination = crate::native_hooks::raw(*term);
    }
}

fn value_term(value: u64) -> Term {
    crate::native_hooks::from_raw(value)
}

/// Records a native BIF failure so the scheduler raises it with the BIF as the top frame.
pub(crate) fn set_native_bif_error(
    process: &mut crate::Process,
    module: &str,
    function: &str,
    args: &[Term],
    error: arinsal_bifs::BifError,
) {
    set_light_bif_error(process, error);
    let (freason, fvalue) = (process.header.freason, process.header.fvalue);
    process.cold_mut().native_bif_error = Some(crate::proc_create::NativeBifError {
        module: module.to_owned(),
        function: function.to_owned(),
        args: args.to_vec(),
        error,
        freason,
        fvalue,
    });
}

fn set_light_bif_error(process: &mut crate::Process, error: arinsal_bifs::BifError) {
    use arinsal_bifs::{BifError, Class};
    let (class, reason) = match error {
        BifError::Badarg { .. } => (1, crate::signals::atom("badarg")),
        BifError::Badarith => (1, crate::signals::atom("badarith")),
        BifError::SystemLimit => (1, crate::signals::atom("system_limit")),
        BifError::Error(reason) => (1, reason),
        BifError::Raise { class, reason, .. } => (
            match class {
                Class::Error => 1,
                Class::Exit => 2,
                Class::Throw => 3,
            },
            reason,
        ),
        BifError::Unsupported(_) => (1, crate::signals::atom("undef")),
        // NIF bodies trap to the executor before reaching here (`trap_to_dirty_nif`).
        BifError::Dirty(_) => (1, crate::signals::atom("notsup")),
    };
    process.header.freason = class;
    process.header.fvalue = crate::native_hooks::raw(reason);
}

/// Resolves a native exception to the innermost catch handler, or 0 to let the scheduler exit.
///
/// Always 0: the scheduler's `handle_error` port builds the raw stacktrace (which needs the
/// loaded-module table) before it resumes a native or interpreted catch.
pub extern "C" fn arinsal_beamasm_exception_resolver(
    _header: *mut ProcessHeader,
    _registers: *mut arinsal_beamasm::SchedulerRegisters,
    _stack: *mut u64,
) -> usize {
    0
}

/// Resolves a fun call that missed the local-dispatch fast path.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp:1307-1365
// (beam_jit_handle_unloaded_fun) and instr_fun.cpp:77-140, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_fun_resolver(
    header: *mut ProcessHeader,
    fun_raw: u64,
    arity: u32,
) -> usize {
    let Some((process, registers)) = crate::native_hooks::process_and_registers(header) else {
        return 0;
    };
    let fun = crate::native_hooks::from_raw(fun_raw);
    let view = crate::native_hooks::fun_view(fun);
    let unported = crate::beamasm_integration::call_fun_unported_entry();
    match view {
        Some(arinsal_term::FunRef::Local { entry, .. }) => {
            if u32::from(entry.arity) != arity {
                set_call_fun_error(process, registers, fun, arity);
                publish_dispatch_x(process, registers);
                process.sync_native_header();
                return 0;
            }
            if let Some(target) = entry.get_dispatch_target(0) {
                publish_dispatch_x(process, registers);
                process.sync_native_header();
                return target;
            }
            process.header.arity = arity.min(u8::MAX as u32) as u8;
            if let Some(slot) = process.x.get_mut(arity as usize) {
                *slot = fun;
            }
            publish_dispatch_x(process, registers);
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
                publish_dispatch_x(process, registers);
                process.sync_native_header();
                return 0;
            }
            let Some(module) = arinsal_term::global_atoms().text(entry.module) else {
                set_call_fun_error(process, registers, fun, arity);
                publish_dispatch_x(process, registers);
                process.sync_native_header();
                return 0;
            };
            let Some(function) = arinsal_term::global_atoms().text(entry.function) else {
                set_call_fun_error(process, registers, fun, arity);
                publish_dispatch_x(process, registers);
                process.sync_native_header();
                return 0;
            };
            let scope = process
                .runtime
                .as_ref()
                .map_or(0, |runtime| runtime.code_scope);
            if let Some(target) =
                crate::beamasm_integration::native_target_for(scope, module, function, entry.arity)
            {
                publish_dispatch_x(process, registers);
                process.sync_native_header();
                return target;
            }
            if let Some(native) = crate::native_function_for(scope, module, function, entry.arity) {
                publish_dispatch_x(process, registers);
                process.sync_native_header();
                return native.start;
            }
            process.header.arity = arity.min(u8::MAX as u32) as u8;
            if let Some(slot) = process.x.get_mut(arity as usize) {
                *slot = fun;
            }
            publish_dispatch_x(process, registers);
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
            publish_dispatch_x(process, registers);
            process.sync_native_header();
            0
        }
    }
}

/// Resolves `apply Arity` to a native entry, or to the fragment that lets the interpreter apply.
// Port of erts/emulator/beam/jit/arm/instr_call.cpp:263-320 (emit_fixed_apply) and
// erts/emulator/beam/beam_common.c (fixed_apply), OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_apply_resolver(header: *mut ProcessHeader, arity: u32) -> usize {
    let Some((process, registers)) = crate::native_hooks::process_and_registers(header) else {
        return 0;
    };
    let arity = arity as usize;
    let fragment = crate::beamasm_integration::apply_fixed_unported_entry();
    if fragment == 0 || arity + 1 >= registers.x_reg_array.len() {
        crate::native_hooks::set_error(process, "system_limit");
        process.sync_native_header();
        return 0;
    }
    let module = crate::native_hooks::from_raw(registers.x_reg_array[arity]);
    let function = crate::native_hooks::from_raw(registers.x_reg_array[arity + 1]);
    // Port of erts/emulator/beam/beam_common.c:1554-1557 (fixed_apply), OTP-29.1.1: an
    // apply of erlang:apply/3 is a plain apply/3 of its arguments.
    if arity == 3
        && module
            .as_atom()
            .and_then(|atom| arinsal_term::global_atoms().text(atom))
            == Some("erlang")
        && function
            .as_atom()
            .and_then(|atom| arinsal_term::global_atoms().text(atom))
            == Some("apply")
    {
        let apply3 = crate::beamasm_integration::apply3_unported_entry();
        if apply3 != 0 {
            return apply3;
        }
    }
    if let (Some(module), Some(function)) = (module.as_atom(), function.as_atom())
        && let (Some(module), Some(function)) = (
            arinsal_term::global_atoms().text(module),
            arinsal_term::global_atoms().text(function),
        )
        && let Some(target) = crate::beamasm_integration::exported_native_target(
            process
                .runtime
                .as_ref()
                .map_or(0, |runtime| runtime.code_scope),
            module,
            function,
            arity as u8,
        )
    {
        return target;
    }
    // Not natively compiled (or invalid): the interpreter applies and raises errors.
    process.header.arity = arity.min(u8::MAX as usize) as u8;
    process.sync_native_header();
    fragment
}

/// Builds a map or applies staged key/value updates to one.
// Port of erts/emulator/beam/jit/arm/instr_map.cpp:125-149,465-633, OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_map_new(
    header: *mut ProcessHeader,
    source: u64,
    _registers: u64,
    live: u64,
    count: u64,
) -> u64 {
    arinsal_beamasm_map_change(header, source, live, count, false, false)
}

/// Applies associative updates to a staged list of key/value pairs.
pub extern "C" fn arinsal_beamasm_map_assoc(
    header: *mut ProcessHeader,
    source: u64,
    _registers: u64,
    live: u64,
    count: u64,
) -> u64 {
    arinsal_beamasm_map_change(header, source, live, count, false, true)
}

/// Applies exact updates to a staged list of key/value pairs.
pub extern "C" fn arinsal_beamasm_map_exact(
    header: *mut ProcessHeader,
    source: u64,
    _registers: u64,
    live: u64,
    count: u64,
) -> u64 {
    arinsal_beamasm_map_change(header, source, live, count, true, true)
}

fn arinsal_beamasm_map_change(
    header: *mut ProcessHeader,
    source: u64,
    live: u64,
    count: u64,
    exact: bool,
    update: bool,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::process_and_registers(header) else {
        return 0;
    };
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
    let Ok(count) = usize::try_from(count) else {
        return 0;
    };
    let has_fail_label = live >> 32 != 0;
    let Ok(live) = usize::try_from(live & 0xffff_ffff) else {
        return 0;
    };
    // Stage source at X6-1 spill space is already used for pairs at X6+; keep source
    // in the live X registers so GC during ensure relocates it. The emitter stages
    // `{key,value}` pairs at X6.. and passes `live` covering X0..X{live-1} plus those.
    let base = live.max(6);
    let source_slot = base + count * 2;
    if source_slot >= registers.x_reg_array.len() {
        return 0;
    }
    registers.x_reg_array[source_slot] = source;
    let root_live = live.max(source_slot + 1);
    if process.x.len() < root_live {
        let mut x = process.x.to_vec();
        x.resize(root_live, arinsal_term::Term::NIL);
        process.x = x.into_boxed_slice();
    }
    for (i, slot) in registers.x_reg_array[..root_live].iter().enumerate() {
        // X registers between the live prefix and the staged pairs are dead and may hold
        // stale words; they must not become GC roots.
        process.x[i] = if (live..base).contains(&i) {
            arinsal_term::Term::NIL
        } else {
            crate::native_hooks::from_raw(*slot)
        };
    }
    // Like the interpreter's put_map_assoc/put_map_exact: build first, and collect only when
    // the heap is short, keeping the live registers (erts/emulator/beam/erl_map.c, OTP-29.1.1).
    let mut collected = false;
    let result = loop {
        let source_term = process.x[source_slot];
        let pairs = (0..count)
            .map(|index| (process.x[base + index * 2], process.x[base + 1 + index * 2]))
            .collect::<Vec<_>>();
        let attempt = match (update, pairs.as_slice()) {
            (true, [(key, value)]) if exact => {
                arinsal_maps::update(source_term, *key, *value, &mut process.heap)
            }
            (true, [(key, value)]) => {
                arinsal_maps::put(source_term, *key, *value, &mut process.heap)
            }
            (true, _) => arinsal_maps::put_many(source_term, &pairs, exact, &mut process.heap),
            (false, _) => arinsal_maps::from_pairs(&pairs, &mut process.heap),
        };
        match attempt {
            Err(arinsal_maps::MapError::HeapFull { need_words }) if !collected => {
                collected = true;
                if process.ensure(need_words, root_live).is_err() {
                    crate::native_hooks::set_error(process, "system_limit");
                    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
                    return 0;
                }
                registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
            }
            other => {
                // Only the live registers moved; the dead ones between them and the staged
                // pairs stay untouched, as in erts.
                for (index, (slot, term)) in registers.x_reg_array[..root_live]
                    .iter_mut()
                    .zip(process.x.iter())
                    .enumerate()
                {
                    if !(live..base).contains(&index) {
                        *slot = crate::native_hooks::raw(*term);
                    }
                }
                break other;
            }
        }
    };
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
    let Some((process, registers)) = crate::native_hooks::process_and_registers(header) else {
        return 0;
    };
    let result = arinsal_maps::get(
        crate::native_hooks::from_raw(map),
        crate::native_hooks::from_raw(key),
    );
    for (destination, term) in registers
        .x_reg_array
        .iter_mut()
        .zip(process.x.iter())
        .take(6)
    {
        *destination = crate::native_hooks::raw(*term);
    }
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
pub extern "C" fn arinsal_beamasm_map_get_elements(
    header: *mut ProcessHeader,
    map: u64,
    _registers: u64,
    base: u64,
    count: u64,
) -> u64 {
    let Some((process, registers)) = crate::native_hooks::process_and_registers(header) else {
        return 0;
    };
    let Ok(count) = usize::try_from(count) else {
        return 0;
    };
    for index in 0..count {
        let key = crate::native_hooks::from_raw(registers.x_reg_array[base as usize + index * 3]);
        let result = arinsal_maps::get(crate::native_hooks::from_raw(map), key);
        let Ok(Some(value)) = result else {
            return 0;
        };
        registers.x_reg_array[base as usize + 1 + index * 3] = crate::native_hooks::raw(value);
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
    let Some((process, registers)) = crate::native_hooks::process_and_registers(header) else {
        return 0;
    };
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
    if root_live > registers.x_reg_array.len() {
        crate::native_hooks::set_error(process, "system_limit");
        return 0;
    }
    if process.x.len() < root_live {
        let mut x = process.x.to_vec();
        x.resize(root_live, Term::NIL);
        process.x = x.into_boxed_slice();
    }
    for (index, slot) in registers.x_reg_array[..root_live].iter().enumerate() {
        // Dead X registers below the staged segments must not become GC roots.
        process.x[index] = if (live..base_slot).contains(&index) {
            Term::NIL
        } else {
            crate::native_hooks::from_raw(*slot)
        };
    }
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
    let mut request = match arinsal_bits::create_bin_size(&initial) {
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
    drop(initial);
    let result = loop {
        if process.ensure(request, root_live).is_err() {
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
    for (slot, term) in registers.x_reg_array[..root_live]
        .iter_mut()
        .zip(process.x.iter())
    {
        *slot = crate::native_hooks::raw(*term);
    }
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
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
    let Some((process, registers)) = crate::native_hooks::process_and_registers(header) else {
        return 0;
    };
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
    let base = (live as usize).max(6);
    let root_live = base + 4;
    if process.x.len() < root_live {
        let mut x = process.x.to_vec();
        x.resize(root_live, Term::NIL);
        process.x = x.into_boxed_slice();
    }
    // The X registers below `base` and the staged operands (the context among them) are the
    // roots of a collection; the staged copies follow the registers in `process.x`.
    // Port of erts/emulator/beam/jit/arm/instr_bs.cpp (emit_gc_test_preserve), OTP-29.1.1.
    for (index, slot) in registers.x_reg_array[..base].iter().enumerate() {
        process.x[index] = crate::native_hooks::from_raw(*slot);
    }
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
    for (slot, term) in registers.x_reg_array[..base]
        .iter_mut()
        .zip(process.x.iter())
    {
        *slot = crate::native_hooks::raw(*term);
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
    let Some((process, registers)) = crate::native_hooks::process_and_registers(header) else {
        return 0;
    };
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
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
    for (destination, term) in registers
        .x_reg_array
        .iter_mut()
        .zip(process.x.iter())
        .take(6)
    {
        *destination = crate::native_hooks::raw(*term);
    }
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
    process.sync_native_header();
    result.map(crate::native_hooks::raw).unwrap_or(0)
}
