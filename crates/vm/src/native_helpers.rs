//! Runtime helper bodies called by BeamAsm generated code.
//!
//! Port of erts/emulator/beam/jit/x86/instr_bif.cpp:1136 (`get_on_load_address`).

use arinsal_beamasm::ProcessHeader;
use arinsal_term::{HeapAlloc, PreparedWritableAppend, Term, TermBuilder};

use crate::beamasm_integration::ExportDispatch;

/// Resolves the on-load function in the process-visible active code tables.
// Port of erts/emulator/beam/jit/x86/instr_bif.cpp:1136 (get_on_load_address), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn get_on_load_address(header: *mut ProcessHeader, module_raw: u64) -> usize {
    let Some(process) = crate::native_hooks::process_from_header(header) else {
        return 0;
    };
    let runtime = process.runtime;
    let address = crate::native_hooks::from_raw(module_raw)
        .as_atom()
        .and_then(|module| arinsal_term::global_atoms().text(module))
        .and_then(|module| {
            runtime?.with_active_code(|_, tables| {
                let id = tables.pending_on_load.get(module).copied()?;
                let meta = tables.code_meta.get(id)?.as_ref()?;
                meta.beamasm.as_ref()?.on_load_address()
            })
        });
    match address {
        Some(address) => address,
        None => {
            process.heap.abi.exc.freason = arinsal_term::exc::EXC_BADARG;
            0
        }
    }
}

struct StaticNif {
    module: String,
    function: String,
    arity: u8,
    entry: arinsal_bifs::BifFn,
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
        .then(|| process.self_pid().and_then(|pid| pid.to_term()));
    Some(crate::dirty::static_nif_job(move |heap| {
        heap.abi.fcalls = fcalls;
        let mut run = || crate::calls::call_bif(heap, entry, &args);
        match pinned_caller {
            Some(caller) => arinsal_nif_zlib::with_caller(caller, run),
            None => run(),
        }
    }))
}

/// Runs a static NIF with the arguments in `reg`, for a dirty NIF call the executor
/// performs on a dirty scheduler, or takes the result of its dirty job.
pub(crate) fn run_static_nif(
    process: &mut crate::Process,
    reg: &[Term],
    identity: usize,
) -> Result<Term, crate::VmError> {
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
    let done = process
        .cold
        .as_mut()
        .and_then(|cold| cold.static_nif_done.take());
    let result = match done {
        Some(result) => result,
        None => crate::calls::call_bif(&mut process.heap, entry, &args),
    };
    result.map_err(|error| crate::exceptions::bif_error(process, &module, &function, &args, error))
}

/// Returns the result of a native call-NIF body to native code: the result term, a trap to
/// the dirty scheduler executor or an exception.
#[cfg(target_arch = "aarch64")]
fn leave_native_nif(
    process: &mut crate::Process,
    reg: &mut [Term],
    result: Result<Term, arinsal_bifs::BifError>,
) -> u64 {
    match result {
        Ok(value) => {
            reg[0] = value;
            crate::native_hooks::raw(value)
        }
        // beam_jit_call_nif set `c_p->current` before the call and the arguments are still in
        // `reg`: the failure is only `freason`/`fvalue` (beam_jit_common.cpp:623-690).
        Err(error) => {
            set_light_bif_error(process, &error);
            0
        }
    }
}

/// Calls a static NIF body through the same BIF function used by NativeBody.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:863-900, OTP-29.1.1.
#[cfg(target_arch = "aarch64")]
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
    // Like the interpreter's NativeBody, the body reads the scheduler hub, which process_main
    // installed when the process was scheduled in.
    if nif.module == "prim_tty" {
        crate::natives::tty::note_caller_native(process);
    }
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:635 (beam_jit_call_nif): `current` is
    // set "to please handle_error" before the NIF runs.
    if let Some(export) =
        crate::beamasm_integration::bif_mfa_export(&nif.module, &nif.function, u32::from(nif.arity))
    {
        process.heap.abi.current = std::ptr::from_ref(export.mfa()).cast();
    }
    let result =
        crate::calls::call_bif(&mut process.heap, nif.entry, &reg[..usize::from(nif.arity)]);
    leave_native_nif(process, reg, result)
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
#[cfg(target_arch = "aarch64")]
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
#[cfg(target_arch = "aarch64")]
pub(crate) extern "C" fn arinsal_beamasm_export_trampoline(
    header: *mut ProcessHeader,
    identity: u64,
    ep: u64,
    reg: *mut u64,
) -> u64 {
    let export = crate::beamasm_integration::export_dispatch(ep as usize);
    // THE_NON_VALUE raises, 1 hands the call to the interpreter, any term word is the result.
    let raw = invoke_dispatch_bif(header, reg, identity as usize, export, true).unwrap_or(1);
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp (beam_jit_call_bif:
    // ERTS_IS_GC_AFTER_BIF_DESIRED, then erts_gc_after_bif_call_lhf with `reg`), OTP-29.1.1:
    // the export entry's BIF call collects after the BIF, for a value or the non-value.
    if raw != 1
        && let Some(export) = export
        && let Some((process, registers)) =
            crate::native_hooks::enter_runtime_after_bif(header, reg)
        && process.heap.gc_after_bif_desired()
    {
        let live_hf_end = process.heap.bif_live_hf_end();
        let arity = export.arity as usize;
        return crate::erl_gc::erts_gc_after_bif_call_lhf(
            process,
            live_hf_end,
            raw,
            &mut registers.x_reg_array,
            arity,
        );
    }
    raw
}

/// `call_error_handler` of the export trampoline: the export of
/// `error_handler:undefined_function/3` (the process's error handler module), with X0..X2 set
/// to the stub's module, function and argument list; zero when there is no such function.
// Port of erts/emulator/beam/beam_common.c:1294-1345 (call_error_handler), OTP-29.1.1.
pub(crate) extern "C" fn arinsal_beamasm_call_error_handler(
    header: *mut ProcessHeader,
    ep: u64,
    reg: *mut u64,
) -> usize {
    let Some(stub) = crate::beamasm_integration::export_dispatch(ep as usize) else {
        return 0;
    };
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(header, reg) else {
        return 0;
    };
    let Ok(undefined_function) = arinsal_term::global_atoms().intern("undefined_function") else {
        return 0;
    };
    let mfa_pointer = std::ptr::from_ref(stub.mfa());
    crate::beam_common::call_error_handler_core(
        process,
        registers,
        (stub.module_atom, stub.function_atom, stub.arity),
        mfa_pointer,
        undefined_function,
    )
}

/// Records the remote call of a process saving calls (the export entry is `identity`) and
/// returns the address the call continues with.
// Port of erts/emulator/beam/jit/arm/instr_call.cpp:123-148 (emit_dispatch_save_calls_export),
// OTP-29.1.1.
pub(crate) extern "C" fn arinsal_beamasm_save_calls_export(
    header: *mut ProcessHeader,
    _identity: u64,
    ep: u64,
) -> u64 {
    let export = crate::beamasm_integration::export_dispatch(ep as usize);
    if let Some(export) = export {
        crate::trace::save_calls(header, export.export_entry_address());
    }
    crate::beamasm_integration::save_calls_continuation(export) as u64
}

/// Runs a light BIF through the shared BeamAsm fragment.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-471, OTP-29.1.1.
// The call site passes the Export*; the send and
// breakpoint identities pass none.
#[cfg(target_arch = "aarch64")]
pub(crate) extern "C" fn arinsal_beamasm_call_light_bif_shared(
    header: *mut ProcessHeader,
    identity: u64,
    // The call site the fragment records in `tmp_mem[6]`; the helper itself reads it from there.
    _site: u64,
    ep: u64,
    reg: *mut u64,
) -> u64 {
    let export = crate::beamasm_integration::export_dispatch(ep as usize);
    call_light_bif_body(header, reg, identity, export)
}

/// The shared fragment's general path. Out of line so a counter BIF does not
/// pay this function's prologue.
#[inline(never)]
#[cfg(target_arch = "aarch64")]
fn call_light_bif_body(
    header: *mut ProcessHeader,
    reg: *mut u64,
    identity: u64,
    export: Option<ExportDispatch>,
) -> u64 {
    invoke_dispatch_bif(header, reg, identity as usize, export, false).unwrap_or(0)
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
#[cfg(target_arch = "aarch64")]
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
    export as *const arinsal_term::ExportEntry as usize as u64
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
    let arity = u8::try_from(export.arity).ok()?;
    if let Some(func) = crate::bif_table::special(&export.module, &export.function, arity) {
        return Some(func);
    }
    // The kind is fixed when the export is created (`bif_table[].f`). The call
    // fragment branches to that pointer; it does not walk `invoke_dispatch_bif`.
    if export.light_process_bif.is_some() {
        return Some(
            crate::natives::thin_entry(&export.module, &export.function, arity)
                .unwrap_or(crate::bif_table::bif!(process_bif_light)),
        );
    }
    if export.runs_in_executor() {
        return Some(crate::bif_table::bif!(yield_executor_bif));
    }
    if let Some(entry) = crate::bif_table::entry(&export.module, &export.function, arity) {
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
    let identity = crate::bif_table::current_export(header);
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp (call_light_bif_shared passes the
    // call's entry address `I`), OTP-29.1.1: the export trampoline passes none.
    let light_call = i != 0;
    let Some(process) = crate::native_hooks::enter_runtime(header) else {
        return 0;
    };
    let Some(export) = crate::beamasm_integration::export_dispatch(identity as usize) else {
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
    process.heap.abi.arity = export.arity as u8;
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
    let identity = crate::bif_table::current_export(header);
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(header, regs) else {
        return 0;
    };
    let Some(export) = crate::beamasm_integration::export_dispatch(identity as usize) else {
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
    let identity = crate::bif_table::current_export(header);
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(header, regs) else {
        return 0;
    };
    let Some(export) = crate::beamasm_integration::export_dispatch(identity as usize) else {
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
    let identity = crate::bif_table::current_export(header);
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(header, regs) else {
        return 0;
    };
    match B::call(process, &registers.x_reg_array[..B::ARITY]) {
        Ok(value) => {
            registers.x_reg_array[0] = value;
            crate::native_hooks::raw(value)
        }
        Err(trap) => thin_bif_failed(process, registers, identity, *trap),
    }
}

/// A thin process BIF's exception, run through the same path as a [`ProcessBif`]'s.
#[cold]
#[inline(never)]
fn thin_bif_failed(
    process: &mut crate::Process,
    _registers: &mut arinsal_beamasm::SchedulerRegisters,
    identity: u64,
    trap: crate::exceptions::Trap,
) -> u64 {
    let Some(export) = crate::beamasm_integration::export_dispatch(identity as usize) else {
        return 0;
    };
    process_bif_result(process, export, Err(trap))
}

// `export_call`: reached through an export entry, whose BIF trampoline charges the call one
// reduction (erts/emulator/beam/jit/arm/instr_bif.cpp:399, OTP-29.1.1); a light BIF call
// site has already charged it.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-471 (call_light_bif_shared), OTP-29.1.1:
// a plain BIF is called straight away; save_calls, tracing and the
// breakpoint and send identities branch off to the slow path.
#[inline(always)]
#[cfg(target_arch = "aarch64")]
fn invoke_dispatch_bif(
    header: *mut ProcessHeader,
    reg: *mut u64,
    identity: usize,
    export: Option<ExportDispatch>,
    export_call: bool,
) -> Option<u64> {
    let (process, registers) = crate::native_hooks::enter_runtime_reg(header, reg)?;
    if let Some(export) = export
        && export_call
    {
        // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:729-745:
        // call_bif_shared stores the export's MFA in c_p->current before the BIF call.
        process.heap.abi.current = if export.is_bif_export() {
            std::ptr::from_ref(export.mfa()).cast()
        } else {
            std::ptr::null()
        };
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
    invoke_dispatch_bif_slow(process, registers, identity, export, export_call)
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

#[cold]
#[inline(never)]
#[cfg(target_arch = "aarch64")]
fn invoke_dispatch_bif_slow(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    identity: usize,
    export: Option<ExportDispatch>,
    export_call: bool,
) -> Option<u64> {
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
        process.heap.abi.arity = export.arity as u8;
        process.heap.abi.i = identity as *const u8 as *const _;
        process.heap.abi.exc.freason = 1 << 10;
        process.native_light_bif_call = !export_call;
        return None;
    }
    park_executor(process, export, identity as u64, !export_call);
    None
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
    let arity = export.arity as usize;
    plain_bif_result(process, registers, arity, result)
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
    let arity = export.arity as usize;
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
    let arity = export.arity as usize;
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
    if !process.heap.gc_enabled() {
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
            let reg: &[Term] = (crate::Vm {}).x_regs().ok().map_or(&[], |reg| &*reg);
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
    let identity = crate::bif_table::current_export(header);
    let Some(process) = crate::native_hooks::process_from_header(header) else {
        return 0;
    };
    let Some(export) = crate::beamasm_integration::export_dispatch(identity as usize) else {
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
    let identity = crate::bif_table::current_export(header);
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(header, regs) else {
        return 0;
    };
    let Some(export) = crate::beamasm_integration::export_dispatch(identity as usize) else {
        return 0;
    };
    // The light fragment passes the call's entry address `I`; the export trampoline none.
    let light_call = i != 0;
    let mut args = [Term::NIL; 4];
    args[..B::ARITY].copy_from_slice(&registers.x_reg_array[..B::ARITY]);
    process.gc_live = B::ARITY;
    // The call site a raising or suspending BIF names (`c_p->i` at the call).
    process.native_call_pc = registers.tmp_mem[6] as usize;
    let result = arinsal_sched::erts_proc_sched_data(process, |process, esdp| {
        arinsal_sched::RunCtx::with_current(esdp, |ctx| {
            (B::BODY)(&mut crate::Vm {}, process, ctx, &args[..B::ARITY])
        })
    })
    .flatten()
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
                export.arity as usize,
            )
    {
        let atoms = arinsal_term::global_atoms();
        if let (Some(m), Some(f)) = (atoms.text(*module), atoms.text(*function))
            && let Some(bif) = crate::beamasm_integration::bif_mfa_export(m, f, terms.len() as u32)
        {
            if let Ok(reg) = (crate::Vm {}).x_regs() {
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
        Err(error) => plain_bif_error(process, error),
    }
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
fn plain_bif_error(process: &mut crate::Process, error: arinsal_bifs::BifError) -> u64 {
    set_native_bif_export_error(process, error);
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
    match crate::funs::call_error_reason(
        process,
        &mut registers.x_reg_array,
        fun,
        arity,
        Term::NON_VALUE,
    ) {
        Ok(reason) => {
            process.heap.abi.exc.freason = arinsal_beamasm::exc::EXC_ERROR;
            process.heap.abi.exc.fvalue = crate::native_hooks::raw(reason);
        }
        Err(_) => crate::native_hooks::set_error(process, "system_limit"),
    }
}

/// Leaves the failure in `freason`/`fvalue`; `call_light_bif_shared` hands the export's MFA
/// to `raise_exception_shared` in ARG4 and the arguments are still in the X registers.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:539-545 (call_light_bif_shared error path:
// `ldp ARG2, ARG4, entry_mem; add ARG4, ARG4, offsetof(Export, info.mfa)`), OTP-29.1.1.
fn set_native_bif_export_error(process: &mut crate::Process, error: arinsal_bifs::BifError) {
    set_light_bif_error(process, &error);
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

/// `exception_tag[GET_EXC_CLASS(freason)]`: the class of any raised `freason`.
// Port of erts/emulator/beam/error.h (GET_EXC_CLASS) and beam_common.c (handle_error:
// `exception_tag[GET_EXC_CLASS(c_p->freason)]`), OTP-29.1.1.
#[inline]
pub(crate) fn get_exc_class(freason: u64) -> arinsal_bifs::Class {
    match arinsal_term::exc::exc_class(freason) {
        arinsal_beamasm::exc::EXTAG_EXIT => arinsal_bifs::Class::Exit,
        arinsal_beamasm::exc::EXTAG_THROWN => arinsal_bifs::Class::Throw,
        _ => arinsal_bifs::Class::Error,
    }
}

/// Unpacks the `Value = {Reason, Args[, ErrorInfo]}` used by `erlang:error/2,3`; an
/// `ErrorInfo` replaces `c_p->fvalue`.
// Port of erts/emulator/beam/beam_common.c (handle_error, `c_p->freason & EXF_ARGLIST`),
// OTP-29.1.1.
pub(crate) fn unpack_error_arglist(process: &mut crate::Process) -> (Term, Term) {
    use arinsal_term::raw::Tuple;
    let value = crate::native_hooks::from_raw(process.heap.abi.exc.fvalue);
    // erts: `tp = tuple_val(Value)`; only error/2,3 set EXF_ARGLIST, always with a tuple.
    let Ok(tuple) = Tuple::try_from(value) else {
        unreachable!("EXF_ARGLIST without an argument tuple: {value:?}");
    };
    let (Some(reason), Some(args)) = (tuple.get(0), tuple.get(1)) else {
        unreachable!("EXF_ARGLIST tuple arity {}", tuple.arity());
    };
    if tuple.arity() == 3
        && let Some(error_info) = tuple.get(2)
    {
        process.heap.abi.exc.fvalue = crate::native_hooks::raw(error_info);
    }
    (reason, args)
}

/// Supplies erts' `bif_mfa` input to `save_stacktrace`, with arguments in the live X registers.
// Port of erts/emulator/beam/beam_common.c:899-925 (`save_stacktrace`), OTP-29.1.1.
pub(crate) fn native_bif_top(
    process: &crate::Process,
    bif_info: u64,
    registers: &[Term],
) -> Option<crate::stacktrace::TopFrame> {
    use crate::stacktrace::TopFrame;
    let freason = process.heap.abi.exc.freason;
    // Port of beam_common.c `save_stacktrace` (non_bif_stacktrace): with a NULL `bif_mfa`,
    // only a function_clause reads its MFA and arguments from `c_p->current` and the
    // argument registers (set by `i_func_info_shared`).
    let bif_info = if bif_info == 0
        && freason & arinsal_beamasm::exc::EXC_INDEXBITS
            == arinsal_term::exc::EXC_FUNCTION_CLAUSE & arinsal_beamasm::exc::EXC_INDEXBITS
    {
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
    let (module, function, arity) = crate::raw::beam_common_ffi::code_mfa(bif_info)?;
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
        arity: arity as usize,
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

/// The error term for `freason`'s exit code. Does not update `c_p->fvalue` or
/// `c_p->freason`.
// Port of erts/emulator/beam/beam_common.c:742-777 (expand_error_value) and :382 (error_atom),
// OTP-29.1.1.
pub(crate) fn expand_error_value(process: &mut crate::Process, freason: u64, value: Term) -> Term {
    use arinsal_term::atoms;
    const ERROR_ATOM: [arinsal_term::Atom; 23] = [
        atoms::INTERNAL_ERROR,
        atoms::NORMAL,
        atoms::INTERNAL_ERROR,
        atoms::BADARG,
        atoms::BADARITH,
        atoms::BADMATCH,
        atoms::FUNCTION_CLAUSE,
        atoms::CASE_CLAUSE,
        atoms::IF_CLAUSE,
        atoms::UNDEF,
        atoms::BADFUN,
        atoms::BADARITY,
        atoms::TIMEOUT_VALUE,
        atoms::NOPROC,
        atoms::NOTALIVE,
        atoms::SYSTEM_LIMIT,
        atoms::TRY_CLAUSE,
        atoms::NOTSUP,
        atoms::BADMAP,
        atoms::BADKEY,
        atoms::BADRECORD,
        atoms::BADFIELD,
        atoms::NOVALUE,
    ];
    // GET_EXC_INDEX: `(x & EXC_INDEXBITS) >> 10`; erts ASSERTs `r < NUMBER_EXIT_CODES`.
    let r = ((freason & arinsal_beamasm::exc::EXC_INDEXBITS) >> 10) as usize;
    match r {
        // Primary exceptions use fvalue as it is.
        0 => value,
        // Some common exceptions: value -> {atom, value}.
        5 | 7 | 10 | 11 | 16 | 18 | 19 | 20 | 21 | 22 => {
            halloc_tuple2(process, Term::atom(ERROR_ATOM[r]), value)
        }
        // Other exceptions just use an atom as descriptor.
        _ => Term::atom(ERROR_ATOM[r]),
    }
}

/// `hp = HAlloc(c_p, 3); TUPLE2(hp, a, b)`: the young heap, else a heap fragment
/// (erts_heap_alloc, utils.c); never fails.
// Port of erts/emulator/beam/erl_vm.h (HAlloc) and erl_term.h (TUPLE2), OTP-29.1.1.
pub(crate) fn halloc_tuple2(process: &mut crate::Process, a: Term, b: Term) -> Term {
    let mut heap = arinsal_bifs::ProcessHeapHandle(&mut process.heap);
    match arinsal_term::TermBuilder::new(&mut heap).tuple(&[a, b]) {
        Ok(tuple) => tuple,
        Err(error) => unreachable!("HAlloc falls back to a heap fragment: {error:?}"),
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
                == 0
                && let Some(target) = entry.fun_code(code_ix)
            {
                return target;
            }
            let export = crate::beam_jit_common::beam_jit_handle_unloaded_fun(
                header,
                reg,
                arity as i32,
                fun_raw,
                code_ix as u32,
            );
            if export == 0 {
                return 0;
            }
            crate::raw::jit_ffi::export_entry(export).address(code_ix)
        }
        Some(arinsal_term::FunRef::Export { entry }) => {
            if fun.fun_arity().map(u32::from) != Some(arity) {
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
                    .export_entry((entry.module(), entry.function(), entry.arity()), code_ix)
                    .or_else(|| {
                        crate::export::export_entry_or_stub((
                            entry.module(),
                            entry.function(),
                            entry.arity(),
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
    mfa: (arinsal_term::Atom, arinsal_term::Atom, u32),
    return_ip: u64,
    stack_offset: u64,
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
    process.ensure_objv(need, &mut registers.x_reg_array[..mfa.2 as usize + 2]);
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

#[derive(Clone, Copy)]
pub(crate) struct ApplyTarget {
    pub export: *const arinsal_term::ExportEntry,
    pub target: usize,
}

#[derive(Clone, Copy)]
pub(crate) enum ApplyFailure {
    Raise,
    Adjustment,
}

fn apply_error(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    module: Term,
    function: Term,
    args: Term,
    reason: arinsal_bifs::BifError,
) -> Result<ApplyTarget, ApplyFailure> {
    set_light_bif_error(process, &reason);
    registers.x_reg_array[0] = module;
    registers.x_reg_array[1] = function;
    registers.x_reg_array[2] = args;
    Err(ApplyFailure::Raise)
}

fn lookup_apply_export(
    process: &crate::Process,
    mfa: (arinsal_term::Atom, arinsal_term::Atom, u32),
    code_ix: usize,
) -> Option<ApplyTarget> {
    process
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.export_entry(mfa, code_ix))
        .map(|export| ApplyTarget {
            export: std::ptr::from_ref(export),
            target: export.address(code_ix),
        })
        .or_else(|| {
            crate::export::export_entry_or_stub(mfa).map(|export| ApplyTarget {
                export: std::ptr::from_ref(&**export),
                target: export.address(code_ix),
            })
        })
}

/// Resolves OTP's `fixed_apply` operation for both the x86 C ABI and arm BeamAsm.
// Port of erts/emulator/beam/beam_common.c:1529-1566 (`fixed_apply`), OTP-29.1.1.
pub(crate) fn resolve_fixed_apply(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    arity: usize,
    return_ip: u64,
    stack_offset: u64,
) -> Result<ApplyTarget, ApplyFailure> {
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
        // Port of erts/emulator/beam/beam_common.c:1540-1552 (`fixed_apply` error path).
        process.ensure_objv(arity * 2, &mut registers.x_reg_array[..arity + 2]);
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
    if arity == 3
        && module_atom == arinsal_term::atoms::ERLANG
        && function_atom == arinsal_term::atoms::APPLY
    {
        return resolve_apply(process, registers, return_ip, stack_offset);
    }
    let mfa = (module_atom, function_atom, arity as u32);
    let code_ix = registers.active_code_ix as usize;
    let Some(target) = lookup_apply_export(process, mfa, code_ix) else {
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
        return Err(ApplyFailure::Adjustment);
    }
    Ok(target)
}

/// Resolves OTP's variable `apply` operation and copies its proper-list arguments to X registers.
// Port of erts/emulator/beam/beam_common.c:1434-1527 (`apply`), OTP-29.1.1.
pub(crate) fn resolve_apply(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
    return_ip: u64,
    stack_offset: u64,
) -> Result<ApplyTarget, ApplyFailure> {
    let (mut module, mut function, mut args) = (
        registers.x_reg_array[0],
        registers.x_reg_array[1],
        registers.x_reg_array[2],
    );
    // Port of erts/emulator/beam/beam_common.c:1462-1495 (nested apply loop).
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
    while let Some((head, tail)) = crate::lists::split(list) {
        if arity == registers.x_reg_array.len() - 1 {
            return apply_error(
                process,
                registers,
                module,
                function,
                args,
                arinsal_bifs::BifError::SystemLimit,
            );
        }
        registers.x_reg_array[arity] = head;
        arity += 1;
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
    let mfa = (module_atom, function_atom, arity as u32);
    let code_ix = registers.active_code_ix as usize;
    let Some(target) = lookup_apply_export(process, mfa, code_ix) else {
        return apply_error(
            process,
            registers,
            Term::atom(module_atom),
            Term::atom(function_atom),
            args,
            arinsal_bifs::BifError::Badarg { cause: None },
        );
    };
    if !apply_bif_error_adjustment(process, registers, mfa, return_ip, stack_offset) {
        return Err(ApplyFailure::Adjustment);
    }
    Ok(target)
}

#[cfg(target_arch = "aarch64")]
fn arm_apply_resolution(
    resolution: Result<ApplyTarget, ApplyFailure>,
) -> arinsal_beamasm::misc::ApplyResolution {
    match resolution {
        Ok(target) => arinsal_beamasm::misc::ApplyResolution {
            export: target.export as u64,
            target: target.target as u64,
        },
        // The emitter raises with `apply3_mfa` in ARG4 (instr_call.cpp emit_i_apply).
        Err(ApplyFailure::Raise | ApplyFailure::Adjustment) => {
            arinsal_beamasm::misc::ApplyResolution::default()
        }
    }
}

/// ARM's fixed-apply entry maps the shared erts export resolution to its branch pair.
// Port of erts/emulator/beam/beam_common.c:1529-1566 (`fixed_apply`), OTP-29.1.1.
#[cfg(target_arch = "aarch64")]
pub extern "C" fn arinsal_beamasm_apply_resolver(
    header: *mut ProcessHeader,
    arity: u32,
    return_ip: u64,
    stack_offset: u32,
    reg: *mut u64,
) -> arinsal_beamasm::misc::ApplyResolution {
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(header, reg) else {
        return arinsal_beamasm::misc::ApplyResolution::default();
    };
    let resolution = resolve_fixed_apply(
        process,
        registers,
        arity as usize,
        return_ip,
        u64::from(stack_offset),
    );
    arm_apply_resolution(resolution)
}

/// ARM's variable-apply entry maps the shared erts export resolution to its branch pair.
// Port of erts/emulator/beam/beam_common.c:1434-1527 (`apply`), OTP-29.1.1.
#[cfg(target_arch = "aarch64")]
pub extern "C" fn arinsal_beamasm_apply3_resolver(
    header: *mut ProcessHeader,
    return_ip: u64,
    stack_offset: u32,
    reg: *mut u64,
) -> arinsal_beamasm::misc::ApplyResolution {
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(header, reg) else {
        return arinsal_beamasm::misc::ApplyResolution::default();
    };
    let resolution = resolve_apply(process, registers, return_ip, u64::from(stack_offset));
    arm_apply_resolution(resolution)
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
            if process.heap.reserve_native_halloc(0, alloc).is_none() {
                process.ensure_native_roots(alloc, &mut x[..live + 1]);
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
                    process.ensure_native_roots(heap_need, &mut x[..live + 1]);
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
                    process.ensure_native_roots(fresh_request, &mut x[..live + 1]);
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

/// Runs erts' checked private append and charges its writable-binary overhead on the process.
// Port of erts/emulator/beam/erl_bits.c:1928-2017 (`erts_bs_private_append_checked`), OTP-29.1.1.
pub(crate) fn bs_private_append_checked(
    process: &mut crate::Process,
    ebs: &mut [u64; 2],
    bin: u64,
    extra_bits: u64,
) -> u64 {
    let update = arinsal_term::erts_bs_private_append_checked_with_heap(
        ebs.as_mut_ptr(),
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
