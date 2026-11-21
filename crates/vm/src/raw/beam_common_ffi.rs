//! Pointer operations for runtime symbols ported from OTP's C ABI.
// Port of erts/emulator/beam/erl_vm.h (Eterm pointer access) and beam_common.c,
// OTP-29.1.1.

use arinsal_beamasm::ProcessHeader;

/// Scans the RA-layout Erlang stack from `E` to `STACK_START(p)` and returns the first
/// continuation address outside a trace frame.
// Port of erts/emulator/beam/beam_common.c:413-435 (`erts_printable_return_address`),
// OTP-29.1.1.
pub(crate) fn printable_return_address(p: *const ProcessHeader, e: *const u64) -> usize {
    if p.is_null() || e.is_null() {
        return 0;
    }
    // SAFETY: the runtime symbol receives the active process header; `hend` is `STACK_START(p)`.
    let stack_bottom = unsafe { (*p).hend };
    if stack_bottom.is_null() || e.addr() >= stack_bottom.addr() {
        return 0;
    }

    let mut scanner = e;
    debug_assert!(arinsal_term::is_cp(read_word(scanner, 0)));
    while scanner.addr() < stack_bottom.addr() {
        // `erts_inspect_frame` in the RA layout reads the CP at frame[0].
        let return_address = read_word(scanner, 0) as usize;
        debug_assert!(arinsal_term::is_cp(return_address as u64));
        if let Some(kind) = crate::trace::TraceFrameKind::of(return_address) {
            scanner = scanner.wrapping_add(arinsal_term::CP_WORDS + kind.data_words());
        } else {
            return return_address;
        }
    }

    debug_assert!(false, "No continuation pointer on the process stack");
    0
}

/// `void copy_in_registers(Process *c_p, Eterm *reg)`: process_main's schedule-in load of
/// the saved argument registers into the scheduler's register array (`schedule_next`).
// Port of erts/emulator/beam/beam_common.c:336 (copy_in_registers), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn copy_in_registers(c_p: *mut ProcessHeader, reg: *mut u64) {
    let process = crate::native_hooks::process_from_header(c_p)
        .expect("copy_in_registers: c_p is the process erts_schedule returned");
    let registers =
        crate::native_hooks::registers_at(arinsal_beamasm::SchedulerRegisters::from_reg(reg))
            .expect("copy_in_registers: reg is esdp->registers->x_reg_array");
    crate::beam_common::copy_in_registers(process, registers);
}

/// `void copy_out_registers(Process *c_p, Eterm *reg)`: process_main's schedule-out save of
/// the `c_p->arity` live registers (`context_switch_simplified`).
// Port of erts/emulator/beam/beam_common.c:306-334 (copy_out_registers), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn copy_out_registers(c_p: *mut ProcessHeader, reg: *mut u64) {
    let (Some(process), Some(registers)) = (
        crate::native_hooks::process_from_header(c_p),
        crate::native_hooks::registers_at(arinsal_beamasm::SchedulerRegisters::from_reg(reg)),
    ) else {
        return;
    };
    crate::beam_common::copy_out_registers(process, &registers.x_reg_array);
}

/// Starts the hibernate scheduler handoff for the live register range.
// Port of erts/emulator/beam/beam_common.c:1568-1600 (`erts_hibernate`), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_hibernate(c_p: *mut ProcessHeader, regs: *mut u64, arity: i32) {
    let (Ok(arity), Some((process, registers))) = (
        usize::try_from(arity),
        crate::native_hooks::enter_runtime_reg(c_p, regs),
    ) else {
        return;
    };
    let Some(live_registers) = registers.x_reg_array.get(..arity) else {
        return;
    };
    let current_mfa =
        code_mfa(process.heap.abi.current as usize as u64).and_then(|(module, function, arity)| {
            Some((
                arinsal_term::global_atoms().text(module)?.to_owned(),
                arinsal_term::global_atoms().text(function)?.to_owned(),
                arity,
            ))
        });
    crate::process::begin_hibernate(process, live_registers, true, current_mfa);
}

/// Implements the x86 BeamAsm `apply` C ABI through the shared apply resolver.
// Port of erts/emulator/beam/beam_common.c:1434-1527 (`apply`), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn apply(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    return_ip: *const core::ffi::c_void,
    stack_offset: u64,
) -> *const arinsal_term::ExportEntry {
    let Some((process, registers)) = crate::native_hooks::enter_runtime_reg(c_p, reg) else {
        return core::ptr::null();
    };
    crate::native_helpers::resolve_apply(
        process,
        registers,
        return_ip as usize as u64,
        stack_offset,
    )
    .map_or(core::ptr::null(), |target| target.export)
}

/// Implements the x86 BeamAsm fixed-arity apply C ABI through the shared resolver.
// Port of erts/emulator/beam/beam_common.c:1529-1566 (`fixed_apply`), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn fixed_apply(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    arity: u64,
    return_ip: *const core::ffi::c_void,
    stack_offset: u64,
) -> *const arinsal_term::ExportEntry {
    let (Ok(arity), Some((process, registers))) = (
        usize::try_from(arity),
        crate::native_hooks::enter_runtime_reg(c_p, reg),
    ) else {
        return core::ptr::null();
    };
    crate::native_helpers::resolve_fixed_apply(
        process,
        registers,
        arity,
        return_ip as usize as u64,
        stack_offset,
    )
    .map_or(core::ptr::null(), |target| target.export)
}

/// Reads a caller-owned word at `index`.
pub(crate) fn read_word(words: *const u64, index: usize) -> u64 {
    // SAFETY: generated BeamAsm operations pass aligned operand, X-register, or stack arrays;
    // their encoded indexes name live words for the duration of this runtime call.
    unsafe { words.add(index).read() }
}

/// Reads a caller-owned word at `index`, or returns `None` for a null table.
pub(crate) fn read_optional_word(words: *const u64, index: usize) -> Option<u64> {
    (!words.is_null()).then(|| read_word(words, index))
}

/// Writes one caller-owned Eterm slot, returning false when the output is null.
pub(crate) fn write_word(output: *mut u64, value: u64) -> bool {
    if output.is_null() {
        return false;
    }
    // SAFETY: the runtime symbol's C ABI contract supplies one writable Eterm output slot.
    unsafe { output.write(value) };
    true
}

/// Attaches the process X file to the scheduler's register array for the current slice.
// Port of erts/emulator/beam/beam_common.c (copy_in_registers), OTP-29.1.1.
pub(crate) fn attach_process_registers(
    process: &mut crate::Process,
    registers: &mut arinsal_beamasm::SchedulerRegisters,
) {
    // SAFETY: the scheduler owns `registers` at a stable address for this process's slice and
    // calls `copy_out_registers` before scheduling it out, matching the attach/detach lifetime.
    unsafe { process.x.attach(registers) };
}

/// Gives a runtime root range to a closure while keeping its raw-pointer borrow local.
pub(crate) fn with_mut_terms<R>(
    words: *mut u64,
    len: usize,
    body: impl FnOnce(&mut [arinsal_term::Term]) -> R,
) -> Option<R> {
    if len == 0 {
        return Some(body(&mut []));
    }
    if words.is_null() {
        return None;
    }
    // SAFETY: `erts_garbage_collect_nobump` receives `objv` and `nobj` from generated code; the
    // live register array contains `nobj` aligned, writable Eterm slots throughout collection.
    Some(body(unsafe {
        std::slice::from_raw_parts_mut(words.cast::<arinsal_term::Term>(), len)
    }))
}

/// Copies the stable MFA fields from an export entry supplied to `save_calls`.
// Port of erts/emulator/beam/export.h (`Export.info.mfa`), OTP-29.1.1.
pub(crate) fn export_mfa(address: usize) -> Option<(arinsal_term::Atom, arinsal_term::Atom, u32)> {
    if address == 0 {
        return None;
    }
    // SAFETY: `save_calls` receives an Export pointer whose code index keeps the entry stable
    // while its address is copied into this process's saved-calls ring.
    let export = unsafe { &*(address as *const arinsal_term::ExportEntry) };
    let mfa = &export.info.mfa;
    Some((
        crate::native_hooks::from_raw(mfa.module).as_atom()?,
        crate::native_hooks::from_raw(mfa.function).as_atom()?,
        mfa.arity as u32,
    ))
}

/// Reads the `ErtsCodeMFA` at `info`: the `bif_mfa` that `handle_error` and the BIF error
/// paths receive from native code (`Export.info.mfa` or a file-static MFA of instr_*.cpp).
// Port of erts/emulator/beam/beam_common.c (handle_error, save_stacktrace read `bif_mfa`),
// OTP-29.1.1.
pub(crate) fn code_mfa(info: u64) -> Option<(arinsal_term::Atom, arinsal_term::Atom, u32)> {
    let info = usize::try_from(info).ok()?;
    if info == 0 || !info.is_multiple_of(core::mem::align_of::<arinsal_term::ErtsCodeMfa>()) {
        return None;
    }
    // SAFETY: native code passes only live `ErtsCodeMfa`s: an export MFA kept by its code index,
    // a static emitter MFA, or `c_p->current` pointing at the active `ErtsCodeInfo.mfa`.
    let mfa = unsafe { (info as *const arinsal_term::ErtsCodeMfa).read() };
    Some((
        crate::native_hooks::from_raw(mfa.module).as_atom()?,
        crate::native_hooks::from_raw(mfa.function).as_atom()?,
        mfa.arity as u32,
    ))
}

/// The fun view of a term native code handed to the runtime; the process heap holding it is
/// live for the whole runtime call.
pub(crate) fn fun_ref(term: arinsal_term::Term) -> Option<arinsal_term::FunRef<'static>> {
    // SAFETY: the term comes from a live process heap (registers, stack or message) that is
    // not collected while the runtime function borrowing the view runs.
    unsafe { term.fun_ref() }
}
