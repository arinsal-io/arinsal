//! Native execution bridge and registered code metadata.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

/// Symbolic information attached to one executable native code range.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeFunction {
    /// Inclusive first byte of generated code.
    pub start: usize,
    /// Exclusive end of generated code.
    pub end: usize,
    /// Erlang module name.
    pub module: String,
    /// Erlang function name.
    pub function: String,
    /// Erlang function arity.
    pub arity: u8,
    /// Source line, when known.
    pub line: Option<u32>,
    /// Source file, when known.
    pub file: Option<String>,
}

fn native_functions() -> &'static RwLock<Vec<NativeFunction>> {
    static FUNCTIONS: OnceLock<RwLock<Vec<NativeFunction>>> = OnceLock::new();
    FUNCTIONS.get_or_init(|| RwLock::new(Vec::new()))
}

fn native_generation() -> &'static AtomicU64 {
    static GENERATION: AtomicU64 = AtomicU64::new(0);
    &GENERATION
}

fn register_bridge_continuation() -> Result<(), &'static str> {
    static REGISTERED: OnceLock<Result<(), &'static str>> = OnceLock::new();
    *REGISTERED.get_or_init(|| {
        let address = arinsal_beamasm::rt::arinsal_enter_native_return as *const () as usize;
        arinsal_term::register_native_code_range(address, address + 4)?;
        let trace_return =
            arinsal_beamasm::rt::arinsal_enter_native_trace_return as *const () as usize;
        arinsal_term::register_native_code_range(trace_return, trace_return + 4)
    })
}

pub(crate) fn native_trace_return_address() -> usize {
    arinsal_beamasm::rt::arinsal_enter_native_trace_return as *const () as usize
}

/// Register a native code range for GC continuation recognition and stack traces.
pub fn register_native_function(info: NativeFunction) -> Result<(), &'static str> {
    if info.start >= info.end {
        return Err("native code range must be non-empty");
    }
    let start = info.start;
    arinsal_term::register_native_code_range(info.start, info.end)?;
    let mut functions = native_functions()
        .write()
        .map_err(|_| "native function registry poisoned")?;
    if functions
        .iter()
        .any(|entry| info.start < entry.end && entry.start < info.end)
    {
        return Err("native function ranges must not overlap");
    }
    functions.push(info);
    functions.sort_unstable_by_key(|function| function.start);
    if std::env::var_os("ARINSAL_BEAMASM_LIFETIME").as_deref() == Some(std::ffi::OsStr::new("1")) {
        let function = functions
            .iter()
            .find(|function| function.start == start)
            .expect("registered native function is present");
        eprintln!(
            "[beamasm-lifetime] native register {}/{}:{} range={:#x}..{:#x}",
            function.module, function.function, function.arity, function.start, function.end
        );
    }
    native_generation().fetch_add(1, Ordering::Release);
    Ok(())
}

/// Unregisters native function entries when their owning module version is purged.
pub(crate) fn unregister_native_functions(entries: &[NativeFunction]) {
    let Ok(mut functions) = native_functions().write() else {
        return;
    };
    let before = functions.len();
    functions.retain(|registered| !entries.contains(registered));
    let removed = before - functions.len();
    if removed == 0 {
        return;
    }
    if std::env::var_os("ARINSAL_BEAMASM_LIFETIME").as_deref() == Some(std::ffi::OsStr::new("1")) {
        for entry in entries {
            eprintln!(
                "[beamasm-lifetime] native unregister {}/{}:{} range={:#x}..{:#x}",
                entry.module, entry.function, entry.arity, entry.start, entry.end
            );
        }
    }
    native_generation().fetch_add(1, Ordering::Release);
}

pub(crate) fn native_registry_generation() -> u64 {
    native_generation().load(Ordering::Acquire)
}

/// Runtime hook for native code to raise a BEAM exception through the scheduler.
/// Class values are 1 (`error`), 2 (`exit`), and 3 (`throw`).
///
/// # Safety
/// `header` must point to the active process header for the current native frame.
pub unsafe extern "C" fn arinsal_native_raise(header: *mut ProcessHeader, class: u64, reason: u64) {
    if header.is_null() || !(1..=3).contains(&class) {
        return;
    }
    // SAFETY: Native code passes the active ProcessHeader in x21 for this hook.
    let header = unsafe { &mut *header };
    header.freason = class;
    header.fvalue = reason;
}

/// Find metadata for a native instruction or continuation address.
pub fn native_function_at(address: usize) -> Option<NativeFunction> {
    let functions = native_functions().read().ok()?;
    let index = functions.partition_point(|function| function.start <= address);
    functions
        .get(index.checked_sub(1)?)
        .filter(|function| address < function.end)
        .cloned()
}

/// Test native code membership without cloning function metadata.
pub(crate) fn is_native_function_at(address: usize) -> bool {
    let Ok(functions) = native_functions().read() else {
        return false;
    };
    let index = functions.partition_point(|function| function.start <= address);
    let Some(function) = index.checked_sub(1).and_then(|index| functions.get(index)) else {
        return false;
    };
    address < function.end
}

fn native_arity_at(address: usize) -> Option<u8> {
    let functions = native_functions().read().ok()?;
    let index = functions.partition_point(|function| function.start <= address);
    functions
        .get(index.checked_sub(1)?)
        .filter(|function| address < function.end)
        .map(|function| function.arity)
}

pub(crate) fn native_function_for(
    module: &str,
    function: &str,
    arity: u8,
) -> Option<NativeFunction> {
    native_functions()
        .read()
        .ok()?
        .iter()
        .find(|entry| entry.module == module && entry.function == function && entry.arity == arity)
        .cloned()
}

/// Enter one native function and commit its ABI state before returning to the scheduler.
///
/// `CallUnported` returns to the scheduler with the interpreter target in `process.ip`;
/// a later native continuation is resumed by calling this function at its saved PC.
// Port of erts/emulator/beam/jit/arm/process_main.cpp:235-317, OTP-29.1.1
pub fn run_native(
    process: &mut Process,
    registers: &mut SchedulerRegisters,
    code_address: usize,
) -> Result<ExitReason, VmError> {
    register_bridge_continuation().map_err(|error| VmError::Unsupported(error.into()))?;
    let arity = native_arity_at(code_address).ok_or_else(|| {
        VmError::Unsupported(format!("unregistered native entry: {code_address:#x}"))
    })?;
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
    registers.tmp_mem[5] =
        crate::native_helpers::arinsal_beamasm_native_trace_return as *const () as usize as u64;
    process.ensure(1 + arinsal_term::CP_WORDS, arity as usize)?;
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
    let resuming_continuation = process
        .cold
        .as_mut()
        .is_some_and(|cold| std::mem::take(&mut cold.native_continuation_resume));
    if !resuming_continuation && !process.heap.reserve_stack(1) {
        return Err(VmError::Unsupported(
            "native bridge continuation stack is full".into(),
        ));
    }
    if !resuming_continuation {
        // This reserved bridge CP stays beneath the native frame CP. Tail calls
        // through the export trampoline add their interpreter-return CP above it.
        let bridge_cp = arinsal_beamasm::rt::arinsal_enter_native_return as *const () as usize;
        if !process
            .heap
            .stack_set(0, native_continuation_term(bridge_cp))
        {
            return Err(VmError::Unsupported(
                "native bridge continuation stack update failed".into(),
            ));
        }
    }
    let code_ptr = code_address as *const std::ffi::c_void;
    process.sync_header();
    process.header.i = code_ptr;
    process.header.arity = arity;
    let count = process.x.len().min(registers.x_reg_array.len());
    for (destination, term) in registers.x_reg_array[..count]
        .iter_mut()
        .zip(&process.x[..count])
    {
        // SAFETY: X register values are 64-bit tagged terms.
        *destination = unsafe { term.raw_bits() };
    }
    let float_count = process.fr.len().min(registers.f_reg_array.len());
    registers.f_reg_array[..float_count].copy_from_slice(&process.fr[..float_count]);
    let saved_ftrace = process.header.ftrace;
    process.header.ftrace = (registers as *mut SchedulerRegisters).cast();
    registers.tmp_mem[3] = 0;
    if std::env::var_os("ARINSAL_BEAMASM_LIFETIME").as_deref() == Some(std::ffi::OsStr::new("1")) {
        eprintln!(
            "[beamasm-lifetime] enter code={code_address:#x} owner={}",
            crate::beamasm_integration::owns_native_address(code_address)
        );
    }
    // Native hooks add their thread-local context setup here; keep this bridge
    // entry call structurally isolated from that setup.
    // SAFETY: The caller supplies a registered executable function using the BeamAsm ABI.
    let exit =
        unsafe { arinsal_beamasm::enter_native_raw(&mut process.header, registers, code_ptr) };
    process.header.ftrace = saved_ftrace;
    if matches!(exit, ExitReason::CallUnported { resume_pc, .. } if resume_pc != 0) {
        registers.x_reg_array[0] = registers.tmp_mem[0];
        registers.x_reg_array[1] = registers.tmp_mem[1];
    }
    process.heap.set_heap_top(process.header.htop);
    process.heap.set_stack_pointer(process.header.stop);
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
    process.reductions = process.header.fcalls;
    for (destination, raw) in process
        .x
        .iter_mut()
        .take(count)
        .zip(&registers.x_reg_array[..count])
    {
        // SAFETY: These words were loaded from the process's X register array.
        *destination = unsafe { Term::from_raw_bits(*raw) };
    }
    process.fr[..float_count].copy_from_slice(&registers.f_reg_array[..float_count]);
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:533-540, OTP-29.1.1.
    // A VM-backed light BIF leaves TRAP for the scheduler when it exits native code.
    let trapped_bif =
        process.header.freason == 1 << 10 && matches!(exit, ExitReason::CallUnported { .. });
    if trapped_bif {
        process.header.freason = 0;
    } else if process.header.freason != 0 {
        let class = process.header.freason;
        let reason = process.header.fvalue;
        return Err(VmError::Trap(exceptions::native_trap(class, reason)?));
    }
    let outcome = match exit {
        ExitReason::CallUnported { .. } => {
            process.native_pc = None;
            exit
        }
        ExitReason::Yield => {
            let resume = process.header.i as usize;
            let bridge_return =
                arinsal_beamasm::rt::arinsal_enter_native_return as *const () as usize;
            if resume == bridge_return {
                // The native function has returned into the bridge. Let the normal
                // return path pop this bridge CP and continue its interpreter caller.
                process.native_pc = None;
                ExitReason::Returned
            } else {
                process.cold_mut().native_continuation_resume = true;
                process.native_pc = Some(if resume == 0 {
                    code_ptr as usize
                } else {
                    resume
                });
                ExitReason::Yield
            }
        }
        ExitReason::Returned => {
            process.native_pc = None;
            ExitReason::Returned
        }
        ExitReason::Unsupported => {
            process.native_pc = None;
            ExitReason::Unsupported
        }
    };
    Ok(outcome)
}
