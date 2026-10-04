//! Native execution bridge and registered code metadata.

use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Symbolic information attached to one executable native code range.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeFunction {
    /// Code scope (node) the code belongs to; 0 registers it for every node.
    pub scope: u64,
    /// Inclusive first byte of generated code.
    pub start: usize,
    /// Exclusive end of generated code.
    pub end: usize,
    /// Erlang module name.
    pub module: String,
    /// Module atom resolved when the native function was registered.
    pub module_atom: arinsal_term::Atom,
    /// Erlang function name.
    pub function: String,
    /// Function atom resolved when the native function was registered.
    pub function_atom: arinsal_term::Atom,
    /// Erlang function arity.
    pub arity: u8,
    /// Source line, when known.
    pub line: Option<u32>,
    /// Source file, when known.
    pub file: Option<Arc<str>>,
    /// Cached literal filename list, when source location metadata is available.
    pub file_term: Option<Term>,
    /// Native PCs and their source locations, sorted by address.
    pub line_table: Vec<NativeLine>,
}

/// One native PC to source location mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeLine {
    /// Native address at which this source line becomes current.
    pub address: usize,
    /// Source filename.
    pub file: Arc<str>,
    /// Cached literal filename list from the owning BEAM module.
    pub file_term: Option<Term>,
    /// One-based source line.
    pub line: u32,
}

impl NativeFunction {
    /// Resolve a native return PC to the nearest preceding BEAM line marker.
    pub fn line_at(&self, address: usize) -> Option<(&str, u32)> {
        let index = self
            .line_table
            .partition_point(|entry| entry.address <= address)
            .checked_sub(1)?;
        // Line 0 marks a location erts cannot represent (LINE_INVALID_LOCATION).
        self.line_table
            .get(index)
            .filter(|entry| entry.line != 0)
            .map(|entry| (entry.file.as_ref(), entry.line))
    }
}

#[derive(Clone)]
pub(crate) struct NativeStackFrame {
    pub module_atom: arinsal_term::Atom,
    pub function_atom: arinsal_term::Atom,
    pub arity: u8,
    pub line: Option<u32>,
    pub file_term: Option<Term>,
    pub file: Option<Arc<str>>,
}

fn native_functions() -> &'static RwLock<Vec<NativeFunction>> {
    static FUNCTIONS: OnceLock<RwLock<Vec<NativeFunction>>> = OnceLock::new();
    FUNCTIONS.get_or_init(|| RwLock::new(Vec::new()))
}

fn native_generation() -> &'static AtomicU64 {
    static GENERATION: AtomicU64 = AtomicU64::new(0);
    &GENERATION
}

#[derive(Clone, Copy, Debug)]
enum CatchTarget {
    Native(usize),
    Interpreted { module: usize, ip: usize },
}

fn catch_table() -> &'static RwLock<std::collections::HashMap<u32, CatchTarget>> {
    static CATCHES: OnceLock<RwLock<std::collections::HashMap<u32, CatchTarget>>> = OnceLock::new();
    CATCHES.get_or_init(|| RwLock::new(std::collections::HashMap::new()))
}

/// Whether a stack word is a catch tag registered by native code (`catch`/`try` in a BeamAsm
/// frame), whose handler only `next_catch` can resolve.
pub(crate) fn is_native_catch_tag(word: Term) -> bool {
    let raw = word.tagged_word();
    raw & 63 == 0x1b
        && u32::try_from(raw >> 6).is_ok_and(|index| {
            catch_table()
                .read()
                .is_ok_and(|table| matches!(table.get(&index), Some(CatchTarget::Native(_))))
        })
}

pub(crate) fn register_native_catches(base: u32, handlers: &[*const u8]) -> Vec<u32> {
    let ids = (0..handlers.len())
        .filter_map(|offset| u32::try_from(offset).ok()?.checked_add(base))
        .collect::<Vec<_>>();
    if let Ok(mut catches) = catch_table().write() {
        for (&id, handler) in ids.iter().zip(handlers) {
            catches.insert(id, CatchTarget::Native(*handler as usize));
        }
    }
    ids
}

pub(crate) fn unregister_native_catches(ids: &[u32]) {
    if let Ok(mut catches) = catch_table().write() {
        for id in ids {
            catches.remove(id);
        }
    }
}

pub(crate) fn register_interpreted_catch(index: u32, module: usize, ip: usize) {
    if let Ok(mut catches) = catch_table().write() {
        catches.insert(index, CatchTarget::Interpreted { module, ip });
    }
}

pub(crate) fn interpreted_catch(index: u32) -> Option<(usize, usize)> {
    match catch_table().read().ok()?.get(&index).copied()? {
        CatchTarget::Interpreted { module, ip } => Some((module, ip)),
        CatchTarget::Native(_) => None,
    }
}

/// Native handler address of a catch-table index, if it names native code.
pub(crate) fn native_catch(index: u32) -> Option<usize> {
    match catch_table().read().ok()?.get(&index).copied()? {
        CatchTarget::Native(address) => Some(address),
        CatchTarget::Interpreted { .. } => None,
    }
}

pub(crate) enum CatchHandler {
    Native(usize),
    Interpreted,
}

pub(crate) fn next_catch(
    process: &mut Process,
    class: arinsal_bifs::Class,
    reason: Term,
    trace: Term,
) -> Option<CatchHandler> {
    if process.header.catches == 0 {
        return None;
    }
    let mut index = 0usize;
    let mut previous_cp = 0usize;
    let mut seen_cp = false;
    while index < process.heap.stack_words() {
        let word = process.heap.stack_get(index)?;
        let raw = word.tagged_word();
        let address = raw as usize;
        if address == native_trace_return_address() {
            let actions = process
                .heap
                .stack_get(index + 3)
                .and_then(Term::as_small)
                .and_then(|count| usize::try_from(count).ok())
                .unwrap_or(0);
            let words = 4usize.saturating_add(actions.saturating_mul(2));
            // The whole trace frame sits below the catching frame's Y slots.
            previous_cp = index + words - arinsal_term::CP_WORDS;
            seen_cp = true;
            index += words;
            continue;
        }
        if native_function_at(address).is_some() {
            previous_cp = index;
            seen_cp = true;
            index += arinsal_term::CP_WORDS;
            continue;
        }
        if raw & 63 == 0x1b
            && let Some(catch_index) = u32::try_from(raw >> 6).ok()
            && let Some(target) = catch_table().read().ok()?.get(&catch_index).copied()
        {
            process.heap.stack_set(index, Term::NIL);
            let base = process.heap.heap_cursor().1;
            // Both native and interpreted frames keep the caller-pushed CP above their Y slots
            // (a call pushes the CP, `allocate` then reserves the Y slots below it), so the
            // resumed E is the first Y slot after the last CP below the catch, or the stack top
            // when the catching frame is the topmost one.
            let resume = if seen_cp {
                previous_cp + arinsal_term::CP_WORDS
            } else {
                0
            };
            process.heap.set_stack_pointer(base.wrapping_add(resume));
            if process.x.len() < 4 {
                let mut registers = process.x.to_vec();
                registers.resize(4, Term::NIL);
                process.x = registers.into_boxed_slice();
            }
            // Port of erts/emulator/beam/beam_common.c:541-544 (handle_error), OTP-29.1.1:
            // x0 = non-value marker, x1 = reason, x2 = raw stacktrace, x3 = class.
            process.x[0] = Term::catch(0);
            let class_atom = match class {
                arinsal_bifs::Class::Error => crate::signals::atom("error"),
                arinsal_bifs::Class::Exit => crate::signals::atom("exit"),
                arinsal_bifs::Class::Throw => crate::signals::atom("throw"),
            };
            process.x[1] = reason;
            process.x[2] = trace;
            process.x[3] = class_atom;
            process.exc_class = Some(class);
            process.header.freason = 0;
            process.sync_native_header();
            return match target {
                CatchTarget::Native(handler) => {
                    process.cold_mut().native_continuation_resume = true;
                    process.cold_mut().native_resume_live = 5;
                    Some(CatchHandler::Native(handler))
                }
                CatchTarget::Interpreted { module, ip } => {
                    process.module = module;
                    process.ip = ip;
                    Some(CatchHandler::Interpreted)
                }
            };
        }
        if crate::stacktrace::decode_tag(word).is_some_and(|(handler, _, _)| !handler) {
            previous_cp = index;
            seen_cp = true;
            index += arinsal_term::CP_WORDS;
        } else {
            index += 1;
        }
    }
    None
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

pub(crate) fn native_continuation_return_address() -> usize {
    arinsal_beamasm::rt::arinsal_enter_native_return as *const () as usize
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
    // The registry stays sorted by start: only the neighbours can overlap.
    let index = functions.partition_point(|function| function.start < info.start);
    let overlaps_previous = index
        .checked_sub(1)
        .and_then(|previous| functions.get(previous))
        .is_some_and(|previous| info.start < previous.end);
    let overlaps_next = functions
        .get(index)
        .is_some_and(|next| next.start < info.end);
    if overlaps_previous || overlaps_next {
        return Err("native function ranges must not overlap");
    }
    functions.insert(index, info);
    if crate::native_bridge::lifetime_trace_enabled() {
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
    for entry in entries {
        arinsal_term::unregister_native_code_range(entry.start, entry.end);
    }
    let removed = before - functions.len();
    if removed == 0 {
        return;
    }
    if crate::native_bridge::lifetime_trace_enabled() {
        for entry in entries {
            eprintln!(
                "[beamasm-lifetime] native unregister {}/{}:{} range={:#x}..{:#x}",
                entry.module, entry.function, entry.arity, entry.start, entry.end
            );
        }
    }
    native_generation().fetch_add(1, Ordering::Release);
}

/// Unregisters scoped native entries when their owning VM code scope is released.
pub(crate) fn unregister_native_scope(scope: u64) {
    if scope == 0 {
        return;
    }
    let Ok(mut functions) = native_functions().write() else {
        return;
    };
    let mut removed = Vec::new();
    functions.retain(|function| {
        if function.scope == scope {
            removed.push((function.start, function.end));
            false
        } else {
            true
        }
    });
    for (start, end) in removed {
        arinsal_term::unregister_native_code_range(start, end);
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
    if !arinsal_term::may_be_native_code_pointer(address) {
        return None;
    }
    let functions = native_functions().read().ok()?;
    let index = functions.partition_point(|function| function.start <= address);
    functions
        .get(index.checked_sub(1)?)
        .filter(|function| address < function.end)
        .cloned()
}

/// Runs `visit` on the native function containing `address` without cloning its metadata.
/// `visit` runs under the registry read lock and must not register or unregister code.
pub(crate) fn with_native_function_at<R>(
    address: usize,
    visit: impl FnOnce(&NativeFunction) -> R,
) -> Option<R> {
    if !arinsal_term::may_be_native_code_pointer(address) {
        return None;
    }
    let functions = native_functions().read().ok()?;
    let index = functions.partition_point(|function| function.start <= address);
    functions
        .get(index.checked_sub(1)?)
        .filter(|function| address < function.end)
        .map(visit)
}

/// Test native code membership without cloning function metadata.
pub(crate) fn is_native_function_at(address: usize) -> bool {
    if !arinsal_term::may_be_native_code_pointer(address) {
        return false;
    }
    let Ok(functions) = native_functions().read() else {
        return false;
    };
    let index = functions.partition_point(|function| function.start <= address);
    let Some(function) = index.checked_sub(1).and_then(|index| functions.get(index)) else {
        return false;
    };
    address < function.end
}

/// A word the interpreter returns into by continuing native code: a native return address, or
/// the stub of a traced native function's return frame.
pub(crate) fn is_native_continuation(address: usize) -> bool {
    address == native_trace_return_address() || is_native_function_at(address)
}

pub(crate) fn native_stack_frame_at(address: usize) -> Option<NativeStackFrame> {
    if !arinsal_term::may_be_native_code_pointer(address) {
        return None;
    }
    let functions = native_functions().read().ok()?;
    let index = functions.partition_point(|function| function.start <= address);
    let function = functions
        .get(index.checked_sub(1)?)
        .filter(|function| address < function.end)?;
    let line = function
        .line_table
        .partition_point(|entry| entry.address <= address)
        .checked_sub(1)
        .and_then(|index| function.line_table.get(index))
        .filter(|entry| entry.line != 0);
    Some(NativeStackFrame {
        module_atom: function.module_atom,
        function_atom: function.function_atom,
        arity: function.arity,
        line: line.map(|entry| entry.line).or(function.line),
        file_term: line
            .and_then(|entry| entry.file_term)
            .or(function.file_term),
        file: line
            .map(|entry| Arc::clone(&entry.file))
            .or_else(|| function.file.clone()),
    })
}

fn native_arity_at(address: usize) -> Option<u8> {
    let functions = native_functions().read().ok()?;
    let index = functions.partition_point(|function| function.start <= address);
    functions
        .get(index.checked_sub(1)?)
        .filter(|function| address < function.end)
        .map(|function| function.arity)
}

/// Every registered native function of `module`, keyed by name and arity.
pub(crate) fn native_functions_of(
    scope: u64,
    module: &str,
) -> std::collections::HashMap<(String, u8), NativeFunction> {
    let Ok(functions) = native_functions().read() else {
        return std::collections::HashMap::new();
    };
    let mut scoped = functions
        .iter()
        .filter(|entry| entry.scope == scope && entry.module == module)
        .map(|entry| ((entry.function.clone(), entry.arity), entry.clone()))
        .collect::<std::collections::HashMap<_, _>>();
    if scope != 0 {
        for entry in functions
            .iter()
            .filter(|entry| entry.scope == 0 && entry.module == module)
        {
            scoped
                .entry((entry.function.clone(), entry.arity))
                .or_insert_with(|| entry.clone());
        }
    }
    scoped
}

pub(crate) fn native_function_for(
    scope: u64,
    module: &str,
    function: &str,
    arity: u8,
) -> Option<NativeFunction> {
    native_functions()
        .read()
        .ok()?
        .iter()
        .find(|entry| {
            (entry.scope == scope || entry.scope == 0)
                && entry.module == module
                && entry.function == function
                && entry.arity == arity
        })
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
    if crate::native_bridge::return_trace_enabled()
        && let Some(function) = native_function_at(code_address)
    {
        eprintln!(
            "[native-before-ensure] {}:{}/{} arity={arity} x0={:#x} E={:#x}",
            function.module,
            function.function,
            function.arity,
            process.x[0].tagged_word(),
            process.heap.frame_pointer()
        );
    }
    if let Some(cold) = process.cold.as_mut() {
        cold.native_error_pc = 0;
    }
    registers.tmp_mem[6] = 0;
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
    registers.tmp_mem[5] =
        crate::native_helpers::arinsal_beamasm_native_trace_return as *const () as usize as u64;
    let resuming_continuation = process
        .cold
        .as_mut()
        .is_some_and(|cold| std::mem::take(&mut cold.native_continuation_resume));
    // A resumed call return has only x0 live and an exception handler x0..x3, whatever
    // the arity of the function the native code belongs to.
    let resume_live = process
        .cold
        .as_mut()
        .map_or(0, |cold| std::mem::take(&mut cold.native_resume_live));
    let live = if resume_live == 0 {
        arity as usize
    } else {
        resume_live as usize - 1
    };
    process.ensure(
        1 + arinsal_term::S_RESERVED + arinsal_term::NATIVE_SPILL_WORDS,
        live,
    )?;
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
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
    if crate::native_bridge::return_trace_enabled()
        && let Some(function) = native_function_at(code_address)
    {
        eprintln!(
            "[native-enter] {}:{}/{} pc={code_address:#x} x0={:#x} E={:#x} freason={:#x}",
            function.module,
            function.function,
            function.arity,
            process.x[0].tagged_word(),
            process.heap.frame_pointer(),
            process.header.freason
        );
    }
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
    if let Some(cold) = process.cold.as_mut() {
        cold.native_bif_error = None;
    }
    let saved_ftrace = process.header.ftrace;
    process.header.ftrace = (registers as *mut SchedulerRegisters).cast();
    registers.tmp_mem[3] = 0;
    process.heap.set_native_allocation(true);
    if crate::native_bridge::lifetime_trace_enabled() {
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
    process.heap.set_native_allocation(false);
    let native_ftrace = process.header.ftrace as u64;
    process.header.ftrace = saved_ftrace;
    if crate::native_bridge::exception_trace_enabled() {
        let (base, end) = process.heap.heap_bounds();
        let (_, current_stop) = process.heap.heap_cursor();
        let requested_stop = process.header.stop as usize;
        if requested_stop < base as usize || requested_stop > end as usize {
            let module = native_function_at(code_address)
                .map_or_else(|| "?".to_owned(), |function| function.module);
            eprintln!(
                "native return stack pointer out of range module={} pc={code_address:#x} exit={exit:?} base={base:p} end={end:p} current_stop={current_stop:p} requested_stop={:#x} htop={:p}",
                module, requested_stop, process.header.htop
            );
        }
    }
    // Native returns may release stack slots and allocate into the newly freed gap.
    process.heap.set_stack_pointer(process.header.stop);
    process.heap.set_heap_top(process.header.htop);
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
    if crate::native_bridge::return_trace_enabled()
        && let Some(function) = native_function_at(code_address)
    {
        eprintln!(
            "[native-exit] {}:{}/{} pc={code_address:#x} exit={exit:?} x0={:#x} E={:#x} i={:p} stop={:p}",
            function.module,
            function.function,
            function.arity,
            process.x[0].tagged_word(),
            process.heap.frame_pointer(),
            process.header.i,
            process.header.stop
        );
    }
    process.fr[..float_count].copy_from_slice(&registers.f_reg_array[..float_count]);
    // Port of erts/emulator/beam/jit/arm/instr_bif.cpp:533-540, OTP-29.1.1.
    // A VM-backed light BIF leaves TRAP for the scheduler when it exits native code.
    // A call handed to the scheduler keeps its call site too, for a BIF that raises there.
    if process.header.freason != 0 || matches!(exit, ExitReason::CallUnported { .. }) {
        process.cold_mut().native_error_pc = registers.tmp_mem[6] as usize;
    }
    if process.header.freason != 0
        && process.header.freason != 1 << 10
        && crate::native_bridge::exception_trace_enabled()
    {
        eprintln!(
            "native exception freason={:#x} fvalue={:?} at {:?}",
            process.header.freason,
            arinsal_term::to_owned(crate::native_hooks::from_raw(process.header.fvalue))
                .map(|term| format!("{term}").chars().take(200).collect::<String>()),
            native_function_at(registers.tmp_mem[6] as usize).map(|function| format!(
                "{}:{}/{} +{:#x}",
                function.module,
                function.function,
                function.arity,
                registers.tmp_mem[6] as usize - function.start
            ))
        );
    }
    let trapped_bif =
        process.header.freason == 1 << 10 && matches!(exit, ExitReason::CallUnported { .. });
    if trapped_bif {
        process.header.freason = 0;
    } else if process.header.freason == arinsal_beamasm::module::EXC_FUNCTION_CLAUSE {
        // Port of erts/emulator/beam/beam_common.c (save_stacktrace, EXC_FUNCTION_CLAUSE):
        // the top frame carries the current function's arguments.
        process.header.freason = 0;
        let arity = native_function_at(registers.tmp_mem[6] as usize)
            .map_or(0, |function| usize::from(function.arity));
        let args = process.x[..arity.min(process.x.len())].to_vec();
        if crate::native_bridge::exception_trace_enabled() {
            eprintln!(
                "native function_clause in {:?} args={:?}",
                native_function_at(registers.tmp_mem[6] as usize)
                    .map(|f| format!("{}:{}/{}", f.module, f.function, f.arity)),
                args.iter()
                    .map(|arg| format!("{:#x}", arg.tagged_word()))
                    .collect::<Vec<_>>()
            );
        }
        let args = arinsal_term::TermBuilder::new(&mut crate::FragmentingHeap(&mut process.heap))
            .list_from_iter(args)
            .map_err(|error| VmError::Unsupported(format!("function_clause args {error:?}")))?;
        let mut trap = exceptions::native_trap(1, process.header.fvalue)?;
        trap.top = Some(crate::stacktrace::TopFrame::CurrentArgs(args));
        return Err(VmError::Trap(trap));
    } else if process.header.freason != 0
        && let Some(failure) = process
            .cold
            .as_mut()
            .and_then(|cold| cold.native_bif_error.take())
        && failure.freason == process.header.freason
        && failure.fvalue == process.header.fvalue
    {
        process.header.freason = 0;
        return Err(exceptions::bif_error(
            process,
            &failure.module,
            &failure.function,
            &failure.args,
            failure.error,
        ));
    } else if process.header.freason != 0 && registers.tmp_mem[7] != 0 {
        // Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp (emit_raise_badarg): an inline
        // BIF failure names the BIF, with its arguments from X0.., as the top frame.
        let slot = std::mem::take(&mut registers.tmp_mem[7]) as usize;
        let (module, function, arity) = arinsal_beamasm::guard::BADARG_MFAS[slot - 1];
        let args = process.x[..usize::from(arity)].to_vec();
        let error = if process.header.freason == arinsal_beamasm::guard::EXC_BADMAP {
            let value = crate::native_hooks::from_raw(process.header.fvalue);
            let reason =
                arinsal_term::TermBuilder::new(&mut crate::FragmentingHeap(&mut process.heap))
                    .tuple(&[crate::signals::atom("badmap"), value])
                    .map_err(|error| VmError::Unsupported(format!("badmap {error:?}")))?;
            arinsal_bifs::BifError::Error(reason)
        } else {
            arinsal_bifs::BifError::BADARG
        };
        process.header.freason = 0;
        return Err(exceptions::bif_error(
            process, module, function, &args, error,
        ));
    } else if process.header.freason
        & (arinsal_beamasm::catch::RAW_RAISE | arinsal_beamasm::catch::RERAISE)
        != 0
    {
        // Port of erts/emulator/beam/beam_common.c:1148-1178 (raw_raise) and the i_raise
        // instruction, OTP-29.1.1: both re-raise the stacktrace in `c_p->ftrace`.
        let raw_rethrow = process.header.freason & arinsal_beamasm::catch::RAW_RAISE != 0;
        let class = match process.header.freason & 3 {
            1 => arinsal_bifs::Class::Error,
            2 => arinsal_bifs::Class::Exit,
            _ => arinsal_bifs::Class::Throw,
        };
        process.header.freason = 0;
        let trace = crate::native_hooks::from_raw(native_ftrace);
        if raw_rethrow {
            // raw_raise stores the new class in the stacktrace too, so a later i_raise of
            // the same trace keeps it. The compiler only passes stacktraces here.
            crate::stacktrace::set_raw_class(process, trace, class);
        }
        return Err(VmError::Trap(exceptions::Trap {
            class,
            reason: crate::native_hooks::from_raw(process.header.fvalue),
            trace: Some(trace),
            top: None,
            raw_rethrow,
            untrappable: false,
        }));
    } else if process.header.freason > 3 && process.header.freason & 0x3ff == 0x50 {
        // Port of erts/emulator/beam/beam_common.c:742-775 (expand_error_value), OTP-29.1.1.
        let index = process.header.freason >> 10;
        process.header.freason = 0;
        let value = crate::native_hooks::from_raw(process.header.fvalue);
        let tag = match index {
            5 => "badmatch",
            7 => "case_clause",
            8 => "if_clause",
            16 => "try_clause",
            20 => "badrecord",
            _ => {
                return Err(VmError::Unsupported(format!(
                    "native exception index {index}"
                )));
            }
        };
        let tag = crate::signals::atom(tag);
        let reason = if index == 8 {
            tag
        } else {
            arinsal_term::TermBuilder::new(&mut crate::FragmentingHeap(&mut process.heap))
                .tuple(&[tag, value])
                .map_err(|error| VmError::Unsupported(format!("error value {error:?}")))?
        };
        return Err(VmError::Trap(exceptions::native_trap(
            1,
            crate::native_hooks::raw(reason),
        )?));
    } else if process.header.freason != 0 {
        let class = process.header.freason;
        let reason = process.header.fvalue;
        let mut trap = exceptions::native_trap(class, reason)?;
        if let Some(info) = process
            .cold
            .as_mut()
            .and_then(|cold| cold.native_error_info.take())
        {
            let arity = native_function_at(registers.tmp_mem[6] as usize)
                .map_or(0, |function| i64::from(function.arity));
            trap.top = Some(crate::stacktrace::TopFrame::CurrentArgsWithInfo(
                Term::small(arity),
                info,
            ));
        }
        return Err(VmError::Trap(trap));
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
                // The yield site stored its live X register count in `c_p->arity`.
                process.cold_mut().native_resume_live = process.header.arity.saturating_add(1);
                // Signal-time GC while switched out roots exactly these registers.
                process.gc_live = usize::from(process.header.arity);
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

fn env_flag(cell: &'static OnceLock<bool>, name: &str, test: fn(&std::ffi::OsStr) -> bool) -> bool {
    *cell.get_or_init(|| std::env::var_os(name).is_some_and(|value| test(&value)))
}

/// `ARINSAL_BEAMASM_RETURN_TRACE`: log native entries and exits.
pub(crate) fn return_trace_enabled() -> bool {
    static FLAG: OnceLock<bool> = OnceLock::new();
    env_flag(&FLAG, "ARINSAL_BEAMASM_RETURN_TRACE", |_| true)
}

/// `ARINSAL_BEAMASM_EXCEPTION_TRACE`: log native exceptions.
pub(crate) fn exception_trace_enabled() -> bool {
    static FLAG: OnceLock<bool> = OnceLock::new();
    env_flag(&FLAG, "ARINSAL_BEAMASM_EXCEPTION_TRACE", |_| true)
}

/// `ARINSAL_BEAMASM_LIFETIME=1`: log native code memory lifetimes.
pub(crate) fn lifetime_trace_enabled() -> bool {
    static FLAG: OnceLock<bool> = OnceLock::new();
    env_flag(&FLAG, "ARINSAL_BEAMASM_LIFETIME", |value| value == "1")
}
