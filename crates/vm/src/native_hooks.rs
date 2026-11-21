//! Runtime callbacks used by BeamAsm slow paths.

use crate::Process;
use arinsal_arith::ArithError;
use arinsal_beamasm::{ProcessHeader, SchedulerRegisters};
#[cfg(target_arch = "aarch64")]
use arinsal_maps::MapError;
use arinsal_term::{Term, cmp, cmp_exact};
use num_traits::ToPrimitive;
use std::cmp::Ordering;

/// Runtime lookup for native map element instructions.
///
/// # Safety
/// The pointers must be the active process header and scheduler registers.
#[cfg(target_arch = "aarch64")]
pub extern "C" fn arinsal_beamasm_map_lookup(
    header: *mut ProcessHeader,
    _reg: *mut u64,
    map: u64,
    key: u64,
    _hash: u64,
    _hashed: u64,
) -> u64 {
    let Some(process) = enter_runtime(header) else {
        return 0;
    };
    match arinsal_maps::get(from_raw(map), from_raw(key)) {
        Ok(Some(value)) => raw(value),
        Ok(None) => 0,
        Err(MapError::Badmap(_)) => {
            set_error(process, "badmap");
            0
        }
        Err(_) => {
            set_error(process, "badarg");
            0
        }
    }
}

/// Reject an unsupported dynamic BIF entry as an Erlang `undef` exception.
///
/// # Safety
/// The pointers must refer to the active process header and scheduler registers.
#[cfg(target_arch = "aarch64")]
pub extern "C" fn arinsal_beamasm_bif_mfa(
    header: *mut ProcessHeader,
    _reg: *mut u64,
    _module: u64,
    _function: u64,
    _arity: u64,
) -> u64 {
    let Some(process) = enter_runtime(header) else {
        return 0;
    };
    set_error(process, "undef");
    0
}

/// The process of a helper called from native code that reads no X register.
// Port of erts/emulator/beam/jit/arm/beam_asm.hpp:460-540 (emit_enter_runtime stores HTOP/E/
// FCALLS into `c_p`), OTP-29.1.1. HTOP, E and FCALLS already live in `c_p` here
// (`ProcessHeap::abi`), so nothing is converted. A helper that needs the X registers takes
// `reg` from its fragment and enters through [`enter_runtime_reg`].
#[track_caller]
pub(crate) fn enter_runtime<'a>(header: *mut ProcessHeader) -> Option<&'a mut Process> {
    let process = process_from_header(header)?;
    // erts spills `c_p->mbuf` as the BIF starts (`live_hf_end`); every native helper enters here.
    process.heap.note_bif_entry();
    Some(process)
}

/// The process and the register array `reg` (`x19`, the scheduler's `x_reg_array`) a native
/// fragment passed, as erts passes `reg` to the runtime functions it calls with X registers
/// live (`load_x_reg_array(ARGn)`).
// Port of erts/emulator/beam/jit/arm/beam_asm.hpp:460-540 (emit_enter_runtime) and
// beam_asm.hpp (load_x_reg_array), OTP-29.1.1.
#[track_caller]
pub(crate) fn enter_runtime_reg<'a>(
    header: *mut ProcessHeader,
    reg: *mut u64,
) -> Option<(&'a mut Process, &'a mut SchedulerRegisters)> {
    let process = process_from_header(header)?;
    process.heap.note_bif_entry();
    // `reg` is the register file's `x_reg_array`, which the JIT register base points at.
    scheduler_registers_at(process, SchedulerRegisters::from_reg(reg))
}

/// [`enter_runtime_reg`] for the collection that follows a BIF: it must not take a new
/// `live_hf_end`, the one spilled before the BIF is still the one that counts.
pub(crate) fn enter_runtime_after_bif<'a>(
    header: *mut ProcessHeader,
    reg: *mut u64,
) -> Option<(&'a mut Process, &'a mut SchedulerRegisters)> {
    let process = process_from_header(header)?;
    scheduler_registers_at(process, SchedulerRegisters::from_reg(reg))
}

/// Records the call site of the running BIF (`I`) as `process.native_call_pc`. The call fragment
/// keeps it in the TMP_MEM of the register array `reg`, as erts' `call_light_bif_shared` keeps
/// `I` in TMP_MEM1q.
// Port of erts/emulator/beam/jit/arm/instr_bif.cpp:378-470 (call_light_bif_shared: `I` in
// TMP_MEM1q, passed as ARG3), OTP-29.1.1.
pub(crate) fn note_call_site(process: &mut Process, reg: *mut u64) {
    if let Some((process, registers)) =
        scheduler_registers_at(process, SchedulerRegisters::from_reg(reg))
    {
        process.native_call_pc = registers.tmp_mem[6] as usize;
    }
}

/// The process and the register file `reg` a native fragment passed (`esdp->registers`, which
/// erts hands to `handle_error` and the BIFs as `reg`).
pub(crate) fn scheduler_registers_at(
    process: &mut Process,
    registers: *mut SchedulerRegisters,
) -> Option<(&mut Process, &mut SchedulerRegisters)> {
    Some((process, registers_at(registers)?))
}

/// The scheduler register file at `registers` (`esdp->registers`), or `None` for null.
pub(crate) fn registers_at<'a>(
    registers: *mut SchedulerRegisters,
) -> Option<&'a mut SchedulerRegisters> {
    if registers.is_null() {
        return None;
    }
    // SAFETY: a non-null address is the register file of the running scheduler (a native
    // fragment's `reg`, or the executor's `esdp->registers` while it runs a process), which only
    // this scheduler touches and which stays in place for the call.
    Some(unsafe { &mut *registers })
}

#[cfg(all(debug_assertions, target_arch = "aarch64"))]
thread_local! {
    static HELPER_RING: std::cell::RefCell<std::collections::VecDeque<String>> =
        const { std::cell::RefCell::new(std::collections::VecDeque::new()) };
}

/// Debug aid: the last native helper entries of this thread, printed when the generated code's
/// cursor validation fails.
#[cfg(all(debug_assertions, target_arch = "aarch64"))]
pub(crate) extern "C" fn dump_helper_ring() {
    HELPER_RING.with(|ring| {
        for entry in ring.borrow().iter() {
            eprintln!("  helper {entry}");
        }
    });
}

#[track_caller]
pub(crate) fn process_from_header<'a>(header: *mut ProcessHeader) -> Option<&'a mut Process> {
    if header.is_null() {
        return None;
    }

    // SAFETY: ProcessHeader is the first repr(C) field of Process; native entry
    // passes the active process header for the duration of the helper call.
    let process = unsafe { &mut *header.cast::<Process>() };
    #[cfg(all(debug_assertions, target_arch = "aarch64"))]
    {
        let location = std::panic::Location::caller();
        let (htop, heap) = (process.heap.abi.htop, process.heap.abi.heap);
        HELPER_RING.with(|ring| {
            let mut ring = ring.borrow_mut();
            if ring.len() >= 6 {
                ring.pop_front();
            }
            ring.push_back(format!(
                "{}:{} htop={htop:p} heap={heap:p}",
                location.file(),
                location.line()
            ));
        });
        arinsal_beamasm::set_cursor_failure_hook(dump_helper_ring);
    }
    Some(process)
}

pub(crate) fn set_error(process: &mut Process, name: &str) {
    // `am_badarg` and the other built-in error atoms. Interning the reason on
    // every `persistent_term:get/1` miss took the atom-table lock.
    let term = crate::atom_cache::put(name);
    process.heap.abi.exc.freason = arinsal_beamasm::exc::EXC_ERROR;
    process.heap.abi.exc.fvalue = term.tagged_word();
}

pub(crate) fn raw(term: Term) -> u64 {
    // SAFETY: Every value crossing this hook ABI is a tagged BEAM term.
    unsafe { term.raw_bits() }
}

pub(crate) fn from_raw(raw: u64) -> Term {
    // SAFETY: The emitter passes tagged BEAM terms for term operands.
    unsafe { Term::from_raw_bits(raw) }
}

fn order_bits(order: Ordering) -> i32 {
    match order {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

/// Atom order. The shared fragment only calls this when both operands are atoms.
// Port of erts/emulator/beam/erl_utils.h:193 (erts_cmp_atoms), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_cmp_atoms(a: u64, b: u64) -> i32 {
    order_bits(cmp(from_raw(a), from_raw(b)))
}

/// Arithmetic term order (`exact == 0`) or exact term order. `eq_only` does not change the sign.
// Port of erts/emulator/beam/utils.c:1658 (erts_cmp_compound), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erts_cmp_compound(a: u64, b: u64, exact: i32, _eq_only: i32) -> isize {
    let left = from_raw(a);
    let right = from_raw(b);
    let order = if exact == 0 {
        cmp(left, right)
    } else {
        cmp_exact(left, right)
    };
    order_bits(order) as isize
}

/// Resolves a `bif.tab` utility BIF function to its stable export MFA.
// Port of erts/emulator/beam/beam_common.c:357-366 (ubif2mfa), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn ubif2mfa(function: *const core::ffi::c_void) -> *const arinsal_term::ErtsCodeMfa {
    let address = function as usize;
    for spec in arinsal_spec::BIFS
        .iter()
        .filter(|spec| spec.kind == arinsal_spec::BifKind::Ubif)
    {
        if crate::bif_table::function(i32::from(spec.index)) != address {
            continue;
        }
        if let Some(export) = crate::beamasm_integration::bif_mfa_export(
            spec.module,
            spec.name,
            u32::from(spec.arity),
        ) {
            return std::ptr::from_ref(export.mfa());
        }
    }
    std::process::abort()
}

/// Fun view for native ABI terms already recovered via [`from_raw`].
pub(crate) fn fun_view(term: Term) -> Option<arinsal_term::FunRef<'static>> {
    crate::raw::beam_common_ffi::fun_ref(term)
}

pub(crate) fn integer_float(term: Term) -> Result<f64, ArithError> {
    if let Some(value) = term.as_small() {
        return Ok(value as f64);
    }
    let owned = arinsal_term::to_owned(term).map_err(|_| ArithError::Badarith)?;
    match &owned {
        arinsal_etf::OwnedTerm::BigInt(value) => value
            .to_f64()
            .filter(|v| v.is_finite())
            .ok_or(ArithError::Badarith),
        arinsal_etf::OwnedTerm::Int(value) => Ok(*value as f64),
        _ => Err(ArithError::Badarith),
    }
}
