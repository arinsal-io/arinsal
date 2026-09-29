//! Runtime callbacks used by BeamAsm slow paths.

use crate::{Process, VmError};
use arinsal_arith::{ArithError, ArithResult};
use arinsal_beamasm::{ProcessHeader, SchedulerRegisters};
use arinsal_maps::MapError;
use arinsal_term::{Term, TermBuilder, TermKind, cmp, exact_eq, global_atoms, loose_eq};
use num_traits::ToPrimitive;
use std::cmp::Ordering;

const NATIVE_X: usize = 6;

/// Runtime lookup for native map element instructions.
///
/// # Safety
/// The pointers must be the active process header and scheduler registers.
pub extern "C" fn arinsal_beamasm_map_lookup(
    header: *mut ProcessHeader,
    _registers: *mut SchedulerRegisters,
    map: u64,
    key: u64,
    _hash: u64,
    _hashed: u64,
) -> u64 {
    let Some((process, registers)) = process_and_registers(header) else {
        return 0;
    };
    match arinsal_maps::get(from_raw(map), from_raw(key)) {
        Ok(Some(value)) => raw(value),
        Ok(None) => 0,
        Err(MapError::Badmap(_)) => {
            set_error(process, "badmap");
            publish_x(process, registers);
            process.sync_native_header();
            0
        }
        Err(_) => {
            set_error(process, "badarg");
            publish_x(process, registers);
            process.sync_native_header();
            0
        }
    }
}

/// Runtime tuple tag and arity check used by native guard instructions.
///
/// # Safety
/// `header` must be the active process header with its live scheduler registers.
pub extern "C" fn arinsal_beamasm_guard3(
    header: *mut ProcessHeader,
    _op: u32,
    tuple: u64,
    arity: u64,
    tag: u64,
) -> u64 {
    let _ = (header, tuple, arity, tag);
    0
}

/// Reject an unsupported dynamic BIF entry as an Erlang `undef` exception.
///
/// # Safety
/// The pointers must refer to the active process header and scheduler registers.
pub extern "C" fn arinsal_beamasm_bif_mfa(
    header: *mut ProcessHeader,
    _registers: *mut SchedulerRegisters,
    _module: u64,
    _function: u64,
    _arity: u64,
) -> u64 {
    let Some((process, registers)) = process_and_registers(header) else {
        return 0;
    };
    set_error(process, "undef");
    publish_x(process, registers);
    process.sync_native_header();
    0
}

pub(crate) fn process_and_registers<'a>(
    header: *mut ProcessHeader,
) -> Option<(&'a mut Process, &'a mut SchedulerRegisters)> {
    if header.is_null() {
        return None;
    }
    // SAFETY: ProcessHeader is the first repr(C) field of Process; native entry
    // publishes a live scheduler register pointer for the duration of the call.
    let process = unsafe { &mut *header.cast::<Process>() };
    // Rust helpers may allocate or publish the header again, so first commit the
    // native heap and stack cursors that generated code flushed at the call site.
    process.heap.set_heap_top(process.header.htop);
    process.heap.set_stack_pointer(process.header.stop);
    let registers = process.header.ftrace.cast::<SchedulerRegisters>();
    if registers.is_null() {
        return None;
    }
    // SAFETY: run_native keeps its scheduler register area exclusively borrowed
    // while native code and its synchronous hooks are executing.
    let registers = unsafe { &mut *registers };
    for (destination, raw) in process
        .x
        .iter_mut()
        .take(NATIVE_X)
        .zip(&registers.x_reg_array)
    {
        // SAFETY: The native ABI register array contains tagged BEAM terms.
        *destination = unsafe { Term::from_raw_bits(*raw) };
    }
    Some((process, registers))
}

fn publish_x(process: &Process, registers: &mut SchedulerRegisters) {
    for (destination, term) in registers
        .x_reg_array
        .iter_mut()
        .zip(process.x.iter())
        .take(NATIVE_X)
    {
        // SAFETY: X registers contain tagged BEAM terms.
        *destination = unsafe { term.raw_bits() };
    }
}

pub(crate) fn set_error(process: &mut Process, name: &str) {
    if let Ok(atom) = global_atoms().intern(name) {
        process.header.freason = 1;
        // SAFETY: Atom terms are immediate values with no heap lifetime.
        process.header.fvalue = unsafe { Term::atom(atom).raw_bits() };
    }
}

pub(crate) fn raw(term: Term) -> u64 {
    // SAFETY: Every value crossing this hook ABI is a tagged BEAM term.
    unsafe { term.raw_bits() }
}

pub(crate) fn from_raw(raw: u64) -> Term {
    // SAFETY: The emitter passes tagged BEAM terms for term operands.
    unsafe { Term::from_raw_bits(raw) }
}

/// Fun view for native ABI terms already recovered via [`from_raw`].
pub(crate) fn fun_view(term: Term) -> Option<arinsal_term::FunRef<'static>> {
    arinsal_beamasm::rt::fun_ref(term)
}

fn ensure_native_frame(
    process: &mut Process,
    registers: &mut SchedulerRegisters,
    words: usize,
    live: usize,
) -> Result<(), VmError> {
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
    let result = process.ensure(words, live);
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
    result
}

fn with_alloc_retry(
    process: &mut Process,
    registers: &mut SchedulerRegisters,
    lhs: Term,
    rhs: Term,
    mut operation: impl FnMut(Term, Term, &mut arinsal_term::ProcessHeap) -> ArithResult,
) -> Result<Term, ArithError> {
    let len = process.x.len();
    if len < NATIVE_X + 2 {
        return Err(ArithError::SystemLimit);
    }
    let saved_live = process.gc_live;
    let left_root = saved_live.max(NATIVE_X).min(len - 2);
    let right_root = left_root + 1;
    let root_count = right_root + 1;
    process.x[left_root] = lhs;
    process.x[right_root] = rhs;
    loop {
        ensure_native_frame(process, registers, 0, root_count).map_err(|_| {
            process.gc_live = saved_live;
            ArithError::SystemLimit
        })?;
        let left = process.x[left_root];
        let right = process.x[right_root];
        match operation(left, right, &mut process.heap) {
            Err(ArithError::HeapFull { need_words }) => {
                if ensure_native_frame(process, registers, need_words, root_count).is_err() {
                    process.gc_live = saved_live;
                    return Err(ArithError::SystemLimit);
                }
            }
            result => {
                process.gc_live = saved_live;
                return result;
            }
        }
    }
}

/// Arithmetic and float slow path. Returns an OTP term, except float-register
/// operations (16, 18-23), whose payload is an IEEE-754 word.
// Port of erts/emulator/beam/jit/arm/instr_arith.cpp:145-1771, OTP-29.1.1.
///
/// # Safety
/// `header` must be the active `ProcessHeader` and publish the live scheduler
/// register area for the current native frame.
pub unsafe extern "C" fn arinsal_beamasm_arith(
    header: *mut ProcessHeader,
    op: u32,
    lhs: u64,
    rhs: u64,
) -> u64 {
    let Some((process, registers)) = process_and_registers(header) else {
        return 0;
    };
    let left = from_raw(lhs);
    let right = from_raw(rhs);
    let operation = match op {
        0 => Some(("+", &[left, right][..])),
        1 => Some(("-", &[left, right][..])),
        2 => Some(("*", &[left, right][..])),
        3 => Some(("div", &[left, right][..])),
        4 => Some(("rem", &[left, right][..])),
        5 => Some(("band", &[left, right][..])),
        6 => Some(("bor", &[left, right][..])),
        7 => Some(("bxor", &[left, right][..])),
        8 => Some(("bnot", &[left][..])),
        9 => Some(("-", &[left][..])),
        10 => Some(("bsl", &[left, right][..])),
        11 => Some(("bsr", &[left, right][..])),
        _ => None,
    };
    if let Some((operation, args)) = operation {
        let charge = arinsal_arith::reduction_charge(operation, args);
        process.reductions_used = process.reductions_used.saturating_add(u64::from(charge));
        process.reductions = process
            .reductions
            .saturating_sub(charge.min(i32::MAX as u32) as i32);
    }
    let result = match op {
        16 => float_value(left)
            .map(f64::to_bits)
            .ok_or(ArithError::Badarith),
        18 => integer_float(left).map(f64::to_bits),
        19..=22 => {
            let (a, b) = (f64::from_bits(lhs), f64::from_bits(rhs));
            let value = match op {
                19 => a + b,
                20 => a - b,
                21 => a * b,
                _ => a / b,
            };
            if value.is_finite() {
                Ok(value.to_bits())
            } else {
                Err(ArithError::Badarith)
            }
        }
        23 => {
            let value = -f64::from_bits(lhs);
            if value.is_finite() {
                Ok(value.to_bits())
            } else {
                Err(ArithError::Badarith)
            }
        }
        17 => with_alloc_retry(process, registers, Term::NIL, Term::NIL, |_, _, heap| {
            TermBuilder::new(heap)
                .float(f64::from_bits(lhs))
                .map_err(|_| ArithError::HeapFull { need_words: 2 })
        })
        .map(raw),
        0..=11 => with_alloc_retry(process, registers, left, right, |a, b, heap| match op {
            0 => arinsal_arith::add(a, b, heap),
            1 => arinsal_arith::sub(a, b, heap),
            2 => arinsal_arith::mul(a, b, heap),
            3 => arinsal_arith::int_div(a, b, heap),
            4 => arinsal_arith::rem(a, b, heap),
            5 => arinsal_arith::band(a, b, heap),
            6 => arinsal_arith::bor(a, b, heap),
            7 => arinsal_arith::bxor(a, b, heap),
            8 => arinsal_arith::bnot(a, heap),
            9 => arinsal_arith::neg(a, heap),
            10 => arinsal_arith::bsl(a, b, heap),
            _ => arinsal_arith::bsr(a, b, heap),
        })
        .map(raw),
        _ => Err(ArithError::Badarith),
    };
    let answer = match result {
        Ok(value) => value,
        Err(ArithError::HeapFull { .. } | ArithError::SystemLimit) => {
            set_error(process, "system_limit");
            0
        }
        Err(ArithError::Badarith | ArithError::Badarg) => {
            set_error(process, "badarith");
            0
        }
    };
    publish_x(process, registers);
    process.sync_native_header();
    answer
}

fn float_value(term: Term) -> Option<f64> {
    // SAFETY: The float header identifies a live boxed float in this process.
    (term.classify() == TermKind::Number)
        .then(|| unsafe { term.float_ref() }.map(|v| v.get()))
        .flatten()
}

fn integer_float(term: Term) -> Result<f64, ArithError> {
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

/// General term comparison/equality and map guard operations.
// Port of erts/emulator/beam/jit/arm/instr_common.cpp:200-600 and instr_guard_bifs.cpp:1-1364, OTP-29.1.1.
///
/// # Safety
/// `header` must be the active `ProcessHeader` and publish the live scheduler
/// register area for the current native frame.
pub unsafe extern "C" fn arinsal_beamasm_guard(
    header: *mut ProcessHeader,
    op: u32,
    first: u64,
    second: u64,
) -> u64 {
    let Some((process, registers)) = process_and_registers(header) else {
        return 0;
    };
    let a = from_raw(first);
    let b = from_raw(second);
    let answer = match op {
        19 => u64::from(exact_eq(a, b)),
        20 => u64::from(!exact_eq(a, b)),
        21 => u64::from(loose_eq(a, b)),
        22 => u64::from(!loose_eq(a, b)),
        23 => u64::from(cmp(a, b) == Ordering::Less),
        24 => u64::from(cmp(a, b) != Ordering::Less),
        25 => {
            let index = a
                .as_small()
                .and_then(|i| i.checked_sub(1))
                .and_then(|i| usize::try_from(i).ok());
            index
                .and_then(|i| {
                    // SAFETY: tuple_ref validates the tagged term and its live heap header.
                    unsafe { b.tuple_ref() }.and_then(|tuple| tuple.get(i))
                })
                .map(raw)
                .unwrap_or_else(|| {
                    set_error(process, "badarg");
                    0
                })
        }
        26 | 27 => {
            // SAFETY: cons_ref validates the tagged term before reading its two words.
            unsafe { a.cons_ref() }
                .map(|(head, tail)| raw(if op == 26 { head } else { tail }))
                .unwrap_or_else(|| {
                    set_error(process, "badarg");
                    0
                })
        }
        28 => tuple_size(a)
            .and_then(|size| Term::small(size as i64))
            .map(raw)
            .unwrap_or_else(|| {
                set_error(process, "badarg");
                0
            }),
        29 => arinsal_maps::size(a)
            .ok()
            .and_then(|size| Term::small(size as i64))
            .map(raw)
            .unwrap_or_else(|| {
                set_error(process, "badmap");
                0
            }),
        30 => u64::from(arinsal_maps::is_key(b, a).unwrap_or(false)),
        31 => match arinsal_maps::get(b, a) {
            Ok(Some(value)) => raw(value),
            Ok(None) => {
                set_error(process, "badkey");
                0
            }
            Err(MapError::Badmap(_)) => {
                set_error(process, "badmap");
                0
            }
            Err(_) => {
                set_error(process, "badarg");
                0
            }
        },
        32 | 33 => binary_size(a, op == 33)
            .and_then(|size| Term::small(size as i64))
            .map(raw)
            .unwrap_or_else(|| {
                set_error(process, "badarg");
                0
            }),
        34 => process.header.self_pid,
        35 => list_length(a)
            .and_then(|size| Term::small(size as i64))
            .map(raw)
            .unwrap_or_else(|| {
                set_error(process, "badarg");
                0
            }),
        36 | 37 => raw(if (cmp(a, b) == Ordering::Greater) == (op == 36) {
            b
        } else {
            a
        }),
        38 => match with_alloc_retry(process, registers, a, Term::NIL, |value, _, heap| {
            arinsal_arith::abs(value, heap)
        }) {
            Ok(value) => raw(value),
            Err(ArithError::HeapFull { .. } | ArithError::SystemLimit) => {
                set_error(process, "system_limit");
                0
            }
            Err(_) => {
                set_error(process, "badarg");
                0
            }
        },
        39 => global_atoms()
            .intern("nonode@nohost")
            .map(Term::atom)
            .map(raw)
            .unwrap_or(0),
        _ => 0,
    };
    publish_x(process, registers);
    process.sync_native_header();
    answer
}

fn tuple_size(term: Term) -> Option<usize> {
    // SAFETY: tuple_ref validates the tagged term before exposing its header.
    unsafe { term.tuple_ref() }.map(|tuple| tuple.len())
}

fn binary_size(term: Term, bits: bool) -> Option<usize> {
    // SAFETY: binary_ref validates the tagged term before exposing its bitstring.
    let length = unsafe { term.binary_ref() }?.bit_len();
    if bits {
        Some(length)
    } else if length.is_multiple_of(8) {
        Some(length / 8)
    } else {
        None
    }
}

fn list_length(mut list: Term) -> Option<usize> {
    let mut length = 0_usize;
    loop {
        if list == Term::NIL {
            return Some(length);
        }
        // SAFETY: cons_ref validates each list link before reading it.
        let (_, tail) = unsafe { list.cons_ref() }?;
        length = length.checked_add(1)?;
        list = tail;
    }
}

/// Heap slow path used by `test_heap` and heap allocation emitters.
// Port of erts/emulator/beam/jit/arm/instr_common.cpp:90-122 and beam_asm_global.cpp:102-140, OTP-29.1.1.
///
/// # Safety
/// `header` and `registers` must be the active process and scheduler register
/// pointers supplied by generated BeamAsm code.
pub unsafe extern "C" fn arinsal_beamasm_gc(
    header: *mut ProcessHeader,
    registers: *mut SchedulerRegisters,
    need_words: usize,
    live: usize,
    _fcalls: i32,
) -> i32 {
    if header.is_null() || registers.is_null() {
        return 0;
    }
    // SAFETY: ProcessHeader is at offset zero and both pointers are published by the native bridge.
    let process = unsafe { &mut *header.cast::<Process>() };
    // SAFETY: The scheduler register pointer is live for the current native call.
    let registers = unsafe { &mut *registers };
    for (destination, raw) in process
        .x
        .iter_mut()
        .take(NATIVE_X)
        .zip(&registers.x_reg_array)
    {
        // SAFETY: The register area contains tagged BEAM terms.
        *destination = unsafe { Term::from_raw_bits(*raw) };
    }
    if ensure_native_frame(process, registers, need_words, live).is_err() {
        set_error(process, "system_limit");
    }
    publish_x(process, registers);
    process.sync_native_header();
    0
}
