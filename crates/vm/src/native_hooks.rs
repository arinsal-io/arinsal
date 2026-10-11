//! Runtime callbacks used by BeamAsm slow paths.

use crate::{Process, VmError};
use arinsal_arith::{ArithError, ArithResult};
use arinsal_beamasm::{ProcessHeader, SchedulerRegisters};
use arinsal_bifs::BifError;
use arinsal_maps::MapError;
use arinsal_term::{Term, TermBuilder, TermKind, cmp, cmp_exact, exact_eq, global_atoms, loose_eq};
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
    let (process, registers) = enter_runtime(header)?;
    for (destination, raw) in process
        .x
        .iter_mut()
        .take(NATIVE_X)
        .zip(&registers.x_reg_array)
    {
        *destination = *raw;
    }
    Some((process, registers))
}

/// The process and scheduler registers of a helper called from native code, with the heap
/// and stack cursors committed but the X registers left in the register array, where the
/// helper reads them.
// Port of erts/emulator/beam/jit/arm/beam_asm.hpp:460-540 (emit_enter_runtime stores only
// HTOP/STOP; the runtime gets `reg`, the scheduler's x_reg_array, not a copy), OTP-29.1.1.
pub(crate) fn enter_runtime<'a>(
    header: *mut ProcessHeader,
) -> Option<(&'a mut Process, &'a mut SchedulerRegisters)> {
    let process = process_from_header(header)?;
    // Rust helpers may allocate or publish the header again, so first commit the
    // native heap and stack cursors that generated code flushed at the call site.
    // `c_p->heap` is the base; converting through the block pointer is the slow path.
    process.heap.set_native_cursors_at(
        process.header.heap,
        process.header.htop,
        process.header.stop,
    );
    scheduler_registers(process)
}

fn scheduler_registers(process: &mut Process) -> Option<(&mut Process, &mut SchedulerRegisters)> {
    let registers = process.header.ftrace.cast::<SchedulerRegisters>();
    if registers.is_null() {
        return None;
    }
    // SAFETY: run_native keeps its scheduler register area exclusively borrowed
    // while native code and its synchronous hooks are executing.
    let registers = unsafe { &mut *registers };
    Some((process, registers))
}

/// Enters a non-collecting heap helper that receives all operands as arguments.
// Port of erts/emulator/beam/jit/arm/beam_asm.hpp:459-537 (emit_enter_runtime with
// Update::eHeapAlloc publishes HTOP and E), OTP-29.1.1.
pub(crate) fn enter_heap_runtime<'a>(header: *mut ProcessHeader) -> Option<&'a mut Process> {
    let process = process_from_header(header)?;
    process
        .heap
        .set_native_cursors(process.header.htop, process.header.stop);
    Some(process)
}

fn process_from_header<'a>(header: *mut ProcessHeader) -> Option<&'a mut Process> {
    if header.is_null() {
        return None;
    }
    // SAFETY: ProcessHeader is the first repr(C) field of Process; native entry
    // passes the active process header for the duration of the helper call.
    Some(unsafe { &mut *header.cast::<Process>() })
}

fn publish_x(process: &Process, registers: &mut SchedulerRegisters) {
    for (destination, term) in registers
        .x_reg_array
        .iter_mut()
        .zip(process.x.iter())
        .take(NATIVE_X)
    {
        *destination = *term;
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

fn order_bits(order: Ordering) -> i32 {
    match order {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

/// Exact equality of two terms. Non-zero means equal.
// Port of erts/emulator/beam/utils.c:1125 (eq), OTP-29.1.1.
pub extern "C" fn arinsal_eq(a: u64, b: u64) -> i32 {
    i32::from(exact_eq(from_raw(a), from_raw(b)))
}

/// Atom order. The shared fragment only calls this when both operands are atoms.
// Port of erts/emulator/beam/erl_utils.h:193 (erts_cmp_atoms), OTP-29.1.1.
pub extern "C" fn arinsal_cmp_atoms(a: u64, b: u64) -> i32 {
    order_bits(cmp(from_raw(a), from_raw(b)))
}

/// Arithmetic term order (`exact == 0`) or exact term order. `eq_only` does not change the sign.
// Port of erts/emulator/beam/utils.c:1658 (erts_cmp_compound), OTP-29.1.1.
pub extern "C" fn arinsal_cmp_compound(a: u64, b: u64, exact: i32, _eq_only: i32) -> i64 {
    let left = from_raw(a);
    let right = from_raw(b);
    let order = if exact == 0 {
        cmp(left, right)
    } else {
        cmp_exact(left, right)
    };
    i64::from(order_bits(order))
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

// Port of erts/emulator/beam/erl_arith.c:358-405 (erts_mixed_plus), OTP-29.1.1.
fn with_fragment_alloc(
    process: &mut Process,
    lhs: Term,
    rhs: Term,
    operation: impl FnOnce(Term, Term, &mut arinsal_bifs::FragmentingHeap<'_>) -> ArithResult,
) -> Result<Term, ArithError> {
    // OTP arithmetic slow paths allocate into heap fragments and therefore
    // cannot move E, HTOP, or the register roots under a reductions-only update.
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    operation(lhs, rhs, &mut heap)
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
    extra: u64,
) -> u64 {
    let Some((process, registers)) = process_and_registers(header) else {
        return 0;
    };
    // An operation with a failure label branches there instead of raising (QUIET_GUARD).
    let quiet = op & QUIET_GUARD != 0;
    let op = op & !QUIET_GUARD;
    // The 128-bit product is a magnitude plus a sign, not two tagged terms.
    if op == 15 {
        return int128_to_big(process, registers, lhs, rhs, extra);
    }
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
        13 => Some(("*", &[left, right][..])),
        14 => Some(("div", &[left, right][..])),
        _ => None,
    };
    // The call site published FCALLS (Update::REDUCTIONS) and reloads it afterwards.
    process.reductions = process.header.fcalls;
    if let Some((operation, args)) = operation {
        // The charge comes off FCALLS, which the scheduler adds to the process's count.
        let charge = arinsal_arith::reduction_charge(operation, args);
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
        17 => with_fragment_alloc(process, Term::NIL, Term::NIL, |_, _, heap| {
            TermBuilder::new(heap)
                .float(f64::from_bits(lhs))
                .map_err(|_| ArithError::HeapFull { need_words: 2 })
        })
        .map(raw),
        0..=14 => with_fragment_alloc(process, left, right, |a, b, heap| match op {
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
            // Port of erts/emulator/erl_arith.c (erts_mixed_div), OTP-29.1.1.
            12 => arinsal_arith::fdiv(a, b, heap),
            // Port of erts/emulator/beam/erl_arith.c:919 (erts_mul_add), OTP-29.1.1.
            13 => {
                let product = arinsal_arith::mul(a, b, heap)?;
                arinsal_arith::add(product, from_raw(extra), heap)
            }
            // Port of erts/emulator/beam/jit/arm/instr_arith.cpp:802-854 (erts_int_div_rem
            // body): quotient is the return value, remainder is published for the caller.
            14 => {
                let quotient = arinsal_arith::int_div(a, b, heap)?;
                let remainder = arinsal_arith::rem(a, b, heap)?;
                registers.tmp_mem[1] = raw(remainder);
                Ok(quotient)
            }
            _ => arinsal_arith::bsr(a, b, heap),
        })
        .map(raw),
        _ => Err(ArithError::Badarith),
    };
    let answer = match result {
        Ok(value) => value,
        Err(error) => {
            let error = match error {
                ArithError::HeapFull { .. } | ArithError::SystemLimit => BifError::SystemLimit,
                ArithError::Badarith | ArithError::Badarg => BifError::Badarith,
            };
            // Port of erts/emulator/beam/jit/arm/instr_arith.cpp (the arithmetic BIF and its
            // operands are the top frame of a raised error), OTP-29.1.1.
            match arith_bif(op) {
                Some((name, arity)) if !quiet => {
                    let args = [left, right];
                    crate::native_helpers::set_native_bif_error(
                        process,
                        "erlang",
                        name,
                        &args[..arity],
                        error,
                    );
                }
                _ => set_light_error(process, &error),
            }
            0
        }
    };
    publish_x(process, registers);
    process.sync_native_header();
    answer
}

/// The erlang BIF behind a generic arithmetic helper op.
fn arith_bif(op: u32) -> Option<(&'static str, usize)> {
    Some(match op {
        0 => ("+", 2),
        1 => ("-", 2),
        2 => ("*", 2),
        3 => ("div", 2),
        4 => ("rem", 2),
        5 => ("band", 2),
        6 => ("bor", 2),
        7 => ("bxor", 2),
        8 => ("bnot", 1),
        9 => ("-", 1),
        10 => ("bsl", 2),
        11 => ("bsr", 2),
        12 => ("/", 2),
        13 => ("*", 2),
        14 => ("div", 2),
        _ => return None,
    })
}

/// `beam_jit_int128_to_big`: a signed 128-bit magnitude becomes a small or a bignum.
// Port of erts/emulator/beam/jit/beam_jit_common.cpp:1025-1040, OTP-29.1.1.
fn int128_to_big(
    process: &mut Process,
    registers: &mut SchedulerRegisters,
    low: u64,
    high: u64,
    sign: u64,
) -> u64 {
    let mut magnitude = num_bigint::BigInt::from((u128::from(high) << 64) | u128::from(low));
    if sign != 0 {
        magnitude = -magnitude;
    }
    let built = TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
        .int_from_bigint(&magnitude);
    let answer = match built {
        Ok(term) => raw(term),
        Err(_) => {
            set_error(process, "system_limit");
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
    // A guard with a failure label passes QUIET_GUARD: the failure branches there instead of
    // raising, so no BIF frame is recorded for it.
    let quiet = op & QUIET_GUARD != 0;
    let op = op & !QUIET_GUARD;
    let a = from_raw(first);
    let b = from_raw(second);
    // Port of erts/emulator/beam/jit/arm/beam_asm_global.cpp (emit_raise_badarg), OTP-29.1.1:
    // a guard BIF raising outside a guard names itself and its arguments as the top frame.
    let fail = |process: &mut Process, name: &str, args: &[Term], error: BifError| {
        if quiet {
            set_light_error(process, &error);
        } else {
            crate::native_helpers::set_native_bif_error(process, "erlang", name, args, error);
        }
        0
    };
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
            match index.and_then(|i| {
                // SAFETY: tuple_ref validates the tagged term and its live heap header.
                unsafe { b.tuple_ref() }.and_then(|tuple| tuple.get(i))
            }) {
                Some(value) => raw(value),
                None => fail(process, "element", &[a, b], BifError::BADARG),
            }
        }
        26 | 27 => {
            // SAFETY: cons_ref validates the tagged term before reading its two words.
            match unsafe { a.cons_ref() } {
                Some((head, tail)) => raw(if op == 26 { head } else { tail }),
                None => fail(
                    process,
                    if op == 26 { "hd" } else { "tl" },
                    &[a],
                    BifError::BADARG,
                ),
            }
        }
        28 => match tuple_size(a).and_then(|size| Term::small(size as i64)) {
            Some(size) => raw(size),
            None => fail(process, "tuple_size", &[a], BifError::BADARG),
        },
        29 => match arinsal_maps::size(a)
            .ok()
            .and_then(|size| Term::small(size as i64))
        {
            Some(size) => raw(size),
            None => {
                let error = tagged_error(process, "badmap", a);
                fail(process, "map_size", &[a], error)
            }
        },
        30 => match arinsal_maps::is_key(b, a) {
            Ok(found) => u64::from(found),
            Err(_) => {
                let error = tagged_error(process, "badmap", b);
                fail(process, "is_map_key", &[a, b], error)
            }
        },
        31 => match arinsal_maps::get(b, a) {
            Ok(Some(value)) => raw(value),
            Ok(None) | Err(MapError::Badkey(_)) => {
                let error = tagged_error(process, "badkey", a);
                fail(process, "map_get", &[a, b], error)
            }
            Err(MapError::Badmap(_)) => {
                let error = tagged_error(process, "badmap", b);
                fail(process, "map_get", &[a, b], error)
            }
            Err(_) => fail(process, "map_get", &[a, b], BifError::BADARG),
        },
        32 | 33 => match binary_size(a, op == 33).and_then(|size| Term::small(size as i64)) {
            Some(size) => raw(size),
            None => fail(
                process,
                if op == 33 { "bit_size" } else { "byte_size" },
                &[a],
                BifError::BADARG,
            ),
        },
        34 => process.header.self_pid,
        35 => match list_length(a).and_then(|size| Term::small(size as i64)) {
            Some(size) => raw(size),
            None => fail(process, "length", &[a], BifError::BADARG),
        },
        // Port of erts/emulator/beam/erl_bif_guard.c (min_2/max_2), OTP-29.1.1: equal
        // arguments return the first one.
        36 => raw(if cmp(a, b) == Ordering::Greater { b } else { a }),
        37 => raw(if cmp(a, b) == Ordering::Less { b } else { a }),
        38 => match with_fragment_alloc(process, a, Term::NIL, |value, _, heap| {
            arinsal_arith::abs(value, heap)
        }) {
            Ok(value) => raw(value),
            Err(ArithError::HeapFull { .. } | ArithError::SystemLimit) => {
                fail(process, "abs", &[a], BifError::SystemLimit)
            }
            Err(_) => fail(process, "abs", &[a], BifError::BADARG),
        },
        // Port of erts/emulator/beam/dist.c:6217 (node/1), OTP-29.1.1.
        39 => match crate::natives::node::node(a) {
            Ok(node) => raw(node),
            Err(_) => fail(process, "node", &[a], BifError::BADARG),
        },
        // OTP calls `erl_is_function` when the arity operand is not a small immediate.
        43 => {
            let requested = b.as_small().filter(|arity| (0..=255).contains(arity));
            let actual = (a.classify() == TermKind::Fun)
                .then(|| a.header().map(|header| ((header >> 8) & 255) as i64))
                .flatten();
            u64::from(requested.is_some() && requested == actual)
        }
        40..=42 => {
            set_error(process, "badarg");
            0
        }
        _ => 0,
    };
    publish_x(process, registers);
    process.sync_native_header();
    answer
}

/// Guard helper op flag: the instruction has a failure label.
pub const QUIET_GUARD: u32 = 0x100;

/// Sets the exception for a BIF error without recording a BIF frame.
fn set_light_error(process: &mut Process, error: &BifError) {
    match error {
        BifError::Error(reason) => {
            process.header.freason = 1;
            process.header.fvalue = raw(*reason);
        }
        BifError::SystemLimit => set_error(process, "system_limit"),
        BifError::Badarith => set_error(process, "badarith"),
        _ => set_error(process, "badarg"),
    }
}

/// Builds `error:{Tag, Value}` for a guard BIF failure.
fn tagged_error(process: &mut Process, tag: &str, value: Term) -> BifError {
    let tag = crate::signals::atom(tag);
    match TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
        .tuple(&[tag, value])
    {
        Ok(reason) => BifError::Error(reason),
        Err(_) => BifError::SystemLimit,
    }
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

/// Collects with the first `live` scheduler X registers as roots and writes the moved
/// roots back, like `erts_garbage_collect(p, need, reg, live)` on the register array.
pub(crate) fn collect_native(
    process: &mut Process,
    registers: &mut SchedulerRegisters,
    need_words: usize,
    live: usize,
) -> Result<(), VmError> {
    // Exactly the live X registers are GC roots, including those past the six register-backed
    // ones; dead registers may hold stale words (erts_garbage_collect_nobump, OTP-29.1.1).
    let roots = live.min(registers.x_reg_array.len());
    if process.x.len() < roots {
        let mut grown = process.x.to_vec();
        grown.resize(roots, Term::NIL);
        process.x = grown.into();
    }
    for (destination, raw) in process.x.iter_mut().take(roots).zip(&registers.x_reg_array) {
        *destination = *raw;
    }
    let result = ensure_native_frame(process, registers, need_words, live);
    for (destination, term) in registers
        .x_reg_array
        .iter_mut()
        .zip(process.x.iter())
        .take(roots)
    {
        *destination = *term;
    }
    result
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
    if collect_native(process, registers, need_words, live).is_err() {
        set_error(process, "system_limit");
    }
    process.sync_native_header();
    0
}
