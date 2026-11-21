//! The coverage BIFs of erl_bif_coverage.c.
//!
//! Port of erts/emulator/beam/erl_bif_coverage.c (code_coverage_support_0,
//! code_set_coverage_mode_1, code_get_coverage_mode_0, code_get_coverage_mode_1,
//! code_get_coverage_2, code_reset_coverage_1), OTP-29.1.1. Each BIF is
//! `bif_table[].f` with `(c_p, reg, I)`.

use crate::code_ix::{code_tables, erts_active_code_ix};
use crate::natives::bif::{bif_badarg, bif_ret, bif_system_limit};
use crate::{Process, VmError};
use arinsal_beamasm::ProcessHeader;
use arinsal_bifs::ProcessHeapHandle;
use arinsal_loader::CoverageMode;
use arinsal_term::{Term, TermBuilder, atoms, global_atoms};

fn badarg() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(Term::atom(atoms::BADARG)))
}

fn system_limit() -> VmError {
    VmError::Trap(crate::exceptions::Trap::error(Term::atom(
        atoms::SYSTEM_LIMIT,
    )))
}

fn ret(c_p: *mut ProcessHeader, i: u64, result: Result<Term, VmError>) -> u64 {
    match result {
        Ok(value) => crate::native_hooks::raw(value),
        Err(VmError::Trap(trap)) if trap.reason == Term::atom(atoms::BADARG) => bif_badarg(c_p),
        Err(VmError::Trap(trap)) if trap.reason == Term::atom(atoms::SYSTEM_LIMIT) => {
            bif_system_limit(c_p)
        }
        Err(error) => bif_ret(c_p, i, Err(error)),
    }
}

// Port of erts/emulator/beam/erl_bif_coverage.c:50-116, OTP-29.1.1.
fn coverage_mode_atom(mode: CoverageMode) -> Term {
    Term::atom(match mode {
        CoverageMode::None => atoms::NONE,
        CoverageMode::Function => atoms::FUNCTION,
        CoverageMode::FunctionCounters => atoms::FUNCTION_COUNTERS,
        CoverageMode::Line => atoms::LINE,
        CoverageMode::LineCounters => atoms::LINE_COUNTERS,
    })
}

pub(crate) fn coverage_mode_from(term: Term) -> Option<CoverageMode> {
    let text = global_atoms().text(term.as_atom()?)?;
    match text {
        "none" => Some(CoverageMode::None),
        "function" => Some(CoverageMode::Function),
        "function_counters" => Some(CoverageMode::FunctionCounters),
        "line" => Some(CoverageMode::Line),
        "line_counters" => Some(CoverageMode::LineCounters),
        _ => None,
    }
}

fn coverage_module(module: Term) -> Result<&'static arinsal_loader::Module, VmError> {
    let name = global_atoms()
        .text(module.as_atom().ok_or_else(badarg)?)
        .ok_or_else(badarg)?;
    let id = code_tables(erts_active_code_ix())
        .loaded
        .get(name)
        .copied()
        .ok_or_else(badarg)?;
    code_tables(erts_active_code_ix())
        .modules
        .get(id)
        .map(AsRef::as_ref)
        .ok_or_else(badarg)
}

fn coverage_count(value: u64, flags: bool) -> Term {
    if flags {
        Term::atom(if value == 0 {
            atoms::FALSE
        } else {
            atoms::TRUE
        })
    } else {
        const MAX_SMALL: u64 = (1_u64 << 59) - 1;
        Term::small(value.min(MAX_SMALL) as i64).expect("coverage counter fits small integer")
    }
}

fn make_list(
    process: &mut Process,
    values: impl IntoIterator<Item = Term>,
) -> Result<Term, VmError> {
    TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
        .list_from_iter(values)
        .map_err(|_| system_limit())
}

fn make_tuple(process: &mut Process, values: &[Term]) -> Result<Term, VmError> {
    TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
        .tuple(values)
        .map_err(|_| system_limit())
}

/// Body of `code:get_coverage/2`.
// Port of erts/emulator/beam/erl_bif_coverage.c:164-440, OTP-29.1.1.
pub(crate) fn get_coverage(process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    let mode = global_atoms()
        .text(args[0].as_atom().ok_or_else(badarg)?)
        .ok_or_else(badarg)?;
    let module = coverage_module(args[1])?;
    let Some(coverage) = module.coverage.as_ref() else {
        return Err(badarg());
    };
    let (flags, line_mode, ids, function_from_lines) = match (mode, coverage.mode) {
        ("function", CoverageMode::Function) => (true, false, false, false),
        ("function", CoverageMode::FunctionCounters) => (false, false, false, false),
        ("function", CoverageMode::Line | CoverageMode::LineCounters) => (true, false, false, true),
        ("line", CoverageMode::Line) => (true, true, false, false),
        ("line", CoverageMode::LineCounters) => (false, true, false, false),
        ("cover_id_line", CoverageMode::LineCounters) => (false, true, true, false),
        _ => return Err(badarg()),
    };
    if line_mode {
        let mut rows = Vec::with_capacity(coverage.len());
        for index in 0..coverage.len() {
            let key = if ids {
                coverage.cover_ids[index]
            } else {
                coverage.lines[index]
            };
            let count = coverage.load(index).unwrap_or(0);
            let key = Term::small(i64::from(key)).ok_or_else(badarg)?;
            rows.push(make_tuple(process, &[key, coverage_count(count, flags)])?);
        }
        return make_list(process, rows);
    }
    let mut rows = Vec::new();
    for (index, (_, function, arity)) in module.functions.iter().enumerate() {
        if *function == "module_info" && *arity <= 1 {
            continue;
        }
        let count = if function_from_lines {
            coverage
                .function_owners
                .iter()
                .enumerate()
                .filter(|(_, owner)| **owner as usize == index)
                .any(|(counter, _)| coverage.load(counter).unwrap_or(0) > 0) as u64
        } else {
            let Some(count) = coverage.load(index) else {
                continue;
            };
            count
        };
        let mfa = make_tuple(
            process,
            &[
                crate::atom_cache::put(function),
                Term::small(i64::from(*arity)).ok_or_else(badarg)?,
            ],
        )?;
        rows.push(make_tuple(process, &[mfa, coverage_count(count, flags)])?);
    }
    make_list(process, rows)
}

/// Body of `code:reset_coverage/1`.
// Port of erts/emulator/beam/erl_bif_coverage.c:444-482, OTP-29.1.1.
pub(crate) fn reset_coverage(module: Term) -> Result<Term, VmError> {
    let module = coverage_module(module)?;
    let Some(coverage) = module.coverage.as_ref() else {
        return Err(badarg());
    };
    coverage.reset();
    Ok(Term::atom(atoms::OK))
}

/// `code:coverage_support/0`.
// Port of erts/emulator/beam/erl_bif_coverage.c (code_coverage_support_0), OTP-29.1.1.
pub(crate) extern "C" fn code_coverage_support_0(
    _c_p: *mut ProcessHeader,
    _reg: *mut u64,
    _i: u64,
) -> u64 {
    crate::native_hooks::raw(Term::atom(atoms::TRUE))
}

/// `code:set_coverage_mode/1`.
// Port of erts/emulator/beam/erl_bif_coverage.c (code_set_coverage_mode_1), OTP-29.1.1.
pub(crate) extern "C" fn code_set_coverage_mode_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let [mode] = crate::bif_table::bif_args::<1>(reg);
    let Some(next) = coverage_mode_from(mode) else {
        return bif_badarg(c_p);
    };
    let previous = crate::code_ix::global().coverage_mode();
    crate::code_ix::global().set_coverage_mode(next);
    ret(c_p, i, Ok(coverage_mode_atom(previous)))
}

/// `code:get_coverage_mode/0`.
// Port of erts/emulator/beam/erl_bif_coverage.c (code_get_coverage_mode_0), OTP-29.1.1.
pub(crate) extern "C" fn code_get_coverage_mode_0(
    _c_p: *mut ProcessHeader,
    _reg: *mut u64,
    _i: u64,
) -> u64 {
    crate::native_hooks::raw(coverage_mode_atom(crate::code_ix::global().coverage_mode()))
}

/// `code:get_coverage_mode/1`.
// Port of erts/emulator/beam/erl_bif_coverage.c (code_get_coverage_mode_1), OTP-29.1.1.
pub(crate) extern "C" fn code_get_coverage_mode_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let [module] = crate::bif_table::bif_args::<1>(reg);
    ret(c_p, i, get_coverage_mode_1(module))
}

fn get_coverage_mode_1(module: Term) -> Result<Term, VmError> {
    let module = coverage_module(module)?;
    Ok(coverage_mode_atom(
        module
            .coverage
            .as_ref()
            .map(|coverage| coverage.mode)
            .unwrap_or(CoverageMode::None),
    ))
}

/// `code:get_coverage/2`.
// Port of erts/emulator/beam/erl_bif_coverage.c (code_get_coverage_2), OTP-29.1.1.
pub(crate) extern "C" fn code_get_coverage_2(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let args = crate::bif_table::bif_args::<2>(reg);
    ret(c_p, i, get_coverage(process, &args))
}

/// `code:reset_coverage/1`.
// Port of erts/emulator/beam/erl_bif_coverage.c (code_reset_coverage_1), OTP-29.1.1.
pub(crate) extern "C" fn code_reset_coverage_1(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
) -> u64 {
    let [module] = crate::bif_table::bif_args::<1>(reg);
    ret(c_p, i, reset_coverage(module))
}
