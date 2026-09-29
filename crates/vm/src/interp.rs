//! VM interp implementation.

use super::*;

/// Port of erts/emulator/beam/erl_record.c:254-343 (native record creation), OTP-29.1.1.
fn execute_put_record(
    process: &mut Process,
    module: &Module,
    op: &GenericOp,
) -> Result<(), VmError> {
    let id = process.read(op.args[1])?;
    let source_arg = op.args[2];
    let source_before_gc = process.read(source_arg)?;
    let destination = module.arg(op, 3);
    let live = module.arg(op, 4).value() as usize;
    let updates = module.arg(op, 5);
    let record_name = if source_before_gc == Term::NIL {
        id.as_atom()
            .ok_or_else(|| VmError::Unsupported("invalid native record id".into()))?
    } else {
        source_before_gc
            .record_snapshot()
            .map(|snapshot| snapshot.name)
            .ok_or_else(|| VmError::Unsupported("invalid native record source".into()))?
    };
    let definition = module
        .records
        .iter()
        .find(|record| {
            arinsal_term::global_atoms().text(record_name).as_deref() == Some(record.name.as_str())
        })
        .ok_or_else(|| VmError::Unsupported("native record definition not found".into()))?;
    let module_atom = arinsal_term::global_atoms()
        .intern(&module.name)
        .map_err(|_| VmError::Unsupported("native record module atom limit".into()))?;
    let required = 9 + 3 * definition.fields.len();
    process.ensure(required, live)?;
    let source = process.read(source_arg)?;
    let update_args = &module.lists[updates.value() as usize];
    if !update_args.len().is_multiple_of(2) {
        return Err(VmError::Unsupported(
            "invalid native record update list".into(),
        ));
    }
    let mut changes = Vec::with_capacity(update_args.len() / 2);
    for pair in update_args.as_chunks::<2>().0 {
        let field = process
            .read(pair[0])?
            .as_atom()
            .ok_or_else(|| VmError::Unsupported("invalid native record field name".into()))?;
        changes.push((field, process.read(pair[1])?));
    }
    let name_atom = record_name;
    let record = if source == Term::NIL {
        let mut values = Vec::with_capacity(definition.fields.len());
        for (name, default) in &definition.fields {
            let field = arinsal_term::global_atoms()
                .intern(name)
                .map_err(|_| VmError::Unsupported("native record field atom limit".into()))?;
            let value = match default {
                Some(default) => {
                    arinsal_term::from_owned(default, &mut FragmentingHeap(&mut process.heap))
                        .map_err(|_| {
                            VmError::Unsupported("native record default allocation".into())
                        })?
                }
                None => Term::NIL,
            };
            values.push((field, value));
        }
        for (field, value) in changes {
            let Some((_, current)) = values.iter_mut().find(|(name, _)| *name == field) else {
                return Err(VmError::Unsupported("unknown native record field".into()));
            };
            *current = value;
        }
        TermBuilder::new(&mut FragmentingHeap(&mut process.heap))
            .native_record(module_atom, name_atom, definition.is_exported, &values)
            .map_err(|_| VmError::Unsupported("native record allocation".into()))?
    } else {
        let snapshot = source
            .record_snapshot()
            .ok_or_else(|| VmError::Unsupported("invalid native record source".into()))?;
        TermBuilder::new(&mut FragmentingHeap(&mut process.heap))
            .update_native_record(&snapshot, &changes)
            .map_err(|_| VmError::Unsupported("native record update".into()))?
    };
    process.write(destination, record)?;
    process.ip += 1;
    Ok(())
}

fn read_validated_arg(heap: &mut ProcessHeap, x: &[Term], arg: Arg) -> Term {
    match arg.kind() {
        Arg::X => x[arg.value() as usize],
        Arg::Y => heap
            .stack_get(arg.value() as usize)
            .expect("operand was validated before tuple allocation"),
        Arg::TERM => arg.term(),
        Arg::U => Term::small(i64::try_from(arg.value()).expect("operand was validated"))
            .expect("operand was validated"),
        Arg::INT => Term::small(arg.signed()).expect("operand was validated"),
        _ => unreachable!("operand was validated before tuple allocation"),
    }
}

fn read_validated_non_y_arg(x: &[Term], arg: Arg) -> Term {
    match arg.kind() {
        Arg::X => x[arg.value() as usize],
        Arg::TERM => arg.term(),
        Arg::U => Term::small(i64::try_from(arg.value()).expect("operand was validated"))
            .expect("operand was validated"),
        Arg::INT => Term::small(arg.signed()).expect("operand was validated"),
        _ => unreachable!("non-Y operand was validated before tuple allocation"),
    }
}

#[inline(always)]
fn read_fast_x(p: &Process, arg: Arg) -> Result<Term, VmError> {
    if arg.kind() != Arg::X {
        return p.read(arg);
    }
    let term =
        p.x.get(arg.value() as usize)
            .copied()
            .ok_or_else(|| VmError::Unsupported("X register out of range".into()))?;
    #[cfg(any(feature = "validate-terms", debug_assertions))]
    arinsal_term::validate::check_if_active(&p.heap, term);
    Ok(term)
}

#[inline(always)]
fn write_fast_x(p: &mut Process, dst: Arg, value: Term) -> Result<(), VmError> {
    if dst.kind() != Arg::X {
        return p.write(dst, value);
    }
    *p.x.get_mut(dst.value() as usize)
        .ok_or_else(|| VmError::Unsupported("X register out of range".into()))? = value;
    Ok(())
}

fn execute_get_map_elements(
    p: &mut Process,
    module: &Module,
    op: &GenericOp,
) -> Result<(), VmError> {
    // Port of erts/emulator/beam/jit/arm/instr_map.cpp:391, OTP-29.1.1.
    let [fail, source, destination] = op.args;
    let map = p.read(source)?;
    if matches!(
        arinsal_maps::size(map),
        Err(arinsal_maps::MapError::Badmap(_))
    ) {
        return branch_map_failure(p, fail);
    }
    let args = &module.lists[destination.value() as usize];
    for pair in args.as_chunks::<2>().0 {
        match arinsal_maps::get(map, p.read(pair[0])?) {
            Ok(Some(_)) => {}
            Ok(None) | Err(arinsal_maps::MapError::Badmap(_)) => {
                return branch_map_failure(p, fail);
            }
            Err(_) => return maps::execute(p, module, op, ""),
        }
    }
    for pair in args.as_chunks::<2>().0 {
        match arinsal_maps::get(map, p.read(pair[0])?) {
            Ok(Some(value)) => p.write(pair[1], value)?,
            Ok(None) | Err(arinsal_maps::MapError::Badmap(_)) => {
                return branch_map_failure(p, fail);
            }
            Err(_) => return maps::execute(p, module, op, ""),
        }
    }
    p.ip += 1;
    Ok(())
}

fn branch_map_failure(p: &mut Process, fail: Arg) -> Result<(), VmError> {
    if fail.kind() != Arg::LABEL || fail.value() == u32::MAX as u64 {
        return Err(VmError::Unsupported("map failure label zero".into()));
    }
    p.ip = fail.value() as usize;
    Ok(())
}

#[inline(always)]
fn execute_tuple_bif(
    p: &mut Process,
    module: &Module,
    op: &GenericOp,
    opcode: Opcode,
) -> Result<bool, VmError> {
    let [fail, second, third] = op.args;
    let (import_index, first_arg, arity, dst, live) = match opcode {
        Opcode::Bif2 => (second.value() as usize, 2, 2, module.arg(op, 4), 2),
        Opcode::GcBif3 => (
            third.value() as usize,
            3,
            3,
            module.arg(op, 6),
            second.value() as usize,
        ),
        _ => return Ok(false),
    };
    let Some(import) = module.imports.get(import_index) else {
        return Ok(false);
    };
    let is_element = import.fast_op == ImportFastOp::Element && arity == 2;
    let is_setelement = import.fast_op == ImportFastOp::SetElement && arity == 3;
    if !is_element && !is_setelement {
        return Ok(false);
    }

    p.gc_live = live;
    let mut args = [Term::NIL; 3];
    for (index, arg) in args.iter_mut().enumerate().take(arity) {
        *arg = read_fast_x(p, module.arg(op, first_arg + index))?;
    }
    let result = if is_element {
        args[0].as_small().and_then(|index| {
            (index >= 1)
                .then(|| usize::try_from(index - 1).ok())
                .flatten()
                .and_then(|index| tuples::element(args[1], index))
        })
    } else {
        let tuple = args[1];
        let index = args[0].as_small().and_then(|index| {
            if index < 1 {
                None
            } else {
                usize::try_from(index - 1).ok()
            }
        });
        let arity = if tuple.classify() == TermKind::Tuple {
            tuple.header().map(|header| (header >> 6) as usize)
        } else {
            None
        };
        match (index, arity) {
            (Some(index), Some(arity)) if index < arity => Some(
                TermBuilder::new(&mut FragmentingHeap(&mut p.heap))
                    .tuple_from_fn(arity, |element, _| {
                        if element == index {
                            args[2]
                        } else {
                            tuples::element(tuple, element).expect("validated tuple element")
                        }
                    })
                    .map_err(|error| {
                        VmError::Unsupported(format!("setelement tuple allocation {error:?}"))
                    })?,
            ),
            _ => None,
        }
    };
    if let Some(value) = result {
        write_fast_x(p, dst, value)?;
        p.ip += 1;
        return Ok(true);
    }

    if fail.kind() == Arg::LABEL && fail.value() != u32::MAX as u64 {
        p.ip = fail.value() as usize;
        return Ok(true);
    }
    let function = if is_element { "element" } else { "setelement" };
    Err(exceptions::bif_error(
        p,
        "erlang",
        function,
        &args[..arity],
        arinsal_bifs::BifError::BADARG,
    ))
}

#[inline(always)]
fn call_fast_tuple_bif(
    p: &mut Process,
    operation: ImportFastOp,
    arity: usize,
) -> Option<Result<Term, arinsal_bifs::BifError>> {
    let args = p.x.get(..arity)?;
    let result = match operation {
        ImportFastOp::Element if arity == 2 => {
            let index = args[0]
                .as_small()
                .and_then(|index| usize::try_from(index.checked_sub(1)?).ok());
            index
                .and_then(|index| tuples::element(args[1], index))
                .ok_or(arinsal_bifs::BifError::BADARG)
        }
        ImportFastOp::SetElement if arity == 3 => {
            let tuple = args[1];
            let index = args[0]
                .as_small()
                .and_then(|index| usize::try_from(index.checked_sub(1)?).ok());
            let tuple_arity = (tuple.classify() == TermKind::Tuple)
                .then(|| tuple.header())
                .flatten()
                .filter(|header| header & 63 == 0)
                .map(|header| (header >> 6) as usize);
            match (index, tuple_arity) {
                (Some(index), Some(tuple_arity)) if index < tuple_arity => {
                    TermBuilder::new(&mut FragmentingHeap(&mut p.heap))
                        .tuple_from_fn(tuple_arity, |element, _| {
                            if element == index {
                                args[2]
                            } else {
                                tuples::element(tuple, element).expect("tuple arity was validated")
                            }
                        })
                        .map_err(|_| arinsal_bifs::BifError::SystemLimit)
                }
                _ => Err(arinsal_bifs::BifError::BADARG),
            }
        }
        ImportFastOp::TupleSize if arity == 1 => args[0]
            .header()
            .filter(|header| args[0].classify() == TermKind::Tuple && header & 63 == 0)
            .and_then(|header| Term::small((header >> 6) as i64))
            .ok_or(arinsal_bifs::BifError::BADARG),
        _ => return None,
    };
    Some(result)
}

#[inline(always)]
fn execute_small_bif(
    p: &mut Process,
    module: &Module,
    op: &GenericOp,
    opcode: Opcode,
) -> Result<bool, VmError> {
    let [_, live_or_import, import_or_unused] = op.args;
    let (import_index, first, dst, live) = match opcode {
        Opcode::Bif2 => (live_or_import.value() as usize, 2, module.arg(op, 4), 2),
        Opcode::GcBif2 => (
            import_or_unused.value() as usize,
            3,
            module.arg(op, 5),
            live_or_import.value() as usize,
        ),
        _ => return Ok(false),
    };
    let Some(import) = module.imports.get(import_index) else {
        return Ok(false);
    };
    let [left, right] = [
        read_fast_x(p, module.arg(op, first))?,
        read_fast_x(p, module.arg(op, first + 1))?,
    ];
    let result = if import.fast != FastBif::None {
        arith::small(import.fast, left, right)
    } else {
        match import.fast_op {
            ImportFastOp::Rem => right
                .as_small()
                .filter(|right| *right != 0)
                .and_then(|right| left.as_small().and_then(|left| Term::small(left % right))),
            _ => return Ok(false),
        }
    };
    let Some(result) = result else {
        return Ok(false);
    };
    p.gc_live = live;
    write_fast_x(p, dst, result)?;
    p.ip += 1;
    Ok(true)
}

#[inline(always)]
fn execute_guard_bif(
    p: &mut Process,
    module: &Module,
    op: &GenericOp,
    opcode: Opcode,
) -> Result<bool, VmError> {
    let [fail, second, third] = op.args;
    let (import_index, first_arg, arity, dst, live) = match opcode {
        Opcode::Bif1 => (second.value() as usize, 2, 1, module.arg(op, 3), 1),
        Opcode::Bif2 => (second.value() as usize, 2, 2, module.arg(op, 4), 2),
        Opcode::GcBif1 => (
            third.value() as usize,
            3,
            1,
            module.arg(op, 4),
            second.value() as usize,
        ),
        Opcode::GcBif2 => (
            third.value() as usize,
            3,
            2,
            module.arg(op, 5),
            second.value() as usize,
        ),
        _ => return Ok(false),
    };
    let Some(import) = module.imports.get(import_index) else {
        return Ok(false);
    };
    if fail.kind() == Arg::LABEL
        && fail.value() != u32::MAX as u64
        && arity == 2
        && import.fast != FastBif::None
    {
        let left = read_fast_x(p, module.arg(op, first_arg))?;
        let right = read_fast_x(p, module.arg(op, first_arg + 1))?;
        let Some(bif) = import.bif_fn() else {
            return Ok(false);
        };
        p.gc_live = live;
        let result = arith::small(import.fast, left, right)
            .map(Ok)
            .unwrap_or_else(|| calls::call_bif(&mut p.heap, bif, &[left, right]));
        if let Ok(value) = result {
            write_fast_x(p, dst, value)?;
            p.ip += 1;
        } else {
            p.ip = fail.value() as usize;
        }
        return Ok(true);
    }
    if !matches!(
        (import.fast_op, arity),
        (ImportFastOp::IsInteger, 1)
            | (ImportFastOp::IsFloat, 1)
            | (ImportFastOp::IsNumber, 1)
            | (ImportFastOp::IsAtom, 1)
            | (ImportFastOp::IsTuple, 1)
            | (ImportFastOp::IsList, 1)
            | (ImportFastOp::IsMap, 1)
            | (ImportFastOp::IsFunction, 1)
            | (ImportFastOp::TupleSize, 1)
            | (ImportFastOp::Less, 2)
            | (ImportFastOp::LessEqual, 2)
            | (ImportFastOp::Greater, 2)
            | (ImportFastOp::GreaterEqual, 2)
            | (ImportFastOp::Equal, 2)
            | (ImportFastOp::NotEqual, 2)
            | (ImportFastOp::ExactEqual, 2)
            | (ImportFastOp::ExactNotEqual, 2)
    ) {
        return Ok(false);
    }
    let mut args = [Term::NIL; 2];
    for (index, arg) in args.iter_mut().enumerate().take(arity) {
        *arg = read_fast_x(p, module.arg(op, first_arg + index))?;
    }
    let value = match import.fast_op {
        ImportFastOp::IsInteger => Some(boolean(is_integer_term(args[0]))),
        ImportFastOp::IsFloat => Some(boolean(is_float_term(args[0]))),
        ImportFastOp::IsNumber => Some(boolean(args[0].classify() == TermKind::Number)),
        ImportFastOp::IsAtom => Some(boolean(args[0].as_atom().is_some())),
        ImportFastOp::IsTuple => Some(boolean(args[0].classify() == TermKind::Tuple)),
        ImportFastOp::IsList => Some(boolean(matches!(
            args[0].classify(),
            TermKind::Nil | TermKind::List
        ))),
        ImportFastOp::IsMap => Some(boolean(args[0].classify() == TermKind::Map)),
        ImportFastOp::IsFunction => Some(boolean(args[0].classify() == TermKind::Fun)),
        ImportFastOp::TupleSize => (args[0].classify() == TermKind::Tuple)
            .then(|| args[0].header())
            .flatten()
            .filter(|header| header & 63 == 0)
            .and_then(|header| Term::small((header >> 6) as i64)),
        ImportFastOp::Less => Some(boolean(cmp(args[0], args[1]).is_lt())),
        ImportFastOp::LessEqual => Some(boolean(!cmp(args[0], args[1]).is_gt())),
        ImportFastOp::Greater => Some(boolean(cmp(args[0], args[1]).is_gt())),
        ImportFastOp::GreaterEqual => Some(boolean(!cmp(args[0], args[1]).is_lt())),
        ImportFastOp::Equal => Some(boolean(loose_eq(args[0], args[1]))),
        ImportFastOp::NotEqual => Some(boolean(!loose_eq(args[0], args[1]))),
        ImportFastOp::ExactEqual => Some(boolean(hot_eq_exact(args[0], args[1]))),
        ImportFastOp::ExactNotEqual => Some(boolean(!hot_eq_exact(args[0], args[1]))),
        _ => return Ok(false),
    };
    if let Some(value) = value {
        p.gc_live = live;
        write_fast_x(p, dst, value)?;
        p.ip += 1;
        return Ok(true);
    }
    if fail.kind() == Arg::LABEL && fail.value() != u32::MAX as u64 {
        p.ip = fail.value() as usize;
        return Ok(true);
    }
    let function = match import.fast_op {
        ImportFastOp::IsInteger => "is_integer",
        ImportFastOp::IsFloat => "is_float",
        ImportFastOp::IsNumber => "is_number",
        ImportFastOp::IsAtom => "is_atom",
        ImportFastOp::IsTuple => "is_tuple",
        ImportFastOp::IsList => "is_list",
        ImportFastOp::IsMap => "is_map",
        ImportFastOp::IsFunction => "is_function",
        ImportFastOp::TupleSize => "tuple_size",
        ImportFastOp::Less => "<",
        ImportFastOp::LessEqual => "=<",
        ImportFastOp::Greater => ">",
        ImportFastOp::GreaterEqual => ">=",
        ImportFastOp::Equal => "==",
        ImportFastOp::NotEqual => "/=",
        ImportFastOp::ExactEqual => "=:=",
        ImportFastOp::ExactNotEqual => "=/=",
        _ => return Ok(false),
    };
    Err(exceptions::bif_error(
        p,
        "erlang",
        function,
        &args[..arity],
        arinsal_bifs::BifError::BADARG,
    ))
}

#[inline(always)]
fn boolean(value: bool) -> Term {
    Term::atom(if value {
        arinsal_term::atoms::TRUE
    } else {
        arinsal_term::atoms::FALSE
    })
}

#[inline(always)]
fn is_integer_term(term: Term) -> bool {
    term.as_small().is_some()
        || matches!(term.header().map(|header| header & 63), Some(0x08 | 0x0c))
}

#[inline(always)]
fn is_float_term(term: Term) -> bool {
    term.header().is_some_and(|header| header & 63 == 0x18)
}

pub(crate) fn gc_stress_enabled() -> bool {
    static GC_STRESS: OnceLock<bool> = OnceLock::new();
    *GC_STRESS.get_or_init(|| {
        std::env::var_os("ARINSAL_GC_STRESS").as_deref() == Some(std::ffi::OsStr::new("1"))
    })
}

#[inline]
fn function_index_at(module: &Module, ip: usize) -> Option<usize> {
    let index = *module.on_entry_fn.get(ip)?;
    (index != u32::MAX).then_some(index as usize)
}

#[inline]
fn instruction_offset(base: *const Instr, ip: *const Instr) -> usize {
    (ip as usize - base as usize) / std::mem::size_of::<Instr>()
}

fn debug_line_system_limit() -> VmError {
    let atom = arinsal_term::global_atoms()
        .intern("system_limit")
        .expect("system_limit is a built-in atom");
    VmError::Trap(exceptions::Trap::error(Term::atom(atom)))
}

#[cfg(feature = "pf-mem-counters")]
static PF_SPAWN_CONSTRUCTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(feature = "pf-mem-counters")]
static PF_SPAWN_CONSTRUCT_NS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn ensure_register_file(need: (usize, usize), p: &mut Process) -> (*mut Term, *mut f64) {
    let (need_x, need_fr) = need;
    if p.x.len() < need_x {
        let mut registers = p.x.to_vec();
        registers.resize(need_x, Term::NIL);
        p.x = registers.into_boxed_slice();
    }
    if p.fr.len() < need_fr {
        let mut registers = p.fr.to_vec();
        registers.resize(need_fr, 0.0);
        p.fr = registers.into_boxed_slice();
    }
    (p.x.as_mut_ptr(), p.fr.as_mut_ptr())
}

/// Locals carried across a streak of specialized instructions.
struct HotCursor {
    ip: *const Instr,
    htop: *mut u64,
    reds: i32,
    consumed: u32,
    gc_live: usize,
    heap_dirty: bool,
}

/// Pointers that stay fixed for one fast streak. Bundled so `exec_hot` stays
/// under clippy's argument limit; the body copies them into locals.
struct HotFixed {
    base: *const Instr,
    x: *mut Term,
    stop: *mut u64,
    budget: u32,
    entry_arity: *const u16,
    #[cfg(feature = "instr-count")]
    count_stats: *mut ProcessStats,
    #[cfg(any(feature = "validate-terms", debug_assertions))]
    module: *const Module,
}

/// Run specialized instructions until the budget ends or the next opcode needs
/// the full interpreter. Kept out of line so the giant match does not force
/// spills on this loop.
#[inline(never)]
fn exec_hot(cursor: HotCursor, fixed: HotFixed) -> HotCursor {
    let HotCursor {
        mut ip,
        mut htop,
        mut reds,
        mut consumed,
        mut gc_live,
        mut heap_dirty,
    } = cursor;
    let HotFixed {
        base,
        x,
        stop,
        budget,
        entry_arity,
        #[cfg(feature = "instr-count")]
        count_stats,
        #[cfg(any(feature = "validate-terms", debug_assertions))]
        module,
    } = fixed;
    loop {
        if consumed == budget {
            break;
        }
        // SAFETY: The caller keeps `ip` inside this module's code, which ends
        // with CodeEnd, and only passes targets the loader resolved.
        let instr = unsafe { &*ip };
        #[cfg(any(feature = "validate-terms", debug_assertions))]
        {
            // SAFETY: `ip` and `base` belong to the same code allocation.
            let offset = unsafe { ip.offset_from(base) } as usize;
            // SAFETY: `module` is the module that owns `base` for this streak.
            publish_term_context(unsafe { &*module }, offset, *instr);
        }
        let handled = match instr {
            Instr::MoveXX { src, dst } => {
                // SAFETY: Specialization validates both register indices below 1024.
                unsafe { *x.add(*dst as usize) = *x.add(*src as usize) };
                ip = hot_next(ip);
                true
            }
            Instr::MoveCX { value, dst } => {
                // SAFETY: Specialization validates the X index below 1024.
                unsafe { *x.add(*dst as usize) = *value };
                ip = hot_next(ip);
                true
            }
            Instr::IsEqExactXC { a, b, fail } => {
                // SAFETY: Specialization validates the X index below 1024.
                let left = unsafe { *x.add(*a as usize) };
                match hot_branch(ip, base, *fail, hot_eq_exact(left, *b)) {
                    Some(next) => {
                        ip = next;
                        true
                    }
                    None => false,
                }
            }
            Instr::IsEqExactXX { a, b, fail } => {
                // SAFETY: Specialization validates both X indices below 1024.
                let (left, right) = unsafe { (*x.add(*a as usize), *x.add(*b as usize)) };
                match hot_branch(ip, base, *fail, hot_eq_exact(left, right)) {
                    Some(next) => {
                        ip = next;
                        true
                    }
                    None => false,
                }
            }
            Instr::IsLtXC { a, b, fail } => {
                // SAFETY: Specialization validates the X index below 1024.
                let left = unsafe { *x.add(*a as usize) };
                match hot_branch(ip, base, *fail, compare::lt(left, *b)) {
                    Some(next) => {
                        ip = next;
                        true
                    }
                    None => false,
                }
            }
            Instr::IsLtXX { a, b, fail } => {
                // SAFETY: Specialization validates both X indices below 1024.
                let (left, right) = unsafe { (*x.add(*a as usize), *x.add(*b as usize)) };
                match hot_branch(ip, base, *fail, compare::lt(left, right)) {
                    Some(next) => {
                        ip = next;
                        true
                    }
                    None => false,
                }
            }
            Instr::IsNilX { src, fail } => {
                // SAFETY: Specialization validates the X index below 1024.
                let term = unsafe { *x.add(*src as usize) };
                match hot_branch(ip, base, *fail, term == Term::NIL) {
                    Some(next) => {
                        ip = next;
                        true
                    }
                    None => false,
                }
            }
            Instr::IsNonemptyListX { src, fail } => {
                // SAFETY: Specialization validates the X index below 1024.
                let term = unsafe { *x.add(*src as usize) };
                // Cons cells are the only terms with primary tag 1, so this
                // matches `classify() == List` without the full classifier.
                // SAFETY: The tag test reads the register word only.
                let is_list = unsafe { term.raw_bits() } & 3 == 1;
                match hot_branch(ip, base, *fail, is_list) {
                    Some(next) => {
                        ip = next;
                        true
                    }
                    None => false,
                }
            }
            Instr::ArithRC {
                kind,
                src,
                from_y,
                value,
                dst,
                ..
            } => {
                if *from_y {
                    false
                } else {
                    // SAFETY: Specialization validates the X index below 1024.
                    let left = unsafe { *x.add(*src as usize) };
                    if let Some(result) = arith::small(*kind, left, *value) {
                        // SAFETY: Specialization validates the destination X index.
                        unsafe { *x.add(*dst as usize) = result };
                        // SAFETY: Fallthrough stays inside the code allocation.
                        ip = hot_next(ip);
                        true
                    } else {
                        false
                    }
                }
            }
            Instr::ArithXXX {
                kind, a, b, dst, ..
            } => {
                // SAFETY: Specialization validates all X indices below 1024.
                let (left, right) = unsafe { (*x.add(*a as usize), *x.add(*b as usize)) };
                if let Some(result) = arith::small(*kind, left, right) {
                    // SAFETY: Specialization validates the destination X index.
                    unsafe { *x.add(*dst as usize) = result };
                    // SAFETY: Fallthrough stays inside the code allocation.
                    ip = hot_next(ip);
                    true
                } else {
                    false
                }
            }
            Instr::CallOnly { target } => {
                let slot = *target as usize;
                // SAFETY: The loader resolves call targets inside the code,
                // and the table has one slot per code instruction.
                let packed = unsafe { *entry_arity.add(slot) };
                if packed == 0 {
                    false
                } else {
                    gc_live = (packed - 1) as usize;
                    reds -= 1;
                    if reds == 0 {
                        reds = 4000;
                    }
                    // SAFETY: The loader resolved the local call target.
                    ip = unsafe { base.add(slot) };
                    true
                }
            }
            Instr::TestHeap { words, live } => {
                if stop as usize - (htop as usize) < *words as usize * 8 {
                    false
                } else {
                    gc_live = *live as usize;
                    ip = hot_next(ip);
                    true
                }
            }
            Instr::PutListXXX { head, tail, dst } => {
                if stop as usize - (htop as usize) < 16 {
                    false
                } else if let Some(ptr) = cursor_alloc(&mut htop, stop, 2) {
                    // SAFETY: Specialization validates all X indices below 1024.
                    let (head, tail) = unsafe { (*x.add(*head as usize), *x.add(*tail as usize)) };
                    heap_dirty = true;
                    let list = lists::cons(ptr, head, tail);
                    // SAFETY: Specialization validates the destination X index.
                    unsafe { *x.add(*dst as usize) = list };
                    // SAFETY: Fallthrough stays inside the code allocation.
                    ip = hot_next(ip);
                    true
                } else {
                    false
                }
            }
            Instr::GetListXXX { src, head, tail } => {
                // SAFETY: Specialization validates the source X index.
                let list = unsafe { *x.add(*src as usize) };
                if let Some((hd, tl)) = lists::split(list) {
                    // SAFETY: Specialization validates both destinations.
                    unsafe {
                        *x.add(*head as usize) = hd;
                        *x.add(*tail as usize) = tl;
                    }
                    ip = hot_next(ip);
                    true
                } else {
                    false
                }
            }
            Instr::GetTupleElementXX { src, index, dst } => {
                // SAFETY: Specialization validates the source X index.
                let tuple = unsafe { *x.add(*src as usize) };
                if let Some(value) = tuples::element(tuple, *index as usize) {
                    // SAFETY: Specialization validates the destination X index.
                    unsafe { *x.add(*dst as usize) = value };
                    ip = hot_next(ip);
                    true
                } else {
                    false
                }
            }
            _ => false,
        };
        if !handled {
            break;
        }
        consumed += 1;
        #[cfg(feature = "instr-count")]
        {
            // SAFETY: The counter pointer is the running process stats.
            let stats = unsafe { &mut *count_stats };
            stats.instructions += 1;
            let name = match instr {
                Instr::MoveXX { .. } | Instr::MoveCX { .. } => "move",
                Instr::IsEqExactXC { .. } | Instr::IsEqExactXX { .. } => "is_eq_exact",
                Instr::IsLtXC { .. } | Instr::IsLtXX { .. } => "is_lt",
                Instr::IsNilX { .. } => "is_nil",
                Instr::IsNonemptyListX { .. } => "is_nonempty_list",
                Instr::ArithRC { .. } | Instr::ArithXXX { .. } => "gc_bif2",
                Instr::CallOnly { .. } => "call_only",
                Instr::TestHeap { .. } => "test_heap",
                Instr::PutListXXX { .. } => "put_list",
                Instr::GetListXXX { .. } => "get_list",
                Instr::GetTupleElementXX { .. } => "get_tuple_element",
                _ => "specialized",
            };
            *stats.opcodes.entry(name).or_insert(0) += 1;
        }
    }
    HotCursor {
        ip,
        htop,
        reds,
        consumed,
        gc_live,
        heap_dirty,
    }
}

#[inline(always)]
fn hot_eq_exact(a: Term, b: Term) -> bool {
    if a == b {
        return true;
    }
    if a.as_small().is_some() && b.as_small().is_some() {
        return false;
    }
    compare::eq_exact(a, b)
}

fn hot_next(ip: *const Instr) -> *const Instr {
    // SAFETY: Fallthrough stays inside the code allocation, which ends in CodeEnd.
    unsafe { ip.add(1) }
}

#[inline(always)]
fn hot_prefix(instr: Instr) -> bool {
    matches!(
        instr,
        Instr::MoveXX { .. }
            | Instr::MoveCX { .. }
            | Instr::IsEqExactXC { .. }
            | Instr::IsEqExactXX { .. }
            | Instr::IsLtXC { .. }
            | Instr::IsLtXX { .. }
            | Instr::IsNilX { .. }
            | Instr::IsNonemptyListX { .. }
            | Instr::ArithRC { .. }
            | Instr::ArithXXX { .. }
            | Instr::CallOnly { .. }
            | Instr::TestHeap { .. }
            | Instr::PutListXXX { .. }
            | Instr::GetListXXX { .. }
            | Instr::GetTupleElementXX { .. }
    )
}

fn hot_branch(ip: *const Instr, base: *const Instr, fail: u32, ok: bool) -> Option<*const Instr> {
    if ok {
        // SAFETY: Fallthrough stays inside the code allocation, which has CodeEnd.
        Some(unsafe { ip.add(1) })
    } else if fail == u32::MAX {
        None
    } else {
        // SAFETY: Nonzero failure labels are resolved within this module.
        Some(unsafe { base.add(fail as usize) })
    }
}

#[inline(always)]
fn cursor_alloc(top: &mut *mut u64, stop: *mut u64, words: usize) -> Option<*mut u64> {
    if (stop as usize - *top as usize) < words * 8 {
        return None;
    }
    let ptr = *top;
    // SAFETY: The capacity check keeps the cursor at or below the stack boundary.
    *top = unsafe { (*top).add(words) };
    Some(ptr)
}

#[inline(always)]
fn sync_cursor(p: &mut Process, top: *mut u64, dirty: &mut bool) {
    if *dirty {
        p.heap.set_heap_top(top);
        *dirty = false;
    }
}

// g_asan
#[cfg(any(feature = "validate-terms", debug_assertions))]
#[inline]
fn publish_term_context(module: &Module, ip: usize, instr: Instr) {
    if !arinsal_term::validate::active() {
        return;
    }
    publish_term_context_slow(module, ip, instr);
}

// g_asan
#[cfg(any(feature = "validate-terms", debug_assertions))]
#[cold]
fn publish_term_context_slow(module: &Module, ip: usize, instr: Instr) {
    let (function, arity) = module.function_at(ip).unwrap_or(("?", 0));
    let opcode = match instr {
        Instr::Generic(index) => module
            .generic
            .get(index as usize)
            .map(|op| op.opcode().name())
            .unwrap_or("generic"),
        _ => instr_name(instr),
    };
    arinsal_term::validate::set_context(&format!("{}:{function}/{arity} {opcode}", module.name));
}

pub(crate) fn instr_name(instr: Instr) -> &'static str {
    match instr {
        Instr::CoverageProbe { .. } => "coverage_probe",
        Instr::MoveXX { .. }
        | Instr::MoveYX { .. }
        | Instr::MoveXY { .. }
        | Instr::MoveYY { .. }
        | Instr::MoveCX { .. }
        | Instr::MoveCY { .. } => "move",
        Instr::SwapXX { .. } | Instr::SwapYX { .. } => "swap",
        Instr::MoveCallLocal { .. } => "move",
        Instr::ReturnInstr => "return",
        Instr::NativeBody { .. } => "native_body",
        Instr::DeallocateReturn { .. } => "deallocate",
        Instr::Jump { .. } => "jump",
        Instr::CallLocal { .. } => "call",
        Instr::CallLast { .. } => "call_last",
        Instr::CallOnly { .. } => "call_only",
        Instr::CallBif { tail: true, .. } => "call_light_bif_only",
        Instr::CallBif { .. } => "call_light_bif",
        Instr::CallExternal { tail: true, .. } => "call_ext_only",
        Instr::CallExternal { .. } => "call_ext",
        Instr::DebugLine { .. } => "debug_line",
        Instr::DebugLineCleanup { .. } => "debug_line_cleanup",
        Instr::Allocate { .. } => "allocate",
        Instr::Deallocate { .. } => "deallocate",
        Instr::Trim { .. } => "trim",
        Instr::InitYregs { .. } => "init_yregs",
        Instr::TestHeap { .. } => "test_heap",
        Instr::IsLtXX { .. } | Instr::IsLtXC { .. } | Instr::IsLtCX { .. } => "is_lt",
        Instr::IsLtXCReturn { .. } => "is_lt",
        Instr::IsGeXX { .. } | Instr::IsGeXC { .. } | Instr::IsGeCX { .. } => "is_ge",
        Instr::IsEqXX { .. } | Instr::IsEqXC { .. } | Instr::IsEqCX { .. } => "is_eq",
        Instr::IsNeXX { .. } | Instr::IsNeXC { .. } | Instr::IsNeCX { .. } => "is_ne",
        Instr::IsEqExactXX { .. } | Instr::IsEqExactXC { .. } | Instr::IsEqExactCX { .. } => {
            "is_eq_exact"
        }
        Instr::IsNeExactXX { .. } | Instr::IsNeExactXC { .. } | Instr::IsNeExactCX { .. } => {
            "is_ne_exact"
        }
        Instr::Fadd { .. } => "fadd",
        Instr::Fsub { .. } => "fsub",
        Instr::Fmul { .. } => "fmul",
        Instr::Fdiv { .. } => "fdiv",
        Instr::FloatBin { kind, .. } => kind.name(),
        Instr::GetTupleElementXX { .. }
        | Instr::GetTupleElementYX { .. }
        | Instr::GetTupleElementXY { .. } => "get_tuple_element",
        Instr::GetTupleFloat { .. } => "get_tuple_element",
        Instr::PutTupleXX { .. } | Instr::PutTuple { .. } => "put_tuple2",
        Instr::PutListXXX { .. } | Instr::PutList { .. } => "put_list",
        Instr::GetListXXX { .. } | Instr::GetList { .. } => "get_list",
        Instr::GetHdXX { .. } => "get_hd",
        Instr::GetTlXX { .. } => "get_tl",
        Instr::ArithXXX { .. }
        | Instr::ArithYXX { .. }
        | Instr::ArithRC { .. }
        | Instr::ArithRCY { .. } => "gc_bif2",
        Instr::FmoveXFr { .. }
        | Instr::FmoveYFr { .. }
        | Instr::FmoveCFr { .. }
        | Instr::FmoveFrX { .. }
        | Instr::FmoveFrY { .. }
        | Instr::FmoveFrFr { .. } => "fmove",
        Instr::IsTupleX { .. } => "is_tuple",
        Instr::IsTupleOfArity { .. } => "is_tuple",
        Instr::IsNilX { .. } => "is_nil",
        Instr::IsNonemptyListX { .. } => "is_nonempty_list",
        Instr::IsIntegerX { .. } => "is_integer",
        Instr::TestArityX { .. } => "test_arity",
        Instr::Generic(_) | Instr::Unsupported(_) => "unsupported",
        // ---- vm_maps_bits ----
        Instr::MapsBits(_) => "maps_bits",
        // vm_binparse
        Instr::BsEnsure { .. }
        | Instr::BsReadU32 { .. }
        | Instr::BsReadUint { .. }
        | Instr::BsAppendByte { .. }
        | Instr::BsBinaryReg { .. }
        | Instr::BsTail { .. }
        | Instr::BsMatchTail { .. } => "bs_match",
        Instr::BsStartReuse { .. } => "bs_start_match3",
        Instr::BsPositionSmall { .. } => "bs_get_position",
        // ---- vm_exc ----
        Instr::Exc { op, .. } => op.name(),
        Instr::CodeEnd => "int_code_end",
        Instr::Select {
            tuple_arity: true, ..
        } => "select_tuple_arity",
        Instr::Select { .. } => "select_val",
        // ---- vm_funs ----
        Instr::MakeFun { .. } => "make_fun3",
        Instr::CallFun { .. } => "call_fun",
        Instr::Apply { .. } => "apply",
        Instr::IsFunction2 { .. } => "is_function2",
        _ => "specialized",
    }
}

pub(crate) enum RunState {
    Done(Term),
    Yield,
    Wait { timeout_ms: Option<u64> },
}

// Port of erts/emulator/beam/beam_bp.c:1242-1268, OTP-29.1.1.
fn push_trace_frames(
    process: &mut Process,
    module_id: usize,
    entry_ip: usize,
    return_trace_ip: usize,
    return_to_ip: usize,
    actions: &[crate::trace::CallActions],
) -> Result<(), VmError> {
    for action in actions.iter().rev().filter(|action| action.return_to) {
        if !process.heap.reserve_stack(2) {
            return Err(VmError::Unsupported("return_to trace stack".into()));
        }
        process
            .heap
            .stack_set(0, trace_continuation(module_id, return_to_ip)?);
        process.heap.stack_set(
            1,
            Term::small(
                i64::try_from(action.session)
                    .map_err(|_| VmError::Unsupported("trace session stack value".into()))?,
            )
            .ok_or_else(|| VmError::Unsupported("trace session stack value".into()))?,
        );
    }
    for action in actions {
        if !action.return_trace && !action.exception_trace {
            continue;
        }
        if !process.heap.reserve_stack(6) {
            return Err(VmError::Unsupported("call trace stack".into()));
        }
        process
            .heap
            .stack_set(0, trace_continuation(module_id, return_trace_ip)?);
        for (index, value) in [
            module_id,
            entry_ip,
            (action.session >> 32) as usize,
            action.session as u32 as usize,
            usize::from(action.exception_trace),
        ]
        .into_iter()
        .enumerate()
        {
            process.heap.stack_set(
                index + 1,
                Term::small(
                    i64::try_from(value)
                        .map_err(|_| VmError::Unsupported("trace frame stack value".into()))?,
                )
                .ok_or_else(|| VmError::Unsupported("trace frame stack value".into()))?,
            );
        }
    }
    Ok(())
}

fn trace_continuation(module_id: usize, target: usize) -> Result<Term, VmError> {
    let module = u32::try_from(module_id)
        .map_err(|_| VmError::Unsupported("trace continuation module".into()))?;
    let target = u32::try_from(target)
        .map_err(|_| VmError::Unsupported("trace continuation target".into()))?;
    Ok(Term::catch(((module as u64) << 32) | u64::from(target)))
}

#[allow(clippy::too_many_arguments)] // Breakpoint metadata stays explicit at the interpreter boundary.
fn trace_breakpoint_call(
    vm: &mut Vm,
    process: &mut Process,
    ctx: Option<&mut arinsal_sched::RunCtx<'_, process::Message>>,
    module_id: usize,
    entry_ip: usize,
    function: &str,
    arity: u8,
    local: bool,
) -> Result<Vec<crate::trace::CallActions>, VmError> {
    crate::trace_bp::increment(process, &vm.modules[module_id].name, function, arity, local);
    let Some(ctx) = ctx else {
        return Ok(Vec::new());
    };
    let args = process.x[..usize::from(arity)].to_vec();
    let module_name = vm.modules[module_id].name.clone();
    let actions = crate::trace::call_event(vm, process, ctx, &module_name, function, &args, local)?;
    push_trace_frames(
        process,
        module_id,
        entry_ip,
        vm.modules[module_id].return_trace_ip,
        vm.modules[module_id].return_to_trace_ip,
        &actions,
    )?;
    Ok(actions)
}

impl Vm {
    /// Execute one exported function in a fresh process.
    pub fn eval(
        &mut self,
        module: &str,
        function: &str,
        args: &[Term],
    ) -> Result<EvalResult, VmError> {
        // ---- vm_funs ----
        if module == "erlang"
            && let Some(result) = self.eval_erlang_fun_builtin(function, args)
        {
            return result;
        }
        if args.len() > 1024 {
            return Err(VmError::Unsupported("more than 1024 arguments".into()));
        }
        let mut process = Process::new();
        let frame = format!("{module}:{function}/{}", args.len());
        let result = if let Some(bif) = arinsal_bifs::lookup(module, function, args.len() as u8)
            .or_else(|| natives::static_nif_lookup(module, function, args.len() as u8))
        {
            let result = {
                let mut heap = FragmentingHeap(&mut process.heap);
                let mut ctx = Ctx::new(&mut heap);
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| bif(&mut ctx, args)))
                    .map_err(|_| VmError::Unsupported(format!("BIF {frame} panicked")))?
            };
            // ---- vm_exc ----
            Some(result.map_err(|e| {
                exceptions::direct_bif_error(&mut process, module, function, args, e)
            })?)
        } else {
            None
        };
        if let Some(term) = result {
            process.stats.heap_words = process.heap.capacity_words();
            return Ok(EvalResult {
                term,
                stats: process.stats.snapshot(),
                _process: process,
            });
        }
        if arinsal_spec::bif_lookup(module, function, args.len() as u8).is_some() {
            return Err(VmError::Unsupported(format!("BIF {frame}")));
        }
        let module_id = self.load_named(module)?;
        let ip = self.modules[module_id]
            .export(function, args.len() as u8)
            .ok_or_else(|| VmError::Exception {
                reason: "undef".into(),
                frame: format!("{module}:{function}/{}", args.len()),
            })?;
        process.module = module_id;
        process.ip = ip;
        process.x[..args.len()].copy_from_slice(args);
        // ---- vm_exc ----
        let result = loop {
            match self.run(&mut process) {
                Ok(value) => break value,
                Err(VmError::Trap(trap)) => {
                    if let Some(error) = exceptions::resume(self, &mut process, None, trap)? {
                        return Err(error);
                    }
                }
                Err(VmError::Exception { reason, .. }) => {
                    let trap = exceptions::from_legacy(&reason)?;
                    if let Some(error) = exceptions::resume(self, &mut process, None, trap)? {
                        return Err(error);
                    }
                }
                Err(VmError::ExceptionInfo { reason, info, .. }) => {
                    let mut trap = exceptions::from_legacy(&reason)?;
                    let arity = self.modules[process.module]
                        .function_at(process.ip)
                        .map(|(_, arity)| arity)
                        .unwrap_or(0);
                    trap.top = Some(crate::stacktrace::TopFrame::CurrentArgsWithInfo(
                        Term::small(i64::from(arity)).expect("arity is small"),
                        Box::new(info),
                    ));
                    if let Some(error) = exceptions::resume(self, &mut process, None, trap)? {
                        return Err(error);
                    }
                }
                Err(error) => return Err(error),
            }
        };
        process.stats.heap_words = process.heap.capacity_words();
        Ok(EvalResult {
            term: result,
            stats: process.stats.snapshot(),
            _process: process,
        })
    }
    pub(crate) fn frame_name(&self, p: &Process) -> String {
        let module = &self.modules[p.module];
        let (name, arity) = module.function_at(p.ip).unwrap_or(("?", 0));
        format!("{}:{name}/{arity}", module.name)
    }
    pub(crate) fn exception(&self, p: &Process, reason: impl Into<String>) -> VmError {
        let reason = reason.into();
        VmError::Exception {
            reason,
            frame: self.frame_name(p),
        }
    }
    pub(crate) fn run(&mut self, p: &mut Process) -> Result<Term, VmError> {
        loop {
            match self.run_slice(p, None, u32::MAX)? {
                RunState::Done(term) => return Ok(term),
                RunState::Yield => continue,
                RunState::Wait { .. } => {
                    return Err(VmError::Unsupported("receive requires a scheduler".into()));
                }
            }
        }
    }

    /// Drain the ingress and report whether `wait` / `wait_timeout` may block.
    ///
    /// A scheduling quantum can expire on the wait instruction after `loop_rec`
    /// has already observed an empty mailbox. The next slice drains before that
    /// instruction runs, which would otherwise sleep with the message queued.
    pub(crate) fn mailbox_ready_to_wait(
        process: &mut Process,
        ctx: &mut Option<&mut arinsal_sched::RunCtx<'_, process::Message>>,
    ) -> Result<bool, VmError> {
        let ctx = ctx
            .as_deref_mut()
            .ok_or_else(|| VmError::Unsupported("receive requires a scheduler".into()))?;
        process.drain(ctx)?;
        Ok(process.receive_cursor >= process.inbox.len())
    }

    pub(crate) fn run_slice(
        &mut self,
        p: &mut Process,
        ctx: Option<&mut arinsal_sched::RunCtx<'_, process::Message>>,
        budget: u32,
    ) -> Result<RunState, VmError> {
        let result = self.run_slice_inner(p, ctx, budget);
        result.map_err(|error| {
            let Some(module) = self.modules.get(p.module) else {
                return error;
            };
            let Some(&instr) = module.code.get(p.ip) else {
                return error;
            };
            let (function, arity) = module.function_at(p.ip).unwrap_or(("?", 0));
            let opcode = match instr {
                Instr::Generic(index) => module.generic[index as usize].opcode().name(),
                _ => instr_name(instr),
            };
            let context = format!("{}:{function}/{arity} {opcode}", module.name);
            match error {
                VmError::Unsupported(message) => {
                    VmError::Unsupported(format!("{context}: {message}"))
                }
                VmError::Load(message) => VmError::Load(format!("{context}: {message}")),
                other => other,
            }
        })
    }

    pub(crate) fn run_slice_inner(
        &mut self,
        p: &mut Process,
        mut ctx: Option<&mut arinsal_sched::RunCtx<'_, process::Message>>,
        budget: u32,
    ) -> Result<RunState, VmError> {
        self.sync_code_epoch();
        // A migrated process may already be inside a module this replica has
        // not copied yet. Sync only when the id is past the local table.
        self.sync_module(p.module);
        let mut module_id = p.module;
        if module_id >= self.modules.len() {
            return Err(VmError::Unsupported(format!(
                "process module {module_id} is not loaded on this scheduler"
            )));
        }
        let (need_x, need_fr) = self.registers[module_id];
        if p.x.len() < need_x {
            let mut registers = p.x.to_vec();
            registers.resize(need_x, Term::NIL);
            p.x = registers.into_boxed_slice();
        }
        if p.fr.len() < need_fr {
            let mut registers = p.fr.to_vec();
            registers.resize(need_fr, 0.0);
            p.fr = registers.into_boxed_slice();
        }
        let mut base = self.modules[module_id].code.as_ptr();
        let mut ip = {
            // SAFETY: Export indices are resolved to this code allocation by the loader.
            unsafe { base.add(p.ip) }
        };
        let mut x = p.x.as_mut_ptr();
        let mut fr = p.fr.as_mut_ptr();
        let (mut htop, mut stop) = p.heap.heap_cursor();
        let mut heap_dirty = false;
        let mut depth = p.heap.stack_words();
        let mut reds = p.reductions;
        let mut consumed = 0_u32;
        macro_rules! compare_branch {
            ($ok:expr, $fail:expr) => {
                if !$ok {
                    if $fail == u32::MAX {
                        return Err(VmError::Unsupported("failure label zero".into()));
                    }
                    // SAFETY: Nonzero failure labels are resolved within this module.
                    ip = unsafe { base.add($fail as usize) };
                    continue;
                }
            };
        }
        macro_rules! count_second {
            ($name:literal) => {
                #[cfg(feature = "instr-count")]
                {
                    p.stats.instructions += 1;
                    *p.stats.opcodes.entry($name).or_insert(0) += 1;
                }
            };
        }
        macro_rules! float_bin {
            ($a:expr, $b:expr, $dst:expr, $op:tt) => {{
                // SAFETY: Specialization validates all FR indices below 1024.
                let (lhs, rhs) = unsafe { (*fr.add($a as usize), *fr.add($b as usize)) };
                let value = lhs $op rhs;
                if !value.is_finite() {
                    return Err(self.exception(p, "badarith"));
                }
                // SAFETY: Specialization validates the destination FR index.
                unsafe { *fr.add($dst as usize) = value };
            }};
        }
        macro_rules! return_from_frame {
            ($charge:expr) => {{
                if $charge {
                    reds -= 1;
                    if reds == 0 {
                        reds = 4000;
                    }
                }
                let mut cp = p.heap.stack_get(0).map_or(0, Term::tagged_word);
                while cp as usize
                    == arinsal_beamasm::rt::arinsal_enter_native_return as *const () as usize
                {
                    if !p.heap.release_stack(1) {
                        return Err(VmError::Unsupported("stack underflow".into()));
                    }
                    // The bridge CP is a real Erlang-stack word. Keep the
                    // interpreter cursor aligned before resuming the BEAM CP.
                    depth = depth.saturating_sub(1);
                    stop = p.heap.heap_cursor().1;
                    if p.heap.heap_cursor().1 == p.heap.heap_bounds().1 {
                        return Ok(RunState::Done(p.x[0]));
                    }
                    cp = p.heap.stack_get(0).map_or(0, Term::tagged_word);
                }
                if crate::native_bridge::is_native_function_at(cp as usize) {
                    sync_cursor(p, htop, &mut heap_dirty);
                    p.reductions = reds;
                    p.heap.release_stack(1);
                    p.cold_mut().native_continuation_resume = true;
                    p.native_pc = Some(cp as usize);
                    return Ok(RunState::Yield);
                }
                if depth == 0 {
                    sync_cursor(p, htop, &mut heap_dirty);
                    p.reductions = reds;
                    return Ok(RunState::Done(p.x[0]));
                }
                if cp & 63 != 0x1b {
                    sync_cursor(p, htop, &mut heap_dirty);
                    p.reductions = reds;
                    return Ok(RunState::Done(p.x[0]));
                }
                let payload = cp >> 6;
                let target = payload as u32 as usize;
                module_id = (payload >> 32) as usize;
                // The caller module may have been published after this slice
                // started, on another scheduler. `base` is replaced immediately.
                self.sync_module(module_id);
                if module_id >= self.modules.len() {
                    return Err(VmError::Unsupported(format!(
                        "return to missing module {module_id}"
                    )));
                }
                base = self.modules[module_id].code.as_ptr();
                p.heap.release_stack(1);
                depth -= 1;
                // SAFETY: The popped continuation occupied the first stack word.
                stop = unsafe { stop.add(1) };
                // SAFETY: Continuations were created from a valid next instruction.
                ip = unsafe { base.add(target) };
                continue;
            }};
        }
        let mut regs_module = usize::MAX;
        let mut module_handle = self.modules[module_id].clone();
        let mut module_epoch = self.seen_epoch;
        let mut handle_module = module_id;
        loop {
            if module_epoch != self.seen_epoch || handle_module != module_id {
                let same_module = handle_module == module_id;
                let active_offset = if same_module {
                    // SAFETY: `ip` is within the active module code allocation.
                    instruction_offset(base, ip)
                } else {
                    0
                };
                module_handle = self.modules[module_id].clone();
                if same_module {
                    base = module_handle.code.as_ptr();
                    // SAFETY: Breakpoint patching preserves instruction offsets.
                    ip = base.wrapping_add(active_offset);
                }
                module_epoch = self.seen_epoch;
                handle_module = module_id;
            }
            // Register windows change only when the process enters another module.
            if regs_module != module_id {
                (x, fr) = ensure_register_file(self.registers[module_id], p);
                regs_module = module_id;
            }
            let arity_ptr = self.modules[module_id].entry_arity.as_ptr();
            // Skip the fast loop when the next opcode is not in it. A cold
            // streak would otherwise pay a call that returns immediately.
            // SAFETY: `ip` addresses this module's code, which ends with CodeEnd.
            if hot_prefix(unsafe { *ip }) {
                let before = consumed;
                let cursor = exec_hot(
                    HotCursor {
                        ip,
                        htop,
                        reds,
                        consumed,
                        gc_live: p.gc_live,
                        heap_dirty,
                    },
                    HotFixed {
                        base,
                        x,
                        stop,
                        budget,
                        entry_arity: arity_ptr,
                        #[cfg(feature = "instr-count")]
                        count_stats: std::ptr::addr_of_mut!(p.stats),
                        #[cfg(any(feature = "validate-terms", debug_assertions))]
                        module: std::ptr::from_ref(&self.modules[module_id]),
                    },
                );
                ip = cursor.ip;
                htop = cursor.htop;
                reds = cursor.reds;
                consumed = cursor.consumed;
                p.gc_live = cursor.gc_live;
                heap_dirty = cursor.heap_dirty;
                let charge = consumed - before;
                if charge != 0
                    && let Some(context) = ctx.as_deref_mut()
                {
                    context.consume(charge);
                }
            }
            // ---- processes and messages ----
            let module = &self.modules[module_id];
            // SAFETY: The instruction pointer belongs to this module's code allocation.
            let offset = unsafe { ip.offset_from(base) } as usize;
            debug_assert!(
                offset < module.code.len(),
                "instruction pointer out of bounds"
            );
            if consumed == budget {
                sync_cursor(p, htop, &mut heap_dirty);
                p.module = module_id;
                p.ip = offset;
                p.reductions = reds;
                return Ok(RunState::Yield);
            }
            consumed += 1;
            if let Some(ctx) = ctx.as_deref_mut() {
                ctx.consume(1);
            }
            // SAFETY: The loader resolves branch targets within this allocation
            // and appends CodeEnd for a fallthrough past the last BEAM opcode.
            let fetched = unsafe { *ip };
            p.module = module_id;
            p.ip = offset;
            let module = module_handle.as_ref();
            let instr = fetched;
            p.reductions_used = p.reductions_used.saturating_add(1);
            #[cfg(feature = "instr-count")]
            {
                p.stats.instructions += 1;
                let name = match instr {
                    Instr::Generic(index) => {
                        *p.stats.opcodes.entry("generic").or_insert(0) += 1;
                        let name = module.generic[index as usize].opcode().name();
                        *p.stats.generic_opcodes.entry(name).or_insert(0) += 1;
                        name
                    }
                    _ => instr_name(instr),
                };
                *p.stats.opcodes.entry(name).or_insert(0) += 1;
            }
            // g_asan
            #[cfg(any(feature = "validate-terms", debug_assertions))]
            publish_term_context(module, offset, instr);
            macro_rules! normal_instruction_dispatch {
                ($instruction:expr; $($arms:tt)*) => {
                    match $instruction {
                        Instr::Breakpoint { .. } | Instr::ExportBreakpoint { .. } => {
                            return Err(VmError::Unsupported("nested trace breakpoint".into()));
                        }
                        $($arms)*
                    }
                };
            }
            macro_rules! traced_instruction_dispatch {
                ($instruction:expr; $($arms:tt)*) => {
                    match $instruction {
                        Instr::Breakpoint { index } => {
                            let entry_ip = index as usize;
                            let original = module
                                .breakpoint_originals
                                .get(&entry_ip)
                                .copied()
                                .ok_or_else(|| VmError::Unsupported("missing trace breakpoint data".into()))?;
                            let Some(function_index) = function_index_at(module, entry_ip) else {
                                return Err(VmError::Unsupported("trace breakpoint function".into()));
                            };
                            let (_, function, arity) = &module.functions[function_index];
                            let debug_break = crate::trace_bp::debug_breakpoint_enabled(
                                p,
                                &module.name,
                                function,
                                *arity,
                            );
                            let actions = trace_breakpoint_call(
                                self, p, ctx.as_deref_mut(), module_id, entry_ip, function, *arity, true,
                            )?;
                            if !actions.is_empty() || ctx.as_deref().is_some() {
                                (htop, stop) = p.heap.heap_cursor();
                                depth = p.heap.stack_words();
                                heap_dirty = false;
                            }
                            if debug_break {
                                let arity = usize::from(*arity);
                                p.gc_live = arity;
                                p.ensure(arity.saturating_mul(2), arity)?;
                                let module_atom = arinsal_term::global_atoms()
                                    .intern(&module.name)
                                    .map_err(|_| debug_line_system_limit())?;
                                let function_atom = arinsal_term::global_atoms()
                                    .intern(function)
                                    .map_err(|_| debug_line_system_limit())?;
                                let arguments = p.x[..arity].to_vec();
                                let argument_list = TermBuilder::new(
                                    &mut arinsal_bifs::FragmentingHeap(&mut p.heap),
                                )
                                .list_from_iter(arguments)
                                .map_err(|_| debug_line_system_limit())?;
                                p.x[0] = Term::atom(module_atom);
                                p.x[1] = Term::atom(function_atom);
                                p.x[2] = argument_list;
                                p.gc_live = 3;
                                p.module = module_id;
                                p.ip = entry_ip;
                                p.reductions = reds;
                                let breakpoint_import = module.debug_breakpoint_import as usize;
                                let outcome = self.call_import(
                                    p,
                                    breakpoint_import,
                                    3,
                                    true,
                                    ctx.as_deref_mut(),
                                )?;
                                module_id = p.module;
                                self.sync_module(module_id);
                                base = self.modules[module_id].code.as_ptr();
                                module_handle = self.modules[module_id].clone();
                                x = p.x.as_mut_ptr();
                                fr = p.fr.as_mut_ptr();
                                reds = p.reductions;
                                depth = p.heap.stack_words();
                                (htop, stop) = p.heap.heap_cursor();
                                match outcome {
                                    ImportOutcome::Returned(value) => {
                                        p.x[0] = value;
                                        return_from_frame!(true);
                                    }
                                    ImportOutcome::Yield => {
                                        sync_cursor(p, htop, &mut heap_dirty);
                                        return Ok(RunState::Yield);
                                    }
                                    ImportOutcome::Jump(target) => {
                                        if let Some(native) = self.beamasm_targets.function_for_target(
                                            module_id,
                                            &self.modules[module_id],
                                            instruction_offset(base, target),
                                        ) {
                                            sync_cursor(p, htop, &mut heap_dirty);
                                            p.native_pc = Some(native.start);
                                            return Ok(RunState::Yield);
                                        }
                                        ip = target;
                                    }
                                    ImportOutcome::Advanced => return_from_frame!(true),
                                }
                                continue;
                            }
                            normal_instruction_dispatch!(original; $($arms)*)
                        }
                        Instr::ExportBreakpoint { index } => {
                            let export_index = index as usize;
                            let Some(export) = module.exports.get(export_index) else {
                                return Err(VmError::Unsupported("export trace breakpoint".into()));
                            };
                            let target = *module
                                .export_entry_targets
                                .get(export_index)
                                .ok_or_else(|| VmError::Unsupported("export trace target".into()))?;
                            let function = export.function.clone();
                            let arity = export.arity;
                            let actions = trace_breakpoint_call(
                                self, p, ctx.as_deref_mut(), module_id, target, &function, arity, false,
                            )?;
                            if !actions.is_empty() || ctx.as_deref().is_some() {
                                (htop, stop) = p.heap.heap_cursor();
                                depth = p.heap.stack_words();
                                heap_dirty = false;
                            }
                            let Some(target) = module.code.get(target) else {
                                return Err(VmError::Unsupported("export trace target".into()));
                            };
                            ip = std::ptr::from_ref(target);
                            continue;
                        }
                        $($arms)*
                    }
                };
            }
            #[rustfmt::skip]
            traced_instruction_dispatch!(instr;
                Instr::ReturnTrace => {
                    let (Some(module), Some(entry), Some(session_high), Some(session_low), Some(_exception)) = (
                        p.heap.stack_get(0).and_then(Term::as_small),
                        p.heap.stack_get(1).and_then(Term::as_small),
                        p.heap.stack_get(2).and_then(Term::as_small),
                        p.heap.stack_get(3).and_then(Term::as_small),
                        p.heap.stack_get(4).and_then(Term::as_small),
                    ) else {
                        return Err(VmError::Unsupported("return trace frame".into()));
                    };
                    let session = ((session_high as u64) << 32) | session_low as u32 as u64;
                    if let Some(trace_ctx) = ctx.as_deref_mut() {
                        crate::trace::return_event(
                            self,
                            p,
                            trace_ctx,
                            session,
                            module as usize,
                            entry as usize,
                            p.x[0],
                            false,
                            None,
                        )?;
                    }
                    if !p.heap.release_stack(5) {
                        return Err(VmError::Unsupported("return trace stack".into()));
                    }
                    depth = depth.saturating_sub(5);
                    (htop, stop) = p.heap.heap_cursor();
                    heap_dirty = false;
                    return_from_frame!(false);
                }
                Instr::ReturnToTrace => {
                    let Some(session) = p.heap.stack_get(0).and_then(Term::as_small) else {
                        return Err(VmError::Unsupported("return_to trace frame".into()));
                    };
                    if let Some(trace_ctx) = ctx.as_deref_mut()
                        && let Some((false, module, target)) =
                            p.heap.stack_get(1).and_then(crate::stacktrace::decode_tag)
                    {
                        crate::trace::return_to_event(
                            self,
                            p,
                            trace_ctx,
                            module,
                            target,
                            session as u64,
                        )?;
                    }
                    if !p.heap.release_stack(1) {
                        return Err(VmError::Unsupported("return_to trace stack".into()));
                    }
                    depth = depth.saturating_sub(1);
                    (htop, stop) = p.heap.heap_cursor();
                    heap_dirty = false;
                    return_from_frame!(false);
                }
                Instr::CoverageProbe { index } => {
                    if let (Some(coverage), Some(probe)) = (
                        module.coverage.as_ref(),
                        module.coverage_probes.get(index as usize),
                    ) {
                        coverage.counters[probe.counter as usize]
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                Instr::NativeBody { index } => {
                    sync_cursor(p, htop, &mut heap_dirty);
                    let Some(native) = self.native_fns.get(index as usize).copied() else {
                        return Err(VmError::Unsupported(format!(
                            "native function index {index}"
                        )));
                    };
                    // SAFETY: `ip` remains within the active module code allocation.
                    let arity = self.modules[module_id]
                        .function_at(unsafe { ip.offset_from(base) } as usize)
                        .map(|(_, arity)| arity as usize)
                        .ok_or_else(|| VmError::Unsupported("native function entry".into()))?;
                    p.gc_live = arity;
                    // Local prim_tty NIFs never pass through the tty family, so the
                    // select owner has to be recorded here or input is delivered
                    // to whichever process last touched the thread-local slot.
                    // Other native bodies (erl_tracer) read the scheduler hub that
                    // import dispatch used to refresh on every call.
                    if let Some(run) = &mut ctx {
                        natives::refresh_hub(p, run);
                        if self.modules[module_id].name == "prim_tty" {
                            natives::tty::note_caller(p, run);
                        }
                    }
                    // Panic landing the previous native-body path used. The
                    // argument slice is not copied unless the body fails.
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        calls::call_bif(&mut p.heap, native, &p.x[..arity])
                    }));
                    let result = match result {
                        Ok(result) => result,
                        Err(_) => Err(arinsal_bifs::BifError::Error(Term::atom(
                            arinsal_term::global_atoms()
                                .intern("error")
                                .expect("built-in atom"),
                        ))),
                    };
                    let value = match result {
                        Ok(value) => value,
                        Err(error) => {
                            // SAFETY: The native body is executing inside this module's code.
                            let (function, _) = self.modules[module_id]
                                .function_at(unsafe { ip.offset_from(base) } as usize)
                                .unwrap_or(("?", arity as u8));
                            let arguments = p.x[..arity].to_vec();
                            return Err(exceptions::bif_error(
                                p,
                                &self.modules[module_id].name,
                                function,
                                &arguments,
                                error,
                            ));
                        }
                    };
                    p.x[0] = value;
                    (htop, stop) = p.heap.heap_cursor();
                    depth = p.heap.stack_words();
                    heap_dirty = false;
                    return_from_frame!(true);
                }
                Instr::MoveXX { src, dst } => {
                    // SAFETY: Specialization validates both register indices below 1024.
                    unsafe { *x.add(dst as usize) = *x.add(src as usize) };
                    // SAFETY: The next pointer is within or one past code; the loop checks it.
                    ip = hot_next(ip);
                    continue;
                }
                Instr::MoveCallLocal { src, dst, target } => {
                    // SAFETY: Specialization validates both X indices.
                    unsafe { *x.add(dst as usize) = *x.add(src as usize) };
                    count_second!("call");
                    // SAFETY: `ip` and `base` belong to the current module.
                    let offset = unsafe { ip.offset_from(base) } as usize;
                    sync_cursor(p, htop, &mut heap_dirty);
                    let arity = module
                        .function_at(target as usize)
                        .ok_or_else(|| VmError::Unsupported("local call target".into()))?
                        .1 as usize;
                    p.gc_live = arity;
                    if p.heap.free_words() == 0 {
                        p.ensure(1, arity)?;
                        (htop, stop) = p.heap.heap_cursor();
                    }
                    if !p.heap.reserve_stack(1) {
                        return Err(VmError::Unsupported("continuation stack".into()));
                    }
                    depth += 1;
                    // SAFETY: Reserving one stack word extends the live interval downward.
                    stop = unsafe { stop.sub(1) };
                    let cp = Term::catch(((module_id as u64) << 32) | ((offset + 2) as u64));
                    // SAFETY: The new stack slot is reserved and contains an immediate.
                    unsafe { *stop = cp.raw_bits() };
                    reds -= 1;
                    if reds == 0 {
                        reds = 4000;
                    }
                    // SAFETY: The loader resolved the local call target.
                    ip = unsafe { base.add(target as usize) };
                    continue;
                }
                Instr::MoveYX { src, dst } => {
                    if src as usize >= depth {
                        return Err(VmError::Unsupported("Y register".into()));
                    }
                    // SAFETY: The slot is within the live stack depth, which is
                    // refreshed whenever collection or stack movement occurs.
                    let value: Term =
                        unsafe { std::mem::transmute::<u64, Term>(*stop.add(src as usize)) };
                    // SAFETY: Specialization validates X index below 1024.
                    unsafe { *x.add(dst as usize) = value };
                }
                Instr::MoveXY { src, dst } => {
                    // SAFETY: Specialization validates X index below 1024.
                    let value = unsafe { *x.add(src as usize) };
                    if dst as usize >= depth {
                        return Err(VmError::Unsupported("Y register".into()));
                    }
                    // SAFETY: The destination is a live stack slot and `value` is a tagged word.
                    unsafe { *stop.add(dst as usize) = value.raw_bits() };
                }
                Instr::MoveYY { src, dst } => {
                    if src as usize >= depth || dst as usize >= depth {
                        return Err(VmError::Unsupported("Y register".into()));
                    }
                    // SAFETY: Both Y slots are live.
                    unsafe { *stop.add(dst as usize) = *stop.add(src as usize) };
                }
                Instr::MoveCX { value, dst } => {
                    // SAFETY: Specialization validates X index below 1024.
                    unsafe { *x.add(dst as usize) = value };
                }
                Instr::MoveCY { value, dst } => {
                    if dst as usize >= depth {
                        return Err(VmError::Unsupported("Y register".into()));
                    }
                    // SAFETY: The destination is a live stack slot and `value` is a tagged word.
                    unsafe { *stop.add(dst as usize) = value.raw_bits() };
                }
                Instr::SwapXX { a, b } => {
                    // SAFETY: Specialization validates both X indices below 1024.
                    unsafe { std::ptr::swap(x.add(a as usize), x.add(b as usize)) };
                }
                Instr::SwapYX { y, x: src } => {
                    if y as usize >= depth {
                        return Err(VmError::Unsupported("Y register".into()));
                    }
                    // SAFETY: The Y slot is live; specialization validates the X index.
                    unsafe {
                        let slot = stop.add(y as usize);
                        let value = (*x.add(src as usize)).raw_bits();
                        *x.add(src as usize) = std::mem::transmute::<u64, Term>(*slot);
                        *slot = value;
                    }
                }
                Instr::Jump { target } => {
                    // SAFETY: Loader-resolved labels designate instructions in this code allocation.
                    ip = unsafe { base.add(target as usize) };
                    continue;
                }
                Instr::DebugLine { line, live, import } => {
                    // Port of erts/emulator/beam/emu/instrs.tab:1265-1292, OTP-29.1.1.
                    if !crate::trace_bp::line_breakpoint_enabled(
                        p,
                        module_id,
                        line,
                    ) {
                        // The following cleanup belongs only to an enabled hit.
                        ip = hot_next(hot_next(ip));
                        continue;
                    }
                    sync_cursor(p, htop, &mut heap_dirty);
                    if !p.heap.reserve_stack(1) {
                        return Err(debug_line_system_limit());
                    }
                    let module_index = module_id as u64;
                    if module_index >= 1 << 26 {
                        return Err(debug_line_system_limit());
                    }
                    if !p.heap.stack_set(
                        0,
                        Term::catch((module_index << 32) | (offset as u64 + 1)),
                    ) {
                        return Err(debug_line_system_limit());
                    }
                    if !p.heap.reserve_stack(live as usize) {
                        return Err(debug_line_system_limit());
                    }
                    for index in 0..live as usize {
                        if !p.heap.stack_set(index, p.x[index]) {
                            return Err(debug_line_system_limit());
                        }
                    }
                    let (function, arity) = module
                        .function_at(offset)
                        .ok_or_else(debug_line_system_limit)?;
                    let module_atom = arinsal_term::global_atoms()
                        .intern(&module.name)
                        .map_err(|_| debug_line_system_limit())?;
                    let function_atom = arinsal_term::global_atoms()
                        .intern(function)
                        .map_err(|_| debug_line_system_limit())?;
                    p.x[0] = Term::atom(module_atom);
                    p.x[1] = Term::atom(function_atom);
                    p.x[2] = Term::small(i64::from(arity)).expect("arity is a small integer");
                    p.x[3] = Term::small(i64::from(line)).expect("line is a small integer");
                    p.gc_live = 4;
                    p.module = module_id;
                    p.ip = offset;
                    p.reductions = reds;
                    let outcome = self.call_import(
                        p,
                        import as usize,
                        4,
                        false,
                        ctx.as_deref_mut(),
                    )?;
                    module_id = p.module;
                    self.sync_module(module_id);
                    base = self.modules[module_id].code.as_ptr();
                    module_handle = self.modules[module_id].clone();
                    x = p.x.as_mut_ptr();
                    fr = p.fr.as_mut_ptr();
                    reds = p.reductions;
                    depth = p.heap.stack_words();
                    (htop, stop) = p.heap.heap_cursor();
                    match outcome {
                        ImportOutcome::Returned(value) => return Ok(RunState::Done(value)),
                        ImportOutcome::Yield => {
                            sync_cursor(p, htop, &mut heap_dirty);
                            return Ok(RunState::Yield);
                        }
                        ImportOutcome::Jump(target) => {
                            if let Some(native) = self.beamasm_targets.function_for_target(
                                module_id,
                                &self.modules[module_id],
                                // SAFETY: The import target belongs to the active module.
                                instruction_offset(base, target),
                            ) {
                                sync_cursor(p, htop, &mut heap_dirty);
                                p.native_pc = Some(native.start);
                                return Ok(RunState::Yield);
                            }
                            ip = target;
                        }
                        ImportOutcome::Advanced => {
                            ip = base.wrapping_add(p.ip);
                        }
                    }
                    continue;
                }
                Instr::DebugLineCleanup { live } => {
                    // Port of erts/emulator/beam/emu/instrs.tab:1294-1304, OTP-29.1.1.
                    for index in 0..live as usize {
                        let value = p.heap.stack_get(index).ok_or_else(debug_line_system_limit)?;
                        p.x[index] = value;
                    }
                    if !p.heap.release_stack(live as usize + 1) {
                        return Err(debug_line_system_limit());
                    }
                    depth = depth.saturating_sub(live as usize);
                    stop = p.heap.heap_cursor().1;
                }
                Instr::CallOnly { target } => {
                    p.gc_live = module
                        .function_at(target as usize)
                        .ok_or_else(|| VmError::Unsupported("local call target".into()))?
                        .1 as usize;
                    reds -= 1;
                    if reds == 0 {
                        reds = 4000;
                    }
                    // SAFETY: Loader-resolved labels designate instructions in this code allocation.
                    ip = unsafe { base.add(target as usize) };
                    continue;
                }
                Instr::CallBif {
                    bif,
                    fast_op,
                    import,
                    arity,
                    dealloc,
                    tail,
                } => {
                    if arity as usize > p.x.len() {
                        return Err(VmError::Unsupported("BIF argument registers".into()));
                    }
                    sync_cursor(p, htop, &mut heap_dirty);
                    p.gc_live = arity as usize;
                    p.reductions = reds;
                    let (result, bif_reductions) =
                        if let Some(result) = call_fast_tuple_bif(p, fast_op, arity as usize) {
                            (result, 0)
                        } else {
                            calls::call_bif_metered(&mut p.heap, bif, &p.x[..arity as usize])
                        };
                    match result {
                        Ok(value) => {
                            p.x[0] = value;
                            (htop, stop) = p.heap.heap_cursor();
                            heap_dirty = false;
                            if let Some(resume) = p
                                .cold
                                .as_mut()
                                .and_then(|cold| cold.native_resume_after_call.take())
                            {
                                sync_cursor(p, htop, &mut heap_dirty);
                                p.native_pc = Some(resume);
                                p.reductions = reds;
                                return Ok(RunState::Yield);
                            }
                            if tail {
                                if dealloc > 0 && !p.heap.release_stack(dealloc as usize) {
                                    return Err(VmError::Unsupported("stack underflow".into()));
                                }
                                depth = p.heap.stack_words();
                                stop = p.heap.heap_cursor().1;
                                return_from_frame!(true);
                            }
                            // SAFETY: This instruction is followed by another
                            // instruction or CodeEnd in this allocation.
                            ip = unsafe { ip.add(1) };
                            let charge = bif_reductions.saturating_add(1);
                            reds = reds.saturating_sub(charge.min(i32::MAX as u32) as i32);
                            consumed = consumed.saturating_add(charge).min(budget);
                            if let Some(run) = ctx.as_deref_mut() {
                                run.consume(charge);
                            }
                            if reds == 0 || consumed == budget {
                                sync_cursor(p, htop, &mut heap_dirty);
                                // SAFETY: `ip` remains inside the current module allocation.
                                p.ip = unsafe { ip.offset_from(base) } as usize;
                                p.module = module_id;
                                p.reductions = 4000;
                                return Ok(RunState::Yield);
                            }
                            continue;
                        }
                        Err(error) => {
                            return Err(self.fail_pure_bif(
                                p,
                                module_id,
                                import as usize,
                                arity as usize,
                                error,
                            ));
                        }
                    }
                }
                Instr::CallExternal {
                    import,
                    arity,
                    dealloc,
                    tail,
                } => {
                    // call_ext of a pure BIF: one class/pointer load and one
                    // indirect call. Arguments are the live X registers.
                    // Tail calls and stack deallocation stay on the general path.
                    if dealloc == 0
                        && !tail
                        && (arity as usize) <= p.x.len()
                        && let Some(bif) = self.pure_bif(module_id, import as usize)
                    {
                        sync_cursor(p, htop, &mut heap_dirty);
                        p.gc_live = arity as usize;
                        // Native entry takes its reduction counter from the
                        // process, not the interpreter's cached `reds`.
                        p.reductions = reds;
                        let (result, bif_reductions) =
                            calls::call_bif_metered(&mut p.heap, bif, &p.x[..arity as usize]);
                        match result {
                            Ok(value) => {
                                // SAFETY: `x` is the base of the live X file, which
                                // has a slot 0. This BIF does not reallocate it.
                                unsafe { *x = value };
                                (htop, stop) = p.heap.heap_cursor();
                                heap_dirty = false;
                                // SAFETY: CallExternal is followed by another
                                // instruction or CodeEnd in this allocation.
                                ip = unsafe { ip.add(1) };
                                let charge = bif_reductions.saturating_add(1);
                                reds = reds.saturating_sub(charge.min(i32::MAX as u32) as i32);
                                consumed = consumed.saturating_add(charge).min(budget);
                                if let Some(run) = ctx.as_deref_mut() {
                                    run.consume(charge);
                                }
                                if reds == 0 || consumed == budget {
                                    sync_cursor(p, htop, &mut heap_dirty);
                                    // SAFETY: `ip` remains inside the current module allocation.
                                    p.ip = unsafe { ip.offset_from(base) } as usize;
                                    p.module = module_id;
                                    p.reductions = 4000;
                                    return Ok(RunState::Yield);
                                }
                                if let Some(resume) = p
                                    .cold
                                    .as_mut()
                                    .and_then(|cold| cold.native_resume_after_call.take())
                                {
                                    sync_cursor(p, htop, &mut heap_dirty);
                                    p.native_pc = Some(resume);
                                    p.reductions = reds;
                                    return Ok(RunState::Yield);
                                }
                                continue;
                            }
                            Err(error) => {
                                return Err(self.fail_pure_bif(
                                    p,
                                    module_id,
                                    import as usize,
                                    arity as usize,
                                    error,
                                ));
                            }
                        }
                    }
                    sync_cursor(p, htop, &mut heap_dirty);
                    // SAFETY: `ip` and `base` belong to the current module.
                    let offset = unsafe { ip.offset_from(base) } as usize;
                    if dealloc > 0 && !p.heap.release_stack(dealloc as usize) {
                        return Err(VmError::Unsupported("stack underflow".into()));
                    }
                    p.module = module_id;
                    p.ip = offset;
                    p.reductions = reds;
                    let outcome = self.call_import(
                        p,
                        import as usize,
                        arity as usize,
                        tail,
                        ctx.as_deref_mut(),
                    )?;
                    let native_resume = p
                        .cold
                        .as_mut()
                        .and_then(|cold| cold.native_resume_after_call.take());
                    if let Some(resume) = native_resume {
                        match outcome {
                            ImportOutcome::Jump(_) => {
                                p.replace_native_continuation(resume)
                                    .map_err(|error| VmError::Unsupported(error.into()))?;
                            }
                            ImportOutcome::Advanced | ImportOutcome::Yield => {
                                sync_cursor(p, htop, &mut heap_dirty);
                                p.native_pc = Some(resume);
                                p.reductions = reds;
                                return Ok(RunState::Yield);
                            }
                            ImportOutcome::Returned(value) => {
                                sync_cursor(p, htop, &mut heap_dirty);
                                // The BIF returned a value for the native caller in x[0].
                                p.x[0] = value;
                                p.native_pc = Some(resume);
                                p.reductions = reds;
                                return Ok(RunState::Yield);
                            }
                        }
                    }
                    // g_code_fix: nested on_load may reallocate X and FR.
                    x = p.x.as_mut_ptr();
                    fr = p.fr.as_mut_ptr();
                    module_id = p.module;
                    base = self.modules[module_id].code.as_ptr();
                    reds = p.reductions;
                    depth = p.heap.stack_words();
                    (htop, stop) = p.heap.heap_cursor();
                    ip = match outcome {
                        ImportOutcome::Returned(value) => return Ok(RunState::Done(value)),
                        ImportOutcome::Yield => {
                            sync_cursor(p, htop, &mut heap_dirty);
                            p.reductions = reds;
                            return Ok(RunState::Yield);
                        }
                        ImportOutcome::Jump(target) => target,
                        ImportOutcome::Advanced => {
                            // SAFETY: The continuation uses a resolved code index.
                            unsafe { base.add(p.ip) }
                        }
                    };
                    if let ImportOutcome::Jump(target) = outcome {
                        // Port of erts/emulator/beam/jit/arm/process_main.cpp:235-317,
                        // OTP-29.1.1: return to the scheduler at an unported callee.
                        // SAFETY: The jump target belongs to the active module code allocation.
                        let target_ip = unsafe { target.offset_from(base) } as usize;
                        if let Some(native) = self.beamasm_targets.function_for_target(
                            module_id,
                            &self.modules[module_id],
                            target_ip,
                        ) {
                            sync_cursor(p, htop, &mut heap_dirty);
                            p.module = module_id;
                            p.ip = target_ip;
                            p.reductions = reds;
                            p.native_pc = Some(native.start);
                            return Ok(RunState::Yield);
                        }
                    }
                    continue;
                }
                Instr::CallLocal { target } => {
                    // SAFETY: `ip` and `base` belong to the current module.
                    let offset = unsafe { ip.offset_from(base) } as usize;
                    sync_cursor(p, htop, &mut heap_dirty);
                    let function_index = function_index_at(module, target as usize)
                        .ok_or_else(|| VmError::Unsupported("local call target".into()))?;
                    let arity = module.functions[function_index].2 as usize;
                    p.gc_live = arity;
                    if p.heap.free_words() == 0 {
                        p.ensure(1, arity)?;
                        (htop, stop) = p.heap.heap_cursor();
                    }
                    if !p.heap.reserve_stack(1) {
                        return Err(VmError::Unsupported("continuation stack".into()));
                    }
                    depth += 1;
                    // SAFETY: Reserving one stack word extends the live interval downward.
                    stop = unsafe { stop.sub(1) };
                    let cp = Term::catch(((module_id as u64) << 32) | ((offset + 1) as u64));
                    // SAFETY: The new stack slot is reserved; CATCH is an immediate
                    // that the collector correctly skips.
                    unsafe { *stop = cp.raw_bits() };
                    if let Some(native) =
                        self.beamasm_targets
                            .function_for_target(module_id, module, target as usize)
                    {
                        // Keep this BEAM continuation below run_native's bridge
                        // CP; native return copies XREG0 back before resuming it.
                        sync_cursor(p, htop, &mut heap_dirty);
                        p.module = module_id;
                        p.ip = target as usize;
                        p.reductions = reds;
                        p.native_pc = Some(native.start);
                        return Ok(RunState::Yield);
                    }
                    reds -= 1;
                    if reds == 0 {
                        reds = 4000;
                    }
                    // SAFETY: Loader-resolved labels designate instructions in this allocation.
                    ip = unsafe { base.add(target as usize) };
                    continue;
                }
                Instr::CallLast { target, dealloc } => {
                    let function_index = function_index_at(module, target as usize)
                        .ok_or_else(|| VmError::Unsupported("local call target".into()))?;
                    let arity = module.functions[function_index].2;
                    p.gc_live = arity as usize;
                    if !p.heap.release_stack(dealloc as usize) {
                        return Err(VmError::Unsupported("stack underflow".into()));
                    }
                    depth -= dealloc as usize;
                    // SAFETY: `release_stack` checked that these words were live.
                    stop = unsafe { stop.add(dealloc as usize) };
                    if let Some(native) =
                        self.beamasm_targets
                            .function_for_target(module_id, module, target as usize)
                    {
                        // Tail calls reuse the existing caller CP; run_native
                        // supplies only the temporary bridge CP for this entry.
                        sync_cursor(p, htop, &mut heap_dirty);
                        p.module = module_id;
                        p.ip = target as usize;
                        p.reductions = reds;
                        p.native_pc = Some(native.start);
                        return Ok(RunState::Yield);
                    }
                    reds -= 1;
                    if reds == 0 {
                        reds = 4000;
                    }
                    // SAFETY: Loader-resolved labels designate instructions in this allocation.
                    ip = unsafe { base.add(target as usize) };
                    continue;
                }
                Instr::ReturnInstr => return_from_frame!(true),
                Instr::DeallocateReturn { slots } => {
                    if !p.heap.release_stack(slots as usize) {
                        return Err(VmError::Unsupported("stack underflow".into()));
                    }
                    depth -= slots as usize;
                    // SAFETY: `release_stack` checked the old live interval.
                    stop = unsafe { stop.add(slots as usize) };
                    count_second!("return");
                    return_from_frame!(true);
                }
                Instr::Allocate { slots, words, live } => {
                    p.gc_live = live as usize;
                    let need = slots as usize + words as usize;
                    sync_cursor(p, htop, &mut heap_dirty);
                    if p.heap.free_words() < need {
                        p.ensure(need, live as usize)?;
                        (htop, stop) = p.heap.heap_cursor();
                    }
                    if !p.heap.reserve_stack(slots as usize) {
                        return Err(VmError::Unsupported("stack allocation".into()));
                    }
                    depth += slots as usize;
                    // SAFETY: Reserving Y words extends the live interval downward.
                    stop = unsafe { stop.sub(slots as usize) };
                }
                Instr::Deallocate { slots } => {
                    if !p.heap.release_stack(slots as usize) {
                        return Err(VmError::Unsupported("stack underflow".into()));
                    }
                    depth -= slots as usize;
                    // SAFETY: `release_stack` checked the old live interval.
                    stop = unsafe { stop.add(slots as usize) };
                }
                Instr::Trim { slots } => {
                    if !p.heap.release_stack(slots as usize) {
                        return Err(VmError::Unsupported("trim underflow".into()));
                    }
                    depth -= slots as usize;
                    // SAFETY: `release_stack` checked the old live interval.
                    stop = unsafe { stop.add(slots as usize) };
                }
                Instr::InitYregs { list } => {
                    for arg in &module.lists[list as usize] {
                        let dst = arg.value() as usize;
                        if dst >= depth {
                            return Err(VmError::Unsupported("Y register".into()));
                        }
                        // SAFETY: The list was validated as Y registers during loading.
                        unsafe { *stop.add(dst) = Term::NIL.raw_bits() };
                    }
                }
                Instr::TestHeap { words, live } => {
                    p.gc_live = live as usize;
                    if (stop as usize - htop as usize) < words as usize * 8 {
                        sync_cursor(p, htop, &mut heap_dirty);
                        p.ensure(words as usize, live as usize)?;
                        (htop, stop) = p.heap.heap_cursor();
                    }
                }
                Instr::IsLtXX { a, b, fail } => {
                    // SAFETY: Specialization validates both X indices below 1024.
                    let (left, right) = unsafe { (*x.add(a as usize), *x.add(b as usize)) };
                    compare_branch!(compare::lt(left, right), fail);
                }
                Instr::IsLtXC { a, b, fail } => {
                    // SAFETY: Specialization validates every X index below 1024.
                    compare_branch!(compare::lt(unsafe { *x.add(a as usize) }, b), fail);
                }
                Instr::IsLtXCReturn { a, b, fail } => {
                    // SAFETY: Specialization validates the X index.
                    compare_branch!(compare::lt(unsafe { *x.add(a as usize) }, b), fail);
                    count_second!("return");
                    return_from_frame!(true);
                }
                Instr::IsLtCX { a, b, fail } => {
                    // SAFETY: Specialization validates every X index below 1024.
                    compare_branch!(compare::lt(a, unsafe { *x.add(b as usize) }), fail);
                }
                Instr::IsGeXX { a, b, fail } => {
                    // SAFETY: Specialization validates both X indices below 1024.
                    let (left, right) = unsafe { (*x.add(a as usize), *x.add(b as usize)) };
                    compare_branch!(compare::ge(left, right), fail);
                }
                Instr::IsGeXC { a, b, fail } => {
                    // SAFETY: Specialization validates every X index below 1024.
                    compare_branch!(compare::ge(unsafe { *x.add(a as usize) }, b), fail);
                }
                Instr::IsGeCX { a, b, fail } => {
                    // SAFETY: Specialization validates every X index below 1024.
                    compare_branch!(compare::ge(a, unsafe { *x.add(b as usize) }), fail);
                }
                Instr::IsEqXX { a, b, fail } => {
                    // SAFETY: Specialization validates both X indices below 1024.
                    let (left, right) = unsafe { (*x.add(a as usize), *x.add(b as usize)) };
                    compare_branch!(compare::eq(left, right), fail);
                }
                Instr::IsEqXC { a, b, fail } => {
                    // SAFETY: Specialization validates every X index below 1024.
                    compare_branch!(compare::eq(unsafe { *x.add(a as usize) }, b), fail);
                }
                Instr::IsEqCX { a, b, fail } => {
                    // SAFETY: Specialization validates every X index below 1024.
                    compare_branch!(compare::eq(a, unsafe { *x.add(b as usize) }), fail);
                }
                Instr::IsNeXX { a, b, fail } => {
                    // SAFETY: Specialization validates both X indices below 1024.
                    let (left, right) = unsafe { (*x.add(a as usize), *x.add(b as usize)) };
                    compare_branch!(compare::ne(left, right), fail);
                }
                Instr::IsNeXC { a, b, fail } => {
                    // SAFETY: Specialization validates every X index below 1024.
                    compare_branch!(compare::ne(unsafe { *x.add(a as usize) }, b), fail);
                }
                Instr::IsNeCX { a, b, fail } => {
                    // SAFETY: Specialization validates every X index below 1024.
                    compare_branch!(compare::ne(a, unsafe { *x.add(b as usize) }), fail);
                }
                Instr::IsEqExactXX { a, b, fail } => {
                    // SAFETY: Specialization validates both X indices below 1024.
                    let (left, right) = unsafe { (*x.add(a as usize), *x.add(b as usize)) };
                    compare_branch!(compare::eq_exact(left, right), fail);
                }
                Instr::IsEqExactXC { a, b, fail } => {
                    // SAFETY: Specialization validates every X index below 1024.
                    compare_branch!(compare::eq_exact(unsafe { *x.add(a as usize) }, b), fail);
                }
                Instr::IsEqExactCX { a, b, fail } => {
                    // SAFETY: Specialization validates every X index below 1024.
                    compare_branch!(compare::eq_exact(a, unsafe { *x.add(b as usize) }), fail);
                }
                Instr::IsNeExactXX { a, b, fail } => {
                    // SAFETY: Specialization validates both X indices below 1024.
                    let (left, right) = unsafe { (*x.add(a as usize), *x.add(b as usize)) };
                    compare_branch!(compare::ne_exact(left, right), fail);
                }
                Instr::IsNeExactXC { a, b, fail } => {
                    // SAFETY: Specialization validates every X index below 1024.
                    compare_branch!(compare::ne_exact(unsafe { *x.add(a as usize) }, b), fail);
                }
                Instr::IsNeExactCX { a, b, fail } => {
                    // SAFETY: Specialization validates every X index below 1024.
                    compare_branch!(compare::ne_exact(a, unsafe { *x.add(b as usize) }), fail);
                }
                Instr::GetTupleElementXX { src, index, dst } => {
                    // SAFETY: `ip` and `base` belong to the current module.
                    let offset = unsafe { ip.offset_from(base) } as usize;
                    // SAFETY: Specialization validates the X indices below 1024.
                    let tuple = unsafe { *x.add(src as usize) };
                    let value = tuples::element(tuple, index as usize).ok_or_else(|| {
                        p.module = module_id;
                        p.ip = offset;
                        self.exception(p, "badarg")
                    })?;
                    // SAFETY: Specialization validates the destination X index below 1024.
                    unsafe { *x.add(dst as usize) = value };
                }
                Instr::GetTupleFloat {
                    src,
                    index,
                    dst_x,
                    dst_fr,
                } => {
                    // SAFETY: Specialization validates X and FR indices.
                    let tuple = unsafe { *x.add(src as usize) };
                    let value = tuples::element(tuple, index as usize).ok_or_else(|| {
                        // SAFETY: `ip` and `base` belong to the current module.
                        p.ip = unsafe { ip.offset_from(base) } as usize;
                        p.module = module_id;
                        self.exception(p, "badarg")
                    })?;
                    // SAFETY: Specialization validates the X destination.
                    unsafe { *x.add(dst_x as usize) = value };
                    count_second!("fmove");
                    let value =
                        floats::number(value).ok_or_else(|| self.exception(p, "badarith"))?;
                    // SAFETY: Specialization validates the FR destination.
                    unsafe { *fr.add(dst_fr as usize) = value };
                    // SAFETY: The fused second instruction occupies the next code slot.
                    ip = unsafe { ip.add(2) };
                    continue;
                }
                Instr::GetTupleElementYX { src, index, dst } => {
                    if src as usize >= depth {
                        return Err(VmError::Unsupported("Y register".into()));
                    }
                    // SAFETY: The Y slot is live and contains a tagged term.
                    let tuple =
                        unsafe { std::mem::transmute::<u64, Term>(*stop.add(src as usize)) };
                    let value = tuples::element(tuple, index as usize)
                        .ok_or_else(|| self.exception(p, "badarg"))?;
                    // SAFETY: Specialization validates the destination X index.
                    unsafe { *x.add(dst as usize) = value };
                }
                Instr::GetTupleElementXY { src, index, dst } => {
                    if dst as usize >= depth {
                        return Err(VmError::Unsupported("Y register".into()));
                    }
                    // SAFETY: Specialization validates the source X index.
                    let tuple = unsafe { *x.add(src as usize) };
                    let value = tuples::element(tuple, index as usize)
                        .ok_or_else(|| self.exception(p, "badarg"))?;
                    // SAFETY: The destination Y slot is live.
                    unsafe { *stop.add(dst as usize) = value.raw_bits() };
                }
                Instr::PutTupleXX { a, b, dst } => {
                    if (stop as usize - htop as usize) < 3 * 8 {
                        sync_cursor(p, htop, &mut heap_dirty);
                        p.ensure(3, p.gc_live)?;
                        (htop, stop) = p.heap.heap_cursor();
                    }
                    // SAFETY: Specialization validates all X indices below 1024.
                    let (first, second) = unsafe { (*x.add(a as usize), *x.add(b as usize)) };
                    let ptr = cursor_alloc(&mut htop, stop, 3)
                        .ok_or_else(|| VmError::Unsupported("tuple allocation".into()))?;
                    heap_dirty = true;
                    let tuple = tuples::pair(ptr, first, second);
                    // SAFETY: Specialization validates the X destination below 1024.
                    unsafe { *x.add(dst as usize) = tuple };
                }
                Instr::PutTuple { list, dst } => {
                    let items = &module.lists[list as usize];
                    let words = items.len() + 1;
                    if (stop as usize - htop as usize) < words * 8 {
                        sync_cursor(p, htop, &mut heap_dirty);
                        p.ensure(words, p.gc_live)?;
                        (htop, stop) = p.heap.heap_cursor();
                    }
                    let ptr = cursor_alloc(&mut htop, stop, words)
                        .ok_or_else(|| VmError::Unsupported("tuple allocation".into()))?;
                    heap_dirty = true;
                    // SAFETY: The allocation reserves a header and one word per item.
                    unsafe { *ptr = (items.len() as u64) << 6 };
                    for (i, item) in items.iter().copied().enumerate() {
                        let value = p.read(item)?;
                        // SAFETY: The allocation reserves a word for every list item.
                        unsafe { *ptr.add(i + 1) = value.raw_bits() };
                    }
                    // SAFETY: The pointer names a tuple header in the process heap.
                    let tuple = unsafe { std::mem::transmute::<u64, Term>((ptr as u64) | 2) };
                    // SAFETY: Specialization validates the destination X index.
                    unsafe { *x.add(dst as usize) = tuple };
                }
                Instr::PutListXXX { head, tail, dst } => {
                    if (stop as usize - htop as usize) < 2 * 8 {
                        sync_cursor(p, htop, &mut heap_dirty);
                        p.ensure(2, p.gc_live)?;
                        (htop, stop) = p.heap.heap_cursor();
                    }
                    // SAFETY: Specialization validates all X indices below 1024.
                    let (head, tail) = unsafe { (*x.add(head as usize), *x.add(tail as usize)) };
                    let ptr = cursor_alloc(&mut htop, stop, 2)
                        .ok_or_else(|| VmError::Unsupported("list allocation".into()))?;
                    heap_dirty = true;
                    let list = lists::cons(ptr, head, tail);
                    // SAFETY: Specialization validates the X destination below 1024.
                    unsafe { *x.add(dst as usize) = list };
                }
                Instr::PutList { head, tail, dst } => {
                    if (stop as usize - htop as usize) < 2 * 8 {
                        sync_cursor(p, htop, &mut heap_dirty);
                        p.ensure(2, p.gc_live)?;
                        (htop, stop) = p.heap.heap_cursor();
                    }
                    let head = p.read(head)?;
                    let tail = p.read(tail)?;
                    let ptr = cursor_alloc(&mut htop, stop, 2)
                        .ok_or_else(|| VmError::Unsupported("list allocation".into()))?;
                    heap_dirty = true;
                    let list = lists::cons(ptr, head, tail);
                    // SAFETY: Specialization validates the destination X index.
                    unsafe { *x.add(dst as usize) = list };
                }
                Instr::GetListXXX { src, head, tail } => {
                    // SAFETY: Specialization validates the X source below 1024.
                    let list = unsafe { *x.add(src as usize) };
                    // SAFETY: The source term remains in a live process or literal heap.
                    let (hd, tl) = lists::split(list).ok_or_else(|| self.exception(p, "badarg"))?;
                    // SAFETY: Specialization validates both X destinations below 1024.
                    unsafe {
                        *x.add(head as usize) = hd;
                        *x.add(tail as usize) = tl
                    };
                }
                Instr::GetList { src, head, tail } => {
                    // SAFETY: Specialization validates the source X index.
                    let list = unsafe { *x.add(src as usize) };
                    let (hd, tl) = lists::split(list).ok_or_else(|| self.exception(p, "badarg"))?;
                    p.write(head, hd)?;
                    p.write(tail, tl)?;
                }
                Instr::GetHdXX { src, dst } => {
                    // SAFETY: Specialization validates both X indices.
                    let list = unsafe { *x.add(src as usize) };
                    let (head, _) =
                        lists::split(list).ok_or_else(|| self.exception(p, "badarg"))?;
                    // SAFETY: Specialization validates the destination X index.
                    unsafe { *x.add(dst as usize) = head };
                }
                Instr::GetTlXX { src, dst } => {
                    // SAFETY: Specialization validates both X indices.
                    let list = unsafe { *x.add(src as usize) };
                    let (_, tail) =
                        lists::split(list).ok_or_else(|| self.exception(p, "badarg"))?;
                    // SAFETY: Specialization validates the destination X index.
                    unsafe { *x.add(dst as usize) = tail };
                }
                Instr::ArithXXX {
                    kind,
                    a,
                    b,
                    dst,
                    fail,
                    import,
                } => {
                    // SAFETY: `ip` and `base` belong to the current module.
                    let offset = unsafe { ip.offset_from(base) } as usize;
                    // SAFETY: Specialization validates all X indices below 1024.
                    let (left, right) = unsafe { (*x.add(a as usize), *x.add(b as usize)) };
                    let value = if let Some(value) = arith::small(kind, left, right) {
                        value
                    } else {
                        p.module = module_id;
                        p.ip = offset;
                        let bif = module.imports[import as usize]
                            .bif
                            .ok_or_else(|| VmError::Unsupported("arithmetic BIF".into()))?;
                        sync_cursor(p, htop, &mut heap_dirty);
                        let result = {
                            let mut heap = FragmentingHeap(&mut p.heap);
                            let mut ctx = Ctx::new(&mut heap);
                            // ---- vm_exc ----
                            bif(&mut ctx, &[left, right])
                        };
                        match result {
                            Ok(value) => {
                                (htop, stop) = p.heap.heap_cursor();
                                value
                            }
                            Err(_) if fail != u32::MAX => {
                                (htop, stop) = p.heap.heap_cursor();
                                // Guard arithmetic exceptions select the encoded fail label.
                                // This matches erts guard evaluation, where an exception makes
                                // the guard false instead of escaping the function.
                                ip = base.wrapping_add(fail as usize);
                                continue;
                            }
                            Err(error) => {
                                return Err(exceptions::bif_error(
                                    p,
                                    &module.imports[import as usize].module,
                                    &module.imports[import as usize].function,
                                    &[left, right],
                                    error,
                                ));
                            }
                        }
                    };
                    // SAFETY: Specialization validates destination X index below 1024.
                    unsafe { *x.add(dst as usize) = value };
                }
                Instr::ArithYXX {
                    kind,
                    a,
                    b,
                    dst,
                    fail,
                    import,
                } => {
                    if a as usize >= depth {
                        return Err(VmError::Unsupported("Y register".into()));
                    }
                    // SAFETY: The Y slot is live and specialization validates X indices.
                    let (left, right) = unsafe {
                        (
                            std::mem::transmute::<u64, Term>(*stop.add(a as usize)),
                            *x.add(b as usize),
                        )
                    };
                    let value = if let Some(value) = arith::small(kind, left, right) {
                        value
                    } else {
                        // SAFETY: `ip` and `base` belong to the current module.
                        let offset = unsafe { ip.offset_from(base) } as usize;
                        p.module = module_id;
                        p.ip = offset;
                        let bif = module.imports[import as usize]
                            .bif
                            .ok_or_else(|| VmError::Unsupported("arithmetic BIF".into()))?;
                        sync_cursor(p, htop, &mut heap_dirty);
                        let result = {
                            let mut heap = FragmentingHeap(&mut p.heap);
                            let mut ctx = Ctx::new(&mut heap);
                            // ---- vm_exc ----
                            bif(&mut ctx, &[left, right])
                        };
                        (htop, stop) = p.heap.heap_cursor();
                        match result {
                            Ok(value) => value,
                            Err(_) if fail != u32::MAX => {
                                ip = base.wrapping_add(fail as usize);
                                continue;
                            }
                            Err(error) => {
                                return Err(exceptions::bif_error(
                                    p,
                                    &module.imports[import as usize].module,
                                    &module.imports[import as usize].function,
                                    &[left, right],
                                    error,
                                ));
                            }
                        }
                    };
                    // SAFETY: Specialization validates destination X index below 1024.
                    unsafe { *x.add(dst as usize) = value };
                }
                Instr::ArithRC {
                    kind,
                    src,
                    from_y,
                    value,
                    dst,
                    fail,
                    import,
                } => {
                    // SAFETY: `ip` and `base` belong to the current module.
                    let offset = unsafe { ip.offset_from(base) } as usize;
                    let left = if from_y {
                        if src as usize >= depth {
                            return Err(VmError::Unsupported("Y register".into()));
                        }
                        // SAFETY: The source is within the live stack interval.
                        unsafe { std::mem::transmute::<u64, Term>(*stop.add(src as usize)) }
                    } else {
                        // SAFETY: Specialization validates the X index below 1024.
                        unsafe { *x.add(src as usize) }
                    };
                    let result = if let Some(result) = arith::small(kind, left, value) {
                        result
                    } else {
                        p.module = module_id;
                        p.ip = offset;
                        let bif = module.imports[import as usize]
                            .bif
                            .ok_or_else(|| VmError::Unsupported("arithmetic BIF".into()))?;
                        sync_cursor(p, htop, &mut heap_dirty);
                        let result = {
                            let mut heap = FragmentingHeap(&mut p.heap);
                            let mut ctx = Ctx::new(&mut heap);
                            // ---- vm_exc ----
                            bif(&mut ctx, &[left, value])
                        };
                        (htop, stop) = p.heap.heap_cursor();
                        match result {
                            Ok(result) => result,
                            Err(_) if fail != u32::MAX => {
                                ip = base.wrapping_add(fail as usize);
                                continue;
                            }
                            Err(error) => {
                                return Err(exceptions::bif_error(
                                    p,
                                    &module.imports[import as usize].module,
                                    &module.imports[import as usize].function,
                                    &[left, value],
                                    error,
                                ));
                            }
                        }
                    };
                    // SAFETY: Specialization validates destination X index below 1024.
                    unsafe { *x.add(dst as usize) = result };
                }
                Instr::ArithRCY {
                    kind,
                    src,
                    from_y,
                    value,
                    dst,
                    fail,
                    import,
                } => {
                    if dst as usize >= depth || (from_y && src as usize >= depth) {
                        return Err(VmError::Unsupported("Y register".into()));
                    }
                    let left = if from_y {
                        // SAFETY: The checked Y slot is live and contains a tagged term.
                        unsafe { std::mem::transmute::<u64, Term>(*stop.add(src as usize)) }
                    } else {
                        // SAFETY: Specialization validates the X index below 1024.
                        unsafe { *x.add(src as usize) }
                    };
                    let result = if let Some(result) = arith::small(kind, left, value) {
                        result
                    } else {
                        // SAFETY: `ip` and `base` belong to the current module.
                        let offset = unsafe { ip.offset_from(base) } as usize;
                        p.module = module_id;
                        p.ip = offset;
                        let bif = module.imports[import as usize]
                            .bif
                            .ok_or_else(|| VmError::Unsupported("arithmetic BIF".into()))?;
                        sync_cursor(p, htop, &mut heap_dirty);
                        let result = {
                            let mut heap = FragmentingHeap(&mut p.heap);
                            let mut ctx = Ctx::new(&mut heap);
                            // ---- vm_exc ----
                            bif(&mut ctx, &[left, value])
                        };
                        (htop, stop) = p.heap.heap_cursor();
                        match result {
                            Ok(result) => result,
                            Err(_) if fail != u32::MAX => {
                                // SAFETY: Specialization resolves fail labels in this module.
                                ip = unsafe { base.add(fail as usize) };
                                continue;
                            }
                            Err(error) => {
                                return Err(exceptions::bif_error(
                                    p,
                                    &module.imports[import as usize].module,
                                    &module.imports[import as usize].function,
                                    &[left, value],
                                    error,
                                ));
                            }
                        }
                    };
                    // SAFETY: The destination Y slot is live.
                    unsafe { *stop.add(dst as usize) = result.raw_bits() };
                }
                Instr::FmoveXFr { src, dst } => {
                    // SAFETY: Specialization validates X and FR indices below 1024.
                    let value = unsafe { *x.add(src as usize) };
                    let value =
                        floats::number(value).ok_or_else(|| self.exception(p, "badarith"))?;
                    // SAFETY: Specialization validates FR index below 1024.
                    unsafe { *fr.add(dst as usize) = value };
                }
                Instr::FmoveYFr { src, dst } => {
                    if src as usize >= depth {
                        return Err(VmError::Unsupported("Y register".into()));
                    }
                    // SAFETY: The Y slot is live and contains a tagged term.
                    let term = unsafe { std::mem::transmute::<u64, Term>(*stop.add(src as usize)) };
                    let value =
                        floats::number(term).ok_or_else(|| self.exception(p, "badarith"))?;
                    // SAFETY: Specialization validates the FR index.
                    unsafe { *fr.add(dst as usize) = value };
                }
                Instr::FmoveCFr { value, dst } => {
                    // SAFETY: Specialization validates the FR index.
                    unsafe { *fr.add(dst as usize) = value };
                }
                Instr::FmoveFrX { src, dst } => {
                    // SAFETY: Specialization validates FR index below 1024.
                    let value = unsafe { *fr.add(src as usize) };
                    if !value.is_finite() {
                        return Err(self.exception(p, "badarith"));
                    }
                    if (stop as usize - htop as usize) < 2 * 8 {
                        sync_cursor(p, htop, &mut heap_dirty);
                        p.ensure(2, p.gc_live)?;
                        (htop, stop) = p.heap.heap_cursor();
                    }
                    let ptr = cursor_alloc(&mut htop, stop, 2)
                        .ok_or_else(|| VmError::Unsupported("float allocation".into()))?;
                    heap_dirty = true;
                    let term = floats::box_float(ptr, value);
                    // SAFETY: Specialization validates X destination below 1024.
                    unsafe { *x.add(dst as usize) = term };
                }
                Instr::FmoveFrY { src, dst } => {
                    if dst as usize >= depth {
                        return Err(VmError::Unsupported("Y register".into()));
                    }
                    // SAFETY: Specialization validates the FR index.
                    let value = unsafe { *fr.add(src as usize) };
                    if !value.is_finite() {
                        return Err(self.exception(p, "badarith"));
                    }
                    if (stop as usize - htop as usize) < 2 * 8 {
                        sync_cursor(p, htop, &mut heap_dirty);
                        p.ensure(2, p.gc_live)?;
                        (htop, stop) = p.heap.heap_cursor();
                    }
                    let ptr = cursor_alloc(&mut htop, stop, 2)
                        .ok_or_else(|| VmError::Unsupported("float allocation".into()))?;
                    heap_dirty = true;
                    let term = floats::box_float(ptr, value);
                    // SAFETY: The Y slot is live.
                    unsafe { *stop.add(dst as usize) = term.raw_bits() };
                }
                Instr::FmoveFrFr { src, dst } => {
                    // SAFETY: Specialization validates both FR indices below 1024.
                    unsafe { *fr.add(dst as usize) = *fr.add(src as usize) };
                }
                Instr::Fadd { a, b, dst } => float_bin!(a, b, dst, +),
                Instr::Fsub { a, b, dst } => float_bin!(a, b, dst, -),
                Instr::Fmul { a, b, dst } => float_bin!(a, b, dst, *),
                Instr::Fdiv { a, b, dst } => float_bin!(a, b, dst, /),
                Instr::FloatBin { kind, a, b, dst } => match kind {
                    Opcode::Fadd => float_bin!(a, b, dst, +),
                    Opcode::Fsub => float_bin!(a, b, dst, -),
                    Opcode::Fmul => float_bin!(a, b, dst, *),
                    Opcode::Fdiv => float_bin!(a, b, dst, /),
                    _ => return Err(VmError::Unsupported("float opcode".into())),
                },
                Instr::IsTupleX { src, fail } => {
                    // SAFETY: Specialization validates the X index.
                    let term = unsafe { *x.add(src as usize) };
                    compare_branch!(term.classify() == TermKind::Tuple, fail);
                }
                Instr::IsTupleOfArity {
                    src,
                    arity,
                    fail_type,
                    fail_arity,
                } => {
                    // SAFETY: Specialization validates the X index.
                    let term = unsafe { *x.add(src as usize) };
                    compare_branch!(term.classify() == TermKind::Tuple, fail_type);
                    count_second!("test_arity");
                    // SAFETY: The type test proved the term is a live tuple.
                    let tuple = unsafe { term.tuple_ref() };
                    compare_branch!(
                        tuple.is_some_and(|tuple| tuple.len() == arity as usize),
                        fail_arity
                    );
                    // SAFETY: The fused second instruction occupies the next code slot.
                    ip = unsafe { ip.add(2) };
                    continue;
                }
                Instr::IsNilX { src, fail } => {
                    // SAFETY: Specialization validates the X index.
                    compare_branch!(unsafe { *x.add(src as usize) } == Term::NIL, fail);
                }
                Instr::IsNonemptyListX { src, fail } => {
                    // SAFETY: Specialization validates the X index.
                    let term = unsafe { *x.add(src as usize) };
                    compare_branch!(term.classify() == TermKind::List, fail);
                }
                Instr::IsIntegerX { src, fail } => {
                    // SAFETY: Specialization validates the X index and the heap stays live.
                    let term = unsafe { *x.add(src as usize) };
                    // SAFETY: The process or literal heap remains live for the test.
                    let is_big = unsafe { term.big_ref() }.is_some();
                    compare_branch!(term.as_small().is_some() || is_big, fail);
                }
                Instr::TestArityX { src, arity, fail } => {
                    // SAFETY: Specialization validates the X index; live terms retain their heap.
                    let tuple = unsafe { (*x.add(src as usize)).tuple_ref() };
                    compare_branch!(
                        tuple.is_some_and(|tuple| tuple.len() == arity as usize),
                        fail
                    );
                }
                Instr::Select {
                    src,
                    from_y,
                    table,
                    fallback,
                    tuple_arity,
                } => {
                    let mut key = if from_y {
                        if src as usize >= depth {
                            return Err(VmError::Unsupported("Y register".into()));
                        }
                        // SAFETY: The source is within the live stack interval.
                        unsafe { std::mem::transmute::<u64, Term>(*stop.add(src as usize)) }
                    } else {
                        // SAFETY: Specialization validates the X index below 1024.
                        unsafe { *x.add(src as usize) }
                    };
                    if tuple_arity {
                        // SAFETY: The process or literal heap is stable for this instruction.
                        key = Term::small(
                            unsafe { key.tuple_ref() }
                                .map(|tuple| tuple.len())
                                .unwrap_or(usize::MAX) as i64,
                        )
                        .unwrap_or(Term::NIL);
                    }
                    let target = match &module.selects[table as usize] {
                        SelectTable::Linear(entries) => entries
                            .iter()
                            .find(|(value, _)| exact_eq(key, *value))
                            .map(|(_, target)| *target),
                        SelectTable::Sorted(entries) => {
                            if key.is_pointer() {
                                None
                            } else {
                                // SAFETY: Immediate values contain no heap address.
                                let bits = unsafe { key.raw_bits() };
                                entries
                                    .binary_search_by_key(&bits, |(value, _)| *value)
                                    .ok()
                                    .map(|i| entries[i].1)
                            }
                        }
                        SelectTable::Dense { min, targets } => key
                            .as_small()
                            .and_then(|n| n.checked_sub(*min))
                            .and_then(|n| targets.get(n as usize))
                            .copied()
                            .filter(|n| *n != u32::MAX),
                    }
                    .unwrap_or(fallback);
                    if target == u32::MAX {
                        return Err(VmError::Unsupported("failure label zero".into()));
                    }
                    // SAFETY: Select targets and fallback labels are resolved within this module.
                    ip = unsafe { base.add(target as usize) };
                    continue;
                }
                // ---- processes and messages ----
                Instr::Send => {
                    sync_cursor(p, htop, &mut heap_dirty);
                    // SAFETY: The current instruction is within this module.
                    p.ip = unsafe { ip.offset_from(base) } as usize;
                    p.module = module_id;
                    let ctx = ctx
                        .as_deref_mut()
                        .ok_or_else(|| VmError::Unsupported("send requires a scheduler".into()))?;
                    let value = p.send_message_with_vm(self, ctx, p.x[0], p.x[1])?;
                    p.x[0] = value;
                }
                Instr::LoopRec { empty, dst } => {
                    sync_cursor(p, htop, &mut heap_dirty);
                    let ctx = ctx.as_deref_mut().ok_or_else(|| {
                        VmError::Unsupported("receive requires a scheduler".into())
                    })?;
                    p.drain(ctx)?;
                    (htop, stop) = p.heap.heap_cursor();
                    if !p.loop_rec(dst)? {
                        // SAFETY: The label was resolved within this code allocation.
                        ip = unsafe { base.add(empty as usize) };
                        continue;
                    }
                }
                Instr::LoopRecEnd { target } => {
                    p.loop_rec_end();
                    // SAFETY: The label was resolved within this code allocation.
                    ip = unsafe { base.add(target as usize) };
                    continue;
                }
                Instr::RemoveMessage => {
                    if let Some(ctx) = ctx.as_deref_mut()
                        && crate::trace::flags(p, ctx.pid()) & crate::trace::RECEIVE != 0
                        && let Some(&message) = p.inbox.get(p.receive_cursor)
                    {
                        crate::trace::emit(
                            Some(self),
                            p,
                            ctx,
                            ctx.pid(),
                            crate::trace::RECEIVE,
                            "receive",
                            &[message],
                        );
                    }
                    p.remove_message_with_vm(self, ctx.as_deref_mut())?;
                }
                Instr::Wait { target } => {
                    sync_cursor(p, htop, &mut heap_dirty);
                    // The slice may begin at `wait` after a yield that followed
                    // an empty `loop_rec`. The executor has already drained the
                    // ingress, so block only when the mailbox has nothing left
                    // at the save cursor. Port of erts/emulator/beam/emu/msg_instrs.tab
                    // (`wait.execute`), OTP-29.1.1.
                    if !Self::mailbox_ready_to_wait(p, &mut ctx)? {
                        (htop, stop) = p.heap.heap_cursor();
                        // SAFETY: `wait`'s target is the `loop_rec` label in this module.
                        ip = unsafe { base.add(target as usize) };
                        continue;
                    }
                    p.module = module_id;
                    p.ip = target as usize;
                    p.reductions = reds;
                    p.gc_live = 0;
                    return Ok(RunState::Wait { timeout_ms: None });
                }
                Instr::WaitTimeout { target, time } => {
                    sync_cursor(p, htop, &mut heap_dirty);
                    // A receive with no clauses targets this instruction itself:
                    // it must wait out the timer even when messages are queued.
                    // Port of erts/emulator/beam/emu/msg_instrs.tab (`wait_timeout`), OTP-29.1.1.
                    // SAFETY: `ip` is within this module's code allocation.
                    let wait_ip = unsafe { ip.offset_from(base) } as usize;
                    let timeout_only = target as usize == wait_ip;
                    // SAFETY: The current instruction is within this module.
                    p.ip = wait_ip;
                    p.module = module_id;
                    // Same yield window as `wait`: a message drained before this
                    // instruction runs must be matched, not timed out. Port of
                    // erts/emulator/beam/emu/msg_instrs.tab (`wait_timeout`), OTP-29.1.1.
                    if !timeout_only && !Self::mailbox_ready_to_wait(p, &mut ctx)? {
                        (htop, stop) = p.heap.heap_cursor();
                        // SAFETY: `wait_timeout`'s target is the `loop_rec` label.
                        ip = unsafe { base.add(target as usize) };
                        continue;
                    }
                    (htop, stop) = p.heap.heap_cursor();
                    let value = p.read(time)?;
                    let remaining = p.wait_timeout(value)?;
                    if remaining == Some(0) {
                        // SAFETY: The timeout instruction follows wait_timeout.
                        ip = hot_next(ip);
                        continue;
                    }
                    p.module = module_id;
                    p.ip = target as usize;
                    p.reductions = reds;
                    p.gc_live = 0;
                    return Ok(RunState::Wait {
                        timeout_ms: remaining,
                    });
                }
                Instr::Timeout => p.timeout(),
                Instr::IsTaggedTuple {
                    fail,
                    src,
                    arity,
                    tag,
                } => {
                    let term = p.read(src)?;
                    // SAFETY: The term remains in the live process or literal heap.
                    let matched = unsafe { term.tuple_ref() }.is_some_and(|tuple| {
                        tuple.len() == arity as usize && tuple.get(0) == Some(tag)
                    });
                    compare_branch!(matched, fail);
                }
                // ---- vm_funs ----
                Instr::MakeFun { index, dst, env } => {
                    sync_cursor(p, htop, &mut heap_dirty);
                    funs::make_fun(p, module, index, dst, env, self.seen_epoch)?;
                    (htop, stop) = p.heap.heap_cursor();
                    depth = p.heap.stack_words();
                }
                Instr::IsFunction2 { fail, src, arity } => {
                    if !funs::is_function2(p, src, arity)? {
                        if fail == u32::MAX {
                            return Err(VmError::Unsupported("failure label zero".into()));
                        }
                        // SAFETY: The loader resolves nonzero failure labels.
                        ip = unsafe { base.add(fail as usize) };
                        continue;
                    }
                }
                Instr::CallFun { arity, src } => {
                    sync_cursor(p, htop, &mut heap_dirty);
                    // SAFETY: `ip` and `base` point into this module's code.
                    let offset = unsafe { ip.offset_from(base) } as usize;
                    p.module = module_id;
                    p.ip = offset;
                    p.reductions = reds;
                    let fun = p.read(src)?;
                    let outcome =
                        self.call_fun_term(p, fun, arity as usize, false, ctx.as_deref_mut())?;
                    // call_fun may grow X to hold the closure environment.
                    x = p.x.as_mut_ptr();
                    module_id = p.module;
                    base = self.modules[module_id].code.as_ptr();
                    reds = p.reductions;
                    depth = p.heap.stack_words();
                    (htop, stop) = p.heap.heap_cursor();
                    ip = match outcome {
                        ImportOutcome::Returned(value) => return Ok(RunState::Done(value)),
                        ImportOutcome::Yield => {
                            sync_cursor(p, htop, &mut heap_dirty);
                            p.reductions = reds;
                            return Ok(RunState::Yield);
                        }
                        ImportOutcome::Jump(target) => target,
                        ImportOutcome::Advanced => {
                            // SAFETY: The handler advances to a valid code index.
                            unsafe { base.add(p.ip) }
                        }
                    };
                    continue;
                }
                Instr::Apply {
                    arity,
                    dealloc,
                    tail,
                } => {
                    sync_cursor(p, htop, &mut heap_dirty);
                    // SAFETY: `ip` and `base` point into this module's code.
                    let offset = unsafe { ip.offset_from(base) } as usize;
                    p.module = module_id;
                    p.ip = offset;
                    p.reductions = reds;
                    if dealloc > 0 && !p.heap.release_stack(dealloc as usize) {
                        return Err(VmError::Unsupported("stack underflow".into()));
                    }
                    let outcome = self.apply_fixed(p, arity as usize, tail, ctx.as_deref_mut())?;
                    module_id = p.module;
                    base = self.modules[module_id].code.as_ptr();
                    reds = p.reductions;
                    depth = p.heap.stack_words();
                    (htop, stop) = p.heap.heap_cursor();
                    ip = match outcome {
                        ImportOutcome::Returned(value) => return Ok(RunState::Done(value)),
                        ImportOutcome::Yield => {
                            sync_cursor(p, htop, &mut heap_dirty);
                            p.reductions = reds;
                            return Ok(RunState::Yield);
                        }
                        ImportOutcome::Jump(target) => target,
                        ImportOutcome::Advanced => {
                            // SAFETY: The handler advances to a valid code index.
                            unsafe { base.add(p.ip) }
                        }
                    };
                    continue;
                }
                // ---- vm_exc ----
                Instr::Exc { op, a, b } => {
                    sync_cursor(p, htop, &mut heap_dirty);
                    // SAFETY: The current instruction belongs to this module allocation.
                    p.ip = unsafe { ip.offset_from(base) } as usize;
                    p.module = module_id;
                    p.reductions = reds;
                    exceptions::execute(self, p, op, a, b)?;
                    module_id = p.module;
                    base = self.modules[module_id].code.as_ptr();
                    (htop, stop) = p.heap.heap_cursor();
                    depth = p.heap.stack_words();
                    reds = p.reductions;
                    // SAFETY: The handler sets a resolved instruction index.
                    ip = unsafe { base.add(p.ip) };
                    continue;
                }
                Instr::RecvMarkerReserve { dst } => {
                    sync_cursor(p, htop, &mut heap_dirty);
                    let ctx = ctx.as_deref_mut().ok_or_else(|| {
                        VmError::Unsupported("receive marker requires scheduler".into())
                    })?;
                    // Port of erts/emulator/beam/erl_proc_sig_queue.h:2226
                    // (erts_msgq_recv_marker_insert), OTP-29.1.1.
                    p.drain(ctx)?;
                    let marker = p.reserve_receive_marker()?;
                    p.write(dst, marker)?;
                    (htop, stop) = p.heap.heap_cursor();
                }
                Instr::RecvMarkerBind { marker, reference } => {
                    let marker = p.read(marker)?;
                    let reference = p.read(reference)?;
                    p.bind_receive_marker(marker, reference);
                }
                Instr::RecvMarkerClear { reference } => {
                    let reference = p.read(reference)?;
                    p.clear_receive_marker(reference);
                }
                Instr::RecvMarkerUse { reference } => {
                    let reference = p.read(reference)?;
                    p.use_receive_marker(reference);
                }
                Instr::Unsupported(reason) => {
                    if module.unsupported_reasons[reason as usize] == "opcode on_load" {
                        // OTP's on_load marker identifies the entry point and executes as a no-op.
                        // The loader retains it as an unsupported instruction for now.
                        // SAFETY: The next instruction is within the loaded function body.
                        ip = hot_next(ip);
                        continue;
                    }
                    return Err(VmError::Unsupported(
                        module.unsupported_reasons[reason as usize].clone(),
                    ));
                }
                Instr::CodeEnd => {
                    return Err(VmError::Unsupported(
                        "instruction pointer out of bounds".into(),
                    ));
                }
                // ---- vm_maps_bits ----
                // vm_binparse2: context reuse and small positions are general bit syntax cases.
                instr @ (Instr::BsStartReuse { .. } | Instr::BsPositionSmall { .. }) => {
                    let (fallback, fast) = match instr {
                        Instr::BsStartReuse {
                            source,
                            dst,
                            fallback,
                        } => {
                            // SAFETY: Loader validation bounds both X registers.
                            let value = unsafe { *x.add(source as usize) };
                            if is_match_context(value) {
                                // SAFETY: `dst` is a validated X register.
                                unsafe { *x.add(dst as usize) = value };
                                (fallback, true)
                            } else {
                                (fallback, false)
                            }
                        }
                        Instr::BsPositionSmall {
                            context,
                            dst,
                            fallback,
                        } => {
                            // SAFETY: Loader validation bounds both X registers.
                            let value = unsafe { *x.add(context as usize) };
                            let position = match_position(value)
                                .and_then(|n| i64::try_from(n).ok())
                                .and_then(Term::small);
                            if let Some(position) = position {
                                // SAFETY: `dst` is a validated X register.
                                unsafe { *x.add(dst as usize) = position };
                                (fallback, true)
                            } else {
                                (fallback, false)
                            }
                        }
                        _ => unreachable!(),
                    };
                    if fast {
                        // SAFETY: The next instruction belongs to this code allocation.
                        ip = hot_next(ip);
                        continue;
                    }
                    sync_cursor(p, htop, &mut heap_dirty);
                    // SAFETY: `ip` and `base` refer to this module's code allocation.
                    let offset = unsafe { ip.offset_from(base) } as usize;
                    p.reductions = reds;
                    p.module = module_id;
                    p.ip = offset;
                    let op = module.generic[fallback as usize];
                    let frame = || {
                        let (name, arity) = module.function_at(offset).unwrap_or(("?", 0));
                        format!("{}:{name}/{arity}", module.name)
                    };
                    bits::execute(p, module, &op, &frame)?;
                    reds = p.reductions;
                    depth = p.heap.stack_words();
                    (htop, stop) = p.heap.heap_cursor();
                    // SAFETY: The handler sets a resolved code index.
                    ip = unsafe { base.add(p.ip) };
                    continue;
                }
                // bits_cursor: a private one-byte append extends the existing writer.
                Instr::BsAppendByte {
                    source,
                    value,
                    dst,
                    fallback,
                } => {
                    // SAFETY: The loader validates these X register indices.
                    let (binary, integer) =
                        unsafe { (*x.add(source as usize), *x.add(value as usize)) };
                    if arinsal_term::is_writable_binary(binary)
                        && let Some(integer) = integer.as_small()
                        && let Ok(result) =
                            arinsal_bits::private_append_byte(binary, integer, &mut p.heap)
                    {
                        // SAFETY: The destination is a loader-validated X register.
                        unsafe { *x.add(dst as usize) = result };
                        // SAFETY: The next instruction belongs to this allocation.
                        ip = hot_next(ip);
                        continue;
                    }
                    sync_cursor(p, htop, &mut heap_dirty);
                    // SAFETY: `ip` and `base` refer to this module allocation.
                    let offset = unsafe { ip.offset_from(base) } as usize;
                    p.reductions = reds;
                    p.module = module_id;
                    p.ip = offset;
                    let op = module.generic[fallback as usize];
                    let frame = || {
                        let (name, arity) = module.function_at(offset).unwrap_or(("?", 0));
                        format!("{}:{name}/{arity}", module.name)
                    };
                    bits::execute(p, module, &op, &frame)?;
                    reds = p.reductions;
                    depth = p.heap.stack_words();
                    (htop, stop) = p.heap.heap_cursor();
                    // SAFETY: The handler sets a resolved instruction index.
                    ip = unsafe { base.add(p.ip) };
                    continue;
                }
                // vm_binparse2: bound checks and fixed integer reads need no heap sync.
                Instr::BsEnsure {
                    context,
                    bits,
                    unit,
                    fail,
                    exact,
                } if fail != u32::MAX => {
                    // SAFETY: Loader validation bounds every X register index.
                    let ctx = unsafe { *x.add(context as usize) };
                    let matched = is_match_context(ctx)
                        && if exact {
                            ctx.ensure_exactly(bits as usize)
                        } else {
                            ctx.ensure_at_least(bits as usize, unit as usize)
                        };
                    // SAFETY: The loader resolves this failure label and the next instruction.
                    ip = unsafe {
                        if matched {
                            ip.add(1)
                        } else {
                            base.add(fail as usize)
                        }
                    };
                    continue;
                }
                Instr::BsReadU32 { context, dst, fail } if fail != u32::MAX => {
                    // SAFETY: Loader validation bounds every X register index.
                    let ctx = unsafe { *x.add(context as usize) };
                    if let Some(value) = arinsal_bits::match_u32_be(ctx) {
                        // SAFETY: `dst` is an X register validated by the loader.
                        unsafe { *x.add(dst as usize) = Term::small(i64::from(value)).unwrap() };
                        // SAFETY: The next instruction stays in the code allocation.
                        ip = hot_next(ip);
                    } else {
                        // SAFETY: The loader resolves this nonzero failure label.
                        ip = unsafe { base.add(fail as usize) };
                    }
                    continue;
                }
                // bits_cursor: execute the decoded unsigned match without heap sync.
                Instr::BsReadUint {
                    context,
                    dst,
                    fail,
                    ensure_bits,
                    unit,
                    bits,
                } if fail != u32::MAX => {
                    // SAFETY: The loader validates both X indices.
                    let ctx = unsafe { *x.add(context as usize) };
                    if let Some(value) = arinsal_bits::match_uint_be(
                        ctx,
                        ensure_bits as usize,
                        unit as usize,
                        bits as usize,
                    ) {
                        // SAFETY: The destination is a loader-validated X register.
                        unsafe { *x.add(dst as usize) = Term::small(i64::from(value)).unwrap() };
                        // SAFETY: The next instruction belongs to this allocation.
                        ip = hot_next(ip);
                    } else {
                        // SAFETY: The loader resolved the nonzero failure label.
                        ip = unsafe { base.add(fail as usize) };
                    }
                    continue;
                }
                // vm_binparse2: a successful binary match needs only one heap write.
                instr @ Instr::BsBinaryReg {
                    context, size, dst, ..
                } => {
                    sync_cursor(p, htop, &mut heap_dirty);
                    // SAFETY: Loader validation bounds these X register indices.
                    let (ctx, count) = unsafe { (*x.add(context as usize), *x.add(size as usize)) };
                    let bits = count
                        .as_small()
                        .and_then(|value| usize::try_from(value).ok())
                        .and_then(|value| value.checked_mul(8));
                    let result = if is_match_context(ctx) {
                        bits.and_then(|bits| ctx.get_binary(bits, &mut p.heap).ok().flatten())
                    } else {
                        None
                    };
                    if let Some(value) = result {
                        // SAFETY: `dst` is an X register validated by the loader.
                        unsafe { *x.add(dst as usize) = value };
                        (htop, stop) = p.heap.heap_cursor();
                        // SAFETY: The next instruction remains in the code allocation.
                        ip = hot_next(ip);
                        continue;
                    }
                    // Guard failure and heap exhaustion retain the full exception path.
                    // SAFETY: `ip` and `base` refer to this module's code allocation.
                    let offset = unsafe { ip.offset_from(base) } as usize;
                    p.reductions = reds;
                    p.module = module_id;
                    p.ip = offset;
                    bits::execute_compact(p, instr, || {
                        let (name, arity) = module.function_at(offset).unwrap_or(("?", 0));
                        format!("{}:{name}/{arity}", module.name)
                    })?;
                    reds = p.reductions;
                    depth = p.heap.stack_words();
                    (htop, stop) = p.heap.heap_cursor();
                    // SAFETY: The handler sets a resolved code index.
                    ip = unsafe { base.add(p.ip) };
                    continue;
                }
                // vm_binparse2: allocating bit commands retain their generic handlers.
                instr @ (Instr::BsEnsure { .. }
                | Instr::BsReadU32 { .. }
                | Instr::BsReadUint { .. }
                | Instr::BsTail { .. }
                | Instr::BsMatchTail { .. }) => {
                    sync_cursor(p, htop, &mut heap_dirty);
                    // SAFETY: `ip` and `base` refer to this module's code allocation.
                    let offset = unsafe { ip.offset_from(base) } as usize;
                    p.reductions = reds;
                    p.module = module_id;
                    p.ip = offset;
                    bits::execute_compact(p, instr, || {
                        let (name, arity) = module.function_at(offset).unwrap_or(("?", 0));
                        format!("{}:{name}/{arity}", module.name)
                    })?;
                    reds = p.reductions;
                    depth = p.heap.stack_words();
                    (htop, stop) = p.heap.heap_cursor();
                    // SAFETY: The handler sets a resolved code index.
                    ip = unsafe { base.add(p.ip) };
                    continue;
                }
                Instr::MapsBits(index) => {
                    sync_cursor(p, htop, &mut heap_dirty);
                    // SAFETY: `ip` and `base` refer to this module's code allocation.
                    let offset = unsafe { ip.offset_from(base) } as usize;
                    p.reductions = reds;
                    p.module = module_id;
                    p.ip = offset;
                    let op = module.generic[index as usize];
                    let frame = || {
                        let (name, arity) = module.function_at(offset).unwrap_or(("?", 0));
                        format!("{}:{name}/{arity}", module.name)
                    };
                    if matches!(
                        op.opcode(),
                        Opcode::PutMapAssoc | Opcode::PutMapExact | Opcode::HasMapFields
                    ) {
                        maps::execute(p, module, &op, &frame())?;
                    } else if op.opcode() == Opcode::GetMapElements {
                        execute_get_map_elements(p, module, &op)?;
                    } else {
                        let frame = || {
                            let (name, arity) = module.function_at(offset).unwrap_or(("?", 0));
                            format!("{}:{name}/{arity}", module.name)
                        };
                        bits::execute(p, module, &op, &frame)?;
                    }
                    reds = p.reductions;
                    depth = p.heap.stack_words();
                    (htop, stop) = p.heap.heap_cursor();
                    // SAFETY: Feature handlers set a resolved code index.
                    ip = unsafe { base.add(p.ip) };
                    continue;
                }
                Instr::Generic(index) => {
                    sync_cursor(p, htop, &mut heap_dirty);
                    // SAFETY: `ip` and `base` belong to the current module.
                    let offset = unsafe { ip.offset_from(base) } as usize;
                    p.reductions = reds;
                    p.module = module_id;
                    p.ip = offset;
                    let op: GenericOp = module.generic[index as usize];
                    let opcode = op.opcode();
                    let [a, b, c] = op.args;
                    let mut native_target = None;
                    match opcode {
                        Opcode::FuncInfo => return Err(self.exception(p, "function_clause")),
                        Opcode::PutRecord => execute_put_record(p, module, &op)?,
                        Opcode::OnLoad => {
                            // The opcode marks the module's on_load entry for the loader;
                            // code metadata retains that entry while execution advances past it.
                            p.ip += 1;
                        }
                        Opcode::IntCodeEnd => {
                            return Err(VmError::Unsupported("int_code_end".into()));
                        }
                        Opcode::Move => {
                            let value = p.read(a)?;
                            p.write(b, value)?;
                            p.ip += 1;
                        }
                        Opcode::Swap => {
                            let av = p.read(a)?;
                            let bv = p.read(b)?;
                            p.write(a, bv)?;
                            p.write(b, av)?;
                            p.ip += 1;
                        }
                        Opcode::Return => {
                            if let Some(value) = Self::ret(p) {
                                return Ok(RunState::Done(value));
                            }
                        }
                        Opcode::Call | Opcode::CallLast | Opcode::CallOnly => {
                            p.gc_live = a.value() as usize;
                            if opcode == Opcode::CallLast {
                                p.heap.release_stack(module.arg(&op, 2).value() as usize);
                            }
                            if opcode == Opcode::Call {
                                calls::push_continuation(
                                    p,
                                    p.module,
                                    p.ip + 1,
                                    a.value() as usize,
                                )?;
                            }
                            p.ip = b.value() as usize;
                            native_target = Some((p.module, p.ip));
                            p.tick();
                        }
                        Opcode::CallExt | Opcode::CallExtLast | Opcode::CallExtOnly => {
                            let tail = opcode != Opcode::CallExt;
                            if opcode == Opcode::CallExtLast {
                                p.heap.release_stack(c.value() as usize);
                            }
                            let outcome = self.call_import(
                                p,
                                b.value() as usize,
                                a.value() as usize,
                                tail,
                                ctx.as_deref_mut(),
                            )?;
                            match outcome {
                                ImportOutcome::Returned(value) => {
                                    return Ok(RunState::Done(value));
                                }
                                ImportOutcome::Yield => {
                                    sync_cursor(p, htop, &mut heap_dirty);
                                    p.reductions = reds;
                                    return Ok(RunState::Yield);
                                }
                                ImportOutcome::Jump(_) => {
                                    native_target = Some((p.module, p.ip));
                                }
                                ImportOutcome::Advanced => {}
                            }
                        }
                        Opcode::Allocate | Opcode::AllocateHeap => {
                            let n = a.value() as usize;
                            let extra = if opcode == Opcode::AllocateHeap {
                                b.value() as usize
                            } else {
                                0
                            };
                            let live = if opcode == Opcode::AllocateHeap {
                                c.value() as usize
                            } else {
                                b.value() as usize
                            };
                            p.gc_live = live;
                            if p.heap.free_words() < n + extra {
                                p.ensure(n + extra, live)?;
                            }
                            if !p.heap.reserve_stack(n) {
                                return Err(VmError::Unsupported("stack allocation".into()));
                            }
                            p.ip += 1;
                        }
                        Opcode::Deallocate => {
                            if !p.heap.release_stack(a.value() as usize) {
                                return Err(VmError::Unsupported("stack underflow".into()));
                            }
                            p.ip += 1;
                        }
                        Opcode::Trim => {
                            if !p.heap.release_stack(a.value() as usize) {
                                return Err(VmError::Unsupported("trim underflow".into()));
                            }
                            p.ip += 1;
                        }
                        Opcode::TestHeap => {
                            p.gc_live = b.value() as usize;
                            if p.heap.free_words() < a.value() as usize {
                                p.ensure(a.value() as usize, b.value() as usize)?;
                            }
                            p.ip += 1;
                        }
                        Opcode::InitYregs => {
                            for reg in &module.lists[a.value() as usize] {
                                p.write(*reg, Term::NIL)?;
                            }
                            p.ip += 1;
                        }
                        Opcode::Jump => {
                            p.ip = a.value() as usize;
                        }
                        Opcode::IsLt
                        | Opcode::IsGe
                        | Opcode::IsEq
                        | Opcode::IsNe
                        | Opcode::IsEqExact
                        | Opcode::IsNeExact => {
                            let left = p.read(b)?;
                            let right = p.read(c)?;
                            let ok = match opcode {
                                Opcode::IsLt => cmp(left, right).is_lt(),
                                Opcode::IsGe => !cmp(left, right).is_lt(),
                                Opcode::IsEq => loose_eq(left, right),
                                Opcode::IsNe => !loose_eq(left, right),
                                Opcode::IsEqExact => exact_eq(left, right),
                                Opcode::IsNeExact => !exact_eq(left, right),
                                _ => unreachable!(),
                            };
                            if ok {
                                p.ip += 1;
                            } else {
                                Self::branch(p, a)?;
                            }
                        }
                        Opcode::IsPort => {
                            if p.read(b)?.classify() == TermKind::Port {
                                p.ip += 1;
                            } else {
                                Self::branch(p, a)?;
                            }
                        }
                        Opcode::IsPid => {
                            if p.read(b)?.classify() == TermKind::Pid {
                                p.ip += 1;
                            } else {
                                Self::branch(p, a)?;
                            }
                        }
                        Opcode::IsReference => {
                            if p.read(b)?.classify() == TermKind::Ref {
                                p.ip += 1;
                            } else {
                                Self::branch(p, a)?;
                            }
                        }
                        Opcode::IsAnyNativeRecord => {
                            Self::branch(p, a)?;
                        }
                        Opcode::IsTuple
                        | Opcode::IsNil
                        | Opcode::IsNonemptyList
                        | Opcode::IsList
                        | Opcode::IsInteger
                        | Opcode::IsFloat
                        | Opcode::IsNumber
                        | Opcode::IsAtom
                        | Opcode::IsBinary
                        | Opcode::IsMap
                        | Opcode::IsBoolean
                        | Opcode::IsFunction => {
                            let term = p.read(b)?;
                            let kind = term.classify();
                            let ok = match opcode {
                                Opcode::IsTuple => kind == TermKind::Tuple,
                                Opcode::IsNil => kind == TermKind::Nil,
                                Opcode::IsNonemptyList => kind == TermKind::List,
                                Opcode::IsList => matches!(kind, TermKind::Nil | TermKind::List),
                                Opcode::IsInteger => {
                                    // SAFETY: The term's heap remains live for this instruction.
                                    term.as_small().is_some() || unsafe { term.big_ref() }.is_some()
                                }
                                Opcode::IsFloat => {
                                    // SAFETY: The term's heap remains live for this instruction.
                                    unsafe { term.float_ref() }.is_some()
                                }
                                Opcode::IsNumber => kind == TermKind::Number,
                                Opcode::IsAtom => kind == TermKind::Atom,
                                Opcode::IsBinary => kind == TermKind::Bitstring,
                                Opcode::IsMap => kind == TermKind::Map,
                                Opcode::IsPid => kind == TermKind::Pid,
                                Opcode::IsBoolean => {
                                    term == Term::atom(arinsal_term::atoms::TRUE)
                                        || term == Term::atom(arinsal_term::atoms::FALSE)
                                }
                                Opcode::IsFunction => kind == TermKind::Fun,
                                _ => false,
                            };
                            if ok {
                                p.ip += 1;
                            } else {
                                Self::branch(p, a)?;
                            }
                        }
                        Opcode::TestArity => {
                            // SAFETY: The term's heap remains live for this instruction.
                            let len = unsafe { p.read(b)?.tuple_ref() }.map(|v| v.len());
                            if len == Some(c.value() as usize) {
                                p.ip += 1;
                            } else {
                                Self::branch(p, a)?;
                            }
                        }
                        Opcode::GetTupleElement => {
                            let tuple = p.read(a)?;
                            // SAFETY: This instruction only reads a tuple in a live heap.
                            let value = unsafe { tuple.tuple_ref() }
                                .and_then(|v| v.get(b.value() as usize))
                                .ok_or_else(|| self.exception(p, "badarg"))?;
                            p.write(c, value)?;
                            p.ip += 1;
                        }
                        Opcode::PutTuple2 => {
                            // Port of erts/emulator/beam/jit/arm/instr_common.cpp:794, OTP-29.1.1.
                            let items = &module.lists[b.value() as usize];
                            if p.heap.free_words() < items.len() + 1 {
                                p.ensure(items.len() + 1, p.gc_live)?;
                            }
                            // Validate all operands before reserving tuple space so malformed
                            // operands still fail without partially allocating the tuple.
                            for &arg in items {
                                p.read(arg)?;
                            }
                            let tuple = if items.iter().all(|arg| arg.kind() != Arg::Y) {
                                let x: &[Term] = &p.x;
                                let values = items
                                    .iter()
                                    .copied()
                                    .map(|arg| read_validated_non_y_arg(x, arg));
                                TermBuilder::new(&mut p.heap)
                                    .tuple_iter(items.len(), values)
                                    .map_err(|e| {
                                        VmError::Unsupported(format!("tuple allocation {e:?}"))
                                    })?
                            } else {
                                let x: &[Term] = &p.x;
                                TermBuilder::new(&mut p.heap)
                                    .tuple_from_fn(items.len(), |index, heap| {
                                        read_validated_arg(heap, x, items[index])
                                    })
                                    .map_err(|e| {
                                        VmError::Unsupported(format!("tuple allocation {e:?}"))
                                    })?
                            };
                            p.write(a, tuple)?;
                            p.ip += 1;
                        }
                        Opcode::PutList => {
                            if p.heap.free_words() < 2 {
                                p.ensure(2, p.gc_live)?;
                            }
                            let head = p.read(a)?;
                            let tail = p.read(b)?;
                            let value =
                                TermBuilder::new(&mut p.heap)
                                    .cons(head, tail)
                                    .map_err(|e| {
                                        VmError::Unsupported(format!("list allocation {e:?}"))
                                    })?;
                            p.write(c, value)?;
                            p.ip += 1;
                        }
                        Opcode::GetList | Opcode::GetHd | Opcode::GetTl => {
                            // SAFETY: The source list remains in a live process or literal heap.
                            let (head, tail) = unsafe { p.read(a)?.cons_ref() }
                                .ok_or_else(|| self.exception(p, "badarg"))?;
                            match opcode {
                                Opcode::GetList => {
                                    p.write(b, head)?;
                                    p.write(c, tail)?;
                                }
                                Opcode::GetHd => p.write(b, head)?,
                                Opcode::GetTl => p.write(b, tail)?,
                                _ => unreachable!(),
                            }
                            p.ip += 1;
                        }
                        Opcode::GcBif1
                        | Opcode::GcBif2
                        | Opcode::GcBif3
                        | Opcode::Bif0
                        | Opcode::Bif1
                        | Opcode::Bif2
                        | Opcode::Bif3 => {
                            if !execute_tuple_bif(p, module, &op, opcode)?
                                && !execute_guard_bif(p, module, &op, opcode)?
                                && !execute_small_bif(p, module, &op, opcode)?
                            {
                                self.exec_bif_op(p, ctx.as_deref_mut(), op, opcode)?;
                            }
                        }
                        Opcode::Fmove | Opcode::Fconv => {
                            let value = p.float(a)?;
                            p.set_float(b, value)?;
                            p.ip += 1;
                        }
                        Opcode::Fadd | Opcode::Fsub | Opcode::Fmul | Opcode::Fdiv => {
                            let x = p.float(b)?;
                            let y = p.float(c)?;
                            let result = match opcode {
                                Opcode::Fadd => x + y,
                                Opcode::Fsub => x - y,
                                Opcode::Fmul => x * y,
                                Opcode::Fdiv => x / y,
                                _ => unreachable!(),
                            };
                            p.set_float(module.arg(&op, 3), result)?;
                            p.ip += 1;
                        }
                        Opcode::Fnegate => {
                            let value = -p.float(b)?;
                            p.set_float(c, value)?;
                            p.ip += 1;
                        }
                        Opcode::SelectVal | Opcode::SelectTupleArity => {
                            let value = p.read(a)?;
                            let key = if opcode == Opcode::SelectTupleArity {
                                // SAFETY: The term's heap remains live for this instruction.
                                Term::small(
                                    unsafe { value.tuple_ref() }
                                        .map(|v| v.len())
                                        .unwrap_or(usize::MAX)
                                        as i64,
                                )
                                .unwrap_or(Term::NIL)
                            } else {
                                value
                            };
                            let list = &module.lists[c.value() as usize];
                            let mut target = b;
                            for pair in list.as_chunks::<2>().0 {
                                let candidate = if opcode == Opcode::SelectTupleArity
                                    && pair[0].kind() == Arg::U
                                {
                                    i64::try_from(pair[0].value())
                                        .ok()
                                        .and_then(Term::small)
                                        .ok_or_else(|| {
                                            VmError::Unsupported("tuple arity out of range".into())
                                        })?
                                } else {
                                    p.read(pair[0])?
                                };
                                if exact_eq(key, candidate) {
                                    target = pair[1];
                                    break;
                                }
                            }
                            Self::branch(p, target)?;
                        }
                        Opcode::UpdateRecord => {
                            // Port of erts/emulator/beam/jit/arm/instr_common.cpp:893, OTP-29.1.1.
                            let arity = b.value() as usize;
                            if p.heap.free_words() < arity + 1 {
                                p.ensure(arity + 1, p.gc_live)?;
                            }
                            let source = p.read(c)?;
                            // SAFETY: The source remains on the process heap for this instruction.
                            let tuple = unsafe { source.tuple_ref() }
                                .filter(|tuple| tuple.len() == arity)
                                .ok_or_else(|| {
                                    VmError::Unsupported("update_record source arity".into())
                                })?;
                            let updates = module.arg(&op, 4);
                            let updates =
                                module.lists.get(updates.value() as usize).ok_or_else(|| {
                                    VmError::Unsupported("update_record update list".into())
                                })?;
                            // The reuse hint permits a copy; avoiding in-place mutation also
                            // preserves old-generation pointer safety.
                            let tuple = if updates.len() == 2 {
                                let index = updates[0].value() as usize;
                                if index == 0 || index > arity {
                                    return Err(VmError::Unsupported(
                                        "update_record field index".into(),
                                    ));
                                }
                                let value = p.read(updates[1])?;
                                TermBuilder::new(&mut p.heap)
                                    .tuple_iter(
                                        arity,
                                        (0..arity).map(|field| {
                                            if field + 1 == index {
                                                value
                                            } else {
                                                tuple.get(field).expect("tuple arity was checked")
                                            }
                                        }),
                                    )
                                    .map_err(|error| {
                                        VmError::Unsupported(format!(
                                            "update_record allocation {error:?}"
                                        ))
                                    })?
                            } else {
                                for pair in updates.as_chunks::<2>().0 {
                                    let index = pair[0].value() as usize;
                                    if index == 0 || index > arity {
                                        return Err(VmError::Unsupported(
                                            "update_record field index".into(),
                                        ));
                                    }
                                    p.read(pair[1])?;
                                }
                                let mut update_index = 0;
                                let x: &[Term] = &p.x;
                                TermBuilder::new(&mut p.heap)
                                    .tuple_from_fn(arity, |index, heap| {
                                        let original =
                                            tuple.get(index).expect("tuple arity was checked");
                                        let field = index + 1;
                                        while updates
                                            .get(update_index * 2)
                                            .is_some_and(|arg| (arg.value() as usize) < field)
                                        {
                                            update_index += 1;
                                        }
                                        let mut replacement = None;
                                        while updates
                                            .get(update_index * 2)
                                            .is_some_and(|arg| (arg.value() as usize) == field)
                                        {
                                            let value_arg = updates[update_index * 2 + 1];
                                            update_index += 1;
                                            replacement =
                                                Some(read_validated_arg(heap, x, value_arg));
                                        }
                                        replacement.unwrap_or(original)
                                    })
                                    .map_err(|error| {
                                        VmError::Unsupported(format!(
                                            "update_record allocation {error:?}"
                                        ))
                                    })?
                            };
                            p.write(module.arg(&op, 3), tuple)?;
                            p.ip += 1;
                        }
                        Opcode::Badmatch => {
                            return Err(self.exception(p, format!("{{badmatch,{}}}", p.read(a)?)));
                        }
                        Opcode::CaseEnd => {
                            return Err(
                                self.exception(p, format!("{{case_clause,{}}}", p.read(a)?))
                            );
                        }
                        Opcode::IfEnd => return Err(self.exception(p, "if_clause")),
                        Opcode::ExecutableLine | Opcode::DebugLine => p.ip += 1,
                        _ => {
                            return Err(VmError::Unsupported(format!(
                                "opcode {} in {} at {}",
                                opcode.name(),
                                module.name,
                                p.ip
                            )));
                        }
                    }
                    module_id = p.module;
                    base = self.modules[module_id].code.as_ptr();
                    reds = p.reductions;
                    depth = p.heap.stack_words();
                    (htop, stop) = p.heap.heap_cursor();
                    // SAFETY: Generic handlers set a resolved code index before dispatch.
                    ip = unsafe { base.add(p.ip) };
                    if matches!(
                        opcode,
                        Opcode::CallExt | Opcode::CallExtLast | Opcode::CallExtOnly
                    ) {
                        // g_code_fix: nested on_load may reallocate X and FR.
                        x = p.x.as_mut_ptr();
                        fr = p.fr.as_mut_ptr();
                    }
                    if matches!(
                        opcode,
                        Opcode::Call
                            | Opcode::CallLast
                            | Opcode::CallOnly
                            | Opcode::CallExt
                            | Opcode::CallExtLast
                            | Opcode::CallExtOnly
                    ) {
                        // Port of erts/emulator/beam/jit/arm/process_main.cpp:235-317,
                        // OTP-29.1.1: native entries resume only at scheduler boundaries.
                        if let Some((target_module, target_ip)) = native_target
                            && let Some(native) = self.beamasm_targets.function_for_target(
                                target_module,
                                &self.modules[target_module],
                                target_ip,
                            )
                        {
                            p.module = target_module;
                            p.ip = target_ip;
                            p.reductions = reds;
                            p.native_pc = Some(native.start);
                            return Ok(RunState::Yield);
                        }
                    }
                    continue;
                }
            );
            // SAFETY: The loader appends CodeEnd after the final decoded opcode.
            ip = unsafe { ip.add(1) };
        }
    }
}

#[cfg(test)]
mod trace_frame_tests {
    use super::*;

    #[test]
    fn return_trace_frame_preserves_wide_session_ids() {
        let mut process = Process::new();
        let session = 0x7000_0000_0000_0001;
        let actions = [crate::trace::CallActions {
            session,
            return_trace: true,
            exception_trace: true,
            return_to: false,
        }];
        push_trace_frames(&mut process, 3, 7, 11, 13, &actions).unwrap();
        assert_eq!(process.heap.stack_get(1).and_then(Term::as_small), Some(3));
        assert_eq!(process.heap.stack_get(2).and_then(Term::as_small), Some(7));
        assert_eq!(
            process.heap.stack_get(3).and_then(Term::as_small),
            Some((session >> 32) as i64)
        );
        assert_eq!(
            process.heap.stack_get(4).and_then(Term::as_small),
            Some(session as u32 as i64)
        );
        assert_eq!(process.heap.stack_get(5).and_then(Term::as_small), Some(1));
    }
}
