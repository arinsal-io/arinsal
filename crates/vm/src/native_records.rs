//! Runtime helpers of the native record instructions in native code.
//!
//! Port of erts/emulator/beam/erl_record.c:223-578 (erl_get_record_elements,
//! erl_create_local_native_record, erl_create_native_record, erl_update_native_record,
//! erl_get_local_record_field, erl_get_record_field), OTP-29.1.1. The emitted code stages the
//! key/value operands in the scheduler X register array, sorted by field name like the loader's
//! `map_key_sort`, and these helpers merge them with the definition's keys in atom-index order.

use crate::{Process, native_hooks, native_hooks::enter_runtime};
use arinsal_beamasm::ProcessHeader;
use arinsal_term::{Atom, Term, TermBuilder, global_atoms, term_sequence};

/// Why a record operation failed, reported as `error:{Tag, Value}`.
enum Failure {
    /// `{badrecord, Value}`.
    BadRecord(Term),
    /// `{badfield, {{Module, Name}, Field}}`.
    BadField(Atom, Atom, Atom),
    /// `{novalue, {{Module, Name}, Field}}`.
    NoValue(Atom, Atom, Atom),
    /// A heap that cannot hold the result.
    SystemLimit,
}

/// Fields of a record definition tuple.
struct Definition {
    module: Atom,
    name: Atom,
    exported: bool,
    /// Field names in atom-index order.
    keys: Vec<Atom>,
}

impl Definition {
    fn parse(definition: Term) -> Option<Self> {
        // `{FieldOrder, Hash, Module, Name, IsExported | Keys}`.
        let words = term_sequence(definition)?;
        let [_, _, module, name, exported, keys @ ..] = words.as_slice() else {
            return None;
        };
        Some(Self {
            module: module.as_atom()?,
            name: name.as_atom()?,
            exported: *exported == Term::atom(arinsal_term::atoms::TRUE),
            keys: keys
                .iter()
                .map(|key| key.as_atom())
                .collect::<Option<Vec<_>>>()?,
        })
    }
}

fn report(process: &mut Process, failure: Failure) {
    let (tag, value) = match failure {
        Failure::BadRecord(value) => ("badrecord", Ok(value)),
        Failure::BadField(module, name, field) => {
            ("badfield", field_value(process, module, name, field))
        }
        Failure::NoValue(module, name, field) => {
            ("novalue", field_value(process, module, name, field))
        }
        Failure::SystemLimit => {
            native_hooks::set_error(process, "system_limit");
            return;
        }
    };
    match value
        .and_then(|value| crate::exceptions::tuple(process, &[crate::atom_cache::put(tag), value]))
    {
        Ok(reason) => {
            process.heap.abi.exc.freason = arinsal_beamasm::exc::EXC_ERROR;
            process.heap.abi.exc.fvalue = native_hooks::raw(reason);
        }
        Err(_) => native_hooks::set_error(process, "system_limit"),
    }
}

/// `{{Module, Name}, Field}`.
// Port of erts/emulator/beam/erl_record.c:325-331, OTP-29.1.1.
fn field_value(
    process: &mut Process,
    module: Atom,
    name: Atom,
    field: Atom,
) -> Result<Term, crate::VmError> {
    let id = crate::exceptions::tuple(process, &[Term::atom(module), Term::atom(name)])?;
    crate::exceptions::tuple(process, &[id, Term::atom(field)])
}

/// Make the live X registers and the staged operands collector roots; the registers between
/// the live prefix and the staged words are dead and must not be roots. `x` is the register
/// array the fragment passed, so the collector moves the roots in place.
fn stage_roots(x: &mut [Term], live: usize, base: usize, top: usize) -> Option<()> {
    if top > x.len() {
        return None;
    }
    x[live..base].fill(Term::NIL);
    Some(())
}

/// Merge the sorted staged `(key, value)` words with a record's sorted keys.
fn staged_pairs(x: &[Term], base: usize, count: usize) -> Vec<(Term, Term)> {
    (0..count / 2)
        .map(|pair| (x[base + 2 * pair], x[base + 2 * pair + 1]))
        .collect()
}

/// The registered definition literal of `Module:Name` when it is exported.
fn exported_definition(id: Term) -> Option<Term> {
    let parts = term_sequence(id)?;
    let [module, name] = parts.as_slice() else {
        return None;
    };
    let cons = arinsal_term::find_record_definition(module.as_atom()?, name.as_atom()?)?;
    let (definition, _) = crate::lists::split(cons)?;
    Definition::parse(definition)?.exported.then_some(cons)
}

/// Port of erts/emulator/beam/erl_record.c:254-379 (erl_create_local_native_record,
/// erl_create_native_record), OTP-29.1.1.
fn create(
    header: *mut ProcessHeader,
    reg: *mut u64,
    id: u64,
    live: u64,
    count: u64,
    base: u64,
    external: bool,
) -> u64 {
    let Some((process, registers)) = native_hooks::enter_runtime_reg(header, reg) else {
        return 0;
    };
    let (Ok(live), Ok(count), Ok(base)) = (
        usize::try_from(live),
        usize::try_from(count),
        usize::try_from(base),
    ) else {
        return 0;
    };
    let result = create_record(
        process,
        &mut registers.x_reg_array,
        native_hooks::from_raw(id),
        (live, count, base),
        external,
    );
    match result {
        Ok(record) => native_hooks::raw(record),
        Err(failure) => {
            report(process, failure);
            0
        }
    }
}

fn create_record(
    process: &mut Process,
    x: &mut [Term],
    id: Term,
    (live, count, base): (usize, usize, usize),
    external: bool,
) -> Result<Term, Failure> {
    let cons = if external {
        exported_definition(id).ok_or(Failure::BadRecord(id))?
    } else {
        id
    };
    let (definition_term, defaults) = crate::lists::split(cons).ok_or(Failure::SystemLimit)?;
    let definition = Definition::parse(definition_term).ok_or(Failure::SystemLimit)?;
    let defaults = term_sequence(defaults).ok_or(Failure::SystemLimit)?;
    let top = base + count;
    stage_roots(x, live, base, top).ok_or(Failure::SystemLimit)?;
    process
        .ensure_objv(2 + definition.keys.len(), &mut x[..top])
        .map_err(|_| Failure::SystemLimit)?;
    let pairs = staged_pairs(x, base, count);
    let mut values = Vec::with_capacity(definition.keys.len());
    let mut next = 0;
    let mut missing = None;
    for (key, default) in definition.keys.iter().zip(&defaults) {
        if pairs
            .get(next)
            .is_some_and(|(given, _)| *given == Term::atom(*key))
        {
            values.push(pairs[next].1);
            next += 1;
        } else if *default == Term::catch(0) {
            // A field without a default is reported after a `badfield`, which outranks it.
            missing.get_or_insert(*key);
            values.push(Term::NIL);
        } else {
            values.push(*default);
        }
    }
    if let Some((field, _)) = pairs.get(next) {
        let field = field.as_atom().unwrap_or(definition.name);
        return Err(Failure::BadField(definition.module, definition.name, field));
    }
    if let Some(field) = missing {
        return Err(Failure::NoValue(definition.module, definition.name, field));
    }
    TermBuilder::new(&mut process.heap)
        .native_record_instance(definition_term, &values)
        .map_err(|_| Failure::SystemLimit)
}

/// Runtime helper of `i_create_local_native_record`.
pub extern "C" fn arinsal_beamasm_create_local_record(
    header: *mut ProcessHeader,
    reg: *mut u64,
    definition: u64,
    live: u64,
    count: u64,
    base: u64,
) -> u64 {
    create(header, reg, definition, live, count, base, false)
}

/// Runtime helper of `i_create_native_record`.
pub extern "C" fn arinsal_beamasm_create_record(
    header: *mut ProcessHeader,
    reg: *mut u64,
    id: u64,
    live: u64,
    count: u64,
    base: u64,
) -> u64 {
    create(header, reg, id, live, count, base, true)
}

/// Port of erts/emulator/beam/erl_record.c:381-468 (erl_update_native_record), OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_update_record(
    header: *mut ProcessHeader,
    reg: *mut u64,
    source: u64,
    live: u64,
    count: u64,
    base: u64,
) -> u64 {
    let Some((process, registers)) = native_hooks::enter_runtime_reg(header, reg) else {
        return 0;
    };
    let (Ok(live), Ok(count), Ok(base)) = (
        usize::try_from(live),
        usize::try_from(count),
        usize::try_from(base),
    ) else {
        return 0;
    };
    let result = update_record(
        process,
        &mut registers.x_reg_array,
        native_hooks::from_raw(source),
        (live, count, base),
    );
    match result {
        Ok(record) => native_hooks::raw(record),
        Err(failure) => {
            report(process, failure);
            0
        }
    }
}

fn update_record(
    process: &mut Process,
    x: &mut [Term],
    source: Term,
    (live, count, base): (usize, usize, usize),
) -> Result<Term, Failure> {
    let snapshot = source.record_snapshot().ok_or(Failure::BadRecord(source))?;
    // The source is the only operand the collector may not know about: it rides after the
    // staged words.
    let source_slot = base + count;
    let top = source_slot + 1;
    if top > x.len() {
        return Err(Failure::SystemLimit);
    }
    x[source_slot] = source;
    stage_roots(x, live, base, top).ok_or(Failure::SystemLimit)?;
    process
        .ensure_objv(2 + snapshot.fields.len(), &mut x[..top])
        .map_err(|_| Failure::SystemLimit)?;
    let source = x[source_slot];
    let snapshot = source.record_snapshot().ok_or(Failure::BadRecord(source))?;
    let definition = Definition::parse(snapshot.definition).ok_or(Failure::SystemLimit)?;
    let pairs = staged_pairs(x, base, count);
    let mut values = snapshot.values.clone();
    let mut next = 0;
    for (index, key) in definition.keys.iter().enumerate() {
        if pairs
            .get(next)
            .is_some_and(|(given, _)| *given == Term::atom(*key))
        {
            values[index] = pairs[next].1;
            next += 1;
        }
    }
    if let Some((field, _)) = pairs.get(next) {
        let field = field.as_atom().unwrap_or(definition.name);
        return Err(Failure::BadField(definition.module, definition.name, field));
    }
    TermBuilder::new(&mut process.heap)
        .native_record_instance(snapshot.definition, &values)
        .map_err(|_| Failure::SystemLimit)
}

/// Port of the x86 `GetSource` operands in erl_record.c's native record helpers.
fn x86_elements(
    elements: *const u64,
    count: usize,
    x: &[Term],
    stack: &arinsal_term::ProcessHeap,
) -> Option<Vec<Term>> {
    let elements = crate::raw::runtime_ffi::RuntimeOperandArray::from_raw(elements, count)?;
    crate::raw::runtime_ffi::resolve_operands(elements, x, stack)
}

/// Scans the definition's atom-sorted fields once and writes values for the sorted request.
// Port of erts/emulator/beam/erl_record.c:223-252 (erl_get_record_elements), OTP-29.1.1.
fn scan_record_elements(
    definition: &Definition,
    values: &[Term],
    count: usize,
    mut match_and_put: impl FnMut(usize, Term, Term) -> Option<bool>,
) -> bool {
    let mut next = 0;
    for (key, value) in definition.keys.iter().zip(values) {
        if next < count {
            match match_and_put(next, Term::atom(*key), *value) {
                None => return false,
                Some(true) => {
                    next += 1;
                    if next == count {
                        return true;
                    }
                }
                Some(false) => {}
            }
        }
    }
    false
}

/// Port of erts/emulator/beam/erl_record.c:223-252 (erl_get_record_elements), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erl_get_record_elements(
    header: *mut ProcessHeader,
    reg: *mut u64,
    source: u64,
    count: usize,
    elements: *const u64,
) -> bool {
    let Some((process, registers)) = native_hooks::enter_runtime_reg(header, reg) else {
        return false;
    };
    let Some(operands) = crate::raw::runtime_ffi::RuntimeOperandArray::from_raw(elements, count)
    else {
        return false;
    };
    let Some(snapshot) = native_hooks::from_raw(source).record_snapshot() else {
        return false;
    };
    let Some(definition) = Definition::parse(snapshot.definition) else {
        return false;
    };
    let requests = count / 2;
    scan_record_elements(
        &definition,
        &snapshot.values,
        requests,
        |index, key, value| {
            let descriptor = operands.get(index * 2)?;
            let requested = crate::raw::runtime_ffi::get_source(
                descriptor,
                &registers.x_reg_array,
                &process.heap,
            )?;
            if requested != key {
                return Some(false);
            }
            let destination = operands.get(index * 2 + 1)?;
            Some(crate::raw::runtime_ffi::put_term_reg(
                destination,
                value,
                &mut registers.x_reg_array,
                &mut process.heap,
            ))
        },
    )
}

/// Port of erts/emulator/beam/erl_record.c:254-379 (erl_create_local_native_record), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erl_create_local_native_record(
    header: *mut ProcessHeader,
    reg: *mut u64,
    definition: u64,
    live: u64,
    count: usize,
    elements: *const u64,
) -> u64 {
    x86_create_record(header, reg, definition, live, count, elements, false)
}

/// Port of erts/emulator/beam/erl_record.c:337-379 (erl_create_native_record), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erl_create_native_record(
    header: *mut ProcessHeader,
    reg: *mut u64,
    definition_id: u64,
    live: u64,
    count: usize,
    elements: *const u64,
) -> u64 {
    x86_create_record(header, reg, definition_id, live, count, elements, true)
}

fn x86_create_record(
    header: *mut ProcessHeader,
    reg: *mut u64,
    definition: u64,
    live: u64,
    count: usize,
    elements: *const u64,
    external: bool,
) -> u64 {
    let Some((process, registers)) = native_hooks::enter_runtime_reg(header, reg) else {
        return native_hooks::raw(Term::NON_VALUE);
    };
    let Ok(live) = usize::try_from(live) else {
        return native_hooks::raw(Term::NON_VALUE);
    };
    if !count.is_multiple_of(2) {
        return native_hooks::raw(Term::NON_VALUE);
    }
    let Some(values) = x86_elements(elements, count, &registers.x_reg_array, &process.heap) else {
        return native_hooks::raw(Term::NON_VALUE);
    };
    let Some(end) = live.checked_add(count) else {
        return native_hooks::raw(Term::NON_VALUE);
    };
    let Some(staged) = registers.x_reg_array.get_mut(live..end) else {
        return native_hooks::raw(Term::NON_VALUE);
    };
    staged.copy_from_slice(&values);
    match create_record(
        process,
        &mut registers.x_reg_array,
        native_hooks::from_raw(definition),
        (live, count, live),
        external,
    ) {
        Ok(record) => native_hooks::raw(record),
        Err(failure) => {
            report(process, failure);
            native_hooks::raw(Term::NON_VALUE)
        }
    }
}

/// Port of erts/emulator/beam/erl_record.c:381-468 (erl_update_native_record), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erl_update_native_record(
    header: *mut ProcessHeader,
    reg: *mut u64,
    source: u64,
    live: u64,
    count: usize,
    elements: *const u64,
) -> u64 {
    let Some((process, registers)) = native_hooks::enter_runtime_reg(header, reg) else {
        return native_hooks::raw(Term::NON_VALUE);
    };
    let Ok(live) = usize::try_from(live) else {
        return native_hooks::raw(Term::NON_VALUE);
    };
    if count == 0 || !count.is_multiple_of(2) {
        return native_hooks::raw(Term::NON_VALUE);
    }
    let Some(values) = x86_elements(elements, count, &registers.x_reg_array, &process.heap) else {
        return native_hooks::raw(Term::NON_VALUE);
    };
    let Some(end) = live.checked_add(count) else {
        return native_hooks::raw(Term::NON_VALUE);
    };
    let Some(staged) = registers.x_reg_array.get_mut(live..end) else {
        return native_hooks::raw(Term::NON_VALUE);
    };
    staged.copy_from_slice(&values);
    match update_record(
        process,
        &mut registers.x_reg_array,
        native_hooks::from_raw(source),
        (live, count, live),
    ) {
        Ok(record) => native_hooks::raw(record),
        Err(failure) => {
            report(process, failure);
            native_hooks::raw(Term::NON_VALUE)
        }
    }
}

/// Port of erts/emulator/beam/erl_record.c:470-578 (erl_get_local_record_field), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erl_get_local_record_field(
    header: *mut ProcessHeader,
    source: u64,
    definition_id: u64,
    name: u64,
) -> u64 {
    get_field(header, source, definition_id, name, 1, true)
}

/// Port of erts/emulator/beam/erl_record.c:507-578 (erl_get_record_field), OTP-29.1.1.
#[unsafe(no_mangle)]
pub extern "C" fn erl_get_record_field(
    header: *mut ProcessHeader,
    source: u64,
    definition_id: u64,
    name: u64,
) -> u64 {
    get_field(header, source, definition_id, name, 1, false)
}

/// Port of erts/emulator/beam/erl_record.c:223-252 (erl_get_record_elements), OTP-29.1.1.
/// Reads the sorted keys staged at `base` and replaces each with its value; returns 1 when
/// every key was found.
pub extern "C" fn arinsal_beamasm_get_record_elements(
    header: *mut ProcessHeader,
    reg: *mut u64,
    source: u64,
    count: u64,
    base: u64,
) -> u64 {
    let Some((process, registers)) = native_hooks::enter_runtime_reg(header, reg) else {
        return 0;
    };
    let (Ok(count), Ok(base)) = (usize::try_from(count), usize::try_from(base)) else {
        return 0;
    };
    let _ = process;
    let Some(snapshot) = native_hooks::from_raw(source).record_snapshot() else {
        return 0;
    };
    let Some(definition) = Definition::parse(snapshot.definition) else {
        return 0;
    };
    u64::from(scan_record_elements(
        &definition,
        &snapshot.values,
        count,
        |index, key, value| {
            let slot = registers.x_reg_array.get_mut(base + index)?;
            if *slot != key {
                return Some(false);
            }
            *slot = value;
            Some(true)
        },
    ))
}

/// Port of erts/emulator/beam/erl_record.c:470-578 (erl_get_local_record_field,
/// erl_get_record_field), OTP-29.1.1.
fn get_field(
    header: *mut ProcessHeader,
    source: u64,
    id: u64,
    field: u64,
    raise: u64,
    local: bool,
) -> u64 {
    let Some(process) = enter_runtime(header) else {
        return 0;
    };
    let source = native_hooks::from_raw(source);
    let id = native_hooks::from_raw(id);
    let Some(field) = native_hooks::from_raw(field).as_atom() else {
        return 0;
    };
    let atoms = global_atoms();
    let underscore = atoms.intern("_").ok();
    let outcome = (|| {
        let snapshot = source.record_snapshot().ok_or(Failure::BadRecord(source))?;
        if local {
            if id.as_atom() != underscore && id.as_atom() != Some(snapshot.name) {
                return Err(Failure::BadRecord(source));
            }
        } else {
            if id.as_atom() != underscore {
                let parts = term_sequence(id).unwrap_or_default();
                let [module, name] = parts.as_slice() else {
                    return Err(Failure::BadRecord(source));
                };
                if module.as_atom() != Some(snapshot.module)
                    || name.as_atom() != Some(snapshot.name)
                {
                    return Err(Failure::BadRecord(source));
                }
            }
            if !snapshot.is_exported {
                return Err(Failure::BadRecord(source));
            }
        }
        if !snapshot.fields.contains(&field) {
            return Err(Failure::BadField(snapshot.module, snapshot.name, field));
        }
        let sorted_index = snapshot
            .fields
            .iter()
            .filter(|other| other.0 < field.0)
            .count();
        Ok(snapshot.values[sorted_index])
    })();
    match outcome {
        Ok(value) => native_hooks::raw(value),
        Err(_) if raise == 0 => 0,
        Err(failure) => {
            report(process, failure);
            0
        }
    }
}

/// Runtime helper of `get_record_field` with an atom record id.
pub extern "C" fn arinsal_beamasm_get_local_record_field(
    header: *mut ProcessHeader,
    source: u64,
    id: u64,
    field: u64,
    raise: u64,
) -> u64 {
    get_field(header, source, id, field, raise, true)
}

/// Runtime helper of `get_record_field` with a `{Module, Name}` or `_` record id.
pub extern "C" fn arinsal_beamasm_get_record_field(
    header: *mut ProcessHeader,
    source: u64,
    id: u64,
    field: u64,
    raise: u64,
) -> u64 {
    get_field(header, source, id, field, raise, false)
}
