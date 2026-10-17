//! Runtime helpers of the native record instructions in native code.
//!
//! Port of erts/emulator/beam/erl_record.c:223-578 (erl_get_record_elements,
//! erl_create_local_native_record, erl_create_native_record, erl_update_native_record,
//! erl_get_local_record_field, erl_get_record_field), OTP-29.1.1. The emitted code stages the
//! key/value operands in the scheduler X register array, sorted by field name like the loader's
//! `map_key_sort`, and these helpers merge them with the definition's keys in atom-index order.

use crate::{Process, native_hooks, native_hooks::enter_runtime};
use arinsal_beamasm::{ProcessHeader, SchedulerRegisters};
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

fn scope(process: &Process) -> u64 {
    process
        .runtime
        .as_ref()
        .map_or(0, |runtime| runtime.code_scope)
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
            process.sync_native_header();
            return;
        }
    };
    match value
        .and_then(|value| crate::exceptions::tuple(process, &[crate::signals::atom(tag), value]))
    {
        Ok(reason) => {
            process.header.freason = 1;
            process.header.fvalue = native_hooks::raw(reason);
        }
        Err(_) => native_hooks::set_error(process, "system_limit"),
    }
    process.sync_native_header();
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
/// the live prefix and the staged words are dead and must not be roots. `process.x` is the
/// scheduler's array, so the collector moves the roots in place.
fn stage_roots(process: &mut Process, live: usize, base: usize, top: usize) -> Option<()> {
    if top > process.x.len() {
        return None;
    }
    process.x[live..base].fill(Term::NIL);
    Some(())
}

/// Merge the sorted staged `(key, value)` words with a record's sorted keys.
fn staged_pairs(process: &Process, base: usize, count: usize) -> Vec<(Term, Term)> {
    (0..count / 2)
        .map(|pair| (process.x[base + 2 * pair], process.x[base + 2 * pair + 1]))
        .collect()
}

/// The registered definition literal of `Module:Name` when it is exported.
fn exported_definition(process: &Process, id: Term) -> Option<Term> {
    let parts = term_sequence(id)?;
    let [module, name] = parts.as_slice() else {
        return None;
    };
    let cons = arinsal_term::find_record_definition_in(
        scope(process),
        module.as_atom()?,
        name.as_atom()?,
    )?;
    let (definition, _) = crate::lists::split(cons)?;
    Definition::parse(definition)?.exported.then_some(cons)
}

/// Port of erts/emulator/beam/erl_record.c:254-379 (erl_create_local_native_record,
/// erl_create_native_record), OTP-29.1.1.
fn create(
    header: *mut ProcessHeader,
    id: u64,
    live: u64,
    count: u64,
    base: u64,
    external: bool,
) -> u64 {
    let Some((process, registers)) = enter_runtime(header) else {
        return 0;
    };
    process.reductions = process.header.fcalls;
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
    let (Ok(live), Ok(count), Ok(base)) = (
        usize::try_from(live),
        usize::try_from(count),
        usize::try_from(base),
    ) else {
        return 0;
    };
    let result = create_record(
        process,
        native_hooks::from_raw(id),
        (live, count, base),
        external,
    );
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
    match result {
        Ok(record) => {
            process.sync_native_header();
            native_hooks::raw(record)
        }
        Err(failure) => {
            report(process, failure);
            0
        }
    }
}

fn create_record(
    process: &mut Process,
    id: Term,
    (live, count, base): (usize, usize, usize),
    external: bool,
) -> Result<Term, Failure> {
    let cons = if external {
        exported_definition(process, id).ok_or(Failure::BadRecord(id))?
    } else {
        id
    };
    let (definition_term, defaults) = crate::lists::split(cons).ok_or(Failure::SystemLimit)?;
    let definition = Definition::parse(definition_term).ok_or(Failure::SystemLimit)?;
    let defaults = term_sequence(defaults).ok_or(Failure::SystemLimit)?;
    let top = base + count;
    stage_roots(process, live, base, top).ok_or(Failure::SystemLimit)?;
    process
        .ensure(2 + definition.keys.len(), top)
        .map_err(|_| Failure::SystemLimit)?;
    let pairs = staged_pairs(process, base, count);
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
    _registers: *mut SchedulerRegisters,
    definition: u64,
    live: u64,
    count: u64,
    base: u64,
) -> u64 {
    create(header, definition, live, count, base, false)
}

/// Runtime helper of `i_create_native_record`.
pub extern "C" fn arinsal_beamasm_create_record(
    header: *mut ProcessHeader,
    _registers: *mut SchedulerRegisters,
    id: u64,
    live: u64,
    count: u64,
    base: u64,
) -> u64 {
    create(header, id, live, count, base, true)
}

/// Port of erts/emulator/beam/erl_record.c:381-468 (erl_update_native_record), OTP-29.1.1.
pub extern "C" fn arinsal_beamasm_update_record(
    header: *mut ProcessHeader,
    _registers: *mut SchedulerRegisters,
    source: u64,
    live: u64,
    count: u64,
    base: u64,
) -> u64 {
    let Some((process, registers)) = enter_runtime(header) else {
        return 0;
    };
    process.reductions = process.header.fcalls;
    process
        .heap
        .set_frame_pointer(registers.tmp_mem[2] as usize);
    let (Ok(live), Ok(count), Ok(base)) = (
        usize::try_from(live),
        usize::try_from(count),
        usize::try_from(base),
    ) else {
        return 0;
    };
    let result = update_record(process, native_hooks::from_raw(source), (live, count, base));
    registers.tmp_mem[2] = process.heap.frame_pointer() as u64;
    match result {
        Ok(record) => {
            process.sync_native_header();
            native_hooks::raw(record)
        }
        Err(failure) => {
            report(process, failure);
            0
        }
    }
}

fn update_record(
    process: &mut Process,
    source: Term,
    (live, count, base): (usize, usize, usize),
) -> Result<Term, Failure> {
    let snapshot = source.record_snapshot().ok_or(Failure::BadRecord(source))?;
    // The source is the only operand the collector may not know about: it rides after the
    // staged words.
    let source_slot = base + count;
    let top = source_slot + 1;
    if top > process.x.len() {
        return Err(Failure::SystemLimit);
    }
    process.x[source_slot] = source;
    stage_roots(process, live, base, top).ok_or(Failure::SystemLimit)?;
    process
        .ensure(2 + snapshot.fields.len(), top)
        .map_err(|_| Failure::SystemLimit)?;
    let source = process.x[source_slot];
    let snapshot = source.record_snapshot().ok_or(Failure::BadRecord(source))?;
    let definition = Definition::parse(snapshot.definition).ok_or(Failure::SystemLimit)?;
    let pairs = staged_pairs(process, base, count);
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

/// Port of erts/emulator/beam/erl_record.c:223-252 (erl_get_record_elements), OTP-29.1.1.
/// Reads the sorted keys staged at `base` and replaces each with its value; returns 1 when
/// every key was found.
pub extern "C" fn arinsal_beamasm_get_record_elements(
    header: *mut ProcessHeader,
    _registers: *mut SchedulerRegisters,
    source: u64,
    count: u64,
    base: u64,
) -> u64 {
    let Some((process, registers)) = enter_runtime(header) else {
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
    let mut next = 0;
    for (key, value) in definition.keys.iter().zip(&snapshot.values) {
        if next < count && registers.x_reg_array[base + next] == Term::atom(*key) {
            registers.x_reg_array[base + next] = *value;
            next += 1;
            if next == count {
                return 1;
            }
        }
    }
    0
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
    let Some((process, _)) = enter_runtime(header) else {
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
            process.reductions = process.header.fcalls;
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
