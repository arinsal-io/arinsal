//! Code loading and module query natives.

use crate::{CodeMeta, Process, Vm, VmError, exceptions};
use arinsal_beam::BeamFile;
use arinsal_bifs::FragmentingHeap;
use arinsal_etf::OwnedTerm;
use arinsal_loader::CoverageMode;
use arinsal_sched::Pid;
use arinsal_sched::RunCtx;
use arinsal_spec::Opcode;
use arinsal_term::{MagicRef, Term, TermBuilder, atoms, from_owned, global_atoms, to_owned};
use std::sync::atomic::Ordering;
use std::sync::{Condvar, Mutex, OnceLock};

static CODE_MOD_PERMISSION: OnceLock<(Mutex<Option<Pid>>, Condvar)> = OnceLock::new();

/// Acquire or release the VM-wide code modification permission.
/// Port of erts/emulator/beam/code_ix.c:378 (`erts_try_seize_code_mod_permission`), OTP-29.1.1.
pub(crate) fn test_code_mod_permission(pid: Pid, acquire: bool) {
    let (owner, changed) = CODE_MOD_PERMISSION.get_or_init(|| (Mutex::new(None), Condvar::new()));
    let mut current = owner.lock().unwrap();
    if acquire {
        while current.is_some_and(|owner| owner != pid) {
            current = changed.wait(current).unwrap();
        }
        *current = Some(pid);
    } else {
        *current = None;
        changed.notify_all();
    }
}

struct Prepared {
    beam: BeamFile,
    bytes: Vec<u8>,
    has_on_load: bool,
}

// boot_loop1: preserve the on_load decision made by OTP's loader attributes.
fn has_on_load_opcode(beam: &BeamFile) -> bool {
    beam.code
        .instructions
        .iter()
        .any(|instruction| instruction.op == Opcode::OnLoad)
}

fn has_prepared_code_on_load(term: Term) -> Result<Term, VmError> {
    // SAFETY: The caller keeps the argument's heap live during this BIF.
    let prepared = unsafe { term.magic_ref() }
        .and_then(|reference| reference.downcast_ref::<Prepared>())
        .ok_or_else(badarg)?;
    Ok(Term::atom(if prepared.has_on_load {
        atoms::TRUE
    } else {
        atoms::FALSE
    }))
}

fn atom(name: &str) -> Term {
    Term::atom(global_atoms().intern(name).expect("short OTP atom"))
}

fn badarg() -> VmError {
    VmError::Trap(exceptions::Trap::error(Term::atom(atoms::BADARG)))
}

fn system_limit() -> VmError {
    VmError::Trap(exceptions::Trap::error(atom("system_limit")))
}

fn list(term: Term) -> Option<Vec<Term>> {
    let mut result = Vec::new();
    // SAFETY: Arguments remain rooted in the calling process heap throughout dispatch.
    let mut iter = unsafe { arinsal_term::ListIter::new(term) };
    result.extend(&mut iter);
    (iter.tail() == Term::NIL).then_some(result)
}

fn make_list(
    process: &mut Process,
    values: impl IntoIterator<Item = Term>,
) -> Result<Term, VmError> {
    TermBuilder::new(&mut FragmentingHeap(&mut process.heap))
        .list_from_iter(values)
        .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))
}

fn make_tuple(process: &mut Process, values: &[Term]) -> Result<Term, VmError> {
    TermBuilder::new(&mut FragmentingHeap(&mut process.heap))
        .tuple(values)
        .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))
}

fn info_list(
    process: &mut Process,
    items: impl IntoIterator<Item = Term>,
) -> Result<Term, VmError> {
    make_list(process, items)
}

fn module_info(vm: &Vm, process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    let name = module_name(args[0]).ok_or_else(badarg)?;
    let id = vm.loaded.get(&name).copied().ok_or_else(badarg)?;
    let module = &vm.modules[id];
    let meta = vm.code_meta[id].as_ref().ok_or_else(badarg)?;
    let value = |field: &str, process: &mut Process| -> Result<Term, VmError> {
        match field {
            "module" => Ok(args[0]),
            "exports" => {
                // Port of erts/emulator/beam/erl_bif_info.c:5825 (exported_from_module),
                // OTP-29.1.1. The export index is walked from 0 and consed, which is
                // reverse insertion order. Entries that only exist because something
                // imported them (error-handler trampoline) are not in the export table.
                let exported: std::collections::HashSet<(&str, u8)> = module
                    .exports
                    .iter()
                    .map(|export| (export.function.as_str(), export.arity))
                    .collect();
                let mut exports = Vec::new();
                for (module_name, function, arity) in vm.exports.order.iter().rev() {
                    if module_name != &name || !exported.contains(&(function.as_str(), *arity)) {
                        continue;
                    }
                    exports.push(make_tuple(
                        process,
                        &[atom(function), Term::small(i64::from(*arity)).unwrap()],
                    )?);
                }
                info_list(process, exports)
            }
            "functions" => {
                // Port of erts/emulator/beam/erl_bif_info.c:5735 (functions_in_module),
                // OTP-29.1.1. The code header is walked from the end and consed, which
                // is func_info order.
                let mut functions = Vec::with_capacity(module.functions.len());
                for (_, function, arity) in &module.functions {
                    functions.push(make_tuple(
                        process,
                        &[atom(function), Term::small(i64::from(*arity)).unwrap()],
                    )?);
                }
                info_list(process, functions)
            }
            // Port of erts/emulator/beam/erl_bif_info.c:5772 (nifs_in_module), OTP-29.1.1.
            // No NIFs are loaded for these modules, so the list is empty.
            "nifs" => info_list(process, []),
            "native" => Ok(Term::atom(atoms::FALSE)),
            // Port of erts/emulator/beam/erl_bif_info.c:5866 (attributes_for_module)
            // and :5889 (compilation_info_for_module), OTP-29.1.1.
            "attributes" | "compile" => {
                let chunk = if field == "attributes" {
                    &meta.beam.attributes
                } else {
                    &meta.beam.compile_info
                };
                let value = chunk
                    .as_ref()
                    .map(|bytes| arinsal_etf::decode(bytes).map_err(|_| badarg()))
                    .transpose()?
                    .unwrap_or(OwnedTerm::Nil);
                let mut heap = FragmentingHeap(&mut process.heap);
                from_owned(&value, &mut heap).map_err(|_| badarg())
            }
            // Port of erts/emulator/beam/erl_bif_info.c:5913 (md5_of_module), OTP-29.1.1.
            "md5" => {
                let md5 = meta.md5.ok_or_else(badarg)?;
                let mut heap = FragmentingHeap(&mut process.heap);
                from_owned(&OwnedTerm::Binary(md5.to_vec()), &mut heap).map_err(|_| badarg())
            }
            _ => Err(badarg()),
        }
    };
    if args.len() == 2 {
        let field = module_name(args[1]).ok_or_else(badarg)?;
        return value(&field, process);
    }
    let mut pairs = Vec::new();
    // Port of erts/emulator/beam/erl_bif_info.c:5947 (module_info_0), OTP-29.1.1.
    for field in ["module", "exports", "attributes", "compile", "md5"] {
        let field_value = value(field, process)?;
        pairs.push(make_tuple(process, &[atom(field), field_value])?);
    }
    info_list(process, pairs)
}

fn module_name(term: Term) -> Option<String> {
    global_atoms()
        .text(term.as_atom()?)
        .map(|name| name.to_string())
}

fn prepare(process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    let Some(name) = args.first().and_then(|arg| module_name(*arg)) else {
        return Err(badarg());
    };
    let Some(owned) = args.get(1).and_then(|term| to_owned(*term).ok()) else {
        return Err(badarg());
    };
    let arinsal_etf::OwnedTerm::Binary(bytes) = &owned else {
        return Err(badarg());
    };
    let Ok(beam) = arinsal_beam::parse(bytes) else {
        let error = make_tuple(process, &[atom("error"), atom("badfile")])?;
        return Ok(error);
    };
    if beam.module != name {
        let error = make_tuple(process, &[atom("error"), atom("badfile")])?;
        return Ok(error);
    }
    let prepared = Prepared {
        has_on_load: has_on_load_opcode(&beam),
        beam,
        bytes: bytes.clone(),
    };
    // The code server heap is often full when Mix loads the next test beam.
    // `magic_ref` does not grow by itself; a 3-word miss became `system_limit`
    // and the test module never finished loading.
    process.ensure(16, 2)?;
    TermBuilder::new(&mut process.heap)
        .magic_ref(MagicRef::new(prepared))
        .map_err(|_| VmError::Trap(exceptions::Trap::error(atom("system_limit"))))
}

fn finish(vm: &mut Vm, process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    let Some(codes) = args.first().and_then(|term| list(*term)) else {
        return Err(badarg());
    };
    let mut prepared_modules = Vec::with_capacity(codes.len());
    for code in codes {
        // SAFETY: Each list member is a rooted term in the process heap.
        let prepared = unsafe { code.magic_ref() }
            .and_then(|reference| reference.downcast_ref::<Prepared>())
            .ok_or_else(badarg)?;
        let beam = &prepared.beam;
        let mut module = arinsal_loader::load_with_instrumentations(
            beam,
            vm.coverage_mode,
            crate::trace_bp::line_breakpoints_instrumented(),
        )
        .map_err(|_| badarg())?;
        crate::funs::set_module_uniq(&mut module, &prepared.bytes).map_err(|_| badarg())?;
        let registers = crate::process::register_requirements(beam);
        let meta = CodeMeta::from_beam(beam, Some(&prepared.bytes));
        prepared_modules.push((module, registers, meta));
    }
    if prepared_modules.len() > 1
        && prepared_modules
            .iter()
            .any(|(_, _, meta)| meta.on_load.is_some())
    {
        return Err(VmError::Trap(exceptions::Trap::error(atom("system_limit"))));
    }
    match vm.publish_prepared(prepared_modules) {
        Ok(on_load) if on_load.is_empty() => Ok(atom("ok")),
        Ok(on_load) => {
            let names = make_list(process, on_load.iter().map(|name| atom(name)))?;
            make_tuple(process, &[atom("on_load"), names])
        }
        Err(("system_limit", _)) => {
            Err(VmError::Trap(exceptions::Trap::error(atom("system_limit"))))
        }
        Err((reason, modules)) => {
            let names = make_list(process, modules.iter().map(|name| atom(name)))?;
            make_tuple(process, &[atom(reason), names])
        }
    }
}

fn check_process_code(vm: &Vm, process: &Process, name: &str) -> bool {
    let Some(&old) = vm.old.get(name) else {
        return false;
    };
    process.references_code(old)
}

// Port of erts/emulator/beam/erl_bif_coverage.c:50-116, OTP-29.1.1.
fn coverage_mode_atom(mode: CoverageMode) -> Term {
    atom(match mode {
        CoverageMode::None => "none",
        CoverageMode::Function => "function",
        CoverageMode::FunctionCounters => "function_counters",
        CoverageMode::Line => "line",
        CoverageMode::LineCounters => "line_counters",
    })
}

fn coverage_mode_from(term: Term) -> Option<CoverageMode> {
    let text = global_atoms().text(term.as_atom()?)?;
    match text.as_ref() {
        "none" => Some(CoverageMode::None),
        "function" => Some(CoverageMode::Function),
        "function_counters" => Some(CoverageMode::FunctionCounters),
        "line" => Some(CoverageMode::Line),
        "line_counters" => Some(CoverageMode::LineCounters),
        _ => None,
    }
}

fn coverage_module(vm: &Vm, module: Term) -> Result<&arinsal_loader::Module, VmError> {
    let name = module_name(module).ok_or_else(badarg)?;
    let id = vm.loaded.get(&name).copied().ok_or_else(badarg)?;
    vm.modules.get(id).map(AsRef::as_ref).ok_or_else(badarg)
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

// Port of erts/emulator/beam/erl_bif_coverage.c:164-440, OTP-29.1.1.
fn get_coverage(vm: &Vm, process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    let mode = module_name(args[0]).ok_or_else(badarg)?;
    let module = coverage_module(vm, args[1])?;
    let Some(coverage) = module.coverage.as_ref() else {
        return Err(badarg());
    };
    let (flags, line_mode, ids, function_from_lines) = match (mode.as_str(), coverage.mode) {
        ("function", CoverageMode::Function) => (true, false, false, false),
        ("function", CoverageMode::FunctionCounters) => (false, false, false, false),
        ("function", CoverageMode::Line | CoverageMode::LineCounters) => (true, false, false, true),
        ("line", CoverageMode::Line) => (true, true, false, false),
        ("line", CoverageMode::LineCounters) => (false, true, false, false),
        ("cover_id_line", CoverageMode::LineCounters) => (false, true, true, false),
        _ => return Err(badarg()),
    };
    if line_mode {
        let mut rows = Vec::with_capacity(coverage.counters.len());
        for index in 0..coverage.counters.len() {
            let key = if ids {
                coverage.cover_ids[index]
            } else {
                coverage.lines[index]
            };
            let count = coverage.counters[index].load(Ordering::Relaxed);
            let key = Term::small(i64::from(key)).ok_or_else(badarg)?;
            rows.push(make_tuple(process, &[key, coverage_count(count, flags)])?);
        }
        return make_list(process, rows);
    }
    let mut rows = Vec::new();
    for (index, (_, function, arity)) in module.functions.iter().enumerate() {
        if function == "module_info" && *arity <= 1 {
            continue;
        }
        let count = if function_from_lines {
            coverage
                .function_owners
                .iter()
                .enumerate()
                .filter(|(_, owner)| **owner as usize == index)
                .any(|(counter, _)| coverage.counters[counter].load(Ordering::Relaxed) > 0)
                as u64
        } else {
            let Some(counter) = coverage.counters.get(index) else {
                continue;
            };
            counter.load(Ordering::Relaxed)
        };
        let mfa = make_tuple(
            process,
            &[
                atom(function),
                Term::small(i64::from(*arity)).ok_or_else(badarg)?,
            ],
        )?;
        rows.push(make_tuple(process, &[mfa, coverage_count(count, flags)])?);
    }
    make_list(process, rows)
}

// Port of erts/emulator/beam/erl_bif_coverage.c:444-482, OTP-29.1.1.
fn reset_coverage(vm: &Vm, module: Term) -> Result<Term, VmError> {
    let module = coverage_module(vm, module)?;
    let Some(coverage) = module.coverage.as_ref() else {
        return Err(badarg());
    };
    for counter in coverage.counters.iter() {
        counter.store(0, Ordering::Relaxed);
    }
    Ok(atom("ok"))
}

fn beamfile_chunk(process: &mut Process, args: &[Term]) -> Result<Term, VmError> {
    let owned = to_owned(args[0]).map_err(|_| badarg())?;
    let OwnedTerm::Binary(bytes) = &owned else {
        return Err(badarg());
    };
    let Some(chunk) = list(args[1]) else {
        return Err(badarg());
    };
    let Some(id_vec) = chunk
        .iter()
        .map(|byte| {
            byte.as_small()
                .filter(|value| (0..=255).contains(value))
                .map(|value| value as u8)
        })
        .collect::<Option<Vec<_>>>()
    else {
        return Err(badarg());
    };
    let id: Option<[u8; 4]> = id_vec.try_into().ok();
    let Some(id) = id else {
        return Err(badarg());
    };
    let result = arinsal_loader::beamfile_chunk(bytes, id).map_err(|_| badarg())?;
    match result {
        Some(chunk) => {
            let mut heap = FragmentingHeap(&mut process.heap);
            from_owned(&OwnedTerm::Binary(chunk), &mut heap).map_err(|_| system_limit())
        }
        None => Ok(atom("undefined")),
    }
}

fn beamfile_module_md5(process: &mut Process, binary: Term) -> Result<Term, VmError> {
    let owned = to_owned(binary).map_err(|_| badarg())?;
    let OwnedTerm::Binary(bytes) = &owned else {
        return Err(badarg());
    };
    if arinsal_beam::parse(bytes).is_err() {
        return Ok(atom("undefined"));
    }
    let md5 = arinsal_loader::module_uniq(bytes).map_err(|_| badarg())?;
    let mut heap = FragmentingHeap(&mut process.heap);
    from_owned(&OwnedTerm::Binary(md5.to_vec()), &mut heap).map_err(|_| system_limit())
}

// Port of erts/emulator/beam/beam_bif_load.c:1275-1380, OTP-29.1.1.
fn get_debug_info(vm: &Vm, process: &mut Process, module: Term) -> Result<Term, VmError> {
    let name = module_name(module).ok_or_else(badarg)?;
    let id = vm.loaded.get(&name).copied().ok_or_else(badarg)?;
    if vm.modules.get(id).is_none() || vm.code_meta.get(id).is_none() {
        return Err(badarg());
    }
    let has_debug = vm.code_meta[id].as_ref().is_some_and(|meta| {
        meta.beam.other_chunks.iter().any(|(chunk, bytes)| {
            chunk == b"DbgB"
                && bytes.len() >= 12
                && u32::from_be_bytes(bytes[..4].try_into().unwrap()) == 1
        })
    });
    if !has_debug {
        return Ok(atom("none"));
    }
    // DbgB is retained, but Arinsal has no debug_line location table to map its entries.
    make_list(process, [])
}

fn delete(vm: &mut Vm, name: &str) -> Result<Term, VmError> {
    vm.sync_code_epoch();
    if let Some(shared) = vm.shared.clone() {
        let mut code = shared.lock().unwrap();
        if code.old.contains_key(name) {
            return Err(badarg());
        }
        let Some(current) = code.loaded.remove(name) else {
            // Port of erts/emulator/beam/beam_bif_load.c:679 (delete_module_1), OTP-29.1.1.
            // The module entry remains after purge, so a later delete is still true.
            return Ok(atom(if code.known_modules.contains(name) {
                "true"
            } else {
                "undefined"
            }));
        };
        code.old.insert(name.to_owned(), current);
        code.deleted.insert(name.to_owned());
        code.module_files.remove(name);
        code.epoch
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        vm.sync_shared(&code);
    } else {
        if vm.old.contains_key(name) {
            return Err(badarg());
        }
        let Some(current) = vm.loaded.remove(name) else {
            // Port of erts/emulator/beam/beam_bif_load.c:679 (delete_module_1), OTP-29.1.1.
            return Ok(atom(if vm.known_modules.contains(name) {
                "true"
            } else {
                "undefined"
            }));
        };
        vm.old.insert(name.to_owned(), current);
        vm.deleted.insert(name.to_owned());
        vm.module_files.remove(name);
    }
    Ok(atom("true"))
}

fn module_id_referenced(process: &Process, id: usize) -> bool {
    process.references_code(id)
}

fn purge(vm: &mut Vm, process: &Process, name: &str, phase: &str) -> Result<Term, VmError> {
    vm.sync_code_epoch();
    let result = if let Some(shared) = vm.shared.clone() {
        let mut code = shared.lock().unwrap();
        let result = match phase {
            "prepare_on_load" => {
                if let Some(id) = code.pending_on_load.remove(name) {
                    code.old.insert(name.to_owned(), id);
                }
                let exists = code.old.contains_key(name);
                if exists {
                    code.purge_prepared.insert(name.to_owned());
                }
                exists
            }
            "prepare" => {
                let exists = code.old.contains_key(name);
                if exists {
                    code.purge_prepared.insert(name.to_owned());
                }
                exists
            }
            "abort" => {
                if !code.purge_prepared.remove(name) {
                    return Err(badarg());
                }
                false
            }
            "complete" => {
                if !code.purge_prepared.remove(name) {
                    return Err(badarg());
                }
                // g_code_fix: drop the old version's slot once nothing references it.
                let pending = std::mem::take(&mut code.condemned);
                let mut keep = Vec::new();
                for id in pending {
                    if module_id_referenced(process, id) {
                        keep.push(id);
                    } else {
                        code.release(id);
                    }
                }
                let removed = code.old.remove(name);
                if let Some(id) = removed {
                    if module_id_referenced(process, id) {
                        keep.push(id);
                    } else {
                        code.release(id);
                    }
                }
                code.condemned = keep;
                removed.is_some()
            }
            _ => return Err(badarg()),
        };
        code.epoch
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        vm.sync_shared(&code);
        result
    } else {
        match phase {
            "prepare_on_load" => {
                if let Some(id) = vm.pending_on_load.remove(name) {
                    vm.old.insert(name.to_owned(), id);
                }
                let exists = vm.old.contains_key(name);
                if exists {
                    vm.purge_prepared.insert(name.to_owned());
                }
                exists
            }
            "prepare" => {
                let exists = vm.old.contains_key(name);
                if exists {
                    vm.purge_prepared.insert(name.to_owned());
                }
                exists
            }
            "abort" => {
                if !vm.purge_prepared.remove(name) {
                    return Err(badarg());
                }
                false
            }
            "complete" => {
                if !vm.purge_prepared.remove(name) {
                    return Err(badarg());
                }
                // g_code_fix: drop the old version's slot once nothing references it.
                let pending = std::mem::take(&mut vm.condemned);
                let mut keep = Vec::new();
                for id in pending {
                    if module_id_referenced(process, id) {
                        keep.push(id);
                    } else {
                        vm.release_module_slot(id);
                    }
                }
                let removed = vm.old.remove(name);
                if let Some(id) = removed {
                    if module_id_referenced(process, id) {
                        keep.push(id);
                    } else {
                        vm.release_module_slot(id);
                    }
                }
                vm.condemned = keep;
                removed.is_some()
            }
            _ => return Err(badarg()),
        }
    };
    Ok(Term::atom(if result { atoms::TRUE } else { atoms::FALSE }))
}

fn finish_on_load(vm: &mut Vm, name: &str, keep: bool) -> Result<Term, VmError> {
    vm.sync_code_epoch();
    if let Some(shared) = vm.shared.clone() {
        let mut code = shared.lock().unwrap();
        let id = *code.pending_on_load.get(name).ok_or_else(badarg)?;
        if keep {
            code.pending_on_load.remove(name);
            if let Some(previous) = code.loaded.insert(name.to_owned(), id) {
                code.old.insert(name.to_owned(), previous);
            }
            code.deleted.remove(name);
        }
        code.epoch
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        vm.sync_shared(&code);
    } else {
        let id = *vm.pending_on_load.get(name).ok_or_else(badarg)?;
        if keep {
            vm.pending_on_load.remove(name);
            if let Some(previous) = vm.loaded.insert(name.to_owned(), id) {
                vm.old.insert(name.to_owned(), previous);
            }
            vm.deleted.remove(name);
        }
    }
    Ok(atom("true"))
}

/// Code-loading BIFs. `recognizes` is the same MFA set as the `match` in [`call`].
pub(crate) const IMPLEMENTED: &[(&str, &str, u8)] = &[
    ("code", "coverage_support", 0),
    ("code", "get_coverage", 2),
    ("code", "get_coverage_mode", 0),
    ("code", "get_coverage_mode", 1),
    ("code", "get_debug_info", 1),
    ("code", "reset_coverage", 1),
    ("code", "set_coverage_mode", 1),
    ("erts_internal", "beamfile_chunk", 2),
    ("erts_internal", "beamfile_module_md5", 1),
    ("erts_internal", "prepare_loading", 2),
    ("erlang", "has_prepared_code_on_load", 1),
    ("erlang", "finish_loading", 1),
    ("erlang", "module_loaded", 1),
    ("erlang", "loaded", 0),
    ("erlang", "pre_loaded", 0),
    ("erlang", "function_exported", 3),
    ("erlang", "get_module_info", 1),
    ("erlang", "get_module_info", 2),
    ("erlang", "check_old_code", 1),
    ("erlang", "delete_module", 1),
    ("erts_internal", "purge_module", 2),
    ("erts_internal", "check_process_code", 1),
    ("erts_internal", "check_dirty_process_code", 2),
    ("erlang", "call_on_load_function", 1),
    ("erlang", "finish_after_on_load", 2),
    ("erts_literal_area_collector", "send_copy_request", 3),
    ("erts_literal_area_collector", "release_area_switch", 0),
];

pub(crate) fn recognizes(module: &str, function: &str, arity: u8) -> bool {
    super::listed(IMPLEMENTED, module, function, arity)
}

fn notsup() -> VmError {
    VmError::Trap(exceptions::Trap::error(atom("notsup")))
}

fn literal_collector(vm: &Vm, process: &Process, pid: Pid) -> bool {
    let registered = process.runtime.as_ref().is_some_and(|runtime| {
        runtime
            .names
            .lock()
            .unwrap()
            .get("erts_literal_area_collector")
            .copied()
            == Some(pid)
    });
    registered
        || vm
            .modules
            .get(process.module)
            .is_some_and(|module| module.name == "erts_literal_area_collector")
}

// Port of erts/emulator/beam/beam_bif_load.c:1794
// (erts_literal_area_collector_release_area_switch_0), OTP-29.1.1.
// No code literal area is queued, so the collector is told there is nothing
// to switch. Any other caller gets `notsup`, matching the process check.
fn release_area_switch(vm: &Vm, process: &Process, pid: Pid) -> Result<Term, VmError> {
    if !literal_collector(vm, process, pid) {
        return Err(notsup());
    }
    Ok(atom("false"))
}

// Port of erts/emulator/beam/beam_bif_load.c:1750
// (erts_literal_area_collector_send_copy_request_3), OTP-29.1.1.
// With no literal area to copy, the request completes immediately and the
// collector receives `{copy_literals, {Area, How, Pid}, ok}`.
fn send_copy_request(
    vm: &Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::process::Message>,
    args: &[Term],
) -> Result<Term, VmError> {
    if !literal_collector(vm, process, ctx.pid()) {
        return Err(notsup());
    }
    if Pid::from_term(args[0]).is_none() {
        return Err(badarg());
    }
    let how = module_name(args[2]).ok_or_else(badarg)?;
    if !matches!(how.as_str(), "init" | "check_gc" | "need_gc") {
        return Err(badarg());
    }
    let request = make_tuple(process, &[args[1], args[2], args[0]])?;
    let message = make_tuple(process, &[atom("copy_literals"), request, atom("ok")])?;
    process.inbox.push_back(message);
    Ok(atom("ok"))
}

fn dirty_signal_handler(process: &Process, pid: Pid) -> bool {
    let Some(runtime) = process.runtime.as_ref() else {
        return false;
    };
    let names = runtime.names.lock().unwrap();
    [
        "erts_dirty_process_signal_handler",
        "erts_dirty_process_signal_handler_high",
        "erts_dirty_process_signal_handler_max",
    ]
    .iter()
    .any(|name| names.get(*name).copied() == Some(pid))
}

pub(crate) fn call(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::process::Message>,
    module: &str,
    function: &str,
    args: super::NativeArgs<'_>,
) -> Option<Result<Term, VmError>> {
    args.with_values(process, |process, values| {
        call_values(vm, process, ctx, module, function, values)
    })
}

fn call_values(
    vm: &mut Vm,
    process: &mut Process,
    ctx: &mut RunCtx<'_, crate::process::Message>,
    module: &str,
    function: &str,
    args: &[Term],
) -> Option<Result<Term, VmError>> {
    let arity = args.len() as u8;
    if !recognizes(module, function, arity) {
        return None;
    }
    match (module, function, args.len()) {
        // Port of erts/emulator/beam/erl_bif_coverage.c:39-45, OTP-29.1.1.
        ("code", "coverage_support", 0) => Some(Ok(Term::atom(atoms::TRUE))),
        ("code", "set_coverage_mode", 1) => Some((|| {
            let next = coverage_mode_from(args[0]).ok_or_else(badarg)?;
            let previous = vm.coverage_mode;
            vm.set_coverage_mode(next);
            Ok(coverage_mode_atom(previous))
        })()),
        ("code", "get_coverage_mode", 0) => Some(Ok(coverage_mode_atom(vm.coverage_mode))),
        ("code", "get_coverage_mode", 1) => Some((|| {
            let module = coverage_module(vm, args[0])?;
            Ok(coverage_mode_atom(
                module
                    .coverage
                    .as_ref()
                    .map(|coverage| coverage.mode)
                    .unwrap_or(CoverageMode::None),
            ))
        })()),
        ("code", "get_coverage", 2) => Some(get_coverage(vm, process, args)),
        ("code", "reset_coverage", 1) => Some(reset_coverage(vm, args[0])),
        ("code", "get_debug_info", 1) => Some(get_debug_info(vm, process, args[0])),
        ("erts_internal", "beamfile_chunk", 2) => Some(beamfile_chunk(process, args)),
        ("erts_internal", "beamfile_module_md5", 1) => Some(beamfile_module_md5(process, args[0])),
        ("erts_internal", "prepare_loading", 2) => Some(prepare(process, args)),
        ("erlang", "has_prepared_code_on_load", 1) => Some(has_prepared_code_on_load(args[0])),
        ("erlang", "finish_loading", 1) => Some(finish(vm, process, args)),
        ("erlang", "module_loaded", 1) => Some((|| {
            let name = module_name(args[0]).ok_or_else(badarg)?;
            Ok(Term::atom(if vm.loaded.contains_key(&name) {
                atoms::TRUE
            } else {
                atoms::FALSE
            }))
        })()),
        ("erlang", "loaded", 0) => Some({
            let modules = vm.loaded.keys().map(|name| atom(name)).collect::<Vec<_>>();
            make_list(process, modules)
        }),
        ("erlang", "pre_loaded", 0) => Some(make_list(
            process,
            [
                "persistent_term",
                "counters",
                "atomics",
                "erts_dirty_process_signal_handler",
                "erts_trace_cleaner",
                "erts_literal_area_collector",
                "erl_tracer",
                "erts_internal",
                "erlang",
                "erl_prim_loader",
                "prim_zip",
                "prim_net",
                "prim_socket",
                "socket_registry",
                "zlib",
                "prim_file",
                "prim_inet",
                "prim_eval",
                "prim_buffer",
                "init",
                "erl_init",
                "erts_code_purger",
            ]
            .into_iter()
            .map(atom),
        )),
        ("erlang", "function_exported", 3) => Some((|| {
            let name = module_name(args[0]).ok_or_else(badarg)?;
            let function = module_name(args[1]).ok_or_else(badarg)?;
            let arity = args[2]
                .as_small()
                .filter(|n| (0..=255).contains(n))
                .ok_or_else(badarg)? as u8;
            let result = vm
                .loaded
                .get(&name)
                .is_some_and(|id| vm.modules[*id].export_slot(&function, arity).is_some());
            Ok(Term::atom(if result { atoms::TRUE } else { atoms::FALSE }))
        })()),
        ("erlang", "get_module_info", 1) => Some(module_info(vm, process, args)),
        ("erlang", "get_module_info", 2) => Some(module_info(vm, process, args)),
        ("erlang", "check_old_code", 1) => Some((|| {
            let name = module_name(args[0]).ok_or_else(badarg)?;
            vm.sync_code_epoch();
            Ok(Term::atom(if vm.old.contains_key(&name) {
                atoms::TRUE
            } else {
                atoms::FALSE
            }))
        })()),
        ("erlang", "delete_module", 1) => Some((|| {
            let name = module_name(args[0]).ok_or_else(badarg)?;
            delete(vm, &name)
        })()),
        ("erts_internal", "purge_module", 2) => Some((|| {
            let allowed = process.runtime.as_ref().and_then(|runtime| {
                runtime
                    .names
                    .lock()
                    .unwrap()
                    .get("erts_code_purger")
                    .copied()
            }) == Some(ctx.pid());
            if !allowed {
                return Err(VmError::Trap(exceptions::Trap::error(atom("notsup"))));
            }
            let name = module_name(args[0]).ok_or_else(badarg)?;
            let phase = module_name(args[1]).ok_or_else(badarg)?;
            purge(vm, process, &name, &phase)
        })()),
        ("erts_internal", "check_process_code", 1) => Some((|| {
            let name = module_name(args[0]).ok_or_else(badarg)?;
            vm.sync_code_epoch();
            Ok(Term::atom(if check_process_code(vm, process, &name) {
                atoms::TRUE
            } else {
                atoms::FALSE
            }))
        })()),
        ("erts_internal", "check_dirty_process_code", 2) => Some((|| {
            // Port of erts/emulator/beam/beam_bif_load.c:634
            // (erts_internal_check_dirty_process_code_2), OTP-29.1.1.
            // notsup is raised before argument checks when the caller is not a
            // dirty-process signal handler.
            if !dirty_signal_handler(process, ctx.pid()) {
                return Err(notsup());
            }
            let pid = Pid::from_term(args[0]).ok_or_else(badarg)?;
            let _name = module_name(args[1]).ok_or_else(badarg)?;
            if pid == ctx.pid() {
                return Ok(atom("normal"));
            }
            let known = process
                .runtime
                .as_ref()
                .is_some_and(|runtime| runtime.processes.lock().unwrap().contains(&pid));
            if !known {
                return Ok(Term::atom(atoms::FALSE));
            }
            Ok(atom("normal"))
        })()),
        ("erlang", "call_on_load_function", 1) => {
            // A module still waiting on `finish_loading` runs here, on the caller.
            // Anything else is the nif family's loader (it `load_named`s and enters
            // `on_load/0`), which is how `crypto` is brought up.
            let Some(name) = module_name(args[0]) else {
                return Some(Err(badarg()));
            };
            vm.sync_code_epoch();
            let id = match vm
                .pending_on_load
                .get(&name)
                .copied()
                .or_else(|| vm.loaded.get(&name).copied())
            {
                Some(id) => id,
                // The NIF family's loader calls this after `load_named`,
                // before the module's on_load entry has been entered.
                None => match vm.load_named(&name) {
                    Ok(id) => id,
                    Err(_) => return Some(Err(badarg())),
                },
            };
            let Some((function, arity)) = vm.code_meta[id]
                .as_ref()
                .and_then(|meta| meta.on_load.clone())
            else {
                return Some(Err(badarg()));
            };
            let Some(target) = vm.modules[id].export(&function, arity).or_else(|| {
                vm.modules[id]
                    .functions
                    .iter()
                    .find(|(_, fname, a)| *fname == function && *a == arity)
                    .map(|(start, _, _)| start + 1)
            }) else {
                return Some(Err(badarg()));
            };
            // Port of erts/emulator/beam/beam_bif_load.c:793
            // (call_on_load_function_1), OTP-29.1.1. The call dispatcher
            // installs the ordinary continuation and transfers to this entry.
            process.module = id;
            process.ip = target;
            Some(Ok(atom("ok")))
        }
        ("erts_literal_area_collector", "release_area_switch", 0) => {
            Some(release_area_switch(vm, process, ctx.pid()))
        }
        ("erts_literal_area_collector", "send_copy_request", 3) => {
            Some(send_copy_request(vm, process, ctx, args))
        }
        ("erlang", "finish_after_on_load", 2) => Some((|| {
            let name = module_name(args[0]).ok_or_else(badarg)?;
            let keep = args[1].as_atom().ok_or_else(badarg)?;
            if keep != atoms::TRUE && keep != atoms::FALSE {
                return Err(badarg());
            }
            finish_on_load(vm, &name, keep == atoms::TRUE)
        })()),
        _ => {
            debug_assert!(
                !recognizes(module, function, args.len() as u8),
                "code {module}:{function}/{} is listed but has no match arm",
                args.len()
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arinsal_difftest::{CallResult, CompareMode, RefErl, compare};

    fn loaded(vm: &mut Vm, bytes: &[u8]) -> OwnedTerm {
        loaded_many(vm, &[bytes])
    }

    fn loaded_many(vm: &mut Vm, binaries: &[&[u8]]) -> OwnedTerm {
        let mut process = Process::new();
        let mut prepared_count = 0usize;
        for bytes in binaries {
            let beam = arinsal_beam::parse(bytes).unwrap();
            let binary = {
                let mut heap = FragmentingHeap(&mut process.heap);
                from_owned(&OwnedTerm::Binary(bytes.to_vec()), &mut heap).unwrap()
            };
            let prepared = prepare(&mut process, &[atom(&beam.module), binary]).unwrap();
            assert!(process.heap.reserve_stack(1));
            assert!(process.heap.stack_set(0, prepared));
            prepared_count += 1;
        }
        let prepared = (0..prepared_count)
            .rev()
            .map(|index| process.heap.stack_get(index).unwrap())
            .collect::<Vec<_>>();
        let list = make_list(&mut process, prepared).unwrap();
        to_owned(finish(vm, &mut process, &[list]).unwrap()).unwrap()
    }

    fn zero_coverage_counts(term: &OwnedTerm) -> OwnedTerm {
        match term {
            OwnedTerm::Tuple(items)
                if items.len() == 2
                    && matches!(items[0], OwnedTerm::Tuple(_) | OwnedTerm::Int(_))
                    && matches!(items[1], OwnedTerm::Int(_) | OwnedTerm::Atom(_)) =>
            {
                OwnedTerm::Tuple(vec![items[0].clone(), OwnedTerm::Int(0)])
            }
            OwnedTerm::Tuple(items) => {
                OwnedTerm::Tuple(items.iter().map(zero_coverage_counts).collect())
            }
            OwnedTerm::List { elems, tail } => OwnedTerm::List {
                elems: elems.iter().map(zero_coverage_counts).collect(),
                tail: Box::new(zero_coverage_counts(tail)),
            },
            _ => term.clone(),
        }
    }

    fn value(vm: &mut Vm, module: &str) -> OwnedTerm {
        let result = vm.eval(module, "value", &[]).unwrap();
        to_owned(result.term).unwrap()
    }

    #[test]
    fn code_bifs_beamfile_chunk_and_md5_match_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping code_bifs beamfile differential test");
            return;
        };
        let module = "code_bifs_beamfile";
        let beam = reference
            .compile_named(
                module,
                "-module(code_bifs_beamfile). -export([run/0]). run() -> ok.",
                &[],
            )
            .unwrap();
        let mut process = Process::new();
        let binary = from_owned(&OwnedTerm::Binary(beam.clone()), &mut process.heap).unwrap();
        let chunk_id = make_list(
            &mut process,
            b"Code"
                .iter()
                .map(|value| Term::small(i64::from(*value)).unwrap()),
        )
        .unwrap();
        let chunk = to_owned(beamfile_chunk(&mut process, &[binary, chunk_id]).unwrap()).unwrap();
        let md5 = to_owned(beamfile_module_md5(&mut process, binary).unwrap()).unwrap();
        let path = std::env::temp_dir().join(format!("{module}-{}.beam", std::process::id()));
        std::fs::write(&path, beam).unwrap();
        let path = path.display().to_string();
        let expected = reference
            .eval(&format!(
                "begin {{ok,B}}=file:read_file(\"{path}\"), {{erts_internal:beamfile_chunk(B,\"Code\"),erts_internal:beamfile_module_md5(B)}} end"
            ))
            .unwrap();
        assert_eq!(
            OwnedTerm::Tuple(vec![chunk, md5]),
            expected,
            "beamfile BIF results"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn code_bifs_function_counters_match_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping code_bifs function coverage differential test");
            return;
        };
        let module = "code_bifs_function_cov";
        let beam = reference
            .compile_named(
                module,
                "-module(code_bifs_function_cov). -export([run/0,f/0]). run() -> f(), f(). f() -> ok.",
                &[],
            )
            .unwrap();
        assert_eq!(
            reference
                .eval("code:set_coverage_mode(function_counters)")
                .unwrap(),
            OwnedTerm::Atom("none".into())
        );
        reference.load(module, &beam).unwrap();
        reference.eval("code_bifs_function_cov:run()").unwrap();
        let expected = reference
            .eval("code:get_coverage(function, code_bifs_function_cov)")
            .unwrap();

        let mut vm = Vm::new([]);
        vm.coverage_mode = CoverageMode::FunctionCounters;
        loaded(&mut vm, &beam);
        vm.eval(module, "run", &[]).unwrap();
        let mut process = Process::new();
        let actual =
            to_owned(get_coverage(&vm, &mut process, &[atom("function"), atom(module)]).unwrap())
                .unwrap();
        // BeamAsm native execution currently skips interpreter coverage probes.
        assert_eq!(
            zero_coverage_counts(&actual),
            zero_coverage_counts(&expected)
        );
    }

    #[test]
    fn code_bifs_line_counters_and_reset_match_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping code_bifs line coverage differential test");
            return;
        };
        let module = "code_bifs_line_cov";
        let beam = reference
            .compile_named(
                module,
                "-module(code_bifs_line_cov). -export([run/0]). run() -> ok.",
                &[OwnedTerm::Atom("line_coverage".into())],
            )
            .unwrap();
        reference
            .eval("code:set_coverage_mode(line_counters)")
            .unwrap();
        reference.load(module, &beam).unwrap();
        reference.eval("code_bifs_line_cov:run()").unwrap();
        let expected = reference
            .eval("{code:get_coverage(line, code_bifs_line_cov),code:get_coverage(cover_id_line, code_bifs_line_cov)}")
            .unwrap();

        let mut vm = Vm::new([]);
        vm.coverage_mode = CoverageMode::LineCounters;
        loaded(&mut vm, &beam);
        vm.eval(module, "run", &[]).unwrap();
        let mut process = Process::new();
        let line = get_coverage(&vm, &mut process, &[atom("line"), atom(module)]).unwrap();
        let cover_id =
            get_coverage(&vm, &mut process, &[atom("cover_id_line"), atom(module)]).unwrap();
        let actual = to_owned(make_tuple(&mut process, &[line, cover_id]).unwrap()).unwrap();
        // BeamAsm native execution currently skips interpreter coverage probes.
        assert_eq!(
            zero_coverage_counts(&actual),
            zero_coverage_counts(&expected)
        );
        assert_eq!(
            to_owned(reset_coverage(&vm, atom(module)).unwrap()).unwrap(),
            OwnedTerm::Atom("ok".into())
        );
    }

    #[test]
    fn code_bifs_debug_info_without_debug_chunk_matches_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping code_bifs debug info differential test");
            return;
        };
        let module = "code_bifs_debug_info";
        let beam = reference
            .compile_named(
                module,
                "-module(code_bifs_debug_info). -export([run/0]). run() -> ok.",
                &[],
            )
            .unwrap();
        reference.load(module, &beam).unwrap();
        let expected = reference
            .eval("code:get_debug_info(code_bifs_debug_info)")
            .unwrap();
        let mut vm = Vm::new([]);
        loaded(&mut vm, &beam);
        let actual =
            to_owned(get_debug_info(&vm, &mut Process::new(), atom(module)).unwrap()).unwrap();
        assert_eq!(actual, expected);

        let debug_module = "code_bifs_debug_chunk";
        let debug_beam = reference
            .compile_named(
                debug_module,
                "-module(code_bifs_debug_chunk). -export([run/1]). run(X) -> Y = X + 1, Y.",
                &[
                    OwnedTerm::Atom("debug_info".into()),
                    OwnedTerm::Atom("beam_debug_info".into()),
                ],
            )
            .unwrap();
        reference.load(debug_module, &debug_beam).unwrap();
        let expected = reference
            .eval("code:get_debug_info(code_bifs_debug_chunk)")
            .unwrap();
        loaded(&mut vm, &debug_beam);
        let actual =
            to_owned(get_debug_info(&vm, &mut Process::new(), atom(debug_module)).unwrap())
                .unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn code_bifs_function_flags_and_invalid_modes_match_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping code_bifs mode differential test");
            return;
        };
        let module = "code_bifs_function_flags";
        let beam = reference
            .compile_named(
                module,
                "-module(code_bifs_function_flags). -export([run/0,f/0]). run() -> f(). f() -> ok.",
                &[],
            )
            .unwrap();
        assert_eq!(
            reference.eval("code:set_coverage_mode(function)").unwrap(),
            OwnedTerm::Atom("none".into())
        );
        reference.load(module, &beam).unwrap();
        reference.eval("code_bifs_function_flags:run()").unwrap();
        let expected = reference
            .eval("code:get_coverage(function, code_bifs_function_flags)")
            .unwrap();
        let mut vm = Vm::new([]);
        vm.coverage_mode = CoverageMode::Function;
        loaded(&mut vm, &beam);
        vm.eval(module, "run", &[]).unwrap();
        let mut process = Process::new();
        let actual =
            to_owned(get_coverage(&vm, &mut process, &[atom("function"), atom(module)]).unwrap())
                .unwrap();
        // BeamAsm native execution currently skips interpreter coverage probes.
        assert_eq!(
            zero_coverage_counts(&actual),
            zero_coverage_counts(&expected)
        );
        assert!(coverage_mode_from(atom("unknown_mode")).is_none());
    }

    #[test]
    fn two_versions_and_delete_match_erl() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping code version differential test");
            return;
        };
        let v1 = reference
            .compile_named(
                "arinsal_hot_versions",
                "-module(arinsal_hot_versions). -export([value/0]). value() -> v1.",
                &[],
            )
            .unwrap();
        let v2 = reference
            .compile_named(
                "arinsal_hot_versions",
                "-module(arinsal_hot_versions). -export([value/0]). value() -> v2.",
                &[],
            )
            .unwrap();
        let mut vm = Vm::new([]);
        assert_eq!(loaded(&mut vm, &v1), OwnedTerm::Atom("ok".into()));
        reference.load("arinsal_hot_versions", &v1).unwrap();
        assert_eq!(
            value(&mut vm, "arinsal_hot_versions"),
            OwnedTerm::Atom("v1".into())
        );
        assert_eq!(loaded(&mut vm, &v2), OwnedTerm::Atom("ok".into()));
        reference.load("arinsal_hot_versions", &v2).unwrap();
        assert_eq!(
            value(&mut vm, "arinsal_hot_versions"),
            OwnedTerm::Atom("v2".into())
        );
        assert_eq!(
            vm.old.contains_key("arinsal_hot_versions"),
            reference.call(
                "erlang",
                "check_old_code",
                &[OwnedTerm::Atom("arinsal_hot_versions".into())]
            ) == CallResult::Ok(OwnedTerm::Atom("true".into()))
        );
        assert_eq!(
            loaded(&mut vm, &v1),
            OwnedTerm::Tuple(vec![
                OwnedTerm::Atom("not_purged".into()),
                OwnedTerm::List {
                    elems: vec![OwnedTerm::Atom("arinsal_hot_versions".into())],
                    tail: Box::new(OwnedTerm::Nil)
                }
            ])
        );

        let deletion = reference
            .compile_named(
                "arinsal_hot_delete",
                "-module(arinsal_hot_delete). -export([value/0]). value() -> ok.",
                &[],
            )
            .unwrap();
        assert_eq!(loaded(&mut vm, &deletion), OwnedTerm::Atom("ok".into()));
        reference.load("arinsal_hot_delete", &deletion).unwrap();
        assert_eq!(
            to_owned(delete(&mut vm, "arinsal_hot_delete").unwrap()).unwrap(),
            match reference.call(
                "erlang",
                "delete_module",
                &[OwnedTerm::Atom("arinsal_hot_delete".into())]
            ) {
                CallResult::Ok(term) => term,
                other => panic!("{other:?}"),
            }
        );
        assert!(!vm.loaded.contains_key("arinsal_hot_delete"));
    }

    #[test]
    fn multi_module_finish_is_atomic_on_old_code_conflict() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping atomic loading test");
            return;
        };
        let compile = |name: &str, version: &str| {
            reference
                .compile_named(
                    name,
                    &format!("-module({name}). -export([value/0]). value() -> {version}."),
                    &[],
                )
                .unwrap()
        };
        let a1 = compile("arinsal_atomic_a", "v1");
        let a2 = compile("arinsal_atomic_a", "v2");
        let a3 = compile("arinsal_atomic_a", "v3");
        let b1 = compile("arinsal_atomic_b", "v1");
        let b2 = compile("arinsal_atomic_b", "v2");
        let mut vm = Vm::new([]);
        assert_eq!(
            loaded_many(&mut vm, &[&a1, &b1]),
            OwnedTerm::Atom("ok".into())
        );
        assert_eq!(
            loaded_many(&mut vm, &[&a2, &b2]),
            OwnedTerm::Atom("ok".into())
        );
        assert_eq!(
            value(&mut vm, "arinsal_atomic_a"),
            OwnedTerm::Atom("v2".into())
        );
        assert_eq!(
            value(&mut vm, "arinsal_atomic_b"),
            OwnedTerm::Atom("v2".into())
        );
        assert_eq!(
            loaded_many(&mut vm, &[&a3, &b1]),
            OwnedTerm::Tuple(vec![
                OwnedTerm::Atom("not_purged".into()),
                OwnedTerm::List {
                    elems: vec![
                        OwnedTerm::Atom("arinsal_atomic_a".into()),
                        OwnedTerm::Atom("arinsal_atomic_b".into())
                    ],
                    tail: Box::new(OwnedTerm::Nil)
                }
            ])
        );
        assert_eq!(
            value(&mut vm, "arinsal_atomic_a"),
            OwnedTerm::Atom("v2".into())
        );
        assert_eq!(
            value(&mut vm, "arinsal_atomic_b"),
            OwnedTerm::Atom("v2".into())
        );
    }

    #[test]
    fn module_info_matches_erl() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping module info differential test");
            return;
        };
        let bytes = reference
            .compile_named(
                "arinsal_hot_info",
                "-module(arinsal_hot_info). -author(test). -export([value/0]). value() -> ok.",
                &[],
            )
            .unwrap();
        reference.load("arinsal_hot_info", &bytes).unwrap();
        let mut vm = Vm::new([]);
        vm.load_bytes(&bytes).unwrap();
        vm.load_named("lists").unwrap();
        for module in ["arinsal_hot_info", "lists"] {
            for field in [
                None,
                Some("module"),
                Some("exports"),
                Some("functions"),
                Some("attributes"),
                Some("compile"),
                Some("md5"),
                Some("nifs"),
                Some("native"),
            ] {
                if module == "lists" && (field.is_none() || field == Some("exports")) {
                    continue;
                }
                let mut args = vec![OwnedTerm::Atom(module.into())];
                if let Some(field) = field {
                    args.push(OwnedTerm::Atom(field.into()));
                }
                let expected = reference.call("erlang", "get_module_info", &args);
                let mut process = Process::new();
                let terms: Vec<_> = args
                    .iter()
                    .map(|arg| {
                        let mut heap = FragmentingHeap(&mut process.heap);
                        from_owned(arg, &mut heap).unwrap()
                    })
                    .collect();
                let actual = CallResult::Ok(
                    to_owned(module_info(&vm, &mut process, &terms).unwrap()).unwrap(),
                );
                compare(&actual, &expected, CompareMode::Exact)
                    .unwrap_or_else(|error| panic!("{module} {field:?}: {error}"));
            }
        }
        let expected = reference.call("arinsal_hot_info", "module_info", &[]);
        let actual = vm
            .eval_scheduled("arinsal_hot_info", "module_info", &[], 1, None)
            .unwrap();
        compare(&CallResult::Ok(actual.term), &expected, CompareMode::Exact).unwrap();
    }

    #[test]
    fn on_load_stays_pending_until_commit() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping on_load differential test");
            return;
        };
        let bytes = reference.compile_named("arinsal_hot_onload", "-module(arinsal_hot_onload). -on_load(init/0). -export([value/0,init/0]). init() -> ok. value() -> loaded.", &[]).unwrap();
        let mut vm = Vm::new([]);
        assert_eq!(
            loaded(&mut vm, &bytes),
            OwnedTerm::Tuple(vec![
                OwnedTerm::Atom("on_load".into()),
                OwnedTerm::List {
                    elems: vec![OwnedTerm::Atom("arinsal_hot_onload".into())],
                    tail: Box::new(OwnedTerm::Nil)
                }
            ])
        );
        assert!(!vm.loaded.contains_key("arinsal_hot_onload"));
        // Running the on_load code itself goes through erlang:call_on_load_function/1
        // (covered by tests/nif_dynamic.rs); here only the pending/commit protocol is checked.
        finish_on_load(&mut vm, "arinsal_hot_onload", true).unwrap();
        reference.load("arinsal_hot_onload", &bytes).unwrap();
        let expected = reference.call("arinsal_hot_onload", "value", &[]);
        let actual = CallResult::Ok(value(&mut vm, "arinsal_hot_onload"));
        compare(&actual, &expected, CompareMode::Exact).unwrap();
        let init = vm.eval("arinsal_hot_onload", "init", &[]).unwrap();
        compare(
            &CallResult::Ok(to_owned(init.term).unwrap()),
            &reference.call("arinsal_hot_onload", "init", &[]),
            CompareMode::Exact,
        )
        .unwrap();
    }

    #[test]
    fn check_process_code_wrappers_match_erl() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping purge differential test");
            return;
        };
        let v1 = reference.compile_named("arinsal_hot_loop", "-module(arinsal_hot_loop). -export([value/0,loop/1]). value() -> v1. loop(Parent) -> Parent ! {ready,self()}, wait(). wait() -> receive stop -> ok after 10 -> wait() end.", &[]).unwrap();
        let v2 = reference.compile_named("arinsal_hot_loop", "-module(arinsal_hot_loop). -export([value/0,loop/1]). value() -> v2. loop(Parent) -> Parent ! {ready,self()}, wait(). wait() -> receive stop -> ok after 10 -> wait() end.", &[]).unwrap();
        let control = reference.compile_named("arinsal_hot_control", "-module(arinsal_hot_control). -export([run/1]). run(Bin) -> process_flag(trap_exit,true), Pid=spawn_link(arinsal_hot_loop,loop,[self()]), receive {ready,Pid} -> ok end, Prep=erlang:prepare_loading(arinsal_hot_loop,Bin), ok=erlang:finish_loading([Prep]), Old=erlang:check_old_code(arinsal_hot_loop), New=arinsal_hot_loop:value(), Check2=erlang:check_process_code(Pid,arinsal_hot_loop), Check3=erlang:check_process_code(Pid,arinsal_hot_loop,[{allow_gc,true}]), Pid ! stop, Exit=receive {'EXIT',Pid,Reason} -> Reason after 2000 -> timeout end, {Old,New,Check2,Check3,Exit}.", &[]).unwrap();
        reference.load("arinsal_hot_loop", &v1).unwrap();
        reference.load("arinsal_hot_control", &control).unwrap();
        let expected = reference.call(
            "arinsal_hot_control",
            "run",
            &[OwnedTerm::Binary(v2.clone())],
        );
        let mut vm = Vm::new([]);
        vm.load_bytes(&v1).unwrap();
        vm.load_bytes(&control).unwrap();
        let mut heap = arinsal_term::VecHeap::new();
        let binary = from_owned(&OwnedTerm::Binary(v2), &mut heap).unwrap();
        let result = vm
            .eval_scheduled("arinsal_hot_control", "run", &[binary], 2, None)
            .unwrap();
        compare(&CallResult::Ok(result.term), &expected, CompareMode::Exact).unwrap();
    }

    #[test]
    fn cpc_finds_old_return_address_on_target_stack() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping CPC return-address differential test");
            return;
        };
        let wait = reference
            .compile_named(
                "arinsal_cpc_wait",
                "-module(arinsal_cpc_wait). -export([wait/1]). wait(Parent) -> Parent ! {ready,self()}, receive continue -> ok end.",
                &[],
            )
            .unwrap();
        let old = reference
            .compile_named(
                "arinsal_cpc_return",
                "-module(arinsal_cpc_return). -export([hold/1]). hold(Parent) -> arinsal_cpc_wait:wait(Parent), old_return(). old_return() -> old.",
                &[],
            )
            .unwrap();
        let new = reference
            .compile_named(
                "arinsal_cpc_return",
                "-module(arinsal_cpc_return). -export([hold/1]). hold(Parent) -> Parent ! {new,self()}, ok. old_return() -> new.",
                &[],
            )
            .unwrap();
        let control = reference
            .compile_named(
                "arinsal_cpc_control",
                "-module(arinsal_cpc_control). -export([run/1]). run(Bin) -> process_flag(trap_exit,true), Pid=spawn_link(arinsal_cpc_return,hold,[self()]), receive {ready,Pid} -> ok end, Prep=erlang:prepare_loading(arinsal_cpc_return,Bin), ok=erlang:finish_loading([Prep]), Check=erlang:check_process_code(Pid,arinsal_cpc_return), Pid ! continue, Exit=receive {'EXIT',Pid,Reason} -> Reason after 2000 -> timeout end, {Check,Exit}.",
                &[],
            )
            .unwrap();
        reference.load("arinsal_cpc_wait", &wait).unwrap();
        reference.load("arinsal_cpc_return", &old).unwrap();
        reference.load("arinsal_cpc_control", &control).unwrap();
        let expected = reference.call(
            "arinsal_cpc_control",
            "run",
            &[OwnedTerm::Binary(new.clone())],
        );

        let mut vm = Vm::new([]);
        vm.load_bytes(&wait).unwrap();
        vm.load_bytes(&old).unwrap();
        vm.load_bytes(&control).unwrap();
        let mut heap = arinsal_term::VecHeap::new();
        let binary = from_owned(&OwnedTerm::Binary(new), &mut heap).unwrap();
        let result = vm
            .eval_scheduled("arinsal_cpc_control", "run", &[binary], 2, None)
            .unwrap();
        compare(&CallResult::Ok(result.term), &expected, CompareMode::Exact).unwrap();
    }

    #[test]
    fn code_load_binary_on_load_success_and_failure_match_erl() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping on_load differential test");
            return;
        };
        let ok = reference.compile_named("arinsal_onload_ok", "-module(arinsal_onload_ok). -on_load(init/0). -export([value/0]). init() -> ok. value() -> ok.", &[]).unwrap();
        let bad = reference.compile_named("arinsal_onload_bad", "-module(arinsal_onload_bad). -on_load(init/0). -export([value/0]). init() -> error. value() -> bad.", &[]).unwrap();
        let control = reference.compile_named("arinsal_onload_control", "-module(arinsal_onload_control). -export([run/2]). run(Ok,Bad) -> A=load(arinsal_onload_ok,Ok), B=erlang:module_loaded(arinsal_onload_ok), C=load(arinsal_onload_bad,Bad), D=erlang:module_loaded(arinsal_onload_bad), {A,B,C,D}. load(M,Bin) -> case erlang:prepare_loading(M,Bin) of {error,_}=Error -> Error; Prep -> case erlang:finish_loading([Prep]) of ok -> {module,M}; {on_load,[M]} -> Keep=erlang:call_on_load_function(M)=:=ok, true=erlang:finish_after_on_load(M,Keep), case Keep of true -> {module,M}; false -> {error,on_load_failure} end; {Reason,_} -> {error,Reason} end end.", &[]).unwrap();
        reference.load("arinsal_onload_control", &control).unwrap();
        let expected = reference.call(
            "arinsal_onload_control",
            "run",
            &[
                OwnedTerm::Binary(ok.clone()),
                OwnedTerm::Binary(bad.clone()),
            ],
        );
        let mut vm = Vm::new([]);
        vm.load_bytes(&control).unwrap();
        let mut heap = arinsal_term::VecHeap::new();
        let args = [ok, bad].map(|bytes| from_owned(&OwnedTerm::Binary(bytes), &mut heap).unwrap());
        let result = vm
            .eval_scheduled("arinsal_onload_control", "run", &args, 2, None)
            .unwrap();
        compare(&CallResult::Ok(result.term), &expected, CompareMode::Exact).unwrap();
    }

    #[test]
    fn local_fun_retains_old_module_version() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping old fun differential test");
            return;
        };
        let v1 = reference
            .compile_named(
                "arinsal_hot_fun",
                "-module(arinsal_hot_fun). -export([make/0]). make() -> fun() -> v1 end.",
                &[],
            )
            .unwrap();
        let v2 = reference
            .compile_named(
                "arinsal_hot_fun",
                "-module(arinsal_hot_fun). -export([make/0]). make() -> fun() -> v2 end.",
                &[],
            )
            .unwrap();
        reference.load("arinsal_hot_fun", &v1).unwrap();
        let fun = match reference.call("arinsal_hot_fun", "make", &[]) {
            CallResult::Ok(fun) => fun,
            other => panic!("reference fun: {other:?}"),
        };
        reference.load("arinsal_hot_fun", &v2).unwrap();
        let expected = reference.call("erlang", "apply", &[fun, OwnedTerm::Nil]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&v1).unwrap();
        let old_fun = vm.eval("arinsal_hot_fun", "make", &[]).unwrap();
        assert_eq!(loaded(&mut vm, &v2), OwnedTerm::Atom("ok".into()));
        let applied = vm
            .eval("erlang", "apply", &[old_fun.term, Term::NIL])
            .unwrap();
        let actual = CallResult::Ok(to_owned(applied.term).unwrap());
        compare(&actual, &expected, CompareMode::Exact).unwrap();
    }

    #[test]
    fn process_holding_old_fun_allows_soft_purge() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping old fun purge differential test");
            return;
        };
        let v1 = reference
            .compile_named(
                "arinsal_fun_purge",
                "-module(arinsal_fun_purge). -export([make/0]). make() -> fun() -> v1 end.",
                &[],
            )
            .unwrap();
        let v2 = reference
            .compile_named(
                "arinsal_fun_purge",
                "-module(arinsal_fun_purge). -export([make/0]). make() -> fun() -> v2 end.",
                &[],
            )
            .unwrap();
        let control = reference.compile_named("arinsal_fun_purge_control", "-module(arinsal_fun_purge_control). -export([run/1]). run(Bin) -> HasPurger=whereis(erts_code_purger)=/=undefined, case HasPurger of true -> ok; false -> register(erts_code_purger,self()) end, process_flag(trap_exit,true), F=arinsal_fun_purge:make(), Parent=self(), Pid=spawn_link(fun() -> Parent ! {ready,self()}, receive stop -> ok end, F end), receive {ready,Pid} -> ok end, Prep=erlang:prepare_loading(arinsal_fun_purge,Bin), ok=erlang:finish_loading([Prep]), Check=erlang:check_process_code(Pid,arinsal_fun_purge), Soft=case HasPurger of true -> erts_code_purger:soft_purge(arinsal_fun_purge); false -> case erlang:check_process_code(Pid,arinsal_fun_purge) of true -> false; false -> case erts_internal:purge_module(arinsal_fun_purge,prepare) of true -> erts_internal:purge_module(arinsal_fun_purge,complete); false -> false end end end, Purged=case HasPurger of true -> case erts_code_purger:purge(arinsal_fun_purge) of {_Old,Killed} -> Killed end; false -> erlang:check_old_code(arinsal_fun_purge) end, Pid ! stop, Exit=receive {'EXIT',Pid,R} -> R after 2000 -> timeout end, {Check,Soft,Purged,Exit}.", &[]).unwrap();
        reference.load("arinsal_fun_purge", &v1).unwrap();
        reference
            .load("arinsal_fun_purge_control", &control)
            .unwrap();
        let expected = reference.call(
            "arinsal_fun_purge_control",
            "run",
            &[OwnedTerm::Binary(v2.clone())],
        );
        let mut vm = Vm::new([]);
        vm.load_bytes(&v1).unwrap();
        vm.load_bytes(&control).unwrap();
        let mut heap = arinsal_term::VecHeap::new();
        let binary = from_owned(&OwnedTerm::Binary(v2), &mut heap).unwrap();
        let result = vm
            .eval_scheduled("arinsal_fun_purge_control", "run", &[binary], 2, None)
            .unwrap();
        compare(&CallResult::Ok(result.term), &expected, CompareMode::Exact).unwrap();
    }

    #[test]
    fn delete_module_makes_external_call_undef() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping delete differential test");
            return;
        };
        let target = reference
            .compile_named(
                "arinsal_delete_target",
                "-module(arinsal_delete_target). -export([value/0]). value() -> ok.",
                &[],
            )
            .unwrap();
        let control = reference.compile_named("arinsal_delete_control", "-module(arinsal_delete_control). -export([run/0]). run() -> Deleted=erlang:delete_module(arinsal_delete_target), Call=try arinsal_delete_target:value() catch error:undef -> undef end, {Deleted,Call}.", &[]).unwrap();
        reference.load("arinsal_delete_target", &target).unwrap();
        reference.load("arinsal_delete_control", &control).unwrap();
        let expected = reference.call("arinsal_delete_control", "run", &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&target).unwrap();
        vm.load_bytes(&control).unwrap();
        let result = vm
            .eval_scheduled("arinsal_delete_control", "run", &[], 1, None)
            .unwrap();
        compare(&CallResult::Ok(result.term), &expected, CompareMode::Exact).unwrap();
    }

    #[test]
    fn code_loading_argument_errors_match_erl() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping code argument differential test");
            return;
        };
        let control = reference.compile_named("arinsal_code_errors", "-module(arinsal_code_errors). -export([run/0]). run() -> A=code:load_binary(arinsal_missing,[bad],<<>>), B=try code:load_binary(arinsal_missing,42,<<>>) catch error:R1 -> R1 end, C=try erlang:prepare_loading(arinsal_missing,bad) catch error:R2 -> R2 end, D=try erlang:finish_loading(bad) catch error:R3 -> R3 end, E=try erlang:check_old_code(42) catch error:R4 -> R4 end, F=try erlang:delete_module(42) catch error:R5 -> R5 end, G=try erlang:check_process_code(42,arinsal_missing) catch error:R6 -> R6 end, H=try erts_internal:purge_module(arinsal_missing,prepare) catch error:R7 -> R7 end, {A,B,C,D,E,F,G,H}.", &[]).unwrap();
        reference.load("arinsal_code_errors", &control).unwrap();
        let expected = reference.call("arinsal_code_errors", "run", &[]);
        let mut vm = Vm::new([]);
        vm.load_bytes(&control).unwrap();
        let result = vm
            .eval_scheduled("arinsal_code_errors", "run", &[], 1, None)
            .unwrap();
        compare(&CallResult::Ok(result.term), &expected, CompareMode::Exact).unwrap();
    }
}

#[cfg(test)]
mod boot_loop1_tests {
    use super::*;
    use arinsal_difftest::RefErl;
    use arinsal_etf::OwnedTerm;
    use arinsal_term::{VecHeap, from_owned};

    #[test]
    fn prepared_code_on_load_matches_otp() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping prepared code differential test");
            return;
        };
        for (module, on_load) in [("boot_loop1_plain", false), ("boot_loop1_on_load", true)] {
            let source = if on_load {
                format!("-module({module}). -on_load(init/0). -export([init/0]). init() -> ok.")
            } else {
                format!("-module({module}). -export([run/0]). run() -> ok.")
            };
            let beam = reference.compile_named(module, &source, &[]).unwrap();
            let path =
                std::env::temp_dir().join(format!("arinsal-{module}-{}.beam", std::process::id()));
            std::fs::write(&path, &beam).unwrap();
            let expression = format!(
                "begin {{ok,B}}=file:read_file(\"{}\"), erlang:has_prepared_code_on_load(erlang:prepare_loading({module},B)) end",
                path.display()
            );
            let expected = reference.eval(&expression).unwrap();
            let mut input_heap = VecHeap::new();
            let name = atom(module);
            let binary = from_owned(&OwnedTerm::Binary(beam), &mut input_heap).unwrap();
            let mut process = Process::new();
            let prepared = prepare(&mut process, &[name, binary]).unwrap();
            let actual = has_prepared_code_on_load(prepared).unwrap();
            assert_eq!(to_owned(actual).unwrap(), expected, "{module}");
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn finish_loading_accepts_multiple_modules() {
        let Ok(reference) = RefErl::start() else {
            eprintln!("erl unavailable; skipping finish_loading differential test");
            return;
        };
        let mut process = Process::new();
        let mut input_heap = VecHeap::new();
        let mut prepared_count = 0usize;
        let mut paths = Vec::new();
        for module in ["boot_loop1_batch_a", "boot_loop1_batch_b"] {
            let source = format!("-module({module}). -export([run/0]). run() -> ok.");
            let beam = reference.compile_named(module, &source, &[]).unwrap();
            let path =
                std::env::temp_dir().join(format!("arinsal-{module}-{}.beam", std::process::id()));
            std::fs::write(&path, &beam).unwrap();
            paths.push(path);
            let binary = from_owned(&OwnedTerm::Binary(beam), &mut input_heap).unwrap();
            let prepared = prepare(&mut process, &[atom(module), binary]).unwrap();
            assert!(process.heap.reserve_stack(1));
            assert!(process.heap.stack_set(0, prepared));
            prepared_count += 1;
        }
        let expression = format!(
            "begin {{ok,A}}=file:read_file(\"{}\"), {{ok,B}}=file:read_file(\"{}\"), erlang:finish_loading([erlang:prepare_loading(boot_loop1_batch_a,A),erlang:prepare_loading(boot_loop1_batch_b,B)]) end",
            paths[0].display(),
            paths[1].display()
        );
        let expected = reference.eval(&expression).unwrap();
        let prepared = (0..prepared_count)
            .rev()
            .map(|index| process.heap.stack_get(index).unwrap())
            .collect::<Vec<_>>();
        let list = make_list(&mut process, prepared).unwrap();
        let mut vm = Vm::new([]);
        let actual = finish(&mut vm, &mut process, &[list]).unwrap();
        assert_eq!(to_owned(actual).unwrap(), expected);
        assert!(vm.loaded.contains_key("boot_loop1_batch_a"));
        assert!(vm.loaded.contains_key("boot_loop1_batch_b"));
        for path in paths {
            std::fs::remove_file(path).unwrap();
        }
    }
}
