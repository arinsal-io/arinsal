//! Resumable BIF calls and their private continuation exports.

use super::*;
use arinsal_bifs::BifError;
use arinsal_term::{MagicRef, global_atoms};
use std::sync::{Arc, Mutex};

pub(crate) enum TrapResult {
    Done {
        value: Term,
        reductions: u32,
    },
    Failed {
        error: BifError,
        reductions: u32,
    },
    Yield {
        continuation: &'static str,
        state: Arc<MagicRef>,
        reductions: u32,
    },
}

type Handler = fn(
    &mut Process,
    &[Term],
    Option<&Arc<MagicRef>>,
    Option<arinsal_sched::Pid>,
    bool,
) -> Result<TrapResult, BifError>;

struct Entry {
    module: &'static str,
    function: &'static str,
    arity: u8,
    continuation: &'static str,
    handler: Handler,
}

const CODE_PERMISSION_CONTINUATION: &str = "erts_debug:set_internal_state/2";
const IOLIST_CONTINUATION: &str = "erts_internal:list_to_bitstring_continue/1";
const IOLIST_SIZE_CONTINUATION: &str = "erts_internal:iolist_size_continue/1";
const BINARY_TO_TERM_CONTINUATION: &str = "erts_internal:binary_to_term_trap/1";
const BINARY_COPY_CONTINUATION: &str = "erlang:binary_copy_trap/3";
const TERM_TO_BINARY_CONTINUATION: &str = "erts_internal:term_to_binary_trap/1";
const BINARY_SEARCH_CONTINUATION: &str = "erlang:binary_find_trap/3";
const PTAB_LIST_CONTINUATION: &str = "erlang:ptab_list_continue/2";

const ENTRIES: &[Entry] = &[
    Entry {
        module: "erlang",
        function: "processes",
        arity: 0,
        continuation: PTAB_LIST_CONTINUATION,
        handler: processes,
    },
    Entry {
        module: "erts_debug",
        function: "set_internal_state",
        arity: 2,
        continuation: CODE_PERMISSION_CONTINUATION,
        handler: code_permission,
    },
    Entry {
        module: "erlang",
        function: "list_to_binary",
        arity: 1,
        continuation: IOLIST_CONTINUATION,
        handler: list_to_binary,
    },
    Entry {
        module: "erlang",
        function: "iolist_to_binary",
        arity: 1,
        continuation: IOLIST_CONTINUATION,
        handler: iolist_to_binary,
    },
    Entry {
        module: "binary",
        function: "list_to_bin",
        arity: 1,
        continuation: IOLIST_CONTINUATION,
        handler: list_to_binary,
    },
    Entry {
        module: "erlang",
        function: "list_to_bitstring",
        arity: 1,
        continuation: IOLIST_CONTINUATION,
        handler: list_to_bitstring,
    },
    Entry {
        module: "erlang",
        function: "iolist_size",
        arity: 1,
        continuation: IOLIST_SIZE_CONTINUATION,
        handler: iolist_size,
    },
    Entry {
        module: "erlang",
        function: "binary_to_term",
        arity: 1,
        continuation: BINARY_TO_TERM_CONTINUATION,
        handler: binary_to_term,
    },
    Entry {
        module: "erlang",
        function: "term_to_binary",
        arity: 1,
        continuation: TERM_TO_BINARY_CONTINUATION,
        handler: term_to_binary,
    },
    Entry {
        module: "erlang",
        function: "term_to_iovec",
        arity: 1,
        continuation: TERM_TO_BINARY_CONTINUATION,
        handler: term_to_iovec,
    },
    Entry {
        module: "erlang",
        function: "term_to_iovec",
        arity: 2,
        continuation: TERM_TO_BINARY_CONTINUATION,
        handler: term_to_iovec,
    },
    Entry {
        module: "erlang",
        function: "term_to_binary",
        arity: 2,
        continuation: TERM_TO_BINARY_CONTINUATION,
        handler: term_to_binary,
    },
    Entry {
        module: "erlang",
        function: "binary_to_term",
        arity: 2,
        continuation: BINARY_TO_TERM_CONTINUATION,
        handler: binary_to_term,
    },
    Entry {
        module: "binary",
        function: "copy",
        arity: 1,
        continuation: BINARY_COPY_CONTINUATION,
        handler: binary_copy,
    },
    Entry {
        module: "binary",
        function: "copy",
        arity: 2,
        continuation: BINARY_COPY_CONTINUATION,
        handler: binary_copy,
    },
    Entry {
        module: "binary",
        function: "match",
        arity: 2,
        continuation: BINARY_SEARCH_CONTINUATION,
        handler: binary_match,
    },
    Entry {
        module: "binary",
        function: "match",
        arity: 3,
        continuation: BINARY_SEARCH_CONTINUATION,
        handler: binary_match,
    },
    Entry {
        module: "binary",
        function: "matches",
        arity: 2,
        continuation: BINARY_SEARCH_CONTINUATION,
        handler: binary_matches,
    },
    Entry {
        module: "binary",
        function: "matches",
        arity: 3,
        continuation: BINARY_SEARCH_CONTINUATION,
        handler: binary_matches,
    },
    Entry {
        module: "binary",
        function: "split",
        arity: 2,
        continuation: BINARY_SEARCH_CONTINUATION,
        handler: binary_split,
    },
    Entry {
        module: "binary",
        function: "split",
        arity: 3,
        continuation: BINARY_SEARCH_CONTINUATION,
        handler: binary_split,
    },
];

struct BinaryCopyState {
    bytes: Vec<u8>,
    copied: usize,
}

fn binary_match(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<TrapResult, BifError> {
    binary_search(
        process,
        args,
        state,
        restore_gc,
        arinsal_bifs::BinarySearchKind::Match,
    )
}

fn binary_matches(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<TrapResult, BifError> {
    binary_search(
        process,
        args,
        state,
        restore_gc,
        arinsal_bifs::BinarySearchKind::Matches,
    )
}

fn binary_split(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<TrapResult, BifError> {
    binary_search(
        process,
        args,
        state,
        restore_gc,
        arinsal_bifs::BinarySearchKind::Split,
    )
}

fn binary_search(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    restore_gc: bool,
    kind: arinsal_bifs::BinarySearchKind,
) -> Result<TrapResult, BifError> {
    // Port of erts/emulator/beam/erl_bif_binary.c:1433-1528 (do_binary_find), OTP-29.1.1.
    const SEARCH_LOOP_FACTOR: usize = 10;
    let budget = (process.reductions.max(0) as usize).saturating_mul(SEARCH_LOOP_FACTOR);
    let resumed = state.is_some();
    let state = if let Some(state) = state {
        Arc::clone(state)
    } else {
        MagicRef::new(Mutex::new(arinsal_bifs::BinarySearchWalk::new(kind, args)?))
    };
    let search = state
        .downcast_ref::<Mutex<arinsal_bifs::BinarySearchWalk>>()
        .ok_or(BifError::BADARG)?;
    let mut search = search.lock().map_err(|_| BifError::SystemLimit)?;
    let (done, work) = search.step(budget);
    let reductions = (work / SEARCH_LOOP_FACTOR) as u32;
    if !done {
        drop(search);
        return Ok(TrapResult::Yield {
            continuation: BINARY_SEARCH_CONTINUATION,
            state,
            reductions,
        });
    }
    if resumed {
        process.set_gc_enabled(restore_gc);
    }
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    let mut ctx = arinsal_bifs::Ctx::new(&mut heap);
    let value = search.finish(&mut ctx)?;
    Ok(TrapResult::Done { value, reductions })
}

/// Key of a trapped call made through `apply` when the caller does not import the BIF.
pub(crate) const APPLY_TRAP_KEY: usize = usize::MAX;

/// Execute or resume one registered trapping BIF before the ordinary BIF path.
pub(crate) fn execute(
    vm: &mut Vm,
    process: &mut Process,
    import: usize,
    arity: usize,
    args: [Term; 3],
    ctx: Option<&mut arinsal_sched::RunCtx<'_, process::Message>>,
) -> Option<Result<TrapResult, VmError>> {
    let import_info = vm.modules.get(process.module).and_then(|module| {
        module.imports.get(import).map(|import| {
            (
                import.module.as_str(),
                import.function.as_str(),
                usize::from(import.arity),
            )
        })
    });
    let Some((module_name, function_name, import_arity)) = import_info else {
        if let Some(pending) = process.cold_mut().bif_trap.take() {
            process.set_gc_enabled(pending.gc_was_enabled);
        }
        return Some(Err(VmError::Unsupported(format!("import {import}"))));
    };
    if import_arity != arity {
        return None;
    }
    execute_named(
        process,
        module_name,
        function_name,
        import,
        arity,
        args,
        ctx,
    )
}

/// Execute or resume a trapping BIF named by module and function; `key` identifies the call
/// at the current call site (an import index, or [`APPLY_TRAP_KEY`]).
/// Whether `module:function/arity` is a BIF that may trap to a continuation.
pub(crate) fn traps(module: &str, function: &str, arity: u8) -> bool {
    ENTRIES
        .iter()
        .any(|entry| entry.module == module && entry.function == function && entry.arity == arity)
}

pub(crate) fn execute_named(
    process: &mut Process,
    module_name: &str,
    function_name: &str,
    import: usize,
    arity: usize,
    mut args: [Term; 3],
    ctx: Option<&mut arinsal_sched::RunCtx<'_, process::Message>>,
) -> Option<Result<TrapResult, VmError>> {
    let gc_enabled_on_entry = process.gc_enabled;
    let pending_site = process
        .cold
        .as_ref()
        .and_then(|cold| cold.bif_trap.as_ref())
        .map(|pending| {
            (
                pending.caller_module == process.module && pending.caller_ip == process.ip,
                pending.import == import,
            )
        });
    let pending_matches = pending_site == Some((true, true));
    if pending_site.is_some_and(|(same_site, _)| !same_site) {
        // A trap continuation belongs to exactly one interrupted call. An
        // exception can redirect control without re-entering that call, so
        // discard its state before dispatching a call from another site. The
        // same site may first dispatch `apply` before reaching the trapped BIF.
        if let Some(pending) = process.cold_mut().bif_trap.take() {
            process.set_gc_enabled(pending.gc_was_enabled);
        }
    }
    if module_name == "erts_debug"
        && function_name == "set_internal_state"
        && args[0].as_atom().and_then(|atom| global_atoms().text(atom))
            != Some("code_mod_permission")
    {
        return None;
    }
    let entry = ENTRIES.iter().find(|entry| {
        entry.module == module_name
            && entry.function == function_name
            && usize::from(entry.arity) == arity
    });
    let pending = pending_matches
        .then(|| {
            process
                .cold
                .as_ref()
                .and_then(|cold| cold.bif_trap.as_ref())
        })
        .flatten();
    let gc_was_enabled = pending.map_or(gc_enabled_on_entry, |pending| pending.gc_was_enabled);
    let (handler, state) = if let Some(pending) = pending {
        let Some(entry) = entry else {
            if let Some(pending) = process.cold_mut().bif_trap.take() {
                process.set_gc_enabled(pending.gc_was_enabled);
            }
            return Some(Err(VmError::Unsupported(
                "missing BIF continuation entry".into(),
            )));
        };
        if entry.continuation != pending.continuation {
            if let Some(pending) = process.cold_mut().bif_trap.take() {
                process.set_gc_enabled(pending.gc_was_enabled);
            }
            return Some(Err(VmError::Unsupported(
                "BIF continuation export mismatch".into(),
            )));
        }
        (entry.handler, Some(Arc::clone(&pending.state)))
    } else {
        (entry?.handler, None)
    };
    if module_name == "erlang"
        && function_name == "binary_to_term"
        && state.is_none()
        && let Some(bits) = arinsal_bifs::bitstring_bit_len(args[0]).ok()
        && bits.is_multiple_of(8)
        && let Some(reserve) = (bits / 8).checked_mul(2).and_then(|n| n.checked_add(64))
    {
        if let Err(error) = process.ensure(reserve, process.gc_live) {
            return Some(Err(error));
        }
        for slot in 0..arity.min(args.len()) {
            args[slot] = process.x.get(slot).copied().unwrap_or(Term::NIL);
        }
    }

    let pid = ctx.as_deref().map(|run| run.pid());
    if module_name == "erlang" && function_name == "binary_to_term" {
        process.set_gc_enabled(false);
    }
    let result = handler(process, &args[..arity], state.as_ref(), pid, gc_was_enabled);
    Some(match result {
        Err(error) => {
            process.cold_mut().bif_trap = None;
            process.set_gc_enabled(gc_was_enabled);
            // Re-enabling GC may collect: the X registers, not the copies, hold the live
            // arguments.
            let args = live_args(process, &args, arity);
            Err(exceptions::bif_error(
                process,
                module_name,
                function_name,
                &args,
                error,
            ))
        }
        Ok(TrapResult::Done { value, reductions }) => {
            process.cold_mut().bif_trap = None;
            process.set_gc_enabled(gc_was_enabled);
            charge(process, ctx, reductions);
            Ok(TrapResult::Done { value, reductions })
        }
        Ok(TrapResult::Failed { error, reductions }) => {
            process.cold_mut().bif_trap = None;
            process.set_gc_enabled(gc_was_enabled);
            charge(process, ctx, reductions);
            let args = live_args(process, &args, arity);
            Err(exceptions::bif_error(
                process,
                module_name,
                function_name,
                &args,
                error,
            ))
        }
        Ok(TrapResult::Yield {
            continuation,
            state,
            reductions,
        }) => {
            // The ptab list state holds no heap terms, so the process stays collectable
            // while trapped (erts keeps it GC-able in ptab_list_continue/2).
            if continuation != PTAB_LIST_CONTINUATION {
                process.set_gc_enabled(false);
            }
            process.cold_mut().bif_trap = Some(crate::proc_create::BifTrapPending {
                caller_module: process.module,
                caller_ip: process.ip,
                import,
                continuation,
                state,
                gc_was_enabled,
            });
            charge(process, ctx, reductions);
            Ok(TrapResult::Yield {
                continuation,
                state: process
                    .cold
                    .as_ref()
                    .and_then(|cold| cold.bif_trap.as_ref())
                    .map(|pending| Arc::clone(&pending.state))
                    .expect("stored continuation"),
                reductions,
            })
        }
    })
}

/// The call's arguments as the X registers hold them now; a collection since the copies
/// were taken has moved boxed arguments.
fn live_args(process: &Process, copies: &[Term; 3], arity: usize) -> Vec<Term> {
    (0..arity)
        .map(|slot| process.x.get(slot).copied().unwrap_or(copies[slot]))
        .collect()
}

fn charge(
    process: &mut Process,
    ctx: Option<&mut arinsal_sched::RunCtx<'_, process::Message>>,
    reductions: u32,
) {
    let charge = reductions.max(1);
    process.reductions = process
        .reductions
        .saturating_sub(charge.min(i32::MAX as u32) as i32);
    if let Some(run) = ctx {
        let _ = run.consume(charge);
    }
    if process.reductions <= 0 {
        process.reductions = 4000;
    }
}

fn code_permission(
    _process: &mut Process,
    args: &[Term],
    _state: Option<&Arc<MagicRef>>,
    pid: Option<arinsal_sched::Pid>,
    _gc_changed: bool,
) -> Result<TrapResult, BifError> {
    if !crate::natives::internal_state_enabled() {
        return Err(BifError::Error(Term::atom(
            global_atoms().intern("undef").unwrap(),
        )));
    }
    if args[0] != Term::atom(global_atoms().intern("code_mod_permission").unwrap()) {
        return Err(BifError::Unsupported(
            "unhandled set_internal_state selector",
        ));
    }
    let acquire = match global_atoms().text(args[1].as_atom().ok_or(BifError::BADARG)?) {
        Some("true") => true,
        Some("false") => false,
        _ => return Err(BifError::BADARG),
    };
    let pid = pid.ok_or(BifError::Unsupported(
        "code_mod_permission requires a scheduler",
    ))?;
    if crate::natives::try_code_mod_permission(pid, acquire) {
        return Ok(TrapResult::Done {
            value: Term::atom(global_atoms().intern("true").unwrap()),
            reductions: 1,
        });
    }
    Ok(TrapResult::Yield {
        continuation: CODE_PERMISSION_CONTINUATION,
        state: MagicRef::new(acquire),
        reductions: 1,
    })
}

fn list_to_binary(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    gc_changed: bool,
) -> Result<TrapResult, BifError> {
    let root = args[0];
    if !matches!(root.classify(), TermKind::List | TermKind::Nil) {
        return Err(BifError::BADARG);
    }
    if let Some(value) = arinsal_bifs::singleton_bitstring(root, 8)? {
        return Ok(TrapResult::Done {
            value,
            reductions: 1,
        });
    }
    iolist_conversion(process, root, state, false, gc_changed)
}

fn iolist_to_binary(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    gc_changed: bool,
) -> Result<TrapResult, BifError> {
    let root = args[0];
    if root.classify() == TermKind::Bitstring {
        if !arinsal_bifs::bitstring_bit_len(root)?.is_multiple_of(8) {
            return Err(BifError::BADARG);
        }
        return Ok(TrapResult::Done {
            value: root,
            reductions: 1,
        });
    }
    iolist_conversion(process, root, state, false, gc_changed)
}

fn list_to_bitstring(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    gc_changed: bool,
) -> Result<TrapResult, BifError> {
    if !matches!(args[0].classify(), TermKind::List | TermKind::Nil) {
        return Err(BifError::BADARG);
    }
    if let Some(value) = arinsal_bifs::singleton_bitstring(args[0], 1)? {
        return Ok(TrapResult::Done {
            value,
            reductions: 1,
        });
    }
    iolist_conversion(process, args[0], state, true, gc_changed)
}

fn iolist_size(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<TrapResult, BifError> {
    const CHUNK: usize = 4096;
    let root = args[0];
    let resumed = state.is_some();
    let state = if let Some(state) = state {
        Arc::clone(state)
    } else {
        MagicRef::new(Mutex::new(arinsal_bifs::IolistSizeWalk::new(root)))
    };
    let walker = state
        .downcast_ref::<Mutex<arinsal_bifs::IolistSizeWalk>>()
        .ok_or(BifError::BADARG)?;
    let mut walker = walker.lock().map_err(|_| BifError::SystemLimit)?;
    let (done, reductions) = match walker.step(CHUNK) {
        Ok(progress) => progress,
        Err((error, reductions)) => {
            return Ok(TrapResult::Failed {
                error,
                reductions: reductions as u32,
            });
        }
    };
    if !done {
        drop(walker);
        return Ok(TrapResult::Yield {
            continuation: IOLIST_SIZE_CONTINUATION,
            state,
            reductions: reductions as u32,
        });
    }
    let size = walker.take_size();
    drop(walker);
    if resumed {
        process.set_gc_enabled(restore_gc);
    }
    let value = TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
        .int_from_bigint(&size)
        .map_err(|_| BifError::SystemLimit)?;
    Ok(TrapResult::Done {
        value,
        reductions: reductions as u32,
    })
}

fn iolist_conversion(
    process: &mut Process,
    root: Term,
    state: Option<&Arc<MagicRef>>,
    bitstring: bool,
    restore_gc: bool,
) -> Result<TrapResult, BifError> {
    const CHUNK: usize = 4096;
    if !matches!(root.classify(), TermKind::List | TermKind::Nil) {
        return Err(BifError::BADARG);
    }
    let resumed = state.is_some();
    let state = if let Some(state) = state {
        Arc::clone(state)
    } else {
        MagicRef::new(Mutex::new(arinsal_bifs::IolistWalk::new(root, bitstring)))
    };
    let walker = state
        .downcast_ref::<Mutex<arinsal_bifs::IolistWalk>>()
        .ok_or(BifError::BADARG)?;
    let mut walker = walker.lock().map_err(|_| BifError::SystemLimit)?;
    let (done, reductions) = match walker.step(CHUNK) {
        Ok(progress) => progress,
        Err((error, reductions)) => {
            return Ok(TrapResult::Failed {
                error,
                reductions: reductions as u32,
            });
        }
    };
    if !done {
        drop(walker);
        return Ok(TrapResult::Yield {
            continuation: IOLIST_CONTINUATION,
            state,
            reductions: reductions as u32,
        });
    }
    let (bytes, bits) = walker.take_parts();
    drop(walker);
    if resumed {
        process.set_gc_enabled(restore_gc);
    }
    let value = TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
        .bitstring(&bytes, bits)
        .map_err(|_| BifError::SystemLimit)?;
    Ok(TrapResult::Done {
        value,
        reductions: reductions as u32,
    })
}

fn binary_to_term(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<TrapResult, BifError> {
    const BYTES_PER_REDUCTION: usize = 128;
    let chunk_bytes = (process.reductions.max(0) as usize).saturating_mul(BYTES_PER_REDUCTION);
    let state = if let Some(state) = state {
        Arc::clone(state)
    } else {
        MagicRef::new(Mutex::new(arinsal_bifs::DecodeWalk::new(args)?))
    };
    let decoder = state
        .downcast_ref::<Mutex<arinsal_bifs::DecodeWalk>>()
        .ok_or(BifError::BADARG)?;
    let mut decoder = decoder.lock().map_err(|_| BifError::SystemLimit)?;
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    let mut ctx = arinsal_bifs::Ctx::new(&mut heap);
    let step = decoder.step_into(chunk_bytes, &mut ctx);
    match step {
        Ok((None, consumed)) => {
            drop(decoder);
            Ok(TrapResult::Yield {
                continuation: BINARY_TO_TERM_CONTINUATION,
                state,
                reductions: consumed.div_ceil(BYTES_PER_REDUCTION) as u32,
            })
        }
        Ok((Some(value), consumed)) => {
            process.set_gc_enabled(restore_gc);
            Ok(TrapResult::Done {
                value,
                reductions: consumed.div_ceil(BYTES_PER_REDUCTION) as u32,
            })
        }
        Err((error, consumed)) => {
            process.set_gc_enabled(restore_gc);
            Ok(TrapResult::Failed {
                error: match error {
                    BifError::Unsupported(_) => BifError::BADARG,
                    other => other,
                },
                reductions: consumed.div_ceil(BYTES_PER_REDUCTION) as u32,
            })
        }
    }
}

fn binary_copy(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<TrapResult, BifError> {
    // Port of erts/emulator/beam/erl_bif_binary.c:2380-2505, OTP-29.1.1.
    const COPY_BYTES_PER_REDUCTION: usize = 64;
    const CHUNK_BYTES: usize = 4000 * COPY_BYTES_PER_REDUCTION;
    let resumed = state.is_some();
    let input = args[0];
    let count = if args.len() == 2 {
        args[1]
            .as_small()
            .filter(|count| *count >= 0)
            .ok_or(BifError::BADARG)? as usize
    } else {
        1
    };
    let input_bits = arinsal_bifs::bitstring_bit_len(input)?;
    if !input_bits.is_multiple_of(8) {
        return Err(BifError::BADARG);
    }
    let input_len = input_bits / 8;
    let len = input_len
        .checked_mul(count)
        .filter(|len| *len <= (1 << 30))
        .ok_or(BifError::SystemLimit)?;
    if len == 0 || input_len == 0 {
        let value = TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
            .binary(&[])
            .map_err(|_| BifError::SystemLimit)?;
        return Ok(TrapResult::Done {
            value,
            reductions: 1,
        });
    }
    let state = if let Some(state) = state {
        Arc::clone(state)
    } else {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| BifError::SystemLimit)?;
        bytes.resize(len, 0);
        MagicRef::new(Mutex::new(BinaryCopyState { bytes, copied: 0 }))
    };
    let copy = state
        .downcast_ref::<Mutex<BinaryCopyState>>()
        .ok_or(BifError::BADARG)?;
    let mut copy = copy.lock().map_err(|_| BifError::SystemLimit)?;
    let end = copy.copied.saturating_add(CHUNK_BYTES).min(len);
    let mut offset = copy.copied;
    while offset < end {
        let source_offset = offset % input_len;
        let amount = (end - offset).min(input_len - source_offset);
        arinsal_bifs::copy_binary_range(
            input,
            source_offset,
            &mut copy.bytes[offset..offset + amount],
        )?;
        offset += amount;
    }
    let reductions = ((end - copy.copied) / COPY_BYTES_PER_REDUCTION) as u32;
    copy.copied = end;
    if end < len {
        drop(copy);
        return Ok(TrapResult::Yield {
            continuation: BINARY_COPY_CONTINUATION,
            state,
            reductions,
        });
    }
    if resumed {
        process.set_gc_enabled(restore_gc);
    }
    let value = TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
        .binary(&copy.bytes)
        .map_err(|_| BifError::SystemLimit)?;
    Ok(TrapResult::Done { value, reductions })
}

fn term_to_binary(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<TrapResult, BifError> {
    term_encode(process, args, state, restore_gc, false)
}

fn term_to_iovec(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    restore_gc: bool,
) -> Result<TrapResult, BifError> {
    term_encode(process, args, state, restore_gc, true)
}

fn term_encode(
    process: &mut Process,
    args: &[Term],
    state: Option<&Arc<MagicRef>>,
    restore_gc: bool,
    iovec: bool,
) -> Result<TrapResult, BifError> {
    // Port of erts/emulator/beam/external.c:2449-2590, OTP-29.1.1.
    const TERM_TO_BINARY_LOOP_FACTOR: usize = 32;
    let chunk_work =
        (process.reductions.max(0) as usize).saturating_mul(TERM_TO_BINARY_LOOP_FACTOR);
    let resumed = state.is_some();
    let state = if let Some(state) = state {
        Arc::clone(state)
    } else {
        MagicRef::new(Mutex::new(arinsal_bifs::EncodeWalk::new(args)?))
    };
    let encoder = state
        .downcast_ref::<Mutex<arinsal_bifs::EncodeWalk>>()
        .ok_or(BifError::BADARG)?;
    let mut encoder_guard = encoder.lock().map_err(|_| BifError::SystemLimit)?;
    let (done, work) = encoder_guard.step(chunk_work)?;
    let reductions = work.div_ceil(TERM_TO_BINARY_LOOP_FACTOR) as u32;
    if !done {
        drop(encoder_guard);
        return Ok(TrapResult::Yield {
            continuation: TERM_TO_BINARY_CONTINUATION,
            state,
            reductions,
        });
    }
    if resumed {
        process.set_gc_enabled(restore_gc);
    }
    let encoder = std::mem::replace(&mut *encoder_guard, arinsal_bifs::EncodeWalk::completed());
    drop(encoder_guard);
    let mut heap = arinsal_bifs::FragmentingHeap(&mut process.heap);
    let mut builder = TermBuilder::new(&mut heap);
    let value = if iovec {
        let (parts, compressed) = encoder.finish_iovec()?;
        let terms = parts
            .iter()
            .map(|bytes| builder.binary(bytes).map_err(|_| BifError::SystemLimit))
            .collect::<Result<Vec<_>, _>>()?;
        if compressed {
            terms[0]
        } else {
            builder
                .list_from_iter(terms)
                .map_err(|_| BifError::SystemLimit)?
        }
    } else {
        let bytes = encoder.finish_binary()?;
        builder.binary(&bytes).map_err(|_| BifError::SystemLimit)?
    };
    Ok(TrapResult::Done { value, reductions })
}

/// Progress of one `erlang:processes/0` call.
struct PtabListState {
    /// Consistent snapshot of the table taken when the BIF started.
    pids: Vec<arinsal_sched::Pid>,
    /// Next table index to inspect.
    next_index: u32,
}

// Port of erts/emulator/beam/erl_ptab.c:746 (erts_ptab_list) and :1281 (ptab_list_continue),
// OTP-29.1.1. Costs follow the engine's constants (erl_ptab.c:42-57): 25 table indices per
// reduction scanned in chunks of 1000, 75 result conses per reduction.
fn processes(
    process: &mut Process,
    _args: &[Term],
    state: Option<&Arc<MagicRef>>,
    _pid: Option<arinsal_sched::Pid>,
    _restore_gc: bool,
) -> Result<TrapResult, BifError> {
    const INDICES_PER_RED: u32 = 25;
    const CHUNK_SIZE: u32 = 1000;
    const MIN_START_REDS: u32 = CHUNK_SIZE / INDICES_PER_RED;
    const CONSES_PER_RED: usize = 75;
    const TABLE_MAX: u32 = 1_048_576;
    let reds_left = process.reductions.max(0) as u32;
    let (state, first) = if let Some(state) = state {
        (Arc::clone(state), false)
    } else {
        let runtime = process.runtime.as_ref().ok_or(BifError::BADARG)?;
        let scheduler = runtime.scheduler().map_err(|_| BifError::BADARG)?;
        let mut pids = runtime
            .processes
            .lock()
            .map_err(|_| BifError::SystemLimit)?
            .iter()
            .copied()
            .filter(|pid| scheduler.lookup(*pid))
            .collect::<Vec<_>>();
        pids.sort_by_key(|pid| (pid.index, pid.generation));
        (
            MagicRef::new(Mutex::new(PtabListState {
                pids,
                next_index: 0,
            })),
            true,
        )
    };
    let yield_now = |state: Arc<MagicRef>, reductions: u32| {
        Ok(TrapResult::Yield {
            continuation: PTAB_LIST_CONTINUATION,
            state,
            reductions,
        })
    };
    if first && reds_left < MIN_START_REDS {
        return yield_now(state, 1);
    }
    let mut spent = 0_u32;
    let done = {
        let mut list = state
            .downcast_ref::<Mutex<PtabListState>>()
            .ok_or(BifError::BADARG)?
            .lock()
            .map_err(|_| BifError::SystemLimit)?;
        while list.next_index < TABLE_MAX && spent < reds_left {
            list.next_index = (list.next_index + CHUNK_SIZE).min(TABLE_MAX);
            spent += MIN_START_REDS;
        }
        if list.next_index >= TABLE_MAX {
            spent = spent.max(list.pids.len().div_ceil(CONSES_PER_RED) as u32);
            true
        } else {
            false
        }
    };
    if !done {
        return yield_now(state, spent);
    }
    let pid_terms = state
        .downcast_ref::<Mutex<PtabListState>>()
        .ok_or(BifError::BADARG)?
        .lock()
        .map_err(|_| BifError::SystemLimit)?
        .pids
        .iter()
        .filter_map(|pid| pid.to_term())
        .collect::<Vec<_>>();
    let value = TermBuilder::new(&mut arinsal_bifs::FragmentingHeap(&mut process.heap))
        .list_from_iter(pid_terms)
        .map_err(|_| BifError::SystemLimit)?;
    Ok(TrapResult::Done {
        value,
        reductions: spent,
    })
}
