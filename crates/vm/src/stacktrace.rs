//! Symbolic stack traces from BEAM continuations.

use crate::{NativeFunction, Process, VmError, native_function_at};
use arinsal_bifs::{Class, FragmentingHeap};
use arinsal_etf::OwnedTerm;
use arinsal_loader::Module;
use arinsal_term::{ProcessHeap, Term, TermBuilder, TermKind, from_owned, global_atoms, to_owned};
use std::sync::Arc;

const HANDLER_BIT: u64 = 1 << 57;
// Reserve the last encodable handler module index for private trace handles.
const RAW_TRACE_PREFIX: u64 = (1 << 26) - 1;

/// Continuation addresses saved before exception unwinding.
#[derive(Default, Clone)]
pub(super) struct RawTrace {
    class: Option<Class>,
    explicit: Option<OwnedTerm>,
    top: Option<StoredTopFrame>,
    module: Option<Arc<Module>>,
    ip: usize,
    continuations: Vec<Continuation>,
    depth: usize,
}

#[derive(Clone)]
enum Continuation {
    Interpreted(Arc<Module>, usize),
    Native(NativeFunction),
}

#[derive(Clone)]
enum StoredTopFrame {
    Bif {
        module: String,
        function: String,
        args: OwnedTerm,
    },
    CurrentArgs(OwnedTerm),
    CurrentArgsWithInfo(OwnedTerm, Box<OwnedTerm>),
}

/// Port of erts/emulator/beam/beam_common.c:781 (gather_stacktrace), OTP-29.1.1.
pub(super) fn capture(
    raw: &mut RawTrace,
    class: Option<Class>,
    top: Option<&TopFrame>,
    modules: &[Arc<Module>],
    current: (usize, usize),
    heap: &ProcessHeap,
    depth: usize,
) -> Result<(), VmError> {
    // Port of beam_common.c:600-614 (`erts_inspect_frame`) and beam_common.h:301-315,
    // OTP-29.1.1: continuations are raw CP words resolved back to code metadata.
    let (module, ip) = current;
    raw.class = class;
    raw.explicit = None;
    raw.top = top
        .map(|top| match top {
            TopFrame::Bif {
                module,
                function,
                args,
            } => Ok(StoredTopFrame::Bif {
                module: module.clone(),
                function: function.clone(),
                args: to_owned(*args)
                    .map_err(|e| VmError::Unsupported(format!("exception args {e:?}")))?,
            }),
            TopFrame::CurrentArgs(args) => Ok(StoredTopFrame::CurrentArgs(
                to_owned(*args)
                    .map_err(|e| VmError::Unsupported(format!("exception args {e:?}")))?,
            )),
            TopFrame::CurrentArgsWithInfo(args, info) => Ok(StoredTopFrame::CurrentArgsWithInfo(
                to_owned(*args)
                    .map_err(|e| VmError::Unsupported(format!("exception args {e:?}")))?,
                info.clone(),
            )),
        })
        .transpose()?;
    raw.module = modules.get(module).cloned();
    raw.ip = ip;
    raw.depth = depth.max(1);
    raw.continuations.clear();
    let mut previous = None;
    let mut index = 0;
    while index < heap.stack_words() {
        if raw.continuations.len() + 1 >= raw.depth {
            break;
        }
        let Some(word) = heap.stack_get(index) else {
            index += 1;
            continue;
        };
        let raw_address = word.tagged_word() as usize;
        if raw_address == crate::native_bridge::native_trace_return_address() {
            let function_pc = heap
                .stack_get(index + 2)
                .and_then(Term::as_small)
                .unwrap_or(0) as usize;
            let action_count = heap
                .stack_get(index + 3)
                .and_then(Term::as_small)
                .and_then(|count| usize::try_from(count).ok())
                .unwrap_or(0);
            if let Some(function) = native_function_at(function_pc) {
                raw.continuations.push(Continuation::Native(function));
            }
            index += 4usize.saturating_add(action_count.saturating_mul(2));
            continue;
        }
        if let Some(function) = native_function_at(raw_address) {
            raw.continuations.push(Continuation::Native(function));
            index += 1;
            continue;
        }
        let Some((handler, module, ip)) = decode_tag(word) else {
            index += 1;
            continue;
        };
        if let Some(code) = modules.get(module)
            && !handler
            && (ip == code.return_trace_ip || ip == code.return_to_trace_ip)
        {
            index += if ip == code.return_trace_ip { 5 } else { 2 };
            continue;
        }
        if handler || previous == Some((module, ip)) {
            index += 1;
            continue;
        }
        previous = Some((module, ip));
        if let Some(module) = modules.get(module) {
            raw.continuations
                .push(Continuation::Interpreted(Arc::clone(module), ip));
        }
        index += 1;
    }
    Ok(())
}

/// Preserve an explicit `raise/3` stacktrace with its class across `try/after`.
pub(super) fn save_explicit(raw: &mut RawTrace, class: Class, trace: Term) -> Result<(), VmError> {
    raw.class = Some(class);
    raw.explicit =
        Some(to_owned(trace).map_err(|e| VmError::Unsupported(format!("exception stack {e:?}")))?);
    raw.top = None;
    raw.module = None;
    raw.continuations.clear();
    Ok(())
}

/// Exception class saved with a raw trace for a later `raise` instruction.
pub(super) fn raw_class(p: &Process, term: Term) -> Option<Class> {
    let index = raw_index(term)?;
    p.cold
        .as_ref()
        .and_then(|cold| cold.raw_traces.get(index))
        .and_then(|raw| raw.class)
}

/// Encode a process-local raw trace handle as an internal catch immediate.
pub(super) fn raw_tag(index: usize) -> Result<Term, VmError> {
    let index = u32::try_from(index).map_err(|_| VmError::Unsupported("raw trace index".into()))?;
    Ok(Term::catch((RAW_TRACE_PREFIX << 32) | u64::from(index)))
}

/// Decode a raw trace handle without treating a BEAM catch tag as one.
pub(super) fn raw_index(term: Term) -> Option<usize> {
    if term.tagged_word() & 63 != 0x1b || term.classify() != TermKind::Catch {
        return None;
    }
    // SAFETY: CATCH is immediate and contains no heap pointer.
    let payload = unsafe { term.raw_bits() } >> 6;
    (payload >> 32 == RAW_TRACE_PREFIX).then_some(payload as u32 as usize)
}

#[derive(Debug)]
pub(super) enum TopFrame {
    Bif {
        module: String,
        function: String,
        args: Term,
    },
    CurrentArgs(Term),
    CurrentArgsWithInfo(Term, Box<OwnedTerm>),
}

pub(super) fn handler_tag(module: usize, ip: usize) -> Result<Term, VmError> {
    let module = u64::try_from(module).map_err(|_| VmError::Unsupported("module index".into()))?;
    let ip = u32::try_from(ip).map_err(|_| VmError::Unsupported("code index".into()))?;
    if module >= (1 << 25) - 1 {
        return Err(VmError::Unsupported("module index".into()));
    }
    Ok(Term::catch(HANDLER_BIT | module << 32 | u64::from(ip)))
}

pub(super) fn decode_tag(term: Term) -> Option<(bool, usize, usize)> {
    if term.tagged_word() & 63 != 0x1b || term.classify() != TermKind::Catch {
        return None;
    }
    // SAFETY: CATCH is an immediate and carries no heap pointer.
    let payload = unsafe { term.raw_bits() } >> 6;
    if payload >> 32 == RAW_TRACE_PREFIX {
        return None;
    }
    Some((
        payload & HANDLER_BIT != 0,
        ((payload & !HANDLER_BIT) >> 32) as usize,
        payload as u32 as usize,
    ))
}

fn atom(name: &str) -> Result<Term, VmError> {
    global_atoms()
        .intern(name)
        .map(Term::atom)
        .map_err(|_| VmError::Unsupported(format!("atom {name}")))
}

fn build_frame(
    p: &mut Process,
    module: &str,
    function: &str,
    arity_or_args: Term,
    location: Option<&(String, u64)>,
    bif: bool,
    error_info: Option<Term>,
) -> Result<Term, VmError> {
    let module = atom(module)?;
    let function = atom(function)?;
    let file = atom("file")?;
    let line = atom("line")?;
    let mut heap = FragmentingHeap(&mut p.heap);
    let mut builder = TermBuilder::new(&mut heap);
    let error_info = if bif {
        let map = builder
            .flatmap_from_pairs(&[(atom("module")?, atom("erl_erts_errors")?)])
            .map_err(|e| VmError::Unsupported(format!("BIF error info {e:?}")))?;
        Some(map)
    } else {
        error_info
    };
    let mut info = Vec::new();
    if let Some(error_info) = error_info {
        info.push(
            builder
                .tuple(&[atom("error_info")?, error_info])
                .map_err(|e| VmError::Unsupported(format!("error info tuple {e:?}")))?,
        );
    }
    if !bif && let Some((name, number)) = location {
        let name = builder
            .string_to_list(name)
            .map_err(|e| VmError::Unsupported(format!("stack file {e:?}")))?;
        let number = Term::small(*number as i64)
            .ok_or_else(|| VmError::Unsupported("source line number".into()))?;
        info.push(
            builder
                .tuple(&[file, name])
                .map_err(|e| VmError::Unsupported(format!("stack file {e:?}")))?,
        );
        info.push(
            builder
                .tuple(&[line, number])
                .map_err(|e| VmError::Unsupported(format!("stack line {e:?}")))?,
        );
    }
    let location = builder
        .list_from_iter(info)
        .map_err(|e| VmError::Unsupported(format!("stack frame info {e:?}")))?;
    builder
        .tuple(&[module, function, arity_or_args, location])
        .map_err(|e| VmError::Unsupported(format!("stack frame {e:?}")))
}

/// Port of erts/emulator/beam/beam_common.c:781 (gather_stacktrace), OTP-29.1.1.
/// A continuation points after the call; the preceding instruction owns its line.
pub(super) fn build(
    modules: &[Arc<Module>],
    p: &mut Process,
    top: Option<&TopFrame>,
    depth: usize,
) -> Result<Term, VmError> {
    let mut raw = RawTrace::default();
    capture(
        &mut raw,
        None,
        top,
        modules,
        (p.module, p.ip),
        &p.heap,
        depth,
    )?;
    build_saved(p, &raw)
}

/// Port of erts/emulator/beam/beam_common.c:1205 (build_stacktrace), OTP-29.1.1.
pub(super) fn build_saved(p: &mut Process, raw: &RawTrace) -> Result<Term, VmError> {
    if let Some(explicit) = &raw.explicit {
        return from_owned(explicit, &mut FragmentingHeap(&mut p.heap))
            .map_err(|e| VmError::Unsupported(format!("exception stack {e:?}")));
    }
    let top = raw
        .top
        .as_ref()
        .map(|top| match top {
            StoredTopFrame::Bif {
                module,
                function,
                args,
            } => Ok(TopFrame::Bif {
                module: module.clone(),
                function: function.clone(),
                args: from_owned(args, &mut FragmentingHeap(&mut p.heap))
                    .map_err(|e| VmError::Unsupported(format!("exception args {e:?}")))?,
            }),
            StoredTopFrame::CurrentArgs(args) => Ok(TopFrame::CurrentArgs(
                from_owned(args, &mut FragmentingHeap(&mut p.heap))
                    .map_err(|e| VmError::Unsupported(format!("exception args {e:?}")))?,
            )),
            StoredTopFrame::CurrentArgsWithInfo(args, info) => {
                let args = from_owned(args, &mut FragmentingHeap(&mut p.heap))
                    .map_err(|e| VmError::Unsupported(format!("exception args {e:?}")))?;
                Ok(TopFrame::CurrentArgsWithInfo(args, info.clone()))
            }
        })
        .transpose()?;
    let top = top.as_ref();
    let mut frames = Vec::with_capacity(raw.depth);
    let current = raw
        .module
        .as_ref()
        .ok_or_else(|| VmError::Unsupported("stacktrace module".into()))?;
    let (name, arity) = current.function_at(raw.ip).unwrap_or(("?", 0));
    let location = current.lines.get(raw.ip).and_then(Option::as_ref);
    let top_frame = if let Some(TopFrame::Bif {
        module,
        function,
        args,
    }) = top
    {
        build_frame(p, module, function, *args, None, true, None)?
    } else {
        let top_args = match top {
            Some(TopFrame::CurrentArgs(args)) | Some(TopFrame::CurrentArgsWithInfo(args, _)) => {
                *args
            }
            _ => Term::small(i64::from(arity)).expect("arity is small"),
        };
        let error_info = match top {
            Some(TopFrame::CurrentArgsWithInfo(_, info)) => Some(
                from_owned(info.as_ref(), &mut FragmentingHeap(&mut p.heap))
                    .map_err(|e| VmError::Unsupported(format!("exception info {e:?}")))?,
            ),
            _ => None,
        };
        build_frame(
            p,
            &current.name,
            name,
            top_args,
            location,
            false,
            error_info,
        )?
    };
    frames.push(top_frame);
    if matches!(top, Some(TopFrame::Bif { .. })) && frames.len() < raw.depth {
        frames.push(build_frame(
            p,
            &current.name,
            name,
            Term::small(i64::from(arity)).expect("arity is small"),
            location,
            false,
            None,
        )?);
    }
    for continuation in &raw.continuations {
        if frames.len() >= raw.depth {
            break;
        }
        if let Continuation::Native(function) = continuation {
            let location = function
                .line
                .map(|line| (function.file.clone().unwrap_or_default(), u64::from(line)));
            frames.push(build_frame(
                p,
                &function.module,
                &function.function,
                Term::small(i64::from(function.arity)).expect("arity is small"),
                location.as_ref(),
                false,
                None,
            )?);
            continue;
        }
        let Continuation::Interpreted(module, ip) = continuation else {
            unreachable!()
        };
        let call_site = ip.saturating_sub(1);
        let Some((name, arity)) = module.function_at(call_site) else {
            continue;
        };
        frames.push(build_frame(
            p,
            &module.name,
            name,
            Term::small(i64::from(arity)).expect("arity is small"),
            module.lines.get(call_site).and_then(Option::as_ref),
            false,
            None,
        )?);
    }
    let mut heap = FragmentingHeap(&mut p.heap);
    TermBuilder::new(&mut heap)
        .list_from_iter(frames)
        .map_err(|e| VmError::Unsupported(format!("stacktrace {e:?}")))
}

pub(super) fn atom_term(name: &str) -> Result<Term, VmError> {
    atom(name)
}
