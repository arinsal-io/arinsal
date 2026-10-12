//! Symbolic stack traces from BEAM continuations.

use crate::{Process, VmError};
use arinsal_alloc::typed::{AllocBlock, ErtsAlcType};
use arinsal_bifs::{Class, FragmentingHeap};
use arinsal_etf::OwnedTerm;
use arinsal_loader::Module;
use arinsal_term::{
    Atom, HeapAlloc, ProcessHeap, Term, TermBuilder, TermKind, from_owned, global_atoms, to_owned,
};
use arinsal_term::{ExportEntry, ExternalBinary, FunEntry, MagicRef, Node, WritableBinary};
use std::sync::{Arc, Mutex, OnceLock};

// Reserve the last encodable handler module index for the empty-trace markers.
const RAW_TRACE_PREFIX: u64 = (1 << 26) - 1;
const CONTINUATION_BIT: u64 = 1 << 57;

fn interpreted_catch_ids() -> &'static Mutex<std::collections::HashMap<(usize, usize), u32>> {
    static IDS: OnceLock<Mutex<std::collections::HashMap<(usize, usize), u32>>> = OnceLock::new();
    IDS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

/// Allocator for stack trace terms.
///
/// Port of erts/emulator/beam/beam_common.c:1205 (build_stacktrace), OTP-29.1.1: the
/// whole trace is sized first and allocated as one block (`HAlloc`, falling back to a
/// single heap fragment), instead of one heap fragment per term.
struct TraceHeap<'a> {
    heap: &'a mut ProcessHeap,
    block: *mut u64,
    capacity: usize,
    used: usize,
    /// Heap top right after the block when it was taken from the young heap.
    block_end: Option<usize>,
}

impl<'a> TraceHeap<'a> {
    fn new(heap: &'a mut ProcessHeap) -> Self {
        Self {
            heap,
            block: std::ptr::null_mut(),
            capacity: 0,
            used: 0,
            block_end: None,
        }
    }

    /// Reserves one block that later allocations are carved from.
    fn with_block(heap: &'a mut ProcessHeap, words: usize) -> Self {
        let mut trace = Self::new(heap);
        trace.capacity = words;
        if let Some(block) = HeapAlloc::alloc(trace.heap, words) {
            trace.block = block;
            // A detached heap hands out blocks outside the young heap; there is no top to trim.
            trace.block_end = (!trace.heap.is_detached()).then(|| trace.heap.used_words());
        } else {
            trace.block = trace.heap.gc_fragment(words);
        }
        trace
    }
}

impl Drop for TraceHeap<'_> {
    fn drop(&mut self) {
        // Give the unused tail of the block back when nothing was allocated after it.
        if let Some(end) = self.block_end
            && self.heap.used_words() == end
        {
            self.heap.set_heap_top(self.block.wrapping_add(self.used));
        }
    }
}

impl HeapAlloc for TraceHeap<'_> {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        if words <= self.capacity - self.used {
            let ptr = self.block.wrapping_add(self.used);
            self.used += words;
            return Some(ptr);
        }
        HeapAlloc::alloc(self.heap, words).or_else(|| Some(self.heap.gc_fragment(words)))
    }

    fn retain_binary(&mut self, binary: Arc<arinsal_term::RefcBinary>) {
        HeapAlloc::retain_binary(self.heap, binary);
    }

    fn retain_writable_binary(
        &mut self,
        binary: Arc<WritableBinary>,
    ) -> Result<(), arinsal_term::TermError> {
        HeapAlloc::retain_writable_binary(self.heap, binary)
    }

    fn supports_writable_binary(&self) -> bool {
        true
    }

    fn retain_external_binary(
        &mut self,
        binary: Arc<ExternalBinary>,
    ) -> Result<(), arinsal_term::TermError> {
        HeapAlloc::retain_external_binary(self.heap, binary)
    }

    fn supports_external_binary(&self) -> bool {
        true
    }

    fn retain_node(&mut self, node: Arc<Node>) {
        HeapAlloc::retain_node(self.heap, node);
    }

    fn retain_fun(&mut self, entry: Arc<FunEntry>) {
        HeapAlloc::retain_fun(self.heap, entry);
    }

    fn retain_export(&mut self, entry: Arc<ExportEntry>) {
        HeapAlloc::retain_export(self.heap, entry);
    }

    fn retain_magic(&mut self, owner: Arc<MagicRef>) {
        HeapAlloc::retain_magic(self.heap, owner);
    }

    fn supports_magic(&self) -> bool {
        true
    }
}

/// Continuation addresses saved before exception unwinding.
#[derive(Default)]
pub(super) struct RawTrace {
    class: Option<Class>,
    explicit: Option<OwnedTerm>,
    top: Option<StoredTopFrame>,
    module: Option<Arc<Module>>,
    /// Module-table index when `module` was not cloned (heap-resident raw trace).
    module_index: Option<usize>,
    /// Module name atom id, so a heap trace can be resolved without the original index.
    module_name: Option<Atom>,
    /// Slot in `ProcessCold::trace_keep.explicit` after the trace is heap-resident.
    explicit_slot: Option<usize>,
    /// Slot in `ProcessCold::trace_keep.tops` after the trace is heap-resident.
    top_slot: Option<usize>,
    /// Parallel to `continuations`: the module of each indexed frame, interned at `store`.
    frame_modules: Vec<Option<Arc<Module>>>,
    ip: usize,
    /// Native function and pc that raised the exception, when it came from native code.
    native_top: Option<usize>,
    continuations: Vec<Continuation>,
    frames: Vec<Term>,
    depth: usize,
    /// `module_index` and indexed continuations name the active code table.
    /// A raw `save_stacktrace` sets this and does not resolve frames.
    code_table: bool,
}

enum Continuation {
    Native(usize),
    /// Module-table index and instruction pointer, used by a heap-resident raw trace.
    Indexed(usize, usize),
}

#[derive(Clone, Debug)]
pub(super) enum BifArgs {
    Inline {
        values: [Term; 4],
        len: u8,
    },
    /// Shared so a rebuilt trace never deep-clones a deeply nested argument.
    Owned(Arc<OwnedTerm>),
}

impl BifArgs {
    pub(super) fn from_terms(args: &[Term]) -> Result<Self, VmError> {
        if args.len() <= 4 {
            let mut values = [Term::NIL; 4];
            values[..args.len()].copy_from_slice(args);
            return Ok(Self::Inline {
                values,
                len: args.len() as u8,
            });
        }
        let elems = args
            .iter()
            .map(|term| {
                to_owned(*term)
                    .map_err(|error| VmError::Unsupported(format!("exception arg {error:?}")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::Owned(Arc::new(OwnedTerm::List {
            elems,
            tail: Box::new(OwnedTerm::Nil),
        })))
    }

    /// Copy for storage in a saved trace: the payload is invisible to GC, so inline
    /// heap pointers are turned into an owned copy; immediates cannot dangle.
    fn detached(&self) -> Result<Self, VmError> {
        match self {
            Self::Inline { values, len }
                if values[..usize::from(*len)].iter().any(|t| t.is_pointer()) =>
            {
                let elems = values[..usize::from(*len)]
                    .iter()
                    .map(|term| {
                        to_owned(*term).map_err(|error| {
                            VmError::Unsupported(format!("exception arg {error:?}"))
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Self::Owned(Arc::new(OwnedTerm::List {
                    elems,
                    tail: Box::new(OwnedTerm::Nil),
                })))
            }
            other => Ok(other.clone()),
        }
    }

    pub(super) fn root_terms(&self, roots: &mut Vec<Term>) -> Option<(usize, usize)> {
        let Self::Inline { values, len } = self else {
            return None;
        };
        let start = roots.len();
        roots.extend_from_slice(&values[..usize::from(*len)]);
        Some((start, usize::from(*len)))
    }

    pub(super) fn update_root_terms(&mut self, roots: &[Term], start: usize, len: usize) {
        if let Self::Inline { values, .. } = self {
            values[..len].copy_from_slice(&roots[start..start + len]);
        }
    }

    fn to_term(&self, heap: &mut TraceHeap) -> Result<Term, VmError> {
        match self {
            Self::Inline { values, len } => TermBuilder::new(heap)
                .list_from_slice(&values[..usize::from(*len)])
                .map_err(|error| VmError::Unsupported(format!("exception args {error:?}"))),
            Self::Owned(args) => from_owned(args, heap)
                .map_err(|error| VmError::Unsupported(format!("exception args {error:?}"))),
        }
    }
}

#[derive(Clone)]
enum StoredTopFrame {
    Bif {
        module: Atom,
        function: Atom,
        args: BifArgs,
        info: BifErrorInfo,
    },
    CurrentArgs(OwnedTerm),
    CurrentArgsWithInfo(Option<OwnedTerm>, Box<OwnedTerm>),
}

/// Where the exception was raised: erts' `s->pc` (save_stacktrace's `pc`).
pub(super) struct Current {
    /// Last interpreter module and instruction.
    pub(super) module: usize,
    pub(super) ip: usize,
    /// Raising pc inside native code, when the process was executing there.
    pub(super) native_pc: Option<usize>,
}

/// Port of erts/emulator/beam/beam_common.c:781 (gather_stacktrace), OTP-29.1.1.
pub(super) fn capture(
    raw: &mut RawTrace,
    class: Option<Class>,
    top: Option<&TopFrame>,
    modules: &[Arc<Module>],
    current: Current,
    heap: &ProcessHeap,
    depth: usize,
) -> Result<(), VmError> {
    // Port of beam_common.c:600-614 (`erts_inspect_frame`) and beam_common.h:301-315,
    // OTP-29.1.1: continuations are raw CP words resolved back to code metadata.
    let Current {
        module,
        ip,
        native_pc,
    } = current;
    raw.class = class;
    raw.explicit = None;
    raw.top = top
        .map(|top| match top {
            TopFrame::Bif {
                module,
                function,
                args,
                info,
            } => Ok(StoredTopFrame::Bif {
                module: *module,
                function: *function,
                args: args.detached()?,
                info: *info,
            }),
            TopFrame::CurrentArgs(args) => Ok(StoredTopFrame::CurrentArgs(
                to_owned(*args)
                    .map_err(|e| VmError::Unsupported(format!("exception args {e:?}")))?,
            )),
            TopFrame::CurrentArgsWithInfo(args, info) => Ok(StoredTopFrame::CurrentArgsWithInfo(
                args.map(|args| {
                    to_owned(args)
                        .map_err(|e| VmError::Unsupported(format!("exception args {e:?}")))
                })
                .transpose()?,
                info.clone(),
            )),
        })
        .transpose()?;
    raw.module_index = Some(module);
    raw.module = modules.get(module).cloned();
    raw.module_name = raw.module.as_ref().map(|module| module.name_atom);
    raw.ip = ip;
    raw.depth = depth.max(1);
    raw.continuations.clear();
    raw.frame_modules.clear();
    raw.continuations.reserve(raw.depth.min(16));
    raw.native_top = None;
    // OTP starts with the failing instruction as `prev` and compares it with
    // each continuation after moving that continuation back to its call site.
    let mut previous = Some((module, ip));
    // Native return addresses share erts' single `prev`, so the two trackers reset each other.
    let mut previous_native: Option<usize> = None;
    if let Some(pc) = native_pc {
        let tag = arinsal_beamasm::module::RETURN_SITE_TAG;
        if pc & tag != 0 {
            // Port of erts/emulator/beam/beam_common.c:791-835 (gather_stacktrace), OTP-29.1.1:
            // the raising pc is the call's return address and seeds `prev`, so the identical
            // continuation is skipped before it can take a `max_depth` slot; the pc's line is
            // looked up inside the call instruction.
            let address = pc & !tag;
            raw.native_top = Some(address - 1);
            previous_native = Some(address);
            previous = None;
        } else {
            raw.native_top = Some(pc);
        }
    }
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
            // Port of erts/emulator/beam/beam_common.c:803-815 (save_stacktrace), OTP-29.1.1:
            // trace frames are skipped; the caller's own continuation follows the frame.
            let action_count = heap
                .stack_get(index + 3)
                .and_then(Term::as_small)
                .and_then(|count| usize::try_from(count).ok())
                .unwrap_or(0);
            index += 4usize.saturating_add(action_count.saturating_mul(2));
            continue;
        }
        if raw_address == arinsal_beamasm::rt::arinsal_enter_native_return as *const () as usize {
            // The interpreter-to-native bridge CP sits in the native callee's CP slot while the
            // caller's real continuation lies beneath it; erts has only that one CP, so the
            // bridge word is not a frame of its own (beam_common.c:803-840, OTP-29.1.1).
            // Recording it would use up a `max_depth` slot that `build_saved` then drops.
            index += 1;
            continue;
        }
        if raw_address & 3 == 0 && arinsal_term::may_be_native_code_pointer(raw_address) {
            // Port of erts/emulator/beam/beam_common.c:815-835 (save_stacktrace), OTP-29.1.1:
            // only non-duplicate return addresses are recorded, each looked up one byte back,
            // inside its call instruction. Like erts' is_CP test this only checks the word's
            // shape (plus the lock-free native hull); the function is looked up in `build`.
            if previous_native != Some(raw_address) {
                previous_native = Some(raw_address);
                previous = None;
                push_frame(raw, Continuation::Native(raw_address - 1), None);
            }
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
            index += if ip == code.return_trace_ip { 6 } else { 2 };
            continue;
        }
        let call_site = ip.saturating_sub(1);
        if handler || previous == Some((module, call_site)) {
            index += 1;
            continue;
        }
        previous = Some((module, call_site));
        previous_native = None;
        if let Some(code) = modules.get(module) {
            push_frame(
                raw,
                Continuation::Indexed(module, ip),
                Some(Arc::clone(code)),
            );
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
    raw.frame_modules.clear();
    Ok(())
}

fn push_frame(raw: &mut RawTrace, continuation: Continuation, module: Option<Arc<Module>>) {
    raw.continuations.push(continuation);
    raw.frame_modules.push(module);
}

/// Off-heap pieces a heap bignum cannot hold: module `Arc`s (GC does not scan
/// bignum digits) plus an explicit `raise/3` trace and a BIF argument frame.
#[derive(Default)]
pub(crate) struct TraceKeep {
    modules: Vec<Arc<Module>>,
    explicit: Vec<OwnedTerm>,
    tops: Vec<StoredTopFrame>,
}

fn intern_module(p: &mut Process, module: &Arc<Module>) -> Option<u64> {
    let keep = p
        .cold_mut()
        .trace_keep
        .get_or_insert_with(|| Box::new(TraceKeep::default()));
    if let Some(index) = keep
        .modules
        .iter()
        .position(|found| Arc::ptr_eq(found, module))
    {
        return u64::try_from(index).ok();
    }
    let index = u64::try_from(keep.modules.len()).ok()?;
    keep.modules.push(Arc::clone(module));
    Some(index)
}

fn slot_word(word: u64) -> Option<usize> {
    if word == RAW_TRACE_NONE {
        None
    } else {
        usize::try_from(word).ok()
    }
}

/// Saved trace stored in a process-heap magic reference.
///
/// Port of erts/emulator/beam/beam_common.c:880 (save_stacktrace), OTP-29.1.1: erts keeps
/// `struct StackTrace` in an opaque heap object, so GC copies and reclaims it with the process.
pub(super) struct SavedTrace(Mutex<RawTrace>);

/// BIF frame recorded by a caught native failure, matched against `freason`/`fvalue`
/// so a later exception does not reuse it.
#[derive(Clone)]
pub(crate) struct PendingTop {
    freason: u64,
    fvalue: u64,
    top: StoredTopFrame,
}

/// Drop a BIF frame that belonged to an exception this process has finished with.
pub(crate) fn clear_pending_top(p: &mut Process) {
    if let Some(cold) = p.cold.as_mut() {
        cold.pending_trace_top = None;
    }
}

/// Port of erts/emulator/beam/beam_common.c:899-925 (`save_stacktrace`), OTP-29.1.1:
/// a failing BIF other than `error/1,2,3`, `exit/1` and `throw/1` is `s->current`.
/// `error/1` and friends leave the frame to the Erlang caller (`c_p->current`).
pub(crate) fn note_caught_bif_frame(
    p: &mut Process,
    module: &str,
    function: &str,
    args: &[Term],
    error: &arinsal_bifs::BifError,
) {
    let info = match error {
        // `error/2,3` is the caller's frame, with the option list's `error_info`
        // map (beam_common.c:909-925). `exit/1` and `throw/1` keep the caller too,
        // and have no map.
        arinsal_bifs::BifError::Raise { .. } => {
            if module == "erlang" && function == "error" && args.len() > 1 {
                let args_term = arinsal_term::to_owned(args[1]).ok();
                let top = match args.get(2).and_then(crate::exceptions::error_info_option) {
                    Some(info) => StoredTopFrame::CurrentArgsWithInfo(args_term, Box::new(info)),
                    None => {
                        let Some(args_term) = args_term else {
                            return;
                        };
                        StoredTopFrame::CurrentArgs(args_term)
                    }
                };
                let freason = p.header.freason;
                let fvalue = p.header.fvalue;
                p.cold_mut().pending_trace_top = Some(PendingTop {
                    freason,
                    fvalue,
                    top,
                });
            }
            return;
        }
        arinsal_bifs::BifError::Unsupported(_) | arinsal_bifs::BifError::Dirty(_) => return,
        arinsal_bifs::BifError::Badarg { cause: Some(cause) } => cause
            .as_atom()
            .map_or(BifErrorInfo::Plain, BifErrorInfo::Cause),
        _ => BifErrorInfo::Plain,
    };
    let Some(top) = bif_pending_top(module, function, args, info) else {
        return;
    };
    let freason = p.header.freason;
    let fvalue = p.header.fvalue;
    p.cold_mut().pending_trace_top = Some(PendingTop {
        freason,
        fvalue,
        top,
    });
}

fn bif_pending_top(
    module: &str,
    function: &str,
    args: &[Term],
    info: BifErrorInfo,
) -> Option<StoredTopFrame> {
    let module = global_atoms().intern(module).ok()?;
    let function = global_atoms().intern(function).ok()?;
    let args = BifArgs::from_terms(args).ok()?;
    Some(StoredTopFrame::Bif {
        module,
        function,
        args,
        info,
    })
}

fn clone_matching_pending(p: &Process) -> Option<StoredTopFrame> {
    let pending = p.cold.as_ref()?.pending_trace_top.as_ref()?;
    (pending.freason == p.header.freason && pending.fvalue == p.header.fvalue)
        .then(|| pending.top.clone())
}

/// Attach a matching BIF frame and consume it. The scheduler rebuilds a trace when
/// the native catch search misses; that rebuild must see the same `s->current`.
pub(crate) fn take_pending_top(p: &mut Process, raw: &mut RawTrace) {
    if raw.top.is_some() {
        return;
    }
    let Some(cold) = p.cold.as_mut() else {
        return;
    };
    let matches = cold.pending_trace_top.as_ref().is_some_and(|pending| {
        pending.freason == p.header.freason && pending.fvalue == p.header.fvalue
    });
    if matches {
        raw.top = cold.pending_trace_top.take().map(|pending| pending.top);
    }
}

/// Raw stacktrace for a caught exception, without building the symbolic list.
///
/// Port of erts/emulator/beam/beam_common.c:505-507 and :880 (`save_stacktrace`),
/// OTP-29.1.1: `handle_error` stores `struct StackTrace` when `EXF_SAVETRACE` is set.
/// `build_stacktrace` turns it into a list only if the handler asks.
///
/// `native_pc` is the raising instruction (erts' `pc`). `backtrace_depth` counts the
/// current frame plus continuations; `save_stacktrace` stores `depth - 1` continuation
/// slots and always keeps the current function (beam_common.c:885).
pub(crate) fn save_lazy(
    p: &mut Process,
    class: Class,
    native_pc: Option<usize>,
) -> Result<Term, VmError> {
    let depth = p.runtime.as_ref().map_or(8, |runtime| {
        runtime
            .backtrace_depth
            .load(std::sync::atomic::Ordering::Acquire)
    });
    // Port of erts/emulator/beam/beam_common.c:880-893 (`save_stacktrace`), OTP-29.1.1:
    // one HAlloc of the raw `StackTrace` (pc, current, depth, trace[] of CP words).
    // Frames are resolved in `build_stacktrace`, not here.
    let depth = depth.max(1);
    let class_digit = match class {
        Class::Error => 1,
        Class::Exit => 2,
        Class::Throw => 3,
    };
    let module_digit = u64::try_from(p.module).unwrap_or(RAW_TRACE_NONE);
    let ip_digit = u64::try_from(p.ip).unwrap_or(0);
    let (native_top, previous_native, previous) = match native_pc {
        Some(pc) if pc & arinsal_beamasm::module::RETURN_SITE_TAG != 0 => {
            let address = pc & !arinsal_beamasm::module::RETURN_SITE_TAG;
            (Some(address.wrapping_sub(1)), Some(address), None)
        }
        Some(pc) => (Some(pc), None, Some((p.module, p.ip))),
        None => (None, None, Some((p.module, p.ip))),
    };
    let pc_digit = native_top
        .and_then(|pc| u64::try_from(pc).ok())
        .unwrap_or(RAW_TRACE_NONE);
    let top_slot = match clone_matching_pending(p) {
        Some(top) => {
            let keep = p
                .cold_mut()
                .trace_keep
                .get_or_insert_with(|| Box::new(TraceKeep::default()));
            let index = u64::try_from(keep.tops.len()).unwrap_or(RAW_TRACE_NONE);
            keep.tops.push(top);
            index
        }
        None => RAW_TRACE_NONE,
    };
    // Port of beam_common.c:884-893 (`save_stacktrace`) and :781 (`gather_stacktrace`),
    // OTP-29.1.1. One HAlloc, then the walk stores `trace[]`. The heap words are not
    // zeroed first. The continuation pcs are staged in a fixed array of `max_depth`
    // slots (default 8, at most 64) and copied once; a per-digit callback was slower
    // than erts' in-place stores, and an uninitialized heap slice is not a `[u64]`.
    // Digit map: [0] magic, [1] freason class, [2] depth, [3..4] current (module, ip),
    // [5] pc, [6] unused (no module-name atom), [7] no explicit slot, [8] pending top,
    // [9] trace count, [10..] trace[].
    let slots = depth.saturating_sub(1).min(64);
    let depth_digit = u64::try_from(depth).unwrap_or(u64::MAX);
    let header = StagedHeader {
        class: class_digit,
        depth: depth_digit,
        module: module_digit,
        ip: ip_digit,
        pc: pc_digit,
        top: top_slot,
    };
    if slots <= 8 {
        let mut raw = [0u64; 18];
        store_staged(p, &mut raw, slots, header, previous_native, previous)
    } else {
        let mut raw = [0u64; 74];
        store_staged(p, &mut raw, slots, header, previous_native, previous)
    }
}

struct StagedHeader {
    class: u64,
    depth: u64,
    module: u64,
    ip: u64,
    pc: u64,
    top: u64,
}

fn store_staged(
    p: &mut Process,
    raw: &mut [u64],
    slots: usize,
    header: StagedHeader,
    previous_native: Option<usize>,
    previous: Option<(usize, usize)>,
) -> Result<Term, VmError> {
    let count = gather_continuations(p, &mut raw[10..10 + slots], previous_native, previous);
    raw[0] = RAW_TRACE_MAGIC;
    raw[1] = header.class;
    raw[2] = header.depth;
    raw[3] = header.module;
    raw[4] = header.ip;
    raw[5] = header.pc;
    raw[7] = RAW_TRACE_NONE;
    raw[8] = header.top;
    raw[9] = u64::try_from(count).unwrap_or(0) | RAW_CODE_TABLE;
    TermBuilder::new(&mut FragmentingHeap(&mut p.heap))
        .pos_bignum_from_digits(&raw[..10 + count])
        .map_err(|error| VmError::Unsupported(format!("raw stacktrace {error:?}")))
}

/// Writes raw CP words the way `gather_stacktrace` does (beam_common.c:781), OTP-29.1.1.
/// One pass from `stop` toward the stack start. A continuation pointer is recorded when
/// it differs from the previous one; every other word is skipped. No code-table lookup.
fn gather_continuations(
    p: &Process,
    pcs: &mut [u64],
    mut previous_native: Option<usize>,
    mut previous: Option<(usize, usize)>,
) -> usize {
    let limit = pcs.len();
    let mut count = 0usize;
    let mut index = 0usize;
    let scanned_limit = p.heap.stack_words();
    let trace_return = crate::native_bridge::native_trace_return_address();
    let bridge = arinsal_beamasm::rt::arinsal_enter_native_return as *const () as usize;
    while index < scanned_limit && count < limit {
        let Some(word) = p.heap.stack_get(index) else {
            index += 1;
            continue;
        };
        let raw_address = word.tagged_word() as usize;
        if raw_address == trace_return {
            let action_count = p
                .heap
                .stack_get(index + 3)
                .and_then(Term::as_small)
                .and_then(|n| usize::try_from(n).ok())
                .unwrap_or(0);
            index += 4usize.saturating_add(action_count.saturating_mul(2));
            continue;
        }
        if raw_address == bridge {
            index += 1;
            continue;
        }
        if raw_address & 3 == 0 && arinsal_term::may_be_native_code_pointer(raw_address) {
            if previous_native != Some(raw_address) {
                previous_native = Some(raw_address);
                previous = None;
                pcs[count] = u64::try_from(raw_address.wrapping_sub(1)).unwrap_or(0);
                count += 1;
            }
            index += 1;
            continue;
        }
        if let Some((module, ip)) = continuation_word(word) {
            if let Some(skip) = interpreter_trace_skip(p, module, ip) {
                index += skip;
                continue;
            }
            let call_site = ip.saturating_sub(1);
            if previous == Some((module, call_site)) {
                index += 1;
                continue;
            }
            previous = Some((module, call_site));
            previous_native = None;
            if let Some(packed) = pack_indexed(module, ip) {
                pcs[count] = packed;
                count += 1;
            }
            index += 1;
            continue;
        }
        index += 1;
    }
    count
}

/// Bit in the continuation-count digit: indexed frames name the code table.
const RAW_CODE_TABLE: u64 = 1 << 32;

/// Interpreter continuation or catch tag carried as a catch immediate.
/// Catch handlers are not frames. No catch-table lookup: a handler index has
/// no continuation bit, and `build_stacktrace` is what resolves a real CP.
fn continuation_word(word: Term) -> Option<(usize, usize)> {
    if word.tagged_word() & 63 != 0x1b || word.classify() != TermKind::Catch {
        return None;
    }
    let payload = word.tagged_word() >> 6;
    if payload >> 32 == RAW_TRACE_PREFIX || payload & CONTINUATION_BIT == 0 {
        return None;
    }
    Some((
        ((payload & !CONTINUATION_BIT) >> 32) as usize,
        payload as u32 as usize,
    ))
}

/// Extra stack words a return-trace frame occupies, when `ip` is one.
fn interpreter_trace_skip(p: &Process, module: usize, ip: usize) -> Option<usize> {
    let tables = p.runtime.as_ref()?.active_code_tables();
    let code = tables.modules.get(module)?;
    if ip == code.return_trace_ip {
        Some(6)
    } else if ip == code.return_to_trace_ip {
        Some(2)
    } else {
        None
    }
}

/// Allocate `raw` as a heap term of `p`.
///
/// Port of erts/emulator/beam/beam_common.c:888-893 (`save_stacktrace`), OTP-29.1.1:
/// the raw trace is a positive bignum on the process heap. `build_stacktrace`
/// turns it into a list only when a handler asks.
pub(super) fn store(p: &mut Process, mut raw: RawTrace) -> Result<Term, VmError> {
    let mut digits = [0u64; 64];
    let len = encode_raw_trace(p, &mut raw, &mut digits)
        .ok_or_else(|| VmError::Unsupported("raw stacktrace does not fit a heap bignum".into()))?;
    TermBuilder::new(&mut FragmentingHeap(&mut p.heap))
        .pos_bignum_from_digits(&digits[..len])
        .map_err(|error| VmError::Unsupported(format!("raw stacktrace {error:?}")))
}

const RAW_TRACE_MAGIC: u64 = 0xA11C_E000_0000_0001;
const RAW_TRACE_NONE: u64 = u64::MAX;

fn encode_raw_trace(p: &mut Process, raw: &mut RawTrace, digits: &mut [u64; 64]) -> Option<usize> {
    let mut len = 10usize;
    digits[0] = RAW_TRACE_MAGIC;
    digits[1] = match raw.class {
        None => 0,
        Some(Class::Error) => 1,
        Some(Class::Exit) => 2,
        Some(Class::Throw) => 3,
    };
    digits[2] = u64::try_from(raw.depth).ok()?;
    digits[3] = raw
        .module
        .as_ref()
        .and_then(|module| intern_module(p, module))
        .unwrap_or(RAW_TRACE_NONE);
    digits[4] = u64::try_from(raw.ip).ok()?;
    digits[5] = raw
        .native_top
        .and_then(|pc| u64::try_from(pc).ok())
        .unwrap_or(RAW_TRACE_NONE);
    digits[6] = raw.module_name.map(|atom| u64::from(atom.0)).unwrap_or(0);
    digits[7] = match raw.explicit.take() {
        Some(term) => {
            let keep = p
                .cold_mut()
                .trace_keep
                .get_or_insert_with(|| Box::new(TraceKeep::default()));
            let index = u64::try_from(keep.explicit.len()).ok()?;
            keep.explicit.push(term);
            index
        }
        None => RAW_TRACE_NONE,
    };
    digits[8] = match raw.top.take() {
        Some(top) => {
            let keep = p
                .cold_mut()
                .trace_keep
                .get_or_insert_with(|| Box::new(TraceKeep::default()));
            let index = u64::try_from(keep.tops.len()).ok()?;
            keep.tops.push(top);
            index
        }
        None => RAW_TRACE_NONE,
    };
    digits[9] = 0;
    for (continuation, module) in raw.continuations.iter().zip(raw.frame_modules.iter()) {
        if len >= digits.len() {
            return None;
        }
        let word = match continuation {
            Continuation::Native(pc) => u64::try_from(*pc).ok()?,
            Continuation::Indexed(_, ip) => {
                let module = module.as_ref()?;
                let slot = intern_module(p, module)?;
                pack_indexed(usize::try_from(slot).ok()?, *ip)?
            }
        };
        digits[len] = word;
        len += 1;
        digits[9] += 1;
    }
    Some(len)
}

fn pack_indexed(module: usize, ip: usize) -> Option<u64> {
    let module = u64::try_from(module).ok()?;
    let ip = u64::try_from(ip).ok()?;
    if module >= 1 << 31 || ip >= 1 << 32 {
        return None;
    }
    Some((1 << 63) | (module << 32) | ip)
}

fn class_from_digit(value: u64) -> Option<Class> {
    match value {
        1 => Some(Class::Error),
        2 => Some(Class::Exit),
        3 => Some(Class::Throw),
        _ => None,
    }
}

fn raw_from_digits(digits: &[u64]) -> Option<RawTrace> {
    if digits.first().copied() != Some(RAW_TRACE_MAGIC) || digits.len() < 10 {
        return None;
    }
    let code_table = digits[9] & RAW_CODE_TABLE != 0;
    let count = usize::try_from(digits[9] & !RAW_CODE_TABLE).ok()?;
    if digits.len() < 10 + count {
        return None;
    }
    let mut continuations = Vec::with_capacity(count);
    for word in &digits[10..10 + count] {
        if word & (1 << 63) != 0 {
            let payload = word & !(1 << 63);
            continuations.push(Continuation::Indexed(
                (payload >> 32) as usize,
                payload as u32 as usize,
            ));
        } else {
            continuations.push(Continuation::Native(usize::try_from(*word).ok()?));
        }
    }
    let module_index = if digits[3] == RAW_TRACE_NONE {
        None
    } else {
        Some(usize::try_from(digits[3]).ok()?)
    };
    let native_top = if digits[5] == RAW_TRACE_NONE {
        None
    } else {
        Some(usize::try_from(digits[5]).ok()?)
    };
    Some(RawTrace {
        class: class_from_digit(digits[1]),
        module_index,
        module_name: (digits[6] != 0).then_some(Atom(digits[6] as u32)),
        explicit_slot: slot_word(digits[7]),
        top_slot: slot_word(digits[8]),
        ip: usize::try_from(digits[4]).ok()?,
        native_top,
        continuations,
        depth: usize::try_from(digits[2]).ok()?,
        code_table,
        ..RawTrace::default()
    })
}

/// Run `f` on the saved trace behind `term`, or return `None` when it is not one.
pub(super) fn with_saved<R>(term: Term, f: impl FnOnce(&mut RawTrace) -> R) -> Option<R> {
    if let Some(mut raw) = term
        .with_bignum_digits_mut(|digits| raw_from_digits(digits))
        .flatten()
    {
        return Some(f(&mut raw));
    }
    // SAFETY: the term is reachable from a live process register or stack, so its heap
    // and the retained owner stay valid for this call; nothing below collects.
    let saved = unsafe { term.magic_ref() }?.downcast_ref::<SavedTrace>()?;
    let mut raw = saved.0.lock().unwrap_or_else(|e| e.into_inner());
    Some(f(&mut raw))
}

/// True when `term` is a saved raw trace.
pub(super) fn is_saved(term: Term) -> bool {
    with_saved(term, |_| ()).is_some()
}

/// Exception class saved with a raw trace for a later `raise` instruction.
pub(super) fn raw_class(_p: &Process, term: Term) -> Option<Class> {
    with_saved(term, |raw| raw.class).flatten()
}

/// Port of erts/emulator/beam/beam_common.c:1148-1178 (raw_raise).
pub(super) fn set_raw_class(_p: &mut Process, term: Term, class: Class) -> bool {
    let code = match class {
        Class::Error => 1,
        Class::Exit => 2,
        Class::Throw => 3,
    };
    if term
        .with_bignum_digits_mut(|digits| {
            if digits.first().copied() == Some(RAW_TRACE_MAGIC) && digits.len() >= 2 {
                digits[1] = code;
                true
            } else {
                false
            }
        })
        .unwrap_or(false)
    {
        return true;
    }
    with_saved(term, |raw| raw.class = Some(class)).is_some()
}

/// What `save_stacktrace` puts in a BIF frame's `error_info`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BifErrorInfo {
    /// Not a BIF failure (`undef`): no `error_info`.
    None,
    /// `#{module => FormatModule}`.
    Plain,
    /// `EXF_HAS_EXT_INFO`: `#{cause => c_p->fvalue, module => FormatModule}`.
    Cause(Atom),
}

#[derive(Debug)]
pub(super) enum TopFrame {
    /// A failing BIF, or the MFA of an `undef` call.
    Bif {
        module: Atom,
        function: Atom,
        args: BifArgs,
        info: BifErrorInfo,
    },
    CurrentArgs(Term),
    CurrentArgsWithInfo(Option<Term>, Box<OwnedTerm>),
}

pub(super) fn handler_tag(module: usize, ip: usize) -> Result<Term, VmError> {
    // Per-thread cache in front of the shared table: erts keeps the handler's code pointer in
    // the stack slot, so `catch` must not take a lock or hash with SipHash.
    thread_local! {
        static CACHE: std::cell::RefCell<std::collections::HashMap<(usize, usize), u32, CodeKeyHasher>> =
            std::cell::RefCell::new(std::collections::HashMap::default());
    }
    let key = (module, ip);
    if let Some(index) = CACHE.with(|cache| cache.borrow().get(&key).copied()) {
        return Ok(Term::catch(u64::from(index)));
    }
    let index = handler_tag_shared(key)?;
    CACHE.with(|cache| cache.borrow_mut().insert(key, index));
    Ok(Term::catch(u64::from(index)))
}

/// Multiplicative hasher for `(module, ip)` keys; they are small dense integers.
#[derive(Default)]
struct CodeKeyHasher(u64);

impl std::hash::Hasher for CodeKeyHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.write_u64(u64::from(*byte));
        }
    }
    fn write_usize(&mut self, value: usize) {
        self.write_u64(value as u64);
    }
    fn write_u64(&mut self, value: u64) {
        self.0 = (self.0.rotate_left(5) ^ value).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }
}

impl std::hash::BuildHasher for CodeKeyHasher {
    type Hasher = CodeKeyHasher;
    fn build_hasher(&self) -> CodeKeyHasher {
        CodeKeyHasher(0)
    }
}

fn handler_tag_shared(key: (usize, usize)) -> Result<u32, VmError> {
    let (module, ip) = key;
    let mut ids = interpreted_catch_ids()
        .lock()
        .map_err(|_| VmError::Unsupported("catch table lock".into()))?;
    let index = if let Some(index) = ids.get(&key) {
        *index
    } else {
        let base = arinsal_beamasm::catch::reserve_catch_indices(1)
            .map_err(|_| VmError::Unsupported("catch table exhausted".into()))?;
        crate::native_bridge::register_interpreted_catch(
            crate::fun_dispatch::code_scope(),
            base,
            module,
            ip,
        );
        ids.insert(key, base);
        base
    };
    Ok(index)
}

/// Encodes an interpreter continuation without colliding with catch-table indices.
pub(crate) fn continuation_tag(module: usize, ip: usize) -> Result<Term, VmError> {
    let module = u64::try_from(module).map_err(|_| VmError::Unsupported("module index".into()))?;
    let ip = u32::try_from(ip).map_err(|_| VmError::Unsupported("code index".into()))?;
    if module >= (1 << 25) {
        return Err(VmError::Unsupported("module index".into()));
    }
    Ok(Term::catch(CONTINUATION_BIT | module << 32 | u64::from(ip)))
}

/// Handler address of a stack word that is a catch tag of native code.
pub(crate) fn native_catch_address(term: Term) -> Option<usize> {
    if term.tagged_word() & 63 != 0x1b || term.classify() != TermKind::Catch {
        return None;
    }
    // SAFETY: CATCH is an immediate and carries no heap pointer.
    let payload = unsafe { term.raw_bits() } >> 6;
    if payload >> 32 != 0 || payload & CONTINUATION_BIT != 0 {
        return None;
    }
    crate::native_bridge::native_catch(
        crate::fun_dispatch::code_scope(),
        u32::try_from(payload).ok()?,
    )
}

pub(super) fn decode_tag(term: Term) -> Option<(bool, usize, usize)> {
    if term.tagged_word() & 63 != 0x1b || term.classify() != TermKind::Catch {
        return None;
    }
    // SAFETY: CATCH is an immediate and carries no heap pointer.
    let payload = unsafe { term.raw_bits() } >> 6;
    if payload >> 32 == RAW_TRACE_PREFIX {
        // Empty-trace marker, not a continuation.
        return None;
    }
    // Interpreter continuations use an immediate module/IP pair. Catch tags
    // themselves are process-independent indices into the shared catch table.
    if payload & CONTINUATION_BIT != 0 {
        return Some((
            false,
            ((payload & !CONTINUATION_BIT) >> 32) as usize,
            payload as u32 as usize,
        ));
    }
    if payload >> 32 != 0 {
        return Some((false, (payload >> 32) as usize, payload as u32 as usize));
    }
    let index = u32::try_from(payload).ok()?;
    let (module, ip) =
        crate::native_bridge::interpreted_catch(crate::fun_dispatch::code_scope(), index)?;
    Some((true, module, ip))
}

fn atom(name: &str) -> Result<Term, VmError> {
    global_atoms()
        .intern(name)
        .map(Term::atom)
        .map_err(|_| VmError::Unsupported(format!("atom {name}")))
}

struct TraceAtoms {
    file: Atom,
    line: Atom,
    module: Atom,
    cause: Atom,
    /// BIF module to `format_error` module, as in beam_common.c:937-990.
    format_modules: [(Atom, Atom); 14],
    error_info: Atom,
    unknown: Atom,
}

fn trace_atoms() -> &'static TraceAtoms {
    static ATOMS: OnceLock<TraceAtoms> = OnceLock::new();
    ATOMS.get_or_init(|| {
        let table = global_atoms();
        let intern = |name| table.intern(name).expect("stacktrace atom is valid");
        TraceAtoms {
            file: intern("file"),
            line: intern("line"),
            module: intern("module"),
            cause: intern("cause"),
            format_modules: [
                ("atomics", "erl_erts_errors"),
                ("counters", "erl_erts_errors"),
                ("erlang", "erl_erts_errors"),
                ("erts_internal", "erl_erts_errors"),
                ("persistent_term", "erl_erts_errors"),
                ("code", "erl_kernel_errors"),
                ("os", "erl_kernel_errors"),
                ("binary", "erl_stdlib_errors"),
                ("ets", "erl_stdlib_errors"),
                ("lists", "erl_stdlib_errors"),
                ("maps", "erl_stdlib_errors"),
                ("math", "erl_stdlib_errors"),
                ("re", "erl_stdlib_errors"),
                ("unicode", "erl_stdlib_errors"),
            ]
            .map(|(bif, format)| (intern(bif), intern(format))),
            error_info: intern("error_info"),
            unknown: intern("?"),
        }
    })
}

/// The `error_info` map of a failing BIF frame.
// Port of erts/emulator/beam/beam_common.c:932-998 (save_stacktrace), OTP-29.1.1.
fn bif_error_info(
    heap: &mut TraceHeap,
    module: Atom,
    info: BifErrorInfo,
) -> Result<Option<Term>, VmError> {
    let cause = match info {
        BifErrorInfo::None => return Ok(None),
        BifErrorInfo::Plain => None,
        BifErrorInfo::Cause(cause) => Some(cause),
    };
    let atoms = trace_atoms();
    let Some(&(_, format_module)) = atoms.format_modules.iter().find(|(bif, _)| *bif == module)
    else {
        return Ok(None);
    };
    let module_pair = (Term::atom(atoms.module), Term::atom(format_module));
    let mut builder = TermBuilder::new(heap);
    let map = match cause {
        Some(cause) => {
            builder.flatmap_from_pairs(&[(Term::atom(atoms.cause), Term::atom(cause)), module_pair])
        }
        None => builder.flatmap_from_pairs(&[module_pair]),
    }
    .map_err(|e| VmError::Unsupported(format!("BIF error info {e:?}")))?;
    Ok(Some(map))
}

fn literal_location(
    frame: &crate::native_bridge::NativeStackFrame,
    current: &Module,
) -> Option<(Term, u64)> {
    let line = frame.line?;
    let file = frame.file_term.or_else(|| {
        frame
            .file
            .as_deref()
            .and_then(|file| current.line_file_terms.get(file).copied())
    })?;
    Some((file, u64::from(line)))
}

fn build_frame(
    heap: &mut TraceHeap,
    module: Atom,
    function: Atom,
    arity_or_args: Term,
    location: Option<(Term, u64)>,
    bif: bool,
    error_info: Option<Term>,
) -> Result<Term, VmError> {
    let module = Term::atom(module);
    let function = Term::atom(function);
    let file = Term::atom(trace_atoms().file);
    let line = Term::atom(trace_atoms().line);
    let mut builder = TermBuilder::new(heap);
    let mut info = [Term::NIL; 3];
    let mut info_len = 0;
    if bif && let Some(error_info) = error_info {
        info[info_len] = builder
            .tuple(&[Term::atom(trace_atoms().error_info), error_info])
            .map_err(|e| VmError::Unsupported(format!("error info tuple {e:?}")))?;
        info_len += 1;
    }
    if !bif && let Some((name, number)) = location {
        let number = Term::small(number as i64)
            .ok_or_else(|| VmError::Unsupported("source line number".into()))?;
        info[info_len] = builder
            .tuple(&[file, name])
            .map_err(|e| VmError::Unsupported(format!("stack file {e:?}")))?;
        info_len += 1;
        info[info_len] = builder
            .tuple(&[line, number])
            .map_err(|e| VmError::Unsupported(format!("stack line {e:?}")))?;
        info_len += 1;
    }
    if !bif && let Some(error_info) = error_info {
        info[info_len] = builder
            .tuple(&[Term::atom(trace_atoms().error_info), error_info])
            .map_err(|e| VmError::Unsupported(format!("error info tuple {e:?}")))?;
        info_len += 1;
    }
    let location = builder
        .list_from_slice(&info[..info_len])
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
    // A process inside a native BIF call raises at that call's pc, as in `exceptions.rs`.
    let native_pc = p.cold.as_ref().map_or(0, |cold| cold.native_call_pc);
    let native_pc = if native_pc != 0 && crate::native_bridge::is_native_function_at(native_pc) {
        Some(native_pc)
    } else {
        // A process suspended inside native code: `p.module`/`p.ip` still hold the last
        // interpreter position, so the current function comes from its native resume pc.
        p.native_pc
            .or_else(|| Some(p.header.i as usize).filter(|&pc| pc != 0))
            .filter(|&pc| crate::native_bridge::is_native_function_at(pc))
    };
    let mut raw = RawTrace::default();
    capture(
        &mut raw,
        None,
        top,
        modules,
        Current {
            module: p.module,
            ip: p.ip,
            native_pc,
        },
        &p.heap,
        depth,
    )?;
    build_saved(p, &mut raw)
}

/// Port of erts/emulator/beam/beam_common.c:1205 (build_stacktrace), OTP-29.1.1.
/// One looked-up MFA frame. Five term words plus a location flag, the fields
/// `erts_build_mfa_item` reads off `FunctionInfo`.
const FRAME_INFO_WORDS: usize = 6;

struct PreparedFrames {
    block: AllocBlock,
    frames: usize,
    words: usize,
}

enum FramePrep {
    /// BIF tops, explicit traces, and interpreter module tables still use `build_saved`.
    Fallback,
    Ready(PreparedFrames),
}

/// Port of beam_common.c:1205 (`build_stacktrace`), OTP-29.1.1.
///
/// Lookups land in one `ERTS_ALC_T_TMP` array. The symbolic list is one `HAlloc`.
/// `None` means this term is not a plain raw trace.
pub(super) fn build_direct(p: &mut Process, term: Term) -> Option<Result<Term, VmError>> {
    let ranges = p.runtime.as_ref().map(|runtime| runtime.code_ranges());
    let tables = p
        .runtime
        .as_ref()
        .map(|runtime| runtime.active_code_tables());
    let prepared = term.with_bignum_digits_mut(|digits| {
        prepare_frames(
            digits,
            ranges.as_deref().map(|ranges| ranges.as_slice()),
            tables.as_ref(),
        )
    })?;
    match prepared {
        Ok(FramePrep::Fallback) => None,
        Ok(FramePrep::Ready(ready)) => Some(cons_prepared(p, ready)),
        Err(error) => Some(Err(error)),
    }
}

fn prepare_frames(
    digits: &[u64],
    ranges: Option<&[crate::native_bridge::ModuleRange]>,
    tables: Option<&std::sync::Arc<crate::load::CodeTables>>,
) -> Result<FramePrep, VmError> {
    if digits.first().copied() != Some(RAW_TRACE_MAGIC) || digits.len() < 10 {
        return Ok(FramePrep::Fallback);
    }
    if digits[7] != RAW_TRACE_NONE || digits[8] != RAW_TRACE_NONE {
        return Ok(FramePrep::Fallback);
    }
    let code_table = digits[9] & RAW_CODE_TABLE != 0;
    let count = usize::try_from(digits[9] & !RAW_CODE_TABLE).unwrap_or(usize::MAX);
    if digits.len() < 10 + count {
        return Ok(FramePrep::Fallback);
    }
    if !code_table
        && digits[10..10 + count]
            .iter()
            .any(|word| word & (1 << 63) != 0)
    {
        return Ok(FramePrep::Fallback);
    }
    let depth = usize::try_from(digits[2]).unwrap_or(0).max(1);
    let native_top = (digits[5] != RAW_TRACE_NONE).then(|| usize::try_from(digits[5]).ok());
    let Some(native_top) = native_top else {
        return Ok(FramePrep::Fallback);
    };
    let native_top = native_top.ok_or_else(|| VmError::Unsupported("stacktrace pc".into()))?;
    let current = digits[3]
        .ne(&RAW_TRACE_NONE)
        .then(|| usize::try_from(digits[3]).ok())
        .flatten()
        .and_then(|index| tables?.modules.get(index).map(std::convert::AsRef::as_ref));
    let mut frames = 0usize;
    let mut words = 0usize;
    let capacity = (1 + count).min(depth);
    let mut block = AllocBlock::new(ErtsAlcType::TMP, capacity * FRAME_INFO_WORDS)
        .map_err(|error| VmError::Unsupported(format!("stacktrace temp {error:?}")))?;
    let slots = block.as_mut_slice();
    if let Some(resolved) = crate::native_bridge::stack_frame_in(ranges, native_top) {
        let location = resolved.line.and_then(|line| {
            resolved
                .file_term
                .or_else(|| {
                    resolved.file.as_deref().and_then(|file| {
                        current.and_then(|module| module.line_file_terms.get(file).copied())
                    })
                })
                .map(|file| (file, u64::from(line)))
        });
        let located = location.is_some();
        write_frame(
            slots,
            frames,
            Term::atom(resolved.module_atom),
            Term::atom(resolved.function_atom),
            Term::small(i64::from(resolved.arity)).expect("arity is small"),
            location,
        );
        words += if located { 17 } else { 7 };
        frames += 1;
    }
    for word in &digits[10..10 + count] {
        if frames >= depth {
            break;
        }
        if word & (1 << 63) == 0 {
            let Some(address) = usize::try_from(*word).ok() else {
                continue;
            };
            let Some(resolved) = crate::native_bridge::stack_frame_in(ranges, address) else {
                continue;
            };
            let location = resolved.line.and_then(|line| {
                resolved
                    .file_term
                    .or_else(|| {
                        resolved.file.as_deref().and_then(|file| {
                            current.and_then(|module| module.line_file_terms.get(file).copied())
                        })
                    })
                    .map(|file| (file, u64::from(line)))
            });
            let located = location.is_some();
            write_frame(
                slots,
                frames,
                Term::atom(resolved.module_atom),
                Term::atom(resolved.function_atom),
                Term::small(i64::from(resolved.arity)).expect("arity is small"),
                location,
            );
            words += if located { 17 } else { 7 };
            frames += 1;
            continue;
        }
        let payload = word & !(1 << 63);
        let Some(module) = tables
            .and_then(|tables| tables.modules.get((payload >> 32) as usize))
            .map(std::convert::AsRef::as_ref)
        else {
            continue;
        };
        let ip = payload as u32 as usize;
        let call_site = ip.saturating_sub(1);
        let Some((function, arity)) = module.function_atom_at(call_site) else {
            continue;
        };
        let location = module.line_term_at(call_site);
        let located = location.is_some();
        write_frame(
            slots,
            frames,
            Term::atom(module.name_atom),
            Term::atom(function),
            Term::small(i64::from(arity)).expect("arity is small"),
            location,
        );
        words += if located { 17 } else { 7 };
        frames += 1;
    }
    Ok(FramePrep::Ready(PreparedFrames {
        block,
        frames,
        words,
    }))
}

fn write_frame(
    slots: &mut [u64],
    index: usize,
    module: Term,
    function: Term,
    args: Term,
    location: Option<(Term, u64)>,
) {
    let base = index * FRAME_INFO_WORDS;
    slots[base] = module.tagged_word();
    slots[base + 1] = function.tagged_word();
    slots[base + 2] = args.tagged_word();
    if let Some((file, line)) = location {
        slots[base + 3] = file.tagged_word();
        slots[base + 4] = line;
        slots[base + 5] = 1;
    } else {
        slots[base + 3] = 0;
        slots[base + 4] = 0;
        slots[base + 5] = 0;
    }
}

fn read_frame(slots: &[u64], index: usize) -> (Term, Term, Term, Option<(Term, u64)>) {
    let base = index * FRAME_INFO_WORDS;
    let location = (slots[base + 5] & 1 != 0).then(|| {
        (
            crate::native_hooks::from_raw(slots[base + 3]),
            slots[base + 4],
        )
    });
    (
        crate::native_hooks::from_raw(slots[base]),
        crate::native_hooks::from_raw(slots[base + 1]),
        crate::native_hooks::from_raw(slots[base + 2]),
        location,
    )
}

fn cons_prepared(p: &mut Process, ready: PreparedFrames) -> Result<Term, VmError> {
    if ready.frames == 0 || ready.words == 0 {
        return Ok(Term::NIL);
    }
    let mut heap = TraceHeap::with_block(&mut p.heap, ready.words);
    let file_atom = Term::atom(trace_atoms().file);
    let line_atom = Term::atom(trace_atoms().line);
    let mut builder = TermBuilder::new(&mut heap);
    let mut list = Term::NIL;
    for index in (0..ready.frames).rev() {
        let (module, function, args, location) = read_frame(ready.block.as_slice(), index);
        let location = location.map(|(file, number)| arinsal_term::MfaLocation {
            file_atom,
            file,
            line_atom,
            line: Term::small(number as i64).expect("source line is a small"),
        });
        list = builder
            .cons_mfa_frame(module, function, args, location, list)
            .map_err(|error| VmError::Unsupported(format!("stacktrace {error:?}")))?;
    }
    Ok(list)
}

pub(super) fn build_saved(p: &mut Process, raw: &mut RawTrace) -> Result<Term, VmError> {
    if let Some(explicit) = &raw.explicit {
        return from_owned(explicit, &mut FragmentingHeap(&mut p.heap))
            .map_err(|e| VmError::Unsupported(format!("exception stack {e:?}")));
    }
    if let Some(slot) = raw.explicit_slot {
        let explicit = p
            .cold
            .as_ref()
            .and_then(|cold| cold.trace_keep.as_ref())
            .and_then(|keep| keep.explicit.get(slot).cloned())
            .ok_or_else(|| VmError::Unsupported("stacktrace explicit".into()))?;
        return from_owned(&explicit, &mut FragmentingHeap(&mut p.heap))
            .map_err(|e| VmError::Unsupported(format!("exception stack {e:?}")));
    }
    if raw.top.is_none()
        && let Some(slot) = raw.top_slot
    {
        raw.top = p
            .cold
            .as_ref()
            .and_then(|cold| cold.trace_keep.as_ref())
            .and_then(|keep| keep.tops.get(slot).cloned());
    }
    let kept_modules = p
        .cold
        .as_ref()
        .and_then(|cold| cold.trace_keep.as_ref())
        .map(|keep| keep.modules.clone())
        .unwrap_or_default();
    let top = raw
        .top
        .as_ref()
        .map(|top| match top {
            StoredTopFrame::Bif {
                module,
                function,
                args,
                info,
            } => Ok(TopFrame::Bif {
                module: *module,
                function: *function,
                args: args.clone(),
                info: *info,
            }),
            StoredTopFrame::CurrentArgs(args) => Ok(TopFrame::CurrentArgs(
                from_owned(args, &mut FragmentingHeap(&mut p.heap))
                    .map_err(|e| VmError::Unsupported(format!("exception args {e:?}")))?,
            )),
            StoredTopFrame::CurrentArgsWithInfo(args, info) => {
                let args = args
                    .as_ref()
                    .map(|args| {
                        from_owned(args, &mut FragmentingHeap(&mut p.heap))
                            .map_err(|e| VmError::Unsupported(format!("exception args {e:?}")))
                    })
                    .transpose()?;
                Ok(TopFrame::CurrentArgsWithInfo(args, info.clone()))
            }
        })
        .transpose()?;
    let top = top.as_ref();
    raw.frames.clear();
    // Upper bound per frame: 4-tuple, 3-element info list, file/line/error_info tuples
    // and the one-pair error_info map; plus the result list and BIF argument list.
    let bif_args = match top {
        Some(TopFrame::Bif { args, .. }) => match args {
            BifArgs::Inline { len, .. } => usize::from(*len),
            BifArgs::Owned(_) => 0,
        },
        _ => 0,
    };
    // Port of beam_common.c:1258-1277: `fi.needed + 2` per frame, one HAlloc.
    // A located frame is 17 words (file tuple, line tuple, two conses, MFA tuple, list cell).
    let frame_budget = (1 + raw.continuations.len()).min(raw.depth.max(1));
    let bif_extra = if matches!(top, Some(TopFrame::Bif { .. })) {
        48 + 2 * bif_args
    } else {
        0
    };
    let block_words = frame_budget * 17 + bif_extra;
    let code_modules = raw.code_table.then(|| {
        p.runtime
            .as_ref()
            .map(|runtime| runtime.active_code_tables())
    });
    if raw.module.is_none() {
        raw.module = raw.module_index.and_then(|slot| {
            if raw.code_table {
                code_modules
                    .as_ref()
                    .and_then(|tables| tables.as_ref())
                    .and_then(|tables| tables.modules.get(slot).cloned())
            } else {
                kept_modules.get(slot).cloned()
            }
        });
    }
    if raw.module.is_none()
        && let Some(name) = raw.module_name
    {
        raw.module = p.runtime.as_ref().and_then(|runtime| {
            runtime
                .active_code_tables()
                .modules
                .iter()
                .find(|module| module.name_atom == name)
                .cloned()
        });
    }
    // Loaded before the heap is borrowed: `erts_lookup_function_info` reads the active
    // code index, not the function registry.
    let ranges = p.runtime.as_ref().map(|runtime| runtime.code_ranges());
    let ranges = ranges.as_deref().map(Vec::as_slice);
    let mut heap = TraceHeap::with_block(&mut p.heap, block_words);
    let current = raw
        .module
        .as_ref()
        .ok_or_else(|| VmError::Unsupported("stacktrace module".into()))?;
    let (frame_module, function, arity, location) = if let Some(frame) = raw
        .native_top
        .and_then(|pc| crate::native_bridge::stack_frame_in(ranges, pc))
    {
        // The frame's own file term: `raw.module` is only the last interpreter module.
        // Port of erts/emulator/beam/utils.c:3430 (`erts_build_mfa_item`), OTP-29.1.1.
        let location = frame.line.and_then(|line| {
            frame
                .file_term
                .or_else(|| {
                    frame
                        .file
                        .as_deref()
                        .and_then(|file| current.line_file_terms.get(file).copied())
                })
                .map(|file| (file, u64::from(line)))
        });
        (
            frame.module_atom,
            frame.function_atom,
            frame.arity,
            location,
        )
    } else {
        let (function, arity) = current
            .function_atom_at(raw.ip)
            .unwrap_or((trace_atoms().unknown, 0));
        (
            current.name_atom,
            function,
            arity,
            current.line_term_at(raw.ip),
        )
    };
    // Head-first. `erts_build_mfa_item` writes plain frames; a BIF frame or one
    // carrying `error_info` still goes through `build_frame`.
    struct Plain {
        module: Atom,
        function: Atom,
        args: Term,
        location: Option<(Term, u64)>,
    }
    enum Item {
        Built(Term),
        Plain(Plain),
    }
    let mut items = Vec::new();
    if let Some(TopFrame::Bif {
        module: bif_module,
        function: bif_function,
        args,
        info,
    }) = top
    {
        let args = args.to_term(&mut heap)?;
        let error_info = bif_error_info(&mut heap, *bif_module, *info)?;
        items.push(Item::Built(build_frame(
            &mut heap,
            *bif_module,
            *bif_function,
            args,
            None,
            true,
            error_info,
        )?));
        if items.len() < raw.depth {
            items.push(Item::Plain(Plain {
                module: frame_module,
                function,
                args: Term::small(i64::from(arity)).expect("arity is small"),
                location,
            }));
        }
    } else {
        let top_args = match top {
            Some(TopFrame::CurrentArgs(args)) => *args,
            Some(TopFrame::CurrentArgsWithInfo(Some(args), _)) => *args,
            Some(TopFrame::CurrentArgsWithInfo(None, _)) => {
                Term::small(i64::from(arity)).expect("arity is small")
            }
            _ => Term::small(i64::from(arity)).expect("arity is small"),
        };
        let error_info = match top {
            Some(TopFrame::CurrentArgsWithInfo(_, info)) => Some(
                from_owned(info.as_ref(), &mut heap)
                    .map_err(|e| VmError::Unsupported(format!("exception info {e:?}")))?,
            ),
            _ => None,
        };
        if error_info.is_some() {
            items.push(Item::Built(build_frame(
                &mut heap,
                frame_module,
                function,
                top_args,
                location,
                false,
                error_info,
            )?));
        } else {
            items.push(Item::Plain(Plain {
                module: frame_module,
                function,
                args: top_args,
                location,
            }));
        }
    }
    for continuation in &raw.continuations {
        if items.len() >= raw.depth {
            break;
        }
        if let Continuation::Native(address) = continuation {
            // Resolved lazily like erts, which saves raw pcs and decodes them in build_stacktrace.
            let Some(resolved) = crate::native_bridge::stack_frame_in(ranges, *address) else {
                continue;
            };
            items.push(Item::Plain(Plain {
                module: resolved.module_atom,
                function: resolved.function_atom,
                args: Term::small(i64::from(resolved.arity)).expect("arity is small"),
                location: literal_location(&resolved, current),
            }));
            continue;
        }
        let (module, ip) = match continuation {
            Continuation::Native(_) => continue,
            Continuation::Indexed(index, ip) => {
                let module = if raw.code_table {
                    code_modules
                        .as_ref()
                        .and_then(|tables| tables.as_ref())
                        .and_then(|tables| tables.modules.get(*index).cloned())
                } else {
                    kept_modules.get(*index).cloned()
                };
                let Some(module) = module else {
                    continue;
                };
                (module, *ip)
            }
        };
        let call_site = ip.saturating_sub(1);
        let Some((function, arity)) = module.function_atom_at(call_site) else {
            continue;
        };
        items.push(Item::Plain(Plain {
            module: module.name_atom,
            function,
            args: Term::small(i64::from(arity)).expect("arity is small"),
            location: module.line_term_at(call_site),
        }));
    }
    let file_atom = Term::atom(trace_atoms().file);
    let line_atom = Term::atom(trace_atoms().line);
    let mut builder = TermBuilder::new(&mut heap);
    let mut list = Term::NIL;
    for item in items.iter().rev() {
        list = match item {
            Item::Built(frame) => builder
                .cons(*frame, list)
                .map_err(|error| VmError::Unsupported(format!("stacktrace {error:?}")))?,
            Item::Plain(frame) => {
                let location = frame
                    .location
                    .map(|(file, number)| arinsal_term::MfaLocation {
                        file_atom,
                        file,
                        line_atom,
                        line: Term::small(number as i64).expect("source line is a small"),
                    });
                builder
                    .cons_mfa_frame(
                        Term::atom(frame.module),
                        Term::atom(frame.function),
                        frame.args,
                        location,
                        list,
                    )
                    .map_err(|error| VmError::Unsupported(format!("stacktrace {error:?}")))?
            }
        };
    }
    Ok(list)
}

pub(super) fn atom_term(name: &str) -> Result<Term, VmError> {
    atom(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bif_arguments_keep_pointer_terms_inline_and_rewrite_gc_roots() {
        let mut heap = ProcessHeap::new();
        let pointer = TermBuilder::new(&mut heap).tuple(&[]).unwrap();
        assert!(pointer.is_pointer());
        let mut args = BifArgs::from_terms(&[pointer, Term::small(3).unwrap()]).unwrap();
        assert!(matches!(&args, BifArgs::Inline { .. }));
        let mut roots = Vec::new();
        let (start, len) = args.root_terms(&mut roots).unwrap();
        let replacement = Term::small(7).unwrap();
        roots[start] = replacement;
        args.update_root_terms(&roots, start, len);
        assert!(matches!(args, BifArgs::Inline { values, .. } if values[0] == replacement));
    }
}
