//! Symbolic stack traces from BEAM continuations.

use crate::{Process, VmError};
use arinsal_alloc::typed::{AllocBlock, ErtsAlcType};
use arinsal_bifs::{Class, ProcessHeapHandle};
use arinsal_etf::OwnedTerm;
use arinsal_loader::Module;
use arinsal_term::{
    Atom, HeapAlloc, ProcessHeap, Term, TermBuilder, TermKind, from_owned, global_atoms, to_owned,
};
use arinsal_term::{ExportEntry, ExternalBinary, FunEntry, MagicRef, Node, WritableBinary};
use std::sync::{Arc, Mutex, OnceLock};

// The final continuation module index identifies an empty-trace catch immediate.
const EMPTY_TRACE_PREFIX: u64 = (1 << 26) - 1;
const CONTINUATION_BIT: u64 = 1 << 57;
const TRACE_RETURN_MODULE: u64 = (1 << 25) - 1;
const TRACE_EXCEPTION_MODULE: u64 = (1 << 25) - 2;
const TRACE_RETURN_TO_MODULE: u64 = (1 << 25) - 3;
// Port of erts/emulator/beam/beam_common.h:291-293 and beam_bp.c:1228-1246,
// OTP-29.1.1: interpreter trace CPs use reserved module-index values as special addresses.
const TRACE_RETURN_CONTINUATION: Term = Term::catch(CONTINUATION_BIT | TRACE_RETURN_MODULE << 32);
const TRACE_EXCEPTION_CONTINUATION: Term =
    Term::catch(CONTINUATION_BIT | TRACE_EXCEPTION_MODULE << 32);
const TRACE_RETURN_TO_CONTINUATION: Term =
    Term::catch(CONTINUATION_BIT | TRACE_RETURN_TO_MODULE << 32);

/// A catch handler: the code scope of its runtime, its module index and its code index.
type CatchKey = (u64, usize, usize);

fn interpreted_catch_ids() -> &'static Mutex<std::collections::HashMap<CatchKey, u32>> {
    static IDS: OnceLock<Mutex<std::collections::HashMap<CatchKey, u32>>> = OnceLock::new();
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
        if let Some(ptr) = HeapAlloc::alloc(self.heap, words) {
            return Some(ptr);
        }
        Some(self.heap.gc_fragment(words))
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

    fn link_magic_ref(
        &mut self,
        thing: *mut u64,
        owner: Arc<MagicRef>,
    ) -> Result<(), arinsal_term::TermError> {
        HeapAlloc::link_magic_ref(self.heap, thing, owner)
    }

    fn supports_magic(&self) -> bool {
        true
    }
}

/// Continuation addresses saved before exception unwinding.
#[derive(Default)]
pub(super) struct RawTrace {
    class: Option<Class>,
    top: Option<StoredTopFrame>,
    module: Option<Arc<Module>>,
    /// Module-table index when `module` was not cloned (heap-resident raw trace).
    module_index: Option<usize>,
    ip: usize,
    /// Native function and pc that raised the exception, when it came from native code.
    native_top: Option<usize>,
    continuations: Vec<Continuation>,
    frames: Vec<Term>,
    depth: usize,
    /// `module_index` and indexed continuations name the active code table.
    /// A raw `save_stacktrace` sets this and does not resolve frames.
    code_table: bool,
    /// The process waits in a BIF trap: its pc is no function, so no frame stands for it.
    no_current: bool,
}

enum Continuation {
    Native(usize),
    /// Module-table index and instruction pointer, used by a heap-resident raw trace.
    Indexed(usize, usize),
}

/// Fields stored in OTP's `struct StackTrace` bignum allocation.
#[cfg(test)]
struct StackTraceFields<'a> {
    freason: u64,
    pc: u64,
    current: u64,
    depth: usize,
    max_depth: usize,
    trace: &'a [u64],
}

/// One bignum allocation laid out as `struct StackTrace` after its bignum header.
struct StackTrace;

impl StackTrace {
    /// Reserves the exact bignum extent so the CP walk can fill `trace[]` in place.
    fn reserve(heap: &mut impl HeapAlloc, max_depth: usize) -> Result<Term, VmError> {
        let digits = 5usize
            .checked_add(max_depth)
            .ok_or_else(|| VmError::Unsupported("stacktrace size".into()))?;
        TermBuilder::new(heap)
            .pos_bignum_reserve(digits)
            .map_err(|error| VmError::Unsupported(format!("stacktrace allocation {error:?}")))
    }

    /// Port of `HAlloc` and `struct StackTrace` stores in beam_common.c:880-893.
    #[cfg(test)]
    fn allocate(heap: &mut impl HeapAlloc, fields: StackTraceFields<'_>) -> Result<Term, VmError> {
        if fields.depth > fields.max_depth || fields.trace.len() > fields.max_depth {
            return Err(VmError::Unsupported("stacktrace depth".into()));
        }
        let digits = 5usize
            .checked_add(fields.max_depth)
            .ok_or_else(|| VmError::Unsupported("stacktrace size".into()))?;
        let freason = fields.freason;
        let pc = fields.pc;
        let current = fields.current;
        let depth = fields.depth as u64;
        let max_depth = fields.max_depth as u64;
        let trace = fields.trace;
        TermBuilder::new(heap)
            .pos_bignum_fill(digits, |index| match index {
                0 => freason,
                1 => pc,
                2 => current,
                3 => depth,
                4 => max_depth,
                _ => trace.get(index - 5).copied().unwrap_or(0),
            })
            .map_err(|error| VmError::Unsupported(format!("stacktrace allocation {error:?}")))
    }

    /// Port of the negative StackTrace made by erts/emulator/beam/bif.c:1675-1685,
    /// OTP-29.1.1. A raised stacktrace is already symbolic and lives in `Args`.
    fn allocate_raised(heap: &mut impl HeapAlloc, freason: u64) -> Result<Term, VmError> {
        TermBuilder::new(heap)
            .neg_bignum_fill(5, |index| if index == 0 { freason } else { 0 })
            .map_err(|error| VmError::Unsupported(format!("raised stacktrace {error:?}")))
    }
}

/// The `ftrace` value stored by `save_stacktrace`: `{StackTrace, Args, ErrorInfo}`.
struct Ftrace {
    stack_trace: Term,
    args: Term,
    error_info: Term,
}

impl Ftrace {
    /// Packages the already allocated trace and its associated values once.
    fn allocate(self, heap: &mut impl HeapAlloc) -> Result<Term, VmError> {
        TermBuilder::new(heap)
            .tuple(&[self.stack_trace, self.args, self.error_info])
            .map_err(|error| VmError::Unsupported(format!("ftrace tuple {error:?}")))
    }
}

#[derive(Clone, Debug)]
pub(super) enum BifArgs {
    Inline {
        values: [Term; 4],
        len: u8,
    },
    /// Shared so a rebuilt trace never deep-clones a deeply nested argument.
    Owned(Arc<OwnedTerm>),
    /// The list already belongs to the saved ftrace tuple.
    TermList(Term),
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
            Self::TermList(args) => Ok(*args),
        }
    }
}

#[derive(Clone)]
pub(super) enum StoredTopFrame {
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
    /// The process is scheduled out in the export trap of a BIF call.
    pub(super) trapped: bool,
    /// Return address of that BIF call when it is not on the stack (interpreter calls).
    pub(super) trap_return: Option<usize>,
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
        trapped,
        trap_return,
    } = current;
    raw.class = class;
    let captured_top = top
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
    if captured_top.is_some() {
        raw.top = captured_top;
    }
    raw.module_index = Some(module);
    raw.module = modules.get(module).cloned();
    raw.ip = ip;
    raw.depth = depth.max(1);
    raw.continuations.clear();
    raw.continuations.reserve(raw.depth.min(16));
    raw.native_top = None;
    raw.no_current = trapped;
    if matches!(raw.top, Some(StoredTopFrame::Bif { .. })) && native_pc.is_none() {
        // Port of beam_common.c:880-930 (`save_stacktrace`), OTP-29.1.1: the BIF owns
        // `current`; preserve the interpreter caller's CP as the first trace word.
        let caller_cp = ip.saturating_add(1);
        if pack_indexed(module, caller_cp).is_some() {
            push_frame(raw, Continuation::Indexed(module, caller_cp));
        }
    }
    // OTP starts with the failing instruction as `prev` and compares it with
    // each continuation after moving that continuation back to its call site.
    let mut previous = (!trapped).then_some((module, ip));
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
    if let Some(return_ip) = trap_return
        && modules.get(module).is_some()
        && raw.continuations.len() + 1 < raw.depth
    {
        // The trap's pc is no function, so nothing seeds `prev`: the BIF call's own return
        // address is the first frame.
        previous = Some((module, return_ip.saturating_sub(1)));
        push_frame(raw, Continuation::Indexed(module, return_ip));
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
        // Port of erl_term.h:1378-1379 (`is_CP`) and beam_common.c:805 (`gather_stacktrace`),
        // OTP-29.1.1. The stack walk classifies a CP from its alignment bits.
        if arinsal_term::is_cp(raw_address as u64) {
            // Port of erts/emulator/beam/beam_common.c:815-835 (save_stacktrace), OTP-29.1.1:
            // only non-duplicate return addresses are recorded, each looked up one byte back,
            // inside its call instruction. Like erts' is_CP test this only checks the word's
            // shape (plus the lock-free native hull); the function is looked up in `build`.
            if previous_native != Some(raw_address) {
                previous_native = Some(raw_address);
                previous = None;
                push_frame(raw, Continuation::Native(raw_address - 1));
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
        if modules.get(module).is_some() {
            push_frame(raw, Continuation::Indexed(module, ip));
        }
        index += 1;
    }
    Ok(())
}

/// Preserve the supplied `raise/3` trace in Args behind erts' negative StackTrace marker.
///
/// Port of erts/emulator/beam/bif.c:1675-1685 (`raise_3`), OTP-29.1.1.
pub(super) fn save_explicit(p: &mut Process, class: Class, trace: Term) -> Result<Term, VmError> {
    let freason = class_to_freason(Some(class));
    let mut heap = TraceHeap::new(&mut p.heap);
    let stack_trace = StackTrace::allocate_raised(&mut heap, freason)?;
    Ftrace {
        stack_trace,
        args: trace,
        error_info: Term::NIL,
    }
    .allocate(&mut heap)
}

fn push_frame(raw: &mut RawTrace, continuation: Continuation) {
    raw.continuations.push(continuation);
}

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
        arinsal_bifs::BifError::Badarg { cause: Some(cause) } => BifErrorInfo::Cause(*cause),
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

pub(super) fn take_matching_pending_top(p: &mut Process) -> Option<StoredTopFrame> {
    let cold = p.cold.as_mut()?;
    let matches = cold.pending_trace_top.as_ref().is_some_and(|pending| {
        pending.freason == p.header.freason && pending.fvalue == p.header.fvalue
    });
    matches
        .then(|| cold.pending_trace_top.take().map(|pending| pending.top))
        .flatten()
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
    let top = clone_matching_pending(p);
    save_direct(
        p,
        StackTraceSave {
            class,
            depth: runtime_backtrace_depth(p, 8),
            freason: process_freason(p, class),
            native_pc,
            top: top.as_ref().map(SaveTop::Stored),
        },
    )
}

/// Port of erts/emulator/beam/beam_common.c:880-1010 (`save_stacktrace`), OTP-29.1.1.
/// The trace block is sized and allocated before the stack walk, then filled in place.
pub(super) fn save_direct(p: &mut Process, input: StackTraceSave<'_>) -> Result<Term, VmError> {
    let StackTraceSave {
        class,
        depth,
        freason,
        native_pc,
        top,
    } = input;
    let depth = depth.max(1);
    let freason = if freason != 0 {
        freason
    } else {
        class_to_freason(Some(class))
    };
    let (native_top, previous_native, previous) = match native_pc {
        Some(pc) if pc & arinsal_beamasm::module::RETURN_SITE_TAG != 0 => {
            let address = pc & !arinsal_beamasm::module::RETURN_SITE_TAG;
            (Some(address.wrapping_sub(1)), Some(address), None)
        }
        // Port of erts/emulator/beam/beam_common.c:791-835 (`gather_stacktrace`),
        // OTP-29.1.1: the raw `pc` seeds the duplicate check before the stack walk.
        Some(pc) => (Some(pc), Some(pc), None),
        None => (None, None, Some((p.module, p.ip))),
    };
    // Port of erts/emulator/beam/beam_common.c:880-930 (`save_stacktrace`), OTP-29.1.1:
    // `StackTrace` is the bignum itself and ftrace is its three-element tuple. The current
    // frame and continuations remain code addresses until `build_stacktrace` resolves them.
    let bif_top = top.is_some_and(SaveTop::is_bif);
    let max_depth = depth.saturating_sub(1);
    let current = match top {
        Some(top) if let Some((module, function)) = top.bif_mfa() => pack_bif_mfa(module, function),
        _ => pack_indexed(p.module, p.ip)
            .ok_or_else(|| VmError::Unsupported("stacktrace current address".into()))?,
    };
    let pc = if bif_top {
        0
    } else {
        native_top
            .map_or_else(|| pack_indexed(p.module, p.ip), |pc| u64::try_from(pc).ok())
            .unwrap_or(0)
    };
    let native_top_word = native_top
        .map(u64::try_from)
        .transpose()
        .map_err(|_| VmError::Unsupported("stacktrace pc".into()))?;
    let interpreter_caller = (bif_top && native_top_word.is_none())
        .then(|| pack_indexed(p.module, p.ip.saturating_add(1)))
        .flatten();
    let stack_trace = {
        let mut heap = TraceHeap::new(&mut p.heap);
        StackTrace::reserve(&mut heap, max_depth)?
    };
    stack_trace
        .with_bignum_digits_mut(|digits| {
            digits[0] = freason;
            digits[1] = pc;
            digits[2] = current;
            digits[4] = max_depth as u64;
            let mut offset = 0;
            if bif_top
                && max_depth > 0
                && let Some(pc) = native_top_word
            {
                digits[5] = pc;
                offset = 1;
            } else if bif_top
                && max_depth > 0
                && let Some(caller) = interpreter_caller
            {
                // Port of beam_common.c:928-930 (`save_stacktrace`), OTP-29.1.1:
                // a BIF frame owns current, so preserve its interpreter caller CP.
                digits[5] = caller;
                offset = 1;
            }
            let end = 5 + max_depth;
            let gathered =
                gather_continuations(p, &mut digits[5 + offset..end], previous_native, previous);
            let depth = offset + gathered;
            digits[3] = depth as u64;
            depth
        })
        .ok_or_else(|| VmError::Unsupported("stacktrace bignum".into()))?;
    let mut heap = TraceHeap::new(&mut p.heap);
    let (args, error_info) = save_ftrace_values(&mut heap, top)?;
    Ftrace {
        stack_trace,
        args,
        error_info,
    }
    .allocate(&mut heap)
}

pub(super) struct StackTraceSave<'a> {
    pub(super) class: Class,
    pub(super) depth: usize,
    pub(super) freason: u64,
    pub(super) native_pc: Option<usize>,
    pub(super) top: Option<SaveTop<'a>>,
}

#[derive(Clone, Copy)]
pub(super) enum SaveTop<'a> {
    Live(&'a TopFrame),
    Stored(&'a StoredTopFrame),
}

impl SaveTop<'_> {
    fn is_bif(self) -> bool {
        matches!(
            self,
            Self::Live(TopFrame::Bif { .. }) | Self::Stored(StoredTopFrame::Bif { .. })
        )
    }

    fn bif_mfa(&self) -> Option<(Atom, Atom)> {
        match self {
            Self::Live(TopFrame::Bif {
                module, function, ..
            })
            | Self::Stored(StoredTopFrame::Bif {
                module, function, ..
            }) => Some((*module, *function)),
            _ => None,
        }
    }
}

fn runtime_backtrace_depth(p: &Process, fallback: usize) -> usize {
    p.runtime.as_ref().map_or(fallback, |runtime| {
        runtime
            .backtrace_depth
            .load(std::sync::atomic::Ordering::Acquire)
    })
}

fn process_freason(p: &Process, class: Class) -> u64 {
    if p.header.freason != 0 {
        p.header.freason
    } else {
        class_to_freason(Some(class))
    }
}

fn save_ftrace_values(
    heap: &mut TraceHeap<'_>,
    top: Option<SaveTop<'_>>,
) -> Result<(Term, Term), VmError> {
    if let Some(SaveTop::Stored(top)) = top {
        return ftrace_values(heap, Some(top));
    }
    let args = match top {
        Some(SaveTop::Live(TopFrame::Bif { args, .. })) => args.to_term(heap)?,
        Some(SaveTop::Live(TopFrame::CurrentArgs(args)))
        | Some(SaveTop::Live(TopFrame::CurrentArgsWithInfo(Some(args), _))) => *args,
        Some(SaveTop::Live(TopFrame::CurrentArgsWithInfo(None, _))) | None => {
            Term::atom(arinsal_term::atoms::TRUE)
        }
        Some(SaveTop::Stored(_)) => unreachable!(),
    };
    let info_map = match top {
        Some(SaveTop::Live(TopFrame::Bif { module, info, .. })) => {
            bif_error_info(heap, *module, *info)?
        }
        Some(SaveTop::Live(TopFrame::CurrentArgsWithInfo(_, info))) => Some(
            from_owned(info, heap)
                .map_err(|error| VmError::Unsupported(format!("error_info {error:?}")))?,
        ),
        Some(SaveTop::Stored(_)) => unreachable!(),
        _ => None,
    };
    let error_info = if let Some(info) = info_map {
        let entry = TermBuilder::new(heap)
            .tuple(&[Term::atom(trace_atoms().error_info), info])
            .map_err(|error| VmError::Unsupported(format!("error_info tuple {error:?}")))?;
        TermBuilder::new(heap)
            .cons(entry, Term::NIL)
            .map_err(|error| VmError::Unsupported(format!("error_info list {error:?}")))?
    } else {
        Term::NIL
    };
    Ok((args, error_info))
}

fn pack_bif_mfa(module: Atom, function: Atom) -> u64 {
    (u64::from(module.0) << 32) | u64::from(function.0)
}

fn ftrace_values(
    heap: &mut TraceHeap<'_>,
    top: Option<&StoredTopFrame>,
) -> Result<(Term, Term), VmError> {
    let args = match top {
        Some(StoredTopFrame::Bif { args, .. }) => args.to_term(heap)?,
        Some(StoredTopFrame::CurrentArgs(args)) => from_owned(args, heap)
            .map_err(|error| VmError::Unsupported(format!("exception args {error:?}")))?,
        Some(StoredTopFrame::CurrentArgsWithInfo(Some(args), _)) => from_owned(args, heap)
            .map_err(|error| VmError::Unsupported(format!("exception args {error:?}")))?,
        Some(StoredTopFrame::CurrentArgsWithInfo(None, _)) | None => {
            // Port of beam_common.c:922-925 (`save_stacktrace`), OTP-29.1.1: `Args` is
            // the already-interned `true` atom when the current frame has no saved args.
            Term::atom(arinsal_term::atoms::TRUE)
        }
    };
    let info_map = match top {
        Some(StoredTopFrame::Bif { module, info, .. }) => bif_error_info(heap, *module, *info)?,
        Some(StoredTopFrame::CurrentArgsWithInfo(_, info)) => Some(
            from_owned(info, heap)
                .map_err(|error| VmError::Unsupported(format!("error_info {error:?}")))?,
        ),
        _ => None,
    };
    let error_info = if let Some(info) = info_map {
        let entry = TermBuilder::new(heap)
            .tuple(&[Term::atom(trace_atoms().error_info), info])
            .map_err(|error| VmError::Unsupported(format!("error_info tuple {error:?}")))?;
        TermBuilder::new(heap)
            .cons(entry, Term::NIL)
            .map_err(|error| VmError::Unsupported(format!("error_info list {error:?}")))?
    } else {
        Term::NIL
    };
    Ok((args, error_info))
}

/// Writes raw CP words the way `gather_stacktrace` does (beam_common.c:781), OTP-29.1.1.
/// One pass from `stop` toward the stack start. A continuation pointer is recorded when
/// it differs from the previous one; every other word is skipped.
fn gather_continuations(
    p: &Process,
    pcs: &mut [u64],
    previous_native: Option<usize>,
    previous: Option<(usize, usize)>,
) -> usize {
    // Port of erts/emulator/beam/beam_common.c:791-835 (`gather_stacktrace`), OTP-29.1.1.
    // erts advances one pointer through the live stack; use the equivalent sequential view.
    gather_continuations_in(p, pcs, previous_native, previous)
}

fn gather_continuations_in(
    p: &Process,
    pcs: &mut [u64],
    mut previous_native: Option<usize>,
    mut previous: Option<(usize, usize)>,
) -> usize {
    let limit = pcs.len();
    let mut count = 0usize;
    let trace_return = crate::native_bridge::native_trace_return_address();
    let bridge = arinsal_beamasm::rt::arinsal_enter_native_return as *const () as usize;
    let mut stack = p.heap.stack_terms().enumerate();
    while count < limit {
        let Some((index, word)) = stack.next() else {
            break;
        };
        let raw_address = word.tagged_word() as usize;
        if raw_address == trace_return {
            let action_count = p
                .heap
                .stack_get(index + 3)
                .and_then(Term::as_small)
                .and_then(|n| usize::try_from(n).ok())
                .unwrap_or(0);
            let advance = 4usize.saturating_add(action_count.saturating_mul(2));
            stack.nth(advance.saturating_sub(2));
            continue;
        }
        if raw_address == bridge {
            continue;
        }
        if let Some(advance) = trace_continuation_advance(word) {
            stack.nth(advance.saturating_sub(2));
            continue;
        }
        // Port of erts/emulator/beam/erl_term.h:1378-1379 (`is_CP`) and
        // beam_common.c:805 (`gather_stacktrace`), OTP-29.1.1. A continuation is
        // classified from its tag bits; code-range membership is deferred to the builder.
        if arinsal_term::is_cp(raw_address as u64) {
            if previous_native != Some(raw_address) {
                previous_native = Some(raw_address);
                previous = None;
                pcs[count] = u64::try_from(raw_address.wrapping_sub(1)).unwrap_or(0);
                count += 1;
            }
            continue;
        }
        if let Some((module, ip)) = continuation_word(word) {
            let call_site = ip.saturating_sub(1);
            if previous == Some((module, call_site)) {
                continue;
            }
            previous = Some((module, call_site));
            previous_native = None;
            if let Some(packed) = pack_indexed(module, ip) {
                pcs[count] = packed;
                count += 1;
            }
            continue;
        }
    }
    count
}

/// Interpreter continuation or catch tag carried as a catch immediate.
/// Catch handlers are not frames. No catch-table lookup: a handler index has
/// no continuation bit, and `build_stacktrace` is what resolves a real CP.
fn continuation_word(word: Term) -> Option<(usize, usize)> {
    if trace_continuation_advance(word).is_some() {
        return None;
    }
    if word.tagged_word() & 63 != 0x1b || word.classify() != TermKind::Catch {
        return None;
    }
    let payload = word.tagged_word() >> 6;
    if payload >> 32 == EMPTY_TRACE_PREFIX || payload & CONTINUATION_BIT == 0 {
        return None;
    }
    Some((
        ((payload & !CONTINUATION_BIT) >> 32) as usize,
        payload as u32 as usize,
    ))
}

/// Stack span associated with an interpreter equivalent of an erts trace CP.
// Port of erts/emulator/beam/beam_common.c:805-809 (`gather_stacktrace`), OTP-29.1.1.
fn trace_continuation_advance(word: Term) -> Option<usize> {
    if word == TRACE_RETURN_CONTINUATION || word == TRACE_EXCEPTION_CONTINUATION {
        Some(6)
    } else if word == TRACE_RETURN_TO_CONTINUATION {
        Some(2)
    } else {
        None
    }
}

fn pack_indexed(module: usize, ip: usize) -> Option<u64> {
    let module = u64::try_from(module).ok()?;
    let ip = u64::try_from(ip).ok()?;
    if module >= TRACE_RETURN_TO_MODULE || ip >= 1 << 32 {
        return None;
    }
    Some((1 << 63) | (module << 32) | ip)
}

fn class_to_freason(class: Option<Class>) -> u64 {
    match class {
        None => 0,
        Some(Class::Error) => 1,
        Some(Class::Exit) => 2,
        Some(Class::Throw) => 3,
    }
}

fn class_from_freason(value: u64) -> Option<Class> {
    match value {
        1 => Some(Class::Error),
        2 => Some(Class::Exit),
        3 => Some(Class::Throw),
        0 => None,
        _ => Some(Class::Error),
    }
}

fn ftrace_raw(term: Term) -> Option<RawTrace> {
    let fields = arinsal_term::term_sequence(term)?;
    if fields.len() != 3 {
        return None;
    }
    fields[0]
        .with_bignum_digits_mut(|digits| raw_from_stacktrace_digits(digits, fields[1], fields[2]))
        .flatten()
}

fn raw_from_stacktrace_digits(digits: &[u64], args: Term, error_info: Term) -> Option<RawTrace> {
    if digits.len() < 5 {
        return None;
    }
    let freason = digits[0];
    let pc = digits[1];
    let current = digits[2];
    let count = usize::try_from(digits[3]).ok()?;
    let max_depth = usize::try_from(digits[4]).ok()?;
    if count > max_depth || digits.len() < 5 + count {
        return None;
    }
    let (mut module_index, mut ip, top) = if args == Term::atom(arinsal_term::atoms::TRUE) {
        if current & (1 << 63) == 0 {
            return None;
        }
        (
            Some(((current & !(1 << 63)) >> 32) as usize),
            current as u32 as usize,
            None,
        )
    } else if current & (1 << 63) == 0 {
        let module = Atom((current >> 32) as u32);
        let function = Atom(current as u32);
        if !matches!(args.classify(), TermKind::List | TermKind::Nil) {
            return None;
        }
        let bif_args = BifArgs::TermList(args);
        let info = term_error_info(error_info);
        (
            None,
            0,
            Some(StoredTopFrame::Bif {
                module,
                function,
                args: bif_args,
                info,
            }),
        )
    } else {
        let module = ((current & !(1 << 63)) >> 32) as usize;
        let ip = current as u32 as usize;
        let args = (args != Term::atom(arinsal_term::atoms::TRUE))
            .then(|| to_owned(args).ok())
            .flatten();
        let info = term_error_info_map(error_info).and_then(|term| to_owned(term).ok());
        let top = match (args, info) {
            (Some(args), Some(info)) => Some(StoredTopFrame::CurrentArgsWithInfo(
                Some(args),
                Box::new(info),
            )),
            (Some(args), None) => Some(StoredTopFrame::CurrentArgs(args)),
            (None, Some(info)) => Some(StoredTopFrame::CurrentArgsWithInfo(None, Box::new(info))),
            (None, None) => None,
        };
        (Some(module), ip, top)
    };
    let mut trace_start = 5;
    let current_is_bif = matches!(top, Some(StoredTopFrame::Bif { .. }));
    let native_top = (pc != 0 && pc & (1 << 63) == 0)
        .then(|| usize::try_from(pc).ok())
        .flatten()
        .or_else(|| {
            if !current_is_bif || count == 0 || digits[5] & (1 << 63) != 0 {
                return None;
            }
            trace_start += 1;
            usize::try_from(digits[5]).ok()
        });
    let mut bif_caller_interpreted = false;
    if current_is_bif && pc == 0 && count != 0 && digits[5] & (1 << 63) != 0 {
        let payload = digits[5] & !(1 << 63);
        module_index = Some((payload >> 32) as usize);
        ip = payload as u32 as usize;
        trace_start += 1;
        bif_caller_interpreted = true;
    }
    let mut continuations = Vec::with_capacity(count.saturating_sub(trace_start - 5));
    for word in &digits[trace_start..5 + count] {
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
    Some(RawTrace {
        class: class_from_freason(freason),
        top,
        module_index,
        ip,
        native_top,
        continuations,
        depth: count.saturating_add(1),
        code_table: !current_is_bif || bif_caller_interpreted,
        ..RawTrace::default()
    })
}

fn term_error_info_map(value: Term) -> Option<Term> {
    let entries = arinsal_term::term_sequence(value)?;
    if entries.len() != 1 || value.classify() != TermKind::List {
        return None;
    }
    let pair = arinsal_term::term_sequence(entries[0])?;
    (pair.len() == 2 && pair[0] == Term::atom(trace_atoms().error_info)).then_some(pair[1])
}

fn term_error_info(value: Term) -> BifErrorInfo {
    let Some(info) = term_error_info_map(value) else {
        return BifErrorInfo::None;
    };
    let cause = arinsal_term::record_map_pairs(info).and_then(|pairs| {
        pairs
            .into_iter()
            .find_map(|(key, value)| (key.as_atom() == Some(trace_atoms().cause)).then_some(value))
    });
    cause.map_or(BifErrorInfo::Plain, BifErrorInfo::Cause)
}

/// Run `f` on the saved trace behind `term`, or return `None` when it is not one.
pub(super) fn with_saved<R>(term: Term, f: impl FnOnce(&mut RawTrace) -> R) -> Option<R> {
    if let Some(mut raw) = ftrace_raw(term) {
        return Some(f(&mut raw));
    }
    None
}

/// True when `term` is a saved raw trace.
pub(super) fn is_saved(term: Term) -> bool {
    raised_args(term).is_some() || with_saved(term, |_| ()).is_some()
}

/// Exception class saved with a raw trace for a later `raise` instruction.
pub(super) fn raw_class(_p: &Process, term: Term) -> Option<Class> {
    with_saved(term, |raw| raw.class).flatten()
}

/// Args carried by the negative StackTrace used for an explicit `raise/3` trace.
pub(super) fn raised_args(term: Term) -> Option<Term> {
    let fields = arinsal_term::term_sequence(term)?;
    (fields.len() == 3 && fields[0].is_negative_bignum()).then(|| fields[1])
}

/// Port of erts/emulator/beam/beam_common.c:1148-1178 (raw_raise).
pub(super) fn set_raw_class(_p: &mut Process, term: Term, class: Class) -> bool {
    let code = match class {
        Class::Error => 1,
        Class::Exit => 2,
        Class::Throw => 3,
    };
    if let Some(fields) = arinsal_term::term_sequence(term)
        && fields.len() == 3
        && fields[0]
            .with_bignum_digits_mut(|digits| {
                let Some(freason) = digits.first_mut() else {
                    return false;
                };
                *freason = code;
                true
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
    Cause(Term),
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
        static CACHE: std::cell::RefCell<std::collections::HashMap<CatchKey, u32, CodeKeyHasher>> =
            std::cell::RefCell::new(std::collections::HashMap::default());
    }
    let key = (crate::fun_dispatch::code_scope(), module, ip);
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

fn handler_tag_shared(key: CatchKey) -> Result<u32, VmError> {
    let (scope, module, ip) = key;
    let mut ids = interpreted_catch_ids()
        .lock()
        .map_err(|_| VmError::Unsupported("catch table lock".into()))?;
    let index = if let Some(index) = ids.get(&key) {
        *index
    } else {
        let base = arinsal_beamasm::catch::reserve_catch_indices(1)
            .map_err(|_| VmError::Unsupported("catch table exhausted".into()))?;
        crate::native_bridge::register_interpreted_catch(scope, base, module, ip);
        ids.insert(key, base);
        base
    };
    Ok(index)
}

/// Encodes an interpreter continuation without colliding with catch-table indices.
pub(crate) fn continuation_tag(module: usize, ip: usize) -> Result<Term, VmError> {
    let module = u64::try_from(module).map_err(|_| VmError::Unsupported("module index".into()))?;
    let ip = u32::try_from(ip).map_err(|_| VmError::Unsupported("code index".into()))?;
    if module >= TRACE_RETURN_TO_MODULE {
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
    if trace_continuation_advance(term).is_some() {
        return None;
    }
    if term.tagged_word() & 63 != 0x1b || term.classify() != TermKind::Catch {
        return None;
    }
    // SAFETY: CATCH is an immediate and carries no heap pointer.
    let payload = unsafe { term.raw_bits() } >> 6;
    if payload >> 32 == EMPTY_TRACE_PREFIX {
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
        Some(cause) => builder.flatmap_from_pairs(&[(Term::atom(atoms.cause), cause), module_pair]),
        None => builder.flatmap_from_pairs(&[module_pair]),
    }
    .map_err(|e| VmError::Unsupported(format!("BIF error info {e:?}")))?;
    Ok(Some(map))
}

fn literal_location(
    frame: &crate::native_bridge::NativeStackFrame,
    current: Option<&Module>,
) -> Option<(Term, u64)> {
    let line = frame.line?;
    let file = frame.file_term.or_else(|| {
        frame
            .file
            .as_deref()
            .and_then(|file| current?.line_file_terms.get(file).copied())
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
    let trapped = p.header.i as usize == crate::bif_traps::bif_export_trap_pc();
    let native_pc = p.cold.as_ref().map_or(0, |cold| cold.native_call_pc);
    let native_pc = if trapped {
        None
    } else if native_pc != 0 && crate::native_bridge::is_native_function_at(native_pc) {
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
            trapped,
            trap_return: p.trap_return_frame().map(|frame| frame.ip),
        },
        &p.heap,
        depth,
    )?;
    build_saved(p, &mut raw, modules)
}

/// Port of erts/emulator/beam/beam_common.c:1205 (build_stacktrace), OTP-29.1.1.
/// `FunctionInfo` scratch storage from `global.h`: MFA, needed, loc and filename pointer.
const FRAME_INFO_WORDS: usize = 4;

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
    let fields = arinsal_term::term_sequence(term)?;
    if fields.len() != 3
        || fields[1] != Term::atom(arinsal_term::atoms::TRUE)
        || fields[2] != Term::NIL
        || fields[0].is_negative_bignum()
    {
        return None;
    }
    let stack_trace = fields[0];
    let prepared = match p.runtime.as_ref() {
        Some(runtime) => runtime.with_active_code(|ranges, tables| {
            stack_trace
                .with_bignum_digits_mut(|digits| prepare_frames(digits, Some(ranges), Some(tables)))
        }),
        None => stack_trace.with_bignum_digits_mut(|digits| prepare_frames(digits, None, None)),
    }?;
    match prepared {
        Ok(FramePrep::Fallback) => None,
        Ok(FramePrep::Ready(ready)) => Some(cons_prepared(p, ready)),
        Err(error) => Some(Err(error)),
    }
}

fn prepare_frames(
    digits: &[u64],
    ranges: Option<&[crate::native_bridge::ModuleRange]>,
    tables: Option<&crate::load::CodeTables>,
) -> Result<FramePrep, VmError> {
    if digits.len() < 5 {
        return Ok(FramePrep::Fallback);
    }
    let pc = digits[1];
    let current = digits[2];
    let count = usize::try_from(digits[3]).unwrap_or(usize::MAX);
    let depth = count.saturating_add(1);
    let max_depth = usize::try_from(digits[4]).unwrap_or(0);
    if count > max_depth || digits.len() < 5 + count {
        return Ok(FramePrep::Fallback);
    }
    if current & (1 << 63) == 0 {
        return Ok(FramePrep::Fallback);
    }
    if pc == 0 {
        return Ok(FramePrep::Fallback);
    }
    let current_module = ((current & !(1 << 63)) >> 32) as usize;
    let current_module = tables
        .and_then(|tables| tables.modules.get(current_module))
        .map(std::convert::AsRef::as_ref);
    let mut frames = 0usize;
    let mut words = 0usize;
    let capacity = (1 + count).min(depth);
    let mut block = AllocBlock::new(ErtsAlcType::TMP, capacity * FRAME_INFO_WORDS)
        .map_err(|error| VmError::Unsupported(format!("stacktrace temp {error:?}")))?;
    let slots = block.as_mut_slice();
    let frame = if pc & (1 << 63) != 0 {
        let payload = pc & !(1 << 63);
        let module = tables.and_then(|tables| tables.modules.get((payload >> 32) as usize));
        module.and_then(|module| {
            let ip = payload as u32 as usize;
            let (function, arity) = module.function_atom_at(ip)?;
            Some((module.name_atom, function, arity, module.line_term_at(ip)))
        })
    } else {
        crate::native_bridge::stack_frame_in(ranges, usize::try_from(pc).unwrap_or(0)).map(
            |frame| {
                let location = frame.line.and_then(|line| {
                    frame
                        .file_term
                        .or_else(|| {
                            frame.file.as_deref().and_then(|file| {
                                current_module
                                    .and_then(|module| module.line_file_terms.get(file).copied())
                            })
                        })
                        .map(|file| (file, u64::from(line)))
                });
                (
                    frame.module_atom,
                    frame.function_atom,
                    frame.arity,
                    location,
                )
            },
        )
    };
    if let Some((module, function, arity, location)) = frame {
        let located = location.is_some();
        write_frame(slots, frames, module, function, arity, location);
        words += if located { 17 } else { 7 };
        frames += 1;
    }
    if pc & (1 << 63) == 0 && frames == 0 {
        return Ok(FramePrep::Fallback);
    }
    if pc & (1 << 63) != 0 && frames == 0 {
        return Ok(FramePrep::Fallback);
    }
    for word in &digits[5..5 + count] {
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
            let location = literal_location(&resolved, current_module);
            let located = location.is_some();
            write_frame(
                slots,
                frames,
                resolved.module_atom,
                resolved.function_atom,
                resolved.arity,
                location,
            );
            words += if located { 17 } else { 7 };
            frames += 1;
            continue;
        }
        let payload = word & !(1 << 63);
        let Some(module) = tables.and_then(|tables| tables.modules.get((payload >> 32) as usize))
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
        write_frame(slots, frames, module.name_atom, function, arity, location);
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
    module: Atom,
    function: Atom,
    arity: u8,
    location: Option<(Term, u64)>,
) {
    let base = index * FRAME_INFO_WORDS;
    slots[base] = (u64::from(module.0) << 32) | u64::from(function.0);
    if let Some((file, line)) = location {
        slots[base + 1] = 17;
        slots[base + 2] = (line << 32) | u64::from(arity);
        slots[base + 3] = file.tagged_word();
    } else {
        slots[base + 1] = 7;
        slots[base + 2] = u64::from(arity);
        slots[base + 3] = 0;
    }
}

fn read_frame(slots: &[u64], index: usize) -> (Atom, Atom, u8, Option<(Term, u64)>) {
    let base = index * FRAME_INFO_WORDS;
    let location = (slots[base + 1] == 17).then(|| {
        (
            crate::native_hooks::from_raw(slots[base + 3]),
            slots[base + 2] >> 32,
        )
    });
    (
        Atom((slots[base] >> 32) as u32),
        Atom(slots[base] as u32),
        slots[base + 2] as u8,
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
        let (module, function, arity, location) = read_frame(ready.block.as_slice(), index);
        let location = location.map(|(file, number)| arinsal_term::MfaLocation {
            file_atom,
            file,
            line_atom,
            line: Term::small(number as i64).expect("source line is a small"),
        });
        list = builder
            .cons_mfa_frame(
                Term::atom(module),
                Term::atom(function),
                Term::small(i64::from(arity)).expect("arity is small"),
                location,
                list,
            )
            .map_err(|error| VmError::Unsupported(format!("stacktrace {error:?}")))?;
    }
    Ok(list)
}

pub(super) fn build_saved(
    p: &mut Process,
    raw: &mut RawTrace,
    fallback_modules: &[Arc<Module>],
) -> Result<Term, VmError> {
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
                from_owned(args, &mut ProcessHeapHandle(&mut p.heap))
                    .map_err(|e| VmError::Unsupported(format!("exception args {e:?}")))?,
            )),
            StoredTopFrame::CurrentArgsWithInfo(args, info) => {
                let args = args
                    .as_ref()
                    .map(|args| {
                        from_owned(args, &mut ProcessHeapHandle(&mut p.heap))
                            .map_err(|e| VmError::Unsupported(format!("exception args {e:?}")))
                    })
                    .transpose()?;
                Ok(TopFrame::CurrentArgsWithInfo(args, info.clone()))
            }
        })
        .transpose()?;
    let top = top.as_ref();
    let code_table = raw.code_table;
    let module_index = raw.module_index;
    let native_top = raw.native_top;
    if let Some(runtime) = p.runtime.clone() {
        runtime.with_active_code(|ranges, tables| {
            build_saved_active(
                p,
                raw,
                SavedBuildContext {
                    fallback_modules,
                    top,
                    code_table,
                    module_index,
                    native_top,
                    ranges: Some(ranges),
                    tables: Some(tables),
                },
            )
        })
    } else {
        build_saved_active(
            p,
            raw,
            SavedBuildContext {
                fallback_modules,
                top,
                code_table,
                module_index,
                native_top,
                ranges: None,
                tables: None,
            },
        )
    }
}

struct SavedBuildContext<'a> {
    fallback_modules: &'a [Arc<Module>],
    top: Option<&'a TopFrame>,
    code_table: bool,
    module_index: Option<usize>,
    native_top: Option<usize>,
    ranges: Option<&'a [crate::native_bridge::ModuleRange]>,
    tables: Option<&'a crate::load::CodeTables>,
}

fn build_saved_active(
    p: &mut Process,
    raw: &mut RawTrace,
    context: SavedBuildContext<'_>,
) -> Result<Term, VmError> {
    let SavedBuildContext {
        fallback_modules,
        top,
        code_table,
        module_index,
        native_top,
        ranges,
        tables,
    } = context;
    raw.frames.clear();
    // Upper bound per frame: 4-tuple, 3-element info list, file/line/error_info tuples
    // and the one-pair error_info map; plus the result list and BIF argument list.
    let bif_args = match top {
        Some(TopFrame::Bif { args, .. }) => match args {
            BifArgs::Inline { len, .. } => usize::from(*len),
            BifArgs::Owned(_) => 0,
            BifArgs::TermList(args) => {
                arinsal_term::term_sequence(*args).map_or(0, |terms| terms.len())
            }
        },
        _ => 0,
    };
    // Port of beam_common.c:1258-1277: `fi.needed + 2` per frame, one HAlloc.
    // A located frame is 17 words (file tuple, line tuple, two conses, MFA tuple, list cell).
    let frame_budget =
        (1 + raw.continuations.len() + usize::from(matches!(top, Some(TopFrame::Bif { .. }))))
            .min(raw.depth.max(1));
    let bif_extra = if matches!(top, Some(TopFrame::Bif { .. })) {
        48 + 2 * bif_args
    } else {
        0
    };
    let block_words = frame_budget * 17 + bif_extra;
    let table_module = code_table
        .then_some(module_index)
        .flatten()
        .and_then(|slot| {
            tables
                .and_then(|tables| tables.modules.get(slot).cloned())
                .or_else(|| fallback_modules.get(slot).cloned())
        });
    let native_frame = native_top.and_then(|pc| {
        ranges.and_then(|ranges| crate::native_bridge::stack_frame_in(Some(ranges), pc))
    });
    if raw.module.is_none() {
        raw.module = table_module;
    }
    let mut heap = TraceHeap::with_block(&mut p.heap, block_words);
    let current = raw.module.as_deref();
    let current_frame = if raw.no_current {
        None
    } else if let Some(frame) = native_frame {
        // Port of erts/emulator/beam/utils.c:3430 (`erts_build_mfa_item`), OTP-29.1.1.
        let location = frame.line.and_then(|line| {
            frame
                .file_term
                .or_else(|| {
                    frame
                        .file
                        .as_deref()
                        .and_then(|file| current?.line_file_terms.get(file).copied())
                })
                .map(|file| (file, u64::from(line)))
        });
        Some((
            frame.module_atom,
            frame.function_atom,
            frame.arity,
            location,
        ))
    } else {
        current.map(|current| {
            let (function, arity) = current
                .function_atom_at(raw.ip)
                .unwrap_or((trace_atoms().unknown, 0));
            (
                current.name_atom,
                function,
                arity,
                current.line_term_at(raw.ip),
            )
        })
    };
    if current_frame.is_none() && !raw.no_current && !matches!(top, Some(TopFrame::Bif { .. })) {
        return Err(VmError::Unsupported("stacktrace module".into()));
    }
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
        if items.len() < raw.depth
            && let Some((frame_module, function, arity, location)) = current_frame
        {
            items.push(Item::Plain(Plain {
                module: frame_module,
                function,
                args: Term::small(i64::from(arity)).expect("arity is small"),
                location,
            }));
        }
    } else if !raw.no_current {
        let Some((frame_module, function, arity, location)) = current_frame else {
            return Err(VmError::Unsupported("stacktrace frame".into()));
        };
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
            let Some(resolved) = ranges
                .and_then(|ranges| crate::native_bridge::stack_frame_in(Some(ranges), *address))
            else {
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
                let module = tables
                    .and_then(|tables| tables.modules.get(*index).cloned())
                    .or_else(|| fallback_modules.get(*index).cloned());
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
    fn erts_ftrace_uses_stacktrace_bignum_fields_and_three_tuple() {
        let mut heap = arinsal_term::VecHeap::new();
        let trace = StackTrace::allocate(
            &mut heap,
            StackTraceFields {
                freason: 1,
                pc: 0x1000,
                current: 0,
                depth: 1,
                max_depth: 2,
                trace: &[0x2000],
            },
        )
        .unwrap();
        let mut layout_matches = false;
        trace.with_bignum_digits_mut(|digits| {
            layout_matches = digits == [1, 0x1000, 0, 1, 2, 0x2000, 0];
        });
        assert!(layout_matches);

        let ftrace = Ftrace {
            stack_trace: trace,
            args: Term::small(7).unwrap(),
            error_info: Term::NIL,
        }
        .allocate(&mut heap)
        .unwrap();
        let owned = to_owned(ftrace).unwrap();
        assert!(matches!(&owned, OwnedTerm::Tuple(fields)
            if fields.len() == 3 && matches!(fields.first(), Some(OwnedTerm::BigInt(_)))));
    }

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
