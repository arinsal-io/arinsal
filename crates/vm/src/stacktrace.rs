//! Symbolic stack traces from BEAM continuations.

use crate::{Process, VmError};
use arinsal_bifs::{Class, ProcessHeapHandle};
use arinsal_etf::OwnedTerm;
use arinsal_term::{
    Atom, HeapAlloc, ProcessHeap, Term, TermBuilder, TermKind, from_owned, global_atoms, to_owned,
};
use arinsal_term::{ExternalBinary, MagicRef, Node, WritableBinary};
use std::sync::{Arc, OnceLock};

/// A `current` word with bit 63 set: erts `s->current` that is not a BIF MFA; the current
/// function is looked up from `s->pc` (`erts_lookup_function_info`).
const CURRENT_FROM_PC: u64 = 1 << 63;
/// `struct StackTrace` words after the bignum header: `freason`, `pc`, `current`, and `depth`
/// with `max_depth` sharing one word (two C `int`s), as in erts/emulator/beam/error.h:222-230.
const STACKTRACE_HEADER_WORDS: usize = 4;
/// A `current` of MFA atoms (bit 63 clear) paired with the saved argument list rather than a
/// BIF MFA: the function-clause top frame. Atom indexes stay below 2^31 (`+t` limit), so bit 31
/// of the function atom is spare. erts tells the two apart by `GET_EXC_INDEX(freason)`.
const STACKTRACE_CURRENT_ARGS_MFA: u64 = 1 << 31;

/// `StackTrace.depth` and `StackTrace.max_depth` in one word.
fn stacktrace_depth_word(depth: usize, max_depth: usize) -> u64 {
    (depth as u64 & 0xffff_ffff) | ((max_depth as u64) << 32)
}

/// `(depth, max_depth)` of a `StackTrace` depth word.
fn stacktrace_depths(word: u64) -> (usize, usize) {
    ((word as u32) as usize, (word >> 32) as usize)
}

/// Whether `current` is an MFA paired with its argument list (see
/// [`STACKTRACE_CURRENT_ARGS_MFA`]).
fn current_args_mfa(current: u64) -> bool {
    current & (1 << 63) == 0 && current & STACKTRACE_CURRENT_ARGS_MFA != 0
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
            return;
        }
        // Port of erts/emulator/beam/erl_vm.h (HRelease) with erl_term.h (erts_write_heap_filler),
        // OTP-29.1.1: a tail that cannot be given back (later terms were allocated past it, or
        // the block is a fragment) becomes one filler object, so linear heap scans such as the
        // literal-area check step over it instead of reading stale words.
        let unused = self.capacity - self.used;
        if !self.block.is_null() {
            self.heap
                .write_filler(self.block.wrapping_add(self.used), unused);
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
        // Port of HAllocX in erts/emulator/beam/erl_vm.h: an inline young-heap bump, then
        // erts_heap_alloc in utils.c when the process heap cannot satisfy this HAlloc.
        self.heap
            .alloc_halloc(words)
            .or_else(|| Some(self.heap.heap_fragment(words)))
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

    fn link_external_binary(
        &mut self,
        bin_ref: *mut u64,
        binary: Arc<ExternalBinary>,
    ) -> Result<(), arinsal_term::TermError> {
        HeapAlloc::link_external_binary(self.heap, bin_ref, binary)
    }

    fn supports_external_binary(&self) -> bool {
        true
    }

    fn link_node(&mut self, thing: *mut u64, node: Arc<Node>) {
        HeapAlloc::link_node(self.heap, thing, node);
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
    /// Native function and pc that raised the exception, when it came from native code.
    native_top: Option<usize>,
    continuations: Vec<Continuation>,
    frames: Vec<Term>,
    depth: usize,
    /// The process waits in a BIF trap: its pc is no function, so no frame stands for it.
    no_current: bool,
    /// `StackTrace.pc == NULL` while `current` still names the top MFA.
    no_location: bool,
    /// `current` is an MFA paired with the saved argument list, rather than a BIF MFA.
    current_args_mfa: bool,
}

enum Continuation {
    Native(usize),
}

/// Fields stored in OTP's `struct StackTrace` bignum allocation.
#[cfg(test)]
struct StackTraceFields<'a> {
    freason: u64,
    pc: u64,
    current: u64,
    no_location: bool,
    current_args_mfa: bool,
    depth: usize,
    max_depth: usize,
    trace: &'a [u64],
}

/// One bignum allocation laid out as `struct StackTrace` after its bignum header.
struct StackTrace;

impl StackTrace {
    /// Reserves the exact bignum extent so the CP walk can fill `trace[]` in place.
    fn reserve(
        heap: &mut impl HeapAlloc,
        max_depth: usize,
        freason: u64,
        pc: u64,
        current: u64,
    ) -> Result<Term, VmError> {
        let digits = STACKTRACE_HEADER_WORDS
            .checked_add(max_depth)
            .ok_or_else(|| VmError::Unsupported("stacktrace size".into()))?;
        TermBuilder::new(heap)
            .pos_bignum_prefix(
                digits,
                [freason, pc, current, stacktrace_depth_word(0, max_depth)],
            )
            .map_err(|error| VmError::Unsupported(format!("stacktrace allocation {error:?}")))
    }

    /// Port of `HAlloc` and `struct StackTrace` stores in beam_common.c:880-893.
    #[cfg(test)]
    fn allocate(heap: &mut impl HeapAlloc, fields: StackTraceFields<'_>) -> Result<Term, VmError> {
        if fields.depth > fields.max_depth || fields.trace.len() > fields.max_depth {
            return Err(VmError::Unsupported("stacktrace depth".into()));
        }
        let digits = STACKTRACE_HEADER_WORDS
            .checked_add(fields.max_depth)
            .ok_or_else(|| VmError::Unsupported("stacktrace size".into()))?;
        let freason = fields.freason;
        // erts: no location is `pc == NULL`.
        let pc = if fields.no_location { 0 } else { fields.pc };
        let current = if fields.current_args_mfa {
            fields.current | STACKTRACE_CURRENT_ARGS_MFA
        } else {
            fields.current
        };
        let depth = stacktrace_depth_word(fields.depth, fields.max_depth);
        let trace = fields.trace;
        TermBuilder::new(heap)
            .pos_bignum_fill(digits, |index| match index {
                0 => freason,
                1 => pc,
                2 => current,
                3 => depth,
                _ => trace
                    .get(index - STACKTRACE_HEADER_WORDS)
                    .copied()
                    .unwrap_or(0),
            })
            .map_err(|error| VmError::Unsupported(format!("stacktrace allocation {error:?}")))
    }

    /// Port of the negative StackTrace made by erts/emulator/beam/bif.c:1675-1685,
    /// OTP-29.1.1. A raised stacktrace is already symbolic and lives in `Args`.
    fn allocate_raised(heap: &mut impl HeapAlloc, freason: u64) -> Result<Term, VmError> {
        TermBuilder::new(heap)
            .neg_bignum_fill(STACKTRACE_HEADER_WORDS, |index| {
                if index == 0 { freason } else { 0 }
            })
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
            .tuple3(self.stack_trace, self.args, self.error_info)
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
    CurrentArgs(Term),
    CurrentArgsNoLocation {
        module: Atom,
        function: Atom,
        arity: u8,
        args: Term,
    },
    CurrentArgsInfoTerm(Option<Term>, Term),
    CurrentArgsWithInfo(Option<OwnedTerm>, Box<OwnedTerm>),
}

/// Where the exception was raised: erts' `s->pc` (save_stacktrace's `pc`).
pub(super) struct Current<'a> {
    /// Raising pc inside native code, when the process was executing there.
    pub(super) native_pc: Option<usize>,
    /// Current X registers, which carry live arguments for native BIF failures.
    pub(super) registers: &'a [Term],
    /// The process is scheduled out in the export trap of a BIF call.
    pub(super) trapped: bool,
}

/// Port of erts/emulator/beam/beam_common.c:781 (gather_stacktrace), OTP-29.1.1.
pub(super) fn capture(
    raw: &mut RawTrace,
    class: Option<Class>,
    top: Option<&TopFrame>,
    current: Current<'_>,
    heap: &ProcessHeap,
    depth: usize,
) -> Result<(), VmError> {
    // Port of beam_common.c:600-614 (`erts_inspect_frame`) and beam_common.h:301-315,
    // OTP-29.1.1: continuations are raw CP words resolved back to code metadata.
    let Current {
        native_pc,
        registers,
        trapped,
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
            TopFrame::BifRegisters {
                module,
                function,
                arity,
                info,
            } => {
                let args = registers
                    .get(..*arity)
                    .ok_or_else(|| VmError::Unsupported("native BIF argument registers".into()))?;
                Ok(StoredTopFrame::Bif {
                    module: *module,
                    function: *function,
                    args: BifArgs::from_terms(args)?.detached()?,
                    info: *info,
                })
            }
            TopFrame::CurrentArgs(args) => Ok(StoredTopFrame::CurrentArgs(*args)),
            TopFrame::CurrentArgsNoLocation {
                module,
                function,
                arity,
                args,
            } => Ok(StoredTopFrame::CurrentArgsNoLocation {
                module: *module,
                function: *function,
                arity: *arity,
                args: *args,
            }),
            TopFrame::CurrentArgsInfoTerm(args, info) => {
                Ok(StoredTopFrame::CurrentArgsInfoTerm(*args, *info))
            }
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
    raw.no_location = false;
    raw.current_args_mfa = matches!(top, Some(TopFrame::CurrentArgsNoLocation { .. }));
    // The current function comes from the raising pc (`erts_lookup_function_info`).
    raw.depth = depth.max(1);
    raw.continuations.clear();
    raw.continuations.reserve(raw.depth.min(16));
    raw.native_top = None;
    raw.no_current = trapped;
    // erts' single `prev`: the raising pc, compared with each return address.
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
        } else {
            raw.native_top = Some(pc);
            // Port of erts/emulator/beam/beam_common.c:791-835 (`gather_stacktrace`),
            // OTP-29.1.1: the current native PC seeds the same duplicate check as `rp->i`.
            previous_native = Some(pc);
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
        if let Some(kind) = crate::trace::TraceFrameKind::of(raw_address) {
            // Port of erts/emulator/beam/beam_common.c:803-815 (save_stacktrace), OTP-29.1.1:
            // trace frames are skipped; the caller's own continuation follows the frame.
            index += 1 + kind.data_words();
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
                push_frame(raw, Continuation::Native(raw_address - 1));
            }
            index += 1;
            continue;
        }
        index += 1;
    }
    Ok(())
}

/// Preserve the supplied `raise/3` trace in Args behind erts' negative StackTrace marker.
///
/// Port of erts/emulator/beam/bif.c (`raise_3`), OTP-29.1.1.
pub(super) fn save_explicit(
    p: &mut Process,
    class: Class,
    trace: Term,
    backtrace_depth: usize,
) -> Result<Term, VmError> {
    let freason = class_to_freason(Some(class));
    let args = normalize_raise_trace(p, trace, backtrace_depth)?;
    let mut heap = TraceHeap::new(&mut p.heap);
    let stack_trace = StackTrace::allocate_raised(&mut heap, freason)?;
    Ftrace {
        stack_trace,
        args,
        error_info: Term::NIL,
    }
    .allocate(&mut heap)
}

// Port of erts/emulator/beam/bif.c (`raise_3`), OTP-29.1.1: copy only when a legacy
// frame needs conversion or the runtime backtrace limit truncates the supplied trace.
fn normalize_raise_trace(
    p: &mut Process,
    trace: Term,
    backtrace_depth: usize,
) -> Result<Term, VmError> {
    // `raise/3` already validated the list; walk it in place, copying only when a frame needs
    // converting or the backtrace limit truncates it (bif.c, `raise_3`).
    if trace == Term::NIL {
        return Ok(trace);
    }
    let max_depth = runtime_backtrace_depth(p, backtrace_depth);
    let frames = arinsal_term::term_sequence_frames(trace)
        .ok_or_else(|| VmError::Unsupported("raise stacktrace list".into()))?;
    let length = frames.len();
    let mut must_copy = false;
    for frame in &frames {
        let fields = arinsal_term::term_sequence_small(*frame)
            .ok_or_else(|| VmError::Unsupported("raise stacktrace frame".into()))?;
        match fields.as_slice() {
            [fun, _args] if fun.classify() == TermKind::Fun => must_copy = true,
            [module, function, _arity_or_args]
                if module.classify() == TermKind::Atom && function.classify() == TermKind::Atom =>
            {
                must_copy = true;
            }
            _ => {}
        }
    }
    let depth = if max_depth < length {
        max_depth.max(1)
    } else {
        length
    };
    must_copy |= max_depth < length;
    if !must_copy {
        return Ok(trace);
    }
    let mut heap = TraceHeap::new(&mut p.heap);
    let mut normalized = Vec::with_capacity(depth);
    for frame in frames.iter().take(depth) {
        let fields = arinsal_term::term_sequence(*frame)
            .ok_or_else(|| VmError::Unsupported("raise stacktrace frame".into()))?;
        let converted = match fields.as_slice() {
            [fun, args] if fun.classify() == TermKind::Fun => {
                Some([*fun, *args, Term::NIL].to_vec())
            }
            [module, function, arity_or_args]
                if module.classify() == TermKind::Atom && function.classify() == TermKind::Atom =>
            {
                Some(vec![*module, *function, *arity_or_args, Term::NIL])
            }
            _ => None,
        };
        normalized.push(if let Some(fields) = converted {
            TermBuilder::new(&mut heap)
                .tuple(&fields)
                .map_err(|error| {
                    VmError::Unsupported(format!("raise stacktrace tuple {error:?}"))
                })?
        } else {
            *frame
        });
    }
    TermBuilder::new(&mut heap)
        .list_from_slice(&normalized)
        .map_err(|error| VmError::Unsupported(format!("raise stacktrace list {error:?}")))
}

fn push_frame(raw: &mut RawTrace, continuation: Continuation) {
    raw.continuations.push(continuation);
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
/// Port of erts/emulator/beam/beam_common.c:880-1010 (`save_stacktrace`), OTP-29.1.1.
/// The trace block is sized and allocated before the stack walk, then filled in place.
pub(super) fn save_stacktrace(
    p: &mut Process,
    input: StackTraceSave<'_>,
    registers: Option<&[Term]>,
) -> Result<Term, VmError> {
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
    // Consumed here: it describes the one exception being saved.
    if let Some(cold) = p.cold.as_mut() {
        cold.apply_frame_released = 0;
    }
    let (native_top, previous_native) = match native_pc {
        Some(pc) if pc & arinsal_beamasm::module::RETURN_SITE_TAG != 0 => {
            let address = pc & !arinsal_beamasm::module::RETURN_SITE_TAG;
            (Some(address.wrapping_sub(1)), Some(address))
        }
        // Port of erts/emulator/beam/beam_common.c:791-835 (`gather_stacktrace`),
        // OTP-29.1.1: the raw `pc` seeds the duplicate check before the stack walk.
        Some(pc) => (Some(pc), Some(pc)),
        None => (None, None),
    };
    // Port of erts/emulator/beam/beam_common.c:880-930 (`save_stacktrace`), OTP-29.1.1:
    // `StackTrace` is the bignum itself and ftrace is its three-element tuple. The current
    // frame and continuations remain code addresses until `build_stacktrace` resolves them.
    let bif_top = top.is_some_and(SaveTop::is_bif);
    let max_depth = depth.saturating_sub(1);
    let current = match top {
        Some(SaveTop::Live(TopFrame::CurrentArgsNoLocation {
            module, function, ..
        })) => pack_bif_mfa(*module, *function) | STACKTRACE_CURRENT_ARGS_MFA,
        Some(top) if let Some((module, function)) = top.bif_mfa() => pack_bif_mfa(module, function),
        _ => CURRENT_FROM_PC,
    };
    let pc = if bif_top {
        0
    } else {
        native_top
            .and_then(|pc| u64::try_from(pc).ok())
            .unwrap_or(0)
    };
    let native_top_word = native_top
        .map(u64::try_from)
        .transpose()
        .map_err(|_| VmError::Unsupported("stacktrace pc".into()))?;
    // Port of erts/emulator/beam/beam_common.c:880-1045 (`save_stacktrace`), OTP-29.1.1: the
    // StackTrace bignum, the optional `error_info` map and arglist, and the ftrace tuple are
    // separate `HAlloc`s on the process heap (young heap, heap fragment when it is full).
    let (stack_trace, ftrace) = {
        let mut heap = TraceHeap::new(&mut p.heap);
        let stack_trace = StackTrace::reserve(&mut heap, max_depth, freason, pc, current)?;
        let (args, error_info) = save_ftrace_values(&mut heap, top, registers.unwrap_or(&p.x))?;
        let ftrace = Ftrace {
            stack_trace,
            args,
            error_info,
        }
        .allocate(&mut heap)?;
        (stack_trace, ftrace)
    };
    stack_trace
        .with_bignum_digits_mut(|digits| {
            let mut offset = 0;
            if bif_top
                && max_depth > 0
                && let Some(pc) = native_top_word
            {
                digits[STACKTRACE_HEADER_WORDS] = pc;
                offset = 1;
            }
            let end = STACKTRACE_HEADER_WORDS + max_depth;
            let gathered = gather_native_continuations(
                p,
                &mut digits[STACKTRACE_HEADER_WORDS + offset..end],
                previous_native,
            );
            let depth = offset + gathered;
            digits[3] = stacktrace_depth_word(depth, max_depth);
            depth
        })
        .ok_or_else(|| VmError::Unsupported("stacktrace bignum".into()))?;
    Ok(ftrace)
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
}

impl SaveTop<'_> {
    fn is_bif(self) -> bool {
        matches!(
            self,
            Self::Live(TopFrame::Bif { .. }) | Self::Live(TopFrame::BifRegisters { .. })
        )
    }

    fn bif_mfa(&self) -> Option<(Atom, Atom)> {
        match self {
            Self::Live(TopFrame::Bif {
                module, function, ..
            })
            | Self::Live(TopFrame::BifRegisters {
                module, function, ..
            }) => Some((*module, *function)),
            _ => None,
        }
    }
}

/// `erts_backtrace_depth`: a plain global int in erts, read without ordering; nothing else is
/// published with it.
pub(super) fn runtime_backtrace_depth(p: &Process, fallback: usize) -> usize {
    p.runtime.as_ref().map_or(fallback, |runtime| {
        runtime
            .backtrace_depth
            .load(std::sync::atomic::Ordering::Relaxed)
    })
}

fn save_ftrace_values(
    heap: &mut TraceHeap<'_>,
    top: Option<SaveTop<'_>>,
    registers: &[Term],
) -> Result<(Term, Term), VmError> {
    let args = match top {
        Some(SaveTop::Live(TopFrame::Bif { args, .. })) => args.to_term(heap)?,
        Some(SaveTop::Live(TopFrame::BifRegisters { arity, .. })) => {
            let values = registers
                .get(..*arity)
                .ok_or_else(|| VmError::Unsupported("native BIF argument registers".into()))?;
            TermBuilder::new(heap)
                .list_from_slice(values)
                .map_err(|error| VmError::Unsupported(format!("exception args {error:?}")))?
        }
        Some(SaveTop::Live(TopFrame::CurrentArgs(args)))
        | Some(SaveTop::Live(TopFrame::CurrentArgsNoLocation { args, .. }))
        | Some(SaveTop::Live(TopFrame::CurrentArgsWithInfo(Some(args), _)))
        | Some(SaveTop::Live(TopFrame::CurrentArgsInfoTerm(Some(args), _))) => *args,
        Some(SaveTop::Live(TopFrame::CurrentArgsWithInfo(None, _)))
        | Some(SaveTop::Live(TopFrame::CurrentArgsInfoTerm(None, _)))
        | None => Term::atom(arinsal_term::atoms::TRUE),
    };
    let info_map = match top {
        Some(SaveTop::Live(TopFrame::Bif { module, info, .. })) => {
            bif_error_info(heap, *module, *info)?
        }
        Some(SaveTop::Live(TopFrame::BifRegisters { module, info, .. })) => {
            bif_error_info(heap, *module, *info)?
        }
        Some(SaveTop::Live(TopFrame::CurrentArgsInfoTerm(_, info))) => Some(*info),
        Some(SaveTop::Live(TopFrame::CurrentArgsWithInfo(_, info))) => Some(
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

fn pack_bif_mfa(module: Atom, function: Atom) -> u64 {
    (u64::from(module.0) << 32) | u64::from(function.0)
}

/// `gather_stacktrace` over a stack of native frames only: each word costs the `is_CP` test,
/// a CP additionally the trace-frame and exit-bridge compares and the duplicate check.
// Port of erts/emulator/beam/beam_common.c:782-841 (gather_stacktrace), OTP-29.1.1.
fn gather_native_continuations(
    p: &Process,
    pcs: &mut [u64],
    previous_native: Option<usize>,
) -> usize {
    let limit = pcs.len();
    if limit == 0 {
        return 0;
    }
    // erts records `beam_normal_exit` like any CP and `build_stacktrace` drops it because no
    // function contains it; the bridge is skipped here instead, which yields the same frames.
    let bridge = arinsal_beamasm::rt::arinsal_enter_native_return as *const () as usize;
    let words = p.heap.stack_raw_words();
    let mut previous_cp = previous_native.unwrap_or(usize::MAX);
    let mut count = 0usize;
    let mut index = 0usize;
    while let Some(&word) = words.get(index) {
        index += 1;
        if !arinsal_term::is_cp(word) {
            continue;
        }
        let raw_address = word as usize;
        if let Some(kind) = crate::trace::TraceFrameKind::of(raw_address) {
            index = index.saturating_add(kind.data_words());
        } else if raw_address != previous_cp && raw_address != bridge {
            previous_cp = raw_address;
            pcs[count] = raw_address.wrapping_sub(1) as u64;
            count += 1;
            if count == limit {
                break;
            }
        }
    }
    count
}

/// The generic exit code of a class (`EXC_ERROR`, `EXC_EXIT`, `EXC_THROWN`), zero for none.
// Port of erts/emulator/beam/error.h (EXC_ERROR, EXC_EXIT, EXC_THROWN), OTP-29.1.1.
pub(crate) fn class_to_freason(class: Option<Class>) -> u64 {
    use arinsal_beamasm::exc::{EXC_ERROR, EXC_EXIT, EXC_THROWN};
    match class {
        None => 0,
        Some(Class::Error) => EXC_ERROR,
        Some(Class::Exit) => EXC_EXIT,
        Some(Class::Throw) => EXC_THROWN,
    }
}

/// The class of an exit code (`GET_EXC_CLASS`), `None` for no exception.
pub(crate) fn class_from_freason(value: u64) -> Option<Class> {
    use arinsal_beamasm::exc::{EXTAG_EXIT, EXTAG_THROWN, exc_class};
    if value == 0 {
        return None;
    }
    Some(match exc_class(value) {
        EXTAG_EXIT => Class::Exit,
        EXTAG_THROWN => Class::Throw,
        _ => Class::Error,
    })
}

/// Whether the saved `ftrace` tuple's `pc`, `current` or `trace[]` names `module`.
///
/// Port of erts/emulator/beam/beam_bif_load.c:1191-1213 (`check_process_code`), OTP-29.1.1.
/// `pc` and each `trace[]` entry are an interpreter continuation (bit 63, module index in
/// the high half) or a native address. `current` is that continuation, or a BIF MFA packed
/// from two atoms (bit 63 clear): the atom pair is not a pointer into the caller's code,
/// matching `ErtsInArea` on a BIF `ErtsCodeMFA*` that lives in the BIF's own module.
pub(crate) fn saved_trace_names_code(
    term: Term,
    module: usize,
    in_native: impl Fn(usize) -> bool,
) -> bool {
    let Some(fields) = arinsal_term::term_sequence_small(term) else {
        return false;
    };
    if fields.len() != 3 {
        return false;
    }
    fields[0]
        .with_bignum_digits_mut(|digits| digits_name_code(digits, module, &in_native))
        .unwrap_or(false)
}

fn digits_name_code(digits: &[u64], module: usize, in_native: &impl Fn(usize) -> bool) -> bool {
    if digits.len() < STACKTRACE_HEADER_WORDS {
        return false;
    }
    let indexed =
        |word: u64| word & (1 << 63) != 0 && ((word & !(1 << 63)) >> 32) as usize == module;
    let native = |word: u64| {
        word != 0 && word & (1 << 63) == 0 && usize::try_from(word).is_ok_and(in_native)
    };
    if indexed(digits[1]) || native(digits[1]) || indexed(digits[2]) {
        return true;
    }
    let (depth, max_depth) = stacktrace_depths(digits[3]);
    if depth > max_depth {
        return false;
    }
    let end = STACKTRACE_HEADER_WORDS.saturating_add(depth);
    if digits.len() < end {
        return false;
    }
    digits[STACKTRACE_HEADER_WORDS..end]
        .iter()
        .any(|word| indexed(*word) || native(*word))
}

fn ftrace_raw(term: Term) -> Option<RawTrace> {
    let fields = arinsal_term::term_sequence_small(term)?;
    if fields.len() != 3 {
        return None;
    }
    fields[0]
        .with_bignum_digits_mut(|digits| raw_from_stacktrace_digits(digits, fields[1], fields[2]))
        .flatten()
}

/// Reads `StackTrace.pc == NULL` without decoding its continuation array.
// Port of erts/emulator/beam/beam_common.c:1217-1227 (`build_stacktrace`), OTP-29.1.1.
fn raw_no_location(term: Term) -> Option<bool> {
    let fields = arinsal_term::term_sequence_small(term)?;
    if fields.len() != 3 {
        return None;
    }
    // A function-clause trace whose class `raw_raise` rewrote: erts' `pc == NULL` with a
    // `freason` that no longer names `function_clause`.
    fields[0].with_bignum_digits_mut(|digits| {
        digits.len() >= STACKTRACE_HEADER_WORDS && digits[1] == 0 && current_args_mfa(digits[2])
    })
}

// Port of erts/emulator/beam/beam_common.c (get_args_from_exc, get_error_info_from_exc,
// build_stacktrace), OTP-29.1.1: retain the heap terms that erts_build_mfa_item attaches directly.
fn raw_from_stacktrace_digits(digits: &[u64], args: Term, error_info: Term) -> Option<RawTrace> {
    if digits.len() < STACKTRACE_HEADER_WORDS {
        return None;
    }
    let freason = digits[0];
    let pc = digits[1];
    let current_args_mfa = current_args_mfa(digits[2]);
    let current = digits[2]
        & !(if current_args_mfa {
            STACKTRACE_CURRENT_ARGS_MFA
        } else {
            0
        });
    let no_location = current_args_mfa && pc == 0;
    let (count, max_depth) = stacktrace_depths(digits[3]);
    if count > max_depth || digits.len() < STACKTRACE_HEADER_WORDS + count {
        return None;
    }
    let top = if current_args_mfa {
        if current & (1 << 63) != 0 || !matches!(args.classify(), TermKind::List | TermKind::Nil) {
            return None;
        }
        let module = Atom((current >> 32) as u32);
        let function = Atom(current as u32);
        let arity = u8::try_from(arinsal_term::term_sequence_small(args)?.len()).ok()?;
        Some(StoredTopFrame::CurrentArgsNoLocation {
            module,
            function,
            arity,
            args,
        })
    } else if args == Term::atom(arinsal_term::atoms::TRUE) {
        if current & (1 << 63) == 0 {
            return None;
        }
        term_error_info_map(error_info).map(|info| StoredTopFrame::CurrentArgsInfoTerm(None, info))
    } else if current & (1 << 63) == 0 {
        let module = Atom((current >> 32) as u32);
        let function = Atom(current as u32);
        if !matches!(args.classify(), TermKind::List | TermKind::Nil) {
            return None;
        }
        let bif_args = BifArgs::TermList(args);
        let info = term_error_info(error_info);
        Some(StoredTopFrame::Bif {
            module,
            function,
            args: bif_args,
            info,
        })
    } else {
        let args = (args != Term::atom(arinsal_term::atoms::TRUE)).then_some(args);
        let info = term_error_info_map(error_info);
        match (args, info) {
            (Some(args), Some(info)) => Some(StoredTopFrame::CurrentArgsInfoTerm(Some(args), info)),
            (Some(args), None) => Some(StoredTopFrame::CurrentArgs(args)),
            (None, Some(info)) => Some(StoredTopFrame::CurrentArgsInfoTerm(None, info)),
            (None, None) => None,
        }
    };
    let mut trace_start = STACKTRACE_HEADER_WORDS;
    let current_is_bif = matches!(top, Some(StoredTopFrame::Bif { .. }));
    let native_top = (pc != 0 && pc & (1 << 63) == 0)
        .then(|| usize::try_from(pc).ok())
        .flatten()
        .or_else(|| {
            if !current_is_bif || count == 0 || digits[STACKTRACE_HEADER_WORDS] & (1 << 63) != 0 {
                return None;
            }
            trace_start += 1;
            usize::try_from(digits[STACKTRACE_HEADER_WORDS]).ok()
        });
    let mut continuations =
        Vec::with_capacity(count.saturating_sub(trace_start - STACKTRACE_HEADER_WORDS));
    for word in &digits[trace_start..STACKTRACE_HEADER_WORDS + count] {
        continuations.push(Continuation::Native(usize::try_from(*word).ok()?));
    }
    Some(RawTrace {
        class: class_from_freason(freason),
        top,
        native_top,
        continuations,
        depth: count.saturating_add(1),
        no_location,
        current_args_mfa,
        ..RawTrace::default()
    })
}

fn term_error_info_map(value: Term) -> Option<Term> {
    let entries = arinsal_term::term_sequence_small(value)?;
    if entries.len() != 1 || value.classify() != TermKind::List {
        return None;
    }
    let pair = arinsal_term::term_sequence_small(entries[0])?;
    (pair.len() == 2 && pair[0] == Term::atom(trace_atoms().error_info)).then_some(pair[1])
}

fn term_error_info(value: Term) -> BifErrorInfo {
    term_error_info_map(value).map_or(BifErrorInfo::None, BifErrorInfo::Map)
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
// Port of erts/emulator/beam/beam_common.c:1131-1146 (`get_freason_ptr_from_exc`) as read by
// `erts_sanitize_freason`, OTP-29.1.1: the class is `StackTrace.freason`, element 1 of the
// ftrace tuple; the trace itself is not decoded.
pub(super) fn raw_class(_p: &Process, term: Term) -> Option<Class> {
    saved_freason_word(term)?
        .with_bignum_digits_mut(|digits| digits.first().copied())
        .flatten()
        .and_then(class_from_freason)
}

/// Args carried by the negative StackTrace used for an explicit `raise/3` trace.
pub(super) fn raised_args(term: Term) -> Option<Term> {
    let tuple = arinsal_term::raw::Tuple::try_from(term).ok()?;
    (tuple.arity() == 3 && tuple.get(0)?.is_negative_bignum()).then(|| tuple.get(1))?
}

/// Element 1 of a 3-tuple ftrace: the StackTrace bignum whose first digit is
/// `StackTrace.freason`. Read in place through the tuple header, as `tuple_val` does.
#[inline]
fn saved_freason_word(term: Term) -> Option<Term> {
    let tuple = arinsal_term::raw::Tuple::try_from(term).ok()?;
    if tuple.arity() != 3 {
        return None;
    }
    tuple.get(0)
}

/// Port of erts/emulator/beam/beam_common.c:1131-1178 (`get_freason_ptr_from_exc`,
/// `raw_raise`), OTP-29.1.1: the class goes straight into `StackTrace.freason`, found as
/// element 1 of the ftrace tuple. Anything else (NIL) has no saved class to update.
pub(super) fn set_raw_class(_p: &mut Process, term: Term, class: Class) -> bool {
    // raw_raise stores the class in the saved trace after EXF_SAVETRACE is cleared.
    let code = class_to_freason(Some(class)) & !arinsal_beamasm::exc::EXF_SAVETRACE;
    let Some(word) = saved_freason_word(term) else {
        return false;
    };
    word.with_bignum_digits_mut(|digits| {
        let Some(freason) = digits.first_mut() else {
            return false;
        };
        *freason = code;
        // erts loses the `function_clause` index here, so `build_stacktrace` stops looking
        // the location up; the function-clause trace marks that with `pc == NULL`.
        if digits.len() >= STACKTRACE_HEADER_WORDS && current_args_mfa(digits[2]) {
            digits[1] = 0;
        }
        true
    })
    .unwrap_or(false)
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
    /// An `error_info` map already stored in the saved ftrace tuple.
    Map(Term),
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
    /// A native BIF frame whose arguments are still live in the scheduler X registers.
    BifRegisters {
        module: Atom,
        function: Atom,
        arity: usize,
        info: BifErrorInfo,
    },
    CurrentArgs(Term),
    /// Function-clause top frame resolved from its native function pointer, without a source line.
    CurrentArgsNoLocation {
        module: Atom,
        function: Atom,
        arity: u8,
        args: Term,
    },
    CurrentArgsWithInfo(Option<Term>, Box<OwnedTerm>),
    /// `erlang:error/2,3` read straight from the argument registers: the supplied argument
    /// term and validated `error_info` map stay heap terms, as in erts' `c_p->ftrace`. Only
    /// the native exception resolver builds it; nothing collects before `save_stacktrace`
    /// copies the two words.
    CurrentArgsInfoTerm(Option<Term>, Term),
}

/// Handler address of a stack word that is a catch tag of native code.
pub(crate) fn native_catch_address(term: Term) -> Option<usize> {
    if term.tagged_word() & 63 != 0x1b || term.classify() != TermKind::Catch {
        return None;
    }
    // SAFETY: CATCH is an immediate and carries no heap pointer.
    let payload = unsafe { term.raw_bits() } >> 6;
    if payload >> 32 != 0 {
        return None;
    }
    crate::native_bridge::native_catch(u32::try_from(payload).ok()?)
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
        BifErrorInfo::Map(map) => return Ok(Some(map)),
        BifErrorInfo::Plain => None,
        BifErrorInfo::Cause(cause) => Some(cause),
    };
    let atoms = trace_atoms();
    let Some(&(_, format_module)) = atoms.format_modules.iter().find(|(bif, _)| *bif == module)
    else {
        return Ok(None);
    };
    let mut builder = TermBuilder::new(heap);
    // Port of beam_common.c (`MAP1`/`MAP2` in save_stacktrace), OTP-29.1.1:
    // both key tuples are already sorted, so constructing a generic map from pairs would
    // sort and deduplicate keys that erts emits in a fixed order.
    let map = if let Some(cause) = cause {
        let keys = builder
            .tuple(&[Term::atom(atoms.cause), Term::atom(atoms.module)])
            .map_err(|e| VmError::Unsupported(format!("BIF error_info keys {e:?}")))?;
        builder.flatmap_with_key_tuple(keys, &[cause, Term::atom(format_module)])
    } else {
        let keys = builder
            .tuple(&[Term::atom(atoms.module)])
            .map_err(|e| VmError::Unsupported(format!("BIF error_info keys {e:?}")))?;
        builder.flatmap_with_key_tuple(keys, &[Term::atom(format_module)])
    }
    .map_err(|e| VmError::Unsupported(format!("BIF error info {e:?}")))?;
    Ok(Some(map))
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

/// Port of erts/emulator/beam/utils.c:3430 (`erts_build_mfa_item`), OTP-29.1.1.
/// Saved `error/2,3` arguments are shown only when the term is a list or nil;
/// every other sentinel means the frame's actual function arity.
fn mfa_arity_or_args(args: Term, arity: u8) -> Term {
    if matches!(args.classify(), TermKind::List | TermKind::Nil) {
        args
    } else {
        Term::small(i64::from(arity)).expect("function arity is small")
    }
}

/// Port of erts/emulator/beam/beam_common.c:781 (gather_stacktrace), OTP-29.1.1.
/// A continuation points after the call; the preceding instruction owns its line.
pub(super) fn build(
    p: &mut Process,
    top: Option<&TopFrame>,
    depth: usize,
) -> Result<Term, VmError> {
    build_with_reserve(p, top, depth, None)
}

/// Build the live `process_info` stacktrace using `erts_build_stacktrace`'s per-frame heap
/// reservations and the caller's remaining result reserve.
pub(super) fn build_for_process_info(
    p: &mut Process,
    depth: usize,
    reserve: &mut usize,
) -> Result<Term, VmError> {
    build_with_reserve(p, None, depth, Some(reserve))
}

fn build_with_reserve(
    p: &mut Process,
    top: Option<&TopFrame>,
    depth: usize,
    reserve: Option<&mut usize>,
) -> Result<Term, VmError> {
    // A process inside a native BIF call raises at that call's pc, as in `exceptions.rs`.
    let trapped = p.heap.abi.i as usize == crate::bif_traps::bif_export_trap_pc();
    let native_pc = p.native_call_pc;
    let native_pc = if trapped {
        None
    } else if native_pc != 0 && crate::native_bridge::is_native_function_at(native_pc) {
        Some(native_pc)
    } else {
        // A process suspended inside native code: the current function comes from its
        // code address (`c_p->i`).
        p.native_pc()
            .or_else(|| Some(p.heap.abi.i as usize).filter(|&pc| pc != 0))
            .filter(|&pc| crate::native_bridge::is_native_function_at(pc))
    };
    let mut raw = RawTrace::default();
    capture(
        &mut raw,
        None,
        top,
        Current {
            native_pc,
            registers: &p.x,
            trapped,
        },
        &p.heap,
        depth,
    )?;
    if let Some(reserve) = reserve {
        build_saved_with_reserve(p, &mut raw, Some(reserve))
    } else {
        build_saved(p, &mut raw)
    }
}

/// Port of erts/emulator/beam/beam_common.c:1205 (build_stacktrace), OTP-29.1.1.
/// The frame lookups of one trace (`FunctionInfo` in `global.h`).
type FrameScratch = smallvec::SmallVec<[PreparedFrame; 10]>;

#[derive(Clone, Copy)]
struct PreparedFrame {
    module: Atom,
    function: Atom,
    arity: u8,
    location: Option<(Term, u64)>,
    /// `FunctionInfo.needed` (`erts_build_mfa_item` words), before the list cell.
    needed: usize,
}

struct PreparedFrames {
    frames: usize,
    words: usize,
    bif: Option<PreparedBif>,
}

#[derive(Clone, Copy)]
struct PreparedBif {
    module: Atom,
    function: Atom,
    args: Term,
    error_info: Option<Term>,
}

enum FramePrep {
    /// Explicit traces still use `build_saved`.
    Fallback,
    Ready(PreparedFrames),
}

/// Port of beam_common.c:1205 (`build_stacktrace`), OTP-29.1.1.
///
/// Lookups land in one `ERTS_ALC_T_TMP` array. The symbolic list is one `HAlloc`.
/// `None` means the saved frame metadata needs the general builder.
pub(super) fn build_direct(p: &mut Process, term: Term) -> Option<Result<Term, VmError>> {
    if raw_no_location(term) == Some(true) {
        // `build_direct` only sees the raw pc and would restore its source line. OTP's
        // function_clause path clears `s->pc` while retaining the current MFA and args.
        return None;
    }
    let fields = arinsal_term::term_sequence_small(term)?;
    if fields.len() != 3 || fields[0].is_negative_bignum() {
        return None;
    }
    let stack_trace = fields[0];
    let bif_top = stack_trace.with_bignum_digits_mut(|digits| {
        digits
            .get(2)
            .is_some_and(|current| current & (1 << 63) == 0)
    })?;
    let error_info = if fields[2] == Term::NIL {
        None
    } else {
        Some(term_error_info_map(fields[2])?)
    };
    if !bif_top && (fields[1] != Term::atom(arinsal_term::atoms::TRUE) || error_info.is_some()) {
        return None;
    }
    if bif_top && !matches!(fields[1].classify(), TermKind::List | TermKind::Nil) {
        return None;
    }
    let mut scratch = FrameScratch::new();
    let prepared = match p.runtime.as_ref() {
        Some(runtime) => runtime.with_active_code(|ranges, _| {
            stack_trace.with_bignum_digits_mut(|digits| {
                if bif_top {
                    prepare_bif_frames(digits, Some(ranges), fields[1], error_info, &mut scratch)
                } else {
                    prepare_frames(digits, Some(ranges), &mut scratch)
                }
            })
        }),
        None if bif_top => None,
        None => {
            stack_trace.with_bignum_digits_mut(|digits| prepare_frames(digits, None, &mut scratch))
        }
    }?;
    match prepared {
        Ok(FramePrep::Fallback) => None,
        Ok(FramePrep::Ready(ready)) => Some(cons_prepared(p, ready, &scratch)),
        Err(error) => Some(Err(error)),
    }
}

// Port of erts/emulator/beam/beam_common.c:1205-1267 (`build_stacktrace`), OTP-29.1.1.
fn prepare_frames(
    digits: &[u64],
    ranges: Option<&[crate::native_bridge::ModuleRange]>,
    block: &mut FrameScratch,
) -> Result<FramePrep, VmError> {
    if digits.len() < STACKTRACE_HEADER_WORDS {
        return Ok(FramePrep::Fallback);
    }
    let pc = digits[1];
    let current = digits[2];
    let (count, max_depth) = stacktrace_depths(digits[3]);
    let depth = count.saturating_add(1);
    if count > max_depth || digits.len() < STACKTRACE_HEADER_WORDS + count {
        return Ok(FramePrep::Fallback);
    }
    if current & (1 << 63) == 0 {
        return Ok(FramePrep::Fallback);
    }
    if pc == 0 {
        return Ok(FramePrep::Fallback);
    }
    let mut frames = 0usize;
    let mut words = 0usize;
    let frame = crate::native_bridge::stack_frame_in(ranges, usize::try_from(pc).unwrap_or(0)).map(
        |frame| {
            let location = frame.location;
            (
                frame.module_atom,
                frame.function_atom,
                frame.arity,
                location,
            )
        },
    );
    if let Some((module, function, arity, location)) = frame {
        words += write_frame(block, module, function, arity, location) + 2;
        frames += 1;
    }
    if frames == 0 {
        return Ok(FramePrep::Fallback);
    }
    for word in &digits[STACKTRACE_HEADER_WORDS..STACKTRACE_HEADER_WORDS + count] {
        if frames >= depth {
            break;
        }
        let Some(address) = usize::try_from(*word).ok() else {
            continue;
        };
        let Some(resolved) = crate::native_bridge::stack_frame_in(ranges, address) else {
            continue;
        };
        words += write_frame(
            block,
            resolved.module_atom,
            resolved.function_atom,
            resolved.arity,
            resolved.location,
        ) + 2;
        frames += 1;
    }
    Ok(FramePrep::Ready(PreparedFrames {
        frames,
        words,
        bif: None,
    }))
}

/// Port of beam_common.c (`build_stacktrace`), OTP-29.1.1.
/// A BIF MFA is already stored in `current`; the first saved continuation is its caller.
fn prepare_bif_frames(
    digits: &[u64],
    ranges: Option<&[crate::native_bridge::ModuleRange]>,
    args: Term,
    error_info: Option<Term>,
    block: &mut FrameScratch,
) -> Result<FramePrep, VmError> {
    if digits.len() < STACKTRACE_HEADER_WORDS {
        return Ok(FramePrep::Fallback);
    }
    let (pc, current) = (digits[1], digits[2]);
    let (count, max_depth) = stacktrace_depths(digits[3]);
    if pc != 0
        || current & CURRENT_FROM_PC != 0
        || current_args_mfa(current)
        || count > max_depth
        || digits.len() < STACKTRACE_HEADER_WORDS + count
    {
        return Ok(FramePrep::Fallback);
    }
    let module = Atom((current >> 32) as u32);
    let function = Atom(current as u32);
    if module.0 == 0 || function.0 == 0 {
        return Ok(FramePrep::Fallback);
    }
    block.clear();
    let mut frames = 0usize;
    let mut words = 0usize;
    let mut first_continuation = STACKTRACE_HEADER_WORDS;
    if count > 0 {
        let word = digits[STACKTRACE_HEADER_WORDS];
        let Some(frame) = usize::try_from(word)
            .ok()
            .and_then(|address| crate::native_bridge::stack_frame_in(ranges, address))
        else {
            return Ok(FramePrep::Fallback);
        };
        words += write_frame(
            block,
            frame.module_atom,
            frame.function_atom,
            frame.arity,
            frame.location,
        ) + 2;
        frames += 1;
        first_continuation += 1;
    }
    for word in &digits[first_continuation..STACKTRACE_HEADER_WORDS + count] {
        let Some(frame) = usize::try_from(*word)
            .ok()
            .and_then(|address| crate::native_bridge::stack_frame_in(ranges, address))
        else {
            continue;
        };
        words += write_frame(
            block,
            frame.module_atom,
            frame.function_atom,
            frame.arity,
            frame.location,
        ) + 2;
        frames += 1;
    }
    Ok(FramePrep::Ready(PreparedFrames {
        frames,
        words,
        bif: Some(PreparedBif {
            module,
            function,
            args,
            error_info,
        }),
    }))
}

fn write_frame(
    frames: &mut FrameScratch,
    module: Atom,
    function: Atom,
    arity: u8,
    location: Option<(Term, u64)>,
) -> usize {
    // Port of erts/emulator/beam/beam_common.c:1236-1278 (`build_stacktrace`): retain the
    // lookup result and the `needed` field used by the single heap-size pass.
    let (frame, needed) = prepare_frame(module, function, arity, location);
    frames.push(frame);
    needed
}

// Port of erts/emulator/beam/beam_common.c:1205-1267 (`build_stacktrace`), OTP-29.1.1.
fn prepare_frame(
    module: Atom,
    function: Atom,
    arity: u8,
    location: Option<(Term, u64)>,
) -> (PreparedFrame, usize) {
    let needed = if location.is_some() { 15 } else { 5 };
    (
        PreparedFrame {
            module,
            function,
            arity,
            location,
            needed,
        },
        needed,
    )
}

// Port of erts/emulator/beam/beam_common.c:1267-1284 (`erts_build_mfa_item` loop), OTP-29.1.1.
fn cons_prepared(
    p: &mut Process,
    ready: PreparedFrames,
    block: &[PreparedFrame],
) -> Result<Term, VmError> {
    let bif_words = ready
        .bif
        .map_or(0, |bif| if bif.error_info.is_some() { 12 } else { 7 });
    if ready.frames == 0 && ready.bif.is_none() {
        return Ok(Term::NIL);
    }
    let mut heap = TraceHeap::with_block(&mut p.heap, ready.words + bif_words);
    let file_atom = Term::atom(trace_atoms().file);
    let line_atom = Term::atom(trace_atoms().line);
    let mut list = Term::NIL;
    {
        let mut builder = TermBuilder::new(&mut heap);
        for index in (0..ready.frames).rev() {
            let frame = block[index];
            debug_assert_eq!(frame.needed, if frame.location.is_some() { 15 } else { 5 });
            let location = frame
                .location
                .map(|(file, number)| arinsal_term::MfaLocation {
                    file_atom,
                    file,
                    line_atom,
                    line: Term::small(number as i64).expect("source line is a small"),
                });
            list = builder
                .cons_mfa_frame(
                    Term::atom(frame.module),
                    Term::atom(frame.function),
                    Term::small(i64::from(frame.arity)).expect("arity is small"),
                    location,
                    list,
                )
                .map_err(|error| VmError::Unsupported(format!("stacktrace {error:?}")))?;
        }
    }
    if let Some(bif) = ready.bif {
        let frame = build_frame(
            &mut heap,
            bif.module,
            bif.function,
            bif.args,
            None,
            true,
            bif.error_info,
        )?;
        list = TermBuilder::new(&mut heap)
            .cons(frame, list)
            .map_err(|error| VmError::Unsupported(format!("BIF stacktrace frame {error:?}")))?;
    }
    Ok(list)
}

pub(super) fn build_saved(p: &mut Process, raw: &mut RawTrace) -> Result<Term, VmError> {
    build_saved_with_reserve(p, raw, None)
}

fn build_saved_with_reserve(
    p: &mut Process,
    raw: &mut RawTrace,
    reserve: Option<&mut usize>,
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
            StoredTopFrame::CurrentArgs(args) => Ok(TopFrame::CurrentArgs(*args)),
            StoredTopFrame::CurrentArgsNoLocation {
                module,
                function,
                arity,
                args,
            } => Ok(TopFrame::CurrentArgsNoLocation {
                module: *module,
                function: *function,
                arity: *arity,
                args: *args,
            }),
            StoredTopFrame::CurrentArgsInfoTerm(args, info) => {
                Ok(TopFrame::CurrentArgsInfoTerm(*args, *info))
            }
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
    let native_top = raw.native_top;
    if let Some(runtime) = p.runtime {
        runtime.with_active_code(|ranges, _| {
            build_saved_active(
                p,
                raw,
                SavedBuildContext {
                    top,
                    native_top,
                    ranges: Some(ranges),
                    reserve,
                },
            )
        })
    } else {
        build_saved_active(
            p,
            raw,
            SavedBuildContext {
                top,
                native_top,
                ranges: None,
                reserve,
            },
        )
    }
}

struct SavedBuildContext<'a> {
    top: Option<&'a TopFrame>,
    native_top: Option<usize>,
    ranges: Option<&'a [crate::native_bridge::ModuleRange]>,
    reserve: Option<&'a mut usize>,
}

fn build_saved_active(
    p: &mut Process,
    raw: &mut RawTrace,
    context: SavedBuildContext<'_>,
) -> Result<Term, VmError> {
    let SavedBuildContext {
        top,
        native_top,
        ranges,
        reserve,
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
    let native_frame = native_top.and_then(|pc| {
        ranges.and_then(|ranges| crate::native_bridge::stack_frame_in(Some(ranges), pc))
    });
    let no_location = raw.no_location;
    let mut heap = if reserve.is_some() {
        TraceHeap::new(&mut p.heap)
    } else {
        TraceHeap::with_block(&mut p.heap, block_words)
    };
    let current_frame = if raw.no_current {
        None
    } else if no_location {
        match top {
            Some(TopFrame::CurrentArgsNoLocation {
                module,
                function,
                arity,
                ..
            }) => Some((*module, *function, *arity, None)),
            _ => return Err(VmError::Unsupported("stacktrace current MFA".into())),
        }
    } else {
        // Port of erts/emulator/beam/utils.c:3430 (`erts_build_mfa_item`), OTP-29.1.1.
        native_frame.map(|frame| {
            (
                frame.module_atom,
                frame.function_atom,
                frame.arity,
                frame.location,
            )
        })
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
    // Port of erl_bif_info.c:2408-2454 (`erts_build_stacktrace`) and beam_common.c:1265,
    // OTP-29.1.1: allocate the frame-info array once before resolving and assembling frames.
    let mut items = Vec::with_capacity(frame_budget);
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
    } else if !raw.no_current
        // Port of erts/emulator/beam/beam_common.c (build_stacktrace), OTP-29.1.1: a pc of
        // no function (`fi.mfa == NULL`) adds no current frame.
        && let Some((frame_module, function, arity, location)) = current_frame
    {
        let top_args = match top {
            Some(TopFrame::CurrentArgs(args))
            | Some(TopFrame::CurrentArgsWithInfo(Some(args), _))
            | Some(TopFrame::CurrentArgsInfoTerm(Some(args), _))
                if matches!(args.classify(), TermKind::List | TermKind::Nil) =>
            {
                *args
            }
            Some(TopFrame::CurrentArgsNoLocation { args, .. })
                if matches!(args.classify(), TermKind::List | TermKind::Nil) =>
            {
                *args
            }
            // Port of erts/emulator/beam/utils.c:3448-3455 (`erts_build_mfa_item`), OTP-29.1.1:
            // a non-list `error/2,3` args marker such as `:none` means use the function arity.
            _ => Term::small(i64::from(arity)).expect("arity is small"),
        };
        let top_args = mfa_arity_or_args(top_args, arity);
        let error_info = match top {
            Some(TopFrame::CurrentArgsWithInfo(_, info)) => Some(
                from_owned(info.as_ref(), &mut heap)
                    .map_err(|e| VmError::Unsupported(format!("exception info {e:?}")))?,
            ),
            Some(TopFrame::CurrentArgsInfoTerm(_, info)) => Some(*info),
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
        {
            let Continuation::Native(address) = continuation;
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
                location: resolved.location,
            }));
            continue;
        }
    }
    let file_atom = Term::atom(trace_atoms().file);
    let line_atom = Term::atom(trace_atoms().line);
    let mut list = Term::NIL;
    if let Some(reserve) = reserve {
        // Port of erl_bif_info.c:2433-2454 (`erts_build_stacktrace`), OTP-29.1.1:
        // size valid frames first, then allocate each frame and list cell while retaining the
        // reserve needed by the enclosing process_info tuple.
        debug_assert!(items.iter().all(|item| matches!(item, Item::Plain(_))));
        *reserve += 3 + items
            .iter()
            .map(|item| match item {
                Item::Plain(frame) => 7 + usize::from(frame.location.is_some()) * 10,
                Item::Built(_) => 0,
            })
            .sum::<usize>();
        drop(heap);
        let mut heap = ProcessHeapHandle(&mut p.heap);
        for item in items.iter().rev() {
            let Item::Plain(frame) = item else {
                continue;
            };
            let words = 7 + usize::from(frame.location.is_some()) * 10;
            *reserve = reserve.saturating_sub(words);
            let mut block = arinsal_term::HeapReservation::with_extra(&mut heap, words, *reserve)
                .map_err(|error| {
                VmError::Unsupported(format!("stacktrace allocation: {error:?}"))
            })?;
            let location = frame
                .location
                .map(|(file, number)| arinsal_term::MfaLocation {
                    file_atom,
                    file,
                    line_atom,
                    line: Term::small(number as i64).expect("source line is a small"),
                });
            list = TermBuilder::new(&mut block)
                .cons_mfa_frame(
                    Term::atom(frame.module),
                    Term::atom(frame.function),
                    frame.args,
                    location,
                    list,
                )
                .map_err(|error| VmError::Unsupported(format!("stacktrace {error:?}")))?;
        }
    } else {
        let mut builder = TermBuilder::new(&mut heap);
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
                freason: arinsal_beamasm::exc::EXC_ERROR,
                pc: 0x1000,
                current: 0,
                no_location: false,
                current_args_mfa: false,
                depth: 1,
                max_depth: 2,
                trace: &[0x2000],
            },
        )
        .unwrap();
        let mut layout_matches = false;
        trace.with_bignum_digits_mut(|digits| {
            layout_matches = digits
                == [
                    arinsal_beamasm::exc::EXC_ERROR,
                    0x1000,
                    0,
                    1 | (2 << 32),
                    0x2000,
                    0,
                ];
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
        crate::boot::erl_init_global_literals();
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
