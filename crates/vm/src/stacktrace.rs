//! Symbolic stack traces from BEAM continuations.
//!
//! Port of erts/emulator/beam/beam_common.c (`save_stacktrace`, `gather_stacktrace`,
//! `build_stacktrace`, `expand_error_value`) and error.h (`struct StackTrace`), OTP-29.1.1.

use crate::{Process, VmError};
use arinsal_bifs::{Class, ProcessHeapHandle};
use arinsal_etf::OwnedTerm;
use arinsal_term::{
    Atom, ErtsCodeMfa, ExternalBinary, HeapAlloc, MagicBin, Node, ProcessHeap,
    TemporaryHeapFactory, Term, TermBuilder, TermKind, WritableBinary, from_owned, global_atoms,
    to_owned,
};
use std::sync::{Arc, OnceLock};

/// `struct StackTrace` words after the bignum header: `freason`, `pc`, `current`, and `depth`
/// with `max_depth` sharing one word (two C `int`s), as in erts/emulator/beam/error.h:222-230.
const STACKTRACE_HEADER_WORDS: usize = 4;

/// `StackTrace.depth` and `StackTrace.max_depth` in one word.
fn stacktrace_depth_word(depth: usize, max_depth: usize) -> u64 {
    (depth as u64 & 0xffff_ffff) | ((max_depth as u64) << 32)
}

/// `(depth, max_depth)` of a `StackTrace` depth word.
fn stacktrace_depths(word: u64) -> (usize, usize) {
    ((word as u32) as usize, (word >> 32) as usize)
}

fn halloc<T>(result: Result<T, arinsal_term::TermError>, what: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => unreachable!("HAlloc {what}: {error:?}"),
    }
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
        // OTP-29.1.1: a tail that cannot be given back (later terms were allocated after it, or
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

    fn link_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        writable: bool,
        overhead_words: u64,
        owner: Option<arinsal_term::OwnedBinaryRef>,
    ) {
        HeapAlloc::link_bin_ref(self.heap, bin_ref, writable, overhead_words, owner)
    }

    fn add_bin_vheap(&mut self, words: u64) {
        HeapAlloc::add_bin_vheap(self.heap, words)
    }

    fn retain_writable_binary(&mut self, binary: Arc<WritableBinary>) {
        HeapAlloc::retain_writable_binary(self.heap, binary)
    }

    fn supports_writable_binary(&self) -> bool {
        true
    }

    fn link_external_binary(&mut self, bin_ref: *mut u64, binary: Arc<ExternalBinary>) {
        HeapAlloc::link_external_binary(self.heap, bin_ref, binary)
    }

    fn supports_external_binary(&self) -> bool {
        true
    }

    fn link_node(&mut self, thing: *mut u64, node: Node) {
        HeapAlloc::link_node(self.heap, thing, node);
    }

    fn link_magic_ref(&mut self, thing: *mut u64, owner: MagicBin) {
        HeapAlloc::link_magic_ref(self.heap, thing, owner)
    }

    fn supports_magic(&self) -> bool {
        true
    }
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
    /// Port of `HAlloc` and `struct StackTrace` stores in beam_common.c:880-893.
    fn reserve(
        heap: &mut impl HeapAlloc,
        max_depth: usize,
        freason: u64,
        pc: u64,
        current: u64,
    ) -> Term {
        let digits = STACKTRACE_HEADER_WORDS + max_depth;
        halloc(
            TermBuilder::new(heap).pos_bignum_prefix(
                digits,
                [freason, pc, current, stacktrace_depth_word(0, max_depth)],
            ),
            "stacktrace",
        )
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
        let pc = fields.pc;
        let current = fields.current;
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
    fn allocate_raised(heap: &mut impl HeapAlloc, freason: u64) -> Term {
        halloc(
            TermBuilder::new(heap).neg_bignum_fill(STACKTRACE_HEADER_WORDS, |index| {
                if index == 0 { freason } else { 0 }
            }),
            "raised stacktrace",
        )
    }
}

/// The `ftrace` value stored by `save_stacktrace`: `{StackTrace, Args, ErrorInfo}`.
struct Ftrace {
    stack_trace: Term,
    args: Term,
    error_info: Term,
}

impl Ftrace {
    fn allocate(self, heap: &mut impl HeapAlloc) -> Term {
        halloc(
            TermBuilder::new(heap).tuple3(self.stack_trace, self.args, self.error_info),
            "ftrace tuple",
        )
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

    /// The argument terms when they are held inline (up to four).
    pub(super) fn inline_terms(&self) -> Option<&[Term]> {
        match self {
            Self::Inline { values, len } => Some(&values[..usize::from(*len)]),
            _ => None,
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

    fn to_terms(&self, heap: &mut impl HeapAlloc) -> Result<Vec<Term>, VmError> {
        match self {
            Self::Inline { values, len } => Ok(values[..usize::from(*len)].to_vec()),
            Self::Owned(args) => {
                let list = from_owned(args, heap)
                    .map_err(|error| VmError::Unsupported(format!("exception args {error:?}")))?;
                Ok(arinsal_term::term_sequence(list)
                    .map(|terms| terms.to_vec())
                    .unwrap_or_default())
            }
        }
    }
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

/// Live exception metadata used until `save_stacktrace` records `c_p->ftrace`.
///
/// Interpreter BIF failures still carry this until the parallel `bif_error_direct` work
/// writes only `freason`/`fvalue`. `save_stacktrace` itself takes erts' `(pc, reg, bif_mfa,
/// args)` and does not store these variants.
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
    CurrentArgsWithInfo(Option<Term>, Box<OwnedTerm>),
    /// `erlang:error/2,3` arguments and the validated `error_info` map stay heap terms, as in
    /// erts' `c_p->ftrace`; a pending BIF epilogue collection roots both terms.
    CurrentArgsInfoTerm(Option<Term>, Term),
}

/// The first `arity` argument registers as a list on the process heap (HAlloc: young heap,
/// else a heap fragment; never fails).
// Port of erts/emulator/beam/beam_common.c:1186 (make_arglist), OTP-29.1.1.
pub(crate) fn make_arglist(p: &mut Process, registers: &[Term], arity: usize) -> Term {
    let values = &registers[..arity.min(registers.len())];
    let mut heap = TraceHeap::new(&mut p.heap);
    halloc(
        TermBuilder::new(&mut heap).list_from_slice(values),
        "make_arglist",
    )
}

/// Port of erts/emulator/beam/beam_common.c:782 (gather_stacktrace), OTP-29.1.1.
fn gather_stacktrace(p: &Process, s_pc: usize, trace: &mut [u64], mut depth: usize) -> usize {
    let max_depth = trace.len();
    if depth >= max_depth {
        return depth;
    }
    let mut prev = if depth > 0 {
        trace[depth - 1] as usize
    } else {
        s_pc
    };
    let bridge = arinsal_beamasm::rt::arinsal_enter_native_return as *const () as usize;
    let words = p.heap.stack_raw_words();
    let mut index = 0usize;
    while let Some(&word) = words.get(index) {
        index += 1;
        if !arinsal_term::is_cp(word) {
            continue;
        }
        let return_address = word as usize;
        if let Some(kind) = crate::trace::TraceFrameKind::of(return_address) {
            index = index.saturating_add(kind.data_words());
            continue;
        }
        // The interpreter-to-native bridge CP is not a frame erts would record: erts has only
        // the caller's continuation. Skipping it keeps the same `trace[]` occupancy.
        if return_address == prev || return_address == bridge {
            continue;
        }
        prev = return_address;
        // BEAMASM: continuation pointers point after the call; subtract one byte so the
        // location is inside the call instruction (beam_common.c:823-834).
        trace[depth] = return_address.wrapping_sub(1) as u64;
        depth += 1;
        if depth == max_depth {
            break;
        }
    }
    depth
}

/// Port of erts/emulator/beam/code_ix.h:346 (`erts_codemfa_to_code`), OTP-29.1.1.
fn erts_codemfa_to_code(mfa: *const ErtsCodeMfa) -> usize {
    mfa as usize + core::mem::size_of::<ErtsCodeMfa>()
}

fn is_function_clause(freason: u64) -> bool {
    arinsal_term::exc::exc_index(freason)
        == arinsal_term::exc::exc_index(arinsal_term::exc::EXC_FUNCTION_CLAUSE)
}

fn tagged_atom(atom: Atom) -> u64 {
    Term::atom(atom).word()
}

fn is_non_bif_exception(mfa: &ErtsCodeMfa) -> bool {
    if mfa.module != tagged_atom(arinsal_term::atoms::ERLANG) {
        return false;
    }
    let function = mfa.function;
    let arity = mfa.arity;
    (function == tagged_atom(arinsal_term::atoms::ERROR) && matches!(arity, 1..=3))
        || (function == tagged_atom(arinsal_term::atoms::EXIT) && arity == 1)
        || (function == tagged_atom(arinsal_term::atoms::THROW) && arity == 1)
}

fn format_module_for(module: u64) -> Option<Atom> {
    let module = crate::native_hooks::from_raw(module).as_atom()?;
    trace_atoms()
        .format_modules
        .iter()
        .find(|(bif, _)| *bif == module)
        .map(|(_, format)| *format)
}

/// Port of erts/emulator/beam/beam_common.c:880 (`save_stacktrace`), OTP-29.1.1.
///
/// Fills `c_p->ftrace` with `{StackTrace, Args, ErrorInfo}` and returns that term.
pub(super) fn save_stacktrace(
    p: &mut Process,
    pc: usize,
    registers: &[Term],
    bif_mfa: *const ErtsCodeMfa,
    mut args: Term,
) -> Term {
    if let Some(cold) = p.cold.as_mut() {
        cold.apply_frame_released = 0;
    }
    let max_depth = crate::erl_init::erts_backtrace_depth().saturating_sub(1);
    let freason = p.heap.abi.exc.freason;
    let mut error_info = Term::NON_VALUE;
    let mut s_pc = pc as u64;
    let mut s_current = p.heap.abi.current as u64;
    let mut first_trace: Option<u64> = None;

    let mut bif = false;
    if !bif_mfa.is_null() {
        let mfa = crate::natives::raw::code_mfa(bif_mfa as usize);
        if !is_non_bif_exception(mfa) {
            bif = true;
            s_current = bif_mfa as u64;
            if max_depth > 0 {
                first_trace = Some(pc as u64);
            }
            s_pc = 0;
            if let Some(format_module) = format_module_for(mfa.module) {
                error_info = bif_format_error_info(p, format_module);
            }
            args = make_arglist(p, registers, mfa.arity);
        }
    }
    if !bif {
        if p.heap.abi.exc.freason & arinsal_term::exc::EXF_HAS_EXT_INFO != 0 {
            let value = crate::native_hooks::from_raw(p.heap.abi.exc.fvalue);
            if value.classify() == TermKind::Map {
                error_info = value;
            }
        }
        s_current = p.heap.abi.current as u64;
        if is_function_clause(freason) {
            let arity = if s_current == 0 {
                0
            } else {
                crate::natives::raw::code_mfa(s_current as usize).arity
            };
            args = make_arglist(p, registers, arity);
            s_pc = 0;
        } else {
            s_pc = pc as u64;
        }
    }
    if freason == arinsal_term::exc::EXC_ERROR_3 {
        error_info = crate::native_hooks::from_raw(p.heap.abi.exc.fvalue);
    }

    let (stack_trace, ftrace) = {
        let mut heap = TraceHeap::new(&mut p.heap);
        let stack_trace = StackTrace::reserve(&mut heap, max_depth, freason, s_pc, s_current);
        let error_info = package_error_info(&mut heap, error_info);
        let ftrace = Ftrace {
            stack_trace,
            args,
            error_info,
        }
        .allocate(&mut heap);
        (stack_trace, ftrace)
    };
    stack_trace.with_bignum_digits_mut(|digits| {
        let mut depth = 0usize;
        if let Some(pc) = first_trace {
            digits[STACKTRACE_HEADER_WORDS] = pc;
            depth = 1;
        }
        let end = STACKTRACE_HEADER_WORDS + max_depth;
        depth = gather_stacktrace(
            p,
            s_pc as usize,
            &mut digits[STACKTRACE_HEADER_WORDS..end],
            depth,
        );
        digits[3] = stacktrace_depth_word(depth, max_depth);
    });
    p.heap.abi.exc.ftrace = crate::native_hooks::raw(ftrace);
    ftrace
}

fn bif_format_error_info(p: &mut Process, format_module: Atom) -> Term {
    let atoms = trace_atoms();
    let ext_info = p.heap.abi.exc.freason & arinsal_term::exc::EXF_HAS_EXT_INFO != 0;
    let cause = crate::native_hooks::from_raw(p.heap.abi.exc.fvalue);
    let mut heap = TraceHeap::new(&mut p.heap);
    let mut builder = TermBuilder::new(&mut heap);
    if ext_info {
        let keys = halloc(
            builder.tuple(&[Term::atom(atoms.cause), Term::atom(atoms.module)]),
            "BIF error_info keys",
        );
        halloc(
            builder.flatmap_with_key_tuple(keys, &[cause, Term::atom(format_module)]),
            "BIF error_info map",
        )
    } else {
        let keys = halloc(
            builder.tuple(&[Term::atom(atoms.module)]),
            "BIF error_info keys",
        );
        halloc(
            builder.flatmap_with_key_tuple(keys, &[Term::atom(format_module)]),
            "BIF error_info map",
        )
    }
}

fn package_error_info(heap: &mut impl HeapAlloc, error_info: Term) -> Term {
    if error_info.is_non_value() {
        return Term::NIL;
    }
    let entry = halloc(
        TermBuilder::new(heap).tuple(&[Term::atom(trace_atoms().error_info), error_info]),
        "error_info tuple",
    );
    halloc(
        TermBuilder::new(heap).cons(entry, Term::NIL),
        "error_info list",
    )
}

/// Convert a live `TopFrame` into erts' `save_stacktrace` arguments.
///
/// Interpreter BIF failures still pass a `TopFrame` until they write only `freason`/`fvalue`.
pub(super) fn save_from_top(
    p: &mut Process,
    pc: usize,
    registers: &[Term],
    top: Option<&TopFrame>,
) -> Term {
    let true_atom = Term::atom(arinsal_term::atoms::TRUE);
    let mut owned_regs: Vec<Term> = Vec::new();
    let mut bif_mfa: *const ErtsCodeMfa = std::ptr::null();
    let mut args = true_atom;
    match top {
        Some(TopFrame::Bif {
            module,
            function,
            args: bif_args,
            info,
        }) => {
            apply_top_error_info(p, *info);
            if let Ok(terms) = bif_args.to_terms(&mut TraceHeap::new(&mut p.heap)) {
                owned_regs = terms;
            }
            let arity = owned_regs.len() as u32;
            bif_mfa = export_mfa_ptr(*module, *function, arity);
            args = true_atom;
        }
        Some(TopFrame::BifRegisters {
            module,
            function,
            arity,
            info,
        }) => {
            apply_top_error_info(p, *info);
            bif_mfa = export_mfa_ptr(*module, *function, *arity as u32);
            args = true_atom;
        }
        Some(TopFrame::CurrentArgs(value)) => {
            bif_mfa = std::ptr::null();
            args = *value;
        }
        Some(TopFrame::CurrentArgsInfoTerm(value, info)) => {
            p.heap.abi.exc.fvalue = crate::native_hooks::raw(*info);
            p.heap.abi.exc.freason |= arinsal_term::exc::EXF_HAS_EXT_INFO;
            if value.is_some() {
                p.heap.abi.exc.freason |= arinsal_term::exc::EXF_ARGLIST;
            }
            bif_mfa = std::ptr::null();
            args = value.unwrap_or(true_atom);
        }
        Some(TopFrame::CurrentArgsWithInfo(value, info)) => {
            let info_term = {
                let mut heap = TraceHeap::new(&mut p.heap);
                from_owned(info.as_ref(), &mut heap).ok()
            };
            if let Some(info) = info_term {
                p.heap.abi.exc.fvalue = crate::native_hooks::raw(info);
                p.heap.abi.exc.freason |= arinsal_term::exc::EXF_HAS_EXT_INFO;
            }
            if value.is_some() {
                p.heap.abi.exc.freason |= arinsal_term::exc::EXF_ARGLIST;
            }
            bif_mfa = std::ptr::null();
            args = value.unwrap_or(true_atom);
        }
        None => {}
    }
    let regs = if owned_regs.is_empty() {
        registers
    } else {
        owned_regs.as_slice()
    };
    save_stacktrace(p, pc, regs, bif_mfa, args)
}

fn apply_top_error_info(p: &mut Process, info: BifErrorInfo) {
    match info {
        BifErrorInfo::None | BifErrorInfo::Plain => {}
        BifErrorInfo::Cause(cause) => {
            p.heap.abi.exc.freason |= arinsal_term::exc::EXF_HAS_EXT_INFO;
            p.heap.abi.exc.fvalue = crate::native_hooks::raw(cause);
        }
    }
}

fn export_mfa_ptr(module: Atom, function: Atom, arity: u32) -> *const ErtsCodeMfa {
    let entry = arinsal_term::export_get_or_make_stub(module, function, arity);
    std::ptr::from_ref(entry.mfa())
}

/// Preserve the supplied `raise/3` trace in Args behind erts' negative StackTrace marker.
///
/// Port of erts/emulator/beam/bif.c (`raise_3`), OTP-29.1.1.
pub(super) fn save_explicit(p: &mut Process, class: Class, trace: Term) -> Result<Term, VmError> {
    let freason = class_to_freason(Some(class)) & !arinsal_beamasm::exc::EXF_SAVETRACE;
    let args = normalize_raise_trace(p, trace)?;
    let ftrace = {
        let mut heap = TraceHeap::new(&mut p.heap);
        let stack_trace = StackTrace::allocate_raised(&mut heap, freason);
        Ftrace {
            stack_trace,
            args,
            error_info: Term::NIL,
        }
        .allocate(&mut heap)
    };
    p.heap.abi.exc.ftrace = crate::native_hooks::raw(ftrace);
    Ok(ftrace)
}

// Port of erts/emulator/beam/bif.c (`raise_3`), OTP-29.1.1: copy only when a legacy
// frame needs conversion or the runtime backtrace limit truncates the supplied trace.
fn normalize_raise_trace(p: &mut Process, trace: Term) -> Result<Term, VmError> {
    if trace == Term::NIL {
        return Ok(trace);
    }
    let max_depth = crate::erl_init::erts_backtrace_depth();
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
/// `ErtsInArea` on `s->pc`, `s->current` (`ErtsCodeMFA*`) and each `trace[]` continuation.
pub(crate) fn saved_trace_names_code(
    term: Term,
    _module: usize,
    in_native: impl Fn(usize) -> bool,
) -> bool {
    let Some(fields) = arinsal_term::term_sequence_small(term) else {
        return false;
    };
    if fields.len() != 3 {
        return false;
    }
    fields[0]
        .with_bignum_digits_mut(|digits| digits_in_area(digits, &in_native))
        .unwrap_or(false)
}

fn digits_in_area(digits: &[u64], in_native: &impl Fn(usize) -> bool) -> bool {
    if digits.len() < STACKTRACE_HEADER_WORDS {
        return false;
    }
    let in_area = |word: u64| word != 0 && usize::try_from(word).is_ok_and(in_native);
    if in_area(digits[1]) || in_area(digits[2]) {
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
        .any(|word| in_area(*word))
}

fn ftrace_parts(term: Term) -> Option<(Term, Term, Term)> {
    let fields = arinsal_term::term_sequence_small(term)?;
    (fields.len() == 3).then_some((fields[0], fields[1], fields[2]))
}

/// Args carried by the negative StackTrace used for an explicit `raise/3` trace.
pub(super) fn raised_args(term: Term) -> Option<Term> {
    let (stack, args, _) = ftrace_parts(term)?;
    stack.is_negative_bignum().then_some(args)
}

/// True when `term` is a saved raw trace.
pub(super) fn is_saved(term: Term) -> bool {
    ftrace_parts(term).is_some_and(|(stack, _, _)| stack.bignum_digit_count().is_some())
}

/// Reads the saved exception word carried by the raw stacktrace in an exception tuple.
pub(crate) fn raw_freason(term: Term) -> Option<u64> {
    let (stack, _, _) = ftrace_parts(term)?;
    stack
        .with_bignum_digits_mut(|digits| digits.first().copied())
        .flatten()
}

/// Port of erts/emulator/beam/beam_common.c:1131-1178 (`get_freason_ptr_from_exc`,
/// `raw_raise`), OTP-29.1.1: the class goes straight into `StackTrace.freason`.
pub(super) fn set_raw_class(_p: &mut Process, term: Term, class: Class) -> bool {
    let code = class_to_freason(Some(class)) & !arinsal_beamasm::exc::EXF_SAVETRACE;
    let Some((stack, _, _)) = ftrace_parts(term) else {
        return false;
    };
    stack
        .with_bignum_digits_mut(|digits| {
            let Some(freason) = digits.first_mut() else {
                return false;
            };
            *freason = code;
            true
        })
        .unwrap_or(false)
}

struct TraceAtoms {
    file: Atom,
    line: Atom,
    module: Atom,
    cause: Atom,
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

/// `FunctionInfo` filled by `erts_lookup_function_info` / `erts_set_current_function`.
// Port of erts/emulator/beam/global.h:964-973 (`FunctionInfo`), OTP-29.1.1.
struct FunctionInfo {
    module: Term,
    function: Term,
    arity: usize,
    needed: usize,
    loc: Option<(Term, u64)>,
    present: bool,
}

impl FunctionInfo {
    fn empty() -> Self {
        Self {
            module: Term::NIL,
            function: Term::NIL,
            arity: 0,
            needed: 5,
            loc: None,
            present: false,
        }
    }
}

fn lookup_function_info(p: &Process, pc: usize) -> FunctionInfo {
    if pc == 0 {
        return FunctionInfo::empty();
    }
    let frame = if let Some(runtime) = p.runtime {
        runtime.with_active_code(|ranges, _| crate::native_bridge::stack_frame_in(Some(ranges), pc))
    } else {
        crate::native_bridge::stack_frame_in(None, pc)
    };
    match frame {
        Some(frame) => FunctionInfo {
            module: Term::atom(frame.module_atom),
            function: Term::atom(frame.function_atom),
            arity: usize::from(frame.arity),
            needed: if frame.location.is_some() { 15 } else { 5 },
            loc: frame.location,
            present: true,
        },
        None => FunctionInfo::empty(),
    }
}

/// Port of erts/emulator/beam/beam_ranges.c:288 (`erts_set_current_function`), OTP-29.1.1.
fn erts_set_current_function(mfa: *const ErtsCodeMfa) -> FunctionInfo {
    if mfa.is_null() {
        return FunctionInfo::empty();
    }
    let mfa = crate::natives::raw::code_mfa(mfa as usize);
    FunctionInfo {
        module: crate::native_hooks::from_raw(mfa.module),
        function: crate::native_hooks::from_raw(mfa.function),
        arity: mfa.arity,
        needed: 5,
        loc: None,
        present: true,
    }
}

fn initial_function(p: &Process) -> FunctionInfo {
    let Some((module, function, arity)) = p.initial_mfa else {
        return FunctionInfo::empty();
    };
    FunctionInfo {
        module: Term::atom(module),
        function: Term::atom(function),
        arity: usize::from(arity),
        needed: 5,
        loc: None,
        present: true,
    }
}

/// Port of erts/emulator/beam/utils.c:3430 (`erts_build_mfa_item`), OTP-29.1.1.
fn erts_build_mfa_item(
    heap: &mut impl HeapAlloc,
    fi: &FunctionInfo,
    args: Term,
    mut loc: Term,
) -> Result<Term, VmError> {
    let atoms = trace_atoms();
    let mut builder = TermBuilder::new(heap);
    if let Some((file, line)) = fi.loc {
        let line_term = Term::small(line as i64)
            .ok_or_else(|| VmError::Unsupported("source line number".into()))?;
        let line_tuple = builder
            .tuple(&[Term::atom(atoms.line), line_term])
            .map_err(|error| VmError::Unsupported(format!("stack line {error:?}")))?;
        loc = builder
            .cons(line_tuple, loc)
            .map_err(|error| VmError::Unsupported(format!("stack line {error:?}")))?;
        let file_tuple = builder
            .tuple(&[Term::atom(atoms.file), file])
            .map_err(|error| VmError::Unsupported(format!("stack file {error:?}")))?;
        loc = builder
            .cons(file_tuple, loc)
            .map_err(|error| VmError::Unsupported(format!("stack file {error:?}")))?;
    }
    let arity_or_args = if matches!(args.classify(), TermKind::List | TermKind::Nil) {
        args
    } else {
        Term::small(fi.arity as i64).ok_or_else(|| VmError::Unsupported("function arity".into()))?
    };
    builder
        .tuple(&[fi.module, fi.function, arity_or_args, loc])
        .map_err(|error| VmError::Unsupported(format!("stack frame {error:?}")))
}

/// Port of erts/emulator/beam/beam_common.c:1205 (`build_stacktrace`), OTP-29.1.1.
pub(super) fn build_stacktrace(p: &mut Process, exc: Term) -> Result<Term, VmError> {
    let Some((stack, args_term, error_info)) = ftrace_parts(exc) else {
        return Ok(Term::NIL);
    };
    if stack.is_negative_bignum() {
        return Ok(args_term);
    }
    let Some((freason, pc, current, trace)) = stack
        .with_bignum_digits_mut(|digits| {
            if digits.len() < STACKTRACE_HEADER_WORDS {
                return None;
            }
            let (depth, max_depth) = stacktrace_depths(digits[3]);
            if depth > max_depth || digits.len() < STACKTRACE_HEADER_WORDS + depth {
                return None;
            }
            Some((
                digits[0],
                digits[1] as usize,
                digits[2] as *const ErtsCodeMfa,
                digits[STACKTRACE_HEADER_WORDS..STACKTRACE_HEADER_WORDS + depth].to_vec(),
            ))
        })
        .flatten()
    else {
        return Ok(Term::NIL);
    };
    let mut fi = if pc != 0 {
        lookup_function_info(p, pc)
    } else if is_function_clause(freason) {
        lookup_function_info(p, erts_codemfa_to_code(current))
    } else {
        erts_set_current_function(current)
    };
    let depth = trace.len();
    let mut args = args_term;
    if !fi.present {
        if depth == 0 {
            fi = initial_function(p);
        }
        args = Term::atom(arinsal_term::atoms::TRUE);
    }
    let mut stk = Vec::with_capacity(depth);
    let mut heap_size = if fi.present { fi.needed + 2 } else { 0 };
    for &pc in &trace {
        let info = lookup_function_info(p, pc as usize);
        if info.present {
            heap_size += info.needed + 2;
            stk.push(info);
        }
    }
    let mut heap = TraceHeap::with_block(&mut p.heap, heap_size);
    let mut res = Term::NIL;
    for info in stk.iter().rev() {
        let mfa = erts_build_mfa_item(
            &mut heap,
            info,
            Term::atom(arinsal_term::atoms::TRUE),
            Term::NIL,
        )?;
        res = TermBuilder::new(&mut heap)
            .cons(mfa, res)
            .map_err(|error| VmError::Unsupported(format!("stacktrace {error:?}")))?;
    }
    if fi.present {
        let mfa = erts_build_mfa_item(&mut heap, &fi, args, error_info)?;
        res = TermBuilder::new(&mut heap)
            .cons(mfa, res)
            .map_err(|error| VmError::Unsupported(format!("stacktrace {error:?}")))?;
    }
    Ok(res)
}

/// Port of erts/emulator/beam/erl_bif_info.c:2408 (`erts_build_stacktrace`), OTP-29.1.1.
fn erts_build_stacktrace(
    p: &mut Process,
    max_depth: usize,
    include_i: bool,
    reserve: Option<&mut usize>,
    temporary_heap: Option<&mut TemporaryHeapFactory>,
) -> Result<Term, VmError> {
    let mut trace = vec![0u64; max_depth];
    let mut depth = 0usize;
    if include_i && max_depth > 0 {
        let i = p.heap.abi.i as usize;
        if i != 0 {
            trace[0] = i as u64;
            depth = 1;
        }
    }
    depth = gather_stacktrace(p, 0, &mut trace[..max_depth], depth);
    let mut stk = Vec::with_capacity(depth);
    let mut heap_size = 3;
    for &pc in &trace[..depth] {
        let info = lookup_function_info(p, pc as usize);
        if info.present {
            heap_size += info.needed + 2;
            stk.push(info);
        }
    }
    if let Some(reserve) = reserve {
        *reserve += heap_size;
        let mut list = Term::NIL;
        let mut heap = ProcessHeapHandle(&mut p.heap);
        for info in stk.iter().rev() {
            let words = info.needed + 2;
            *reserve = reserve.saturating_sub(words);
            let mut block = arinsal_term::HeapReservation::with_extra(&mut heap, words, *reserve)
                .map_err(|error| {
                VmError::Unsupported(format!("stacktrace allocation: {error:?}"))
            })?;
            let location = info.loc.map(|(file, number)| arinsal_term::MfaLocation {
                file_atom: Term::atom(trace_atoms().file),
                file,
                line_atom: Term::atom(trace_atoms().line),
                line: Term::small(number as i64).expect("source line is a small"),
            });
            list = TermBuilder::new(&mut block)
                .cons_mfa_frame(
                    info.module,
                    info.function,
                    Term::small(info.arity as i64).expect("arity is small"),
                    location,
                    list,
                )
                .map_err(|error| VmError::Unsupported(format!("stacktrace {error:?}")))?;
        }
        return Ok(list);
    }
    if let Some(heap) = temporary_heap {
        return cons_process_info_frames(heap, &stk);
    }
    let mut heap = TraceHeap::with_block(&mut p.heap, heap_size);
    cons_process_info_frames(&mut heap, &stk)
}

fn cons_process_info_frames(
    heap: &mut impl HeapAlloc,
    stk: &[FunctionInfo],
) -> Result<Term, VmError> {
    let mut list = Term::NIL;
    let file_atom = Term::atom(trace_atoms().file);
    let line_atom = Term::atom(trace_atoms().line);
    let mut builder = TermBuilder::new(heap);
    for info in stk.iter().rev() {
        let location = info.loc.map(|(file, number)| arinsal_term::MfaLocation {
            file_atom,
            file,
            line_atom,
            line: Term::small(number as i64).expect("source line is a small"),
        });
        list = builder
            .cons_mfa_frame(
                info.module,
                info.function,
                Term::small(info.arity as i64).expect("arity is small"),
                location,
                list,
            )
            .map_err(|error| VmError::Unsupported(format!("stacktrace {error:?}")))?;
    }
    Ok(list)
}

/// Port of erts/emulator/beam/beam_common.c:781 (gather_stacktrace) used as a live
/// `process_info` / match-spec capture: `s->pc == NULL`, frames from the stack only.
pub(super) fn build(p: &mut Process, depth: usize) -> Result<Term, VmError> {
    erts_build_stacktrace(p, depth, false, None, None)
}

/// Build `erts_build_stacktrace` terms in the caller's temporary factory.
// Port of erts/emulator/beam/erl_gc.c:3777 (`erts_build_stacktrace`, include_i = 1), OTP-29.1.1.
pub(super) fn build_tmp(
    p: &mut Process,
    depth: usize,
) -> Result<(TemporaryHeapFactory, Term), VmError> {
    let mut heap = TemporaryHeapFactory::new();
    let trace = erts_build_stacktrace(p, depth, true, None, Some(&mut heap))?;
    Ok((heap, trace))
}

/// Build the live `process_info` stacktrace using `erts_build_stacktrace`'s per-frame heap
/// reservations and the caller's remaining result reserve.
pub(super) fn build_for_process_info(
    p: &mut Process,
    depth: usize,
    include_i: bool,
    reserve: &mut usize,
) -> Result<Term, VmError> {
    erts_build_stacktrace(p, depth, include_i, Some(reserve), None)
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
        .allocate(&mut heap);
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
