//! BIF registry and the process-independent BIF implementations.
//! Owned by task S1.6.
//!
//! Contract (frozen by the supervisor; implement and extend, never change
//! these signatures):
//! - A BIF is a plain function `fn(&mut Ctx, &[Term]) -> Result<Term, BifError>`.
//! - BIFs never trigger GC (ADR 0007). `Ctx::heap` is infallible: it allocates
//!   on the process heap while there is room and in a heap fragment otherwise
//!   (see [`FragmentingHeap`]), so BIFs may `unwrap` allocation results.
//! - [`lookup`] returns `None` for BIFs that are not implemented here (for
//!   example the ones that need processes, ETS or code loading).

use std::sync::Arc;

use arinsal_term::{
    ExportEntry, ExternalBinary, FunEntry, HeapAlloc, MagicRef, Node, ProcessHeap, Term,
};

mod arith;
mod atomics;
mod binary_mod;
mod checksum;
mod etf;
mod lists;
mod maps_bifs;
mod pure;
mod sys;
mod time;
mod unicode;
mod unique;

pub use etf::{DecodeWalk, EncodeWalk};
pub use lists::{
    APPEND_ALLOC_PER_RED, APPEND_EMPTY_PER_RED, APPEND_ONHEAP_PER_RED, AppendCont, AppendStep,
    DeferredTrap, KEYFIND_MAX_ITER, KeyOp, KeyOutcome, KeyfindCont, MEMBER_PER_RED, MemberCont,
    MemberStep, REVERSE_CELLS_PER_RED, ReverseCont, ReverseStep, SubtractWalk, lists_append,
    lists_key, lists_member, lists_reverse,
};
pub use maps_bifs::maps_merge_start;
pub use maps_bifs::{MapsBuildWalk, MapsProjectionWalk, ProjectionStart};
pub use pure::{
    BinarySearchKind, BinarySearchWalk, IolistCopyWalk, IolistSizeWalk, IolistWalk,
    allocate_iolist_binary, atom_to_list_term, binary_bytes, bitstring_bit_len, copy_binary_range,
    copy_bitstring_range, eval_unique_integer, finish_iolist_binary_output, next_ref_id,
    next_unique_monotonic, singleton_bitstring, with_binary_bytes, with_iolist_binary_output,
};
pub use time::{monotonic_time_milliseconds, monotonic_time_nanos};
pub use unique::{
    SchedulerRefState, UniqueInt, bind_scheduler_ref_state, init_unique_scheduler_count,
    next_ref_words, next_unique_integer, next_unique_monotonic_positive, ordinary_ref_key,
    ordinary_ref_words, scheduler_thr_id,
};

pub use sys::{set_emu_flavor_jit, sys_perf_counter};
pub use time::initialize_time_origin;

/// Exception class, as in `erlang:raise/3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Error,
    Exit,
    Throw,
}

/// How a BIF failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BifError {
    /// `error:badarg`. `cause` is reserved for extended error info
    /// (`error_info`); `None` for now.
    Badarg { cause: Option<Term> },
    /// `error:badarith`
    Badarith,
    /// `error:system_limit`
    SystemLimit,
    /// `error:Reason` with an arbitrary reason term (e.g. `{badkey, K}`).
    Error(Term),
    /// An explicit raise (`error/1,2,3`, `exit/1`, `throw/1`, `raise/3`).
    /// `stacktrace` is `None` when the VM should build it.
    Raise {
        class: Class,
        reason: Term,
        stacktrace: Option<Term>,
    },
    /// The BIF exists but this part is not implemented in Arinsal yet.
    Unsupported(&'static str),
    /// The call must continue on a scheduler of this class; the VM re-executes it there.
    /// Port of erts/emulator/beam/erl_nif.c:3540 (enif_schedule_nif dirty flags), OTP-29.1.1.
    Dirty(SchedulerClass),
}

/// Scheduler class a rescheduled native call continues on.
///
/// Port of erts/emulator/beam/erl_process.h (`ERTS_PSFLG_DIRTY_CPU_PROC`,
/// `ERTS_PSFLG_DIRTY_IO_PROC`), OTP-29.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerClass {
    /// A normal scheduler.
    Normal,
    /// A dirty CPU scheduler (`ERL_NIF_DIRTY_JOB_CPU_BOUND`).
    DirtyCpu,
    /// A dirty I/O scheduler (`ERL_NIF_DIRTY_JOB_IO_BOUND`).
    DirtyIo,
}

impl BifError {
    pub const BADARG: BifError = BifError::Badarg { cause: None };
}

/// Execution context handed to every BIF.
///
/// More fields (the calling process, scheduler services) are added by later
/// stages; construct it only through [`Ctx::new`].
pub struct Ctx<'a> {
    /// Infallible allocator (see the crate docs).
    pub heap: &'a mut dyn HeapAlloc,
    reductions: u32,
    /// `usize::MAX` runs the BIF to completion. A finite budget is one scheduler
    /// slice; the BIF records [`lists::DeferredTrap`] only when that slice runs out.
    budget: usize,
    deferred: Option<Box<lists::DeferredTrap>>,
}

impl<'a> Ctx<'a> {
    pub fn new(heap: &'a mut dyn HeapAlloc) -> Self {
        Ctx {
            heap,
            reductions: 0,
            budget: usize::MAX,
            deferred: None,
        }
    }

    /// Reductions left for this call. `usize::MAX` means do not trap.
    pub fn reduction_budget(&self) -> usize {
        self.budget
    }

    /// One scheduler slice, from `ERTS_BIF_REDS_LEFT`.
    pub fn set_reduction_budget(&mut self, budget: usize) {
        self.budget = budget;
    }

    /// Remember a continuation. The VM installs it only after this call returns.
    pub fn defer_trap(&mut self, trap: lists::DeferredTrap) {
        self.deferred = Some(Box::new(trap));
    }

    /// Take a continuation the BIF deferred, if the slice ran out.
    pub fn take_deferred(&mut self) -> Option<Box<lists::DeferredTrap>> {
        self.deferred.take()
    }

    /// Charge work performed by this BIF so the VM can schedule large calls.
    pub fn charge_reductions(&mut self, amount: usize) {
        self.reductions = self
            .reductions
            .saturating_add(amount.min(u32::MAX as usize) as u32);
    }

    /// Return the work charge accumulated during this BIF call.
    pub fn reductions(&self) -> u32 {
        self.reductions
    }
}

/// Signature shared by all BIFs.
pub type BifFn = fn(&mut Ctx<'_>, &[Term]) -> Result<Term, BifError>;

/// Find the implementation of `module:name/arity`.
pub fn lookup(module: &str, name: &str, arity: u8) -> Option<BifFn> {
    arith::lookup(module, name, arity)
        .or_else(|| atomics::lookup(module, name, arity))
        .or_else(|| maps_bifs::lookup(module, name, arity))
        .or_else(|| time::lookup(module, name, arity))
        .or_else(|| sys::lookup(module, name, arity))
        .or_else(|| checksum::lookup(module, name, arity))
        .or_else(|| etf::lookup(module, name, arity))
        .or_else(|| lists::lookup(module, name, arity))
        .or_else(|| pure::lookup(module, name, arity))
        .or_else(|| unicode::lookup(module, name, arity))
}

/// A [`HeapAlloc`] over a [`ProcessHeap`] that never fails: when the heap is
/// full it allocates a heap fragment, which the next GC merges.
pub struct FragmentingHeap<'a>(pub &'a mut ProcessHeap);

impl HeapAlloc for FragmentingHeap<'_> {
    #[inline]
    fn words_left(&self) -> Option<usize> {
        self.0.halloc_words_left()
    }
    #[inline]
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        // Port of erts/emulator/beam/erl_vm.h:150-162 (HAllocX), OTP-29.1.1.
        match self.0.alloc_halloc(words) {
            Some(ptr) => Some(ptr),
            None => Some(self.0.heap_fragment(words)),
        }
    }
    #[inline]
    fn alloc_with_extra(&mut self, words: usize, extra: usize) -> Option<*mut u64> {
        match HeapAlloc::alloc(self.0, words) {
            Some(ptr) => Some(ptr),
            None => Some(self.0.heap_fragment_with_extra(words, extra)),
        }
    }
    fn alloc_fragment_only(&mut self, words: usize) -> Option<*mut u64> {
        HeapAlloc::alloc_fragment_only(self.0, words)
    }
    fn release(&mut self, end: *mut u64, start: *mut u64) {
        self.0.release(end, start)
    }
    fn retain_binary(&mut self, binary: Arc<arinsal_term::RefcBinary>) {
        self.0.retain_binary(binary)
    }
    fn retain_writable_binary(
        &mut self,
        binary: Arc<arinsal_term::WritableBinary>,
    ) -> Result<(), arinsal_term::TermError> {
        self.0.retain_writable_binary(binary)
    }
    fn retain_writable_binary_with_apparent_size(
        &mut self,
        binary: Arc<arinsal_term::WritableBinary>,
        apparent_size_bits: usize,
    ) -> Result<(), arinsal_term::TermError> {
        HeapAlloc::retain_writable_binary_with_apparent_size(self.0, binary, apparent_size_bits)
    }
    fn update_writable_binary_overhead(
        &mut self,
        source: arinsal_term::Term,
        old_size_bits: usize,
        new_size_bits: usize,
    ) {
        HeapAlloc::update_writable_binary_overhead(self.0, source, old_size_bits, new_size_bits)
    }
    fn supports_writable_binary(&self) -> bool {
        self.0.supports_writable_binary()
    }
    fn retain_external_binary(
        &mut self,
        binary: Arc<ExternalBinary>,
    ) -> Result<(), arinsal_term::TermError> {
        self.0.retain_external_binary(binary)
    }
    fn supports_external_binary(&self) -> bool {
        true
    }
    fn retain_node(&mut self, node: Arc<Node>) {
        self.0.retain_node(node)
    }
    fn retain_fun(&mut self, entry: Arc<FunEntry>) {
        self.0.retain_fun(entry)
    }
    fn retain_export(&mut self, entry: Arc<ExportEntry>) {
        self.0.retain_export(entry)
    }
    fn retain_magic(&mut self, owner: Arc<MagicRef>) {
        self.0.retain_magic(owner)
    }
    fn supports_magic(&self) -> bool {
        true
    }
}
