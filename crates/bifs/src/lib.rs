//! BIF registry and the process-independent BIF implementations.
//! Owned by task S1.6.
//!
//! Contract (frozen by the supervisor; implement and extend, never change
//! these signatures):
//! - A BIF is a plain function `fn(&mut Ctx, &[Term]) -> Result<Term, BifError>`.
//! - `Ctx` carries a concrete [`ProcessHeapHandle`] and a mutable FCALLS reference.
//!   `HAlloc` is its inlined `ProcessHeap::alloc_halloc` check with heap-fragment
//!   fallback; `HEAP_TOP`/`HEAP_LIMIT` map to the process heap's cursors and limit.
//! - `HRelease` lowers the young heap top when the block is last. It writes a
//!   filler only for non-top blocks and fragments. `BUMP_REDS` subtracts directly
//!   from FCALLS; the finite budget maps to `ERTS_BIF_REDS_LEFT`.
//! - BIFs never trigger GC (ADR 0007). The process BIF allocator is infallible:
//!   it allocates on the young heap while there is room and in a heap fragment
//!   otherwise. Generic allocators remain available to process-independent helpers.
//! - [`lookup`] returns `None` for BIFs that are not implemented here (for
//!   example the ones that need processes, ETS or code loading).

use std::sync::Arc;

use arinsal_term::{ExternalBinary, HeapAlloc, MagicRef, Node, ProcessHeap, Term};

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

pub use checksum::{ChksumCont, ChksumKind, ChksumStep, chksum_resume, chksum_start};
pub use etf::{DecodeWalk, EncodeWalk, RefcEncoded, encode_term_to_binary, install_refc_binary};
pub use lists::{
    APPEND_ALLOC_PER_RED, APPEND_EMPTY_PER_RED, APPEND_ONHEAP_PER_RED, AppendCont, AppendStep,
    DeferredTrap, KEYFIND_MAX_ITER, KeyOp, KeyOutcome, KeyfindCont, LENGTH_PER_RED, LengthCont,
    LengthStep, MEMBER_PER_RED, MemberCont, MemberStep, REVERSE_CELLS_PER_RED,
    REVERSE_ONHEAP_CELLS_PER_RED, ReverseCont, ReverseStep, SubtractWalk, length_slice,
    lists_append, lists_key, lists_member, lists_member_bif, lists_reverse,
};
pub use maps_bifs::{MapsBuildWalk, MapsProjectionWalk, ProjectionStart};
pub use maps_bifs::{maps_merge_start, maps_merge_start_on_process_heap};
pub use pure::{
    BinarySearchKind, BinarySearchWalk, BinaryToListWalk, IolistCopyWalk, IolistSizeWalk,
    IolistVecWalk, Phash2Cont, Phash2Run, Phash2Step, allocate_iolist_binary, atom_to_list_term,
    binary_bytes, binary_part_2, bitstring_bit_len, copy_binary_pattern, copy_binary_range,
    copy_bitstring_range, copy_bitstring_range_to, eval_unique_integer,
    finish_iolist_binary_output, for_each_list_term, iolist_size_direct, iolist_to_binary_direct,
    iolist_to_iovec_shortcut, iolist_yield_reductions, next_ref_id, next_unique_monotonic,
    phash2_immediate_1, phash2_immediate_result, phash2_run, phash2_run_1,
    phash2_run_1_after_immediate_check, phash2_run_2, phash2_slice, phash2_start,
    proper_list_terms, singleton_bitstring, tuple_arity, tuple_element, tuple_pair, tuple_terms,
    with_binary_bytes, with_iolist_binary_output,
};
pub use time::{
    monotonic_time_milliseconds, monotonic_time_nanos, monotonic_time_raw_nanos, next_now_micros,
    time_offset_nanos_value,
};
pub use unicode::{
    UnicodeCont, UnicodeStage, UnicodeStep, set_locale_utf8 as unicode_set_locale_utf8,
    unicode_resume, unicode_utf8_binary_fast_path,
};
pub use unique::{
    SchedulerRefState, UniqueInt, bind_scheduler_ref_state, debug_make_unique_integer,
    init_unique_scheduler_count, next_ref_words, next_unique_integer,
    next_unique_monotonic_positive, ordinary_ref_key, ordinary_ref_words, scheduler_thr_id,
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

/// Process header state used directly by native BIF bodies.
///
/// The ABI fields stay first and in erts order. Context-only state follows the frozen header
/// prefix, so constructing a BIF context only needs a heap handle and this state pointer.
#[repr(C)]
pub struct BifState {
    /// Current young heap allocation pointer.
    pub htop: *mut u64,
    /// Erlang stack pointer, growing toward lower addresses.
    pub stop: *mut u64,
    /// Young heap start.
    pub heap: *mut u64,
    /// Young heap end.
    pub hend: *mut u64,
    /// Reductions remaining in the current scheduler slice.
    pub fcalls: i32,
    pub _fcalls_pad: u32,
    /// `c_p->freason`, `fvalue` and `ftrace`, adjacent as in erts.
    pub exc: arinsal_term::exc::ExcFields,
    /// Number of active catch tags in the process stack.
    pub catches: usize,
    /// Next instruction or native code pointer.
    pub i: *const core::ffi::c_void,
    /// Current function arity.
    pub arity: u8,
    pub _arity_pad: [u8; 7],
    /// Current function metadata pointer.
    pub current: *const core::ffi::c_void,
    /// Process flags.
    pub flags: u64,
    /// Current process identifier consumed by the inline `self/0` emitter.
    pub self_pid: u64,
    /// First heap address safe for destructive tuple updates.
    pub high_water: *mut u64,
    /// Reduction count at context entry, used to report this call's charge.
    pub initial_fcalls: i32,
    /// Explicit reduction charge for contexts without process FCALLS.
    pub fallback_reductions: u32,
    /// `usize::MAX` runs the BIF to completion. A finite budget is one scheduler slice.
    pub budget: usize,
    /// Deferred continuation installed by the VM after the BIF body returns.
    pub deferred: Option<Box<lists::DeferredTrap>>,
    /// Context-local failure when this state is not attached to a process exception record.
    pub error: Option<BifError>,
    /// Whether reductions are charged against `fcalls`.
    pub has_fcalls: bool,
    /// Whether failures are written to the ABI exception words.
    pub uses_process_exc: bool,
}

impl Default for BifState {
    fn default() -> Self {
        Self {
            htop: core::ptr::null_mut(),
            stop: core::ptr::null_mut(),
            heap: core::ptr::null_mut(),
            hend: core::ptr::null_mut(),
            fcalls: 0,
            _fcalls_pad: 0,
            exc: arinsal_term::exc::ExcFields::default(),
            catches: 0,
            i: core::ptr::null(),
            arity: 0,
            _arity_pad: [0; 7],
            current: core::ptr::null(),
            flags: 0,
            self_pid: 0,
            high_water: core::ptr::null_mut(),
            initial_fcalls: 0,
            fallback_reductions: 0,
            budget: usize::MAX,
            deferred: None,
            error: None,
            has_fcalls: false,
            uses_process_exc: false,
        }
    }
}

impl core::fmt::Debug for BifState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BifState")
            .field("htop", &self.htop)
            .field("stop", &self.stop)
            .field("heap", &self.heap)
            .field("hend", &self.hend)
            .field("fcalls", &self.fcalls)
            .field("exc", &self.exc)
            .field("catches", &self.catches)
            .field("i", &self.i)
            .field("arity", &self.arity)
            .field("current", &self.current)
            .field("flags", &self.flags)
            .field("self_pid", &self.self_pid)
            .field("high_water", &self.high_water)
            .finish_non_exhaustive()
    }
}

impl BifState {
    /// Create BIF state initialized with a caller-owned reduction count.
    pub fn from_fcalls(fcalls: i32) -> Self {
        Self {
            fcalls,
            ..Self::default()
        }
    }

    /// Initialize slice accounting for a context that charges `fcalls`.
    pub fn begin_fcalls(&mut self) {
        self.initial_fcalls = self.fcalls;
        self.fallback_reductions = 0;
        self.budget = usize::MAX;
        // Both fields are `None` on every value path; assigning drops the old value each call.
        if self.deferred.is_some() {
            self.deferred = None;
        }
        if self.error.is_some() {
            self.error = None;
        }
        self.has_fcalls = true;
        self.uses_process_exc = false;
    }

    /// Initialize a process BIF context that writes failures to the ABI exception words.
    pub fn begin_process_call(&mut self) {
        // A process BIF consumes deferred work and context errors before returning. Keep
        // those cold fields untouched on the value path; clearing an `Option<Box<_>>`
        // here makes construction drop glue for every ordinary BIF call.
        self.initial_fcalls = self.fcalls;
        self.budget = usize::MAX;
        self.has_fcalls = true;
        self.uses_process_exc = true;
    }

    /// Initialize a context that tracks reductions only when it explicitly charges them.
    pub fn begin_allocator_call(&mut self) {
        self.initial_fcalls = 0;
        self.fallback_reductions = 0;
        self.budget = usize::MAX;
        self.deferred = None;
        self.error = None;
        self.has_fcalls = false;
        self.uses_process_exc = false;
    }
}

/// Temporary process state for callers that expose reductions separately from the header.
pub struct BifStateGuard<'a> {
    state: BifState,
    fcalls: &'a mut i32,
}

impl<'a> BifStateGuard<'a> {
    /// Build a state view that writes the updated count back when the call scope ends.
    pub fn new(fcalls: &'a mut i32) -> Self {
        Self {
            state: BifState::from_fcalls(*fcalls),
            fcalls,
        }
    }
}

impl core::ops::Deref for BifStateGuard<'_> {
    type Target = BifState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl core::ops::DerefMut for BifStateGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.state
    }
}

impl Drop for BifStateGuard<'_> {
    fn drop(&mut self) {
        *self.fcalls = self.state.fcalls;
    }
}

/// Process-shaped execution handle handed to native BIF bodies.
pub struct ProcessBif<'a, H: HeapAlloc = ProcessHeapHandle<'a>> {
    /// Concrete process heap handle; its HAlloc path is monomorphized.
    pub heap: H,
    state: &'a mut BifState,
}

impl<'a, H: HeapAlloc> ProcessBif<'a, H> {
    /// Construct an allocator-only context over caller-owned BIF state.
    pub fn with_allocator(heap: H, state: &'a mut BifState) -> Self {
        state.begin_allocator_call();
        Self { heap, state }
    }

    pub(crate) fn into_allocator(self) -> H {
        self.heap
    }

    /// Reductions left for this call. `usize::MAX` means do not trap.
    pub fn reduction_budget(&self) -> usize {
        let budget = self.state.budget;
        if self.state.has_fcalls {
            budget.min(self.state.fcalls.max(0) as usize)
        } else {
            budget
        }
    }

    /// One scheduler slice, from `ERTS_BIF_REDS_LEFT`.
    pub fn set_reduction_budget(&mut self, budget: usize) {
        self.state.budget = budget;
    }

    /// Remember a continuation. The VM installs it only after this call returns.
    pub fn defer_trap(&mut self, trap: lists::DeferredTrap) {
        self.state.deferred = Some(Box::new(trap));
    }

    /// Fail the call: leave `error` in the process' failure words (or in the context when it
    /// has none) and return the non-value.
    // Port of erts/emulator/beam/bif.h (BIF_ERROR sets c_p->freason and returns
    // THE_NON_VALUE), OTP-29.1.1.
    #[inline]
    pub fn fail(&mut self, error: BifError) -> Term {
        if self.state.uses_process_exc {
            encode_failure(&mut self.state.exc, error);
        } else {
            self.state.error = Some(error);
        }
        Term::NON_VALUE
    }

    /// `BIF_ERROR(p, BADARG)`.
    #[inline]
    pub fn badarg(&mut self) -> Term {
        self.fail(BifError::BADARG)
    }

    /// `BIF_ERROR(p, SYSTEM_LIMIT)`.
    #[inline]
    pub fn system_limit(&mut self) -> Term {
        self.fail(BifError::SystemLimit)
    }

    /// `BIF_ERROR(p, EXC_ERROR)` with `reason` in `fvalue` (`error:Reason`).
    #[inline]
    pub fn error_reason(&mut self, reason: Term) -> Term {
        self.fail(BifError::Error(reason))
    }

    /// Defer the continuation `trap` and return the non-value: `BIF_TRAP`.
    // Port of erts/emulator/beam/bif.h (BIF_TRAP sets c_p->freason = TRAP), OTP-29.1.1.
    #[inline]
    pub fn trap(&mut self, trap: lists::DeferredTrap) -> Term {
        self.defer_trap(trap);
        self.mark_pending_trap();
        Term::NON_VALUE
    }

    /// Mark a deferred process BIF as a trap while preserving its continuation.
    // Port of BIF_TRAP in erts/emulator/beam/bif.h, OTP-29.1.1.
    pub(crate) fn mark_pending_trap(&mut self) {
        if self.state.uses_process_exc {
            self.state.exc.freason = arinsal_term::exc::TRAP;
        }
    }

    /// The failure of a body that returned the non-value, for a context without process
    /// failure words.
    #[inline]
    pub fn take_context_failure(&mut self) -> Option<BifError> {
        self.state.error.take()
    }

    /// Whether a continuation was deferred.
    #[inline]
    pub fn has_deferred(&self) -> bool {
        self.state.deferred.is_some()
    }

    /// Record why the body returned the non-value.
    #[inline]
    pub fn set_error(&mut self, error: BifError) {
        self.state.error = Some(error);
    }

    /// The failure recorded by [`ProcessBif::set_error`].
    #[inline]
    pub fn take_error(&mut self) -> Option<BifError> {
        self.state.error.take()
    }

    /// Take a continuation the BIF deferred, if the slice ran out.
    pub fn take_deferred(&mut self) -> Option<Box<lists::DeferredTrap>> {
        self.state.deferred.take()
    }

    /// Charge work performed by this BIF so the VM can schedule large calls.
    pub fn charge_reductions(&mut self, amount: usize) {
        if self.state.has_fcalls {
            self.state.fcalls = self
                .state
                .fcalls
                .saturating_sub(i32::try_from(amount).unwrap_or(i32::MAX))
                .max(0);
        } else {
            self.state.fallback_reductions = self
                .state
                .fallback_reductions
                .saturating_add(amount.min(u32::MAX as usize) as u32);
        }
    }

    /// Consume the process' remaining BIF budget.
    ///
    /// Port of `BUMP_ALL_REDS` in `erts/emulator/beam/bif.h:80-82`, OTP-29.1.1.
    pub fn bump_all_reds(&mut self) {
        if self.state.has_fcalls {
            self.state.fcalls = 0;
        } else if self.state.budget != usize::MAX {
            self.charge_reductions(self.state.budget);
        }
    }

    /// Whether this context is attached to the process' live FCALLS value.
    pub fn has_fcalls(&self) -> bool {
        self.state.has_fcalls
    }

    /// Return the work charge accumulated during this BIF call.
    pub fn reductions(&self) -> u32 {
        if self.state.has_fcalls {
            self.state
                .initial_fcalls
                .saturating_sub(self.state.fcalls)
                .max(0) as u32
        } else {
            self.state.fallback_reductions
        }
    }
}

impl<'heap> ProcessBif<'_, ProcessHeapHandle<'heap>> {
    /// Construct a process BIF context by reborrowing the process heap handle.
    #[inline]
    pub fn new<'a>(heap: &'a mut ProcessHeapHandle<'heap>, state: &'a mut BifState) -> Ctx<'a> {
        state.begin_allocator_call();
        Ctx {
            heap: ProcessHeapHandle(&mut *heap.0),
            state,
        }
    }

    /// A context that charges `fcalls` and leaves failures in the process' `exc` words.
    #[inline]
    pub fn with_failure<'a>(
        heap: &'a mut ProcessHeapHandle<'heap>,
        state: &'a mut BifState,
    ) -> Ctx<'a> {
        state.begin_process_call();
        Ctx {
            heap: ProcessHeapHandle(&mut *heap.0),
            state,
        }
    }

    /// Construct a process BIF context that charges the process FCALLS directly.
    #[inline]
    pub fn with_fcalls<'a>(
        heap: &'a mut ProcessHeapHandle<'heap>,
        state: &'a mut BifState,
    ) -> Ctx<'a> {
        state.begin_fcalls();
        Ctx {
            heap: ProcessHeapHandle(&mut *heap.0),
            state,
        }
    }
}

/// Process-independent adapter retained for callers without a VM process.
///
/// Generic allocator callers use the same body through this alias and the
/// body-table adapter; process dispatch uses [`ProcessBif`] directly.
pub type Ctx<'a, H = ProcessHeapHandle<'a>> = ProcessBif<'a, H>;

const _: () = assert!(std::mem::size_of::<Ctx<'static>>() == 2 * std::mem::size_of::<usize>());
const _: () = assert!(std::mem::offset_of!(BifState, fcalls) == 0x20);
const _: () = assert!(std::mem::offset_of!(BifState, exc) == 0x28);
const _: () = assert!(std::mem::offset_of!(BifState, catches) == 0x40);
const _: () = assert!(std::mem::offset_of!(BifState, high_water) == 0x70);

/// Signature shared by all BIFs.
pub type BifFn = fn(&mut Ctx<'_>, &[Term]) -> Result<Term, BifError>;

/// Native process-shaped BIF entry, including the incoming Beam instruction.
pub type ProcessBifFn = fn(&mut ProcessBif<'_>, &[Term], usize) -> Result<Term, BifError>;

/// Leaves `error` in the failure words of a process, as erts leaves `freason`, `fvalue` and
/// `ftrace`. `Unsupported` raises `undef` without its message, and `Dirty` is a `TRAP` whose
/// `ftrace` names the scheduler class (deviations from erts, which has neither).
fn encode_failure(exc: &mut arinsal_term::exc::ExcFields, error: BifError) {
    use arinsal_term::exc::*;
    let class_code = |class: Class| match class {
        Class::Error => EXC_ERROR,
        Class::Exit => EXC_EXIT,
        Class::Throw => EXC_THROWN,
    };
    exc.ftrace = 0;
    match error {
        BifError::Badarg { cause: None } => exc.freason = EXC_BADARG,
        BifError::Badarg { cause: Some(cause) } => {
            exc.freason = EXC_BADARG | EXF_HAS_EXT_INFO;
            exc.ftrace = cause.word();
        }
        BifError::Badarith => exc.freason = EXC_BADARITH,
        BifError::SystemLimit => exc.freason = EXC_SYSTEM_LIMIT,
        BifError::Error(reason) => {
            exc.freason = EXC_ERROR;
            exc.fvalue = reason.word();
        }
        BifError::Raise {
            class,
            reason,
            stacktrace,
        } => {
            // `EXF_ARGLIST` marks a raise (with or without a stacktrace in `ftrace`) and so
            // tells it apart from a plain `error:Reason` failure.
            exc.freason = class_code(class) | EXF_ARGLIST;
            exc.fvalue = reason.word();
            exc.ftrace = stacktrace.map_or(0, Term::word);
        }
        BifError::Unsupported(_) => exc.freason = EXC_UNDEF,
        BifError::Dirty(class) => {
            exc.freason = TRAP;
            exc.ftrace = match class {
                SchedulerClass::Normal => 1,
                SchedulerClass::DirtyCpu => 2,
                SchedulerClass::DirtyIo => 3,
            };
        }
    }
}

/// A BIF body known when its table entry is compiled.
///
/// Port of erts/emulator/beam/erl_bif_table.c (`bif_table[].f`), OTP-29.1.1: every
/// BIF is its own function, so the VM entry that calls it is compiled per BIF.
pub trait BifBody {
    fn call(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError>;

    /// Process entry used by the VM's `bif_table` dispatch.
    fn call_process(
        process: &mut ProcessBif<'_>,
        args: &[Term],
        _instruction: usize,
    ) -> Result<Term, BifError> {
        Self::call(process, args)
    }

    /// The body as erts' BIF function: one word, a term or [`arinsal_term::THE_NON_VALUE`]
    /// with the failure in the context. Bodies that still return a `Result` are adapted here.
    // Port of erts/emulator/beam/bif.h (BIF_ERROR returns THE_NON_VALUE), OTP-29.1.1.
    fn call_word(process: &mut ProcessBif<'_>, args: &[Term], instruction: usize) -> u64 {
        match Self::call_process(process, args, instruction) {
            Ok(_value) if process.has_deferred() => {
                process.mark_pending_trap();
                arinsal_term::THE_NON_VALUE
            }
            Ok(value) => value.word(),
            Err(error) => {
                process.set_error(error);
                arinsal_term::THE_NON_VALUE
            }
        }
    }
}

/// Receives the body of one BIF from [`visit_bif`].
pub trait BifTableVisitor {
    /// What the visitor makes of one BIF.
    type Output;
    fn entry<B: BifBody>(&mut self) -> Self::Output;
}

/// The function pointer of a BIF body: [`lookup`]'s visitor.
struct FnPointer;

impl BifTableVisitor for FnPointer {
    type Output = BifFn;
    fn entry<B: BifBody>(&mut self) -> BifFn {
        B::call
    }
}

/// Hands the body of `module:name/arity` to `visitor`, for the same BIFs [`lookup`]
/// finds. `None` when this crate does not implement it.
pub fn visit_bif<V: BifTableVisitor>(
    module: &str,
    name: &str,
    arity: u8,
    visitor: &mut V,
) -> Option<V::Output> {
    if let Some(found) = arith::lookup(module, name, arity, visitor) {
        return Some(found);
    }
    if let Some(found) = atomics::lookup(module, name, arity, visitor) {
        return Some(found);
    }
    if let Some(found) = maps_bifs::lookup(module, name, arity, visitor) {
        return Some(found);
    }
    if let Some(found) = time::lookup(module, name, arity, visitor) {
        return Some(found);
    }
    if let Some(found) = sys::lookup(module, name, arity, visitor) {
        return Some(found);
    }
    if let Some(found) = checksum::lookup(module, name, arity, visitor) {
        return Some(found);
    }
    if let Some(found) = etf::lookup(module, name, arity, visitor) {
        return Some(found);
    }
    if let Some(found) = lists::lookup(module, name, arity, visitor) {
        return Some(found);
    }
    if let Some(found) = pure::lookup(module, name, arity, visitor) {
        return Some(found);
    }
    unicode::lookup(module, name, arity, visitor)
}

/// One [`BifBody`] per BIF function of a module, named after the function, in
/// that module's `bodies`.
macro_rules! bif_bodies {
    ($($bif:ident),* $(,)?) => {
        #[allow(non_camel_case_types)]
        mod bodies {
            $(
                pub(super) struct $bif;
                impl $crate::BifBody for $bif {
                    fn call(
                        ctx: &mut $crate::Ctx<'_>,
                        args: &[arinsal_term::Term],
                    ) -> Result<arinsal_term::Term, $crate::BifError> {
                        super::$bif(ctx, args)
                    }
                }
            )*
        }
    };
}
pub(crate) use bif_bodies;

/// Process-shaped BIF bodies shared by process dispatch and allocator-only callers.
macro_rules! process_bif_bodies {
    ($($bif:ident),* $(,)?) => {
        $crate::process_bif_bodies_in!(bodies; $($bif),*);
    };
}
pub(crate) use process_bif_bodies;

/// Process-shaped BIF bodies in a separate table module for mixed families.
macro_rules! process_bif_bodies_in {
    ($module:ident; $($bif:ident),* $(,)?) => {
        #[allow(non_camel_case_types)]
        mod $module {
            $(
                pub(super) struct $bif;
                impl $crate::BifBody for $bif {
                    fn call(ctx: &mut $crate::Ctx<'_>, args: &[arinsal_term::Term])
                        -> Result<arinsal_term::Term, $crate::BifError>
                    {
                        <Self as $crate::BifBody>::call_process(ctx, args, 0)
                    }
                    fn call_process(process: &mut $crate::ProcessBif<'_>, args: &[arinsal_term::Term], instruction: usize)
                        -> Result<arinsal_term::Term, $crate::BifError>
                    {
                        let _ = instruction;
                        super::$bif(process, args)
                    }
                }
            )*
        }
    };
}
pub(crate) use process_bif_bodies_in;

/// Bodies that return a term or [`arinsal_term::Term::NON_VALUE`] (erts' BIF shape), in their
/// own table module. `call_word` is the body itself; `call` adapts it for callers that want a
/// `Result`: a deferred continuation is `Ok(NIL)` with the trap in the context, as before.
macro_rules! word_bif_bodies_in {
    ($module:ident; $($bif:ident),* $(,)?) => {
        #[allow(non_camel_case_types)]
        mod $module {
            $(
                pub(super) struct $bif;
                impl $crate::BifBody for $bif {
                    fn call(ctx: &mut $crate::Ctx<'_>, args: &[arinsal_term::Term])
                        -> Result<arinsal_term::Term, $crate::BifError>
                    {
                        let value = super::$bif(ctx, args);
                        if !value.is_non_value() {
                            Ok(value)
                        } else if ctx.has_deferred() {
                            Ok(arinsal_term::Term::NIL)
                        } else {
                            Err(ctx.take_context_failure().unwrap_or($crate::BifError::BADARG))
                        }
                    }
                    #[inline]
                    fn call_word(
                        ctx: &mut $crate::ProcessBif<'_>,
                        args: &[arinsal_term::Term],
                        _instruction: usize,
                    ) -> u64 {
                        let value = super::$bif(ctx, args);
                        if ctx.has_deferred() {
                            ctx.mark_pending_trap();
                            arinsal_term::THE_NON_VALUE
                        } else {
                            value.word()
                        }
                    }
                }
            )*
        }
    };
}
pub(crate) use word_bif_bodies_in;

/// Find the implementation of `module:name/arity`.
pub fn lookup(module: &str, name: &str, arity: u8) -> Option<BifFn> {
    visit_bif(module, name, arity, &mut FnPointer)
}

/// A [`HeapAlloc`] over a [`ProcessHeap`] that never fails: when the heap is
/// full it allocates a heap fragment, which the next GC merges.
/// Concrete process-heap allocator for BIF bodies.
///
/// Port of `HAlloc`/`HAllocX` in erts/emulator/beam/erl_vm.h:150-162, OTP-29.1.1.
pub struct ProcessHeapHandle<'a>(pub &'a mut ProcessHeap);

impl<'heap> ProcessHeapHandle<'heap> {
    /// Bound a direct BIF fill to available young heap and its reduction budget.
    // Port of erts/emulator/beam/erl_bif_lists.c:1204-1214, OTP-29.1.1.
    #[inline(always)]
    pub fn bounded_cursor<'a>(
        &'a mut self,
        max_cells: usize,
    ) -> Option<ProcessHeapCursor<'a, 'heap>> {
        let words_left = self.0.halloc_words_left()?;
        if words_left <= 8 {
            return None;
        }
        let (top, _) = self.0.heap_cursor();
        let limit = top.wrapping_add(words_left);
        let budget_end = top.wrapping_add(max_cells.saturating_mul(2));
        let end = budget_end.min(limit.wrapping_sub(2));
        Some(ProcessHeapCursor {
            heap: self,
            top,
            end,
            cells: 0,
        })
    }
}

/// A bounded cursor for direct `CONS` writes to a process's young heap.
pub struct ProcessHeapCursor<'a, 'heap> {
    heap: &'a mut ProcessHeapHandle<'heap>,
    top: *mut u64,
    end: *mut u64,
    cells: usize,
}

impl ProcessHeapCursor<'_, '_> {
    /// Whether one cons cell fits before the heap or reduction boundary.
    #[inline(always)]
    pub fn has_room(&self) -> bool {
        self.top < self.end
    }

    /// Write one `CONS` cell and return its list term.
    #[inline(always)]
    pub fn push_cons(&mut self, head: Term, tail: Term) -> Option<Term> {
        self.push_cons_with(|| Some((head, tail, ())))
            .map(|(term, ())| term)
    }

    /// Check room before loading the next source cell, then write its cons.
    #[inline(always)]
    pub(crate) fn push_cons_with<R>(
        &mut self,
        make: impl FnOnce() -> Option<(Term, Term, R)>,
    ) -> Option<(Term, R)> {
        if !self.has_room() {
            return None;
        }
        let (head, tail, value) = make()?;
        let cell = self.top;
        // SAFETY: the cursor was clipped to `HEAP_LIMIT - 2`; `top < end` leaves
        // two writable words, and ProcessHeap owns this young-heap allocation.
        unsafe {
            cell.write(head.raw_bits());
            cell.add(1).write(tail.raw_bits());
            let term = Term::from_raw_bits(cell as u64 | 1);
            self.top = self.top.wrapping_add(2);
            self.cells += 1;
            Some((term, value))
        }
    }

    /// Commit the final `HEAP_TOP` and return the number of cells written.
    // Port of erts/emulator/beam/erl_bif_lists.c:1230-1231, OTP-29.1.1.
    #[inline(always)]
    pub fn finish(self) -> usize {
        self.heap.0.set_heap_top(self.top);
        self.cells
    }
}

impl HeapAlloc for ProcessHeapHandle<'_> {
    fn allocator_identity(&self) -> usize {
        self.0.allocator_identity()
    }
    #[inline(always)]
    fn words_left(&self) -> Option<usize> {
        self.0.halloc_words_left()
    }
    #[inline(always)]
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        if let Some(ptr) = self.0.alloc_halloc(words) {
            Some(ptr)
        } else {
            Some(self.0.heap_fragment(words))
        }
    }
    #[inline(always)]
    fn alloc_with_extra(&mut self, words: usize, extra: usize) -> Option<*mut u64> {
        if let Some(ptr) = self.0.alloc_halloc(words) {
            Some(ptr)
        } else {
            Some(self.0.heap_fragment_with_extra(words, extra))
        }
    }
    fn alloc_fragment_only(&mut self, words: usize) -> Option<*mut u64> {
        HeapAlloc::alloc_fragment_only(self.0, words)
    }
    fn release(&mut self, end: *mut u64, start: *mut u64) {
        HeapAlloc::release(self.0, end, start)
    }
    fn release_needs_filler(&self, end: *mut u64, start: *mut u64) -> bool {
        HeapAlloc::release_needs_filler(self.0, end, start)
    }
    fn retain_binary(&mut self, binary: Arc<arinsal_term::RefcBinary>) {
        HeapAlloc::retain_binary(self.0, binary)
    }
    fn link_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        writable: bool,
        overhead_words: u64,
        owner: Option<arinsal_term::OwnedBinaryRef>,
    ) -> Result<(), arinsal_term::TermError> {
        HeapAlloc::link_bin_ref(self.0, bin_ref, writable, overhead_words, owner)
    }
    fn add_bin_vheap(&mut self, words: u64) {
        HeapAlloc::add_bin_vheap(self.0, words)
    }
    fn retain_writable_binary(
        &mut self,
        binary: Arc<arinsal_term::WritableBinary>,
    ) -> Result<(), arinsal_term::TermError> {
        HeapAlloc::retain_writable_binary(self.0, binary)
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
        source: Term,
        old_size_bits: usize,
        new_size_bits: usize,
    ) {
        HeapAlloc::update_writable_binary_overhead(self.0, source, old_size_bits, new_size_bits)
    }
    fn supports_writable_binary(&self) -> bool {
        HeapAlloc::supports_writable_binary(self.0)
    }
    fn link_external_binary(
        &mut self,
        bin_ref: *mut u64,
        binary: Arc<ExternalBinary>,
    ) -> Result<(), arinsal_term::TermError> {
        HeapAlloc::link_external_binary(self.0, bin_ref, binary)
    }
    fn supports_external_binary(&self) -> bool {
        true
    }
    fn link_node(&mut self, thing: *mut u64, node: Arc<Node>) {
        HeapAlloc::link_node(self.0, thing, node)
    }
    fn link_magic_ref(
        &mut self,
        thing: *mut u64,
        owner: Arc<MagicRef>,
    ) -> Result<(), arinsal_term::TermError> {
        HeapAlloc::link_magic_ref(self.0, thing, owner)
    }
    fn supports_magic(&self) -> bool {
        true
    }
}
