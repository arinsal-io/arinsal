//! The list BIFs of `erl_bif_lists.c`.
//!
//! Each BIF is registered directly as `bif_table[].f` with `(c_p, reg, I)`. Trapping
//! continuations use magic binaries and the same export and argument sequence as ERTS.

use crate::VmError;
use crate::bif_traps::TrapContext;
use crate::natives::bif::{bif_badarg, bif_ret, bif_system_limit};
use arinsal_beamasm::ProcessHeader;
use arinsal_bifs::ProcessHeapHandle;
use arinsal_term::raw::{Cons, Tuple, UninitTermArray};
use arinsal_term::{
    ConsHeapBuilder, ConsHeapChain, ConsHeapSegment, MagicBin, Term, TermBuilder, TermError, atoms,
    exact_eq_after_word_mismatch, loose_eq,
};

/// `sizeof(ErtsAppendContext)` on a 64-bit build.
// Port of erts/emulator/beam/erl_bif_lists.c (ErtsAppendContext), OTP-29.1.1.
const ERTS_APPEND_CONTEXT_SIZE: usize = 40;
/// `sizeof(ErtsSubtractContext)` on a 64-bit build.
// Port of erts/emulator/beam/erl_bif_lists.c (ErtsSubtractContext), OTP-29.1.1.
const ERTS_SUBTRACT_CONTEXT_SIZE: usize = 192;
const APPEND_EMPTY_PER_RED: usize = 32;
const APPEND_ONHEAP_PER_RED: usize = 60;
const APPEND_ALLOC_PER_RED: usize = 40;
const MEMBER_PER_RED: usize = 16;
const KEYFIND_MAX_ITER: usize = 10 * 4_000;
const REVERSE_ONHEAP_PER_RED: usize = 60;
const REVERSE_ALLOC_PER_RED: usize = 40;

/// `is_list(term)`: a list primary tag.
#[inline(always)]
fn is_list(term: Term) -> bool {
    term.tagged_word() & 3 == 1
}

/// `CAR` and `CDR` after the caller's list-tag test.
#[inline(always)]
fn cons_cell(term: Term) -> Option<(Term, Term)> {
    Cons::try_from(term).ok().map(Cons::pair)
}

/// `ERTS_BIF_REDS_LEFT(c_p)`.
// Port of erts/emulator/beam/bif.h (ERTS_BIF_REDS_LEFT), OTP-29.1.1.
#[inline(always)]
pub(crate) fn bif_reds_left(process: &crate::Process) -> usize {
    process.heap.abi.fcalls.max(0) as usize
}

/// `BUMP_REDS(p, reds)`.
// Port of erts/emulator/beam/bif.h (BUMP_REDS), OTP-29.1.1.
#[inline(always)]
fn bump_reds(process: &mut crate::Process, reds: usize) {
    process.heap.abi.fcalls = (process.heap.abi.fcalls - reds.min(i32::MAX as usize) as i32).max(0);
}

/// `BUMP_ALL_REDS(p)`.
// Port of erts/emulator/beam/bif.h (BUMP_ALL_REDS), OTP-29.1.1.
#[inline(always)]
fn bump_all_reds(process: &mut crate::Process) {
    process.heap.abi.fcalls = 0;
}

/// `BIF_TRAPn(BIF_TRAP_EXPORT(bif), c_p, args...)`.
#[cold]
#[inline(never)]
pub(crate) fn bif_trap(
    process: &mut crate::Process,
    export: &'static str,
    args: Vec<Term>,
) -> VmError {
    VmError::TrapExport(crate::ExportTrap::new(process, export, args))
}

/// `erts_create_magic_binary` and `erts_mk_magic_ref` for a trap context.
// Port of erts/emulator/beam/erl_bif_lists.c (append_create_trap_state, subtract_create_trap_state), OTP-29.1.1.
pub(crate) fn create_trap_state<T>(
    process: &mut crate::Process,
    context: T,
    c_size: usize,
) -> Result<Term, VmError>
where
    TrapContext<T>: arinsal_term::MagicPayload,
{
    let state: MagicBin = MagicBin::with_erts_payload_size_and_refn(
        TrapContext::new(context),
        c_size,
        arinsal_bifs::next_ref_words(),
    );
    TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
        .magic_ref(state)
        .map_err(|_| {
            VmError::Trap(crate::exceptions::Trap::error(Term::atom(
                atoms::SYSTEM_LIMIT,
            )))
        })
}

/// The native context has the same fields and size as `ErtsAppendContext`.
// Port of erts/emulator/beam/erl_bif_lists.c (ErtsAppendContext), OTP-29.1.1.
struct AppendContext {
    lhs_original: Term,
    rhs_original: Term,
    iterator: Term,
    result: ConsHeapChain,
}

impl AppendContext {
    fn new(lhs: Term, rhs: Term) -> Self {
        Self {
            lhs_original: lhs,
            rhs_original: rhs,
            iterator: lhs,
            result: ConsHeapChain::new(),
        }
    }
}

#[inline(always)]
fn append_result(context: &mut AppendContext, tail: Term) -> Term {
    std::mem::replace(&mut context.result, ConsHeapChain::new()).finish(tail)
}

/// `erlang:'++'/2`.
// Port of erts/emulator/beam/erl_bif_lists.c (ebif_plusplus_2), OTP-29.1.1.
pub(crate) extern "C" fn ebif_plusplus_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    append(c_p, reg, i, "erlang:++/2")
}

/// `erlang:append/2`.
// Port of erts/emulator/beam/erl_bif_lists.c (append_2), OTP-29.1.1.
pub(crate) extern "C" fn append_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    append(c_p, reg, i, "erlang:append/2")
}

/// `append` dispatch, stack context, trap resume, and `BIF_ERROR` handling.
// Port of erts/emulator/beam/erl_bif_lists.c (append), OTP-29.1.1.
#[inline(always)]
fn append(c_p: *mut ProcessHeader, reg: *mut u64, i: u64, export: &'static str) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [lhs, rhs] = crate::bif_table::bif_args::<2>(reg);
    if lhs == Term::NIL {
        return crate::native_hooks::raw(rhs);
    }
    if is_list(lhs) {
        // The context starts on the stack in the hope that the call does not trap.
        let mut context = AppendContext::new(lhs, rhs);
        return match append_continue(process, &mut context) {
            Ok(Some(value)) => crate::native_hooks::raw(value),
            Ok(None) => append_trap(c_p, i, process, context, export),
            Err(TermError::BadArg) => bif_badarg(c_p),
            Err(_) => bif_system_limit(c_p),
        };
    }
    append_resume(c_p, reg, i, process, lhs, export)
}

/// The `is_internal_magic_ref(lhs)` arm of `append`: continue a trapped append.
// Port of erts/emulator/beam/erl_bif_lists.c (append), OTP-29.1.1.
#[inline(never)]
fn append_resume(
    c_p: *mut ProcessHeader,
    reg: *mut u64,
    i: u64,
    process: &mut crate::Process,
    lhs: Term,
    export: &'static str,
) -> u64 {
    let resumed = lhs.with_magic_payload::<TrapContext<AppendContext>, _>(|context| {
        let mut context = context.lock().expect("append context");
        let originals = (context.lhs_original, context.rhs_original);
        (append_continue(process, &mut context), originals)
    });
    let Some((result, (lhs_original, rhs_original))) = resumed else {
        return bif_badarg(c_p);
    };
    match result {
        Ok(Some(value)) => {
            process.set_gc_enabled(true);
            crate::native_hooks::raw(value)
        }
        Ok(None) => {
            let trap = bif_trap(process, export, vec![lhs, Term::NIL]);
            bif_ret(c_p, i, Err(trap))
        }
        Err(TermError::BadArg) => {
            process.set_gc_enabled(true);
            crate::bif_table::set_bif_arg(reg, 0, lhs_original);
            crate::bif_table::set_bif_arg(reg, 1, rhs_original);
            bif_badarg(c_p)
        }
        Err(_) => {
            process.set_gc_enabled(true);
            bif_system_limit(c_p)
        }
    }
}

/// `append_create_trap_state`, `erts_set_gc_state(p, 0)`, then `BIF_TRAP2`.
// Port of erts/emulator/beam/erl_bif_lists.c (append_create_trap_state, append), OTP-29.1.1.
#[cold]
#[inline(never)]
fn append_trap(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    context: AppendContext,
    export: &'static str,
) -> u64 {
    let state_mref = match create_trap_state(process, context, ERTS_APPEND_CONTEXT_SIZE) {
        Ok(state_mref) => state_mref,
        Err(error) => return bif_ret(c_p, i, Err(error)),
    };
    process.set_gc_enabled(false);
    let trap = bif_trap(process, export, vec![state_mref, Term::NIL]);
    bif_ret(c_p, i, Err(trap))
}

/// `append_continue`: nil-RHS scan, young-heap copy, or exact alloc chunk.
// Port of erts/emulator/beam/erl_bif_lists.c (append_continue), OTP-29.1.1.
#[inline(always)]
fn append_continue(
    process: &mut crate::Process,
    context: &mut AppendContext,
) -> Result<Option<Term>, TermError> {
    // Fast lane when the rhs is nil: return lhs.
    if context.rhs_original == Term::NIL {
        return append_empty_rhs(process, context);
    }
    // Build the result on the unused part of the heap if possible, falling back to
    // lists_append_alloc when it runs out.
    lists_append_onheap(process, context)
}

/// Walk `lhs` to check that it is a proper list; the result is `lhs` itself.
// Port of erts/emulator/beam/erl_bif_lists.c (append_empty_rhs), OTP-29.1.1.
#[inline(never)]
fn append_empty_rhs(
    process: &mut crate::Process,
    context: &mut AppendContext,
) -> Result<Option<Term>, TermError> {
    let budget = bif_reds_left(process).saturating_mul(APPEND_EMPTY_PER_RED);
    let mut count = 0;
    while count < budget {
        let Some((_, tail)) = cons_cell(context.iterator) else {
            break;
        };
        context.iterator = tail;
        count += 1;
    }
    bump_reds(process, count / APPEND_EMPTY_PER_RED);
    if context.iterator == Term::NIL {
        return Ok(Some(context.lhs_original));
    }
    if !is_list(context.iterator) {
        return Err(TermError::BadArg);
    }
    Ok(None)
}

/// Copy `lhs` into `[HEAP_TOP, HEAP_LIMIT - 2)` for at most the cells the reductions allow.
// Port of erts/emulator/beam/erl_bif_lists.c (lists_append_onheap), OTP-29.1.1.
#[inline(always)]
fn lists_append_onheap(
    process: &mut crate::Process,
    context: &mut AppendContext,
) -> Result<Option<Term>, TermError> {
    let max_cells = bif_reds_left(process).saturating_mul(APPEND_ONHEAP_PER_RED);
    // The window is `[HEAP_TOP, HEAP_LIMIT)`: its length is `HeapWordsLeft(p)`.
    let Some(window) = process
        .heap
        .halloc_window()
        .filter(|window| window.len() > 8)
    else {
        return lists_append_alloc(process, context);
    };
    // alloc_end = MIN(alloc_top + 2 * cells_left, HEAP_LIMIT - 2); each CDR names the next cell.
    let onheap_max = max_cells.min(window.len().saturating_sub(2) / 2);
    let cells = &mut window.as_chunks_mut::<2>().0[..onheap_max];
    let mut count = 0;
    for cell in cells.iter_mut() {
        let Some((head, tail)) = cons_cell(context.iterator) else {
            break;
        };
        cell[0] = head.tagged_word();
        cell[1] = (cell.as_ptr() as u64).wrapping_add(16) | 1;
        context.iterator = tail;
        count += 1;
    }
    if let Some(segment) = ConsHeapSegment::from_window_cells(&mut cells[..count]) {
        context.result.append_segment(segment);
    }
    process.heap.commit_window(count * 2);
    let cells_left = max_cells.saturating_sub(count);
    bump_reds(process, count / APPEND_ONHEAP_PER_RED);
    if context.iterator == Term::NIL {
        return Ok(Some(append_result(context, context.rhs_original)));
    }
    if !is_list(context.iterator) {
        context.result.suspend();
        return Err(TermError::BadArg);
    }
    if cells_left > APPEND_ONHEAP_PER_RED {
        return lists_append_alloc(process, context);
    }
    context.result.suspend();
    Ok(None)
}

/// Count the cells the reductions allow, then copy them into one `HAlloc`.
// Port of erts/emulator/beam/erl_bif_lists.c (lists_append_alloc), OTP-29.1.1.
#[inline(never)]
fn lists_append_alloc(
    process: &mut crate::Process,
    context: &mut AppendContext,
) -> Result<Option<Term>, TermError> {
    let max_cells = bif_reds_left(process).saturating_mul(APPEND_ALLOC_PER_RED);
    let mut lookahead = context.iterator;
    let mut count = 0;
    while count < max_cells {
        let Some((_, tail)) = cons_cell(lookahead) else {
            break;
        };
        lookahead = tail;
        count += 1;
    }
    bump_reds(process, count / APPEND_ALLOC_PER_RED);
    if lookahead != Term::NIL && !is_list(lookahead) {
        context.result.suspend();
        return Err(TermError::BadArg);
    }

    let mut heap = ProcessHeapHandle(&mut process.heap);
    let mut builder = ConsHeapBuilder::new(&mut heap, count)?;
    for _ in 0..count {
        let (head, tail) = cons_cell(context.iterator).ok_or(TermError::BadArg)?;
        builder.push(head)?;
        context.iterator = tail;
    }
    if let Some(segment) = builder.finish_open() {
        context.result.append_segment(segment);
    }
    if context.iterator == Term::NIL {
        Ok(Some(append_result(context, context.rhs_original)))
    } else {
        context.result.suspend();
        Ok(None)
    }
}

/// `erlang:'--'/2`.
// Port of erts/emulator/beam/erl_bif_lists.c (ebif_minusminus_2), OTP-29.1.1.
pub(crate) extern "C" fn ebif_minusminus_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    subtract(c_p, reg, i, "erlang:--/2")
}

/// `erlang:subtract/2`.
// Port of erts/emulator/beam/erl_bif_lists.c (subtract_2), OTP-29.1.1.
pub(crate) extern "C" fn subtract_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    subtract(c_p, reg, i, "erlang:subtract/2")
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SubtractStage {
    Start,
    LenLhs,
    NaiveLhs,
    LenRhs,
    NaiveRhs,
    SetBuild,
    SetFinish,
}

enum SubtractScratch {
    Empty,
    Lhs(UninitTermArray<16>),
    Rhs(UninitTermArray<16>),
    Set(SubtractTree),
}

/// The stage data retained in the magic binary has the same roles as `ErtsSubtractContext`.
// Port of erts/emulator/beam/erl_bif_lists.c (ErtsSubtractContext), OTP-29.1.1.
struct SubtractContext {
    stage: SubtractStage,
    lhs_original: Term,
    rhs_original: Term,
    lhs_remaining: usize,
    rhs_remaining: usize,
    iterator: Term,
    result: Option<ConsHeapChain>,
    scratch: SubtractScratch,
}

impl SubtractContext {
    fn new(lhs: Term, rhs: Term) -> Self {
        Self {
            stage: SubtractStage::Start,
            lhs_original: lhs,
            rhs_original: rhs,
            lhs_remaining: 0,
            rhs_remaining: 0,
            iterator: Term::NIL,
            result: None,
            scratch: SubtractScratch::Empty,
        }
    }

    fn originals(&self) -> (Term, Term) {
        (self.lhs_original, self.rhs_original)
    }

    /// `subtract_continue`: each entered C stage reads the current FCALLS.
    // Port of erts/emulator/beam/erl_bif_lists.c (subtract_continue), OTP-29.1.1.
    fn step(&mut self, process: &mut crate::Process) -> Result<Option<Term>, TermError> {
        loop {
            match self.stage {
                SubtractStage::Start => {
                    self.stage = SubtractStage::LenLhs;
                    self.iterator = self.lhs_original;
                }
                SubtractStage::LenLhs => {
                    if !subtract_get_length(process, &mut self.iterator, &mut self.lhs_remaining)? {
                        return Ok(None);
                    }
                    if self.lhs_remaining > 0
                        && self.lhs_remaining <= 16
                        && is_list(self.rhs_original)
                    {
                        let mut elements = UninitTermArray::new();
                        let mut iterator = self.lhs_original;
                        if !elements.fill_with(self.lhs_remaining, || {
                            let (head, tail) = cons_cell(iterator)?;
                            iterator = tail;
                            Some(head)
                        }) {
                            return Err(TermError::BadArg);
                        }
                        self.iterator = self.rhs_original;
                        self.result = None;
                        self.scratch = SubtractScratch::Lhs(elements);
                        self.stage = SubtractStage::NaiveLhs;
                    } else {
                        self.iterator = self.rhs_original;
                        self.stage = SubtractStage::LenRhs;
                    }
                }
                SubtractStage::NaiveLhs => {
                    return self.step_naive_lhs(process);
                }
                SubtractStage::LenRhs => {
                    if !subtract_get_length(process, &mut self.iterator, &mut self.rhs_remaining)? {
                        return Ok(None);
                    }
                    if self.lhs_remaining == 0 {
                        return Ok(Some(Term::NIL));
                    }
                    if self.rhs_remaining == 0 {
                        return Ok(Some(self.lhs_original));
                    }
                    self.iterator = self.lhs_original;
                    self.result = Some(ConsHeapChain::new());
                    if self.rhs_remaining <= 16 {
                        let mut elements = UninitTermArray::new();
                        let mut iterator = self.rhs_original;
                        if !elements.fill_with(self.rhs_remaining, || {
                            let (head, tail) = cons_cell(iterator)?;
                            iterator = tail;
                            Some(head)
                        }) {
                            return Err(TermError::BadArg);
                        }
                        self.scratch = SubtractScratch::Rhs(elements);
                        self.stage = SubtractStage::NaiveRhs;
                    } else {
                        self.scratch =
                            SubtractScratch::Set(SubtractTree::with_capacity(self.rhs_remaining));
                        self.iterator = self.rhs_original;
                        self.stage = SubtractStage::SetBuild;
                    }
                }
                SubtractStage::NaiveRhs => return self.step_naive_rhs(process),
                SubtractStage::SetBuild => {
                    if !self.step_set_build(process) {
                        return Ok(None);
                    }
                    self.stage = SubtractStage::SetFinish;
                    self.iterator = self.lhs_original;
                }
                SubtractStage::SetFinish => return self.step_set_finish(process),
            }
        }
    }

    /// `subtract_naive_lhs`: remove matching RHS elements from the <=16-entry LHS array.
    // Port of erts/emulator/beam/erl_bif_lists.c (subtract_naive_lhs), OTP-29.1.1.
    fn step_naive_lhs(&mut self, process: &mut crate::Process) -> Result<Option<Term>, TermError> {
        let SubtractScratch::Lhs(elements) = &mut self.scratch else {
            unreachable!("NAIVE_LHS owns the fixed LHS array")
        };
        let budget = bif_reds_left(process).saturating_mul(16);
        let mut checks = 0usize;
        while checks < budget {
            let Some((value, next)) = cons_cell(self.iterator) else {
                break;
            };
            if let Some(found_at) = elements
                .as_slice()
                .iter()
                .position(|&candidate| subtract_term_eq(value, candidate))
            {
                elements.shift_down(found_at);
            }
            checks = checks.saturating_add(elements.len().max(1));
            self.iterator = next;
        }
        bump_reds(process, checks.min(budget) / 16);
        if self.iterator != Term::NIL {
            if !is_list(self.iterator) {
                return Err(TermError::BadArg);
            }
            return Ok(None);
        }
        let values = elements.as_slice();
        if values.is_empty() {
            return Ok(Some(Term::NIL));
        }
        let result = TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
            .reserve_cons_list(values.len())?
            .prepend_exact_with_tail(values.iter().rev().copied(), Term::NIL)?;
        Ok(Some(result))
    }

    /// `subtract_naive_rhs`: scan LHS and consume the last matching RHS occurrence.
    // Port of erts/emulator/beam/erl_bif_lists.c (subtract_naive_rhs), OTP-29.1.1.
    fn step_naive_rhs(&mut self, process: &mut crate::Process) -> Result<Option<Term>, TermError> {
        let budget = bif_reds_left(process).saturating_mul(16);
        let SubtractScratch::Rhs(elements) = &mut self.scratch else {
            unreachable!("NAIVE_RHS owns the fixed RHS array")
        };
        let mut checks = 0usize;
        while checks < budget {
            let Some((value, next)) = cons_cell(self.iterator) else {
                break;
            };
            let found_at = (0..self.rhs_remaining)
                .rev()
                .find(|&index| subtract_term_eq(value, elements.get(index)));
            if let Some(found_at) = found_at {
                if self.rhs_remaining == 1 {
                    bump_reds(process, checks.min(budget) / 16);
                    return Ok(Some(
                        self.result
                            .take()
                            .expect("NAIVE_RHS result chain")
                            .finish(next),
                    ));
                }
                self.rhs_remaining -= 1;
                elements.set(found_at, elements.get(self.rhs_remaining));
            } else {
                self.result
                    .as_mut()
                    .expect("NAIVE_RHS result chain")
                    .push(&mut process.heap, value, self.lhs_remaining)
                    .map_err(|_| TermError::SystemLimit)?;
            }
            checks = checks.saturating_add(self.rhs_remaining);
            self.iterator = next;
            self.lhs_remaining -= 1;
        }
        if self.iterator != Term::NIL && !is_list(self.iterator) {
            return Err(TermError::BadArg);
        }
        bump_reds(process, checks.min(budget) / 16);
        if self.iterator == Term::NIL {
            return Ok(Some(
                self.result
                    .take()
                    .expect("NAIVE_RHS result chain")
                    .finish(Term::NIL),
            ));
        }
        self.result
            .as_ref()
            .expect("NAIVE_RHS result chain")
            .suspend();
        Ok(None)
    }

    /// `subtract_set_build`: insert each RHS term into its multiplicity tree.
    // Port of erts/emulator/beam/erl_bif_lists.c (subtract_set_build), OTP-29.1.1.
    fn step_set_build(&mut self, process: &mut crate::Process) -> bool {
        let budget = bif_reds_left(process).saturating_mul(16);
        let SubtractScratch::Set(tree) = &mut self.scratch else {
            unreachable!("SET_BUILD owns the RHS tree")
        };
        let mut insertions = 0usize;
        while insertions < budget {
            let Some((value, next)) = cons_cell(self.iterator) else {
                break;
            };
            tree.insert(value);
            self.iterator = next;
            insertions += 1;
        }
        bump_reds(process, insertions / 16);
        self.iterator == Term::NIL
    }

    /// `subtract_set_finish`: retain unmatched heads and splice the tail when the set empties.
    // Port of erts/emulator/beam/erl_bif_lists.c (subtract_set_finish), OTP-29.1.1.
    fn step_set_finish(&mut self, process: &mut crate::Process) -> Result<Option<Term>, TermError> {
        let budget = bif_reds_left(process).saturating_mul(8);
        let SubtractScratch::Set(tree) = &mut self.scratch else {
            unreachable!("SET_FINISH owns the RHS tree")
        };
        let mut checks = 0usize;
        while checks < budget {
            let Some((value, next)) = cons_cell(self.iterator) else {
                break;
            };
            if let Some(node) = tree.lookup(value) {
                if self.rhs_remaining == 1 {
                    bump_reds(process, checks / 8);
                    return Ok(Some(
                        self.result
                            .take()
                            .expect("SET_FINISH result chain")
                            .finish(next),
                    ));
                }
                self.rhs_remaining -= 1;
                tree.consume(node);
            } else {
                self.result
                    .as_mut()
                    .expect("SET_FINISH result chain")
                    .push(&mut process.heap, value, self.lhs_remaining)
                    .map_err(|_| TermError::SystemLimit)?;
            }
            self.iterator = next;
            self.lhs_remaining -= 1;
            checks += 1;
        }
        self.result
            .as_ref()
            .expect("SET_FINISH result chain")
            .suspend();
        bump_reds(process, checks / 8);
        if self.iterator == Term::NIL {
            return Ok(Some(
                self.result
                    .take()
                    .expect("SET_FINISH result chain")
                    .finish(Term::NIL),
            ));
        }
        Ok(None)
    }
}

/// `subtract_get_length`, in 32-cell reduction slices.
// Port of erts/emulator/beam/erl_bif_lists.c (subtract_get_length), OTP-29.1.1.
fn subtract_get_length(
    process: &mut crate::Process,
    iterator: &mut Term,
    count: &mut usize,
) -> Result<bool, TermError> {
    let budget = bif_reds_left(process).saturating_mul(32);
    let mut scanned = 0;
    while scanned < budget {
        let Some((_, tail)) = cons_cell(*iterator) else {
            break;
        };
        *iterator = tail;
        *count += 1;
        scanned += 1;
    }
    if *iterator != Term::NIL && !is_list(*iterator) {
        return Err(TermError::BadArg);
    }
    bump_reds(process, scanned / 32);
    Ok(*iterator == Term::NIL)
}

/// `EQ` as used by `subtract_naive_lhs` and the tree path.
// Port of `EQ` in erts/emulator/beam/erl_bif_lists.c, OTP-29.1.1.
#[inline(always)]
fn subtract_term_eq(left: Term, right: Term) -> bool {
    left == right
        || (!(left.is_immed() && right.is_immed()) && exact_eq_after_word_mismatch(left, right))
}

/// Validate the arguments, run the same subtract stages, and resume the magic state.
// Port of erts/emulator/beam/erl_bif_lists.c (subtract), OTP-29.1.1.
fn subtract(c_p: *mut ProcessHeader, reg: *mut u64, i: u64, export: &'static str) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [lhs, rhs] = crate::bif_table::bif_args::<2>(reg);
    if (is_list(lhs) || lhs == Term::NIL) && (is_list(rhs) || rhs == Term::NIL) {
        let mut context = SubtractContext::new(lhs, rhs);
        return match context.step(process) {
            Ok(Some(value)) => crate::native_hooks::raw(value),
            Ok(None) => subtract_trap(c_p, i, process, context, export),
            Err(TermError::BadArg) => bif_badarg(c_p),
            Err(_) => bif_system_limit(c_p),
        };
    }
    let resumed = lhs.with_magic_payload::<TrapContext<SubtractContext>, _>(|context| {
        let mut context = context.lock().expect("subtract context");
        let originals = context.originals();
        (context.step(process), originals)
    });
    let Some((result, (lhs_original, rhs_original))) = resumed else {
        return bif_badarg(c_p);
    };
    match result {
        Ok(Some(value)) => {
            process.set_gc_enabled(true);
            crate::native_hooks::raw(value)
        }
        Ok(None) => {
            let trap = bif_trap(process, export, vec![lhs, Term::NIL]);
            bif_ret(c_p, i, Err(trap))
        }
        Err(TermError::BadArg) => {
            process.set_gc_enabled(true);
            crate::bif_table::set_bif_arg(reg, 0, lhs_original);
            crate::bif_table::set_bif_arg(reg, 1, rhs_original);
            bif_badarg(c_p)
        }
        Err(_) => {
            process.set_gc_enabled(true);
            bif_system_limit(c_p)
        }
    }
}

/// `subtract_create_trap_state`, `erts_set_gc_state(p, 0)`, then `BIF_TRAP2`.
// Port of erts/emulator/beam/erl_bif_lists.c (subtract_create_trap_state, subtract), OTP-29.1.1.
#[cold]
#[inline(never)]
fn subtract_trap(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    context: SubtractContext,
    export: &'static str,
) -> u64 {
    let state_mref = match create_trap_state(process, context, ERTS_SUBTRACT_CONTEXT_SIZE) {
        Ok(state_mref) => state_mref,
        Err(error) => return bif_ret(c_p, i, Err(error)),
    };
    process.set_gc_enabled(false);
    let trap = bif_trap(process, export, vec![state_mref, Term::NIL]);
    bif_ret(c_p, i, Err(trap))
}

/// `lists:member/2`.
// Port of erts/emulator/beam/erl_bif_lists.c (lists_member_2), OTP-29.1.1.
pub(crate) extern "C" fn lists_member_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    let [term, list] = crate::bif_table::bif_args::<2>(reg);
    if list == Term::NIL {
        return crate::native_hooks::raw(Term::atom(atoms::FALSE));
    }
    if !is_list(list) {
        return bif_badarg(c_p);
    }
    let reds_left = bif_reds_left(process);
    let mut max_iter = reds_left.saturating_mul(MEMBER_PER_RED);
    let mut list = list;
    while is_list(list) {
        if max_iter == 0 {
            bump_all_reds(process);
            let trap = bif_trap(process, "lists:member/2", vec![term, list]);
            return bif_ret(c_p, i, Err(trap));
        }
        max_iter -= 1;
        let (item, next) = cons_cell(list).expect("list tag is a cons cell");
        if item == term || (term.tagged_word() & 3 != 3 && exact_eq_after_word_mismatch(item, term))
        {
            bump_reds(process, reds_left - max_iter / MEMBER_PER_RED);
            return crate::native_hooks::raw(Term::atom(atoms::TRUE));
        }
        list = next;
    }
    bump_reds(process, reds_left - max_iter / MEMBER_PER_RED);
    if list != Term::NIL {
        return bif_badarg(c_p);
    }
    crate::native_hooks::raw(Term::atom(atoms::FALSE))
}

/// `lists:reverse/2`.
// Port of erts/emulator/beam/erl_bif_lists.c (lists_reverse_2), OTP-29.1.1.
pub(crate) extern "C" fn lists_reverse_2(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [list, tail] = crate::bif_table::bif_args::<2>(reg);
    // Handle legal and illegal non-lists quickly.
    if list == Term::NIL {
        return crate::native_hooks::raw(tail);
    }
    if !is_list(list) {
        return bif_badarg(c_p);
    }
    // Build the reversal on the unused part of the heap if possible, falling back to
    // lists_reverse_alloc when it runs out.
    lists_reverse_onheap(c_p, i, process, list, tail)
}

/// Reverse into `[HEAP_TOP, HEAP_LIMIT - 2)` for at most the cells the reductions allow.
// Port of erts/emulator/beam/erl_bif_lists.c (lists_reverse_onheap), OTP-29.1.1.
#[inline(always)]
fn lists_reverse_onheap(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    mut list: Term,
    mut tail: Term,
) -> u64 {
    let max_cells = bif_reds_left(process).saturating_mul(REVERSE_ONHEAP_PER_RED);
    // The window is `[HEAP_TOP, HEAP_LIMIT)`: its length is `HeapWordsLeft(c_p)`.
    let Some(window) = process
        .heap
        .halloc_window()
        .filter(|window| window.len() > 8)
    else {
        return lists_reverse_alloc(c_p, i, process, list, tail);
    };
    // alloc_end = MIN(alloc_top + 2 * cells_left, HEAP_LIMIT - 2).
    let available = max_cells.min(window.len().saturating_sub(2) / 2);
    let mut tail_bits = tail.tagged_word();
    let mut cells = 0usize;
    for cell in &mut window.as_chunks_mut::<2>().0[..available] {
        let Some((head, next)) = cons_cell(list) else {
            break;
        };
        cell[0] = head.tagged_word();
        cell[1] = tail_bits;
        tail_bits = cell.as_ptr() as u64 | 1;
        list = next;
        cells += 1;
    }
    if cells != 0 {
        tail = process.heap.window_list_term((cells - 1) * 2);
    }
    process.heap.commit_window(cells * 2);
    let cells_left = max_cells.saturating_sub(cells);
    bump_reds(process, cells / REVERSE_ONHEAP_PER_RED);
    if list == Term::NIL {
        return crate::native_hooks::raw(tail);
    }
    if !is_list(list) {
        return bif_badarg(c_p);
    }
    if cells_left > REVERSE_ONHEAP_PER_RED {
        return lists_reverse_alloc(c_p, i, process, list, tail);
    }
    bump_all_reds(process);
    lists_reverse_trap(c_p, i, process, list, tail)
}

/// Count the cells the reductions allow, then build them in one `HAlloc`.
// Port of erts/emulator/beam/erl_bif_lists.c (lists_reverse_alloc), OTP-29.1.1.
#[inline(never)]
fn lists_reverse_alloc(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    mut list: Term,
    mut tail: Term,
) -> u64 {
    let max_cells = bif_reds_left(process).saturating_mul(REVERSE_ALLOC_PER_RED);
    let mut lookahead = list;
    let mut cells = 0usize;
    while cells < max_cells {
        let Some((_, next)) = cons_cell(lookahead) else {
            break;
        };
        lookahead = next;
        cells += 1;
    }
    bump_reds(process, cells / REVERSE_ALLOC_PER_RED);
    if lookahead != Term::NIL && !is_list(lookahead) {
        return bif_badarg(c_p);
    }
    let built = TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
        .reserve_cons_list(cells)
        .and_then(|builder| {
            let mut values = list;
            let reversed = builder.prepend_exact_with_tail(
                std::iter::from_fn(|| {
                    let (head, next) = cons_cell(values)?;
                    values = next;
                    Some(head)
                })
                .take(cells),
                tail,
            )?;
            Ok((reversed, values))
        });
    match built {
        Ok((reversed, rest)) => {
            tail = reversed;
            list = rest;
        }
        Err(TermError::BadArg) => return bif_badarg(c_p),
        Err(_) => return bif_system_limit(c_p),
    }
    if list == Term::NIL {
        return crate::native_hooks::raw(tail);
    }
    lists_reverse_trap(c_p, i, process, list, tail)
}

/// `BIF_TRAP2(&bif_trap_export[BIF_lists_reverse_2], c_p, list, tail)`.
#[cold]
#[inline(never)]
fn lists_reverse_trap(
    c_p: *mut ProcessHeader,
    i: u64,
    process: &mut crate::Process,
    list: Term,
    tail: Term,
) -> u64 {
    let trap = bif_trap(process, "lists:reverse/2", vec![list, tail]);
    bif_ret(c_p, i, Err(trap))
}

/// `lists:keymember/3`.
// Port of erts/emulator/beam/erl_bif_lists.c (lists_keymember_3), OTP-29.1.1.
pub(crate) extern "C" fn lists_keymember_3(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    keyfind(c_p, reg, i, KeyOp::Member, "lists:keymember/3")
}

/// `lists:keysearch/3`.
// Port of erts/emulator/beam/erl_bif_lists.c (lists_keysearch_3), OTP-29.1.1.
pub(crate) extern "C" fn lists_keysearch_3(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    keyfind(c_p, reg, i, KeyOp::Search, "lists:keysearch/3")
}

/// `lists:keyfind/3`.
// Port of erts/emulator/beam/erl_bif_lists.c (lists_keyfind_3), OTP-29.1.1.
pub(crate) extern "C" fn lists_keyfind_3(c_p: *mut ProcessHeader, reg: *mut u64, i: u64) -> u64 {
    keyfind(c_p, reg, i, KeyOp::Find, "lists:keyfind/3")
}

#[derive(Clone, Copy)]
enum KeyOp {
    Find,
    Member,
    Search,
}

enum KeyOutcome {
    Done(Option<Term>),
    Trap(Term, Term, Term),
}

/// `keyfind` and the three export result wrappers.
// Port of erts/emulator/beam/erl_bif_lists.c (keyfind, lists_keymember_3, lists_keysearch_3), OTP-29.1.1.
fn keyfind(c_p: *mut ProcessHeader, reg: *mut u64, i: u64, op: KeyOp, export: &'static str) -> u64 {
    let Some(process) = crate::native_hooks::process_from_header(c_p) else {
        return 0;
    };
    process.heap.note_bif_entry();
    let [key, pos, list] = crate::bif_table::bif_args::<3>(reg);
    match keyfind_slice(process, key, pos, list) {
        Err(TermError::BadArg) => bif_badarg(c_p),
        Err(_) => bif_system_limit(c_p),
        Ok(KeyOutcome::Trap(key, pos, list)) => {
            let trap = bif_trap(process, export, vec![key, pos, list]);
            bif_ret(c_p, i, Err(trap))
        }
        Ok(KeyOutcome::Done(found)) => {
            let result = match op {
                KeyOp::Find => found.unwrap_or(Term::atom(atoms::FALSE)),
                KeyOp::Member => Term::atom(if found.is_some() {
                    atoms::TRUE
                } else {
                    atoms::FALSE
                }),
                KeyOp::Search => match found {
                    Some(tuple) => {
                        match TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
                            .tuple2(Term::atom(atoms::VALUE), tuple)
                        {
                            Ok(value) => value,
                            Err(_) => return bif_system_limit(c_p),
                        }
                    }
                    None => Term::atom(atoms::FALSE),
                },
            };
            crate::native_hooks::raw(result)
        }
    }
}

/// `keyfind`: small keys also match numerically equal floats; other immediates use word equality.
// Port of erts/emulator/beam/erl_bif_lists.c (keyfind), OTP-29.1.1.
fn keyfind_slice(
    process: &mut crate::Process,
    key: Term,
    pos_term: Term,
    mut list: Term,
) -> Result<KeyOutcome, TermError> {
    let pos = pos_term
        .as_small()
        .filter(|position| *position >= 1)
        .ok_or(TermError::BadArg)?;
    let mut remaining = KEYFIND_MAX_ITER;
    let small_key = key.as_small();
    while is_list(list) {
        if remaining == 0 {
            bump_all_reds(process);
            return Ok(KeyOutcome::Trap(key, pos_term, list));
        }
        remaining -= 1;
        let (tuple_term, next) = cons_cell(list).ok_or(TermError::BadArg)?;
        list = next;
        let Ok(tuple) = Tuple::try_from(tuple_term) else {
            continue;
        };
        let Some(element) = tuple.get(pos as usize - 1) else {
            continue;
        };
        let matched = if let Some(small) = small_key {
            element == key
                || element
                    .float_value()
                    .is_some_and(|value| value == small as f64)
        } else if key.is_immed() {
            element == key
        } else {
            loose_eq(key, element)
        };
        if matched {
            return Ok(KeyOutcome::Done(Some(tuple_term)));
        }
    }
    if list != Term::NIL {
        return Err(TermError::BadArg);
    }
    Ok(KeyOutcome::Done(None))
}

mod subtract_tree {

    //! Red-black tree used by `erlang:'--'/2`.

    use arinsal_term::{Term, cmp_exact, global_atoms};
    use std::cmp::Ordering;
    use std::ops::{Index, IndexMut};

    const NONE: usize = 0;

    /// One node in the preallocated contiguous multiset node area.
    ///
    /// Port of `erts/emulator/beam/erl_bif_lists.c:389-398` and the configured
    /// `erl_rbtree.h` node operations, OTP-29.1.1. Pointer addresses retain the C
    /// node links' values, order, and width while keeping all tree manipulation safe.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Node {
        parent: usize,
        left: usize,
        right: usize,
        is_red: i32,
        key: Term,
        count: usize,
    }

    impl Node {
        fn candidate(key: Term) -> Self {
            Self {
                parent: 0,
                left: 0,
                right: 0,
                is_red: 0,
                key,
                count: 1,
            }
        }
    }

    /// Address-indexed view of the contiguous node allocation. ERTS stores native pointers in each
    /// node; this safe index maps those same pointer words into the Rust-owned array.
    struct NodeArena(Vec<Node>);

    impl NodeArena {
        fn with_capacity(capacity: usize) -> Self {
            Self(Vec::with_capacity(capacity))
        }

        fn push(&mut self, node: Node) -> usize {
            debug_assert!(self.0.len() < self.0.capacity());
            let address = self.0.as_ptr().wrapping_add(self.0.len()) as usize;
            self.0.push(node);
            address
        }

        fn pop(&mut self) {
            self.0.pop().expect("unlinked candidate node");
        }

        #[cfg(test)]
        fn len(&self) -> usize {
            self.0.len()
        }

        fn index_of(&self, address: usize) -> usize {
            debug_assert_ne!(address, NONE);
            let base = self.0.as_ptr() as usize;
            let offset = address.checked_sub(base).expect("node address in arena");
            debug_assert_eq!(offset % std::mem::size_of::<Node>(), 0);
            let index = offset / std::mem::size_of::<Node>();
            debug_assert!(index < self.0.len());
            index
        }
    }

    impl Index<usize> for NodeArena {
        type Output = Node;

        fn index(&self, address: usize) -> &Self::Output {
            &self.0[self.index_of(address)]
        }
    }

    impl IndexMut<usize> for NodeArena {
        fn index_mut(&mut self, address: usize) -> &mut Self::Output {
            let index = self.index_of(address);
            &mut self.0[index]
        }
    }

    /// A contiguous red-black multiset with one count per exact Erlang key.
    pub(super) struct RbTree {
        nodes: NodeArena,
        root: usize,
    }

    impl RbTree {
        /// Reserve room for the maximum number of distinct input keys.
        ///
        /// Port of `subtract_enter_set_build` at `erl_bif_lists.c:797-804`, OTP-29.1.1.
        pub(super) fn with_capacity(capacity: usize) -> Self {
            Self {
                nodes: NodeArena::with_capacity(capacity),
                root: NONE,
            }
        }

        /// Add one occurrence, returning the existing or newly inserted node.
        ///
        /// Port of `erl_rbtree.h:1056-1139` (`insert_aux__` and
        /// `lookup_insert`), OTP-29.1.1.
        pub(super) fn insert(&mut self, key: Term) -> usize {
            let index = self.nodes.push(Node::candidate(key));
            // OTP writes key/count into the next arena slot before lookup_insert initializes
            // its links and searches the tree. A duplicate leaves alloc unchanged, so pop the
            // unlinked candidate after incrementing the existing node.
            if self.root == NONE {
                self.root = index;
                return index;
            }

            let mut cursor = self.root;
            loop {
                let direction = subtract_term_cmp(self.nodes[index].key, self.nodes[cursor].key);
                if direction == Ordering::Equal {
                    self.nodes[cursor].count += 1;
                    self.nodes.pop();
                    return cursor;
                }
                let child = if direction == Ordering::Less {
                    self.nodes[cursor].left
                } else {
                    self.nodes[cursor].right
                };
                if child == NONE {
                    self.nodes[index].parent = cursor;
                    self.nodes[index].is_red = 1;
                    if direction == Ordering::Less {
                        self.nodes[cursor].left = index;
                    } else {
                        self.nodes[cursor].right = index;
                    }
                    break;
                }
                cursor = child;
            }

            if self.is_red(cursor) {
                self.insert_fixup(index);
            }
            index
        }

        /// Find a key by OTP's exact term ordering.
        ///
        /// Port of `erl_rbtree.h:1249-1292` (`lookup`), OTP-29.1.1.
        pub(super) fn lookup(&self, key: Term) -> Option<usize> {
            let mut cursor = self.root;
            while cursor != NONE {
                let node = self.nodes[cursor];
                match subtract_term_cmp(key, node.key) {
                    Ordering::Equal => return Some(cursor),
                    Ordering::Less => cursor = node.left,
                    Ordering::Greater => cursor = node.right,
                }
            }
            None
        }

        /// Return the number of still available occurrences for a found key.
        #[cfg(test)]
        pub(super) fn count(&self, node: usize) -> usize {
            self.nodes[node].count
        }

        /// Consume one occurrence of a key, deleting its node when its count ends.
        ///
        /// Port of `erl_rbtree.h:705-935` (`delete`), OTP-29.1.1.
        pub(super) fn consume(&mut self, node: usize) {
            if self.nodes[node].count > 1 {
                self.nodes[node].count -= 1;
                return;
            }
            self.delete_node(node);
        }

        fn is_red(&self, node: usize) -> bool {
            node != NONE && self.nodes[node].is_red != 0
        }

        fn set_red(&mut self, node: usize) {
            if node != NONE {
                self.nodes[node].is_red = 1;
            }
        }

        fn set_black(&mut self, node: usize) {
            if node != NONE {
                self.nodes[node].is_red = 0;
            }
        }

        fn parent(&self, node: usize) -> usize {
            if node == NONE {
                NONE
            } else {
                self.nodes[node].parent
            }
        }

        fn left(&self, node: usize) -> usize {
            if node == NONE {
                NONE
            } else {
                self.nodes[node].left
            }
        }

        fn right(&self, node: usize) -> usize {
            if node == NONE {
                NONE
            } else {
                self.nodes[node].right
            }
        }

        /// Rotate a subtree left.
        ///
        /// Port of `erl_rbtree.h:565-600` (`left_rotate__`), OTP-29.1.1.
        fn left_rotate(&mut self, x: usize) {
            let y = self.nodes[x].right;
            let left = self.nodes[y].left;
            self.nodes[x].right = left;
            if left != NONE {
                self.nodes[left].parent = x;
            }
            let parent = self.nodes[x].parent;
            self.nodes[y].parent = parent;
            if parent == NONE {
                self.root = y;
            } else if self.nodes[parent].left == x {
                self.nodes[parent].left = y;
            } else {
                self.nodes[parent].right = y;
            }
            self.nodes[y].left = x;
            self.nodes[x].parent = y;
        }

        /// Rotate a subtree right.
        ///
        /// Port of `erl_rbtree.h:602-639` (`right_rotate__`), OTP-29.1.1.
        fn right_rotate(&mut self, x: usize) {
            let y = self.nodes[x].left;
            let right = self.nodes[y].right;
            self.nodes[x].left = right;
            if right != NONE {
                self.nodes[right].parent = x;
            }
            let parent = self.nodes[x].parent;
            self.nodes[y].parent = parent;
            if parent == NONE {
                self.root = y;
            } else if self.nodes[parent].right == x {
                self.nodes[parent].right = y;
            } else {
                self.nodes[parent].left = y;
            }
            self.nodes[y].right = x;
            self.nodes[x].parent = y;
        }

        /// Restore the red-black properties after insertion.
        ///
        /// Port of `erl_rbtree.h:939-1054` (`insert_fixup__`), OTP-29.1.1.
        fn insert_fixup(&mut self, mut x: usize) {
            while x != self.root && self.is_red(self.parent(x)) {
                let parent = self.parent(x);
                let grandparent = self.parent(parent);
                if parent == self.nodes[grandparent].left {
                    let uncle = self.nodes[grandparent].right;
                    if self.is_red(uncle) {
                        self.set_black(uncle);
                        self.set_black(parent);
                        self.set_red(grandparent);
                        x = grandparent;
                    } else {
                        if x == self.nodes[parent].right {
                            x = parent;
                            self.left_rotate(x);
                        }
                        let parent = self.parent(x);
                        let grandparent = self.parent(parent);
                        self.set_black(parent);
                        self.set_red(grandparent);
                        self.right_rotate(grandparent);
                        break;
                    }
                } else {
                    let uncle = self.nodes[grandparent].left;
                    if self.is_red(uncle) {
                        self.set_black(uncle);
                        self.set_black(parent);
                        self.set_red(grandparent);
                        x = grandparent;
                    } else {
                        if x == self.nodes[parent].left {
                            x = parent;
                            self.right_rotate(x);
                        }
                        let parent = self.parent(x);
                        let grandparent = self.parent(parent);
                        self.set_black(parent);
                        self.set_red(grandparent);
                        self.left_rotate(grandparent);
                        break;
                    }
                }
            }
            self.set_black(self.root);
        }

        /// Replace one node with another, retaining the removed node's position.
        ///
        /// Port of `erl_rbtree.h:642-688` (`replace__`), OTP-29.1.1.
        fn replace(&mut self, old: usize, new: usize) {
            let parent = self.nodes[old].parent;
            let left = self.nodes[old].left;
            let right = self.nodes[old].right;
            if parent == NONE {
                self.root = new;
            } else if self.nodes[parent].left == old {
                self.nodes[parent].left = new;
            } else {
                self.nodes[parent].right = new;
            }
            if left != NONE {
                self.nodes[left].parent = new;
            }
            if right != NONE {
                self.nodes[right].parent = new;
            }
            self.nodes[new].is_red = self.nodes[old].is_red;
            self.nodes[new].parent = parent;
            self.nodes[new].left = left;
            self.nodes[new].right = right;
        }

        /// Remove a node and restore the red-black properties.
        ///
        /// Port of `erl_rbtree.h:705-935` (`delete`), OTP-29.1.1.
        fn delete_node(&mut self, z: usize) {
            let mut y = z;
            if self.nodes[z].left != NONE && self.nodes[z].right != NONE {
                y = self.nodes[z].right;
                while self.nodes[y].left != NONE {
                    y = self.nodes[y].left;
                }
            }

            let left = self.nodes[y].left;
            let x = if left != NONE {
                left
            } else {
                self.nodes[y].right
            };
            let spliced_is_black = !self.is_red(y);
            let mut parent = self.nodes[y].parent;
            if x != NONE {
                self.nodes[x].parent = parent;
            }
            if parent == NONE {
                self.root = x;
            } else if self.nodes[parent].left == y {
                self.nodes[parent].left = x;
            } else {
                self.nodes[parent].right = x;
            }

            if y != z {
                self.replace(z, y);
                if x == NONE && parent == z {
                    parent = y;
                }
            }

            if spliced_is_black {
                let mut x = x;
                while !self.is_red(x) && x != self.root && parent != NONE {
                    if x == self.nodes[parent].left {
                        let mut sibling = self.nodes[parent].right;
                        if self.is_red(sibling) {
                            self.set_black(sibling);
                            self.set_red(parent);
                            self.left_rotate(parent);
                            if x != NONE {
                                parent = self.parent(x);
                            }
                            sibling = self.nodes[parent].right;
                        }
                        let left = self.left(sibling);
                        let right = self.right(sibling);
                        if !self.is_red(left) && !self.is_red(right) {
                            self.set_red(sibling);
                            x = parent;
                            parent = self.parent(x);
                        } else {
                            if !self.is_red(right) {
                                self.set_black(left);
                                self.set_red(sibling);
                                self.right_rotate(sibling);
                                if x != NONE {
                                    parent = self.parent(x);
                                }
                                sibling = self.nodes[parent].right;
                            }
                            if self.is_red(parent) {
                                self.set_black(parent);
                                self.set_red(sibling);
                            }
                            self.set_black(self.right(sibling));
                            self.left_rotate(parent);
                            x = self.root;
                            parent = NONE;
                        }
                    } else {
                        let mut sibling = self.nodes[parent].left;
                        if self.is_red(sibling) {
                            self.set_black(sibling);
                            self.set_red(parent);
                            self.right_rotate(parent);
                            if x != NONE {
                                parent = self.parent(x);
                            }
                            sibling = self.nodes[parent].left;
                        }
                        let left = self.left(sibling);
                        let right = self.right(sibling);
                        if !self.is_red(right) && !self.is_red(left) {
                            self.set_red(sibling);
                            x = parent;
                            parent = self.parent(x);
                        } else {
                            if !self.is_red(left) {
                                self.set_black(right);
                                self.set_red(sibling);
                                self.left_rotate(sibling);
                                if x != NONE {
                                    parent = self.parent(x);
                                }
                                sibling = self.nodes[parent].left;
                            }
                            if self.is_red(parent) {
                                self.set_black(parent);
                                self.set_red(sibling);
                            }
                            self.set_black(self.left(sibling));
                            self.right_rotate(parent);
                            x = self.root;
                            parent = NONE;
                        }
                    }
                }
                self.set_black(x);
            }
        }
    }

    /// Compare tagged terms using `erts_cmp`'s immediate fast paths before falling
    /// back to the full exact term order.
    ///
    /// Port of `erts/emulator/beam/utils.c:1723-1737` (`erts_cmp` immediate cases),
    /// reached through `erl_utils.h:122` (`CMP_TERM`), OTP-29.1.1.
    #[inline]
    fn subtract_term_cmp(a: Term, b: Term) -> Ordering {
        if a == b {
            return Ordering::Equal;
        }
        if let (Some(a), Some(b)) = (a.as_small(), b.as_small()) {
            return a.cmp(&b);
        }
        if let (Some(a), Some(b)) = (a.as_atom(), b.as_atom()) {
            let atoms = global_atoms();
            return atoms.text(a).cmp(&atoms.text(b));
        }
        cmp_exact(a, b)
    }

    #[cfg(test)]
    mod tests {
        use super::{NONE, Node, RbTree};
        use arinsal_term::{Term, cmp_exact};
        use similar_asserts::assert_eq;
        use std::cmp::Ordering;

        #[test]
        fn node_layout_matches_erts_subtract_tree() {
            assert_eq!(std::mem::size_of::<Node>(), 48);
            assert_eq!(std::mem::offset_of!(Node, parent), 0);
            assert_eq!(std::mem::offset_of!(Node, left), 8);
            assert_eq!(std::mem::offset_of!(Node, right), 16);
            assert_eq!(std::mem::offset_of!(Node, is_red), 24);
            assert_eq!(std::mem::offset_of!(Node, key), 32);
            assert_eq!(std::mem::offset_of!(Node, count), 40);
        }

        fn assert_valid(tree: &RbTree) {
            fn walk(tree: &RbTree, node: usize, parent: usize) -> (usize, usize) {
                if node == NONE {
                    return (1, 0);
                }
                let current = tree.nodes[node];
                assert_eq!(current.parent, parent);
                if current.is_red != 0 {
                    assert!(!tree.is_red(current.left));
                    assert!(!tree.is_red(current.right));
                }
                if current.left != NONE {
                    assert_eq!(
                        cmp_exact(tree.nodes[current.left].key, current.key),
                        Ordering::Less
                    );
                }
                if current.right != NONE {
                    assert_eq!(
                        cmp_exact(tree.nodes[current.right].key, current.key),
                        Ordering::Greater
                    );
                }
                let (left_black, left_nodes) = walk(tree, current.left, node);
                let (right_black, right_nodes) = walk(tree, current.right, node);
                assert_eq!(left_black, right_black);
                (
                    left_black + usize::from(current.is_red == 0),
                    left_nodes + right_nodes + 1,
                )
            }

            if tree.root != NONE {
                assert!(!tree.is_red(tree.root));
            }
            let (_, visited) = walk(tree, tree.root, NONE);
            assert!(visited <= tree.nodes.len());
        }

        #[test]
        fn insertion_and_deletion_preserve_tree_and_multiset_counts() {
            let repeated = Term::small(17).unwrap();
            let mut multiset = RbTree::with_capacity(3);
            let first = multiset.insert(repeated);
            assert_eq!(multiset.insert(repeated), first);
            assert_eq!(multiset.insert(repeated), first);
            assert_eq!(multiset.nodes.len(), 1);
            assert_eq!(multiset.count(first), 3);
            multiset.consume(first);
            assert_eq!(multiset.count(first), 2);
            multiset.consume(first);
            assert_eq!(multiset.count(first), 1);
            multiset.consume(first);
            assert_eq!(multiset.root, NONE);

            let mut tree = RbTree::with_capacity(256);
            let mut values = Vec::new();
            for step in 0..256 {
                let key = Term::small(((step * 73) % 257) as i64).unwrap();
                values.push(key);
                tree.insert(key);
                assert_valid(&tree);
            }
            for key in values {
                let node = tree.lookup(key).unwrap();
                assert!(tree.count(node) > 0);
                tree.consume(node);
                assert_valid(&tree);
            }
            assert_eq!(tree.root, NONE);
        }
    }
}

type SubtractTree = subtract_tree::RbTree;

arinsal_term::magic_payload!(
    TrapContext<AppendContext> => append_ctx_bin_dtor,
    TrapContext<SubtractContext> => subtract_ctx_bin_dtor,
);
