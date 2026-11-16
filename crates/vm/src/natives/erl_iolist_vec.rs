//! The `iolist_to_iovec/1` walk of erl_iolist.c.
//!
//! Port of erts/emulator/beam/erl_iolist.c (ErtsIOList2VecState, generic_iolist_size and
//! generic_iolist_copy with the iovec threshold, iolist_to_iovec_engine), OTP-29.1.1. The size
//! pass counts the bytes that are copied; the copy pass writes them straight into one off-heap
//! binary and builds the result list incrementally, enqueueing sub-binaries of that binary and
//! the large binaries as they are. Both passes keep their cursor in the state, so a trap resumes
//! them; `natives::erl_iolist` owns the dispatch and the trap export.

use crate::natives::erl_bif_binary::copy_binary_to_buffer;
use crate::natives::erl_iolist::charge;
use arinsal_bifs::{BifError, ProcessHeapHandle};
use arinsal_term::raw::{BinRef, Cons, UninitBitstring};
use arinsal_term::{ConsHeapChain, EStack, HeapAlloc, Term, TermBuilder, TermKind};

const BADARG: BifError = BifError::BADARG;

fn iolist_cons(term: Term) -> Result<(Term, Term), BifError> {
    Cons::try_from(term).ok().map(Cons::pair).ok_or(BADARG)
}

/// `IOL2V_COPY_THRESHOLD`: bits at or below which a binary is copied into the shared binary.
const IOL2V_COPY_THRESHOLD_BITS: usize = 64 * 8 * 8;
/// `ERTS_IOLIST_SIZE_YIELDS_COUNT_PER_RED`.
const YIELDS_PER_RED: i64 = 8;
/// `ERTS_IOLIST_COPY_BITS_PER_YIELD_COUNT`.
const COPY_BITS_PER_YIELD: usize = 32 * 8;

/// `IOL_SHOULD_COPY(VecThreshold, 8, offset, size)`.
fn should_copy(start_bit: usize, bit_len: usize) -> bool {
    bit_len <= IOL2V_COPY_THRESHOLD_BITS || !start_bit.is_multiple_of(8)
}

fn bitstring_geometry(term: Term) -> Option<(usize, usize)> {
    BinRef::try_from(term)
        .ok()
        .map(|view| (view.start_bit(), view.bit_len()))
}

/// `is_byte`.
fn as_byte(term: Term) -> Option<u8> {
    term.as_small().and_then(|n| u8::try_from(n).ok())
}

/// The `[]`, `Bin` and `[Bin]` cases of `iolist_to_iovec/1` that need no traversal.
pub(crate) fn iolist_to_iovec_shortcut<H: HeapAlloc + ?Sized>(
    heap: &mut H,
    root: Term,
) -> Result<Option<Term>, BifError> {
    let single = match root.classify() {
        TermKind::Nil => return Ok(Some(Term::NIL)),
        TermKind::Bitstring => root,
        TermKind::List => {
            let (head, tail) = iolist_cons(root)?;
            if head.classify() == TermKind::Bitstring && tail.classify() == TermKind::Nil {
                head
            } else {
                return Ok(None);
            }
        }
        _ => return Err(BADARG),
    };
    let (_, bit_len) = bitstring_geometry(single).ok_or(BADARG)?;
    if !bit_len.is_multiple_of(8) {
        return Err(BADARG);
    }
    if bit_len == 0 {
        return Ok(Some(Term::NIL));
    }
    if root.classify() == TermKind::List {
        return Ok(Some(root));
    }
    TermBuilder::new(heap)
        .list_from_iter([single])
        .map(Some)
        .map_err(|_| BifError::SystemLimit)
}

/// `enum iolist_action`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IolistAction {
    Ok,
    Overflow,
    Type,
    Yield,
}

/// Why a pass left its loop early.
enum Stop {
    Overflow,
    Type,
    Yield,
}

/// A binary leaf copied in several yields: `from_base`, `from_offset` and `from_size`.
struct PartialLeaf {
    leaf: Term,
    offset: usize,
    size: usize,
}

/// `ErtsIOList2VecState`: the `ErtsIOListCopyState` with its `ErtsIOListState`, the result and the
/// argument.
// Port of erts/emulator/beam/erl_iolist.c (ErtsIOList2VecState), OTP-29.1.1.
pub(crate) struct VecState {
    // ErtsIOListState
    estack: EStack<8>,
    obj: Term,
    size: usize,
    have_size: bool,
    reds_left: i64,
    // ErtsIOListCopyState
    bin_ref: Term,
    to_base: Option<UninitBitstring>,
    vec_start: usize,
    vec_tail: ConsHeapChain,
    from: Option<PartialLeaf>,
    to_offset: usize,
    // ErtsIOList2VecState
    result: Term,
    arg: Term,
}

impl VecState {
    /// `ERTS_IOL2IOV_STATE_INITER`.
    pub(crate) fn new(arg: Term) -> Self {
        Self {
            estack: EStack::new(),
            obj: arg,
            size: 0,
            have_size: false,
            reds_left: 0,
            bin_ref: Term::NIL,
            to_base: None,
            vec_start: 0,
            vec_tail: ConsHeapChain::new(),
            from: None,
            to_offset: 0,
            result: Term::NIL,
            arg,
        }
    }

    /// `state.copy.iolist.reds_left = ERTS_BIF_REDS_LEFT(c_p)`.
    pub(crate) fn set_reds_left(&mut self, process: &crate::Process) {
        self.reds_left = i64::from(process.heap.abi.fcalls);
    }

    pub(crate) fn arg(&self) -> Term {
        self.arg
    }

    pub(crate) fn result(&self) -> Term {
        self.result
    }

    /// `BUMP_REDS` for `used` yield counts and the reductions left.
    fn finish_reds(&mut self, process: &mut crate::Process, init: i64, yield_count: i64) {
        let used = init - yield_count;
        let reds = (used - 1) / YIELDS_PER_RED + 1;
        charge(process, reds as usize);
        self.reds_left -= reds;
    }

    /// `BUMP_ALL_REDS(c_p)` then `reds_left = 0`.
    fn yield_pass(&mut self, process: &mut crate::Process, obj: Term) -> IolistAction {
        process.heap.abi.fcalls = 0;
        self.reds_left = 0;
        self.obj = obj;
        IolistAction::Yield
    }

    /// `generic_iolist_size(state, IOL2V_COPY_THRESHOLD, 8, 1)`.
    // Port of erts/emulator/beam/erl_iolist.c (generic_iolist_size), OTP-29.1.1.
    fn size_pass(&mut self, process: &mut crate::Process) -> IolistAction {
        if self.reds_left <= 0 {
            return IolistAction::Yield;
        }
        let init = YIELDS_PER_RED * self.reds_left;
        let mut yield_count = init;
        let mut obj = self.obj;
        let mut size = self.size;
        let stack = &mut self.estack;
        let run = (|| -> Result<(), Stop> {
            let mut resume = true;
            loop {
                if !resume {
                    match stack.pop() {
                        Some(next) => obj = next,
                        None => break,
                    }
                }
                resume = false;
                while let Ok(cons) = Cons::try_from(obj) {
                    yield_count -= 1;
                    if yield_count <= 0 {
                        return Err(Stop::Yield);
                    }
                    let (head, tail) = cons.pair();
                    if as_byte(head).is_some() {
                        size = size.checked_add(8).ok_or(Stop::Overflow)?;
                    } else if let Some((start, bits)) = bitstring_geometry(head) {
                        if bits % 8 != 0 {
                            return Err(Stop::Type);
                        }
                        if should_copy(start, bits) {
                            size = size.checked_add(bits).ok_or(Stop::Overflow)?;
                        }
                    } else if Cons::try_from(head).is_ok() {
                        stack.push(tail);
                        obj = head;
                        continue;
                    } else if head != Term::NIL {
                        return Err(Stop::Type);
                    }
                    obj = tail;
                }
                yield_count -= 1;
                if yield_count <= 0 {
                    return Err(Stop::Yield);
                } else if let Some((start, bits)) = bitstring_geometry(obj) {
                    if bits % 8 != 0 {
                        return Err(Stop::Type);
                    }
                    if should_copy(start, bits) {
                        size = size.checked_add(bits).ok_or(Stop::Overflow)?;
                    }
                } else if obj != Term::NIL {
                    return Err(Stop::Type);
                }
            }
            Ok(())
        })();
        match run {
            Ok(()) => {
                self.have_size = true;
                self.size = size;
                self.estack = EStack::new();
                self.finish_reds(process, init, yield_count);
                IolistAction::Ok
            }
            Err(Stop::Type) => {
                self.estack = EStack::new();
                self.finish_reds(process, init, yield_count);
                IolistAction::Type
            }
            Err(Stop::Overflow) => {
                self.size = size;
                self.obj = obj;
                self.finish_reds(process, init, yield_count);
                IolistAction::Overflow
            }
            Err(Stop::Yield) => {
                self.size = size;
                self.yield_pass(process, obj)
            }
        }
    }

    /// `generic_iolist_copy_vec_enqueue`.
    fn vec_enqueue(&mut self, process: &mut crate::Process, obj: Term) {
        if self.vec_start < self.to_offset {
            let sub = TermBuilder::new(&mut ProcessHeapHandle(&mut process.heap))
                .sub_binary(
                    self.bin_ref,
                    self.vec_start,
                    self.to_offset - self.vec_start,
                )
                .expect("HAlloc");
            self.vec_start = self.to_offset;
            self.vec_enqueue(process, sub);
        }
        if obj != Term::NIL {
            self.vec_tail
                .push(&mut ProcessHeapHandle(&mut process.heap), obj, 0)
                .expect("HAlloc");
        }
    }

    /// `generic_iolist_copy_bitstring`: whether the leaf was copied only in part.
    // Port of erts/emulator/beam/erl_iolist.c (generic_iolist_copy_bitstring), OTP-29.1.1.
    fn copy_bitstring(&mut self, leaf: Term, yield_count: &mut i64) -> bool {
        let (leaf, offset, size) = match self.from.take() {
            Some(from) => (from.leaf, from.offset, from.size),
            None => {
                let bits = bitstring_geometry(leaf).map_or(0, |(_, bits)| bits);
                (leaf, 0, bits)
            }
        };
        let copy_limit = (*yield_count as usize + 1) * COPY_BITS_PER_YIELD;
        let copy_size = size.min(copy_limit);
        // An empty binary copies nothing, and there may be no target binary then.
        if copy_size > 0 {
            let view = BinRef::try_from(leaf).expect("a bitstring leaf");
            let to_offset = self.to_offset;
            // Unit 8: the destination offset and the sizes are whole bytes.
            let target = self
                .to_base
                .as_mut()
                .and_then(UninitBitstring::bytes_mut)
                .expect("a sized copy pass");
            copy_binary_to_buffer(
                &mut target[to_offset / 8..],
                view.window(),
                view.start_bit() + offset,
                copy_size / 8,
            );
        }
        self.to_offset += copy_size;
        if copy_size < size {
            self.from = Some(PartialLeaf {
                leaf,
                offset: offset + copy_size,
                size: size - copy_size,
            });
            *yield_count = 0;
            return true;
        }
        *yield_count -= (copy_size / COPY_BITS_PER_YIELD) as i64;
        false
    }

    /// `generic_iolist_copy(copy_state, IOL2V_COPY_THRESHOLD, 8, 0, 1)`.
    // Port of erts/emulator/beam/erl_iolist.c (generic_iolist_copy), OTP-29.1.1.
    fn copy_pass(&mut self, process: &mut crate::Process) -> IolistAction {
        if self.reds_left <= 0 {
            return IolistAction::Yield;
        }
        let init = YIELDS_PER_RED * self.reds_left;
        let mut yield_count = init;
        let mut obj = self.obj;
        let mut resume = true;
        let stopped = 'pass: loop {
            if !resume {
                match self.estack.pop() {
                    Some(next) => obj = next,
                    None => break None,
                }
            }
            resume = false;
            while let Ok(cons) = Cons::try_from(obj) {
                yield_count -= 1;
                if yield_count <= 0 {
                    break 'pass Some(obj);
                }
                let (head, tail) = cons.pair();
                obj = head;
                if let Some(byte) = as_byte(obj) {
                    let at = self.to_offset / 8;
                    self.to_base
                        .as_mut()
                        .and_then(UninitBitstring::bytes_mut)
                        .expect("a sized copy pass")[at] = byte;
                    self.to_offset += 8;
                } else if let Some((start, bits)) = bitstring_geometry(obj) {
                    if should_copy(start, bits) {
                        if self.copy_bitstring(obj, &mut yield_count) {
                            self.estack.push(tail);
                            break 'pass Some(obj);
                        }
                    } else {
                        self.vec_enqueue(process, obj);
                    }
                } else if Cons::try_from(obj).is_ok() {
                    self.estack.push(tail);
                    continue;
                }
                obj = tail;
            }
            yield_count -= 1;
            if yield_count <= 0 {
                break 'pass Some(obj);
            } else if let Some((start, bits)) = bitstring_geometry(obj) {
                if should_copy(start, bits) {
                    if self.copy_bitstring(obj, &mut yield_count) {
                        break 'pass Some(obj);
                    }
                } else {
                    self.vec_enqueue(process, obj);
                }
            }
        };
        match stopped {
            None => {
                self.vec_enqueue(process, Term::NIL);
                self.result =
                    std::mem::replace(&mut self.vec_tail, ConsHeapChain::new()).finish(Term::NIL);
                self.estack = EStack::new();
                self.finish_reds(process, init, yield_count);
                IolistAction::Ok
            }
            Some(obj) => self.yield_pass(process, obj),
        }
    }

    /// `iolist_to_iovec_engine`.
    // Port of erts/emulator/beam/erl_iolist.c (iolist_to_iovec_engine), OTP-29.1.1.
    pub(crate) fn engine(&mut self, process: &mut crate::Process) -> IolistAction {
        if !self.have_size {
            match self.size_pass(process) {
                IolistAction::Ok => {}
                other => return other,
            }
            self.result = Term::NIL;
            self.vec_tail = ConsHeapChain::new();
            // We cannot fail from here on. Allocate a common off-heap binary for all copied
            // components if need be.
            if self.size > 0 {
                let output = UninitBitstring::allocate(
                    &mut ProcessHeapHandle(&mut process.heap),
                    self.size / 8,
                )
                .expect("HAlloc");
                self.bin_ref = output.term();
                self.to_base = Some(output);
            }
            self.obj = self.arg;
            if self.reds_left <= 0 {
                process.heap.abi.fcalls = 0;
                return IolistAction::Yield;
            }
        }
        self.copy_pass(process)
    }
}
