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
mod maps_bifs;
mod pure;
mod sys;
mod time;
mod unicode;

pub use etf::{DecodeWalk, EncodeWalk};
pub use pure::{
    BinarySearchKind, BinarySearchWalk, IolistSizeWalk, IolistWalk, binary_bytes,
    bitstring_bit_len, copy_binary_range, copy_bitstring_range, next_ref_id, singleton_bitstring,
};
pub use time::monotonic_time_milliseconds;

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
}

impl<'a> Ctx<'a> {
    pub fn new(heap: &'a mut dyn HeapAlloc) -> Self {
        Ctx {
            heap,
            reductions: 0,
        }
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
        .or_else(|| pure::lookup(module, name, arity))
        .or_else(|| unicode::lookup(module, name, arity))
}

/// A [`HeapAlloc`] over a [`ProcessHeap`] that never fails: when the heap is
/// full it allocates a heap fragment, which the next GC merges.
pub struct FragmentingHeap<'a>(pub &'a mut ProcessHeap);

impl HeapAlloc for FragmentingHeap<'_> {
    #[inline]
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        match HeapAlloc::alloc(self.0, words) {
            Some(ptr) => Some(ptr),
            None => Some(self.0.heap_fragment(words)),
        }
    }
    fn retain_binary(&mut self, binary: Arc<Vec<u8>>) {
        self.0.retain_binary(binary)
    }
    fn retain_writable_binary(
        &mut self,
        binary: Arc<arinsal_term::WritableBinary>,
    ) -> Result<(), arinsal_term::TermError> {
        self.0.retain_writable_binary(binary)
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
