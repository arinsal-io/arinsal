//! Mutable sub-bitstring state and growable off-heap binary owners.
use crate::{BIN_REF, HeapAlloc, SUB_BITS, Term, TermBuilder, TermError};
use std::cell::UnsafeCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

/// The context cursor or active writer may modify this `SUB_BITS` object.
pub const SUB_BITS_MUTABLE: u64 = 1;
/// The binary data may have moved, so readers must resolve the BinRef.
pub const SUB_BITS_VOLATILE: u64 = 2;
const EXTERNAL_OWNER: u64 = 0x100;
static BINARY_MEMORY_BYTES: AtomicU64 = AtomicU64::new(0);

/// Return the live payload bytes held by refcounted binaries.
pub fn binary_memory_bytes() -> u64 {
    BINARY_MEMORY_BYTES.load(Ordering::Relaxed)
}

/// A refcounted binary payload whose size contributes to `erlang:memory(binary)`.
pub struct RefcBinary {
    bytes: Vec<u8>,
}

impl RefcBinary {
    // Port of erts/emulator/beam/erl_binary.h:287 (erts_bin_nrml_alloc_fnf), OTP-29.1.1.
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        BINARY_MEMORY_BYTES.fetch_add(bytes.len() as u64, Ordering::Relaxed);
        Self { bytes }
    }
}

impl std::ops::Deref for RefcBinary {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl Drop for RefcBinary {
    fn drop(&mut self) {
        // Port of erts/emulator/beam/erl_binary.h:374 (erts_bin_free), OTP-29.1.1.
        BINARY_MEMORY_BYTES.fetch_sub(self.bytes.len() as u64, Ordering::Relaxed);
    }
}

/// Bytes borrowed from a native resource whose owner remains live with the term.
pub struct ExternalBinary {
    data: *const u8,
    len: usize,
    _owner: Arc<crate::MagicRef>,
}
// SAFETY: native resource users synchronize any mutation of published bytes.
unsafe impl Send for ExternalBinary {}
// SAFETY: the retained magic owner keeps the borrowed allocation live.
unsafe impl Sync for ExternalBinary {}
impl ExternalBinary {
    /// Keep an external byte range alive through a magic reference.
    ///
    /// # Safety
    /// `data` must remain readable for `len` bytes until `owner` is dropped.
    pub unsafe fn new(data: *const u8, len: usize, owner: Arc<crate::MagicRef>) -> Arc<Self> {
        Arc::new(Self {
            data: if len == 0 && data.is_null() {
                std::ptr::NonNull::dangling().as_ptr()
            } else {
                data
            },
            len,
            _owner: owner,
        })
    }
    /// Length of the resource-backed byte range.
    pub fn len(&self) -> usize {
        self.len
    }
    /// Whether the resource-backed range is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Off-heap bytes with reserved capacity and one active process writer.
/// Mutating and borrowing the bytes is unsafe because BEAM terms are copied by value.
pub struct WritableBinary {
    bytes: UnsafeCell<Vec<u8>>,
    byte_len: AtomicUsize,
    writer: AtomicBool,
    active: AtomicBool,
}

// SAFETY: a writable owner has one process writer. Process handoff and
// cross-process copying finalize it before another thread can observe bytes.
unsafe impl Send for WritableBinary {}
// SAFETY: shared owners are immutable after finalization; active writers stay
// under the owning process's exclusive execution lock.
unsafe impl Sync for WritableBinary {}

impl WritableBinary {
    // Port of erts/emulator/beam/erl_binary.h:287 (erts_bin_nrml_alloc_fnf), OTP-29.1.1.
    fn new(bytes: &[u8], capacity: usize) -> Self {
        let mut data = Vec::with_capacity(capacity.max(bytes.len()));
        data.extend_from_slice(bytes);
        let binary = Self {
            bytes: UnsafeCell::new(data),
            byte_len: AtomicUsize::new(bytes.len()),
            writer: AtomicBool::new(true),
            active: AtomicBool::new(true),
        };
        BINARY_MEMORY_BYTES.fetch_add(binary.capacity() as u64, Ordering::Relaxed);
        binary
    }
    /// Current logical length in bytes.
    pub fn len(&self) -> usize {
        self.byte_len.load(Ordering::Relaxed)
    }
    /// Whether the current logical byte length is zero.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Capacity reserved for future appends, in bytes.
    pub fn capacity(&self) -> usize {
        // SAFETY: capacity is read by the owning process while no append is active.
        unsafe { (*self.bytes.get()).capacity() }
    }
    /// Whether the unique writer may still grow this buffer.
    pub fn has_writer(&self) -> bool {
        self.writer.load(Ordering::Relaxed)
    }
}

impl Drop for WritableBinary {
    fn drop(&mut self) {
        // Port of erts/emulator/beam/erl_binary.h:374 (erts_bin_free), OTP-29.1.1.
        BINARY_MEMORY_BYTES.fetch_sub(self.bytes.get_mut().capacity() as u64, Ordering::Relaxed);
    }
}

/// Read the two low flag bits from a live `SUB_BITS` term.
pub fn sub_bits_flags(term: Term) -> u64 {
    if term.header().is_some_and(|h| h & 63 == SUB_BITS) {
        // SAFETY: SUB_BITS has a base_flags word.
        unsafe { *term.raw_ptr().add(1) & 3 }
    } else {
        0
    }
}

/// Whether the term is a mutable match context.
pub fn is_match_context(term: Term) -> bool {
    term.header().is_some_and(|h| h & 63 == SUB_BITS) && sub_bits_flags(term) == SUB_BITS_MUTABLE
}

/// Whether the term is the active writable binary handle.
pub fn is_writable_binary(term: Term) -> bool {
    term.header().is_some_and(|h| h & 63 == SUB_BITS)
        && sub_bits_flags(term) == SUB_BITS_MUTABLE | SUB_BITS_VOLATILE
        && owner(term).is_some_and(|(_, b)| b.has_writer())
}

/// Current capacity of a writable owner's backing allocation, in bytes.
pub fn writable_capacity(term: Term) -> Option<usize> {
    owner(term).map(|(_, binary)| binary.capacity())
}

fn owner(term: Term) -> Option<(*const u64, &'static WritableBinary)> {
    if term.header()? & 63 != SUB_BITS {
        return None;
    }
    // SAFETY: SUB_BITS word four is its original BinRef, retained by a live heap.
    let original = Term(unsafe { *term.raw_ptr().add(4) });
    if original.header()? & 63 != BIN_REF {
        return None;
    }
    // SAFETY: writable BinRef has a retained Arc<WritableBinary> pointer.
    unsafe {
        let p = original.raw_ptr();
        if *p.add(2) & 1 != 1 {
            return None;
        }
        Some((p, &*(*p.add(1) as *const WritableBinary)))
    }
}

/// Visit a live writable BinRef or its `SUB_BITS` once per GC cycle. Active writers retain
/// capacity; inactive writers shed spare bytes before the next cycle.
///
/// # Safety
/// The collector must stop the owning process and hold no binary view while
/// this function can reallocate the buffer.
pub unsafe fn writable_gc_visit(term: Term) {
    let bin_ref = if term.header().is_some_and(|h| h & 63 == SUB_BITS) {
        // SAFETY: a live SUB_BITS keeps its original term in word four.
        Term(unsafe { *term.raw_ptr().add(4) })
    } else {
        term
    };
    if bin_ref.header().is_none_or(|h| h & 63 != BIN_REF) {
        return;
    }
    // SAFETY: the caller supplies a live BinRef retained by this process.
    unsafe {
        let p = bin_ref.raw_ptr();
        if *p.add(2) & 1 != 1 {
            return;
        }
        let binary = &*(*p.add(1) as *const WritableBinary);
        if binary.writer.load(Ordering::Relaxed) && !binary.active.swap(false, Ordering::Relaxed) {
            let bytes = &mut *binary.bytes.get();
            if bytes.capacity().saturating_sub(bytes.len()) >= 8 {
                let old_capacity = bytes.capacity();
                bytes.shrink_to_fit();
                BINARY_MEMORY_BYTES.fetch_sub(
                    old_capacity.saturating_sub(bytes.capacity()) as u64,
                    Ordering::Relaxed,
                );
            }
        }
    }
}

/// The initial byte displacement recorded by a BinRef. It remains stable
/// even if a writable Vec later reallocates at a differently aligned address.
pub(crate) fn owner_adjustment(term: Term) -> usize {
    let original = if term.header().is_some_and(|h| h & 63 == SUB_BITS) {
        // SAFETY: SUB_BITS word four is its original term.
        Term(unsafe { *term.raw_ptr().add(4) })
    } else {
        term
    };
    if original.header().is_some_and(|h| h & 63 == BIN_REF) {
        // SAFETY: BinRef word two holds kind and initial displacement.
        unsafe { ((*original.raw_ptr().add(2) >> 1) & 3) as usize }
    } else {
        0
    }
}

pub(crate) fn binary_owner_is_writable(term: Term) -> bool {
    if term.header().is_none_or(|h| h & 63 != BIN_REF) {
        return false;
    }
    // SAFETY: a live BinRef stores its owner kind in word two.
    unsafe { *term.raw_ptr().add(2) & 1 == 1 }
}

/// Byte offset folded into `SUB_BITS` positions to reserve low pointer bits.
pub fn binary_offset_adjustment(term: Term) -> usize {
    owner_adjustment(term)
}

/// Return the current absolute bit offset of a match context.
pub fn match_position(term: Term) -> Option<usize> {
    if !is_match_context(term) {
        return None;
    }
    // SAFETY: context word two is its mutable start offset.
    Some(unsafe { *term.raw_ptr().add(2) as usize })
}

/// Set a context's absolute bit offset, preserving it on an invalid offset.
pub fn set_match_position(term: Term, position: usize) -> bool {
    if !is_match_context(term) {
        return false;
    }
    // SAFETY: this process owns the mutable context and its end is word three.
    unsafe {
        let p = term.raw_ptr().cast_mut();
        if position > *p.add(3) as usize {
            return false;
        }
        *p.add(2) = position as u64;
    }
    true
}

/// End the unique writer's lifetime before sharing, matching, or sending a binary.
pub fn writable_finalize(term: Term) {
    if let Some((_, binary)) = owner(term)
        && sub_bits_flags(term) & SUB_BITS_VOLATILE != 0
    {
        binary.writer.store(false, Ordering::Relaxed);
        binary.active.store(false, Ordering::Relaxed);
        // Port of erts/emulator/beam/erl_bits.c:2053 (erts_pin_writable_binary), OTP-29.1.1.
        // SAFETY: the process owns the writer and no binary view is retained.
        unsafe {
            let bytes = &mut *binary.bytes.get();
            if bytes.capacity().saturating_sub(bytes.len()) >= 8 {
                bytes.shrink_to_fit();
            }
            *term.raw_ptr().add(1).cast_mut() = bytes.as_ptr() as u64 & !3;
        }
    }
}

/// Raw bytes and length for a live BinRef, resolving a growable owner's current address.
///
/// # Safety
/// The BinRef and its retained owner must be live; no writer may run while the
/// returned pointer is used.
pub(crate) unsafe fn binary_data(bin_ref: *const u64) -> *const u8 {
    // SAFETY: caller guarantees a live BinRef and retained owner.
    unsafe {
        if *bin_ref.add(2) & EXTERNAL_OWNER != 0 {
            (&*(*bin_ref.add(1) as *const ExternalBinary)).data
        } else if *bin_ref.add(2) & 1 == 1 {
            let binary = &*(*bin_ref.add(1) as *const WritableBinary);
            (*binary.bytes.get()).as_ptr()
        } else {
            (&*(*bin_ref.add(1) as *const Vec<u8>)).as_ptr()
        }
    }
}

/// Clone the Arc owner behind a BinRef and return its raw Arc pointer.
///
/// # Safety
/// The source BinRef and owner must remain live.
pub(crate) unsafe fn clone_binary_owner(bin_ref: Term) -> (u64, u64) {
    // SAFETY: source is a live BinRef and word two selects the Arc type.
    unsafe {
        let p = bin_ref.raw_ptr();
        let ptr = *p.add(1);
        let flags = *p.add(2);
        if flags & EXTERNAL_OWNER != 0 {
            Arc::increment_strong_count(ptr as *const ExternalBinary);
        } else if flags & 1 == 1 {
            Arc::increment_strong_count(ptr as *const WritableBinary);
        } else {
            Arc::increment_strong_count(ptr as *const RefcBinary);
        }
        (ptr, flags)
    }
}

/// Transfer a cloned raw Arc into a heap's owner list.
///
/// # Safety
/// `ptr` must come from `clone_binary_owner` with the same kind.
pub(crate) unsafe fn retain_cloned_binary_owner<H: HeapAlloc + ?Sized>(
    heap: &mut H,
    ptr: u64,
    flags: u64,
) -> Result<(), TermError> {
    // SAFETY: the raw pointer owns precisely one incremented strong reference.
    unsafe {
        if flags & EXTERNAL_OWNER != 0 {
            heap.retain_external_binary(Arc::from_raw(ptr as *const ExternalBinary))
        } else if flags & 1 == 1 {
            heap.retain_writable_binary(Arc::from_raw(ptr as *const WritableBinary))
        } else {
            heap.retain_binary(Arc::from_raw(ptr as *const RefcBinary));
            Ok(())
        }
    }
}

/// Return a mutable slice of reserved data; the caller must hold the unique
/// writer and must not retain any binary views through the mutation.
///
/// # Safety
/// No aliased read or write of the owner's bytes may be live.
pub unsafe fn writable_bytes_mut<'a>(term: Term) -> Option<&'a mut [u8]> {
    if !is_writable_binary(term) {
        return None;
    }
    let (_, binary) = owner(term)?;
    // SAFETY: the caller guarantees exclusive access to the active writer.
    Some(unsafe { &mut *binary.bytes.get() }.as_mut_slice())
}

/// Extend an active private writer's bit length and reserve space geometrically.
pub fn writable_extend_private(term: Term, new_bits: usize) -> Result<bool, TermError> {
    if !is_writable_binary(term) {
        return Ok(false);
    }
    let adjustment = owner_adjustment(term);
    // SAFETY: word three is the current end, and this process is its only writer.
    let current = unsafe { *term.raw_ptr().add(3) as usize } - adjustment * 8;
    if new_bits < current || new_bits > isize::MAX as usize {
        return Err(TermError::SystemLimit);
    }
    let (_, binary) = owner(term).unwrap();
    // SAFETY: the active writer has exclusive mutation rights and no view lives here.
    unsafe {
        let bytes = &mut *binary.bytes.get();
        // Port of erts/emulator/beam/erl_binary.h:321 (erts_bin_realloc_fnf), OTP-29.1.1.
        let old_capacity = bytes.capacity();
        bytes.resize(new_bits.div_ceil(8), 0);
        let new_capacity = bytes.capacity();
        if new_capacity >= old_capacity {
            BINARY_MEMORY_BYTES.fetch_add((new_capacity - old_capacity) as u64, Ordering::Relaxed);
        } else {
            BINARY_MEMORY_BYTES.fetch_sub((old_capacity - new_capacity) as u64, Ordering::Relaxed);
        }
        binary.byte_len.store(bytes.len(), Ordering::Relaxed);
        binary.active.store(true, Ordering::Relaxed);
        *term.raw_ptr().add(3).cast_mut() = (new_bits + adjustment * 8) as u64;
    }
    Ok(true)
}

impl<H: HeapAlloc> TermBuilder<'_, H> {
    /// Box a byte range owned by an opaque native resource without copying it.
    pub fn external_binary(&mut self, owner: Arc<ExternalBinary>) -> Result<Term, TermError> {
        if !self.heap.supports_external_binary() {
            return Err(TermError::Unsupported("external binary heap owner"));
        }
        let adjustment = owner.data as usize & 3;
        let len = owner.len();
        let end = len
            .checked_add(adjustment)
            .and_then(|bytes| bytes.checked_mul(8))
            .ok_or(TermError::SystemLimit)?;
        let p = self.heap.alloc(8).ok_or(TermError::HeapFull)?;
        // SAFETY: eight allocated words hold a BinRef and a SubBits head.
        unsafe {
            let sub = p.add(3);
            *p = (2 << 6) | BIN_REF;
            *p.add(1) = Arc::as_ptr(&owner) as u64;
            *p.add(2) = EXTERNAL_OWNER | (adjustment as u64) << 1;
            *sub = (4 << 6) | SUB_BITS;
            *sub.add(1) = owner.data as u64 & !3;
            *sub.add(2) = (adjustment * 8) as u64;
            *sub.add(3) = end as u64;
            *sub.add(4) = Term::from_ptr(p, 2).0;
        }
        self.heap.retain_external_binary(owner)?;
        // SAFETY: the BinRef occupies the first three words of this allocation.
        Ok(Term::from_ptr(unsafe { p.add(3) }, 2))
    }
    /// Build the OTP 29 mutable `SUB_BITS` match context, or reuse an existing one.
    pub fn match_context(&mut self, source: Term) -> Result<Term, TermError> {
        if is_match_context(source) {
            return Ok(source);
        }
        if source.classify() != crate::TermKind::Bitstring {
            return Err(TermError::BadArg);
        }
        writable_finalize(source);
        // SAFETY: the source heap stays live through construction.
        let view = unsafe { source.binary_ref() }.ok_or(TermError::BadArg)?;
        let mut original = source;
        while original.header().is_some_and(|h| h & 63 == SUB_BITS) {
            // SAFETY: SUB_BITS word four retains its original.
            original = Term(unsafe { *original.raw_ptr().add(4) });
        }
        let p = self.words(5)?;
        let adjustment = owner_adjustment(original);
        // Port of erts/emulator/beam/erl_bits.c:79 (erts_bs_start_match_3), OTP-29.1.1.
        // SAFETY: five words are reserved; the original term stays rooted by word four.
        unsafe {
            *p = (4 << 6) | SUB_BITS;
            *p.add(1) = (view.bytes().as_ptr() as u64 & !3) | SUB_BITS_MUTABLE;
            *p.add(2) = (view.start_bit() + adjustment * 8) as u64;
            *p.add(3) = (view.start_bit() + view.bit_len() + adjustment * 8) as u64;
            *p.add(4) = original.0;
        }
        Ok(Term::from_ptr(p, 2))
    }

    /// Build a writable off-heap bitstring with an initial capacity in bytes.
    pub fn writable_binary(
        &mut self,
        bytes: &[u8],
        bit_len: usize,
        capacity: usize,
    ) -> Result<Term, TermError> {
        if bit_len > bytes.len().saturating_mul(8) || bit_len > isize::MAX as usize {
            return Err(TermError::BadArg);
        }
        if !self.heap.supports_writable_binary() {
            return Err(TermError::Unsupported("writable binary heap owner"));
        }
        let count = bit_len.div_ceil(8);
        let mut initial = bytes[..count].to_vec();
        if !bit_len.is_multiple_of(8) && count > 0 {
            initial[count - 1] &= 0xff << (8 - bit_len % 8);
        }
        let binary = Arc::new(WritableBinary::new(&initial, capacity));
        // SAFETY: the Arc is retained below and its buffer is live.
        let adjustment = unsafe { (*binary.bytes.get()).as_ptr() as usize & 3 };
        let p = self.words(8)?;
        // Port of erts/emulator/beam/erl_bits.c:1675 (build_writable_bitstring), OTP-29.1.1.
        // SAFETY: eight words hold a BinRef and SUB_BITS; heap retains the Arc.
        unsafe {
            let sub = p.add(3);
            *p = (2 << 6) | BIN_REF;
            *p.add(1) = Arc::as_ptr(&binary) as u64;
            *p.add(2) = 1 | ((adjustment as u64) << 1);
            *sub = (4 << 6) | SUB_BITS;
            *sub.add(1) = (binary_data(p) as u64 & !3) | SUB_BITS_MUTABLE | SUB_BITS_VOLATILE;
            *sub.add(2) = (adjustment * 8) as u64;
            *sub.add(3) = (bit_len + adjustment * 8) as u64;
            *sub.add(4) = Term::from_ptr(p, 2).0;
        }
        self.heap.retain_writable_binary(binary)?;
        // SAFETY: p was allocated for the SUB_BITS directly after the BinRef.
        Ok(Term::from_ptr(unsafe { p.add(3) }, 2))
    }

    /// Create the next writable handle after a public append. The prior handle
    /// becomes VOLATILE and retains its prior length.
    pub fn writable_successor(
        &mut self,
        source: Term,
        new_bits: usize,
    ) -> Result<Option<Term>, TermError> {
        if !is_writable_binary(source) {
            return Ok(None);
        }
        let adjustment = owner_adjustment(source);
        // SAFETY: the live writable SUB_BITS stores its end in word three.
        let end = unsafe { *source.raw_ptr().add(3) as usize } - adjustment * 8;
        if new_bits < end || new_bits > isize::MAX as usize {
            return Err(TermError::SystemLimit);
        }
        if new_bits == end {
            return Ok(Some(source));
        }
        let p = self.words(5)?;
        let (_, binary) = owner(source).unwrap();
        // SAFETY: this process owns the active writer and no bytes are borrowed.
        unsafe {
            (&mut *binary.bytes.get()).resize(new_bits.div_ceil(8), 0);
            binary
                .byte_len
                .store(new_bits.div_ceil(8), Ordering::Relaxed);
            binary.active.store(true, Ordering::Relaxed);
            let old = source.raw_ptr().cast_mut();
            *old.add(1) &= !SUB_BITS_MUTABLE;
            std::ptr::copy_nonoverlapping(old, p, 5);
            *p.add(1) |= SUB_BITS_MUTABLE;
            *p.add(3) = (new_bits + adjustment * 8) as u64;
        }
        Ok(Some(Term::from_ptr(p, 2)))
    }
}
