//! Mutable sub-bitstring state and growable off-heap binary owners.
use crate::{BIN_REF, HEAP_BITS, HeapAlloc, SUB_BITS, Term, TermBuilder, TermError};
use arinsal_alloc::raw::BinaryView;
use arinsal_alloc::typed::{BinaryBlock, binary_allocation_bytes};
use std::sync::Arc;
use std::sync::atomic::Ordering;

/// The context cursor or active writer may modify this `SUB_BITS` object.
pub const SUB_BITS_MUTABLE: u64 = 1;
/// The binary data may have moved, so readers must resolve the BinRef.
pub const SUB_BITS_VOLATILE: u64 = 2;
/// Flags marker `clone_binary_owner` returns for a resource-backed binary.
pub(crate) const EXTERNAL_OWNER: u64 = 0x100;
/// Tag bit of `BinRef.val` naming an `Arc<ExternalBinary>` instead of a `Binary` header.
const EXTERNAL_VAL_TAG: u64 = 1;
const BINARY_HEADER_WORDS: usize = 4;
pub(crate) const BINARY_FLAG_WRITABLE: u64 = 1 << 2;
pub(crate) const BINARY_FLAG_ACTIVE_WRITER: u64 = 1 << 3;

/// Whether a BinRef's `val` word names a resource-backed binary.
#[inline(always)]
pub(crate) fn bin_ref_val_is_external(val: u64) -> bool {
    val & EXTERNAL_VAL_TAG != 0
}

/// The `val` word of a BinRef over `binary`, tagged as resource-backed.
#[inline(always)]
pub(crate) fn external_val_word(binary: &Arc<ExternalBinary>) -> u64 {
    Arc::as_ptr(binary) as u64 | EXTERNAL_VAL_TAG
}

/// The `ExternalBinary` a resource-backed BinRef's `val` word names.
#[inline(always)]
pub(crate) fn external_val_ptr(val: u64) -> *const ExternalBinary {
    (val & !EXTERNAL_VAL_TAG) as *const ExternalBinary
}

/// Uncounted handle to the `Arc<ExternalBinary>` a resource-backed BinRef's tagged `val`
/// word names; dropping it does not release the reference.
///
/// `val` must come from a BinRef whose off-heap list entry still holds its counted reference.
fn external_val_handle(val: u64) -> std::mem::ManuallyDrop<Arc<ExternalBinary>> {
    // SAFETY: the list entry's counted `Arc::into_raw` reference keeps the binary alive, and
    // the `ManuallyDrop` keeps this handle from releasing it.
    std::mem::ManuallyDrop::new(unsafe { Arc::from_raw(external_val_ptr(val)) })
}

/// Length of the resource-backed binary a BinRef's tagged `val` word names.
pub(crate) fn external_val_len(val: u64) -> usize {
    external_val_handle(val).len()
}

/// Strong count of the `Arc<ExternalBinary>` a live BinRef's tagged `val` word names.
pub(crate) fn external_val_strong_count(val: u64) -> usize {
    Arc::strong_count(&external_val_handle(val))
}

/// Take over the counted reference of a resource-backed BinRef's tagged `val` word.
///
/// The caller must own that reference: an unforwarded list entry being released, or a
/// forwarded one whose copy takes the reference over.
pub(crate) fn external_val_take(val: u64) -> Arc<ExternalBinary> {
    std::mem::ManuallyDrop::into_inner(external_val_handle(val))
}

/// Return live allocated bytes for erts' `BINARY` allocation type.
pub fn binary_memory_bytes() -> u64 {
    binary_allocation_bytes()
}

// Port of erts/emulator/beam/erl_bits.c:72 (GROW_PROC_BIN_SIZE), OTP-29.1.1.
fn grow_proc_binary_size(size: usize) -> Result<usize, TermError> {
    if size <= 1 << 24 {
        size.checked_mul(2).ok_or(TermError::SystemLimit)
    } else {
        let grown = (1.2 * size as f64) as usize;
        if grown < size {
            return Err(TermError::SystemLimit);
        }
        Ok(grown)
    }
}

fn resize_writable_binary(allocation: &mut BinaryBlock, new_len: usize) -> Result<(), TermError> {
    // Port of erts/emulator/beam/erl_binary.h:321 (erts_bin_realloc_fnf), OTP-29.1.1.
    let old_len = allocation.apparent_size();
    let old_capacity = allocation.size();
    let new_capacity = if new_len > old_capacity {
        grow_proc_binary_size(new_len)?
    } else {
        old_capacity
    };
    if new_capacity != old_capacity {
        allocation
            .realloc(new_capacity)
            .map_err(|_| TermError::SystemLimit)?;
    }
    if new_len > old_len {
        allocation.bytes_mut_unique().ok_or(TermError::BadArg)?[old_len..new_len].fill(0);
    }
    allocation.set_flag_bits(BINARY_FLAG_ACTIVE_WRITER);
    allocation.set_apparent_size(new_len);
    Ok(())
}

fn shrink_writable_binary(allocation: &mut BinaryBlock) -> Result<(), TermError> {
    // Port of erts/emulator/beam/erl_bits.c:2053 (erts_pin_writable_binary), OTP-29.1.1.
    let new_capacity = allocation.apparent_size();
    if allocation.size().saturating_sub(new_capacity) >= 8 {
        allocation
            .realloc(new_capacity)
            .map_err(|_| TermError::SystemLimit)?;
        allocation.set_apparent_size(new_capacity);
    }
    Ok(())
}

/// A refcounted binary owner with the same allocation shape as an erts `Binary`.
pub struct RefcBinary {
    allocation: BinaryBlock,
}

impl RefcBinary {
    // Port of erts/emulator/beam/erl_binary.h:287 (erts_bin_nrml_alloc_fnf), OTP-29.1.1.
    pub(crate) fn new(bytes: Vec<u8>) -> Result<Self, TermError> {
        let mut allocation =
            BinaryBlock::new(bytes.len(), 0, bytes.len()).map_err(|_| TermError::SystemLimit)?;
        allocation
            .bytes_mut_unique()
            .ok_or(TermError::BadArg)?
            .copy_from_slice(&bytes);
        Ok(Self { allocation })
    }

    pub(crate) fn new_zeroed(size: usize) -> Result<Self, TermError> {
        let allocation = BinaryBlock::new(size, 0, size).map_err(|_| TermError::SystemLimit)?;
        Ok(Self { allocation })
    }

    pub(crate) fn bytes_mut_unique(&mut self) -> Option<&mut [u8]> {
        self.allocation.bytes_mut_unique()
    }

    pub(crate) fn as_ptr(&self) -> *const u8 {
        self.allocation.view().bytes_ptr()
    }

    /// Length of the binary payload in bytes.
    pub fn len(&self) -> usize {
        self.allocation.size()
    }

    pub(crate) fn into_reference(self) -> arinsal_alloc::raw::OwnedBinaryRef {
        self.allocation.into_reference()
    }

    /// Whether the binary payload is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
    allocation: BinaryBlock,
}

impl WritableBinary {
    // Port of erts/emulator/beam/erl_binary.h:287 (erts_bin_nrml_alloc_fnf), OTP-29.1.1.
    fn new(bytes: &[u8], capacity: usize, apparent_size: usize) -> Result<Self, TermError> {
        Self::from_parts(bytes, &[], capacity, apparent_size)
    }

    fn from_parts(
        prefix: &[u8],
        suffix: &[u8],
        capacity: usize,
        apparent_size: usize,
    ) -> Result<Self, TermError> {
        let len = prefix
            .len()
            .checked_add(suffix.len())
            .ok_or(TermError::SystemLimit)?;
        Self::from_prefix_suffix(prefix, suffix, len, capacity, apparent_size)
    }

    fn from_prefix(
        prefix: &[u8],
        len: usize,
        capacity: usize,
        apparent_size: usize,
    ) -> Result<Self, TermError> {
        Self::from_prefix_suffix(prefix, &[], len, capacity, apparent_size)
    }

    fn from_prefix_suffix(
        prefix: &[u8],
        suffix: &[u8],
        len: usize,
        capacity: usize,
        apparent_size: usize,
    ) -> Result<Self, TermError> {
        if prefix.len().saturating_add(suffix.len()) > len {
            return Err(TermError::BadArg);
        }
        let capacity = capacity.max(len);
        let mut allocation = BinaryBlock::new(
            capacity,
            BINARY_FLAG_WRITABLE | BINARY_FLAG_ACTIVE_WRITER,
            apparent_size,
        )
        .map_err(|_| TermError::SystemLimit)?;
        let output = allocation.bytes_mut_unique().ok_or(TermError::BadArg)?;
        // Port of erts/emulator/beam/erl_bits.c:1899-1917, OTP-29.1.1: the
        // allocator leaves spare Binary capacity uninitialized; only visible
        // prefix and suffix bytes are copied or emitted.
        output[..prefix.len()].copy_from_slice(prefix);
        output[prefix.len()..prefix.len() + suffix.len()].copy_from_slice(suffix);
        allocation.set_apparent_size(apparent_size);
        Ok(Self { allocation })
    }
    /// Current logical length in bytes.
    pub fn len(&self) -> usize {
        self.allocation.apparent_size()
    }
    /// Whether the current logical byte length is zero.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Capacity reserved for future appends, in bytes.
    pub fn capacity(&self) -> usize {
        self.allocation.size()
    }
    /// Whether the unique writer may still grow this buffer.
    #[inline(always)]
    pub fn has_writer(&self) -> bool {
        self.allocation.flags() & BINARY_FLAG_WRITABLE != 0
    }

    fn into_reference(self) -> arinsal_alloc::raw::OwnedBinaryRef {
        self.allocation.into_reference()
    }

    fn data_ptr(&self) -> *const u8 {
        self.allocation.view().bytes_ptr()
    }
}

/// Read the two low flag bits from a live `SUB_BITS` term.
#[inline(always)]
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
        && owner(term).is_some_and(|(_, b)| b.has_flags(BINARY_FLAG_WRITABLE))
}

/// Current capacity of a writable owner's backing allocation, in bytes.
pub fn writable_capacity(term: Term) -> Option<usize> {
    owner(term).and_then(|(_, binary)| binary.capacity())
}

/// Return the writable binary's heap `BinRef` address for young/old accounting.
pub(crate) fn writable_bin_ref_address(term: Term) -> Option<usize> {
    owner(term).map(|(bin_ref, _)| bin_ref as usize)
}

/// The original BinRef term of a `SUB_BITS` (word four).
#[inline(always)]
fn sub_bits_original(term: Term) -> Term {
    // SAFETY: SUB_BITS word four is its original term, retained by a live heap.
    Term(unsafe { *term.raw_ptr().add(4) })
}

#[inline(always)]
fn owner(term: Term) -> Option<(*const u64, BinaryView<'static>)> {
    if term.header()? & 63 != SUB_BITS {
        return None;
    }
    // SAFETY: SUB_BITS word four is its original BinRef, retained by a live heap.
    let original = sub_bits_original(term);
    if original.header()? & 63 != BIN_REF {
        return None;
    }
    // SAFETY: the heap owns a live BinRef and its `val` points to a retained Binary allocation.
    unsafe {
        let p = original.raw_ptr();
        if bin_ref_val_is_external(*p.add(1)) {
            return None;
        }
        let header = *p.add(1) as *const u64;
        if *header & BINARY_FLAG_WRITABLE == 0 {
            return None;
        }
        let capacity = *header.add(3) as usize;
        let words = BINARY_HEADER_WORDS + capacity.div_ceil(8);
        Some((p, BinaryView::from_header(header, words)))
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
        sub_bits_original(term)
    } else {
        term
    };
    if bin_ref.header().is_none_or(|h| h & 63 != BIN_REF) {
        return;
    }
    // SAFETY: the caller supplies a live BinRef retained by this process.
    unsafe {
        let p = bin_ref.raw_ptr();
        if bin_ref_val_is_external(*p.add(1)) {
            return;
        }
        let header = *p.add(1) as *const u64;
        if *header & BINARY_FLAG_WRITABLE == 0 {
            return;
        }
        let capacity = *header.add(3) as usize;
        let view = BinaryView::from_header(header, BINARY_HEADER_WORDS + capacity.div_ceil(8));
        if view.has_flags(BINARY_FLAG_ACTIVE_WRITER) {
            view.store(
                0,
                view.flags().unwrap_or(0) & !BINARY_FLAG_ACTIVE_WRITER,
                Ordering::Relaxed,
            );
        } else if capacity.saturating_sub(view.apparent_size().unwrap_or(0)) >= 8 {
            // SAFETY: GC has stopped this process; this live writable BinRef is its unique owner.
            let mut allocation = BinaryBlock::borrow_from_view(view)
                .expect("live writable Binary has allocator metadata");
            if capacity.saturating_sub(view.apparent_size().unwrap_or(0)) >= 8 {
                shrink_writable_binary(&mut allocation).expect("binary shrink is valid");
                *p.cast_mut().add(1) = allocation.header_ptr() as u64;
            }
        }
    }
}

/// The initial byte displacement recorded by a BinRef. It remains stable
/// even if a writable Vec later reallocates at a differently aligned address.
pub(crate) fn owner_adjustment(term: Term) -> usize {
    let original = if term.header().is_some_and(|h| h & 63 == SUB_BITS) {
        // SAFETY: SUB_BITS word four is its original term.
        sub_bits_original(term)
    } else {
        term
    };
    if original.header().is_some_and(|h| h & 63 == BIN_REF) {
        // SAFETY: the live BinRef's val points to its Binary header.
        unsafe { binary_data(original.raw_ptr()) as usize & 3 }
    } else {
        0
    }
}

pub(crate) fn binary_owner_is_writable(term: Term) -> bool {
    if term.header().is_none_or(|h| h & 63 != BIN_REF) {
        return false;
    }
    // SAFETY: a live BinRef stores its Binary header, or a tagged resource owner, in word one.
    unsafe {
        let val = *term.raw_ptr().add(1);
        !bin_ref_val_is_external(val) && *(val as *const u64) & BINARY_FLAG_WRITABLE != 0
    }
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
    if let Some((bin_ref, binary)) = owner(term)
        && sub_bits_flags(term) & SUB_BITS_VOLATILE != 0
    {
        let capacity = binary.capacity().unwrap_or(0);
        binary.clear_flags(BINARY_FLAG_ACTIVE_WRITER);
        // Port of erts/emulator/beam/erl_bits.c:2053 (erts_pin_writable_binary), OTP-29.1.1.
        // SAFETY: the process owns the writer and no binary view is retained.
        unsafe {
            let mut allocation = BinaryBlock::borrow_from_view(binary)
                .expect("live writable Binary has allocator metadata");
            if capacity.saturating_sub(binary.apparent_size().unwrap_or(0)) >= 8 {
                shrink_writable_binary(&mut allocation).expect("binary shrink is valid");
            }
            *bin_ref.cast_mut().add(1) = allocation.header_ptr() as u64;
            *term.raw_ptr().add(1).cast_mut() = allocation.header_ptr().wrapping_add(4) as u64;
        }
    }
}

/// A retained reference to the owner of an off-heap binary (erts `Binary*` with its refc
/// raised): it keeps the bytes of the binary alive, whatever happens to the term.
pub enum BinaryOwner {
    /// An erts `Binary` (reference-counted or writable).
    Binary(arinsal_alloc::raw::OwnedBinaryRef),
    /// A NIF resource binary.
    External(Arc<ExternalBinary>),
}

impl Clone for BinaryOwner {
    /// `erts_refc_inc` on the binary.
    fn clone(&self) -> Self {
        match self {
            Self::Binary(binary) => Self::Binary(
                binary
                    .try_clone()
                    .expect("retained Binary has a live count"),
            ),
            Self::External(external) => Self::External(Arc::clone(external)),
        }
    }
}

/// The owner of an off-heap binary term, with its reference count raised; `None` for a heap
/// binary, which has no owner (erts: `br == NULL`).
// Port of erts/emulator/beam/erl_nif.c:4190-4197 (marshal_iovec_binary: `br->val`).
pub fn binary_owner(term: Term) -> Option<BinaryOwner> {
    if term.header()? & 63 != SUB_BITS {
        return None;
    }
    let original = sub_bits_original(term);
    if original.header()? & 63 != BIN_REF {
        return None;
    }
    // SAFETY: a live BinRef owns the Binary or Arc it names; the clone is handed to the caller.
    unsafe {
        let (ptr, _, _, owner) = clone_binary_owner(original).ok()?;
        Some(match owner {
            Some(owner) => BinaryOwner::Binary(owner),
            None => BinaryOwner::External(Arc::from_raw(ptr as *const ExternalBinary)),
        })
    }
}

/// The magic reference that owns the bytes of a resource-backed binary term
/// (`enif_make_resource_binary`), as `enif_get_resource` finds it through the term's BinRef.
///
/// The term's heap and its off-heap owners must stay live for the borrow.
pub fn external_binary_magic<'a>(term: Term) -> Option<&'a crate::MagicRef> {
    if term.header()? & 63 != SUB_BITS {
        return None;
    }
    let original = sub_bits_original(term);
    if original.header()? & 63 != BIN_REF {
        return None;
    }
    // SAFETY: a BinRef with the external tag holds the Arc-owned ExternalBinary in word one.
    unsafe {
        let p = original.raw_ptr();
        if !bin_ref_val_is_external(*p.add(1)) {
            return None;
        }
        Some(&*Arc::as_ptr(&(*external_val_ptr(*p.add(1)))._owner))
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
        if bin_ref_val_is_external(*bin_ref.add(1)) {
            (&*external_val_ptr(*bin_ref.add(1))).data
        } else {
            (*bin_ref.add(1) as *const u64)
                .wrapping_add(BINARY_HEADER_WORDS)
                .cast::<u8>()
        }
    }
}

/// Clone the Binary reference behind a BinRef and return its header and owner token.
///
/// # Safety
/// The source BinRef and owner must remain live.
pub(crate) unsafe fn clone_binary_owner(
    bin_ref: Term,
) -> Result<(u64, u64, u64, Option<arinsal_alloc::raw::OwnedBinaryRef>), TermError> {
    // SAFETY: source is a live BinRef and its Binary is retained by the source heap.
    unsafe {
        let p = bin_ref.raw_ptr();
        let val = *p.add(1);
        if bin_ref_val_is_external(val) {
            let ptr = external_val_ptr(val);
            Arc::increment_strong_count(ptr);
            return Ok((ptr as u64, EXTERNAL_OWNER, 0, None));
        }
        let header = val as *const u64;
        let capacity = *header.add(3) as usize;
        let view = BinaryView::from_header(header, BINARY_HEADER_WORDS + capacity.div_ceil(8));
        let flags = view.flags().ok_or(TermError::BadArg)?;
        let owner = arinsal_alloc::raw::OwnedBinaryRef::clone_from_view(view)
            .ok_or(TermError::SystemLimit)?;
        Ok((
            owner.header_ptr() as u64,
            flags,
            (capacity / 8) as u64,
            Some(owner),
        ))
    }
}

/// Transfer a cloned Binary reference into a heap's BinRef chain.
///
/// # Safety
/// The binary pointer and token must come from `clone_binary_owner`.
pub(crate) unsafe fn retain_cloned_binary_owner<H: HeapAlloc + ?Sized>(
    heap: &mut H,
    bin_ref: *mut u64,
    ptr: u64,
    flags: u64,
    overhead_words: u64,
    owner: Option<arinsal_alloc::raw::OwnedBinaryRef>,
) -> Result<(), TermError> {
    // SAFETY: external owner pointer was incremented by clone_binary_owner.
    unsafe {
        if flags == EXTERNAL_OWNER {
            let binary = Arc::from_raw(ptr as *const ExternalBinary);
            *bin_ref.add(1) = external_val_word(&binary);
            heap.link_external_binary(bin_ref, binary)
        } else {
            *bin_ref.add(1) = ptr;
            let writable = flags & BINARY_FLAG_WRITABLE != 0;
            heap.link_bin_ref(bin_ref, writable, overhead_words, owner)?;
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
    Some(
        binary
            .bytes_mut_unique(binary.apparent_size().unwrap_or(0))
            .expect("unique writable Binary reference"),
    )
}

/// Extend an active private writer's bit length and reserve space geometrically.
pub fn writable_extend_private(term: Term, new_bits: usize) -> Result<bool, TermError> {
    match prepare_private_append(term.tagged_word(), new_bits, true, core::ptr::null_mut()) {
        Ok(update) if update.result == 0 => Ok(false),
        Ok(_) => Ok(true),
        Err(error) => Err(error),
    }
}

/// Grow a private writable binary by `extra_bits` and publish the pre-append cursor.
///
/// Returns the same bitstring word, or zero when `bin` is not an active private writer
/// (the caller then uses the generic construction path). A system limit also returns zero
/// after leaving the binary unchanged.
// Port of erts/emulator/beam/erl_bits.c:1928 (erts_bs_private_append_checked), OTP-29.1.1.
pub extern "C" fn erts_bs_private_append_checked(ebs: *mut u64, bin: u64, extra_bits: u64) -> u64 {
    erts_bs_private_append_checked_with_update(ebs, bin, extra_bits).result
}

/// No-realloc private append.
///
/// Returns the bitstring, `0` when `bin` is not an active writer (generic path),
/// or `u64::MAX` when the buffer must grow. A leaf: the realloc path is the
/// caller. Port of the writable branch of erts/emulator/beam/erl_bits.c:1963-2016
/// (`BEAMASM` drops the overflow and header asserts), OTP-29.1.1.
#[inline(always)]
pub extern "C" fn erts_bs_private_append_fast(ebs: *mut u64, bin: u64, extra_bits: u64) -> u64 {
    erts_bs_private_append_fast_with_update(ebs, bin, extra_bits).result
}

/// Private append result plus the BinRef accounting values from its existing parse.
#[derive(Clone, Copy)]
pub struct PrivateAppendUpdate {
    /// Returned bitstring word or the fast-path sentinel.
    pub result: u64,
    /// BinRef heap address, or zero when no active writer was found.
    pub bin_ref: usize,
    /// Position before the append in bits.
    pub old_size_bits: usize,
    /// Position after the append in bits.
    pub new_size_bits: usize,
}

impl PrivateAppendUpdate {
    const fn new(result: u64) -> Self {
        Self {
            result,
            bin_ref: 0,
            old_size_bits: 0,
            new_size_bits: 0,
        }
    }
}

/// Fast private append with the BinRef accounting values from its existing parse.
// Port of erts/emulator/beam/erl_bits.c:1963-2016, OTP-29.1.1.
#[inline(always)]
pub fn erts_bs_private_append_fast_with_update(
    ebs: *mut u64,
    bin: u64,
    extra_bits: u64,
) -> PrivateAppendUpdate {
    if ebs.is_null() || extra_bits == 0 {
        return PrivateAppendUpdate::new(u64::MAX);
    }
    // Boxed tag only. Release erts drops the HEADER_SUB_BITS / HEADER_BIN_REF
    // asserts (instr path is BEAMASM); a non-box returns 0 so the generic
    // builder runs.
    if bin & 3 != 2 {
        return PrivateAppendUpdate::new(0);
    }
    // SAFETY: exclusive writer, same precondition as `prepare_private_append`.
    unsafe {
        let sb = (bin & !7) as *mut u64;
        if *sb.add(1) & 3 != SUB_BITS_MUTABLE | SUB_BITS_VOLATILE {
            return PrivateAppendUpdate::new(0);
        }
        let orig = *sb.add(4);
        if orig & 3 != 2 {
            return PrivateAppendUpdate::new(0);
        }
        let br = (orig & !7) as *const u64;
        let header = *br.add(1) as *const u64;
        let capacity = *header.add(3) as usize;
        let view = BinaryView::from_header(header, BINARY_HEADER_WORDS + capacity.div_ceil(8));
        if !view.has_flags(BINARY_FLAG_ACTIVE_WRITER) {
            return PrivateAppendUpdate::new(0);
        }
        let adjustment = view.bytes_ptr() as usize & 3;
        let end_word = *sb.add(3) as usize;
        if end_word < adjustment * 8 {
            return PrivateAppendUpdate::new(0);
        }
        let current = end_word - adjustment * 8;
        if current & 7 != 0 {
            return PrivateAppendUpdate::new(0);
        }
        let Some(new_bits) = current.checked_add(extra_bits as usize) else {
            return PrivateAppendUpdate::new(u64::MAX);
        };
        if new_bits > isize::MAX as usize {
            return PrivateAppendUpdate::new(u64::MAX);
        }
        let new_len = new_bits.div_ceil(8);
        let old_len = view.apparent_size().unwrap_or(0);
        if new_len > capacity || (!ebs.is_null() && new_len > old_len + 1) {
            return PrivateAppendUpdate::new(u64::MAX);
        }
        // Port of erts/emulator/beam/erl_bits.c:1978-1983, OTP-29.1.1.
        *sb.add(3) = (new_bits + adjustment * 8) as u64;
        view.set_flags(BINARY_FLAG_ACTIVE_WRITER);
        view.set_apparent_size(new_len);
        let ptr = view.bytes_ptr() as u64;
        publish_ebs(ebs, ptr, current as u64);
        PrivateAppendUpdate {
            result: bin,
            bin_ref: br as usize,
            old_size_bits: current,
            new_size_bits: new_bits,
        }
    }
}

/// Checked private append with the BinRef accounting values from its existing parse.
// Port of erts/emulator/beam/erl_bits.c:1928-2016, OTP-29.1.1.
#[cold]
pub fn erts_bs_private_append_checked_with_update(
    ebs: *mut u64,
    bin: u64,
    extra_bits: u64,
) -> PrivateAppendUpdate {
    let fast = erts_bs_private_append_fast_with_update(ebs, bin, extra_bits);
    if fast.result != u64::MAX {
        return fast;
    }
    let Ok(extra) = usize::try_from(extra_bits) else {
        return PrivateAppendUpdate::new(0);
    };
    match prepare_private_append(bin, extra, false, ebs) {
        Ok(update) => update,
        Err(_) => PrivateAppendUpdate::new(0),
    }
}

#[inline(always)]
fn publish_ebs(ebs: *mut u64, ptr: u64, offset: u64) {
    // SAFETY: `ebs` is the caller’s `ErlBitsState` (two u64s), non-null.
    unsafe {
        *ebs = ptr;
        *ebs.add(1) = offset;
    }
}

/// `absolute` selects a new total length; otherwise `bits` is the number of bits to add.
/// On success the returned word is the bitstring. Zero means it is not a private writer.
/// When `ebs` is non-null it receives `erts_current_bin` and the bit offset before the append.
/// Growth goes through [`resize_writable_binary`], which applies `GROW_PROC_BIN_SIZE`.
#[cold]
#[inline(never)]
fn prepare_private_append(
    bin: u64,
    bits: usize,
    absolute: bool,
    ebs: *mut u64,
) -> Result<PrivateAppendUpdate, TermError> {
    // SAFETY: `bin` is a tagged term from a live register or `Term::tagged_word`. This process
    // is the binary's only writer, which is the precondition of erts_bs_private_append_checked.
    unsafe {
        let term = Term::from_raw_bits(bin);
        let Some((bin_ref, binary)) = owner(term) else {
            return Ok(PrivateAppendUpdate::new(0));
        };
        if sub_bits_flags(term) != SUB_BITS_MUTABLE | SUB_BITS_VOLATILE
            || !binary.has_flags(BINARY_FLAG_WRITABLE)
        {
            return Ok(PrivateAppendUpdate::new(0));
        }
        let adjustment = binary.bytes_ptr() as usize & 3;
        let current = *term.raw_ptr().add(3) as usize - adjustment * 8;
        // The inline store writes whole bytes. A non-byte cursor stays on the generic path,
        // which has not yet grown the binary.
        if !absolute && !ebs.is_null() && !current.is_multiple_of(8) {
            return Ok(PrivateAppendUpdate::new(0));
        }
        let new_bits = if absolute {
            bits
        } else {
            current.checked_add(bits).ok_or(TermError::SystemLimit)?
        };
        if new_bits < current || new_bits > isize::MAX as usize {
            return Err(TermError::SystemLimit);
        }
        // Port of erts/emulator/beam/erl_binary.h:321 (erts_bin_realloc_fnf) and
        // erl_bits.c:72 (GROW_PROC_BIN_SIZE), OTP-29.1.1.
        let mut allocation = BinaryBlock::borrow_from_view(binary)
            .expect("live writable Binary has allocator metadata");
        resize_writable_binary(&mut allocation, new_bits.div_ceil(8))?;
        *bin_ref.cast_mut().add(1) = allocation.header_ptr() as u64;
        *term.raw_ptr().add(1).cast_mut() = (allocation.header_ptr().wrapping_add(4) as u64 & !3)
            | SUB_BITS_MUTABLE
            | SUB_BITS_VOLATILE;
        *term.raw_ptr().add(3).cast_mut() = (new_bits + adjustment * 8) as u64;
        // Port of erl_bits.c:1961 (`update_wb_overhead` before realloc), OTP-29.1.1.
        // Resize does not collect, so the counter moves with the committed size.
        if !ebs.is_null() {
            let ptr = allocation
                .header_ptr()
                .wrapping_add(BINARY_HEADER_WORDS)
                .cast::<u8>() as u64;
            *ebs = ptr;
            *ebs.add(1) = current as u64;
        }
        Ok(PrivateAppendUpdate {
            result: term.tagged_word(),
            bin_ref: bin_ref as usize,
            old_size_bits: current,
            new_size_bits: new_bits,
        })
    }
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
            *p.add(1) = external_val_word(&owner);
            *p.add(2) = 0;
            *sub = (4 << 6) | SUB_BITS;
            *sub.add(1) = owner.data as u64 & !3;
            *sub.add(2) = (adjustment * 8) as u64;
            *sub.add(3) = end as u64;
            *sub.add(4) = Term::from_ptr(p, 2).0;
        }
        self.heap.link_external_binary(p, owner)?;
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
        // A heap bitstring is its own original, has no owner to pin and starts at bit zero
        // (erl_bits.h:433-439, ERTS_PIN_BITSTRING).
        let heap_bits = source.header().is_some_and(|h| h & 63 == HEAP_BITS);
        let view = if heap_bits {
            None
        } else {
            writable_finalize(source);
            // SAFETY: the source heap stays live through construction.
            Some(unsafe { source.binary_ref() }.ok_or(TermError::BadArg)?)
        };
        let mut original = source;
        while original.header().is_some_and(|h| h & 63 == SUB_BITS) {
            // SAFETY: SUB_BITS word four retains its original.
            original = Term(unsafe { *original.raw_ptr().add(4) });
        }
        let p = self.words(5)?;
        let adjustment = owner_adjustment(original);
        // Port of erts/emulator/beam/erl_bits.c:79 (erts_bs_start_match_3), OTP-29.1.1.
        // SAFETY: five words are reserved; the original term stays rooted by word four. A
        // heap bitstring keeps its size in word one and its data from word two.
        unsafe {
            *p = (4 << 6) | SUB_BITS;
            if let Some(view) = &view {
                *p.add(1) = (view.bytes().as_ptr() as u64 & !3) | SUB_BITS_MUTABLE;
                *p.add(2) = (view.start_bit() + adjustment * 8) as u64;
                *p.add(3) = (view.start_bit() + view.bit_len() + adjustment * 8) as u64;
            } else {
                let heap_bits = source.raw_ptr();
                *p.add(1) = (heap_bits.add(2) as u64 & !3) | SUB_BITS_MUTABLE;
                *p.add(2) = 0;
                *p.add(3) = *heap_bits.add(1);
            }
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
        self.writable_binary_with_allocation(
            bytes,
            bit_len,
            capacity,
            capacity.saturating_mul(8),
            false,
        )
    }

    /// Build a writable binary using its visible size for pre-GC overhead.
    // Port of erl_bits.c:1675-1698 (`build_writable_bitstring`), OTP-29.1.1.
    pub fn writable_binary_with_apparent_size(
        &mut self,
        bytes: &[u8],
        bit_len: usize,
        capacity: usize,
        apparent_size_bits: usize,
    ) -> Result<Term, TermError> {
        self.writable_binary_with_allocation(bytes, bit_len, capacity, apparent_size_bits, false)
    }

    /// Build a writable binary whose `BinRef` and `SUB_BITS` live in a heap fragment.
    // Port of erl_bits.c:1996 (`HeapFragOnlyAlloc` for private append), OTP-29.1.1.
    pub fn writable_binary_in_fragment(
        &mut self,
        bytes: &[u8],
        bit_len: usize,
        capacity: usize,
        apparent_size_bits: usize,
    ) -> Result<Term, TermError> {
        self.writable_binary_with_allocation(bytes, bit_len, capacity, apparent_size_bits, true)
    }

    /// Install a writable bitstring from bytes the caller already owns.
    ///
    /// The `Vec` is only the source of those bytes. Storage is an allocator block,
    /// same as [`TermBuilder::writable_binary`].
    pub fn writable_from_vec(
        &mut self,
        mut bytes: Vec<u8>,
        bit_len: usize,
    ) -> Result<Term, TermError> {
        let count = bit_len.div_ceil(8);
        if count > bytes.len() {
            return Err(TermError::BadArg);
        }
        bytes.truncate(count);
        let capacity = bytes.capacity().max(count);
        let apparent = capacity.saturating_mul(8).max(bit_len);
        self.writable_binary_with_allocation(&bytes, bit_len, capacity, apparent, false)
    }

    /// Build a writable binary by copying two byte ranges into its final allocation.
    ///
    /// The visible and apparent size equal the combined input length, while `capacity` reserves
    /// room for later appends. This mirrors the append emitter's destination allocation.
    // Port of erts/emulator/beam/erl_bits.c:1812-1917, OTP-29.1.1.
    pub fn writable_binary_from_parts(
        &mut self,
        prefix: &[u8],
        suffix: &[u8],
        capacity: usize,
    ) -> Result<Term, TermError> {
        self.writable_binary_from_parts_with_address(prefix, suffix, capacity)
            .map(|(term, _)| term)
    }

    /// Build an append destination and return its stable payload address for BeamAsm stores.
    // Port of erts/emulator/beam/erl_bits.c:1725-1917, OTP-29.1.1.
    pub fn writable_binary_from_parts_with_address(
        &mut self,
        prefix: &[u8],
        suffix: &[u8],
        capacity: usize,
    ) -> Result<(Term, usize), TermError> {
        let count = prefix
            .len()
            .checked_add(suffix.len())
            .ok_or(TermError::SystemLimit)?;
        let bit_len = count.checked_mul(8).ok_or(TermError::SystemLimit)?;
        if bit_len > isize::MAX as usize || !self.heap.supports_writable_binary() {
            return Err(if bit_len > isize::MAX as usize {
                TermError::SystemLimit
            } else {
                TermError::Unsupported("writable binary heap owner")
            });
        }
        let binary = WritableBinary::from_parts(prefix, suffix, capacity, count)?;
        self.install_writable_binary(binary, bit_len, bit_len, false)
    }

    /// Build an append destination with an uninitialized suffix reserved for emitted stores.
    // Port of erts/emulator/beam/erl_bits.c:1812-1917, OTP-29.1.1.
    pub fn writable_binary_with_prefix(
        &mut self,
        prefix: &[u8],
        visible_bits: usize,
        capacity: usize,
    ) -> Result<(Term, usize), TermError> {
        if !visible_bits.is_multiple_of(8)
            || prefix.len() > visible_bits / 8
            || visible_bits > isize::MAX as usize
        {
            return Err(TermError::BadArg);
        }
        if !self.heap.supports_writable_binary() {
            return Err(TermError::Unsupported("writable binary heap owner"));
        }
        let visible_bytes = visible_bits / 8;
        let binary = WritableBinary::from_prefix(prefix, visible_bytes, capacity, visible_bytes)?;
        self.install_writable_binary(binary, visible_bits, visible_bits, false)
    }

    fn writable_binary_with_allocation(
        &mut self,
        bytes: &[u8],
        bit_len: usize,
        capacity: usize,
        apparent_size_bits: usize,
        fragment_only: bool,
    ) -> Result<Term, TermError> {
        if bit_len > bytes.len().saturating_mul(8) || bit_len > isize::MAX as usize {
            return Err(TermError::BadArg);
        }
        if apparent_size_bits < bit_len || apparent_size_bits > isize::MAX as usize {
            return Err(TermError::BadArg);
        }
        if !self.heap.supports_writable_binary() {
            return Err(TermError::Unsupported("writable binary heap owner"));
        }
        let count = bit_len.div_ceil(8);
        if apparent_size_bits.div_ceil(8) > capacity.max(count) {
            return Err(TermError::BadArg);
        }
        let mut initial = bytes[..count].to_vec();
        if !bit_len.is_multiple_of(8) && count > 0 {
            initial[count - 1] &= 0xff << (8 - bit_len % 8);
        }
        let binary = WritableBinary::new(&initial, capacity, apparent_size_bits.div_ceil(8))?;
        self.install_writable_binary(binary, bit_len, apparent_size_bits, fragment_only)
            .map(|(term, _)| term)
    }

    fn install_writable_binary(
        &mut self,
        binary: WritableBinary,
        bit_len: usize,
        apparent_size_bits: usize,
        fragment_only: bool,
    ) -> Result<(Term, usize), TermError> {
        let data_address = binary.data_ptr() as usize;
        let adjustment = data_address & 3;
        let p = if fragment_only {
            self.heap.alloc_fragment_only(8)
        } else {
            self.heap.alloc(8)
        }
        .ok_or(TermError::HeapFull)?;
        let binary_owner = binary.into_reference();
        let binary_header = binary_owner.header_ptr();
        // Port of erts/emulator/beam/erl_bits.c:1675 (build_writable_bitstring), OTP-29.1.1.
        // SAFETY: eight words hold a BinRef and SUB_BITS; the heap links the BinRef below.
        unsafe {
            let sub = p.add(3);
            *p = (2 << 6) | BIN_REF;
            *p.add(1) = binary_header as u64;
            *sub = (4 << 6) | SUB_BITS;
            *sub.add(1) = (data_address as u64 & !3) | SUB_BITS_MUTABLE | SUB_BITS_VOLATILE;
            *sub.add(2) = (adjustment * 8) as u64;
            *sub.add(3) = (bit_len + adjustment * 8) as u64;
            *sub.add(4) = Term::from_ptr(p, 2).0;
        }
        self.heap.link_bin_ref(
            p,
            true,
            (apparent_size_bits.div_ceil(8) / 8) as u64,
            Some(binary_owner),
        )?;
        // SAFETY: p was allocated for the SUB_BITS directly after the BinRef.
        Ok((Term::from_ptr(unsafe { p.add(3) }, 2), data_address))
    }

    /// Create the next writable handle after a public append. The prior handle
    /// becomes VOLATILE and retains its prior length.
    pub fn writable_successor(
        &mut self,
        source: Term,
        new_bits: usize,
    ) -> Result<Option<Term>, TermError> {
        self.writable_successor_with_address(source, new_bits)
            .map(|successor| successor.map(|(term, _)| term))
    }

    /// Create the next writable handle and return its stable payload address.
    pub fn writable_successor_with_address(
        &mut self,
        source: Term,
        new_bits: usize,
    ) -> Result<Option<(Term, usize)>, TermError> {
        self.writable_successor_inner(source, Some(new_bits), 0, 0)
            .map(|successor| successor.map(|(term, address, _, _)| (term, address)))
    }

    /// Append to the current writer and return its previous end, payload address and growth bit.
    // Port of erts/emulator/beam/erl_bits.c:1725-1829, OTP-29.1.1.
    #[inline]
    pub fn writable_append_with_address(
        &mut self,
        source: Term,
        extra_bits: usize,
        unit: usize,
    ) -> Result<Option<(Term, usize, usize, bool)>, TermError> {
        self.writable_successor_inner(source, None, extra_bits, unit)
    }

    // Port of erts/emulator/beam/erl_bits.c:1725-1829, OTP-29.1.1.
    #[inline]
    fn writable_successor_inner(
        &mut self,
        source: Term,
        requested_bits: Option<usize>,
        extra_bits: usize,
        unit: usize,
    ) -> Result<Option<(Term, usize, usize, bool)>, TermError> {
        let Some((bin_ref, binary)) = owner(source) else {
            return Ok(None);
        };
        if sub_bits_flags(source) != SUB_BITS_MUTABLE | SUB_BITS_VOLATILE
            || !binary.has_flags(BINARY_FLAG_ACTIVE_WRITER)
        {
            return Ok(None);
        }
        // SAFETY: the live writable SUB_BITS stores its end in word three and its BinRef keeps
        // the backing allocation alive for this operation.
        let (adjustment, end, current_bin) = unsafe {
            let adjustment = binary.bytes_ptr() as usize & 3;
            let end = *source.raw_ptr().add(3) as usize - adjustment * 8;
            let data = binary.bytes_ptr() as usize;
            (adjustment, end, data)
        };
        if unit > 1 && !end.is_multiple_of(unit) {
            return Err(TermError::BadArg);
        }
        let new_bits = match requested_bits {
            Some(bits) => bits,
            None => end.checked_add(extra_bits).ok_or(TermError::SystemLimit)?,
        };
        if new_bits < end || new_bits > isize::MAX as usize {
            return Err(TermError::SystemLimit);
        }
        if new_bits == end {
            return Ok(Some((source, current_bin, end, false)));
        }
        let old_capacity = binary.capacity().ok_or(TermError::BadArg)?;
        let p = self.words(5)?;
        self.heap
            .update_writable_binary_overhead(source, end, new_bits);
        let (_, binary) = owner(source).unwrap();
        // SAFETY: this process owns the active writer and no bytes are borrowed.
        let (term, data_address, grew) = unsafe {
            let mut allocation = BinaryBlock::borrow_from_view(binary)
                .expect("live writable Binary has allocator metadata");
            resize_writable_binary(&mut allocation, new_bits.div_ceil(8))?;
            *bin_ref.cast_mut().add(1) = allocation.header_ptr() as u64;
            let old = source.raw_ptr().cast_mut();
            *old.add(1) = (allocation.header_ptr().wrapping_add(4) as u64 & !3)
                | (if *old.add(1) & SUB_BITS_VOLATILE != 0 {
                    SUB_BITS_VOLATILE
                } else {
                    0
                });
            *old.add(1) &= !SUB_BITS_MUTABLE;
            std::ptr::copy_nonoverlapping(old, p, 5);
            *p.add(1) |= SUB_BITS_MUTABLE;
            *p.add(3) = (new_bits + adjustment * 8) as u64;
            let address = allocation.header_ptr().wrapping_add(4).cast::<u8>() as usize;
            (
                Term::from_ptr(p, 2),
                address,
                allocation.size() > old_capacity,
            )
        };
        Ok(Some((term, data_address, end, grew)))
    }
}

#[cfg(test)]
mod private_append_checked {
    use super::erts_bs_private_append_checked;
    use crate::{TermBuilder, VecHeap};

    #[test]
    fn publishes_the_pre_append_cursor() {
        let mut heap = VecHeap::new();
        let bin = TermBuilder::new(&mut heap)
            .writable_binary(b"ab", 16, 64)
            .unwrap();
        let mut ebs = [0_u64; 2];
        let result = erts_bs_private_append_checked(ebs.as_mut_ptr(), bin.tagged_word(), 8);
        assert_eq!(result, bin.tagged_word());
        assert_eq!(ebs[1], 16);
        assert_ne!(ebs[0], 0);
    }

    #[test]
    fn non_byte_cursor_is_left_for_the_generic_path() {
        let mut heap = VecHeap::new();
        let bin = TermBuilder::new(&mut heap)
            .writable_binary(&[0xf0], 4, 64)
            .unwrap();
        let mut ebs = [7_u64; 2];
        let result = erts_bs_private_append_checked(ebs.as_mut_ptr(), bin.tagged_word(), 8);
        assert_eq!(result, 0);
        assert_eq!(ebs, [7, 7]);
    }

    #[test]
    fn empty_prefix_can_reserve_a_private_append_byte() {
        let mut heap = VecHeap::new();
        let result = TermBuilder::new(&mut heap).writable_binary_with_prefix(&[], 8, 8);
        assert!(result.is_ok());
        let (term, address) = result.unwrap();
        assert!(crate::is_writable_binary(term));
        assert_ne!(address, 0);
    }
}
