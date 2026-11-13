// Port of erts/emulator/beam/erl_binary.h (ErtsMagicBinary, erts_create_magic_binary_x,
// erts_bin_release, erts_bin_free, erts_magic_binary_free, ERTS_MAGIC_BIN_DATA,
// ERTS_MAGIC_BIN_DESTRUCTOR) and erl_bif_unique.c (magic_ref_table,
// erts_magic_ref_lookup_bin__, erts_magic_ref_save_bin__, erts_magic_ref_remove_bin), OTP-29.1.1.
//
//! The magic binary block: one allocation holding the reference count, `orig_size`, the
//! destructor, the reference numbers and the payload inline after the header, and the raw
//! accesses to it. All `unsafe` for magic binaries lives here.

use std::alloc::{Layout, alloc, dealloc, handle_alloc_error};
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering, fence};
use std::sync::{OnceLock, RwLock};

/// `ERTS_MAGIC_DATA_OFFSET` on 64-bit targets: what `ERTS_MAGIC_BIN_ORIG_SIZE` adds to the
/// payload size.
pub const MAGIC_BIN_DATA_OFFSET: usize = 24;

/// `int (*destructor)(Binary *)`: finalizes the payload in place before the block is freed.
type Destructor = unsafe fn(NonNull<MagicRef>);

/// `ErtsMagicBinary`: the header of a magic binary block; the payload follows it inline.
#[repr(C)]
pub struct MagicRef {
    /// `intern.refc`.
    refc: AtomicUsize,
    /// Holders of a [`MagicWeak`] plus one for all `refc` holders together; the block's memory
    /// is released when it reaches zero.
    weak: AtomicUsize,
    /// `orig_size`: what an owning heap charges to its virtual binary heap.
    orig_size: usize,
    /// `destructor`, run when `refc` reaches zero.
    destructor: Destructor,
    /// The payload type, checked by [`MagicRef::downcast_ref`].
    type_id: TypeId,
    /// `refn`.
    refn: [u32; 3],
    /// Whether the reference numbers are in [`magic_ref_table`].
    saved: AtomicBool,
    /// `alloc_type`: the layout the block was allocated with.
    alloc_size: usize,
    alloc_align: usize,
}

/// `ERTS_MAGIC_BIN_DATA`: offset of a `T` payload from the start of the block.
const fn data_offset<T>() -> usize {
    let header = size_of::<MagicRef>();
    let align = align_of::<T>();
    (header + align - 1) & !(align - 1)
}

/// The destructor of `T` payloads: drops the payload in place.
///
/// # Safety
/// `mb` is a block created with a `T` payload that has not been dropped yet.
unsafe fn drop_payload<T>(mb: NonNull<MagicRef>) {
    // SAFETY: by contract the block holds a live `T` at its data offset.
    unsafe { std::ptr::drop_in_place(mb.cast::<u8>().as_ptr().add(data_offset::<T>()).cast::<T>()) }
}

impl MagicRef {
    /// `mb->orig_size` of the magic binary.
    pub fn orig_size(&self) -> usize {
        self.orig_size
    }

    /// The reference identity used for term ordering and hashing.
    pub fn id(&self) -> u64 {
        refn_key(self.refn)
    }

    /// The three erts reference words stored in the magic binary.
    pub(crate) fn ref_numbers(&self) -> [u32; 3] {
        self.refn
    }

    /// `ERTS_MAGIC_BIN_DATA` read as a `T`, if the payload is a `T`.
    #[inline]
    pub fn downcast_ref<T: Any>(&self) -> Option<&T> {
        if self.type_id != TypeId::of::<T>() {
            return None;
        }
        // SAFETY: the block was created with a `T` payload at this offset, and the payload
        // lives as long as `self` is borrowed from a counted reference.
        Some(unsafe {
            &*std::ptr::from_ref(self)
                .cast::<u8>()
                .add(data_offset::<T>())
                .cast::<T>()
        })
    }

    /// Current `intern.refc`, for `erts_debug` introspection.
    pub fn refc(&self) -> usize {
        self.refc.load(Ordering::Relaxed)
    }
}

/// A counted reference to a magic binary: `Binary *` with one `intern.refc` held.
pub struct MagicBin(NonNull<MagicRef>);

// SAFETY: payloads are `Send + Sync` and the count is atomic.
unsafe impl Send for MagicBin {}
// SAFETY: as above; shared access only reads the header and borrows the `Sync` payload.
unsafe impl Sync for MagicBin {}

static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl MagicBin {
    /// A magic binary whose `orig_size` is the payload size, with fresh reference numbers.
    pub fn new<T: Any + Send + Sync>(payload: T) -> Self {
        Self::with_orig_size(payload, size_of::<T>())
    }

    /// A magic binary whose `mb->orig_size` is `orig_size` bytes, for payloads that stand in
    /// for a fixed erts structure.
    pub fn with_orig_size<T: Any + Send + Sync>(payload: T, orig_size: usize) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        Self::create(payload, orig_size, refn_for_key(id))
    }

    /// `erts_create_magic_binary_x` with the reference words returned by its scheduler
    /// (`erts_make_magic_ref_in_array`).
    pub fn with_orig_size_and_refn<T: Any + Send + Sync>(
        payload: T,
        orig_size: usize,
        mut refn: [u32; 3],
    ) -> Self {
        refn[1] |= 1 << 17;
        Self::create(payload, orig_size, refn)
    }

    /// `erts_create_magic_binary(payload_size, ...)`: `orig_size` includes the data offset.
    pub fn with_erts_payload_size<T: Any + Send + Sync>(payload: T, payload_size: usize) -> Self {
        Self::with_orig_size(payload, MAGIC_BIN_DATA_OFFSET + payload_size)
    }

    /// `erts_create_magic_binary` with reference numbers already assigned by its scheduler.
    pub fn with_erts_payload_size_and_refn<T: Any + Send + Sync>(
        payload: T,
        payload_size: usize,
        refn: [u32; 3],
    ) -> Self {
        Self::with_orig_size_and_refn(payload, MAGIC_BIN_DATA_OFFSET + payload_size, refn)
    }

    // Port of erts/emulator/beam/erl_binary.h (erts_create_magic_binary_x), OTP-29.1.1: one
    // allocation, header then aligned payload; the creator holds the first count.
    fn create<T: Any + Send + Sync>(payload: T, orig_size: usize, refn: [u32; 3]) -> Self {
        let align = align_of::<MagicRef>().max(align_of::<T>());
        let size = data_offset::<T>() + size_of::<T>();
        let layout = Layout::from_size_align(size, align).expect("magic binary layout");
        // SAFETY: the layout has a non-zero size (the header is never empty).
        let raw = unsafe { alloc(layout) };
        let Some(block) = NonNull::new(raw.cast::<MagicRef>()) else {
            handle_alloc_error(layout)
        };
        // SAFETY: `block` is a fresh allocation large and aligned enough for the header and a
        // `T` at `data_offset::<T>()`.
        unsafe {
            block.write(MagicRef {
                refc: AtomicUsize::new(1),
                weak: AtomicUsize::new(1),
                orig_size,
                destructor: drop_payload::<T>,
                type_id: TypeId::of::<T>(),
                refn,
                saved: AtomicBool::new(false),
                alloc_size: size,
                alloc_align: align,
            });
            raw.add(data_offset::<T>()).cast::<T>().write(payload);
        }
        Self(block)
    }

    /// Whether two references name the same magic binary.
    pub fn ptr_eq(a: &Self, b: &Self) -> bool {
        a.0 == b.0
    }

    /// The block address, the pointer word of an `ErtsMRefThing`.
    pub fn as_ptr(this: &Self) -> *const MagicRef {
        this.0.as_ptr()
    }

    /// Give up this count to a raw pointer word (an `ErtsMRefThing` taking over the count).
    pub(crate) fn into_raw(this: Self) -> *const MagicRef {
        let ptr = this.0.as_ptr();
        std::mem::forget(this);
        ptr
    }

    /// The owner behind a magic reference thing's pointer word. With `clone` the thing keeps
    /// its counted reference and the result is a new one; without it the thing's own count
    /// moves to the result (an `erts_bin_release` when the result is dropped).
    // Port of erts/emulator/beam/erl_bif_unique.h (ErtsMRefThing `mb`), OTP-29.1.1.
    pub(crate) fn thing_owner(word: u64, clone: bool) -> Self {
        let block = NonNull::new(word as *mut MagicRef).expect("magic thing pointer");
        if clone {
            // SAFETY: the pointer word of a live magic reference thing holds a count.
            unsafe { block.as_ref() }
                .refc
                .fetch_add(1, Ordering::Relaxed);
        }
        Self(block)
    }

    /// A reference that does not keep the payload alive.
    pub fn downgrade(this: &Self) -> MagicWeak {
        this.weak.fetch_add(1, Ordering::Relaxed);
        MagicWeak(Some(this.0))
    }

    // Port of erts/emulator/beam/erl_binary.h (erts_bin_free for BIN_FLAG_MAGIC,
    // erts_magic_binary_free), OTP-29.1.1.
    #[cold]
    fn free(block: NonNull<MagicRef>) {
        // SAFETY: refc reached zero, so this is the only access to the payload; the memory
        // stays valid until the last weak count below is released.
        let header = unsafe { block.as_ref() };
        // SAFETY: the destructor matches the payload written at creation.
        unsafe { (header.destructor)(block) };
        if header.saved.load(Ordering::Acquire) {
            magic_ref_remove_bin(header.id());
        }
        release_weak(block);
    }
}

impl std::ops::Deref for MagicBin {
    type Target = MagicRef;
    #[inline]
    fn deref(&self) -> &MagicRef {
        // SAFETY: a counted reference keeps the block and its payload live.
        unsafe { self.0.as_ref() }
    }
}

impl Clone for MagicBin {
    /// `erts_refc_inc(&mb->intern.refc, 1)`.
    #[inline]
    fn clone(&self) -> Self {
        self.refc.fetch_add(1, Ordering::Relaxed);
        Self(self.0)
    }
}

impl Drop for MagicBin {
    /// `erts_bin_release`.
    #[inline]
    fn drop(&mut self) {
        if self.refc.fetch_sub(1, Ordering::Release) != 1 {
            return;
        }
        fence(Ordering::Acquire);
        Self::free(self.0);
    }
}

impl std::fmt::Debug for MagicBin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MagicBin({})", self.id())
    }
}

/// Release one weak count; the last one frees the block.
fn release_weak(block: NonNull<MagicRef>) {
    // SAFETY: the caller holds a weak count, so the header memory is valid.
    let header = unsafe { block.as_ref() };
    if header.weak.fetch_sub(1, Ordering::Release) != 1 {
        return;
    }
    fence(Ordering::Acquire);
    let layout = Layout::from_size_align(header.alloc_size, header.alloc_align)
        .expect("magic binary layout");
    // SAFETY: no count of any kind remains; the block was allocated with this layout.
    unsafe { dealloc(block.cast::<u8>().as_ptr(), layout) };
}

/// `erts_refc_inc_unless(&mb->intern.refc, 0, 0)`: a new count unless the binary is dead.
///
/// # Safety
/// The block memory must stay valid for the call.
unsafe fn retain_unless_dead(block: NonNull<MagicRef>) -> Option<MagicBin> {
    // SAFETY: by contract the header memory is valid.
    let refc = unsafe { &block.as_ref().refc };
    let mut current = refc.load(Ordering::Relaxed);
    loop {
        if current == 0 {
            return None;
        }
        match refc.compare_exchange_weak(current, current + 1, Ordering::Acquire, Ordering::Relaxed)
        {
            Ok(_) => return Some(MagicBin(block)),
            Err(seen) => current = seen,
        }
    }
}

/// A reference to a magic binary that does not keep its payload alive.
pub struct MagicWeak(Option<NonNull<MagicRef>>);

// SAFETY: only the atomic header counts are touched through a weak reference.
unsafe impl Send for MagicWeak {}
// SAFETY: as above.
unsafe impl Sync for MagicWeak {}

impl MagicWeak {
    /// A weak reference to no binary.
    pub const fn new() -> Self {
        Self(None)
    }

    /// A counted reference, unless the binary's payload is gone.
    pub fn upgrade(&self) -> Option<MagicBin> {
        // SAFETY: the weak count keeps the header memory valid.
        self.0
            .and_then(|block| unsafe { retain_unless_dead(block) })
    }
}

impl Default for MagicWeak {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for MagicWeak {
    fn clone(&self) -> Self {
        if let Some(block) = self.0 {
            // SAFETY: the weak count keeps the header memory valid.
            unsafe { block.as_ref() }
                .weak
                .fetch_add(1, Ordering::Relaxed);
        }
        Self(self.0)
    }
}

impl Drop for MagicWeak {
    fn drop(&mut self) {
        if let Some(block) = self.0 {
            release_weak(block);
        }
    }
}

/// Borrow the magic binary of a magic reference thing's pointer word.
///
/// # Safety
/// The thing's heap and its off-heap owners must stay live for the borrow.
pub(crate) unsafe fn thing_block<'a>(word: u64) -> &'a MagicRef {
    // SAFETY: the pointer word of a live magic reference thing holds a count.
    unsafe { &*(word as *const MagicRef) }
}

// Port of erts/emulator/beam/erl_bif_unique.c (magic_ref_table), OTP-29.1.1: reference
// numbers to the magic binary, sharded like erts' per-scheduler tables. Creating a magic
// reference never touches it. It is filled only when the numbers leave the term
// (`term_to_binary`, `ref_to_list`), so that decoding or `list_to_ref` on this node finds the
// binary again, and the entry goes away when the binary is freed.
const TABLE_SHARDS: usize = 64;

struct Entry(NonNull<MagicRef>);
// SAFETY: the table only hands the pointer to `retain_unless_dead` under its lock.
unsafe impl Send for Entry {}
// SAFETY: as above.
unsafe impl Sync for Entry {}

type Shard = RwLock<HashMap<u64, Entry>>;

fn magic_ref_table(id: u64) -> &'static Shard {
    static TABLE: OnceLock<Vec<Shard>> = OnceLock::new();
    &TABLE.get_or_init(|| (0..TABLE_SHARDS).map(|_| RwLock::default()).collect())
        [(id as usize) % TABLE_SHARDS]
}

impl MagicBin {
    /// `erts_magic_ref_save_bin`: make the reference numbers resolvable on this node.
    pub fn save_in_table(&self) {
        if self.saved.load(Ordering::Acquire) {
            return;
        }
        let id = self.id();
        magic_ref_table(id)
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(id)
            .or_insert(Entry(self.0));
        self.saved.store(true, Ordering::Release);
    }

    /// `erts_magic_ref_lookup_bin`: the live magic binary saved under this identity.
    pub fn lookup_saved(id: u64) -> Option<Self> {
        let shard = magic_ref_table(id)
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: an entry is removed under the write lock before its block is freed, so the
        // block is valid while the read lock is held.
        shard
            .get(&id)
            .and_then(|entry| unsafe { retain_unless_dead(entry.0) })
    }

    /// The live magic binary addressed by its local reference numbers.
    pub fn lookup_saved_numbers(refn: [u32; 3]) -> Option<Self> {
        Self::lookup_saved(refn_key(refn))
    }
}

/// `erts_magic_ref_remove_bin`.
fn magic_ref_remove_bin(id: u64) {
    magic_ref_table(id)
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&id);
}

// Port of erl_bif_unique.h (erts_get_ref_numbers_value/erts_set_ref_numbers), OTP-29.1.1.
fn refn_key(refn: [u32; 3]) -> u64 {
    (u64::from(refn[1] & 0xffff) << 48)
        | (u64::from(refn[2]) << 32)
        | u64::from(refn[1] & 0xfffc_0000)
        | u64::from(refn[0] & 0x3ffff)
}

fn refn_for_key(id: u64) -> [u32; 3] {
    let value = id & 0x0000_ffff_ffff_ffff;
    let thr_id = (id >> 48) as u32;
    [
        value as u32 & 0x3ffff,
        (value as u32 & 0xfffc_0000) | thr_id | (1 << 17),
        (value >> 32) as u32,
    ]
}
