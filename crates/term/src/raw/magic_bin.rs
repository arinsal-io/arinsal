// Port of erts/emulator/beam/erl_binary.h (ErtsMagicBinary, erts_create_magic_binary_x,
// erts_bin_release, erts_bin_free, erts_magic_binary_free, ERTS_MAGIC_BIN_DATA,
// ERTS_MAGIC_BIN_DESTRUCTOR) and erl_bif_unique.c (magic_ref_table,
// erts_magic_ref_lookup_bin__, erts_magic_ref_save_bin__, erts_magic_ref_remove_bin), OTP-29.1.1.
//
//! The magic binary block: one allocation holding the reference count, `orig_size`, the
//! destructor, the reference numbers and the payload inline after the header, and the raw
//! accesses to it. All `unsafe` for magic binaries lives here.

use std::alloc::{Layout, alloc, dealloc, handle_alloc_error};
use std::collections::HashMap;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering, fence};
use std::sync::{OnceLock, RwLock};

/// `ERTS_MAGIC_DATA_OFFSET` on 64-bit targets: what `ERTS_MAGIC_BIN_ORIG_SIZE` adds to the
/// payload size.
pub const MAGIC_BIN_DATA_OFFSET: usize = 24;

/// `int (*destructor)(Binary *)`: finalizes the payload when the last count is released.
/// Each payload type has its own named destructor, and the destructor identifies the type.
/// `true` (erts 1) lets [`MagicBin`] free the block now; `false` (erts 0) means the destructor
/// took control of the deallocation and calls [`MagicBin::magic_binary_free`] itself later.
pub type MagicDestructor = unsafe fn(NonNull<MagicRef>) -> bool;

/// A type that can be the data of a magic binary.
///
/// # Safety
/// `DESTRUCTOR` must be a function that no other type uses (it identifies the payload type in
/// [`MagicRef::downcast_ref`]), that drops the payload exactly once with [`drop_payload`]
/// before the block is freed, and that returns `false` only when it frees the block itself.
/// [`crate::magic_payload!`] defines a distinct non-inlined destructor per type; a type whose
/// destructor takes control of the deallocation implements the trait by hand.
pub unsafe trait MagicPayload: Send + Sync + Sized + 'static {
    /// `ERTS_MAGIC_BIN_DESTRUCTOR` of binaries holding a `Self`.
    const DESTRUCTOR: MagicDestructor;
}

/// Declare the magic binary destructor of a payload type, like the named destructor erts
/// passes to `erts_create_magic_binary` (`db_table_tid_destructor`, `cleanup_match_pseudo_process`, ...).
///
/// The generated destructor is `#[inline(never)]` so that every crate refers to one symbol,
/// and it touches a static of its own so that identical-function merging cannot fold two
/// payload types into one address.
#[macro_export]
macro_rules! magic_payload {
    ($($ty:ty => $name:ident),+ $(,)?) => {$(
        // SAFETY: the destructor below is defined once for this type and only drops it.
        unsafe impl $crate::MagicPayload for $ty {
            const DESTRUCTOR: $crate::MagicDestructor = {
                #[inline(never)]
                unsafe fn $name(mb: ::std::ptr::NonNull<$crate::MagicRef>) -> bool {
                    static MARKER: ::std::sync::atomic::AtomicU8 =
                        ::std::sync::atomic::AtomicU8::new(0);
                    ::std::hint::black_box(&MARKER);
                    // SAFETY: called by `erts_bin_free` once for a block holding this type.
                    unsafe { $crate::raw::magic_bin::drop_payload::<$ty>(mb) };
                    true
                }
                $name
            };
        }
    )+};
}

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
    destructor: MagicDestructor,
    /// `refn`.
    refn: [u32; 3],
    /// Whether the reference numbers are in [`magic_ref_table`].
    saved: AtomicBool,
    /// `alloc_type`: the layout the block was allocated with.
    alloc_size: usize,
    alloc_align: usize,
}

/// Offset of the trailing bytes that follow a `T` payload.
const fn trailing_offset<T>(align: usize) -> usize {
    let end = data_offset::<T>() + size_of::<T>();
    (end + align - 1) & !(align - 1)
}

/// `ERTS_MAGIC_BIN_DATA`: offset of a `T` payload from the start of the block.
const fn data_offset<T>() -> usize {
    let header = size_of::<MagicRef>();
    let align = align_of::<T>();
    (header + align - 1) & !(align - 1)
}

/// Drops a `T` payload in place: the body of every [`MagicPayload::DESTRUCTOR`].
///
/// # Safety
/// `mb` is a block created with a `T` payload that has not been dropped yet.
#[inline(always)]
pub unsafe fn drop_payload<T>(mb: NonNull<MagicRef>) {
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
    // Port of erl_db.c (tid2tab: `ERTS_MAGIC_BIN_DESTRUCTOR(btid) != db_table_tid_destructor`).
    pub fn downcast_ref<T: MagicPayload>(&self) -> Option<&T> {
        if !std::ptr::fn_addr_eq(self.destructor, T::DESTRUCTOR) {
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

    /// The trailing bytes after a `T` payload (`ErtsResource.data`), if the payload is a `T`.
    pub fn trailing_ptr<T: MagicPayload>(&self, trailing_align: usize) -> Option<*mut u8> {
        self.downcast_ref::<T>()?;
        // SAFETY: the block was created with trailing bytes at this offset; writes through
        // the pointer are the C owner's business, as with `ERTS_MAGIC_BIN_UNALIGNED_DATA`.
        Some(unsafe {
            std::ptr::from_ref(self)
                .cast::<u8>()
                .cast_mut()
                .add(trailing_offset::<T>(trailing_align))
        })
    }

    /// The `T` payload of a block whose count may be zero (inside its destructor, or under a
    /// protocol that keeps the memory, like a resource's monitor count).
    ///
    /// # Safety
    /// The block holds a live `T` payload (not yet dropped) for the lifetime `'a`.
    pub unsafe fn payload_of<'a, T: MagicPayload>(block: NonNull<MagicRef>) -> &'a T {
        // SAFETY: by contract the payload is live at this offset.
        unsafe {
            &*block
                .cast::<u8>()
                .as_ptr()
                .add(data_offset::<T>())
                .cast::<T>()
        }
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
    pub fn new<T: MagicPayload>(payload: T) -> Self {
        Self::with_orig_size(payload, size_of::<T>())
    }

    /// A magic binary whose `mb->orig_size` is `orig_size` bytes, for payloads that stand in
    /// for a fixed erts structure.
    pub fn with_orig_size<T: MagicPayload>(payload: T, orig_size: usize) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        Self::create(payload, orig_size, refn_for_key(id))
    }

    /// `erts_create_magic_binary_x` with the reference words returned by its scheduler
    /// (`erts_make_magic_ref_in_array`).
    pub fn with_orig_size_and_refn<T: MagicPayload>(
        payload: T,
        orig_size: usize,
        mut refn: [u32; 3],
    ) -> Self {
        refn[1] |= 1 << 17;
        Self::create(payload, orig_size, refn)
    }

    /// `erts_create_magic_binary(payload_size, ...)`: `orig_size` includes the data offset.
    pub fn with_erts_payload_size<T: MagicPayload>(payload: T, payload_size: usize) -> Self {
        Self::with_orig_size(payload, MAGIC_BIN_DATA_OFFSET + payload_size)
    }

    /// `erts_create_magic_binary` with reference numbers already assigned by its scheduler.
    pub fn with_erts_payload_size_and_refn<T: MagicPayload>(
        payload: T,
        payload_size: usize,
        refn: [u32; 3],
    ) -> Self {
        Self::with_orig_size_and_refn(payload, MAGIC_BIN_DATA_OFFSET + payload_size, refn)
    }

    // Port of erts/emulator/beam/erl_binary.h (erts_create_magic_binary_x), OTP-29.1.1: one
    // allocation, header then aligned payload; the creator holds the first count.
    fn create<T: MagicPayload>(payload: T, orig_size: usize, refn: [u32; 3]) -> Self {
        Self::create_x(payload, 0, 1, orig_size, refn)
    }

    /// `erts_create_magic_binary_x(size, ...)` for a payload followed by `trailing` zeroed bytes
    /// aligned to `trailing_align` (an `ErtsResource` head and its user data).
    pub fn with_trailing_and_refn<T: MagicPayload>(
        payload: T,
        trailing: usize,
        trailing_align: usize,
        orig_size: usize,
        mut refn: [u32; 3],
    ) -> Self {
        refn[1] |= 1 << 17;
        Self::create_x(payload, trailing, trailing_align, orig_size, refn)
    }

    fn create_x<T: MagicPayload>(
        payload: T,
        trailing: usize,
        trailing_align: usize,
        orig_size: usize,
        refn: [u32; 3],
    ) -> Self {
        let align = align_of::<MagicRef>()
            .max(align_of::<T>())
            .max(trailing_align);
        let size = trailing_offset::<T>(trailing_align) + trailing;
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
                destructor: T::DESTRUCTOR,
                refn,
                saved: AtomicBool::new(false),
                alloc_size: size,
                alloc_align: align,
            });
            raw.add(data_offset::<T>()).cast::<T>().write(payload);
            let tail = trailing_offset::<T>(trailing_align);
            raw.add(tail).write_bytes(0, size - tail);
        }
        Self(block)
    }

    /// The block, keeping this count (`Binary *` handed to a C owner).
    pub fn into_raw_block(this: Self) -> NonNull<MagicRef> {
        let block = this.0;
        std::mem::forget(this);
        block
    }

    /// Adopt a count previously given up with [`MagicBin::into_raw_block`].
    ///
    /// # Safety
    /// `block` must be a live block and the caller must own one of its counts.
    pub unsafe fn from_raw_block(block: NonNull<MagicRef>) -> Self {
        Self(block)
    }

    /// `erts_refc_inc(&bin->intern.refc, 2)` on a block that has a count elsewhere.
    ///
    /// # Safety
    /// `block` must be live with a non-zero count held by someone for the call.
    pub unsafe fn retain_raw_block(block: NonNull<MagicRef>) -> Self {
        // SAFETY: by contract the block is live.
        unsafe { block.as_ref() }
            .refc
            .fetch_add(1, Ordering::Relaxed);
        Self(block)
    }

    /// The block whose payload is `payload` (`ERTS_MAGIC_BIN_FROM_DATA`).
    ///
    /// # Safety
    /// `payload` must be the payload of a magic binary block, not a value outside one.
    pub unsafe fn block_of_payload<T: MagicPayload>(payload: &T) -> NonNull<MagicRef> {
        // SAFETY: by contract the payload lies `data_offset::<T>()` bytes into a block.
        let raw = unsafe {
            std::ptr::from_ref(payload)
                .cast::<u8>()
                .sub(data_offset::<T>())
        };
        NonNull::new(raw.cast_mut().cast::<MagicRef>()).expect("magic payload")
    }

    /// `enif_make_resource` from the resource data itself: a new count on the binary whose
    /// payload is `payload`.
    ///
    /// # Safety
    /// `payload` must be the payload of a live magic binary with a count held for the call
    /// (borrowed from a [`MagicBin`] or a reference term), never inside its destructor.
    pub unsafe fn from_payload<T: MagicPayload>(payload: &T) -> Self {
        // SAFETY: forwarded caller contract.
        unsafe { Self::retain_raw_block(Self::block_of_payload(payload)) }
    }

    /// `erts_refc_inc_unless(&bin->intern.refc, 0, 0)`: a new count unless the binary is dead.
    ///
    /// # Safety
    /// The block memory must stay valid for the call (its owner frees it only after the
    /// caller's protocol allows, e.g. a resource's monitor count).
    pub unsafe fn retain_unless_dead(block: NonNull<MagicRef>) -> Option<Self> {
        // SAFETY: forwarded caller contract.
        unsafe { retain_unless_dead(block) }
    }

    /// `ERTS_MAGIC_BIN_FROM_UNALIGNED_DATA`: the block whose trailing bytes start at `data`.
    ///
    /// # Safety
    /// `data` must be the trailing data of a live block created by
    /// [`MagicBin::with_trailing_and_refn`] with payload `T` and this alignment.
    pub unsafe fn block_from_trailing<T: MagicPayload>(
        data: *mut u8,
        trailing_align: usize,
    ) -> NonNull<MagicRef> {
        // SAFETY: by contract `data` lies `trailing_offset` bytes into the block.
        let raw = unsafe { data.sub(trailing_offset::<T>(trailing_align)) };
        NonNull::new(raw.cast::<MagicRef>()).expect("magic binary data")
    }

    /// `erts_bin_free`: run the destructor of a block whose count reached zero and free it
    /// unless the destructor took control of the deallocation.
    ///
    /// # Safety
    /// `block`'s count is zero, and the caller is the one entitled to free it (the destructor
    /// handed the deallocation to it).
    pub unsafe fn bin_free(block: NonNull<MagicRef>) {
        // SAFETY: by contract nobody else uses the payload.
        let header = unsafe { block.as_ref() };
        // SAFETY: the destructor matches the payload written at creation.
        if unsafe { (header.destructor)(block) } {
            // SAFETY: the destructor returned 1: the block is ours to free.
            unsafe { Self::magic_binary_free(block) };
        }
    }

    /// `erts_magic_binary_free`: remove the block from the magic ref table and free it. The
    /// payload must already have been dropped by the destructor.
    ///
    /// # Safety
    /// The count is zero, the payload is dropped, and no other code frees this block.
    pub unsafe fn magic_binary_free(block: NonNull<MagicRef>) {
        // SAFETY: by contract the header memory is still allocated.
        let header = unsafe { block.as_ref() };
        if header.saved.load(Ordering::Acquire) {
            magic_ref_remove_bin(header.id());
        }
        release_weak(block);
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
        // SAFETY: refc reached zero in `drop`, so this release is the one that frees.
        unsafe { Self::bin_free(block) }
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
