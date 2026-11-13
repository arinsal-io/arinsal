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
/// `true` (erts 1) lets [`MagicBin`] free the block now; `false` (erts 0) means another owner
/// will call `erts_bin_free` after the payload's deferred lifetime ends.
pub type MagicDestructor = fn(&mut MagicRef) -> bool;

/// A type that can be the data of a magic binary.
///
/// # Safety
/// `DESTRUCTOR` must be a function that no other type uses (it identifies the payload type in
/// [`MagicRef::downcast_ref`]), that finalizes and drops the payload exactly once before the
/// block is freed, and that returns `false` only when another owner will finish deallocation.
/// The unique named destructor is the invariant that permits safe typed payload access.
/// If [`MagicPayload::external_data_bytes`] returns `Some`, those bytes must remain
/// readable and immutable or synchronized until the payload is dropped.
/// [`crate::magic_payload!`] defines a distinct non-inlined destructor per type.
pub unsafe trait MagicPayload: Send + Sync + Sized + 'static {
    /// `ERTS_MAGIC_BIN_DESTRUCTOR` of binaries holding a `Self`.
    const DESTRUCTOR: MagicDestructor;

    /// Bytes whose storage is kept alive by this payload, if it owns external bytes.
    ///
    /// Implementations returning `Some` must keep the complete slice readable and immutable or
    /// synchronized while this payload remains live.
    fn external_data_bytes<'a>(&'a self, _block: &'a MagicRef) -> Option<&'a [u8]> {
        None
    }
}

/// Declare the magic binary destructor of a payload type, like the named destructor erts
/// passes to `erts_create_magic_binary` (`db_table_tid_destructor`, `cleanup_match_pseudo_process`, ...).
///
/// The generated destructor is `#[inline(never)]` so that every crate refers to one symbol,
/// and it touches a static of its own so that identical-function merging cannot fold two
/// payload types into one address.
#[macro_export]
macro_rules! magic_payload {
    ($ty:ty => $name:ident, finalize = $finalize:path, data = $bytes:path) => {
        // SAFETY: the destructor below is defined once for this type and only finalizes it;
        // the byte view is borrowed from storage kept valid by this payload.
        unsafe impl $crate::MagicPayload for $ty {
            const DESTRUCTOR: $crate::MagicDestructor = {
                #[inline(never)]
                fn $name(mb: &mut $crate::MagicRef) -> bool {
                    static MARKER: ::std::sync::atomic::AtomicU8 =
                        ::std::sync::atomic::AtomicU8::new(0);
                    ::std::hint::black_box(&MARKER);
                    mb.finalize_payload::<$ty>($finalize)
                }
                $name
            };

            fn external_data_bytes<'a>(
                &'a self,
                block: &'a $crate::MagicRef,
            ) -> Option<&'a [u8]> {
                $bytes(self, block)
            }
        }
    };
    ($ty:ty => $name:ident, data = $bytes:path) => {
        // SAFETY: the destructor below is defined once for this type and only drops it; the
        // byte view is borrowed from storage kept valid by this payload.
        unsafe impl $crate::MagicPayload for $ty {
            const DESTRUCTOR: $crate::MagicDestructor = {
                #[inline(never)]
                fn $name(mb: &mut $crate::MagicRef) -> bool {
                    static MARKER: ::std::sync::atomic::AtomicU8 =
                        ::std::sync::atomic::AtomicU8::new(0);
                    ::std::hint::black_box(&MARKER);
                    mb.finalize_payload::<$ty>(|_, _| true)
                }
                $name
            };

            fn external_data_bytes<'a>(
                &'a self,
                block: &'a $crate::MagicRef,
            ) -> Option<&'a [u8]> {
                $bytes(self, block)
            }
        }
    };
    ($($ty:ty => $name:ident),+ $(,)?) => {$(
        // SAFETY: the destructor below is defined once for this type and only drops it.
        unsafe impl $crate::MagicPayload for $ty {
            const DESTRUCTOR: $crate::MagicDestructor = {
                #[inline(never)]
                fn $name(mb: &mut $crate::MagicRef) -> bool {
                    static MARKER: ::std::sync::atomic::AtomicU8 =
                        ::std::sync::atomic::AtomicU8::new(0);
                    ::std::hint::black_box(&MARKER);
                    mb.finalize_payload::<$ty>(|_, _| true)
                }
                $name
            };
        }
    )+};
    ($ty:ty => $name:ident, $finalize:path) => {
        // SAFETY: the destructor below is defined once for this type and only finalizes it;
        unsafe impl $crate::MagicPayload for $ty {
            const DESTRUCTOR: $crate::MagicDestructor = {
                #[inline(never)]
                fn $name(mb: &mut $crate::MagicRef) -> bool {
                    static MARKER: ::std::sync::atomic::AtomicU8 =
                        ::std::sync::atomic::AtomicU8::new(0);
                    ::std::hint::black_box(&MARKER);
                    mb.finalize_payload::<$ty>($finalize)
                }
                $name
            };
        }
    };
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

    /// Mutably accesses this block's `T` payload while its destructor is running.
    #[inline]
    pub fn downcast_mut<T: MagicPayload>(&mut self) -> Option<&mut T> {
        if !std::ptr::fn_addr_eq(self.destructor, T::DESTRUCTOR) {
            return None;
        }
        // SAFETY: only the final destructor receives exclusive access to a live block.
        Some(unsafe {
            &mut *std::ptr::from_mut(self)
                .cast::<u8>()
                .add(data_offset::<T>())
                .cast::<T>()
        })
    }

    /// Runs a payload-specific finalizer and drops the payload when it is ready.
    #[doc(hidden)]
    pub fn finalize_payload<T: MagicPayload>(
        &mut self,
        finalize: impl FnOnce(&MagicRef, &mut T) -> bool,
    ) -> bool {
        if !std::ptr::fn_addr_eq(self.destructor, T::DESTRUCTOR) {
            return false;
        }
        let header = std::ptr::from_mut(self);
        // SAFETY: the named destructor matched above, the header and payload occupy disjoint
        // parts of the allocation, and `&mut self` excludes all other accesses.
        unsafe {
            let (header, payload) = (
                &*header,
                &mut *header.cast::<u8>().add(data_offset::<T>()).cast::<T>(),
            );
            if !finalize(header, payload) {
                return false;
            }
            // `finalize` returned true to authorize the single payload drop.
            std::ptr::drop_in_place(payload);
        }
        true
    }

    /// The trailing bytes after a `T` payload (`ErtsResource.data`), if the payload is a `T`.
    pub fn trailing_ptr<T: MagicPayload>(&self, trailing_align: usize) -> Option<*mut u8> {
        if !std::ptr::fn_addr_eq(self.destructor, T::DESTRUCTOR)
            || !trailing_align.is_power_of_two()
            || trailing_align > self.alloc_align
        {
            return None;
        }
        let offset = trailing_offset::<T>(trailing_align);
        if offset > self.alloc_size {
            return None;
        }
        // SAFETY: the block was created with trailing bytes at this offset; writes through
        // the pointer are the C owner's business, as with `ERTS_MAGIC_BIN_UNALIGNED_DATA`.
        Some(unsafe { std::ptr::from_ref(self).cast::<u8>().cast_mut().add(offset) })
    }

    /// Current `intern.refc`, for `erts_debug` introspection.
    pub fn refc(&self) -> usize {
        self.refc.load(Ordering::Relaxed)
    }
}

/// A counted reference to a magic binary: `Binary *` with one `intern.refc` held.
pub struct MagicBin(usize);

static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl MagicBin {
    fn block(&self) -> NonNull<MagicRef> {
        NonNull::new(self.0 as *mut MagicRef).expect("magic binary block")
    }

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

    /// The pointer for a byte span inside the payload's retained data, preserving its provenance.
    pub(crate) fn validated_data_pointer<T: MagicPayload>(
        &self,
        data: *const u8,
        len: usize,
    ) -> Option<*const u8> {
        if len == 0 {
            return self
                .downcast_ref::<T>()
                .map(|_| std::ptr::NonNull::<u8>::dangling().as_ptr().cast_const());
        }
        if data.is_null() {
            return None;
        }
        let payload = self.downcast_ref::<T>()?;
        let bytes = payload.external_data_bytes(self)?;
        let end = (data as usize).checked_add(len)?;
        let start = bytes.as_ptr() as usize;
        let bytes_end = start.checked_add(bytes.len())?;
        let address = data as usize;
        if address < start || end > bytes_end {
            return None;
        }
        Some(bytes.as_ptr().wrapping_add(address - start))
    }

    /// Retain bytes managed by a resource binary's destructor.
    ///
    /// # Safety
    /// For non-empty spans, `data..data + len` must stay readable and unchanged until this
    /// resource payload is dropped. This is the `enif_make_resource_binary` contract.
    // Port of erts/emulator/beam/erl_nif.c:3206 (`enif_make_resource_binary`), OTP-29.1.1.
    pub unsafe fn external_data<T: MagicPayload>(
        self,
        data: *const u8,
        len: usize,
    ) -> Option<MagicBinaryData<T>> {
        self.downcast_ref::<T>()?;
        let data = if len == 0 {
            std::ptr::NonNull::<u8>::dangling().as_ptr()
        } else {
            if data.is_null() || (data as usize).checked_add(len).is_none() {
                return None;
            }
            data.cast_mut()
        };
        Some(MagicBinaryData {
            data: data as usize,
            len,
            owner: self,
            _payload: std::marker::PhantomData,
        })
    }

    fn create_x<T: MagicPayload>(
        payload: T,
        trailing: usize,
        trailing_align: usize,
        orig_size: usize,
        refn: [u32; 3],
    ) -> Self {
        assert!(
            trailing_align.is_power_of_two() && trailing_align <= isize::MAX as usize,
            "magic binary trailing alignment"
        );
        let align = align_of::<MagicRef>()
            .max(align_of::<T>())
            .max(trailing_align);
        let size = trailing_offset::<T>(trailing_align)
            .checked_add(trailing)
            .expect("magic binary layout");
        let layout = Layout::from_size_align(size, align).expect("magic binary layout");
        // SAFETY: `layout` has non-zero size, and the returned allocation is large and aligned
        // enough for the header, the `T` payload, and trailing bytes.
        let block = unsafe {
            let raw = alloc(layout);
            let Some(block) = NonNull::new(raw.cast::<MagicRef>()) else {
                handle_alloc_error(layout)
            };
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
            block
        };
        Self(block.as_ptr() as usize)
    }

    /// Adopts the count owned by the NIF C pointer at `data`.
    ///
    /// # Safety
    /// `data` must be the trailing data of a live `T` magic block, and its C owner must hold
    /// one reference count for the duration of this call.
    // Port of erts/emulator/beam/erl_binary.h (ERTS_MAGIC_BIN_FROM_UNALIGNED_DATA), OTP-29.1.1.
    pub unsafe fn from_trailing_data<T: MagicPayload>(
        data: *mut u8,
        trailing_align: usize,
    ) -> Option<Self> {
        // SAFETY: the caller's live trailing-data pointer identifies this allocation, and its
        // count keeps the recovered header allocated for the destructor identity check.
        unsafe {
            let raw = data.sub(trailing_offset::<T>(trailing_align));
            let block = NonNull::new(raw.cast::<MagicRef>()).expect("magic binary data");
            std::ptr::fn_addr_eq(block.as_ref().destructor, T::DESTRUCTOR)
                .then_some(Self(block.as_ptr() as usize))
        }
    }

    /// Gives a monitor token access to a payload whose owner has already acquired the
    /// corresponding external monitor count.
    ///
    /// # Safety
    /// The caller must hold one resource-monitor count for this exact block until the returned
    /// token is dropped.
    // Port of erts/emulator/beam/erl_nif.c (enif_monitor_process), OTP-29.1.1.
    pub unsafe fn monitor_ref<T: MagicPayload>(&self) -> Option<MagicMonitor> {
        self.downcast_ref::<T>()?;
        self.weak.fetch_add(1, Ordering::Relaxed);
        Some(MagicMonitor(self.0))
    }

    /// Transfers this count to the NIF C owner and returns its trailing data pointer.
    ///
    /// # Safety
    /// The returned pointer must only be used according to the `enif_*_resource` contract.
    // Port of erts/emulator/beam/erl_nif.c (enif_alloc_resource, enif_keep_resource), OTP-29.1.1.
    pub unsafe fn into_trailing_data<T: MagicPayload>(
        this: Self,
        trailing_align: usize,
    ) -> Option<*mut u8> {
        this.downcast_ref::<T>()?;
        let data = this.trailing_ptr::<T>(trailing_align)?;
        std::mem::forget(this);
        Some(data)
    }

    /// `erts_bin_free`: run the destructor of a block whose count reached zero and free it
    /// unless the destructor returned zero to defer deallocation.
    ///
    /// # Safety
    /// `block`'s count is zero, and the caller is the one entitled to free it (the destructor
    /// handed the deallocation to it).
    unsafe fn bin_free(block: NonNull<MagicRef>) {
        // SAFETY: the matching destructor is stored in the live block; `refc` reached zero, so
        // no counted reference can access the payload. A true result transfers the zero-count
        // block to `magic_binary_free` after the payload has been dropped.
        unsafe {
            let destructor = block.as_ref().destructor;
            if destructor(&mut *block.as_ptr()) {
                Self::magic_binary_free(block);
            }
        }
    }

    /// `erts_magic_binary_free`: remove the block from the magic ref table and free it. The
    /// payload must already have been dropped by the destructor.
    ///
    /// # Safety
    /// The count is zero, the payload is dropped, and no other code frees this block.
    unsafe fn magic_binary_free(block: NonNull<MagicRef>) {
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
        this.0 as *const MagicRef
    }

    /// Give up this count to a raw pointer word (an `ErtsMRefThing` taking over the count).
    pub(crate) fn into_raw(this: Self) -> *const MagicRef {
        let ptr = this.0 as *const MagicRef;
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
        Self(block.as_ptr() as usize)
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

/// An owner-carrying byte span whose lifetime is guaranteed by a magic payload destructor.
///
/// Values can only be created by [`MagicBin::external_data`] after its caller upholds that
/// method's resource binary contract.
pub struct MagicBinaryData<T: MagicPayload> {
    data: usize,
    len: usize,
    owner: MagicBin,
    _payload: std::marker::PhantomData<T>,
}

impl<T: MagicPayload> MagicBinaryData<T> {
    pub(crate) fn into_parts(self) -> (usize, usize, MagicBin) {
        (self.data, self.len, self.owner)
    }
}

impl std::ops::Deref for MagicBin {
    type Target = MagicRef;
    #[inline]
    fn deref(&self) -> &MagicRef {
        // SAFETY: a counted reference keeps the block and its payload live.
        unsafe { self.block().as_ref() }
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
        Self::free(self.block());
    }
}

impl std::fmt::Debug for MagicBin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MagicBin({})", self.id())
    }
}

/// Release one weak count; the last one frees the block.
fn release_weak(block: NonNull<MagicRef>) {
    // SAFETY: the caller holds a weak count, so the header is live until the decrement; the
    // final weak release owns the allocation and its recorded layout.
    unsafe {
        let header = block.as_ref();
        if header.weak.fetch_sub(1, Ordering::Release) != 1 {
            return;
        }
        fence(Ordering::Acquire);
        let layout = Layout::from_size_align(header.alloc_size, header.alloc_align)
            .expect("magic binary layout");
        dealloc(block.cast::<u8>().as_ptr(), layout);
    }
}

/// A non-owning resource monitor handle. Its external monitor count, rather than `refc`, keeps
/// the payload live; this weak count keeps the block header allocated.
pub struct MagicMonitor(usize);

impl MagicMonitor {
    fn block(&self) -> NonNull<MagicRef> {
        NonNull::new(self.0 as *mut MagicRef).expect("magic monitor block")
    }
}

impl MagicMonitor {
    /// The resource payload protected by this monitor count, if it has the requested type.
    pub fn downcast_ref<T: MagicPayload>(&self) -> Option<&T> {
        // SAFETY: the constructor contract keeps the payload live; this weak count keeps the
        // header allocation live for the token's lifetime.
        // SAFETY: this token's external monitor count keeps the block allocated.
        unsafe { self.block().as_ref() }.downcast_ref::<T>()
    }

    /// `erts_refc_inc_unless(&bin->intern.refc, 0, 0)` while a monitor count keeps the header.
    pub fn retain_unless_dead(&self) -> Option<MagicBin> {
        // SAFETY: this token keeps the header allocated until after the atomic count attempt.
        unsafe { retain_unless_dead(self.block()) }
    }

    /// The address of the magic binary block held by this monitor token.
    #[doc(hidden)]
    pub fn block_address(&self) -> usize {
        self.0
    }

    /// Runs `erts_bin_free` after the final external monitor count is released.
    ///
    /// # Safety
    /// The magic binary count is zero, and the caller has released the last monitor count for
    /// this block after its destructor entered the deferred state.
    // Port of erts/emulator/beam/erl_binary.h (erts_bin_free), OTP-29.1.1.
    pub unsafe fn finish_dead(&self) {
        // SAFETY: forwarded caller contract.
        unsafe { MagicBin::bin_free(self.block()) };
    }
}

impl Drop for MagicMonitor {
    fn drop(&mut self) {
        release_weak(self.block());
    }
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
            Ok(_) => return Some(MagicBin(block.as_ptr() as usize)),
            Err(seen) => current = seen,
        }
    }
}

/// A reference to a magic binary that does not keep its payload alive.
pub struct MagicWeak(Option<usize>);

impl MagicWeak {
    /// A weak reference to no binary.
    pub const fn new() -> Self {
        Self(None)
    }

    /// A counted reference, unless the binary's payload is gone.
    pub fn upgrade(&self) -> Option<MagicBin> {
        // SAFETY: the weak count keeps the header memory valid.
        self.0.and_then(|address| {
            let block = NonNull::new(address as *mut MagicRef).expect("magic weak block");
            // SAFETY: the weak count keeps the header memory valid.
            unsafe { retain_unless_dead(block) }
        })
    }
}

impl Default for MagicWeak {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for MagicWeak {
    fn clone(&self) -> Self {
        if let Some(address) = self.0 {
            let block = NonNull::new(address as *mut MagicRef).expect("magic weak block");
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
            release_weak(NonNull::new(block as *mut MagicRef).expect("magic weak block"));
        }
    }
}

/// Borrow the magic binary of a live magic reference thing's pointer word.
pub(crate) fn thing_block<'a>(word: u64) -> &'a MagicRef {
    // SAFETY: callers pass the pointer word of a live magic reference thing, which holds a
    // count for the duration of the borrow.
    unsafe { &*(word as *const MagicRef) }
}

// Port of erts/emulator/beam/erl_bif_unique.c (magic_ref_table), OTP-29.1.1: reference
// numbers to the magic binary, sharded like erts' per-scheduler tables. Creating a magic
// reference never touches it. It is filled only when the numbers leave the term
// (`term_to_binary`, `ref_to_list`), so that decoding or `list_to_ref` on this node finds the
// binary again, and the entry goes away when the binary is freed.
const TABLE_SHARDS: usize = 64;

struct Entry(usize);

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
        shard.get(&id).and_then(|entry| {
            let block = NonNull::new(entry.0 as *mut MagicRef).expect("magic table block");
            // SAFETY: an entry is removed under the write lock before its block is freed.
            unsafe { retain_unless_dead(block) }
        })
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
