//! `Binary*` handles for I/O vectors and queues.
//!
//! erts keeps a `Binary*` per I/O vector entry and counts references on it. A handle here is
//! a boxed [`NifBinary`]: the owner of an off-heap Erlang binary, or a `malloc` block (a binary
//! from `enif_alloc_binary` or a copy). Cloning a handle raises the reference count and
//! freeing it lowers it; the bytes live until the last handle is freed.
use arinsal_term::BinaryOwner;
use std::ffi::c_void;
use std::sync::Arc;

unsafe extern "C" {
    fn free(p: *mut c_void);
}

/// A `malloc`ed block released with `free` when its last handle goes away.
pub(crate) struct MallocBlock(pub(crate) *mut u8);
// SAFETY: the block is plain memory; whoever holds a handle may read it, and writers
// synchronize themselves, as for any NIF binary.
unsafe impl Send for MallocBlock {}
// SAFETY: see above.
unsafe impl Sync for MallocBlock {}
impl Drop for MallocBlock {
    fn drop(&mut self) {
        // SAFETY: the block came from malloc and this is the last reference.
        unsafe { free(self.0.cast()) }
    }
}

/// What a `Binary*` refers to. The payloads are held only to keep the bytes alive.
#[derive(Clone)]
#[allow(dead_code)]
pub(crate) enum NifBinary {
    /// The owner of an off-heap Erlang binary.
    Owner(BinaryOwner),
    /// A `malloc` block.
    Block(Arc<MallocBlock>),
}

/// A new handle (reference count 1).
pub(crate) fn handle_new(binary: NifBinary) -> *mut c_void {
    Box::into_raw(Box::new(binary)).cast()
}

/// Another handle on the same binary (`erts_refc_inc`).
pub(crate) fn handle_clone(handle: *mut c_void) -> *mut c_void {
    // SAFETY: `handle` came from `handle_new` or `handle_clone` and was not freed.
    handle_new(unsafe { &*handle.cast::<NifBinary>() }.clone())
}

/// Drop a handle (`erts_refc_dectest` and `erts_bin_free` on zero).
pub(crate) fn handle_free(handle: *mut c_void) {
    if !handle.is_null() {
        // SAFETY: `handle` came from `handle_new` or `handle_clone` and is freed once.
        drop(unsafe { Box::from_raw(handle.cast::<NifBinary>()) });
    }
}

/// A new `malloc` block of `len` bytes as a fresh handle, with the address of its bytes.
pub(crate) fn alloc_block(len: usize) -> Option<(*mut c_void, *mut u8)> {
    unsafe extern "C" {
        fn malloc(n: usize) -> *mut c_void;
    }
    // SAFETY: malloc returns a block of the requested size or NULL.
    let block = unsafe { malloc(len.max(1)) }.cast::<u8>();
    if block.is_null() {
        return None;
    }
    Some((
        handle_new(NifBinary::Block(Arc::new(MallocBlock(block)))),
        block,
    ))
}

/// A copy of `len` bytes at `bytes` as a fresh handle, with the address of the copy.
pub(crate) fn copy_to_block(bytes: *const u8, len: usize) -> Option<(*mut c_void, *mut u8)> {
    let (handle, block) = alloc_block(len)?;
    // SAFETY: the new block holds `len` bytes and `bytes` is readable for `len` bytes.
    unsafe { std::ptr::copy_nonoverlapping(bytes, block, len) };
    Some((handle, block))
}

/// The handle of a binary from `enif_alloc_binary` (a `malloc` block): ownership of the block
/// moves to the handle.
pub(crate) fn adopt_block(data: *mut u8) -> *mut c_void {
    handle_new(NifBinary::Block(Arc::new(MallocBlock(data))))
}
