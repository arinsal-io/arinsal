//! Executable memory: MAP_JIT, W^X toggling and instruction-cache flush.
//!
//! Port of OTP 29.1.1 `erts/emulator/beam/jit/beam_jit_main.cpp` allocator setup,
//! macOS single-mapping path (task 3 of `docs/arch/beamasm-port.md`).

use core::fmt;

unsafe extern "C" {
    #[cfg(target_os = "macos")]
    fn sys_icache_invalidate(start: *mut libc::c_void, len: libc::size_t);
    #[cfg(not(target_os = "macos"))]
    fn __clear_cache(start: *mut libc::c_void, end: *mut libc::c_void);
}

/// Alignment in bytes for each allocated code block (AArch64 16-byte alignment).
pub const CODE_ALIGNMENT: usize = 16;

/// Default capacity for executable code memory (32 MB).
// Port of erts/emulator/beam/jit/beam_jit_main.cpp:216, OTP-29.1.1
pub const DEFAULT_CAPACITY: usize = 32 * 1024 * 1024;

/// Errors that can occur during executable memory operations.
#[derive(Debug)]
pub enum ExecError {
    /// Memory allocation via `mmap` failed.
    MmapFailed(std::io::Error),
    /// Memory protection change via `mprotect` failed.
    MprotectFailed(std::io::Error),
    /// An invalid size was requested (e.g. 0 or overflow).
    InvalidSize(&'static str),
    /// The requested allocation exceeds remaining capacity.
    OutOfMemory { requested: usize, available: usize },
    /// The requested offset and length exceed memory capacity.
    OutOfBounds {
        offset: usize,
        len: usize,
        capacity: usize,
    },
    /// The requested block was not found in registered allocations.
    BlockNotFound(usize),
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MmapFailed(err) => write!(f, "mmap failed: {err}"),
            Self::MprotectFailed(err) => write!(f, "mprotect failed: {err}"),
            Self::InvalidSize(msg) => write!(f, "invalid size: {msg}"),
            Self::OutOfMemory {
                requested,
                available,
            } => {
                write!(
                    f,
                    "out of code memory: requested {requested} bytes, available {available} bytes"
                )
            }
            Self::OutOfBounds {
                offset,
                len,
                capacity,
            } => {
                write!(
                    f,
                    "code memory access out of bounds: range [{offset}..{}) exceeds capacity {capacity}",
                    offset + len
                )
            }
            Self::BlockNotFound(offset) => {
                write!(f, "no allocated code block found at offset {offset}")
            }
        }
    }
}

impl std::error::Error for ExecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MmapFailed(err) | Self::MprotectFailed(err) => Some(err),
            _ => None,
        }
    }
}

impl From<ExecError> for std::io::Error {
    fn from(err: ExecError) -> Self {
        match err {
            ExecError::MmapFailed(io_err) | ExecError::MprotectFailed(io_err) => io_err,
            ExecError::OutOfMemory { .. } => {
                Self::new(std::io::ErrorKind::OutOfMemory, err.to_string())
            }
            ExecError::InvalidSize(_) | ExecError::OutOfBounds { .. } => {
                Self::new(std::io::ErrorKind::InvalidInput, err.to_string())
            }
            ExecError::BlockNotFound(_) => Self::new(std::io::ErrorKind::NotFound, err.to_string()),
        }
    }
}

/// Metadata describing an allocated code block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeBlock {
    /// Byte offset of the block from the start of the code memory region.
    pub offset: usize,
    /// Size of the block in bytes.
    pub size: usize,
}

/// A region of executable virtual memory for JIT-compiled machine code.
///
/// On macOS (AArch64), memory is reserved with `PROT_READ | PROT_WRITE | PROT_EXEC`
/// and `MAP_PRIVATE | MAP_ANON | MAP_JIT`. W^X protection is toggled per thread using
/// `pthread_jit_write_protect_np`.
///
/// On Linux, memory is reserved with `PROT_READ | PROT_WRITE` and converted to
/// `PROT_READ | PROT_EXEC` via `mprotect`.
pub struct CodeMemory {
    ptr: *mut u8,
    capacity: usize,
    used: usize,
    blocks: Vec<CodeBlock>,
}

// SAFETY: The mapping is uniquely owned, and moving its owner does not change the mapping.
unsafe impl Send for CodeMemory {}

// SAFETY: Shared access only reads metadata or invokes immutable code; mutation requires `&mut self`.
unsafe impl Sync for CodeMemory {}

impl CodeMemory {
    /// Reserves a new region of executable memory with at least `capacity` bytes.
    ///
    /// The actual capacity is rounded up to the system page size.
    pub fn new(capacity: usize) -> Result<Self, ExecError> {
        if capacity == 0 {
            return Err(ExecError::InvalidSize("capacity must be non-zero"));
        }

        let page_size = get_page_size();
        let mapped_size = (capacity + (page_size - 1)) & !(page_size - 1);

        #[cfg(target_os = "macos")]
        // SAFETY: mmap is called with a valid anonymous MAP_JIT configuration and checked result.
        let ptr = unsafe {
            // Port of erts/emulator/beam/jit/beam_jit_main.cpp:188-196, OTP-29.1.1
            let prot = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
            let flags = libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_JIT;
            // SAFETY: mmap is called with valid flags, MAP_ANON (-1 fd, 0 offset).
            let p = libc::mmap(core::ptr::null_mut(), mapped_size, prot, flags, -1, 0);
            if p == libc::MAP_FAILED {
                return Err(ExecError::MmapFailed(std::io::Error::last_os_error()));
            }
            p.cast::<u8>()
        };

        #[cfg(not(target_os = "macos"))]
        // SAFETY: anonymous private mapping, checked results, cleaned up on failure below.
        let ptr = unsafe {
            // Port of erts/emulator/beam/jit/beam_jit_main.cpp:206-235, OTP-29.1.1
            let prot = libc::PROT_READ | libc::PROT_WRITE;
            let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
            // SAFETY: mmap allocates anonymous private memory of size mapped_size.
            let p = libc::mmap(core::ptr::null_mut(), mapped_size, prot, flags, -1, 0);
            if p == libc::MAP_FAILED {
                return Err(ExecError::MmapFailed(std::io::Error::last_os_error()));
            }
            // SAFETY: p is validly mapped with mapped_size.
            let mprotect_res = libc::mprotect(p, mapped_size, libc::PROT_READ | libc::PROT_EXEC);
            if mprotect_res != 0 {
                let err = std::io::Error::last_os_error();
                // SAFETY: Clean up mapping on initialization failure.
                libc::munmap(p, mapped_size);
                return Err(ExecError::MprotectFailed(err));
            }
            p.cast::<u8>()
        };

        Ok(Self {
            ptr,
            capacity: mapped_size,
            used: 0,
            blocks: Vec::new(),
        })
    }

    /// Bump-allocates a code block with 16-byte alignment, returning its byte offset.
    pub fn alloc(&mut self, size: usize) -> Result<usize, ExecError> {
        let block = self.allocate(size)?;
        Ok(block.offset)
    }

    /// Bump-allocates a code block with 16-byte alignment, returning a `CodeBlock`.
    pub fn allocate(&mut self, size: usize) -> Result<CodeBlock, ExecError> {
        if size == 0 {
            return Err(ExecError::InvalidSize("block size must be non-zero"));
        }

        let aligned_offset = (self.used + (CODE_ALIGNMENT - 1)) & !(CODE_ALIGNMENT - 1);
        let new_used = aligned_offset
            .checked_add(size)
            .ok_or(ExecError::InvalidSize("block size overflow"))?;

        if new_used > self.capacity {
            return Err(ExecError::OutOfMemory {
                requested: size,
                available: self.capacity.saturating_sub(aligned_offset),
            });
        }

        self.used = new_used;
        let block = CodeBlock {
            offset: aligned_offset,
            size,
        };
        self.blocks.push(block);
        Ok(block)
    }

    /// Modifies code memory in the range `[offset, offset + len)` using closure `f`.
    ///
    /// On macOS, this toggles per-thread JIT write permissions via `pthread_jit_write_protect_np(0)`
    /// and `(1)`. On Linux, this toggles memory protection via `mprotect(PROT_READ | PROT_WRITE)`
    /// and `(PROT_READ | PROT_EXEC)`. Once written, the instruction cache for the range is flushed.
    pub fn write<R>(
        &mut self,
        offset: usize,
        len: usize,
        f: impl FnOnce(&mut [u8]) -> R,
    ) -> Result<R, ExecError> {
        let end = offset
            .checked_add(len)
            .ok_or(ExecError::InvalidSize("write range overflow"))?;

        if end > self.capacity {
            return Err(ExecError::OutOfBounds {
                offset,
                len,
                capacity: self.capacity,
            });
        }

        if len == 0 {
            return Ok(f(&mut []));
        }

        #[cfg(target_os = "macos")]
        let guard = JitWriteGuard::enter();

        #[cfg(not(target_os = "macos"))]
        let guard = JitWriteGuard::enter(self.ptr, offset, len)?;

        // SAFETY: offset and len are strictly within self.capacity and permissions are RW.
        let slice = unsafe { core::slice::from_raw_parts_mut(self.ptr.add(offset), len) };
        let result = f(slice);

        // Ensure permissions are restored to RX before icache flush.
        drop(guard);

        self.flush(offset, len)?;
        Ok(result)
    }

    /// Modifies the registered block starting at `offset` using closure `f`.
    pub fn write_block<R>(
        &mut self,
        offset: usize,
        f: impl FnOnce(&mut [u8]) -> R,
    ) -> Result<R, ExecError> {
        let size = self
            .block_size(offset)
            .ok_or(ExecError::BlockNotFound(offset))?;
        self.write(offset, size, f)
    }

    /// Copies `bytes` into code memory at `offset` and invalidates the instruction cache.
    pub fn write_bytes(&mut self, offset: usize, bytes: &[u8]) -> Result<(), ExecError> {
        self.write(offset, bytes.len(), |dest| {
            dest.copy_from_slice(bytes);
        })
    }

    /// Flushes the instruction cache for the range `[offset, offset + len)`.
    pub fn flush(&self, offset: usize, len: usize) -> Result<(), ExecError> {
        let end = offset
            .checked_add(len)
            .ok_or(ExecError::InvalidSize("flush range overflow"))?;

        if end > self.capacity {
            return Err(ExecError::OutOfBounds {
                offset,
                len,
                capacity: self.capacity,
            });
        }

        if len == 0 {
            return Ok(());
        }

        // SAFETY: self.ptr.add(offset) with length len is within mapped bounds.
        flush_icache(self.ptr.wrapping_add(offset), len);
        Ok(())
    }

    /// Flushes the instruction cache for all used code memory.
    pub fn flush_all(&self) -> Result<(), ExecError> {
        self.flush(0, self.used)
    }

    /// Returns a typed entry handle to an allocated code block.
    ///
    /// The handle borrows this mapping, keeping its code alive while it is used.
    pub fn entry<F>(&self, offset: usize) -> Entry<'_, F> {
        assert!(
            self.block_size(offset).is_some(),
            "entry must start at an allocated block"
        );
        assert!(
            offset < self.capacity,
            "entry offset {offset} exceeds capacity {}",
            self.capacity
        );
        assert_eq!(
            offset % 4,
            0,
            "instruction entry at offset {offset} must be at least 4-byte aligned"
        );
        assert_eq!(
            core::mem::size_of::<F>(),
            core::mem::size_of::<*const ()>(),
            "type F must be pointer-sized"
        );

        Entry {
            memory: self,
            offset,
            _signature: core::marker::PhantomData,
        }
    }

    /// Returns the total capacity of the mapped memory region in bytes.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the number of bytes bump-allocated so far.
    #[must_use]
    pub fn used(&self) -> usize {
        self.used
    }

    /// Returns the remaining available capacity before out-of-memory.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.capacity.saturating_sub(self.used)
    }

    /// Returns all registered allocated blocks.
    #[must_use]
    pub fn blocks(&self) -> &[CodeBlock] {
        &self.blocks
    }

    /// Returns the size of the block allocated at `offset`, if registered.
    #[must_use]
    pub fn block_size(&self, offset: usize) -> Option<usize> {
        self.blocks
            .iter()
            .find(|b| b.offset == offset)
            .map(|b| b.size)
    }

    /// Returns a raw pointer to the base of the code memory region.
    #[must_use]
    pub fn as_ptr(&self) -> *const u8 {
        self.ptr
    }

    /// Returns a raw pointer to code memory at `offset`.
    ///
    /// # Panics
    /// Panics if `offset >= self.capacity`.
    #[must_use]
    pub fn ptr_at(&self, offset: usize) -> *const u8 {
        assert!(
            offset < self.capacity,
            "offset {offset} exceeds capacity {}",
            self.capacity
        );
        // SAFETY: offset is within capacity.
        self.ptr.wrapping_add(offset)
    }
}

/// A typed, mapping-borrowing handle for generated native code.
pub struct Entry<'a, F> {
    memory: &'a CodeMemory,
    offset: usize,
    _signature: core::marker::PhantomData<F>,
}

impl<F: Copy> Entry<'_, F> {
    /// Materializes the native function pointer for immediate use.
    ///
    /// The caller must select the ABI represented by `F` to match the emitted code.
    pub fn get(&self) -> F {
        // SAFETY: The entry is within an allocated mapped block; lifetime remains tied to memory.
        unsafe {
            let ptr = self.memory.ptr.add(self.offset);
            core::mem::transmute_copy(&ptr)
        }
    }
}

impl Drop for CodeMemory {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: self.ptr was returned by mmap with capacity self.capacity and has not been unmapped.
            unsafe {
                libc::munmap(self.ptr.cast(), self.capacity);
            }
        }
    }
}

/// RAII guard toggling per-thread JIT write permissions on macOS.
#[cfg(target_os = "macos")]
struct JitWriteGuard;

#[cfg(target_os = "macos")]
impl JitWriteGuard {
    // Port of erts/emulator/beam/jit/beam_jit_common.cpp:128, OTP-29.1.1
    fn enter() -> Self {
        // SAFETY: Toggles current thread MAP_JIT access to Read+Write (0).
        unsafe {
            libc::pthread_jit_write_protect_np(0);
        }
        Self
    }
}

#[cfg(target_os = "macos")]
impl Drop for JitWriteGuard {
    // Port of erts/emulator/beam/jit/beam_jit_main.cpp:447, OTP-29.1.1
    fn drop(&mut self) {
        // SAFETY: Restores current thread MAP_JIT access to Read+Execute (1).
        unsafe {
            libc::pthread_jit_write_protect_np(1);
        }
    }
}

/// RAII guard toggling memory protection for written pages on Linux.
#[cfg(not(target_os = "macos"))]
struct JitWriteGuard {
    page_start: *mut libc::c_void,
    page_len: usize,
}

#[cfg(not(target_os = "macos"))]
impl JitWriteGuard {
    fn enter(ptr: *mut u8, offset: usize, len: usize) -> Result<Self, ExecError> {
        let page_size = get_page_size();
        let start_addr = (ptr as usize + offset) & !(page_size - 1);
        let end_addr = (ptr as usize + offset + len + page_size - 1) & !(page_size - 1);
        let page_len = end_addr - start_addr;
        let page_start = start_addr as *mut libc::c_void;

        // SAFETY: mprotect marks the pages covering the write range as Read+Write.
        let res =
            unsafe { libc::mprotect(page_start, page_len, libc::PROT_READ | libc::PROT_WRITE) };
        if res != 0 {
            return Err(ExecError::MprotectFailed(std::io::Error::last_os_error()));
        }
        Ok(Self {
            page_start,
            page_len,
        })
    }
}

#[cfg(not(target_os = "macos"))]
impl Drop for JitWriteGuard {
    fn drop(&mut self) {
        // SAFETY: Restores pages covering the write range to Read+Execute.
        unsafe {
            libc::mprotect(
                self.page_start,
                self.page_len,
                libc::PROT_READ | libc::PROT_EXEC,
            );
        }
    }
}

/// Flushes the CPU instruction cache for the memory range `[ptr, ptr + len)`.
#[cfg(target_os = "macos")]
// Port of erts/emulator/beam/jit/beam_jit_main.cpp:459-460, OTP-29.1.1
fn flush_icache(ptr: *mut u8, len: usize) {
    // SAFETY: sys_icache_invalidate invalidates instruction cache across all cores on Apple Silicon.
    unsafe {
        sys_icache_invalidate(ptr.cast(), len);
    }
}

/// Flushes the CPU instruction cache for the memory range `[ptr, ptr + len)`.
#[cfg(not(target_os = "macos"))]
// Port of erts/emulator/beam/jit/beam_jit_main.cpp:461-485, OTP-29.1.1
fn flush_icache(ptr: *mut u8, len: usize) {
    // On Linux / non-macOS systems, clear cache using libgcc / compiler-rt builtin __clear_cache.
    // SAFETY: __clear_cache clears instruction cache for range [start, end).
    unsafe {
        let start = ptr.cast::<libc::c_void>();
        let end = ptr.add(len).cast::<libc::c_void>();
        __clear_cache(start, end);
    }
}

/// Retrieves the system virtual memory page size in bytes.
fn get_page_size() -> usize {
    // SAFETY: sysconf(_SC_PAGESIZE) is safe to invoke on POSIX systems.
    let sz = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if sz > 0 { sz as usize } else { 4096 }
}
