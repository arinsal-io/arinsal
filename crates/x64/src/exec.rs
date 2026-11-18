//! x86_64 executable memory with explicit writable/executable protection changes.
//!
//! Port of the x86 allocator selection in `erts/emulator/beam/jit/beam_jit_main.cpp`
//! and the writable/executable mapping operations in asmjit's `VirtMem`, OTP-29.1.1.

use core::fmt;

/// Failures from executable memory allocation and writes.
#[derive(Debug)]
pub enum ExecError {
    /// The requested mapping size is invalid.
    InvalidSize,
    /// Anonymous mapping failed.
    MmapFailed(std::io::Error),
    /// A protection change failed.
    MprotectFailed(std::io::Error),
    /// Requested byte range exceeds the mapping.
    OutOfBounds {
        offset: usize,
        len: usize,
        capacity: usize,
    },
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSize => f.write_str("executable memory size must be nonzero"),
            Self::MmapFailed(e) => write!(f, "mmap failed: {e}"),
            Self::MprotectFailed(e) => write!(f, "mprotect failed: {e}"),
            Self::OutOfBounds {
                offset,
                len,
                capacity,
            } => write!(
                f,
                "range [{offset}..{}) exceeds executable memory capacity {capacity}",
                offset.saturating_add(*len)
            ),
        }
    }
}
impl std::error::Error for ExecError {}

/// A single executable mapping; writes temporarily switch the requested pages to RW.
pub struct CodeMemory {
    ptr: *mut u8,
    capacity: usize,
}

impl CodeMemory {
    /// Creates a page-rounded mapping initially writable, then marks it executable and read-only.
    // Port of `erts/emulator/beam/jit/beam_jit_main.cpp` (`pick_allocator`) and asmjit
    // `VirtMem::alloc`/`VirtMem::protect`, OTP-29.1.1.
    pub fn new(capacity: usize) -> Result<Self, ExecError> {
        if capacity == 0 {
            return Err(ExecError::InvalidSize);
        }
        // SAFETY: sysconf has no pointer arguments and returns the system page size.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let page_size = if page_size > 0 {
            page_size as usize
        } else {
            4096
        };
        let mapped = capacity
            .checked_add(page_size - 1)
            .ok_or(ExecError::InvalidSize)?
            & !(page_size - 1);
        // SAFETY: mmap receives a valid anonymous private mapping description; MAP_FAILED is checked.
        let ptr = unsafe {
            let p = libc::mmap(
                core::ptr::null_mut(),
                mapped,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if p == libc::MAP_FAILED {
                return Err(ExecError::MmapFailed(std::io::Error::last_os_error()));
            }
            p.cast::<u8>()
        };
        // SAFETY: ptr is a live mapping of mapped bytes returned above.
        if unsafe { libc::mprotect(ptr.cast(), mapped, libc::PROT_READ | libc::PROT_EXEC) } != 0 {
            let error = std::io::Error::last_os_error();
            // SAFETY: ptr and mapped describe the live mapping created above.
            unsafe {
                libc::munmap(ptr.cast(), mapped);
            }
            return Err(ExecError::MprotectFailed(error));
        }
        Ok(Self {
            ptr,
            capacity: mapped,
        })
    }

    /// Returns the page-rounded mapping capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Copies bytes into the mapping and returns it to read/execute protection.
    // Port of asmjit `VirtMem::protect` write/execute transitions; x86 requires no icache flush.
    pub fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), ExecError> {
        let end = offset
            .checked_add(bytes.len())
            .ok_or(ExecError::InvalidSize)?;
        if end > self.capacity {
            return Err(ExecError::OutOfBounds {
                offset,
                len: bytes.len(),
                capacity: self.capacity,
            });
        }
        if bytes.is_empty() {
            return Ok(());
        }
        // SAFETY: sysconf has no pointer arguments and returns the system page size.
        let queried_page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let page_size = if queried_page_size > 0 {
            queried_page_size as usize
        } else {
            4096
        };
        let start = offset & !(page_size - 1);
        let stop = end
            .checked_add(page_size - 1)
            .ok_or(ExecError::InvalidSize)?
            & !(page_size - 1);
        let len = stop - start;
        // SAFETY: requested protection range lies within the mmap region.
        if unsafe {
            libc::mprotect(
                self.ptr.add(start).cast(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        } != 0
        {
            return Err(ExecError::MprotectFailed(std::io::Error::last_os_error()));
        }
        // SAFETY: offset/end were checked against the mapping and the range is writable.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.ptr.add(offset), bytes.len());
        }
        // SAFETY: same mapped pages are restored to read/execute after writing.
        if unsafe {
            libc::mprotect(
                self.ptr.add(start).cast(),
                len,
                libc::PROT_READ | libc::PROT_EXEC,
            )
        } != 0
        {
            return Err(ExecError::MprotectFailed(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    /// Returns a raw pointer to a byte in the mapping.
    pub fn as_ptr(&self) -> *const u8 {
        self.ptr
    }

    /// Returns the address of an entry point as a pointer-sized function value.
    ///
    /// # Safety
    /// The caller must choose the emitted function ABI and signature and must use a valid offset.
    pub unsafe fn entry<F: Copy>(&self, offset: usize) -> F {
        assert!(
            offset < self.capacity,
            "entry offset exceeds executable mapping"
        );
        assert_eq!(core::mem::size_of::<F>(), core::mem::size_of::<*const ()>());
        // SAFETY: caller guarantees a valid code entry and matching function-pointer ABI.
        unsafe { core::mem::transmute_copy(&self.ptr.add(offset)) }
    }
}

impl Drop for CodeMemory {
    fn drop(&mut self) {
        // SAFETY: ptr/capacity are the live mapping returned by mmap and are unmapped once here.
        unsafe {
            libc::munmap(self.ptr.cast(), self.capacity);
        }
    }
}

// x86_64 has coherent instruction/data caches, so publication after mprotect needs no cache flush.
#[cfg(test)]
mod tests {
    use super::{CodeMemory, ExecError};

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn mapped_function_can_be_written_and_called_after_wx_transition() {
        let mut memory = CodeMemory::new(16).unwrap();
        memory.write(0, &[0xb8, 42, 0, 0, 0, 0xc3]).unwrap();
        // SAFETY: bytes encode `mov eax, 42; ret`, matching this function signature and ABI.
        let f: extern "C" fn() -> u32 = unsafe { memory.entry(0) };
        assert_eq!(f(), 42);
    }

    #[test]
    fn rejects_empty_mapping_and_out_of_bounds_write() {
        assert!(matches!(CodeMemory::new(0), Err(ExecError::InvalidSize)));
        let mut memory = CodeMemory::new(1).unwrap();
        assert!(matches!(
            memory.write(memory.capacity(), &[1]),
            Err(ExecError::OutOfBounds { .. })
        ));
    }
}
