//! Audited OS memory operations and bounded access to mapped memory.

use std::fmt;

/// A system page size in bytes on the current host.
pub fn page_size() -> usize {
    // SAFETY: sysconf is a pure query and requires no pointer arguments.
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if value <= 0 { 4096 } else { value as usize }
}

/// Protection selected for a mapped region.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Protection {
    /// Permit reads.
    pub read: bool,
    /// Permit writes.
    pub write: bool,
    /// Permit instruction execution.
    pub execute: bool,
}

impl Protection {
    /// Read and write access, matching ERTS `os_mmap`.
    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
        execute: false,
    };
}

/// Memory mapping error.
#[derive(Debug)]
pub struct MapError(pub std::io::Error);

impl fmt::Display for MapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for MapError {}

/// Owned page aligned mapping with checked byte and machine word access.
#[derive(Debug)]
pub struct RawRegion {
    // Integer storage keeps the unique mapping owner movable behind a Mutex.
    // Every dereference remains inside this audited module's existing unsafe blocks.
    ptr: usize,
    len: usize,
    protection: Protection,
}

impl RawRegion {
    /// Creates a mapping rounded up to a page boundary.
    /// Port of erts/emulator/sys/common/erl_mmap.c:1304 (os_mmap), OTP-29.1.1.
    pub fn map(len: usize) -> Result<Self, MapError> {
        let len = round_pages(len)
            .ok_or_else(|| MapError(std::io::Error::from(std::io::ErrorKind::InvalidInput)))?;
        // SAFETY: mmap receives a null hint and a nonzero page multiple; success is checked against MAP_FAILED.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(MapError(std::io::Error::last_os_error()));
        }
        if ptr.is_null() {
            return Err(MapError(std::io::Error::from(std::io::ErrorKind::Other)));
        }
        Ok(Self {
            ptr: ptr as usize,
            len,
            protection: Protection::READ_WRITE,
        })
    }

    /// Creates a mapping whose start is aligned to `alignment` (a page multiple).
    /// Port of erts/emulator/sys/common/erl_mmap.c:1351 (os_mmap_aligned), OTP-29.1.1.
    pub fn map_aligned(len: usize, alignment: usize) -> Result<Self, MapError> {
        let page = page_size();
        if alignment < page || !alignment.is_power_of_two() || !alignment.is_multiple_of(page) {
            return Err(MapError(std::io::Error::from(
                std::io::ErrorKind::InvalidInput,
            )));
        }
        let len = round_pages(len)
            .ok_or_else(|| MapError(std::io::Error::from(std::io::ErrorKind::InvalidInput)))?;
        let reserve = len
            .checked_add(alignment)
            .ok_or_else(|| MapError(std::io::Error::from(std::io::ErrorKind::InvalidInput)))?;
        let whole = Self::map(reserve)?;
        let addr = whole.as_ptr() as usize;
        let aligned = (addr + alignment - 1) & !(alignment - 1);
        let prefix = aligned - addr;
        let suffix = reserve - prefix - len;
        // SAFETY: prefix and suffix are page multiples within this live reservation; unmap preserves exactly the aligned middle range.
        if prefix > 0 {
            // SAFETY: prefix is a page multiple inside the live reservation.
            unsafe {
                libc::munmap(whole.base_ptr().cast(), prefix);
            }
        }
        if suffix > 0 {
            // SAFETY: suffix is a page multiple inside the live reservation.
            unsafe {
                libc::munmap((aligned + len) as *mut libc::c_void, suffix);
            }
        }
        std::mem::forget(whole);
        Ok(Self {
            ptr: aligned,
            len,
            protection: Protection::READ_WRITE,
        })
    }

    /// Mapping base address.
    pub fn as_ptr(&self) -> *mut u8 {
        self.base_ptr()
    }
    /// Mapping length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }
    /// Whether the mapping is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Reads one byte at a checked offset.
    pub fn read_byte(&self, offset: usize) -> Option<u8> {
        if offset >= self.len || !self.protection.read {
            return None;
        }
        // SAFETY: offset is in bounds of the mapped region.
        let address = unsafe { self.base_ptr().add(offset) };
        // SAFETY: address was derived from a live mapping at an in-bounds offset.
        Some(unsafe { address.read() })
    }

    /// Writes one byte at a checked offset.
    pub fn write_byte(&mut self, offset: usize, value: u8) -> bool {
        if offset >= self.len || !self.protection.write {
            return false;
        }
        // SAFETY: offset is in bounds of the writable mapping.
        let address = unsafe { self.base_ptr().add(offset) };
        // SAFETY: address was derived from a live writable mapping at an in-bounds offset.
        unsafe {
            address.write(value);
        }
        true
    }

    /// Reads a native machine word at an aligned, checked byte offset.
    pub fn read_word(&self, offset: usize) -> Option<usize> {
        if !self.protection.read || !self.word_offset_valid(offset) {
            return None;
        }
        // SAFETY: offset is aligned and the complete word lies inside the mapping.
        let address = unsafe { self.base_ptr().add(offset).cast::<usize>() };
        // SAFETY: address points to a fully in-bounds aligned word.
        Some(unsafe { address.read() })
    }

    /// Writes a native machine word at an aligned, checked byte offset.
    pub fn write_word(&mut self, offset: usize, value: usize) -> bool {
        if !self.protection.write || !self.word_offset_valid(offset) {
            return false;
        }
        // SAFETY: offset is aligned and the complete word lies inside the writable mapping.
        let address = unsafe { self.base_ptr().add(offset).cast::<usize>() };
        // SAFETY: address points to a fully in-bounds aligned word in a writable mapping.
        unsafe {
            address.write(value);
        }
        true
    }

    /// Changes protection on the entire page aligned mapping.
    pub fn protect(&mut self, protection: Protection) -> Result<(), MapError> {
        let mut flags = 0;
        if protection.read {
            flags |= libc::PROT_READ;
        }
        if protection.write {
            flags |= libc::PROT_WRITE;
        }
        if protection.execute {
            flags |= libc::PROT_EXEC;
        }
        // SAFETY: this object owns a page-aligned address and page-multiple size.
        let result = unsafe { libc::mprotect(self.base_ptr().cast(), self.len, flags) };
        if result == 0 {
            self.protection = protection;
            Ok(())
        } else {
            Err(MapError(std::io::Error::last_os_error()))
        }
    }

    /// Advises the OS about the entire mapping.
    pub fn advise(&mut self, advice: i32) -> Result<(), MapError> {
        // SAFETY: this object owns a valid mapped range; kernel validates advice.
        let result = unsafe { libc::madvise(self.base_ptr().cast(), self.len, advice) };
        if result == 0 {
            Ok(())
        } else {
            Err(MapError(std::io::Error::last_os_error()))
        }
    }

    /// Resizes a mapping while preserving its prefix.
    pub fn resize(self, new_len: usize) -> Result<Self, MapError> {
        self.resize_aligned(new_len, page_size())
    }

    /// Resizes while preserving the prefix and requested base alignment.
    pub fn resize_aligned(self, new_len: usize, alignment: usize) -> Result<Self, MapError> {
        if !self.protection.read || !self.protection.write {
            return Err(MapError(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            )));
        }
        let next = if alignment > page_size() {
            Self::map_aligned(new_len, alignment)?
        } else {
            Self::map(new_len)?
        };
        let copy_len = self.len.min(next.len);
        // SAFETY: both mappings are valid and non-overlapping; copy_len is bounded by both extents.
        unsafe {
            std::ptr::copy_nonoverlapping(self.base_ptr(), next.base_ptr(), copy_len);
        }
        Ok(next)
    }

    /// Replaces this mapping only after the resized mapping has been created and copied.
    pub fn resize_preserving(&mut self, new_len: usize, alignment: usize) -> Result<(), MapError> {
        if !self.protection.read || !self.protection.write {
            return Err(MapError(std::io::Error::from(
                std::io::ErrorKind::PermissionDenied,
            )));
        }
        let mut next = if alignment > page_size() {
            Self::map_aligned(new_len, alignment)?
        } else {
            Self::map(new_len)?
        };
        let copy_len = self.len.min(next.len);
        for offset in 0..copy_len {
            let byte = self
                .read_byte(offset)
                .ok_or_else(|| MapError(std::io::Error::from(std::io::ErrorKind::InvalidData)))?;
            if !next.write_byte(offset, byte) {
                return Err(MapError(std::io::Error::from(
                    std::io::ErrorKind::InvalidData,
                )));
            }
        }
        *self = next;
        Ok(())
    }

    /// Splits a mapping at a page aligned byte offset without copying.
    pub fn split_at(self, offset: usize) -> Result<(Self, Self), Self> {
        if offset == 0 || offset >= self.len || !offset.is_multiple_of(page_size()) {
            return Err(self);
        }
        let base = self.ptr;
        let len = self.len;
        let protection = self.protection;
        std::mem::forget(self);
        // SAFETY: offset is a page multiple strictly inside the original mapping.
        let tail = base + offset;
        Ok((
            Self {
                ptr: base,
                len: offset,
                protection,
            },
            Self {
                ptr: tail,
                len: len - offset,
                protection,
            },
        ))
    }

    fn word_offset_valid(&self, offset: usize) -> bool {
        offset.is_multiple_of(std::mem::align_of::<usize>())
            && offset
                .checked_add(std::mem::size_of::<usize>())
                .is_some_and(|end| end <= self.len)
    }

    fn base_ptr(&self) -> *mut u8 {
        self.ptr as *mut u8
    }
}

impl Drop for RawRegion {
    fn drop(&mut self) {
        // SAFETY: this object uniquely owns the mapping and passes its original page-multiple extent.
        unsafe {
            libc::munmap(self.base_ptr().cast(), self.len);
        }
    }
}

fn round_pages(size: usize) -> Option<usize> {
    let page = page_size();
    if size == 0 {
        return Some(page);
    }
    size.checked_add(page - 1).map(|n| n & !(page - 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_map_reads_writes() {
        let mut r = RawRegion::map(32).unwrap();
        assert!(r.write_byte(0, 9));
        assert_eq!(r.read_byte(0), Some(9));
    }
    #[test]
    fn preserving_resize_copies_before_replacing_mapping() {
        let mut region = RawRegion::map(32).unwrap();
        assert!(region.write_byte(0, 0x5a));
        region
            .resize_preserving(page_size() * 2, page_size())
            .unwrap();
        assert_eq!(region.len(), page_size() * 2);
        assert_eq!(region.read_byte(0), Some(0x5a));
    }
    #[test]
    fn raw_byte_rejects_end() {
        let mut r = RawRegion::map(1).unwrap();
        assert!(!r.write_byte(r.len(), 1));
        assert_eq!(r.read_byte(r.len()), None);
    }
    #[test]
    fn raw_word_roundtrip() {
        let mut r = RawRegion::map(32).unwrap();
        assert!(r.write_word(8, 0x1234));
        assert_eq!(r.read_word(8), Some(0x1234));
    }
    #[test]
    fn raw_word_rejects_unaligned() {
        let r = RawRegion::map(32).unwrap();
        assert_eq!(r.read_word(1), None);
    }
    #[test]
    fn raw_word_rejects_overrun() {
        let r = RawRegion::map(1).unwrap();
        assert_eq!(r.read_word(r.len()), None);
    }
    #[test]
    fn aligned_mapping_respects_alignment() {
        let r = RawRegion::map_aligned(4096, 1 << 20).unwrap();
        assert_eq!((r.as_ptr() as usize) % (1 << 20), 0);
    }
    #[test]
    fn mapping_is_page_aligned() {
        let r = RawRegion::map(2).unwrap();
        assert_eq!((r.as_ptr() as usize) % page_size(), 0);
        assert_eq!(r.len(), page_size());
    }
    #[test]
    fn protect_roundtrip() {
        let mut r = RawRegion::map(1).unwrap();
        r.protect(Protection::READ_WRITE).unwrap();
    }
    #[test]
    fn protection_blocks_safe_writes() {
        let mut r = RawRegion::map(1).unwrap();
        r.protect(Protection {
            read: true,
            write: false,
            execute: false,
        })
        .unwrap();
        assert!(!r.write_byte(0, 1));
        assert_eq!(r.read_byte(0), Some(0));
    }
    #[test]
    fn bounds_word_last_valid() {
        let mut r = RawRegion::map(16).unwrap();
        assert!(r.write_word(8, 7));
        assert_eq!(r.read_word(8), Some(7));
    }
    #[test]
    fn zero_length_still_has_page() {
        let r = RawRegion::map(0).unwrap();
        assert_eq!(r.len(), page_size());
    }
}
