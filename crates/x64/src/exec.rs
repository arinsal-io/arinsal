//! x86_64 executable memory backed by the ERTS dual-mapped JIT allocator path.
//!
//! Port of `erts/emulator/beam/jit/beam_jit_main.cpp:181-229` and asmjit's
//! `JitAllocator::alloc/release` plus `VirtMem::alloc_dual_mapping`, OTP-29.1.1.

use core::fmt;
#[cfg(target_os = "linux")]
use std::ffi::{CStr, CString};
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

const GRANULARITY: usize = 64;
const CONFIGURED_BLOCK_SIZE: usize = 32 * 1024 * 1024;
const MAX_BLOCK_SIZE: usize = 64 * 1024 * 1024;
const MAX_REQUEST_SIZE: usize = u32::MAX as usize / 2;
#[cfg(target_os = "linux")]
const MFD_CLOEXEC: u32 = 0x0001;
#[cfg(target_os = "linux")]
const MFD_EXEC: u32 = 0x0010;

static ALLOCATOR: OnceLock<Mutex<JitAllocator>> = OnceLock::new();
#[cfg(target_os = "linux")]
static MEMFD_UNSUPPORTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(target_os = "linux")]
static SHM_SEQUENCE: AtomicU64 = AtomicU64::new(0);
#[cfg(target_os = "linux")]
static SHM_PREFERS_TMP: AtomicU8 = AtomicU8::new(0);
#[cfg(target_os = "linux")]
static MEMFD_EXEC_SUPPORTED: AtomicU8 = AtomicU8::new(0);

/// Failures from the executable-memory allocator.
#[derive(Debug)]
pub enum ExecError {
    /// A zero or overflowing allocation size was requested.
    InvalidSize,
    /// The request exceeds asmjit's supported span size.
    RequestTooLarge,
    /// A virtual-memory operation failed.
    MappingFailed(std::io::Error),
    /// A dual mapping could not be protected on macOS.
    ProtectionFailed(i32),
    /// The allocator could not reserve a span.
    OutOfMemory,
    /// A write exceeds this executable span.
    OutOfBounds {
        offset: usize,
        len: usize,
        capacity: usize,
    },
    /// The allocator did not find the RX address being released.
    InvalidSpan,
    /// This target has no implementation of asmjit's dual mapping path.
    UnsupportedTarget,
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSize => f.write_str("executable memory size must be nonzero"),
            Self::RequestTooLarge => f.write_str("executable memory request is too large"),
            Self::MappingFailed(error) => write!(f, "executable memory mapping failed: {error}"),
            Self::ProtectionFailed(code) => {
                write!(f, "dual mapping protection failed with Mach error {code}")
            }
            Self::OutOfMemory => f.write_str("executable memory allocator is out of memory"),
            Self::OutOfBounds {
                offset,
                len,
                capacity,
            } => write!(
                f,
                "range [{offset}..{}) exceeds executable span capacity {capacity}",
                offset.saturating_add(*len)
            ),
            Self::InvalidSpan => f.write_str("executable span is not allocated"),
            Self::UnsupportedTarget => {
                f.write_str("dual-mapped executable memory is unsupported on this target")
            }
        }
    }
}
impl std::error::Error for ExecError {}

/// One read/execute alias and one read/write alias for the same backing span.
struct DualMapping {
    rx: *mut u8,
    rw: *mut u8,
    size: usize,
}

// SAFETY: the aliases remain mapped until the allocator releases the block, and its mutex
// serializes all allocator metadata and mapping lifetime changes.
unsafe impl Send for DualMapping {}

impl DualMapping {
    // Port of asmjit `VirtMem::alloc_dual_mapping` in erts/emulator/asmjit/core/virtmem.cpp.
    fn new(size: usize) -> Result<Self, ExecError> {
        #[cfg(target_os = "linux")]
        {
            linux_dual_mapping(size)
        }
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        {
            macos_x86_dual_mapping(size)
        }
        #[cfg(not(any(target_os = "linux", all(target_os = "macos", target_arch = "x86_64"))))]
        {
            let _ = size;
            Err(ExecError::UnsupportedTarget)
        }
    }

    // Port of asmjit `VirtMem::release_dual_mapping`, virtmem.cpp:935-950.
    fn unmap(&mut self) {
        // SAFETY: both pointers describe the live aliases returned by the target mapping routine.
        unsafe {
            libc::munmap(self.rx.cast(), self.size);
            if self.rw != self.rx {
                libc::munmap(self.rw.cast(), self.size);
            }
        }
        self.rx = core::ptr::null_mut();
        self.rw = core::ptr::null_mut();
        self.size = 0;
    }
}

impl Drop for DualMapping {
    fn drop(&mut self) {
        if !self.rx.is_null() {
            self.unmap();
        }
    }
}

struct AllocatorBlock {
    mapping: DualMapping,
    area_count: u32,
    used_count: u32,
    largest_free: u32,
    search_start: u32,
    search_end: u32,
    incremental: bool,
    dirty: bool,
    empty: bool,
    used: Vec<u64>,
    stop: Vec<u64>,
}

impl AllocatorBlock {
    // Port of erts/emulator/asmjit/core/jitallocator.cpp:340-379 (clear_block/mark_allocated_area).
    fn new(size: usize) -> Result<Self, ExecError> {
        let mapping = DualMapping::new(size)?;
        let area_count =
            u32::try_from(size / GRANULARITY).map_err(|_| ExecError::RequestTooLarge)?;
        let word_count = (area_count as usize).div_ceil(u64::BITS as usize);
        let mut used = Vec::new();
        let mut stop = Vec::new();
        used.try_reserve_exact(word_count)
            .map_err(|_| ExecError::OutOfMemory)?;
        stop.try_reserve_exact(word_count)
            .map_err(|_| ExecError::OutOfMemory)?;
        used.resize(word_count, 0);
        stop.resize(word_count, 0);
        used[0] = 1;
        stop[0] = 1;
        Ok(Self {
            mapping,
            area_count,
            used_count: 1,
            largest_free: area_count - 1,
            search_start: 1,
            search_end: area_count,
            incremental: true,
            dirty: false,
            empty: true,
            used,
            stop,
        })
    }

    fn is_used(&self, area: u32) -> bool {
        self.used[area as usize / 64] & (1_u64 << (area % 64)) != 0
    }

    fn set_bit(bits: &mut [u64], area: u32, value: bool) {
        let word = &mut bits[area as usize / 64];
        let mask = 1_u64 << (area % 64);
        if value {
            *word |= mask;
        } else {
            *word &= !mask;
        }
    }

    fn find_free_range(&mut self, needed: u32) -> Option<u32> {
        let mut run_start = None;
        let mut run_len = 0_u32;
        let mut first_free = None;
        let mut last_free_end = self.search_start;
        let mut largest = 0_u32;
        for area in self.search_start..self.search_end {
            if !self.is_used(area) {
                let start = *run_start.get_or_insert(area);
                if first_free.is_none() {
                    first_free = Some(start);
                }
                run_len += 1;
                last_free_end = area + 1;
                largest = largest.max(run_len);
                if run_len >= needed {
                    return Some(start);
                }
            } else {
                run_start = None;
                run_len = 0;
            }
        }
        if let Some(start) = first_free {
            self.search_start = start;
            self.search_end = last_free_end;
            self.largest_free = largest;
        } else {
            self.largest_free = 0;
        }
        self.dirty = false;
        None
    }

    fn allocate(&mut self, count: u32) -> Option<u32> {
        let area = if self.incremental && self.largest_free >= count {
            self.largest_free -= count;
            self.search_start
        } else if self.area_count - self.used_count >= count
            && (self.dirty || self.largest_free >= count)
        {
            self.find_free_range(count)?
        } else {
            return None;
        };
        self.mark_allocated(area, area + count);
        Some(area)
    }

    fn mark_allocated(&mut self, start: u32, end: u32) {
        for area in start..end {
            Self::set_bit(&mut self.used, area, true);
        }
        Self::set_bit(&mut self.stop, end - 1, true);
        self.used_count += end - start;
        if self.area_count == self.used_count {
            self.search_start = self.area_count;
            self.search_end = 0;
            self.largest_free = 0;
            self.dirty = false;
        } else {
            if self.search_start == start {
                self.search_start = end;
            }
            if self.search_end == end {
                self.search_end = start;
            }
            self.dirty = true;
        }
        self.empty = false;
    }

    // Port of asmjit `JitAllocatorBlock::mark_released_area`, jitallocator.cpp:383-415.
    fn release(&mut self, start: u32) -> Result<(), ExecError> {
        if start == 0 || start >= self.area_count || !self.is_used(start) {
            return Err(ExecError::InvalidSpan);
        }
        let end_bit = (start..self.area_count)
            .find(|area| self.stop[*area as usize / 64] & (1_u64 << (*area % 64)) != 0)
            .ok_or(ExecError::InvalidSpan)?;
        let end = end_bit + 1;
        let count = end - start;
        for area in start..end {
            Self::set_bit(&mut self.used, area, false);
        }
        Self::set_bit(&mut self.stop, end_bit, false);
        self.used_count -= count;
        if self.incremental && self.search_start == end {
            self.search_start -= count;
            self.largest_free += count;
        } else {
            self.search_start = self.search_start.min(start);
            self.search_end = self.search_end.max(end);
            self.dirty = self.used_count != 1;
            self.incremental = false;
            if self.used_count == 1 {
                self.search_start = 1;
                self.search_end = self.area_count;
                self.largest_free = self.area_count - 1;
                self.empty = true;
            }
        }
        Ok(())
    }
}

struct JitAllocator {
    blocks: Vec<AllocatorBlock>,
    initialized: bool,
}

impl JitAllocator {
    fn new() -> Self {
        Self {
            blocks: Vec::new(),
            initialized: false,
        }
    }

    // Port of `beam_jit_main.cpp:create_allocator`: probe alloc(1), release its RX span, then
    // use the selected allocator for all subsequent spans.
    fn initialize(&mut self) -> Result<(), ExecError> {
        if self.initialized {
            return Ok(());
        }
        let (rx, _) = self.allocate(1)?;
        self.release(rx)?;
        self.initialized = true;
        Ok(())
    }

    // Port of erts/emulator/asmjit/core/jitallocator.cpp:888-1000 for ERTS's default single
    // pool, 64-byte granularity, initial padding, and 32 MiB configured block size.
    fn allocate(&mut self, requested: usize) -> Result<(*mut u8, usize), ExecError> {
        if requested == 0 {
            return Err(ExecError::InvalidSize);
        }
        let size = requested
            .checked_add(GRANULARITY - 1)
            .ok_or(ExecError::InvalidSize)?
            & !(GRANULARITY - 1);
        if size > MAX_REQUEST_SIZE {
            return Err(ExecError::RequestTooLarge);
        }
        let count = u32::try_from(size / GRANULARITY).map_err(|_| ExecError::RequestTooLarge)?;
        for block in &mut self.blocks {
            if let Some(area) = block.allocate(count) {
                return Ok((
                    block.mapping.rx.wrapping_add(area as usize * GRANULARITY),
                    size,
                ));
            }
        }

        let block_size = self.ideal_block_size(size)?;
        let mut block = AllocatorBlock::new(block_size)?;
        let area = block.allocate(count).ok_or(ExecError::OutOfMemory)?;
        let rx = block.mapping.rx.wrapping_add(area as usize * GRANULARITY);
        self.blocks
            .try_reserve(1)
            .map_err(|_| ExecError::OutOfMemory)?;
        self.blocks.push(block);
        Ok((rx, size))
    }

    fn ideal_block_size(&self, allocation_size: usize) -> Result<usize, ExecError> {
        let mut block_size = self
            .blocks
            .last()
            .map_or(CONFIGURED_BLOCK_SIZE, |block| block.mapping.size);
        let allocation_size = allocation_size
            .checked_add(GRANULARITY)
            .ok_or(ExecError::InvalidSize)?;
        if block_size < MAX_BLOCK_SIZE {
            block_size = block_size.checked_mul(2).ok_or(ExecError::InvalidSize)?;
        }
        if allocation_size > block_size {
            block_size = allocation_size
                .checked_add(CONFIGURED_BLOCK_SIZE - 1)
                .ok_or(ExecError::InvalidSize)?
                & !(CONFIGURED_BLOCK_SIZE - 1);
        }
        Ok(block_size)
    }

    // Port of erts/emulator/asmjit/core/jitallocator.cpp:1009-1045: identify the owner from the RX address and use
    // each span's stop bit as its end sentinel. One empty block remains available for reuse.
    fn release(&mut self, rx: *mut u8) -> Result<(), ExecError> {
        let index = self
            .blocks
            .iter()
            .position(|block| {
                let start = block.mapping.rx as usize;
                (start..start + block.mapping.size).contains(&(rx as usize))
            })
            .ok_or(ExecError::InvalidSpan)?;
        let block_start = self.blocks[index].mapping.rx as usize;
        let offset = (rx as usize)
            .checked_sub(block_start)
            .ok_or(ExecError::InvalidSpan)?;
        if !offset.is_multiple_of(GRANULARITY) {
            return Err(ExecError::InvalidSpan);
        }
        self.blocks[index].release((offset / GRANULARITY) as u32)?;
        if self.blocks[index].empty
            && self
                .blocks
                .iter()
                .enumerate()
                .any(|(other, block)| other != index && block.empty)
        {
            self.blocks.remove(index);
        }
        Ok(())
    }
}

fn allocator() -> &'static Mutex<JitAllocator> {
    ALLOCATOR.get_or_init(|| Mutex::new(JitAllocator::new()))
}

/// A span allocated from ERTS's process-wide 32 MiB configured JIT allocator.
pub struct CodeMemory {
    rx: *mut u8,
    rw: *mut u8,
    capacity: usize,
}

impl CodeMemory {
    /// Allocates a span with separate writable and executable aliases.
    // Port of `beam_jit_main.cpp:181-229` and asmjit `JitAllocator::alloc`, OTP-29.1.1.
    pub fn new(capacity: usize) -> Result<Self, ExecError> {
        if capacity == 0 {
            return Err(ExecError::InvalidSize);
        }
        let mut allocator = allocator()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        allocator.initialize()?;
        let (rx, size) = allocator.allocate(capacity)?;
        let block = allocator
            .blocks
            .iter()
            .find(|block| {
                let start = block.mapping.rx as usize;
                (start..start + block.mapping.size).contains(&(rx as usize))
            })
            .ok_or(ExecError::InvalidSpan)?;
        let offset = (rx as usize) - (block.mapping.rx as usize);
        let rw = block.mapping.rw.wrapping_add(offset);
        Ok(Self {
            rx,
            rw,
            capacity: size,
        })
    }

    /// Returns the allocator-rounded span capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Copies bytes through the RW alias; the RX alias remains executable throughout.
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
        if !bytes.is_empty() {
            // SAFETY: the requested range was checked against this live span and the RW alias is
            // writable by the dual-mapping allocator.
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.rw.add(offset), bytes.len());
            }
        }
        Ok(())
    }

    /// Returns the RX alias address.
    pub fn as_ptr(&self) -> *const u8 {
        self.rx
    }

    /// Returns the RW alias address for identity checks and allocator integrations.
    pub fn as_rw_ptr(&self) -> *const u8 {
        self.rw
    }

    /// Returns the address at `offset` as a function pointer.
    ///
    /// # Safety
    /// The caller must choose the emitted function ABI and signature and use a valid entry offset.
    pub unsafe fn entry<F: Copy>(&self, offset: usize) -> F {
        assert!(
            offset < self.capacity,
            "entry offset exceeds executable span"
        );
        assert_eq!(core::mem::size_of::<F>(), core::mem::size_of::<*const ()>());
        let address = self.rx.wrapping_add(offset);
        // SAFETY: the caller guarantees `address` contains valid machine code for `F`'s ABI.
        unsafe { core::mem::transmute_copy(&address) }
    }
}

impl Drop for CodeMemory {
    fn drop(&mut self) {
        let mut allocator = allocator()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Port of erts/emulator/beam/jit/x86/beam_asm_module.cpp:586-602 (`beamasm_purge_module`):
        // purge likewise ignores JitAllocator::release's return value.
        let _ = allocator.release(self.rx);
    }
}

#[cfg(target_os = "linux")]
// Port of asmjit `alloc_dual_mapping_using_file`, virtmem.cpp:1087-1113.
fn linux_dual_mapping(size: usize) -> Result<DualMapping, ExecError> {
    let fd = anonymous_fd(size)?;
    let rx = match map_fd(fd, size, libc::PROT_READ | libc::PROT_EXEC) {
        Ok(rx) => rx,
        Err(error) => {
            // SAFETY: `fd` is owned by this function and no mapping succeeded.
            unsafe { libc::close(fd) };
            return Err(error);
        }
    };
    let rw = match map_fd(fd, size, libc::PROT_READ | libc::PROT_WRITE) {
        Ok(rw) => rw,
        Err(error) => {
            // SAFETY: `rx` is the live first alias created above.
            unsafe { libc::munmap(rx.cast(), size) };
            // SAFETY: `fd` is owned by this function and both mappings have been attempted.
            unsafe { libc::close(fd) };
            return Err(error);
        }
    };
    // SAFETY: the file descriptor is no longer needed after both MAP_SHARED aliases are live.
    unsafe { libc::close(fd) };
    Ok(DualMapping { rx, rw, size })
}

#[cfg(target_os = "linux")]
// Port of asmjit `AnonymousMemory::open` and `AnonymousMemory::allocate`, virtmem.cpp:588-696.
fn anonymous_fd(size: usize) -> Result<libc::c_int, ExecError> {
    if !MEMFD_UNSUPPORTED.load(Ordering::Relaxed) {
        let name = b"vmem\0";
        // AsmJit passes MFD_EXEC on kernels that support it and falls back to shm_open only when
        // the memfd_create syscall itself is unavailable.
        // SAFETY: the syscall receives a static NUL-terminated name and integer flags.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                name.as_ptr().cast::<libc::c_char>(),
                MFD_CLOEXEC | memfd_exec_flag(),
            )
        } as libc::c_int;
        if fd >= 0 {
            resize_fd(fd, size)?;
            return Ok(fd);
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ENOSYS) {
            return Err(ExecError::MappingFailed(error));
        }
        MEMFD_UNSUPPORTED.store(true, Ordering::Relaxed);
    }
    shm_fd(size)
}

#[cfg(target_os = "linux")]
fn resize_fd(fd: libc::c_int, size: usize) -> Result<(), ExecError> {
    let size = libc::off_t::try_from(size).map_err(|_| ExecError::InvalidSize)?;
    // SAFETY: `fd` is open and `size` is a positive, representable file length.
    if unsafe { libc::ftruncate(fd, size) } != 0 {
        let error = std::io::Error::last_os_error();
        // SAFETY: `fd` was opened in this call chain and must be closed on allocation failure.
        unsafe { libc::close(fd) };
        return Err(ExecError::MappingFailed(error));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn shm_fd(size: usize) -> Result<libc::c_int, ExecError> {
    let prefer_tmp = shm_prefers_tmp()?;
    for _ in 0..100 {
        let (fd, name, is_tmp) = open_anonymous_file(prefer_tmp)?;
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EEXIST) {
                continue;
            }
            return Err(ExecError::MappingFailed(error));
        }
        // SAFETY: unlinking the created object preserves its already-open descriptor.
        unsafe {
            if is_tmp {
                libc::unlink(name.as_ptr());
            } else {
                libc::shm_unlink(name.as_ptr());
            }
        }
        resize_fd(fd, size)?;
        return Ok(fd);
    }
    Err(ExecError::MappingFailed(std::io::Error::from_raw_os_error(
        libc::EEXIST,
    )))
}

#[cfg(target_os = "linux")]
// Port of asmjit `get_mfd_exec_flag`, virtmem.cpp:525-543.
fn memfd_exec_flag() -> u32 {
    match MEMFD_EXEC_SUPPORTED.load(Ordering::Relaxed) {
        1 => return 0,
        2 => return MFD_EXEC,
        _ => {}
    }
    let mut info: libc::utsname =
        // SAFETY: `utsname` is a plain C output struct fully initialized by `uname` below.
        unsafe { core::mem::zeroed() };
    // SAFETY: uname writes the kernel's fixed-size name fields into the valid struct pointer.
    if unsafe { libc::uname(&mut info) } != 0 {
        return 0;
    }
    // SAFETY: uname guarantees that `release` is NUL-terminated.
    let release = unsafe { CStr::from_ptr(info.release.as_ptr()) }.to_bytes();
    let mut parts = release.split(|byte| *byte == b'.');
    let major = parts.next().and_then(parse_decimal).unwrap_or_default();
    let minor = parts.next().and_then(parse_decimal).unwrap_or_default();
    let flag = if major > 6 || (major == 6 && minor >= 3) {
        MFD_EXEC
    } else {
        0
    };
    MEMFD_EXEC_SUPPORTED.store(if flag == 0 { 1 } else { 2 }, Ordering::Relaxed);
    flag
}

#[cfg(target_os = "linux")]
fn parse_decimal(bytes: &[u8]) -> Option<u32> {
    let end = bytes
        .iter()
        .position(|byte| !byte.is_ascii_digit())
        .unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end]).ok()?.parse().ok()
}

#[cfg(target_os = "linux")]
// Port of asmjit `get_anonymous_memory_strategy`, virtmem.cpp:708-739.
fn shm_prefers_tmp() -> Result<bool, ExecError> {
    match SHM_PREFERS_TMP.load(Ordering::Relaxed) {
        1 => return Ok(false),
        2 => return Ok(true),
        _ => {}
    }
    // SAFETY: sysconf has no pointer arguments and returns the system page size.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page_size = if page_size > 0 {
        page_size as usize
    } else {
        4096
    };
    let (fd, name, is_tmp) = open_anonymous_file(false)?;
    if fd < 0 {
        return Err(ExecError::MappingFailed(std::io::Error::last_os_error()));
    }
    // SAFETY: name denotes the temporary shared-memory probe object created above.
    unsafe { libc::shm_unlink(name.as_ptr()) };
    resize_fd(fd, page_size)?;
    let map_result = map_fd(fd, page_size, libc::PROT_READ | libc::PROT_EXEC);
    // SAFETY: the probe descriptor remains open until the RX probe has completed.
    unsafe { libc::close(fd) };
    let prefer_tmp = match map_result {
        Ok(pointer) => {
            // SAFETY: pointer is the live probe mapping returned by mmap.
            unsafe { libc::munmap(pointer.cast(), page_size) };
            false
        }
        Err(ExecError::MappingFailed(error)) if error.raw_os_error() == Some(libc::EINVAL) => true,
        Err(error) => return Err(error),
    };
    let _ = is_tmp;
    SHM_PREFERS_TMP.store(if prefer_tmp { 2 } else { 1 }, Ordering::Relaxed);
    Ok(prefer_tmp)
}

#[cfg(target_os = "linux")]
// Port of asmjit `AnonymousMemory::open`, virtmem.cpp:588-675.
fn open_anonymous_file(prefer_tmp: bool) -> Result<(libc::c_int, CString, bool), ExecError> {
    let sequence = SHM_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    if prefer_tmp {
        let directory = std::env::var_os("TMPDIR").unwrap_or_else(|| "/tmp".into());
        let name = CString::new(format!(
            "{}/arinsal-jit-{}-{sequence}",
            directory.to_string_lossy().trim_end_matches('/'),
            std::process::id()
        ))
        .expect("generated temporary path has no NUL");
        // SAFETY: name is a valid unique path and mode is supplied for O_CREAT.
        let fd = unsafe {
            libc::open(
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
                0o600,
            )
        };
        Ok((fd, name, true))
    } else {
        let name = CString::new(format!("/arinsal-jit-{}-{sequence}", std::process::id()))
            .expect("generated shared-memory name has no NUL");
        // SAFETY: name is a valid NUL-terminated POSIX shared-memory name.
        let fd = unsafe {
            libc::shm_open(
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
                0o600,
            )
        };
        Ok((fd, name, false))
    }
}

#[cfg(target_os = "linux")]
// Port of asmjit `map_memory`, used by `alloc_dual_mapping_using_file`, virtmem.cpp:1087-1113.
fn map_fd(fd: libc::c_int, size: usize, protection: libc::c_int) -> Result<*mut u8, ExecError> {
    // SAFETY: fd is open, offset zero and size describe its shared backing object, and MAP_FAILED
    // is checked before the pointer is returned.
    let ptr = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            size,
            protection,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        Err(ExecError::MappingFailed(std::io::Error::last_os_error()))
    } else {
        Ok(ptr.cast())
    }
}

// SAFETY: these declarations match the macOS Mach VM C ABI used by asmjit VirtMem remapping.
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
unsafe extern "C" {
    static mut mach_task_self_: u32;
    fn mach_vm_remap(
        target_task: u32,
        target_address: *mut u64,
        size: u64,
        mask: u64,
        flags: i32,
        source_task: u32,
        source_address: u64,
        copy: i32,
        current_protection: *mut i32,
        maximum_protection: *mut i32,
        inheritance: u32,
    ) -> i32;
    fn vm_protect(task: u32, address: u64, size: u64, set_maximum: i32, protection: i32) -> i32;
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
// Port of asmjit `alloc_dual_mapping_using_mach_vm_remap`, virtmem.cpp:999-1083.
fn macos_x86_dual_mapping(size: usize) -> Result<DualMapping, ExecError> {
    const VM_PROT_READ: i32 = 1;
    const VM_PROT_WRITE: i32 = 2;
    const VM_PROT_EXECUTE: i32 = 4;
    const VM_FLAGS_ANYWHERE: i32 = 1;
    const VM_FLAGS_RANDOM_ADDR: i32 = 0x0008;
    const VM_INHERIT_DEFAULT: u32 = 0;

    // AsmJit uses a writable mapping as the remap source on x86 macOS; unlike Apple Silicon,
    // x86 selects this dual-mapping path rather than MAP_JIT and per-thread write protection.
    // SAFETY: anonymous private pages are requested read/write and MAP_FAILED is checked.
    let rx = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if rx == libc::MAP_FAILED {
        return Err(ExecError::MappingFailed(std::io::Error::last_os_error()));
    }
    // SAFETY: `mach_task_self_` is the process's current Mach task port exported by libSystem.
    let task = unsafe { mach_task_self_ };
    let mut rw_address = 0_u64;
    let mut current = 0_i32;
    let mut maximum = 0_i32;
    // SAFETY: `rx` is the live source mapping; out-pointers are valid locals and remap is shared.
    let remap_result = unsafe {
        mach_vm_remap(
            task,
            &mut rw_address,
            size as u64,
            0,
            VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR,
            task,
            rx as u64,
            0,
            &mut current,
            &mut maximum,
            VM_INHERIT_DEFAULT,
        )
    };
    if remap_result != 0 {
        // SAFETY: rx is the sole live mapping because remap failed.
        unsafe { libc::munmap(rx, size) };
        return Err(ExecError::ProtectionFailed(remap_result));
    }
    let rw = rw_address as *mut u8;
    for (address, protection) in [
        (rx as u64, VM_PROT_READ | VM_PROT_EXECUTE),
        (rw_address, VM_PROT_READ | VM_PROT_WRITE),
    ] {
        // SAFETY: address and size identify one of the two aliases made by mach_vm_remap.
        let maximum_result = unsafe { vm_protect(task, address, size as u64, 1, protection) };
        if maximum_result != 0 {
            // SAFETY: both aliases are live and owned by this function.
            unsafe {
                libc::munmap(rx, size);
                libc::munmap(rw.cast(), size);
            }
            return Err(ExecError::ProtectionFailed(maximum_result));
        }
        // SAFETY: the alias is live and its maximum permission has just been restricted.
        let current_result = unsafe { vm_protect(task, address, size as u64, 0, protection) };
        if current_result != 0 {
            // SAFETY: both aliases are live and owned by this function.
            unsafe {
                libc::munmap(rx, size);
                libc::munmap(rw.cast(), size);
            }
            return Err(ExecError::ProtectionFailed(current_result));
        }
    }
    Ok(DualMapping {
        rx: rx.cast(),
        rw,
        size,
    })
}

// x86 instruction and data caches are coherent, so publishing RX after an RW-alias write needs
// no cache invalidation. macOS x86 uses asmjit's mach_vm_remap path above; Linux uses shared fd maps.

#[cfg(test)]
mod tests {
    use super::{CodeMemory, ExecError};

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn writes_through_rw_alias_and_executes_through_rx_alias() {
        let mut memory = CodeMemory::new(16).unwrap();
        similar_asserts::assert_eq!(memory.as_ptr() == memory.as_rw_ptr(), false);
        memory.write(0, &[0xb8, 42, 0, 0, 0, 0xc3]).unwrap();
        // SAFETY: bytes encode `mov eax, 42; ret`, matching this function signature and ABI.
        let function: extern "C" fn() -> u32 = unsafe { memory.entry(0) };
        similar_asserts::assert_eq!(function(), 42);
    }

    #[test]
    fn allocator_reuses_a_released_span() {
        let first = CodeMemory::new(16).unwrap();
        let address = first.as_ptr();
        drop(first);
        let second = CodeMemory::new(16).unwrap();
        similar_asserts::assert_eq!(second.as_ptr(), address);
    }

    #[test]
    fn rejects_empty_mapping_and_out_of_bounds_write() {
        assert!(matches!(CodeMemory::new(0), Err(ExecError::InvalidSize)));
        let mut memory = CodeMemory::new(1).unwrap();
        similar_asserts::assert_eq!(memory.capacity(), 64);
        assert!(matches!(
            memory.write(memory.capacity(), &[1]),
            Err(ExecError::OutOfBounds { .. })
        ));
    }
}
