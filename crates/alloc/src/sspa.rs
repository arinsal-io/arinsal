//! Scheduler specific pre-allocation for message references.
//!
//! Port of `erl_sched_spec_pre_alloc.c` and `erl_sched_spec_pre_alloc.h`, OTP-29.1.1.

use crate::instances::InstanceAllocation;
use std::ptr::NonNull;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

const CACHE_LINE: usize = 64;
const FORCE_PROGRESS: i32 = 10;
const MAX_REMOTE: i32 = 5;

fn progress_later(value: u64) -> u64 {
    if value == u64::MAX - 2 {
        0
    } else if value == u64::MAX - 1 {
        1
    } else {
        value + 2
    }
}

/// Scheduler progress operations used by remote-list reclamation.
#[derive(Clone, Copy)]
pub struct ProgressOps {
    /// Current global progress value for the runtime owning `scheduler`.
    pub current: fn(scheduler: usize) -> u64,
    /// Whether that runtime has reached a progress value.
    pub has_reached: fn(scheduler: usize, value: u64) -> bool,
    /// Whether this caller is a managed scheduler.
    pub is_managed: fn() -> bool,
}

static PROGRESS_OPS: OnceLock<ProgressOps> = OnceLock::new();

/// Install the scheduler's thread-progress bridge before creating the message-ref pool.
pub fn install_progress_ops(ops: ProgressOps) -> Result<(), ProgressOps> {
    PROGRESS_OPS.set(ops)
}

#[repr(C)]
struct SspaDataHeader {
    start: usize,
    end: usize,
    chunk_size: i32,
    threads: i32,
    tsd_key: libc::pthread_key_t,
    id_generator: AtomicUsize,
}

#[repr(C)]
struct Block {
    next: AtomicUsize,
}

#[repr(C, align(64))]
struct Tail {
    marker: Block,
    last: AtomicUsize,
    um_refc: [AtomicUsize; 2],
    um_refc_ix: AtomicU32,
}

#[repr(C)]
struct Head {
    no_progress_check: i32,
    used_marker: i32,
    first: usize,
    unref_end: usize,
    next_progress: u64,
    next_progress_reached: i32,
    next_um_refc_ix: i32,
    next_unref_end: usize,
}

#[repr(C)]
struct LocalFreeList {
    first: usize,
    last: usize,
    count: i32,
    limit: i32,
}

#[repr(C, align(64))]
struct ChunkHeader {
    tail: Tail,
    head: std::cell::UnsafeCell<Head>,
    local: std::cell::UnsafeCell<LocalFreeList>,
}

/// A scheduler-private preallocated pool. The chunks and intrusive remote lists follow ERTS.
pub struct SspaPool {
    base: NonNull<u8>,
    allocation: InstanceAllocation,
    chunk_size: usize,
    block_size: usize,
    block_count: usize,
    threads: usize,
    progress: ProgressOps,
}

// SAFETY: only the owner mutates a chunk's head and local list; the tail is atomic.
unsafe impl Send for SspaPool {}
// SAFETY: shared access mutates only the atomic remote-free tail; owner state is thread-local.
unsafe impl Sync for SspaPool {}

impl SspaPool {
    /// Allocate one aligned arena and initialize the per-scheduler chunks.
    // Port of `erts_sspa_create`, erl_sched_spec_pre_alloc.c, OTP-29.1.1.
    pub fn new(block_size: usize, requested: usize, threads: usize) -> Option<Self> {
        let progress = *PROGRESS_OPS.get()?;
        if threads == 0 || block_size == 0 || requested == 0 {
            return None;
        }
        let block_size = align_up(block_size, 8)?;
        let block_count = if threads == 1 {
            requested
        } else {
            requested.checked_add(((requested - 1) / 4 + 1).checked_mul(threads)?)? / threads
        };
        let chunk_size = align_up(
            align_up(std::mem::size_of::<ChunkHeader>(), CACHE_LINE)?
                .checked_add(block_size.checked_mul(block_count)?)?,
            CACHE_LINE,
        )?;
        let prefix = align_up(std::mem::size_of::<SspaDataHeader>(), CACHE_LINE)?;
        let total = prefix.checked_add(chunk_size.checked_mul(threads)?)?;
        let allocation_bytes = total.checked_add(CACHE_LINE - 1)?;
        let (allocation, raw) = crate::typed::pre_alloc_data_alloc(allocation_bytes).ok()?;
        let raw = raw.cast::<u8>() as usize;
        let aligned = raw.checked_add(CACHE_LINE - 1)? & !(CACHE_LINE - 1);
        let base = NonNull::new(aligned as *mut u8)?;
        let start = aligned.checked_add(prefix)?;
        let end = start.checked_add(chunk_size.checked_mul(threads)?)?;
        // SAFETY: the aligned allocator payload includes the full permanent-data header.
        unsafe {
            std::ptr::write(
                base.as_ptr().cast::<SspaDataHeader>(),
                SspaDataHeader {
                    start,
                    end,
                    chunk_size: chunk_size as i32,
                    threads: threads as i32,
                    tsd_key: 0,
                    id_generator: AtomicUsize::new(0),
                },
            );
        }
        let pool = Self {
            base,
            allocation,
            chunk_size,
            block_size,
            block_count,
            threads,
            progress,
        };
        for ix in 0..threads {
            // SAFETY: each chunk is within the allocated arena and cache-line aligned.
            unsafe { pool.init_chunk(ix) };
        }
        Some(pool)
    }

    /// Allocate from the calling scheduler's chunk; `None` requests the MSG_REF fallback.
    // Port of `erts_sspa_alloc`, erl_sched_spec_pre_alloc.h, OTP-29.1.1.
    pub fn alloc(&self, ix: usize) -> Option<NonNull<u8>> {
        if ix >= self.threads {
            return None;
        }
        // SAFETY: the caller passes its own scheduler index; the head/local list are owner-only.
        unsafe {
            let header = self.header(ix);
            let local = &mut *header.local.get();
            let mut result = local.first;
            if result != 0 {
                local.first = (*(result as *mut Block)).next.load(Ordering::Relaxed);
                local.count -= 1;
                if local.first == 0 {
                    local.last = 0;
                }
            }
            if local.count <= local.limit {
                self.process_remote(header, ix, &mut result);
            } else {
                let head = &mut *header.head.get();
                if head.no_progress_check < FORCE_PROGRESS {
                    head.no_progress_check += 1;
                }
            }
            NonNull::new(result as *mut u8)
        }
    }

    /// Return a block to its owner; false means it belongs to another allocator.
    // Port of `erts_sspa_free`, erl_sched_spec_pre_alloc.h, OTP-29.1.1.
    pub fn free(&self, ix: isize, block: NonNull<u8>) -> bool {
        let Some(owner) = self.ptr_to_index(block.as_ptr()) else {
            return false;
        };
        // SAFETY: the address range check selects the owning chunk within this live arena.
        unsafe {
            let header = self.header(owner);
            if owner as isize != ix {
                self.remote_free(header, block.as_ptr() as usize, owner as isize - ix);
            } else {
                let local = &mut *header.local.get();
                (*(block.as_ptr() as *mut Block))
                    .next
                    .store(local.first, Ordering::Relaxed);
                local.first = block.as_ptr() as usize;
                if local.last == 0 {
                    local.last = local.first;
                }
                local.count += 1;
            }
        }
        true
    }

    // SAFETY: `ix` names an initialized chunk in the uniquely owned arena.
    // Port of `erts_sspa_create`, erl_sched_spec_pre_alloc.c, OTP-29.1.1.
    #[allow(unsafe_op_in_unsafe_fn)]
    unsafe fn init_chunk(&self, ix: usize) {
        let mut first = 0;
        let mut last = 0;
        let start = self.chunk_start(ix);
        for n in (0..self.block_count).rev() {
            let address = start + n * self.block_size;
            std::ptr::write(
                address as *mut Block,
                Block {
                    next: AtomicUsize::new(first),
                },
            );
            first = address;
            if last == 0 {
                last = address;
            }
        }
        let header_address = self.chunk_header_start(ix);
        let marker = header_address + std::mem::offset_of!(ChunkHeader, tail.marker);
        std::ptr::write(
            header_address as *mut ChunkHeader,
            ChunkHeader {
                tail: Tail {
                    marker: Block {
                        next: AtomicUsize::new(0),
                    },
                    last: AtomicUsize::new(marker),
                    um_refc: [AtomicUsize::new(0), AtomicUsize::new(0)],
                    um_refc_ix: AtomicU32::new(0),
                },
                head: std::cell::UnsafeCell::new(Head {
                    no_progress_check: 0,
                    used_marker: 1,
                    first: marker,
                    unref_end: marker,
                    next_progress: (self.progress.current)(ix),
                    next_progress_reached: 1,
                    next_um_refc_ix: 1,
                    next_unref_end: marker,
                }),
                local: std::cell::UnsafeCell::new(LocalFreeList {
                    first,
                    last,
                    count: self.block_count as i32,
                    limit: (self.block_count / 3) as i32,
                }),
            },
        );
    }

    // SAFETY: caller validated that `block` is a live node in `header`'s chunk.
    // Port of `erts_sspa_remote_free`, erl_sched_spec_pre_alloc.c, OTP-29.1.1.
    #[allow(unsafe_op_in_unsafe_fn)]
    unsafe fn remote_free(&self, header: &ChunkHeader, block: usize, cinit: isize) {
        let managed = (self.progress.is_managed)();
        let refc_ix = if managed {
            None
        } else {
            let mut ix = header.tail.um_refc_ix.load(Ordering::Acquire) as usize;
            loop {
                header.tail.um_refc[ix].fetch_add(1, Ordering::Acquire);
                let current = header.tail.um_refc_ix.load(Ordering::Acquire) as usize;
                if current == ix {
                    break Some(ix);
                }
                header.tail.um_refc[ix].fetch_sub(1, Ordering::Release);
                ix = current;
            }
        };
        self.enqueue(header, block, cinit as i32);
        if let Some(ix) = refc_ix {
            header.tail.um_refc[ix].fetch_sub(1, Ordering::Release);
        }
    }

    // SAFETY: caller owns the live block and the queue links are atomic.
    // Port of `enqueue_remote_managed_thread`, erl_sched_spec_pre_alloc.c, OTP-29.1.1.
    #[allow(unsafe_op_in_unsafe_fn)]
    unsafe fn enqueue(&self, header: &ChunkHeader, block: usize, cinit: i32) {
        let node = block as *mut Block;
        (*node).next.store(0, Ordering::Relaxed);
        let mut enq = header.tail.last.load(Ordering::Relaxed);
        let itmp = (*(enq as *mut Block)).next.compare_exchange(
            0,
            block,
            Ordering::Release,
            Ordering::Relaxed,
        );
        if let Ok(0) = itmp {
            header.tail.last.store(block, Ordering::Release);
            return;
        }
        let mut i = cinit;
        let mut previous = itmp.unwrap_err();
        loop {
            (*node).next.store(previous, Ordering::Relaxed);
            match (*(enq as *mut Block)).next.compare_exchange(
                previous,
                block,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(observed) => {
                    if i & 1 == 0 {
                        previous = observed;
                    } else {
                        enq = observed;
                        previous = (*(enq as *mut Block)).next.load(Ordering::Acquire);
                    }
                    i += 1;
                }
            }
        }
    }

    // SAFETY: called only by the thread that owns this chunk.
    // Port of `erts_sspa_process_remote_frees`, erl_sched_spec_pre_alloc.c, OTP-29.1.1.
    #[allow(unsafe_op_in_unsafe_fn)]
    unsafe fn process_remote(&self, header: &ChunkHeader, owner: usize, result: &mut usize) {
        self.fetch_remote(header, owner);
        if *result == 0 {
            let local = &mut *header.local.get();
            *result = local.first;
            if *result != 0 {
                local.first = (*(*result as *mut Block)).next.load(Ordering::Relaxed);
                local.count -= 1;
                if local.first == 0 {
                    local.last = 0;
                }
            }
        }
    }

    // SAFETY: called only by the thread that owns `header`.
    // Port of `fetch_remote`, erl_sched_spec_pre_alloc.c, OTP-29.1.1.
    #[allow(unsafe_op_in_unsafe_fn)]
    unsafe fn fetch_remote(&self, header: &ChunkHeader, owner: usize) {
        let head = &mut *header.head.get();
        let mut new_local = 0;
        if head.no_progress_check < FORCE_PROGRESS {
            head.no_progress_check += 1;
        } else {
            head.no_progress_check = 0;
            let mut last = header.tail.last.load(Ordering::Relaxed);
            let marker = std::ptr::addr_of!(header.tail.marker) as usize;
            if last == marker && head.first == marker {
                return;
            }
            let reached = head.next_progress_reached != 0
                || (self.progress.has_reached)(owner, head.next_progress);
            if reached {
                head.next_progress_reached = 1;
                let refc_ix = head.next_um_refc_ix as usize;
                if header.tail.um_refc[refc_ix].load(Ordering::Relaxed) == 0 {
                    std::sync::atomic::fence(Ordering::Acquire);
                    head.unref_end = head.next_unref_end;
                    if head.used_marker == 0 && head.unref_end == last {
                        header.tail.marker.next.store(0, Ordering::Relaxed);
                        if (*(last as *mut Block))
                            .next
                            .compare_exchange(0, marker, Ordering::Release, Ordering::Relaxed)
                            .is_ok()
                        {
                            last = marker;
                            head.used_marker = 1;
                            header.tail.last.store(marker, Ordering::Release);
                        }
                    }
                    if head.unref_end != last {
                        head.next_unref_end = last;
                        head.next_progress = progress_later((self.progress.current)(owner));
                        header
                            .tail
                            .um_refc_ix
                            .store(refc_ix as u32, Ordering::Release);
                        head.next_um_refc_ix = (refc_ix ^ 1) as i32;
                        head.next_progress_reached = 0;
                    }
                }
            }
        }
        if new_local < MAX_REMOTE && head.first != head.unref_end {
            let mut first = head.first;
            let marker = std::ptr::addr_of!(header.tail.marker) as usize;
            if first == marker {
                head.used_marker = 0;
                first = header.tail.marker.next.load(Ordering::Relaxed);
                head.first = first;
            }
            if first != head.unref_end {
                let mut this = first;
                let mut last = first;
                loop {
                    let next = (*(this as *mut Block)).next.load(Ordering::Relaxed);
                    if this == marker {
                        head.used_marker = 0;
                    } else {
                        let local = &mut *header.local.get();
                        (*(this as *mut Block)).next.store(0, Ordering::Relaxed);
                        if local.last == 0 {
                            local.first = this;
                        } else {
                            (*(local.last as *mut Block))
                                .next
                                .store(this, Ordering::Relaxed);
                        }
                        local.last = this;
                        local.count += 1;
                        new_local += 1;
                        last = this;
                    }
                    this = next;
                    if new_local >= MAX_REMOTE || this == head.unref_end {
                        break;
                    }
                }
                head.first = this;
                if new_local != 0 {
                    (*(last as *mut Block)).next.store(0, Ordering::Relaxed);
                }
            }
        }
    }

    fn ptr_to_index(&self, pointer: *mut u8) -> Option<usize> {
        let start = self.base.as_ptr() as usize
            + align_up(std::mem::size_of::<SspaDataHeader>(), CACHE_LINE)?;
        let end = start + self.chunk_size * self.threads;
        let address = pointer as usize;
        if address < start || address >= end {
            return None;
        }
        Some((address - start) / self.chunk_size)
    }

    /// Size of each preallocated block.
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    fn chunk_start(&self, ix: usize) -> usize {
        self.chunk_header_start(ix)
            + align_up(std::mem::size_of::<ChunkHeader>(), CACHE_LINE).unwrap()
    }

    fn chunk_header_start(&self, ix: usize) -> usize {
        self.base.as_ptr() as usize
            + align_up(std::mem::size_of::<SspaDataHeader>(), CACHE_LINE).unwrap()
            + ix * self.chunk_size
    }

    // SAFETY: `ix` is checked against `threads`; each chunk is aligned within the live arena.
    #[allow(unsafe_op_in_unsafe_fn)]
    unsafe fn header(&self, ix: usize) -> &ChunkHeader {
        let start = self.chunk_header_start(ix);
        &*(start as *const ChunkHeader)
    }
}

impl Drop for SspaPool {
    fn drop(&mut self) {
        crate::typed::pre_alloc_data_free(self.allocation);
    }
}

fn align_up(value: usize, alignment: usize) -> Option<usize> {
    value
        .checked_add(alignment - 1)
        .map(|v| v & !(alignment - 1))
}

#[cfg(test)]
mod tests {
    use super::{
        Block, CACHE_LINE, ChunkHeader, Head, LocalFreeList, ProgressOps, SspaPool, Tail,
        install_progress_ops,
    };
    use similar_asserts::assert_eq;
    use std::cell::Cell;
    use std::collections::HashSet;

    thread_local! {
        static MANAGED: Cell<bool> = const { Cell::new(true) };
    }

    fn current(_: usize) -> u64 {
        0
    }
    fn reached(_: usize, _: u64) -> bool {
        true
    }
    fn managed() -> bool {
        MANAGED.with(Cell::get)
    }

    #[test]
    fn remote_frees_return_to_the_owner_chunk() {
        assert_eq!(std::mem::size_of::<Block>(), 8);
        assert_eq!(std::mem::size_of::<Tail>(), CACHE_LINE);
        assert_eq!(std::mem::size_of::<Head>(), 48);
        assert_eq!(std::mem::size_of::<LocalFreeList>(), 24);
        assert_eq!(std::mem::size_of::<ChunkHeader>(), 192);
        let _ = install_progress_ops(ProgressOps {
            current,
            has_reached: reached,
            is_managed: managed,
        });
        let pool = SspaPool::new(40, 12, 1).unwrap();
        let blocks: Vec<_> = (0..12).map(|_| pool.alloc(0).unwrap()).collect();
        assert!(pool.alloc(0).is_none());
        let addresses: Vec<_> = blocks.iter().map(|block| block.as_ptr() as usize).collect();
        let pool_ref = &pool;
        std::thread::scope(|scope| {
            for (scheduler, batch) in addresses.chunks(3).enumerate() {
                scope.spawn(move || {
                    MANAGED.with(|managed| managed.set(false));
                    for address in batch {
                        let block = std::ptr::NonNull::new(*address as *mut u8).unwrap();
                        assert!(pool_ref.free(scheduler as isize + 1, block));
                    }
                });
            }
        });

        let expected: HashSet<_> = addresses.into_iter().collect();
        let mut actual = HashSet::new();
        let mut recycled = Vec::new();
        for _ in 0..256 {
            if let Some(block) = pool.alloc(0) {
                actual.insert(block.as_ptr() as usize);
                recycled.push(block);
                if actual.len() == expected.len() {
                    break;
                }
            }
        }
        assert_eq!(actual, expected);
        for block in recycled {
            assert!(pool.free(0, block));
        }
    }
}
