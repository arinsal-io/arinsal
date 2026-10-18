//! Safe alloc_util core with OTP block headers and bestfit policies. The one exception is `tn`,
//! which turns a tree link into a node pointer like the C code does.

use crate::mseg::{CacheConfig, CallCount, MsegAllocator, MsegOptions, Segment, SegmentFlags};
use crate::raw::{CarrierHeaderRef, MapError, NODE_WORDS, NodeRef, RawRegion, WordView, page_size};
use std::collections::{HashMap as StdHashMap, HashSet as StdHashSet};
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Multiplicative hasher for the integer keys of the allocator model; SipHash dominated the hot path.
#[derive(Default)]
pub(crate) struct FastHasher(u64);

impl Hasher for FastHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.write_u64(u64::from(*byte));
        }
    }

    fn write_u64(&mut self, value: u64) {
        self.0 = (self.0.rotate_left(5) ^ value).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }

    fn write_usize(&mut self, value: usize) {
        self.write_u64(value as u64);
    }
}

pub(crate) type HashMap<K, V> = StdHashMap<K, V, BuildHasherDefault<FastHasher>>;
pub(crate) type HashSet<K> = StdHashSet<K, BuildHasherDefault<FastHasher>>;

const WORD: usize = std::mem::size_of::<usize>();
const ALIGN: usize = 8;
const BLOCK_HEADER: usize = 2 * WORD;
const FOOTER: usize = WORD;
const ALLOCATOR_COUNT: usize = 11;
const FREE: usize = 1;
const PREV_FREE: usize = 2;
const LAST: usize = 4;
const SBC: usize = 2;
const MSEG_CARRIER: usize = 1;
const CARRIER_FLAGS: usize = ALIGN - 1;
const HIGH_BIT: usize = 1usize << (usize::BITS - 1);
const BLOCK_FLAGS: usize = CARRIER_FLAGS | HIGH_BIT;
const TREE_NODE: usize = 1;
const RED: usize = 2;
const TREE_FLAGS_WORD: usize = 2;
const TREE_PARENT_WORD: usize = 3;
const TREE_LEFT_WORD: usize = 4;
const TREE_RIGHT_WORD: usize = 5;
const BF_NEXT_WORD: usize = 6;
const AOFF_PARENT_WORD: usize = 2;
const AOFF_LEFT_WORD: usize = 3;
const AOFF_RIGHT_WORD: usize = 4;
const AOFF_FLAGS_WORD: usize = 5;
// GFFreeBlock_t / AFFreeBlock_t `prev` and `next` follow the free block header and carrier words.
// Port of erts/emulator/beam/erl_goodfit_alloc.c:139 (GFFreeBlock_t) and erl_afit_alloc.c:43, OTP-29.1.1.
const LIST_PREV_WORD: usize = 2;
const LIST_NEXT_WORD: usize = 3;

#[allow(dead_code)]
#[repr(C)]
struct BlockLayout {
    header: usize,
    carrier: usize,
}

#[allow(dead_code)]
#[repr(C)]
struct AoffNodeLayout {
    block: BlockLayout,
    parent: usize,
    left: usize,
    right: usize,
    flags: u32,
    max_size: u32,
    next_or_birth: usize,
}

#[allow(dead_code)]
#[repr(C)]
struct CarrierPoolLayout {
    homecoming: BlockLayout,
    next: usize,
    prev: usize,
    original_allocator: usize,
    thread_progress: u64,
    max_size: usize,
    abandon_limit: usize,
    discard_limit: usize,
    blocks: [usize; ALLOCATOR_COUNT],
    blocks_size: [usize; ALLOCATOR_COUNT],
    total_blocks_size: usize,
    state: u32,
    pooled_tree_node: AoffNodeLayout,
}

#[allow(dead_code)]
#[repr(C)]
struct CarrierLayout {
    header: usize,
    next: usize,
    prev: usize,
    allocator: usize,
    cpool: CarrierPoolLayout,
    aoff_tree_node: AoffNodeLayout,
    root: usize,
    blk_order: u32,
    index: u32,
}

const AOFF_ROOT_WORD: usize = (std::mem::offset_of!(CarrierLayout, root)) / WORD;
const AOFF_BLK_ORDER_WORD: usize = (std::mem::offset_of!(CarrierLayout, blk_order)) / WORD;
const AOFF_INDEX_SHIFT: u32 = 8
    * (std::mem::offset_of!(CarrierLayout, index) - std::mem::offset_of!(CarrierLayout, blk_order))
        as u32;
const AOFF_ROOT_BYTE: usize = std::mem::offset_of!(CarrierLayout, root);
const MBC_HEADER: usize = std::mem::offset_of!(CarrierLayout, aoff_tree_node);
const AOFF_MBC_HEADER: usize = std::mem::size_of::<CarrierLayout>();
const SBC_HEADER: usize =
    align_const(std::mem::offset_of!(CarrierLayout, cpool) + BLOCK_HEADER) - BLOCK_HEADER;
const RB_NODE_SIZE: usize = std::mem::size_of::<BlockLayout>() + 4 * WORD;
const BF_NODE_SIZE: usize = RB_NODE_SIZE + WORD;

const fn align_const(value: usize) -> usize {
    (value + ALIGN - 1) & !(ALIGN - 1)
}

/// Placement policy used by the bestfit allocator family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Strategy {
    /// Best fit, with address as a deterministic tie breaker.
    BestFit,
    /// Address-order best fit, choosing the lowest address among equal fits.
    AddressOrderBestFit,
    /// Address ordered first fit.
    Aoff,
    /// Address ordered first fit within best fit carrier ordering.
    AoffCbf,
    /// Address ordered first fit within address ordered best fit carrier ordering.
    AoffCaobf,
    /// Segregated bucket search with bounded search depth.
    GoodFit,
    /// Largest-fit-first free-list policy used for short-lived allocations.
    Afit,
}

/// Carrier thresholds and growth options (byte quantities unless noted).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct AllocUtilOptions {
    /// Abandon carriers below this utilization, as a percent (`acul`).
    pub acul: usize,
    /// Maximum carriers kept in the shared pool (`acnl`).
    pub acnl: usize,
    /// Shared carrier pool group (`cp`).
    pub cpool: Option<char>,
    pub sbct: usize,
    pub asbcst: usize,
    pub rsbcst: usize,
    pub rsbcmt: usize,
    pub rmbcmt: usize,
    pub mmbcs: usize,
    pub mmsbc: usize,
    pub mmmbc: usize,
    pub lmbcs: usize,
    pub smbcs: usize,
    pub mbcgs: usize,
    /// Maximum free blocks inspected in a GoodFit bucket (`mbsd`).
    pub max_bucket_search: usize,
    /// Discard free blocks below this utilization, as a percent (`acful`).
    pub acful: usize,
    /// Minimum free block size retained in the pool (`acfml`).
    pub acfml: usize,
}

impl Default for AllocUtilOptions {
    fn default() -> Self {
        Self {
            sbct: 512 * 1024,
            asbcst: 4_145_152,
            rsbcst: 50,
            rsbcmt: 80,
            rmbcmt: 50,
            mmbcs: 131_072,
            mmsbc: 256,
            mmmbc: usize::MAX,
            lmbcs: 5 * 1024 * 1024,
            smbcs: 256 * 1024,
            mbcgs: 10,
            max_bucket_search: 3,
            acul: 0,
            acful: 0,
            acnl: 0,
            acfml: 0,
            cpool: None,
        }
    }
}

/// Stable identifier for an allocated user block.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Allocation {
    id: u64,
    size: usize,
}

impl Allocation {
    pub(crate) fn from_parts(id: u64, size: usize) -> Self {
        Self { id, size }
    }

    pub(crate) fn id(self) -> u64 {
        self.id
    }

    /// Address of the payload: the block header address plus the header size.
    pub(crate) fn payload_address(self) -> usize {
        self.id as usize + BLOCK_HEADER
    }

    /// Payload size in bytes as requested.
    pub(crate) fn size(self) -> usize {
        self.size
    }
}

/// Current and peak allocated block and carrier counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct AllocStats {
    pub alloc_calls: u64,
    pub free_calls: u64,
    pub realloc_calls: u64,
    pub carriers: usize,
    pub carriers_size: usize,
    pub max_carriers: usize,
    pub max_carriers_size: usize,
    pub mseg_carriers: usize,
    pub sys_alloc_carriers: usize,
    pub mseg_carriers_size: usize,
    pub sys_alloc_carriers_size: usize,
    pub max_mseg_carriers: usize,
    pub max_sys_alloc_carriers: usize,
    pub max_mseg_carriers_size: usize,
    pub max_sys_alloc_carriers_size: usize,
    pub mseg_alloc_calls: u64,
    pub mseg_dealloc_calls: u64,
    pub sys_alloc_calls: u64,
    pub sys_free_calls: u64,
    pub mseg_realloc_calls: u64,
    pub sys_realloc_calls: u64,
    pub max_ever_carriers: usize,
    pub max_ever_carriers_size: usize,
    pub max_ever_mseg_carriers: usize,
    pub max_ever_sys_alloc_carriers: usize,
    pub max_ever_mseg_carriers_size: usize,
    pub max_ever_sys_alloc_carriers_size: usize,
}

/// Current carrier and allocated-block totals for one carrier class.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AllocatorClassInfo {
    pub blocks: usize,
    pub blocks_size: usize,
    pub carriers: usize,
    pub carriers_size: usize,
    pub mseg_alloc_carriers: usize,
    pub sys_alloc_carriers: usize,
    pub mseg_alloc_carriers_size: usize,
    pub sys_alloc_carriers_size: usize,
    pub blocks_max: usize,
    pub blocks_size_max: usize,
    pub blocks_max_ever: usize,
    pub blocks_size_max_ever: usize,
    pub carriers_max: usize,
    pub carriers_size_max: usize,
    pub carriers_max_ever: usize,
    pub carriers_size_max_ever: usize,
    pub mseg_alloc_carriers_max: usize,
    pub mseg_alloc_carriers_size_max: usize,
    pub mseg_alloc_carriers_max_ever: usize,
    pub mseg_alloc_carriers_size_max_ever: usize,
    pub sys_alloc_carriers_max: usize,
    pub sys_alloc_carriers_size_max: usize,
    pub sys_alloc_carriers_max_ever: usize,
    pub sys_alloc_carriers_size_max_ever: usize,
}

/// Rust data form of the alloc_util `system_info({allocator, A})` sections.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocatorInfo {
    pub instance: usize,
    pub version: (&'static str, &'static str),
    pub allocation_type: &'static str,
    pub strategy: Strategy,
    pub options: AllocUtilOptions,
    pub mbcs: AllocatorClassInfo,
    pub sbcs: AllocatorClassInfo,
    pub calls: AllocStats,
    pub call_counts: AllocatorCallCounts,
    /// Shared carrier pool counters, present when `cp`/`acul` enable pooling.
    pub mbcs_pool: Option<CarrierPoolStats>,
}

/// `{mbcs_pool, ...}` counters exposed by allocator information.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CarrierPoolStats {
    pub carriers: usize,
    pub carriers_size: usize,
    pub blocks: usize,
    pub blocks_size: usize,
    pub entrance_removed: CallCount,
    pub skip_race: CallCount,
    pub skip_homecoming: CallCount,
    pub skip_not_pooled: CallCount,
    pub skip_busy: CallCount,
    pub skip_size: CallCount,
    pub fetch: CallCount,
    pub fail: CallCount,
    pub fail_pend_dealloc: CallCount,
    pub fail_shared: CallCount,
    pub fail_pooled: CallCount,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Block {
    carrier: usize,
    offset: usize,
    size: usize,
    allocated: bool,
    prev_free: bool,
    last: bool,
}

/// Which red-black tree a node belongs to: the free-block tree of one carrier (the single
/// bestfit tree for the non-aoff strategies), or the aoff carrier tree.
#[derive(Clone, Copy)]
enum TreeId {
    Carriers,
    Blocks,
}

const _: () = assert!(cfg!(target_endian = "little"));

/// A free-block tree node (aoff red-black tree or bestfit tree) with the strategy's field layout:
/// `A` selects the aoff layout, where `flags` and `max_sz` share a word as two 32-bit halves.
/// Port of `AOFF_RBTree_t`/`RBTree_t`, erl_ao_firstfit_alloc.c and erl_bestfit_alloc.c.
#[derive(Clone, Copy)]
struct TNode<const A: bool> {
    raw: NodeRef,
}

impl<const A: bool> TNode<A> {
    const PARENT: usize = if A {
        AOFF_PARENT_WORD
    } else {
        TREE_PARENT_WORD
    };
    const LEFT: usize = if A { AOFF_LEFT_WORD } else { TREE_LEFT_WORD };
    const RIGHT: usize = if A { AOFF_RIGHT_WORD } else { TREE_RIGHT_WORD };
    const FLAGS: usize = if A { AOFF_FLAGS_WORD } else { TREE_FLAGS_WORD };

    #[inline(always)]
    fn key(self) -> usize {
        self.raw.key()
    }
    #[inline(always)]
    fn parent(self) -> usize {
        self.raw.word(Self::PARENT)
    }
    #[inline(always)]
    fn left(self) -> usize {
        self.raw.word(Self::LEFT)
    }
    #[inline(always)]
    fn right(self) -> usize {
        self.raw.word(Self::RIGHT)
    }
    #[inline(always)]
    fn set_parent(self, value: usize) {
        self.raw.set_word(Self::PARENT, value)
    }
    #[inline(always)]
    fn set_left(self, value: usize) {
        self.raw.set_word(Self::LEFT, value)
    }
    #[inline(always)]
    fn set_right(self, value: usize) {
        self.raw.set_word(Self::RIGHT, value)
    }
    #[inline(always)]
    fn flags(self) -> usize {
        if A {
            self.raw.load::<u32>(Self::FLAGS * WORD) as usize
        } else {
            self.raw.word(Self::FLAGS)
        }
    }
    /// Sets the color/node bits; the aoff `max_sz` in the upper half is kept.
    #[inline(always)]
    fn set_flags(self, value: usize) {
        if A {
            self.raw.store::<u32>(Self::FLAGS * WORD, value as u32);
        } else {
            self.raw.set_word(Self::FLAGS, value);
        }
    }
    #[inline(always)]
    fn is_red(self) -> bool {
        self.flags() & RED != 0
    }
    /// SET_RED of erl_ao_firstfit_alloc.c.
    #[inline(always)]
    fn set_red(self) {
        self.set_flags(self.flags() | RED);
    }
    /// SET_BLACK of erl_ao_firstfit_alloc.c.
    #[inline(always)]
    fn set_black(self) {
        self.set_flags(self.flags() & !RED);
    }
    #[inline(always)]
    fn size(self) -> usize {
        self.raw.word(0) & !BLOCK_FLAGS
    }
    #[inline(always)]
    fn max(self) -> usize {
        self.raw.load::<u32>(AOFF_FLAGS_WORD * WORD + 4) as usize
    }
    #[inline(always)]
    fn set_max(self, max_size: usize) {
        self.raw
            .store::<u32>(AOFF_FLAGS_WORD * WORD + 4, max_size as u32);
    }
    #[inline(always)]
    fn next(self) -> usize {
        self.raw.word(BF_NEXT_WORD)
    }
    #[inline(always)]
    fn set_next(self, value: usize) {
        self.raw.set_word(BF_NEXT_WORD, value)
    }
}

/// One indexed carrier's address range: the cached answer to "which carrier holds this
/// address". Block keys are addresses, so a key's words are read straight from the range.
#[derive(Clone, Copy)]
struct CarrierSpan {
    start: usize,
    end: usize,
    node_limit: usize,
    index: usize,
    sbc: bool,
}

impl CarrierSpan {
    const EMPTY: Self = Self::new(0, 0, usize::MAX, false);

    /// The number of byte offsets of `[start, end)` at which a whole tree node still fits.
    #[inline(always)]
    const fn node_limit(start: usize, end: usize) -> usize {
        (end - start + 1).saturating_sub(NODE_WORDS * WORD)
    }

    /// The span `[start, end)` of carrier `index`.
    #[inline(always)]
    const fn new(start: usize, end: usize, index: usize, sbc: bool) -> Self {
        Self {
            start,
            end,
            node_limit: Self::node_limit(start, end),
            index,
            sbc,
        }
    }

    /// The carrier's words. A span exists only while its carrier is indexed, and a carrier
    /// is unindexed (dropping the cached span) before its memory moves or is released.
    #[inline(always)]
    fn words(self) -> WordView {
        WordView::new(self.start as *mut u64, (self.end - self.start) / WORD)
    }

    /// Whether the word at address `addr` lies inside the carrier and is word aligned.
    #[inline(always)]
    fn holds(self, addr: usize) -> bool {
        addr.is_multiple_of(WORD) && addr >= self.start && addr + WORD <= self.end
    }

    /// The word at address `addr` of the carrier, a block header word, size footer or free
    /// block field, as one plain load like the pointer dereference of the C code.
    ///
    /// The allocator derives `addr` from the header words and footers it wrote itself (block
    /// address, plus block size, or minus the size in a footer) and from addresses it took out
    /// of its free index, so every `addr` lies inside the carrier; debug builds check it.
    #[inline(always)]
    #[allow(unsafe_code)]
    fn load(self, addr: usize) -> usize {
        debug_assert!(self.holds(addr), "word {addr:#x} outside {:#x}", self.start);
        // SAFETY: `addr` is word aligned and inside a carrier that is indexed, and so mapped
        // read-write, while this span exists: a carrier is unindexed, dropping its spans,
        // before its memory moves or is released.
        unsafe { (addr as *const usize).read() }
    }

    /// Stores the word `value` at address `addr` of the carrier; see `load`.
    #[inline(always)]
    #[allow(unsafe_code)]
    fn store(self, addr: usize, value: usize) {
        debug_assert!(self.holds(addr), "word {addr:#x} outside {:#x}", self.start);
        // SAFETY: as in `load`; the allocator owns its carriers exclusively while it is
        // borrowed mutably, and every caller of `store` holds `&mut AllocUtil`.
        unsafe { (addr as *mut usize).write(value) }
    }

    #[inline(always)]
    fn read(self, key: usize, word: usize) -> Option<usize> {
        self.words()
            .as_slice()
            .get((key - self.start) / WORD + word)
            .map(|&value| value as usize)
    }

    #[inline(always)]
    fn write(self, key: usize, word: usize, value: usize) -> Option<()> {
        *self
            .words()
            .as_mut_slice()
            .get_mut((key - self.start) / WORD + word)? = value as u64;
        Some(())
    }
}

struct Carrier {
    memory: CarrierMemory,
    sbc: bool,
    mseg: bool,
    in_aoff_tree: bool,
    main: bool,
    origin_instance: usize,
    key_base: usize,
    start: usize,
    size: usize,
    /// Sum of this carrier's allocated block sizes (`cpool.total_blocks_size`), kept incrementally.
    blocks_size: usize,
    /// `cpool.abandon_limit`, fixed when the carrier is created.
    abandon_limit: usize,
    /// `cpool.discard_limit`, fixed when the carrier is created.
    discard_limit: usize,
}

/// Port of cpoll_init_carrier_limit and allctr_abandon_limit, erl_alloc_util.c, OTP-29.1.1.
fn percent_limit(size: usize, percent: usize) -> usize {
    let limit = size.wrapping_mul(percent);
    if limit > size {
        limit / 100
    } else {
        (size / 100) * percent
    }
}

pub(crate) struct CarrierTransfer {
    pub(crate) origin_instance: usize,
    carrier: Carrier,
    blocks: Vec<Block>,
    allocations: Vec<(Allocation, usize)>,
}

impl CarrierTransfer {
    pub(crate) fn allocations(&self) -> &[(Allocation, usize)] {
        &self.allocations
    }

    pub(crate) fn origin_instance(&self) -> usize {
        self.origin_instance
    }

    pub(crate) fn pool_summary(&self) -> (usize, usize, usize) {
        let (blocks, blocks_size) = self
            .allocations
            .iter()
            .fold((0, 0), |(count, size), (allocation, _)| {
                (count + 1, size + allocation.size)
            });
        (self.carrier.size, blocks, blocks_size)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct ValueSeries {
    current: usize,
    max: usize,
    max_ever: usize,
}

#[derive(Clone, Copy, Debug, Default)]
struct ClassStats {
    blocks: ValueSeries,
    blocks_size: ValueSeries,
    carriers: ValueSeries,
    carriers_size: ValueSeries,
    mseg_carriers: ValueSeries,
    mseg_carriers_size: ValueSeries,
    sys_carriers: ValueSeries,
    sys_carriers_size: ValueSeries,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AllocatorCallCounts {
    pub alloc: CallCount,
    pub free: CallCount,
    pub realloc: CallCount,
    pub mseg_alloc: CallCount,
    pub mseg_dealloc: CallCount,
    pub mseg_realloc: CallCount,
    pub sys_alloc: CallCount,
    pub sys_free: CallCount,
    pub sys_realloc: CallCount,
}

enum CarrierMemory {
    Mapped(RawRegion),
    Arena(RawRegion),
    Segmented(Segment),
}

impl CarrierMemory {
    #[inline(always)]
    fn len(&self) -> usize {
        match self {
            Self::Mapped(region) => region.len(),
            Self::Arena(region) => region.len(),
            Self::Segmented(segment) => segment.len(),
        }
    }
    #[inline(always)]
    fn as_ptr(&self) -> *mut u8 {
        match self {
            Self::Mapped(region) => region.as_ptr(),
            Self::Arena(region) => region.as_ptr(),
            Self::Segmented(segment) => segment.as_ptr(),
        }
    }
    /// The carrier as words. Carriers are mapped read-write for their whole life (no
    /// carrier is ever re-protected), so the word view needs no protection check.
    #[inline(always)]
    fn words(&self) -> WordView {
        WordView::new(self.as_ptr().cast(), self.len() / WORD)
    }
    #[inline(always)]
    fn read_word(&self, offset: usize) -> Option<usize> {
        if !offset.is_multiple_of(WORD) {
            return None;
        }
        self.words()
            .read_word(offset / WORD)
            .map(|word| word as usize)
    }
    #[inline(always)]
    fn write_word(&mut self, offset: usize, value: usize) -> bool {
        if !offset.is_multiple_of(WORD) {
            return false;
        }
        // Port of the direct block header stores in erts/emulator/beam/erl_alloc_util.c:302-314,
        // OTP-29.1.1; the bounded raw view avoids constructing a slice per word.
        self.words().write_word(offset / WORD, value as u64)
    }
    fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Mapped(region) => region.bytes(),
            Self::Arena(region) => region.bytes(),
            Self::Segmented(segment) => segment.bytes(),
        }
    }
    fn bytes_mut(&mut self) -> Option<&mut [u8]> {
        match self {
            Self::Mapped(region) => region.bytes_mut(),
            Self::Arena(region) => region.bytes_mut(),
            Self::Segmented(segment) => segment.bytes_mut(),
        }
    }
    fn advise_range(&mut self, offset: usize, len: usize, advice: i32) -> Result<(), MapError> {
        match self {
            Self::Mapped(region) => region.advise_range(offset, len, advice),
            Self::Arena(region) => region.advise_range(offset, len, advice),
            Self::Segmented(segment) => segment.advise_range(offset, len, advice),
        }
    }
}

/// Free extents of the literal super-carrier, split into alloc_util carriers on demand.
/// Port of `erts_alcu_mmapper_mseg_alloc` / `erts_alcu_mmapper_mseg_dealloc`,
/// `erl_alloc_util.c:1049-1083`, OTP-29.1.1.
struct CarrierArena {
    free: Vec<RawRegion>,
}

impl CarrierArena {
    fn new(region: RawRegion) -> Self {
        Self { free: vec![region] }
    }

    fn allocate(&mut self, requested: usize) -> Result<RawRegion, AllocError> {
        let page = page_size();
        let size = requested
            .checked_add(page - 1)
            .ok_or(AllocError::Overflow)?
            & !(page - 1);
        let index = self
            .free
            .iter()
            .position(|region| region.len() >= size)
            .ok_or(AllocError::NoSpace)?;
        let region = self.free.remove(index);
        if region.len() == size {
            return Ok(region);
        }
        let (allocated, tail) = region.split_at(size).map_err(|_| AllocError::Corrupt)?;
        self.free.push(tail);
        self.sort_and_coalesce();
        Ok(allocated)
    }

    fn release(&mut self, region: RawRegion) {
        self.free.push(region);
        self.sort_and_coalesce();
    }

    fn sort_and_coalesce(&mut self) {
        self.free
            .sort_unstable_by_key(|region| region.as_ptr() as usize);
        let mut merged: Vec<RawRegion> = Vec::with_capacity(self.free.len());
        for region in std::mem::take(&mut self.free) {
            if let Some(previous) = merged.pop() {
                match previous.merge_adjacent(region) {
                    Ok(joined) => merged.push(joined),
                    Err((previous, region)) => {
                        merged.push(previous);
                        merged.push(region);
                    }
                }
            } else {
                merged.push(region);
            }
        }
        self.free = merged;
    }
}

/// Intrusive GoodFit bucket or AFit free list whose links live in the free blocks.
#[derive(Clone, Copy)]
enum FreeListId {
    Bucket(usize),
    Afit,
}

/// Applies a dynamic `sbct` to the cell of an allocator of `strategy`; false when refused.
///
/// Port of `erts_alcu_try_set_dyn_param` (erl_alloc_util.c, `adjust_sbct`) and
/// `gfalc_try_set_dyn_param` (erl_goodfit_alloc.c), OTP-29.1.1: the threshold is one word that any
/// thread may write. Goodfit cannot rearrange its buckets and refuses.
pub(crate) fn set_dyn_sbct(strategy: Strategy, cell: &AtomicUsize, value: usize) -> bool {
    const MIN_DYN_SBCT: usize = 4000;
    if strategy == Strategy::GoodFit || value < MIN_DYN_SBCT {
        return false;
    }
    cell.store(value, Ordering::Relaxed);
    true
}

/// One safe, single-threaded alloc_util instance.
///
/// Port of `erts/emulator/beam/erl_alloc_util.c` allocator state, OTP-29.1.1.
#[repr(C)]
pub struct AllocUtil {
    strategy: Strategy,
    pool_managed: bool,
    /// Whether `check_abandon_carrier` can ever act: abandoning is enabled by the options, the
    /// instance is pool managed and the strategy is an aoff one. Fixed at creation, so a free
    /// on an instance without a carrier pool tests one byte next to the strategy.
    abandon: bool,
    /// `cpool.abandon_limit` of erl_alloc_util.c: `acul` percent of the multiblock carrier bytes.
    abandon_limit: usize,
    #[cfg(test)]
    carrier_walks: std::cell::Cell<usize>,
    #[cfg(test)]
    verify_abandon_by_walk: bool,
    instance_index: usize,
    /// Number of live multiblock carriers.
    mbc_count: usize,
    /// Dynamic `sbct`, shared with the instance registry so another thread can set it without
    /// reaching into the allocator (`sbc_threshold` word of erl_alloc_util.c, OTP-29.1.1).
    dyn_sbct: Arc<AtomicUsize>,
    /// Last `carrier_ranges` hit; consecutive header accesses nearly always stay in one carrier.
    last_carrier: std::cell::Cell<CarrierSpan>,
    /// Carrier of the block tree being walked. Every node of a block tree lives in the carrier
    /// of its root, so a walk resolves the carrier once and `tn` then checks each node against it
    /// with one compare, instead of looking the node's carrier up again.
    tree_span: std::cell::Cell<CarrierSpan>,
    free_root: usize,
    aoff_carrier_root: usize,
    carriers: Vec<Option<Carrier>>,
    /// `(start, end, index)` of every live carrier sorted by address: block address to carrier,
    /// standing in for erts' carrier pointer arithmetic (erl_alloc_util.h:430 FBLK_TO_MBC/ABLK_TO_MBC).
    carrier_ranges: Vec<(usize, usize, usize)>,
    pending_carriers: Vec<CarrierTransfer>,
    options: AllocUtilOptions,
    stats: AllocStats,
    class_stats: [ClassStats; 2],
    allocation_type: &'static str,
    /// Vacated `carriers` slots, reused so churn does not grow the table.
    free_carrier_slots: Vec<usize>,
    /// Bucket list heads (`buckets` in erl_goodfit_alloc.c); 0 is an empty bucket.
    goodfit_heads: Vec<usize>,
    /// Bit per non-empty goodfit bucket, like `bucket_mask` in erl_goodfit_alloc.c.
    goodfit_mask: [u64; 4],
    /// `bkt_intrvl_d` of erl_goodfit_alloc.c, derived from `sbct`.
    goodfit_interval_d: usize,
    /// `free_list` head of erl_afit_alloc.c; 0 is empty.
    afit_head: usize,
    mseg: MsegAllocator,
    carrier_arena: Option<CarrierArena>,
}

impl AllocUtil {
    fn mbc_header_size(&self) -> usize {
        if is_aoff(self.strategy) {
            AOFF_MBC_HEADER
        } else {
            MBC_HEADER
        }
    }

    /// Creates an allocator instance with the requested OTP bestfit policy.
    /// Port of `erts_bfalc_start`, `erl_bestfit_alloc.c:184`, OTP-29.1.1.
    pub fn new(strategy: Strategy, options: AllocUtilOptions) -> Self {
        Self::new_for_type(strategy, options, "eheap_alloc")
    }

    /// Creates an instance whose stats are tagged with its OTP allocation type.
    pub fn new_for_type(
        strategy: Strategy,
        options: AllocUtilOptions,
        allocation_type: &'static str,
    ) -> Self {
        Self::new_for_instance(strategy, options, allocation_type, 0, false)
    }

    pub(crate) fn new_for_instance(
        strategy: Strategy,
        options: AllocUtilOptions,
        allocation_type: &'static str,
        instance_index: usize,
        pool_managed: bool,
    ) -> Self {
        Self {
            strategy,
            options,
            allocation_type,
            instance_index,
            pool_managed,
            abandon: options.acul != 0
                && options.acnl != 0
                && options.cpool.is_some()
                && pool_managed
                && is_aoff(strategy),
            abandon_limit: 0,
            #[cfg(test)]
            carrier_walks: std::cell::Cell::new(0),
            #[cfg(test)]
            verify_abandon_by_walk: true,
            carriers: Vec::new(),
            free_carrier_slots: Vec::new(),
            mbc_count: 0,
            carrier_ranges: Vec::new(),
            last_carrier: std::cell::Cell::new(CarrierSpan::EMPTY),
            tree_span: std::cell::Cell::new(CarrierSpan::EMPTY),
            free_root: 0,
            aoff_carrier_root: 0,
            goodfit_heads: vec![0; 256],
            goodfit_mask: [0; 4],
            goodfit_interval_d: goodfit_interval_d(options.sbct),
            afit_head: 0,
            dyn_sbct: Arc::new(AtomicUsize::new(options.sbct)),
            stats: AllocStats::default(),
            class_stats: [ClassStats::default(); 2],
            mseg: MsegAllocator::new(0, CacheConfig::default()),
            pending_carriers: Vec::new(),
            carrier_arena: None,
        }
    }

    /// Creates OTP's non-thread-specific literal allocator inside its reserved super-carrier.
    ///
    /// Port of `set_default_literal_alloc_opts`, `erl_alloc.c:287-310`, and the literal
    /// mmapper binding, `erl_alloc.c:333`, OTP-29.1.1.
    pub fn new_literal_alloc(region: RawRegion) -> Self {
        let options = AllocUtilOptions {
            sbct: usize::MAX,
            mmsbc: 0,
            mmbcs: 1024 * 1024,
            ..AllocUtilOptions::default()
        };
        let mut allocator =
            Self::new_for_type(Strategy::AddressOrderBestFit, options, "literal_alloc");
        allocator.carrier_arena = Some(CarrierArena::new(region));
        allocator
    }

    /// Dynamic `sbct` update.
    // Port of erts/emulator/beam/erl_alloc_util.c (erts_alcu_try_set_dyn_param, adjust_sbct) and
    // erl_goodfit_alloc.c (gfalc_try_set_dyn_param, which cannot rearrange its buckets), OTP-29.1.1.
    pub fn try_set_dyn_sbct(&mut self, value: usize) -> bool {
        set_dyn_sbct(self.strategy, &self.dyn_sbct, value)
    }

    /// The cell holding the current `sbct`, writable from any thread through [`set_dyn_sbct`].
    pub(crate) fn sbct_cell(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.dyn_sbct)
    }

    #[inline(always)]
    fn sbct(&self) -> usize {
        self.dyn_sbct.load(Ordering::Relaxed)
    }

    /// Bytes in allocated blocks, for the registry's lock-free mirror.
    #[inline(always)]
    pub(crate) fn blocks_size(&self) -> usize {
        self.class_stats[0].blocks_size.current + self.class_stats[1].blocks_size.current
    }

    /// Number of allocated blocks, multiblock and single-block carriers together.
    pub fn block_count(&self) -> usize {
        self.class_stats[0].blocks.current + self.class_stats[1].blocks.current
    }

    /// Allocates a payload of `size` bytes.
    /// Port of `erts_alcu_alloc`, `erl_alloc_util.c:2377`, OTP-29.1.1.
    #[inline]
    pub fn alloc(&mut self, size: usize) -> Result<Allocation, AllocError> {
        self.stats.alloc_calls += 1;
        let block_size = block_size(size, self.strategy)?;
        if block_size >= self.sbct() {
            return self.alloc_sbc(size, block_size);
        }
        let chosen = if is_aoff(self.strategy) {
            self.choose_aoff_span(block_size)
        } else {
            self.choose_free_span(block_size)?
        };
        let (offset, span) = match chosen {
            Some(chosen) => chosen,
            None => self.new_mbc_block(block_size)?,
        };
        let used = self.mbc_alloc(span, offset, block_size)?;
        self.block_added(false, used);
        self.carrier_blk_alloc(span.index, used)?;
        Ok(Allocation {
            id: offset as u64,
            size,
        })
    }

    /// Port of mbc_alloc_finalize, erl_alloc_util.c, OTP-29.1.1: the free block at `offset`, of
    /// the indexed carrier `span`, is taken off the free index and its header word is rewritten
    /// in place with masks. The block is split when the remainder can hold a free block, else it
    /// is used whole and the PREV_FREE flag of its successor is cleared. Returns the block size.
    #[inline(always)]
    fn mbc_alloc(
        &mut self,
        span: CarrierSpan,
        offset: usize,
        block_size: usize,
    ) -> Result<usize, AllocError> {
        let header = span.load(offset);
        let actual = header & !BLOCK_FLAGS;
        debug_assert!(header & FREE != 0 && actual >= block_size);
        self.unlink_free_in(span, offset, actual)?;
        let last = header & LAST;
        let prev_free = header & PREV_FREE;
        let remainder = actual - block_size;
        if remainder >= min_block_size(self.strategy) {
            let tail = offset + block_size;
            span.store(offset, block_size | prev_free);
            span.store(tail, remainder | FREE | last);
            span.store(tail + WORD, span.start);
            if last == 0 {
                span.store(tail + remainder - WORD, remainder);
            }
            debug_assert!(last != 0 || span.load(tail + remainder) & PREV_FREE != 0);
            self.link_free_in(span, tail, remainder)?;
            Ok(block_size)
        } else {
            span.store(offset, actual | prev_free | last);
            if last == 0 {
                let next = offset + actual;
                span.store(next, span.load(next) & !PREV_FREE);
            }
            Ok(actual)
        }
    }

    /// A single-block carrier for one allocation of `block_size`.
    #[cold]
    #[inline(never)]
    fn alloc_sbc(&mut self, size: usize, block_size: usize) -> Result<Allocation, AllocError> {
        let start = self.add_sbc(block_size)?;
        self.block_added(true, block_size);
        Ok(Allocation {
            id: start as u64,
            size,
        })
    }

    /// A new multiblock carrier whose one free block serves a request no free block could.
    #[cold]
    #[inline(never)]
    fn new_mbc_block(&mut self, block_size: usize) -> Result<(usize, CarrierSpan), AllocError> {
        let ci = self.add_mbc(block_size)?;
        let start = self.carriers[ci].as_ref().ok_or(AllocError::Corrupt)?.start;
        Ok((start, self.span_of(start).ok_or(AllocError::Corrupt)?))
    }

    /// Frees a live allocation and merges adjacent free MBC blocks.
    /// Port of `erts_alcu_free`, `erl_alloc_util.c:2820`, OTP-29.1.1.
    #[inline]
    pub fn free(&mut self, allocation: Allocation) -> Result<(), AllocError> {
        self.stats.free_calls += 1;
        let key = allocation.id as usize;
        let span = self.span_of(key).ok_or(AllocError::InvalidAllocation)?;
        if span.sbc {
            return self.free_sbc(span, key);
        }
        if key < span.start + self.mbc_header_size() || !span.holds(key) {
            return Err(AllocError::InvalidAllocation);
        }
        let header = span.load(key);
        let size = header & !BLOCK_FLAGS;
        if header & FREE != 0 || size == 0 {
            return Err(AllocError::InvalidAllocation);
        }
        self.block_removed(false, size);
        self.mbc_free(span, key, header)
    }

    /// Port of mbc_free, erl_alloc_util.c, OTP-29.1.1: the block at `key` with header word
    /// `header` merges with a free predecessor (found through its size footer) and a free
    /// successor, all on header words, and the result is linked into the free index, or its
    /// carrier is destroyed when it became the one empty block of a non-main carrier.
    #[inline(always)]
    fn mbc_free(&mut self, span: CarrierSpan, key: usize, header: usize) -> Result<(), AllocError> {
        let mut start = key;
        let mut size = header & !BLOCK_FLAGS;
        self.carrier_blk_free(span.index, size)?;
        let mut prev_free = header & PREV_FREE;
        let mut last = header & LAST;
        if prev_free != 0 {
            let footer = span.load(key - WORD);
            debug_assert!(footer != 0 && footer <= key - span.start - self.mbc_header_size());
            let prev = key - footer;
            let prev_header = span.load(prev);
            if prev_header & FREE != 0 {
                self.unlink_free_in(span, prev, footer)?;
                start = prev;
                size += footer;
                prev_free = prev_header & PREV_FREE;
            }
        }
        let mut next_free = false;
        if last == 0 {
            let next = start + size;
            let next_header = span.load(next);
            if next_header & FREE != 0 {
                let next_size = next_header & !BLOCK_FLAGS;
                self.unlink_free_in(span, next, next_size)?;
                size += next_size;
                last = next_header & LAST;
                next_free = true;
            }
        }
        if last != 0
            && start == span.start + self.mbc_header_size()
            && !self.carriers[span.index]
                .as_ref()
                .ok_or(AllocError::Corrupt)?
                .main
        {
            return self.remove_carrier(span.index);
        }
        span.store(start, size | FREE | prev_free | last);
        span.store(start + WORD, span.start);
        if last == 0 {
            span.store(start + size - WORD, size);
            if !next_free {
                let next = start + size;
                span.store(next, span.load(next) | PREV_FREE);
            }
        }
        self.link_free_in(span, start, size)?;
        self.check_abandon_carrier(span)
    }

    /// Frees the block of a single-block carrier, which destroys the carrier.
    #[cold]
    #[inline(never)]
    fn free_sbc(&mut self, span: CarrierSpan, key: usize) -> Result<(), AllocError> {
        if key != span.start + SBC_HEADER || !span.holds(key) {
            return Err(AllocError::InvalidAllocation);
        }
        let size = span.load(key) & !BLOCK_FLAGS;
        if size == 0 {
            return Err(AllocError::InvalidAllocation);
        }
        self.block_removed(true, size);
        self.remove_carrier(span.index)
    }

    /// Returns the stable payload address while `allocation` remains allocated.
    pub fn allocation_ptr(&self, allocation: Allocation) -> Result<*mut u64, AllocError> {
        self.live_block(allocation.id as usize)?;
        Ok(self.payload_address(allocation))
    }

    /// Returns an exclusive byte view of the requested payload while this allocator is borrowed.
    pub fn allocation_bytes_mut(
        &mut self,
        allocation: Allocation,
    ) -> Result<&mut [u8], AllocError> {
        let block = self.live_block(allocation.id as usize)?;
        let carrier = self
            .carriers
            .get_mut(block.carrier)
            .and_then(Option::as_mut)
            .ok_or(AllocError::Corrupt)?;
        let start = block
            .offset
            .checked_sub(carrier.key_base)
            .and_then(|offset| offset.checked_add(BLOCK_HEADER))
            .ok_or(AllocError::Corrupt)?;
        let end = start
            .checked_add(allocation.size)
            .ok_or(AllocError::Overflow)?;
        carrier
            .memory
            .bytes_mut()
            .and_then(|bytes| bytes.get_mut(start..end))
            .ok_or(AllocError::Corrupt)
    }

    /// Payload address of an allocation this instance returned and has not freed.
    ///
    /// Port of `BLK2UMEM`, erl_alloc_util.h, OTP-29.1.1: the payload follows the block header.
    #[inline(always)]
    pub(crate) fn payload_address(&self, allocation: Allocation) -> *mut u64 {
        let key = allocation.id as usize;
        debug_assert!(self.span_of(key).is_some());
        (key + BLOCK_HEADER) as *mut u64
    }

    /// Carrier index containing the address `key`.
    #[inline(always)]
    fn carrier_of(&self, key: usize) -> Option<usize> {
        self.span_of(key).map(|span| span.index)
    }

    /// The indexed carrier holding address `key`, from the one-entry cache when it hits.
    #[inline(always)]
    fn span_of(&self, key: usize) -> Option<CarrierSpan> {
        let span = self.last_carrier.get();
        if key >= span.start && key < span.end {
            return Some(span);
        }
        self.span_of_slow(key)
    }

    #[cold]
    fn span_of_slow(&self, key: usize) -> Option<CarrierSpan> {
        let span = self.find_span(key)?;
        self.last_carrier.set(span);
        Some(span)
    }

    /// Looks `key` up in the carrier address index without touching the carrier caches.
    #[inline(never)]
    fn find_span(&self, key: usize) -> Option<CarrierSpan> {
        let index = self
            .carrier_ranges
            .partition_point(|&(start, _, _)| start <= key)
            .checked_sub(1)?;
        let (start, end, carrier) = self.carrier_ranges[index];
        if key >= start && key < end {
            Some(CarrierSpan::new(
                start,
                end,
                carrier,
                self.carriers[carrier].as_ref()?.sbc,
            ))
        } else {
            None
        }
    }

    fn index_carrier(&mut self, index: usize) {
        let Some(carrier) = self.carriers[index].as_ref() else {
            return;
        };
        let range = (
            carrier.key_base,
            carrier.key_base + carrier.memory.len(),
            index,
        );
        let at = self
            .carrier_ranges
            .partition_point(|&(start, _, _)| start < range.0);
        self.carrier_ranges.insert(at, range);
    }

    fn unindex_carrier(&mut self, index: usize) {
        self.carrier_ranges
            .retain(|&(_, _, carrier)| carrier != index);
        if self.last_carrier.get().index == index {
            self.last_carrier.set(CarrierSpan::EMPTY);
        }
        if self.tree_span.get().index == index {
            self.tree_span.set(CarrierSpan::EMPTY);
        }
    }

    /// Reads word `word` of the block or carrier node at address `key`.
    #[inline(always)]
    fn word_at(&self, key: usize, word: usize) -> Result<usize, AllocError> {
        let span = self.span_of(key).ok_or(AllocError::Corrupt)?;
        span.read(key, word).ok_or(AllocError::Corrupt)
    }

    #[inline(always)]
    fn set_word_at(&mut self, key: usize, word: usize, value: usize) -> Result<(), AllocError> {
        let span = self.span_of(key).ok_or(AllocError::Corrupt)?;
        span.write(key, word, value).ok_or(AllocError::Corrupt)
    }

    /// Decodes the block header at `key`; SBC blocks carry all three flags like erts' SBC_BLK_HDR.
    #[inline(always)]
    fn blk(&self, key: usize) -> Result<Block, AllocError> {
        let span = self.span_of(key).ok_or(AllocError::Corrupt)?;
        Self::decode_block(span, key)
    }

    /// Like `blk` for a block known to live in carrier `index` (a neighbour of a known block).
    #[inline(always)]
    fn blk_in(&self, index: usize, key: usize) -> Result<Block, AllocError> {
        if let Some(span) = self.span_of(key).filter(|span| span.index == index) {
            return Self::decode_block(span, key);
        }
        // A carrier outside the address index (one being resized or imported).
        let carrier = self.carriers[index].as_ref().ok_or(AllocError::Corrupt)?;
        let span = CarrierSpan::new(
            carrier.key_base,
            carrier.key_base + carrier.memory.len(),
            index,
            carrier.sbc,
        );
        if key < span.start || key >= span.end {
            return Err(AllocError::Corrupt);
        }
        Self::decode_block(span, key)
    }

    #[inline(always)]
    fn decode_block(span: CarrierSpan, key: usize) -> Result<Block, AllocError> {
        let index = span.index;
        let header = span.read(key, 0).ok_or(AllocError::Corrupt)?;
        let size = header & !BLOCK_FLAGS;
        if span.sbc {
            return Ok(Block {
                carrier: index,
                offset: key,
                size,
                allocated: true,
                prev_free: true,
                last: true,
            });
        }
        Ok(Block {
            carrier: index,
            offset: key,
            size,
            allocated: header & FREE == 0,
            prev_free: header & PREV_FREE != 0,
            last: header & LAST != 0,
        })
    }

    /// Validates a caller-supplied allocation address.
    #[inline(always)]
    fn live_block(&self, key: usize) -> Result<Block, AllocError> {
        let index = self.carrier_of(key).ok_or(AllocError::InvalidAllocation)?;
        let carrier = self.carriers[index]
            .as_ref()
            .ok_or(AllocError::InvalidAllocation)?;
        if key < carrier.start || (carrier.sbc && key != carrier.start) {
            return Err(AllocError::InvalidAllocation);
        }
        let block = self.blk_in(index, key)?;
        if !block.allocated || block.size == 0 {
            return Err(AllocError::InvalidAllocation);
        }
        Ok(block)
    }

    /// Blocks of one carrier in address order, walked through their headers.
    fn carrier_blocks(&self, index: usize) -> Result<Vec<Block>, AllocError> {
        #[cfg(test)]
        self.carrier_walks.set(self.carrier_walks.get() + 1);
        let carrier = self.carriers[index].as_ref().ok_or(AllocError::Corrupt)?;
        let end = carrier.key_base + carrier.size;
        let mut blocks = Vec::new();
        let mut pos = carrier.start;
        loop {
            let block = self.blk(pos)?;
            if block.size == 0 || pos + block.size > end {
                return Err(AllocError::Corrupt);
            }
            let last = block.last;
            pos += block.size;
            blocks.push(block);
            if last {
                return Ok(blocks);
            }
        }
    }

    /// Copies `len` payload bytes between two live blocks, possibly in different carriers.
    fn copy_payload(&mut self, from: usize, to: usize, len: usize) -> Result<(), AllocError> {
        let source_index = self.carrier_of(from).ok_or(AllocError::Corrupt)?;
        let target_index = self.carrier_of(to).ok_or(AllocError::Corrupt)?;
        if source_index == target_index {
            let carrier = self.carriers[source_index]
                .as_mut()
                .ok_or(AllocError::Corrupt)?;
            let source = from - carrier.key_base + BLOCK_HEADER;
            let target = to - carrier.key_base + BLOCK_HEADER;
            let bytes = carrier.memory.bytes_mut().ok_or(AllocError::Corrupt)?;
            if source.max(target) + len > bytes.len() {
                return Err(AllocError::Corrupt);
            }
            bytes.copy_within(source..source + len, target);
            return Ok(());
        }
        let [Some(source), Some(target)] = self
            .carriers
            .get_disjoint_mut([source_index, target_index])
            .map_err(|_| AllocError::Corrupt)?
        else {
            return Err(AllocError::Corrupt);
        };
        let source_offset = from - source.key_base + BLOCK_HEADER;
        let target_offset = to - target.key_base + BLOCK_HEADER;
        let source_bytes = source
            .memory
            .bytes()
            .and_then(|bytes| bytes.get(source_offset..source_offset + len))
            .ok_or(AllocError::Corrupt)?;
        target
            .memory
            .bytes_mut()
            .and_then(|bytes| bytes.get_mut(target_offset..target_offset + len))
            .ok_or(AllocError::Corrupt)?
            .copy_from_slice(source_bytes);
        Ok(())
    }

    /// Port of STAT_MBC_BLK_ALLOC, erl_alloc_util.c, OTP-29.1.1: the carrier's allocated bytes.
    #[inline(always)]
    fn carrier_blk_alloc(&mut self, carrier: usize, size: usize) -> Result<(), AllocError> {
        self.carriers[carrier]
            .as_mut()
            .ok_or(AllocError::Corrupt)?
            .blocks_size += size;
        Ok(())
    }

    /// Port of STAT_MBC_BLK_FREE, erl_alloc_util.c, OTP-29.1.1.
    #[inline(always)]
    fn carrier_blk_free(&mut self, carrier: usize, size: usize) -> Result<(), AllocError> {
        self.carriers[carrier]
            .as_mut()
            .ok_or(AllocError::Corrupt)?
            .blocks_size -= size;
        Ok(())
    }

    /// In-place block resize: the net change of STAT_MBC_BLK_FREE plus STAT_MBC_BLK_ALLOC.
    #[inline(always)]
    fn carrier_blk_resize(
        &mut self,
        carrier: usize,
        old: usize,
        new: usize,
    ) -> Result<(), AllocError> {
        let entry = self.carriers[carrier].as_mut().ok_or(AllocError::Corrupt)?;
        entry.blocks_size = entry.blocks_size - old + new;
        Ok(())
    }

    /// Port of aoff_largest_fblk_in_mbc, erl_ao_firstfit_alloc.c, OTP-29.1.1: the carrier tree
    /// node holds the largest free block size of its carrier.
    #[inline(always)]
    fn aoff_largest_fblk_in_mbc(&self, span: CarrierSpan) -> usize {
        self.tn::<true>(span.start + MBC_HEADER).size()
    }

    /// Port of check_abandon_carrier, erl_alloc_util.c, OTP-29.1.1: decided from counters only.
    #[inline(always)]
    fn check_abandon_carrier(&mut self, span: CarrierSpan) -> Result<(), AllocError> {
        let abandon = self.abandon_decision(span)?;
        #[cfg(test)]
        if self.verify_abandon_by_walk {
            assert_eq!(
                abandon,
                self.abandon_decision_by_walk(span.index),
                "carrier {}",
                span.index
            );
        }
        if abandon {
            self.abandon_carrier(span.index)?;
        }
        Ok(())
    }

    /// The tests of check_abandon_carrier, in the order of erts. The precomputed `abandon` flag
    /// stands for the checks of the pool and the strategy.
    #[inline(always)]
    fn abandon_decision(&self, span: CarrierSpan) -> Result<bool, AllocError> {
        if !self.abandon || self.class_stats[0].blocks_size.current > self.abandon_limit {
            return Ok(false);
        }
        if self.pending_carriers.len() >= self.options.acnl {
            return Ok(false);
        }
        let carrier = self.carriers[span.index]
            .as_ref()
            .ok_or(AllocError::Corrupt)?;
        if carrier.main || carrier.blocks_size > carrier.abandon_limit {
            return Ok(false);
        }
        Ok(self.aoff_largest_fblk_in_mbc(span) >= self.options.acfml)
    }

    /// The same decision recomputed by walking every carrier, for the tests.
    #[cfg(test)]
    fn abandon_decision_by_walk(&self, carrier_index: usize) -> bool {
        let walks = self.carrier_walks.get();
        let decision = self.abandon_decision_walk_inner(carrier_index);
        self.carrier_walks.set(walks);
        decision
    }

    #[cfg(test)]
    fn abandon_decision_walk_inner(&self, carrier_index: usize) -> bool {
        if !self.abandon || self.pending_carriers.len() >= self.options.acnl {
            return false;
        }
        let Some(carrier) = self.carriers.get(carrier_index).and_then(Option::as_ref) else {
            return false;
        };
        if carrier.sbc || carrier.main {
            return false;
        }
        let (mut mbc_allocated, mut mbc_size) = (0, 0);
        for (index, entry) in self.carriers.iter().enumerate() {
            let Some(entry) = entry else { continue };
            if entry.sbc {
                continue;
            }
            mbc_size += entry.size;
            mbc_allocated += self
                .carrier_blocks(index)
                .unwrap()
                .iter()
                .filter(|block| block.allocated)
                .map(|block| block.size)
                .sum::<usize>();
        }
        let blocks = self.carrier_blocks(carrier_index).unwrap();
        let allocated = blocks
            .iter()
            .filter(|block| block.allocated)
            .map(|block| block.size)
            .sum::<usize>();
        let largest_free = blocks
            .iter()
            .filter(|block| !block.allocated)
            .map(|block| block.size)
            .max()
            .unwrap_or(0);
        mbc_allocated <= percent_limit(mbc_size, self.options.acul)
            && allocated <= percent_limit(carrier.size, self.options.acul)
            && largest_free >= self.options.acfml
    }

    #[inline(never)]
    fn abandon_carrier(&mut self, carrier_index: usize) -> Result<(), AllocError> {
        self.discard_free_blocks(carrier_index)?;
        self.detach_carrier(carrier_index)
    }

    fn discard_free_blocks(&mut self, carrier_index: usize) -> Result<(), AllocError> {
        let carrier = self.carriers[carrier_index]
            .as_ref()
            .ok_or(AllocError::Corrupt)?;
        if self.options.acful == 0 || carrier.blocks_size > carrier.discard_limit {
            return Ok(());
        }
        let blocks = self.carrier_blocks(carrier_index)?;
        let base = carrier.key_base;
        let memory_base = carrier.memory.as_ptr() as usize;
        let page = page_size();
        for block in blocks.iter().filter(|block| !block.allocated) {
            // Free-list links (header, carrier and tree words) stay intact: only whole pages after them go.
            let payload = memory_base + block.offset - base + BF_NODE_SIZE;
            let end = memory_base + block.offset - base + block.size - FOOTER;
            let discard_start = payload.div_ceil(page) * page;
            let discard_end = end / page * page;
            if discard_end > discard_start {
                self.carriers[carrier_index]
                    .as_mut()
                    .ok_or(AllocError::Corrupt)?
                    .memory
                    .advise_range(
                        discard_start - memory_base,
                        discard_end - discard_start,
                        libc::MADV_FREE,
                    )
                    .map_err(AllocError::mapped)?;
            }
        }
        Ok(())
    }

    fn detach_carrier(&mut self, carrier_index: usize) -> Result<(), AllocError> {
        let carrier = self.carriers[carrier_index]
            .as_ref()
            .ok_or(AllocError::Corrupt)?;
        if carrier.sbc || carrier.main {
            return Err(AllocError::Corrupt);
        }
        let transfer_blocks = self.carrier_blocks(carrier_index)?;
        let transfer_allocations = transfer_blocks
            .iter()
            .filter(|block| block.allocated)
            .map(|block| {
                (
                    Allocation {
                        id: block.offset as u64,
                        size: block.size,
                    },
                    block.offset,
                )
            })
            .collect::<Vec<_>>();
        for block in transfer_blocks.iter().filter(|block| !block.allocated) {
            self.unlink_free(block.offset)?;
        }
        self.aoff_remove_carrier_node(carrier_index)?;
        for block in transfer_blocks.iter().filter(|block| block.allocated) {
            self.block_removed(false, block.size);
        }
        let carrier = self
            .vacate_carrier(carrier_index)
            .ok_or(AllocError::Corrupt)?;
        if carrier.mseg {
            self.mseg.release_transferred(carrier.size);
        }
        self.carrier_removed(false, carrier.mseg, carrier.size);
        self.stats.carriers -= 1;
        self.stats.carriers_size -= carrier.size;
        if carrier.mseg {
            self.stats.mseg_carriers -= 1;
            self.stats.mseg_carriers_size -= carrier.size;
        } else {
            self.stats.sys_alloc_carriers -= 1;
            self.stats.sys_alloc_carriers_size -= carrier.size;
        }
        self.pending_carriers.push(CarrierTransfer {
            origin_instance: carrier.origin_instance,
            carrier,
            blocks: transfer_blocks,
            allocations: transfer_allocations,
        });
        Ok(())
    }

    #[inline(always)]
    pub(crate) fn has_pending_carriers(&self) -> bool {
        !self.pending_carriers.is_empty()
    }

    pub(crate) fn take_pending_carriers(&mut self) -> Vec<CarrierTransfer> {
        std::mem::take(&mut self.pending_carriers)
    }

    pub(crate) fn needs_carrier(&self, size: usize) -> Result<bool, AllocError> {
        let Some(need) = self.required_block_size(size)? else {
            return Ok(false);
        };
        Ok(self.choose_free(need)?.is_none())
    }

    pub(crate) fn required_block_size(&self, size: usize) -> Result<Option<usize>, AllocError> {
        let need = block_size(size, self.strategy)?;
        Ok((need < self.sbct()).then_some(need))
    }

    pub(crate) fn transfer_largest_free(&self, transfer: &CarrierTransfer) -> usize {
        transfer
            .blocks
            .iter()
            .filter(|block| !block.allocated)
            .map(|block| block.size)
            .max()
            .unwrap_or(0)
    }

    pub(crate) fn carrier_pool_limit(&self) -> usize {
        self.options.acnl
    }

    pub(crate) fn import_carrier_transfer(
        &mut self,
        mut transfer: CarrierTransfer,
    ) -> Result<Vec<(Allocation, Allocation)>, AllocError> {
        if !is_aoff(self.strategy) || transfer.carrier.sbc {
            return Err(AllocError::Corrupt);
        }
        transfer.carrier.in_aoff_tree = false;
        transfer.carrier.main = false;
        let carrier_index = self.insert_carrier(transfer.carrier);
        self.write_carrier(carrier_index)?;
        self.aoff_add_carrier_node(carrier_index)?;
        // Blocks keep their addresses with the carrier memory, so allocations keep their identity.
        let mut remapped = Vec::with_capacity(transfer.allocations.len());
        for (old, offset) in transfer.allocations {
            let size = self.blk(offset)?.size;
            self.block_added(false, size);
            remapped.push((old, old));
        }
        for block in transfer.blocks {
            let block = self.blk(block.offset)?;
            self.write_block(&block)?;
            if !block.allocated {
                self.link_free(block.offset)?;
            }
        }
        let carrier = self.carriers[carrier_index]
            .as_ref()
            .ok_or(AllocError::Corrupt)?;
        let carrier_size = carrier.size;
        let mseg = carrier.mseg;
        if mseg {
            self.mseg.adopt_existing(carrier_size);
        }
        self.stats.carriers += 1;
        self.stats.carriers_size += carrier_size;
        self.carrier_added(false, mseg, carrier_size);
        if mseg {
            self.stats.mseg_carriers += 1;
            self.stats.mseg_carriers_size += carrier_size;
        } else {
            self.stats.sys_alloc_carriers += 1;
            self.stats.sys_alloc_carriers_size += carrier_size;
        }
        self.update_carrier_peak();
        Ok(remapped)
    }

    /// Resizes an allocation, preserving its prefix and moving only when needed.
    /// Port of `erts_alcu_realloc`, `erl_alloc_util.c:2828`, OTP-29.1.1.
    pub fn realloc(
        &mut self,
        allocation: Allocation,
        size: usize,
    ) -> Result<Allocation, AllocError> {
        self.stats.realloc_calls += 1;
        let old = self.live_block(allocation.id as usize)?;
        let old_offset = old.offset;
        let same = Allocation {
            id: allocation.id,
            size,
        };
        let needed = block_size(size, self.strategy)?;
        let old_sbc = self.carriers[old.carrier]
            .as_ref()
            .ok_or(AllocError::Corrupt)?
            .sbc;
        if old_sbc && needed >= self.sbct() {
            match self.resize_sbc(old_offset, needed) {
                Ok(moved) => {
                    return Ok(Allocation {
                        id: moved as u64,
                        size,
                    });
                }
                Err(AllocError::Map(_)) => {}
                Err(error) => return Err(error),
            }
        }
        if old_sbc && needed < self.sbct() {
            let carrier = self.carriers[old.carrier]
                .as_ref()
                .ok_or(AllocError::Corrupt)?;
            let used = SBC_HEADER
                .checked_add(BLOCK_HEADER)
                .and_then(|n| n.checked_add(size))
                .ok_or(AllocError::Overflow)?;
            let slack = carrier.size.saturating_sub(used);
            if (slack as u128) * 100 < (self.options.rsbcmt as u128) * (carrier.size as u128) {
                match self.resize_sbc(old_offset, needed) {
                    Ok(moved) => {
                        return Ok(Allocation {
                            id: moved as u64,
                            size,
                        });
                    }
                    Err(AllocError::Map(_)) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        let next_free = if old_sbc || old.last {
            None
        } else {
            Some(self.blk(old_offset + old.size)?).filter(|block| !block.allocated)
        };
        let tiny_shrink_can_merge = next_free.is_some();
        if !old_sbc && needed == old.size
            || (!old_sbc
                && needed < old.size
                && old.size - needed < min_block_size(self.strategy)
                && !tiny_shrink_can_merge)
        {
            return Ok(same);
        }
        let large_shrink = !old_sbc
            && needed < old.size
            && ((old.size - needed) as u128) * 100
                > (self.options.rmbcmt as u128) * (old.size as u128);
        if !old_sbc && needed < old.size {
            let mut candidate_start = old_offset;
            let mut candidate_size = old.size;
            if old.prev_free {
                candidate_start = self.previous_block(old_offset)?;
                candidate_size += self.blk(candidate_start)?.size;
            }
            if let Some(next) = next_free {
                candidate_size += next.size;
            }
            let tree_better = match self.choose_free(needed)? {
                Some(candidate) => {
                    let candidate_block_size = self.blk(candidate)?.size;
                    candidate_block_size < candidate_size
                        || (self.strategy == Strategy::AddressOrderBestFit
                            && candidate_block_size == candidate_size
                            && candidate < candidate_start)
                }
                None => false,
            };
            if large_shrink && tree_better {
                let replacement = self.alloc(size)?;
                let copy = size.min(old.size.saturating_sub(BLOCK_HEADER));
                self.copy_payload(old_offset, replacement.id as usize, copy)?;
                self.free(allocation)?;
                self.stats.alloc_calls = self.stats.alloc_calls.saturating_sub(1);
                self.stats.free_calls = self.stats.free_calls.saturating_sub(1);
                return Ok(replacement);
            }
        }
        if !old_sbc
            && needed < old.size
            && (old.size - needed >= min_block_size(self.strategy) || tiny_shrink_can_merge)
        {
            let mut tail = Block {
                carrier: old.carrier,
                offset: old_offset + needed,
                size: old.size - needed,
                allocated: false,
                prev_free: false,
                last: old.last,
            };
            if let Some(next) = next_free {
                self.unlink_free(next.offset)?;
                tail.size += next.size;
                tail.last = next.last;
            }
            self.write_block(&Block {
                size: needed,
                last: false,
                ..old
            })?;
            self.write_block(&tail)?;
            if !tail.last {
                self.set_next_prev_free(&tail, true)?;
            }
            self.link_free(tail.offset)?;
            self.block_resized(false, old.size, needed);
            self.carrier_blk_resize(old.carrier, old.size, needed)?;
            return Ok(same);
        }
        if !old_sbc
            && needed > old.size
            && let Some(next) = next_free
            && old.size + next.size >= needed
        {
            self.unlink_free(next.offset)?;
            let total = old.size + next.size;
            let grown = if total - needed >= min_block_size(self.strategy) {
                let grown = Block {
                    size: needed,
                    last: false,
                    ..old
                };
                let tail = Block {
                    carrier: old.carrier,
                    offset: old_offset + needed,
                    size: total - needed,
                    allocated: false,
                    prev_free: false,
                    last: next.last,
                };
                self.write_block(&grown)?;
                self.write_block(&tail)?;
                if !tail.last {
                    self.set_next_prev_free(&tail, true)?;
                }
                self.link_free(tail.offset)?;
                grown
            } else {
                let grown = Block {
                    size: total,
                    last: next.last,
                    ..old
                };
                self.write_block(&grown)?;
                if !grown.last {
                    self.set_next_prev_free(&grown, false)?;
                }
                grown
            };
            self.block_resized(false, old.size, grown.size);
            self.carrier_blk_resize(old.carrier, old.size, grown.size)?;
            return Ok(same);
        }
        if !old_sbc && old.prev_free && (needed > old.size || large_shrink) {
            let previous = self.previous_block(old_offset)?;
            let prev = self.blk(previous)?;
            let candidate_size = prev.size + old.size + next_free.map_or(0, |next| next.size);
            if candidate_size >= needed {
                let external_is_better = match self.choose_free(needed)? {
                    Some(block) => {
                        let block_size = self.blk(block)?.size;
                        block_size < candidate_size
                            || (self.strategy == Strategy::AddressOrderBestFit
                                && block_size == candidate_size
                                && block < previous)
                    }
                    None => false,
                };
                if !external_is_better {
                    self.unlink_free(previous)?;
                    if let Some(next) = next_free {
                        self.unlink_free(next.offset)?;
                    }
                    let last = next_free.map_or(old.last, |next| next.last);
                    let remainder = candidate_size - needed;
                    let split = remainder >= min_block_size(self.strategy);
                    let used = if split { needed } else { candidate_size };
                    // The payload moves down into the previous block; regions may overlap.
                    let copy = size.min(old.size - BLOCK_HEADER);
                    self.copy_payload(old_offset, previous, copy)?;
                    let moved = Block {
                        size: used,
                        allocated: true,
                        last: last && !split,
                        ..prev
                    };
                    self.write_block(&moved)?;
                    if split {
                        let tail = Block {
                            carrier: prev.carrier,
                            offset: previous + needed,
                            size: remainder,
                            allocated: false,
                            prev_free: false,
                            last,
                        };
                        self.write_block(&tail)?;
                        if !last {
                            self.set_next_prev_free(&tail, true)?;
                        }
                        self.link_free(tail.offset)?;
                    } else if !last {
                        self.set_next_prev_free(&moved, false)?;
                    }
                    self.block_resized(false, old.size, used);
                    self.carrier_blk_resize(old.carrier, old.size, used)?;
                    return Ok(Allocation {
                        id: previous as u64,
                        size,
                    });
                }
            }
        }
        let replacement = match self.alloc(size) {
            Ok(replacement) => replacement,
            Err(error) => {
                self.stats.alloc_calls = self.stats.alloc_calls.saturating_sub(1);
                return Err(error);
            }
        };
        let copy = old.size.saturating_sub(BLOCK_HEADER).min(size);
        self.copy_payload(old_offset, replacement.id as usize, copy)?;
        self.free(allocation)?;
        self.stats.alloc_calls = self.stats.alloc_calls.saturating_sub(1);
        self.stats.free_calls = self.stats.free_calls.saturating_sub(1);
        Ok(replacement)
    }

    /// Reads current and peak allocator counters.
    pub fn stats(&self) -> AllocStats {
        self.stats
    }

    /// Returns current MBC/SBC state and per-instance call counters.
    pub fn info(&self) -> AllocatorInfo {
        let mut mbcs = AllocatorClassInfo::default();
        let mut sbcs = AllocatorClassInfo::default();
        for carrier in self.carriers.iter().flatten() {
            let class = if carrier.sbc { &mut sbcs } else { &mut mbcs };
            class.carriers += 1;
            class.carriers_size += carrier.size;
            if carrier.mseg {
                class.mseg_alloc_carriers += 1;
                class.mseg_alloc_carriers_size += carrier.size;
            } else {
                class.sys_alloc_carriers += 1;
                class.sys_alloc_carriers_size += carrier.size;
            }
        }
        for (info, stats) in [
            (&mut mbcs, self.class_stats[0]),
            (&mut sbcs, self.class_stats[1]),
        ] {
            info.blocks = stats.blocks.current;
            info.blocks_size = stats.blocks_size.current;
            info.blocks_max = stats.blocks.max;
            info.blocks_size_max = stats.blocks_size.max;
            info.blocks_max_ever = stats.blocks.max_ever;
            info.blocks_size_max_ever = stats.blocks_size.max_ever;
            info.carriers_max = stats.carriers.max;
            info.carriers_size_max = stats.carriers_size.max;
            info.carriers_max_ever = stats.carriers.max_ever;
            info.carriers_size_max_ever = stats.carriers_size.max_ever;
            info.mseg_alloc_carriers_max = stats.mseg_carriers.max;
            info.mseg_alloc_carriers_size_max = stats.mseg_carriers_size.max;
            info.mseg_alloc_carriers_max_ever = stats.mseg_carriers.max_ever;
            info.mseg_alloc_carriers_size_max_ever = stats.mseg_carriers_size.max_ever;
            info.sys_alloc_carriers_max = stats.sys_carriers.max;
            info.sys_alloc_carriers_size_max = stats.sys_carriers_size.max;
            info.sys_alloc_carriers_max_ever = stats.sys_carriers.max_ever;
            info.sys_alloc_carriers_size_max_ever = stats.sys_carriers_size.max_ever;
        }
        AllocatorInfo {
            instance: self.instance_index,
            version: ("0.9", "3.0"),
            allocation_type: self.allocation_type,
            strategy: self.strategy,
            options: AllocUtilOptions {
                sbct: self.sbct(),
                ..self.options
            },
            mbcs,
            sbcs,
            calls: self.stats,
            call_counts: AllocatorCallCounts {
                alloc: call_count(self.stats.alloc_calls),
                free: call_count(self.stats.free_calls),
                realloc: call_count(self.stats.realloc_calls),
                mseg_alloc: call_count(self.stats.mseg_alloc_calls),
                mseg_dealloc: call_count(self.stats.mseg_dealloc_calls),
                mseg_realloc: call_count(self.stats.mseg_realloc_calls),
                sys_alloc: call_count(self.stats.sys_alloc_calls),
                sys_free: call_count(self.stats.sys_free_calls),
                sys_realloc: call_count(self.stats.sys_realloc_calls),
            },
            mbcs_pool: None,
        }
    }

    /// Writes bytes into an allocation with checked bounds.
    pub fn write(
        &mut self,
        allocation: Allocation,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), AllocError> {
        let block = self.live_block(allocation.id as usize)?;
        let end = offset
            .checked_add(bytes.len())
            .filter(|end| *end <= allocation.size)
            .ok_or(AllocError::OutOfBounds)?;
        let carrier = self.carriers[block.carrier]
            .as_mut()
            .ok_or(AllocError::Corrupt)?;
        let start = block.offset - carrier.key_base + BLOCK_HEADER;
        carrier
            .memory
            .bytes_mut()
            .and_then(|memory| memory.get_mut(start + offset..start + end))
            .ok_or(AllocError::Corrupt)?
            .copy_from_slice(bytes);
        Ok(())
    }

    /// Reads bytes from an allocation with checked bounds.
    pub fn read(
        &self,
        allocation: Allocation,
        offset: usize,
        out: &mut [u8],
    ) -> Result<(), AllocError> {
        let block = self.live_block(allocation.id as usize)?;
        let end = offset
            .checked_add(out.len())
            .filter(|end| *end <= allocation.size)
            .ok_or(AllocError::OutOfBounds)?;
        let carrier = self.carriers[block.carrier]
            .as_ref()
            .ok_or(AllocError::Corrupt)?;
        let start = block.offset - carrier.key_base + BLOCK_HEADER;
        out.copy_from_slice(
            carrier
                .memory
                .bytes()
                .and_then(|memory| memory.get(start + offset..start + end))
                .ok_or(AllocError::Corrupt)?,
        );
        Ok(())
    }

    /// Checks block chains, footer/header agreement, allocation ownership, and free index.
    pub fn validate(&self) -> Result<(), AllocError> {
        let mut free = HashSet::default();
        let mut count = [0usize; 2];
        let mut bytes = [0usize; 2];
        for (ci, c) in self
            .carriers
            .iter()
            .enumerate()
            .filter_map(|(i, c)| c.as_ref().map(|c| (i, c)))
        {
            let mut pos = c.start;
            let end = c.key_base + c.size;
            let carrier_header = c.memory.read_word(0).ok_or(AllocError::Corrupt)?;
            let expected_carrier_flags =
                (if c.sbc { SBC } else { 0 }) | (if c.mseg { MSEG_CARRIER } else { 0 });
            if carrier_header & !CARRIER_FLAGS != c.size
                || carrier_header & CARRIER_FLAGS != expected_carrier_flags
                || c.start - c.key_base
                    != if c.sbc {
                        SBC_HEADER
                    } else {
                        self.mbc_header_size()
                    }
            {
                return Err(AllocError::Corrupt);
            }
            let mut previous_free = false;
            let mut carrier_bytes = 0;
            while pos < end {
                let b = self.blk(pos)?;
                if b.carrier != ci
                    || b.offset != pos
                    || b.size < min_block_size(self.strategy)
                    || pos + b.size > end
                {
                    return Err(AllocError::Corrupt);
                }
                let rel = pos - c.key_base;
                let h = c.memory.read_word(rel).ok_or(AllocError::Corrupt)?;
                if (c.sbc && h & (FREE | PREV_FREE | LAST) != FREE | PREV_FREE | LAST)
                    || (!c.sbc && b.prev_free != previous_free)
                    || (!c.sbc && previous_free && !b.allocated)
                {
                    return Err(AllocError::Corrupt);
                }
                previous_free = !b.allocated;
                if !b.allocated && !c.sbc {
                    free.insert(pos);
                    if !b.last && c.memory.read_word(rel + b.size - WORD) != Some(b.size) {
                        return Err(AllocError::Corrupt);
                    }
                } else {
                    count[usize::from(c.sbc)] += 1;
                    bytes[usize::from(c.sbc)] += b.size;
                    carrier_bytes += b.size;
                }
                pos += b.size;
                if b.last {
                    if !c.sbc && pos != end {
                        return Err(AllocError::Corrupt);
                    }
                    break;
                }
            }
            if !c.sbc && pos != end {
                return Err(AllocError::Corrupt);
            }
            if !c.sbc && carrier_bytes != c.blocks_size {
                return Err(AllocError::Corrupt);
            }
        }
        if self.abandon_limit
            != percent_limit(self.class_stats[0].carriers_size.current, self.options.acul)
        {
            return Err(AllocError::Corrupt);
        }
        if free != self.tree_free_blocks()?
            || (0..2).any(|class| {
                count[class] != self.class_stats[class].blocks.current
                    || bytes[class] != self.class_stats[class].blocks_size.current
            })
        {
            return Err(AllocError::Corrupt);
        }
        if is_aoff(self.strategy) {
            for carrier in 0..self.carriers.len() {
                let Some(entry) = self.carriers[carrier].as_ref() else {
                    continue;
                };
                let root = if entry.sbc {
                    0
                } else {
                    self.aoff_root(self.carrier_span(carrier)?)
                };
                self.validate_aoff_tree(root, 0, None, None, false)?;
                let carrier_node = self.carrier_tree_node(carrier)?;
                let largest = if root == 0 {
                    0
                } else {
                    self.node_word(root, TREE_FLAGS_WORD)? >> 32
                };
                let in_tree = self.carriers[carrier]
                    .as_ref()
                    .is_some_and(|entry| entry.in_aoff_tree);
                if in_tree
                    == self.carriers[carrier]
                        .as_ref()
                        .is_some_and(|entry| entry.sbc)
                    || (in_tree && self.tree_node_size(carrier_node)? != largest)
                {
                    return Err(AllocError::Corrupt);
                }
            }
            self.validate_aoff_tree(self.aoff_carrier_root, 0, None, None, true)?;
        }
        Ok(())
    }

    fn carrier_tree_node(&self, carrier: usize) -> Result<usize, AllocError> {
        let entry = self
            .carriers
            .get(carrier)
            .and_then(Option::as_ref)
            .ok_or(AllocError::Corrupt)?;
        Ok(entry.key_base + MBC_HEADER)
    }

    fn validate_aoff_tree(
        &self,
        node: usize,
        parent: usize,
        lower: Option<(usize, usize)>,
        upper: Option<(usize, usize)>,
        carrier_tree: bool,
    ) -> Result<(usize, usize), AllocError> {
        if node == 0 {
            return Ok((1, 0));
        }
        let node_carrier = self.aoff_carrier_index(node).is_some();
        if node_carrier != carrier_tree
            || self.node_word(node, TREE_PARENT_WORD)? != parent
            || self.node_word(node, TREE_FLAGS_WORD)? as u32 & TREE_NODE as u32 == 0
        {
            return Err(AllocError::Corrupt);
        }
        let size = self.tree_node_size(node)?;
        let key = if carrier_tree || self.strategy == Strategy::Aoff {
            (0, node)
        } else if self.strategy == Strategy::AoffCbf {
            (size, 0)
        } else {
            (size, node)
        };
        if lower.is_some_and(|bound| key <= bound) || upper.is_some_and(|bound| key >= bound) {
            return Err(AllocError::Corrupt);
        }
        let left = self.node_word(node, TREE_LEFT_WORD)?;
        let right = self.node_word(node, TREE_RIGHT_WORD)?;
        let red = self.is_red(node)?;
        if red && (self.is_red(left)? || self.is_red(right)?) {
            return Err(AllocError::Corrupt);
        }
        let (left_height, left_max) =
            self.validate_aoff_tree(left, node, lower, Some(key), carrier_tree)?;
        let (right_height, right_max) =
            self.validate_aoff_tree(right, node, Some(key), upper, carrier_tree)?;
        let max_size = size.max(left_max).max(right_max);
        if left_height != right_height || self.node_word(node, TREE_FLAGS_WORD)? >> 32 != max_size {
            return Err(AllocError::Corrupt);
        }
        Ok((left_height + usize::from(!red), max_size))
    }

    fn resize_sbc(
        &mut self,
        old_offset: usize,
        new_block_size: usize,
    ) -> Result<usize, AllocError> {
        let old = self.blk(old_offset)?;
        let (old_carrier_size, is_mseg) = self.carriers[old.carrier]
            .as_ref()
            .map(|carrier| (carrier.size, carrier.mseg))
            .ok_or(AllocError::Corrupt)?;
        let requested_size = SBC_HEADER
            .checked_add(new_block_size)
            .ok_or(AllocError::Overflow)?;
        // The carrier may move; it is re-indexed by its new address below, also on failure.
        self.unindex_carrier(old.carrier);
        let resized = {
            let carrier = self.carriers[old.carrier]
                .as_mut()
                .ok_or(AllocError::Corrupt)?;
            if is_mseg {
                self.stats.mseg_realloc_calls += 1;
                let CarrierMemory::Segmented(segment) = &mut carrier.memory else {
                    return Err(AllocError::Corrupt);
                };
                self.mseg
                    .resize_carrier(
                        segment,
                        requested_size,
                        SegmentFlags::PageAligned,
                        MsegOptions {
                            absolute_shrink_threshold: self.options.asbcst,
                            relative_shrink_threshold: self.options.rsbcst,
                            ..MsegOptions::default()
                        },
                    )
                    .map_err(AllocError::mapped)
            } else {
                self.stats.sys_realloc_calls += 1;
                let CarrierMemory::Mapped(region) = &mut carrier.memory else {
                    return Err(AllocError::Corrupt);
                };
                region
                    .resize_preserving(requested_size, page_size())
                    .map_err(AllocError::mapped)
            }
        };
        self.index_carrier(old.carrier);
        resized?;
        let (new_base, new_carrier_size) = self.carriers[old.carrier]
            .as_ref()
            .map(|carrier| (carrier.memory.as_ptr() as usize, carrier.memory.len()))
            .ok_or(AllocError::Corrupt)?;
        let new_offset = new_base + SBC_HEADER;
        {
            let carrier = self.carriers[old.carrier]
                .as_mut()
                .ok_or(AllocError::Corrupt)?;
            carrier.key_base = new_base;
            carrier.start = new_offset;
            carrier.size = new_carrier_size;
        }
        self.unindex_carrier(old.carrier);
        self.index_carrier(old.carrier);
        self.block_resized(true, old.size, new_block_size);
        self.stats.carriers_size = self.stats.carriers_size - old_carrier_size + new_carrier_size;
        self.carrier_resized(true, is_mseg, old_carrier_size, new_carrier_size);
        if is_mseg {
            self.stats.mseg_carriers_size =
                self.stats.mseg_carriers_size - old_carrier_size + new_carrier_size;
        } else {
            self.stats.sys_alloc_carriers_size =
                self.stats.sys_alloc_carriers_size - old_carrier_size + new_carrier_size;
        }
        self.write_carrier(old.carrier)?;
        self.write_block(&Block {
            carrier: old.carrier,
            offset: new_offset,
            size: new_block_size,
            allocated: true,
            prev_free: true,
            last: true,
        })?;
        self.update_carrier_peak();
        Ok(new_offset)
    }

    fn add_sbc(&mut self, size: usize) -> Result<usize, AllocError> {
        let total = align_up(SBC_HEADER + size)?;
        let (memory, mseg) = self.allocate_carrier(
            total,
            self.stats.mseg_carriers < self.options.mmsbc,
            SegmentFlags::PageAligned,
        )?;
        let total = memory.len();
        let key_base = memory.as_ptr() as usize;
        let start = key_base + SBC_HEADER;
        let ci = self.insert_carrier(Carrier {
            memory,
            sbc: true,
            mseg,
            in_aoff_tree: false,
            main: false,
            origin_instance: self.instance_index,
            key_base,
            start,
            size: total,
            blocks_size: 0,
            abandon_limit: 0,
            discard_limit: 0,
        });
        self.write_carrier(ci)?;
        self.write_block(&Block {
            carrier: ci,
            offset: start,
            size,
            allocated: true,
            prev_free: true,
            last: true,
        })?;
        self.stats.carriers += 1;
        self.stats.carriers_size += total;
        self.carrier_added(true, mseg, total);
        if mseg {
            self.stats.mseg_carriers += 1;
            self.stats.mseg_carriers_size += total;
        } else {
            self.stats.sys_alloc_carriers += 1;
            self.stats.sys_alloc_carriers_size += total;
        }
        self.update_carrier_peak();
        Ok(start)
    }
    fn insert_carrier(&mut self, carrier: Carrier) -> usize {
        if !carrier.sbc {
            self.mbc_count += 1;
        }
        let index = if let Some(index) = self.free_carrier_slots.pop() {
            self.carriers[index] = Some(carrier);
            index
        } else {
            self.carriers.push(Some(carrier));
            self.carriers.len() - 1
        };
        self.index_carrier(index);
        index
    }

    fn vacate_carrier(&mut self, index: usize) -> Option<Carrier> {
        self.carriers[index].as_ref()?;
        self.unindex_carrier(index);
        let carrier = self.carriers[index].take()?;
        if !carrier.sbc {
            self.mbc_count -= 1;
        }
        self.free_carrier_slots.push(index);
        Some(carrier)
    }

    fn add_mbc(&mut self, needed: usize) -> Result<usize, AllocError> {
        let mbc_count = self.mbc_count;
        let is_main = mbc_count == 0;
        let mut size = if is_main {
            self.options.mmbcs.max(self.mbc_header_size() + needed)
        } else {
            let completed_stages = mbc_count - 1;
            if completed_stages >= self.options.mbcgs {
                self.options.lmbcs
            } else {
                self.options.smbcs.saturating_add(
                    self.options
                        .lmbcs
                        .saturating_sub(self.options.smbcs)
                        .saturating_mul(completed_stages)
                        / self.options.mbcgs.max(1),
                )
            }
            .max(self.mbc_header_size() + needed)
        };
        size = size.max(self.mbc_header_size() + needed);
        size = align_up(size)?;
        let (memory, mseg) = self.allocate_carrier(
            size,
            !is_main && self.stats.mseg_carriers < self.options.mmmbc,
            SegmentFlags::PowerOfTwo,
        )?;
        let size = memory.len();
        let key_base = memory.as_ptr() as usize;
        let start = key_base + self.mbc_header_size();
        let ci = self.insert_carrier(Carrier {
            memory,
            sbc: false,
            mseg,
            in_aoff_tree: false,
            main: is_main,
            origin_instance: self.instance_index,
            key_base,
            start,
            size,
            blocks_size: 0,
            abandon_limit: percent_limit(size, self.options.acul),
            discard_limit: percent_limit(size, self.options.acful),
        });
        self.write_carrier(ci)?;
        if is_aoff(self.strategy) {
            self.aoff_add_carrier_node(ci)?;
        }
        self.write_block(&Block {
            carrier: ci,
            offset: start,
            size: size - (start - key_base),
            allocated: false,
            prev_free: false,
            last: true,
        })?;
        self.link_free(start)?;
        self.stats.carriers += 1;
        self.stats.carriers_size += size;
        self.carrier_added(false, mseg, size);
        if mseg {
            self.stats.mseg_carriers += 1;
            self.stats.mseg_carriers_size += size;
        } else {
            self.stats.sys_alloc_carriers += 1;
            self.stats.sys_alloc_carriers_size += size;
        }
        self.update_carrier_peak();
        Ok(ci)
    }
    fn write_carrier(&mut self, ci: usize) -> Result<(), AllocError> {
        let mbc_header_size = self.mbc_header_size();
        let c = self.carriers[ci].as_mut().unwrap();
        let flags = (if c.sbc { SBC } else { 0 }) | (if c.mseg { MSEG_CARRIER } else { 0 });
        let _ = c.memory.write_word(0, c.size | flags);
        let _ = c.memory.write_word(WORD, 0);
        let _ = c.memory.write_word(2 * WORD, 0);
        let _ = c.memory.write_word(3 * WORD, 0);
        if !c.sbc {
            for offset in (4 * WORD..mbc_header_size).step_by(WORD) {
                let _ = c.memory.write_word(offset, 0);
            }
        }
        Ok(())
    }
    fn allocate_carrier(
        &mut self,
        size: usize,
        may_use_mseg: bool,
        mseg_flags: SegmentFlags,
    ) -> Result<(CarrierMemory, bool), AllocError> {
        if let Some(arena) = &mut self.carrier_arena {
            self.stats.sys_alloc_calls += 1;
            return arena
                .allocate(size)
                .map(|region| (CarrierMemory::Arena(region), false));
        }
        if may_use_mseg {
            self.stats.mseg_alloc_calls += 1;
            if let Ok(segment) = self.mseg.alloc(size, mseg_flags) {
                return Ok((CarrierMemory::Segmented(segment), true));
            }
        }
        self.stats.sys_alloc_calls += 1;
        let mapped = if mseg_flags == SegmentFlags::PowerOfTwo {
            RawRegion::map_aligned(size, 1 << 24)
        } else {
            RawRegion::map(size)
        };
        match mapped {
            Ok(region) => Ok((CarrierMemory::Mapped(region), false)),
            Err(sys_error) if !may_use_mseg => {
                self.stats.mseg_alloc_calls += 1;
                self.mseg
                    .alloc(size, mseg_flags)
                    .map(|segment| (CarrierMemory::Segmented(segment), true))
                    .map_err(|_| AllocError::mapped(sys_error))
            }
            Err(error) => Err(AllocError::mapped(error)),
        }
    }
    /// Writes a block header, plus the carrier word and size footer of a free MBC block.
    /// Port of SET_MBC_FBLK_HDR/SET_BLK_SZ_FTR, erl_alloc_util.c:225-262, OTP-29.1.1.
    #[inline(always)]
    fn write_block(&mut self, b: &Block) -> Result<(), AllocError> {
        let c = self.carriers[b.carrier]
            .as_mut()
            .ok_or(AllocError::Corrupt)?;
        let flags = if c.sbc {
            FREE | PREV_FREE | LAST
        } else {
            (if !b.allocated { FREE } else { 0 })
                | (if b.prev_free { PREV_FREE } else { 0 })
                | (if b.last { LAST } else { 0 })
        };
        let rel = b.offset - c.key_base;
        if !c.memory.write_word(rel, b.size | flags) {
            return Err(AllocError::Corrupt);
        }
        if !c.sbc && !b.allocated && !c.memory.write_word(rel + WORD, c.memory.as_ptr() as usize) {
            return Err(AllocError::Corrupt);
        }
        if !b.allocated && !b.last && !c.memory.write_word(rel + b.size - WORD, b.size) {
            return Err(AllocError::Corrupt);
        }
        Ok(())
    }

    /// Sets or clears PREV_FREE on the block following `b`.
    #[inline(always)]
    /// Port of SET_PREV_BLK_FREE/SET_PREV_BLK_ALLOCED, erl_alloc_util.c:237-250, OTP-29.1.1:
    /// one read-modify-write of the next header in the same carrier.
    fn set_next_prev_free(&mut self, b: &Block, value: bool) -> Result<(), AllocError> {
        if b.last {
            return Ok(());
        }
        let carrier = self.carriers[b.carrier]
            .as_mut()
            .ok_or(AllocError::Corrupt)?;
        let rel = b.offset + b.size - carrier.key_base;
        let header = carrier.memory.read_word(rel).ok_or(AllocError::Corrupt)?;
        let header = if value {
            header | PREV_FREE
        } else {
            header & !PREV_FREE
        };
        if carrier.memory.write_word(rel, header) {
            Ok(())
        } else {
            Err(AllocError::Corrupt)
        }
    }

    #[inline]
    fn tree_word(&self, word: usize) -> usize {
        if is_aoff(self.strategy) {
            match word {
                TREE_PARENT_WORD => AOFF_PARENT_WORD,
                TREE_LEFT_WORD => AOFF_LEFT_WORD,
                TREE_RIGHT_WORD => AOFF_RIGHT_WORD,
                TREE_FLAGS_WORD => AOFF_FLAGS_WORD,
                other => other,
            }
        } else {
            word
        }
    }

    /// The tree node at `key`, then its fields are plain loads, like the pointer dereference of
    /// the C code. Every link of a tree this allocator maintains is the address of a free block
    /// of an indexed carrier, which holds the whole node; debug builds check that.
    #[inline(always)]
    #[allow(unsafe_code)]
    fn tn<const A: bool>(&self, key: usize) -> TNode<A> {
        debug_assert!(self.is_tree_node_address(key), "tree link {key:#x}");
        // SAFETY: `key` is a link of a tree this allocator maintains, or the address of the
        // carrier tree node in the header of an indexed carrier. Both are word aligned and lie
        // inside a carrier that stays indexed, and so mapped, while the tree refers to them: a
        // carrier is unlinked from the carrier tree and its blocks are unlinked from its block
        // tree before it is unindexed and released.
        let raw = unsafe { NodeRef::at(key) };
        TNode { raw }
    }

    /// Whether the `NODE_WORDS` words at `key` lie inside one indexed carrier, word aligned.
    fn is_tree_node_address(&self, key: usize) -> bool {
        let span = self.tree_span.get();
        if key.wrapping_sub(span.start) < span.node_limit {
            return key.is_multiple_of(WORD);
        }
        let Some(index) = self
            .carrier_ranges
            .partition_point(|&(start, _, _)| start <= key)
            .checked_sub(1)
        else {
            return false;
        };
        let (start, end, _) = self.carrier_ranges[index];
        key.wrapping_sub(start) < CarrierSpan::node_limit(start, end) && key.is_multiple_of(WORD)
    }

    /// The root of the free-block tree of the carrier `span`, kept in the carrier header like
    /// `root` of `AOFF_Carrier_t` in erl_ao_firstfit_alloc.c.
    #[inline(always)]
    fn aoff_root(&self, span: CarrierSpan) -> usize {
        span.read(span.start, AOFF_ROOT_WORD).unwrap_or(0)
    }

    #[inline(always)]
    fn set_aoff_root(&mut self, span: CarrierSpan, root: usize) {
        let _ = span.write(span.start, AOFF_ROOT_WORD, root);
    }

    /// The span of the indexed or about-to-be-indexed carrier `index`.
    fn carrier_span(&self, index: usize) -> Result<CarrierSpan, AllocError> {
        let carrier = self
            .carriers
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(AllocError::Corrupt)?;
        Ok(CarrierSpan::new(
            carrier.key_base,
            carrier.key_base + carrier.memory.len(),
            index,
            carrier.sbc,
        ))
    }

    /// Root of `tree`.
    #[inline(always)]
    fn root_of<const A: bool>(&self, tree: TreeId) -> usize {
        match tree {
            TreeId::Carriers => self.aoff_carrier_root,
            TreeId::Blocks if A => self.aoff_root(self.tree_span.get()),
            TreeId::Blocks => self.free_root,
        }
    }

    /// Makes `root` the root of `tree`.
    #[inline(always)]
    fn set_root_of<const A: bool>(&mut self, tree: TreeId, root: usize) {
        match tree {
            TreeId::Carriers => self.aoff_carrier_root = root,
            TreeId::Blocks if A => self.set_aoff_root(self.tree_span.get(), root),
            TreeId::Blocks => self.free_root = root,
        }
    }

    /// `IS_RED` of erl_ao_firstfit_alloc.c: a null link is black.
    #[inline(always)]
    fn red<const A: bool>(&self, link: usize) -> bool {
        link != 0 && self.tn::<A>(link).is_red()
    }

    #[inline(always)]
    fn node_word(&self, node: usize, word: usize) -> Result<usize, AllocError> {
        self.word_at(node, self.tree_word(word))
    }

    /// The carrier whose aoff carrier-tree node (`crr.cpool`-adjacent node) is `node`.
    #[inline]
    fn aoff_carrier_index(&self, node: usize) -> Option<usize> {
        if !is_aoff(self.strategy) {
            return None;
        }
        // A span starts at its carrier's key_base.
        let span = self.span_of(node)?;
        (!span.sbc && node == span.start + MBC_HEADER).then_some(span.index)
    }

    #[inline(always)]
    fn tree_node_size(&self, node: usize) -> Result<usize, AllocError> {
        Ok(self.tn::<true>(node).size())
    }

    #[inline(always)]
    /// Port of rbt_search, erl_ao_firstfit_alloc.c, OTP-29.1.1.
    fn aoff_search(&self, root: usize, need: usize) -> Option<usize> {
        if root == 0 {
            return None;
        }
        let mut node = self.tn::<true>(root);
        loop {
            let left = node.left();
            if left != 0 {
                let left_node = self.tn::<true>(left);
                if left_node.max() >= need {
                    node = left_node;
                    continue;
                }
            }
            if node.size() >= need {
                return Some(node.raw.key());
            }
            let right = node.right();
            if right == 0 {
                return None;
            }
            node = self.tn::<true>(right);
        }
    }

    #[inline]
    fn aoff_raise_carrier_max(&mut self, span: CarrierSpan, size: usize) {
        let mut crr = self.tn::<true>(span.start + MBC_HEADER);
        if size > crr.size() {
            crr.raw.set_word(0, size);
            while size > crr.max() {
                crr.set_max(size);
                let parent = crr.parent();
                if parent == 0 {
                    break;
                }
                crr = self.tn::<true>(parent);
            }
        }
    }

    #[inline(never)]
    fn aoff_lower_carrier_max(&mut self, span: CarrierSpan) {
        let crr = self.tn::<true>(span.start + MBC_HEADER);
        let root = self.aoff_root(span);
        if root != 0 {
            let root_max = self.tn::<true>(root).max();
            if crr.size() == root_max {
                return;
            }
            crr.raw.set_word(0, root_max);
        } else {
            crr.raw.set_word(0, 0);
        }
        self.lower_max_size(crr, 0)
    }

    fn aoff_add_carrier_node(&mut self, carrier_index: usize) -> Result<(), AllocError> {
        let node = {
            let carrier = self.carriers[carrier_index]
                .as_mut()
                .ok_or(AllocError::Corrupt)?;
            if carrier.sbc {
                return Ok(());
            }
            carrier.in_aoff_tree = true;
            carrier.key_base + MBC_HEADER
        };
        self.tn::<true>(node).raw.set_word(0, 0);
        let span = self.span_of(node).ok_or(AllocError::Corrupt)?;
        // Port of aoff_creating_mbc (erl_ao_firstfit_alloc.c): the block order is stored in the header.
        let blk_order = match self.strategy {
            Strategy::AoffCaobf => 2,
            Strategy::AoffCbf => 3,
            _ => 1,
        };
        let index = u64::from(u32::try_from(carrier_index).map_err(|_| AllocError::Overflow)?);
        span.write(
            span.start,
            AOFF_BLK_ORDER_WORD,
            (index << AOFF_INDEX_SHIFT | blk_order) as usize,
        )
        .ok_or(AllocError::Corrupt)?;
        self.insert_tree_node::<true>(node, 0, span);
        Ok(())
    }

    fn aoff_remove_carrier_node(&mut self, carrier_index: usize) -> Result<(), AllocError> {
        let node = {
            let carrier = self.carriers[carrier_index]
                .as_mut()
                .ok_or(AllocError::Corrupt)?;
            if carrier.sbc || !carrier.in_aoff_tree {
                return Ok(());
            }
            carrier.in_aoff_tree = false;
            carrier.key_base + MBC_HEADER
        };
        self.delete_tree_node::<true>(TreeId::Carriers, node);
        Ok(())
    }

    /// Inserts the free block into the OTP intrusive bestfit tree/list.
    /// Port of `bf_link_free_block` and `aobf_link_free_block`, `erl_bestfit_alloc.c:592-818`, OTP-29.1.1.
    fn link_free(&mut self, node: usize) -> Result<(), AllocError> {
        let size = self.blk(node)?.size;
        self.link_free_inner(node, size)
    }

    fn unlink_free(&mut self, node: usize) -> Result<(), AllocError> {
        let size = self.blk(node)?.size;
        self.unlink_free_inner(node, size)
    }

    #[inline(always)]
    fn list_head(&self, list: FreeListId) -> usize {
        match list {
            FreeListId::Bucket(index) => self.goodfit_heads[index],
            FreeListId::Afit => self.afit_head,
        }
    }

    #[inline(always)]
    fn set_list_head(&mut self, list: FreeListId, node: usize) {
        match list {
            FreeListId::Bucket(index) => self.goodfit_heads[index] = node,
            FreeListId::Afit => self.afit_head = node,
        }
    }

    /// Port of link_free_block, erl_goodfit_alloc.c:440 and erl_afit_alloc.c:150, OTP-29.1.1.
    #[inline(always)]
    fn list_push_front(&mut self, list: FreeListId, node: usize) -> Result<(), AllocError> {
        let head = self.list_head(list);
        self.set_word_at(node, LIST_PREV_WORD, 0)?;
        self.set_word_at(node, LIST_NEXT_WORD, head)?;
        if head != 0 {
            self.set_word_at(head, LIST_PREV_WORD, node)?;
        }
        self.set_list_head(list, node);
        Ok(())
    }

    fn list_insert_after_head(&mut self, list: FreeListId, node: usize) -> Result<(), AllocError> {
        let head = self.list_head(list);
        if head == 0 {
            return self.list_push_front(list, node);
        }
        let next = self.word_at(head, LIST_NEXT_WORD)?;
        self.set_word_at(node, LIST_PREV_WORD, head)?;
        self.set_word_at(node, LIST_NEXT_WORD, next)?;
        if next != 0 {
            self.set_word_at(next, LIST_PREV_WORD, node)?;
        }
        self.set_word_at(head, LIST_NEXT_WORD, node)
    }

    /// Port of unlink_free_block, erl_goodfit_alloc.c:461 and erl_afit_alloc.c:166, OTP-29.1.1.
    #[inline(always)]
    fn list_remove(&mut self, list: FreeListId, node: usize) -> Result<(), AllocError> {
        let prev = self.word_at(node, LIST_PREV_WORD)?;
        let next = self.word_at(node, LIST_NEXT_WORD)?;
        if prev == 0 {
            if self.list_head(list) != node {
                return Err(AllocError::Corrupt);
            }
            self.set_list_head(list, next);
        } else {
            self.set_word_at(prev, LIST_NEXT_WORD, next)?;
        }
        if next != 0 {
            self.set_word_at(next, LIST_PREV_WORD, prev)?;
        }
        Ok(())
    }

    fn list_nodes(&self, list: FreeListId) -> Result<Vec<usize>, AllocError> {
        let mut nodes = Vec::new();
        let mut node = self.list_head(list);
        while node != 0 {
            nodes.push(node);
            node = self.word_at(node, LIST_NEXT_WORD)?;
        }
        Ok(nodes)
    }

    #[inline(always)]
    fn link_free_inner(&mut self, node: usize, size: usize) -> Result<(), AllocError> {
        let span = self.span_of(node).ok_or(AllocError::Corrupt)?;
        self.link_free_in(span, node, size)
    }

    #[inline(always)]
    fn link_free_in(
        &mut self,
        span: CarrierSpan,
        node: usize,
        size: usize,
    ) -> Result<(), AllocError> {
        if is_aoff(self.strategy) {
            self.insert_tree_node::<true>(node, size, span);
            self.aoff_raise_carrier_max(span, size);
            return Ok(());
        }
        if self.strategy == Strategy::GoodFit {
            let bucket = goodfit_bucket(size, self.goodfit_interval_d);
            self.list_push_front(FreeListId::Bucket(bucket), node)?;
            self.goodfit_mask[bucket / 64] |= 1 << (bucket % 64);
            return Ok(());
        }
        if self.strategy == Strategy::Afit {
            let head = self.afit_head;
            if head != 0 && self.blk(head)?.size > size {
                self.list_insert_after_head(FreeListId::Afit, node)?;
            } else {
                self.list_push_front(FreeListId::Afit, node)?;
            }
            return Ok(());
        }
        self.insert_tree_node::<false>(node, size, span);
        Ok(())
    }

    /// Port of rbt_insert, erl_ao_firstfit_alloc.c, OTP-29.1.1, and tree_insert_fixup, which only
    /// runs when the new red node's parent is red. The aoff `max_sz` is raised on the way down,
    /// so no walk to the root follows.
    #[inline(never)]
    fn insert_tree_node<const A: bool>(&mut self, node: usize, size: usize, span: CarrierSpan) {
        let block_node = !(A && !span.sbc && node == span.start + MBC_HEADER);
        let tree = if block_node {
            self.tree_span.set(span);
            TreeId::Blocks
        } else {
            TreeId::Carriers
        };
        let by_address = !block_node || self.strategy == Strategy::Aoff;
        let bestfit = block_node && matches!(self.strategy, Strategy::BestFit | Strategy::AoffCbf);
        let blk = self.tn::<A>(node);
        blk.set_left(0);
        blk.set_right(0);
        if A {
            blk.set_max(size);
        }
        let root = self.root_of::<A>(tree);
        if root == 0 {
            blk.set_parent(0);
            blk.set_flags(TREE_NODE);
            if bestfit {
                blk.set_next(0);
            }
            self.set_root_of::<A>(tree, node);
            return;
        }
        let mut x = self.tn::<A>(root);
        let go_left = loop {
            let x_size = x.size();
            if A && x.max() < size {
                x.set_max(size);
            }
            if bestfit && size == x_size {
                let head_next = x.next();
                blk.set_flags(0);
                blk.set_parent(x.key());
                blk.set_next(head_next);
                if head_next != 0 {
                    self.tn::<A>(head_next).set_parent(node);
                }
                x.set_next(node);
                return;
            }
            let go_left = if by_address {
                node < x.key()
            } else {
                (size, node) < (x_size, x.key())
            };
            let child = if go_left { x.left() } else { x.right() };
            if child == 0 {
                break go_left;
            }
            x = self.tn::<A>(child);
        };
        blk.set_parent(x.key());
        if go_left {
            x.set_left(node);
        } else {
            x.set_right(node);
        }
        blk.set_flags(TREE_NODE | RED);
        if x.is_red() {
            self.insert_fixup(tree, blk);
        }
        if bestfit {
            blk.set_next(0);
        }
    }

    /// First non-empty goodfit bucket at or above `from`, via `bucket_mask` like erl_goodfit_alloc.c.
    #[inline]
    fn next_goodfit_bucket(&self, from: usize) -> Option<usize> {
        let mut word = from / 64;
        if word >= self.goodfit_mask.len() {
            return None;
        }
        let mut bits = self.goodfit_mask[word] & (!0u64 << (from % 64));
        loop {
            if bits != 0 {
                return Some(word * 64 + bits.trailing_zeros() as usize);
            }
            word += 1;
            bits = *self.goodfit_mask.get(word)?;
        }
    }

    /// Finds the smallest fitting size-tree node, retaining OTP's BF list preference.
    /// Port of `bf_get_free_block` and `aobf_get_free_block`, `erl_bestfit_alloc.c:657-865`, OTP-29.1.1.
    #[inline]
    fn choose_free(&self, need: usize) -> Result<Option<usize>, AllocError> {
        Ok(self.choose_free_in(need)?.map(|(block, _)| block))
    }

    /// The span and the block tree root of the aoff carrier whose carrier tree node is
    /// `carrier_node`, read from the carrier header like `AOFF_Carrier_t` in
    /// erl_ao_firstfit_alloc.c: the node is embedded in the header, so no address search runs.
    #[inline(always)]
    #[allow(unsafe_code)]
    fn carrier_of_tree_node(&self, carrier_node: usize) -> (CarrierSpan, usize) {
        let start = carrier_node - MBC_HEADER;
        debug_assert!(
            self.aoff_carrier_index(carrier_node).is_some(),
            "carrier tree link {carrier_node:#x}"
        );
        // SAFETY: `carrier_node` is a link of the carrier tree, so it is the carrier tree node in
        // the header of an indexed aoff main block carrier (`aoff_add_carrier_node` links only
        // those and `aoff_remove_carrier_node` unlinks it before the carrier is unindexed). That
        // carrier starts at `start`, word aligned, and its header of `AOFF_MBC_HEADER` bytes lies
        // inside it.
        let header = unsafe { CarrierHeaderRef::at(start) };
        let size = header.word(0) & !CARRIER_FLAGS;
        let ids = header.word(AOFF_BLK_ORDER_WORD * WORD);
        let index = ids >> AOFF_INDEX_SHIFT;
        let span = CarrierSpan::new(start, start + size, index, false);
        let root = header.word(AOFF_ROOT_BYTE);
        debug_assert!(
            self.carrier_span(index)
                .is_ok_and(|expected| expected.start == span.start && expected.end == span.end),
            "carrier header of {start:#x}"
        );
        (span, root)
    }

    /// `aoff_get_free_block`, erl_ao_firstfit_alloc.c:895, OTP-29.1.1: the carrier tree picks the
    /// carrier and its own block tree the block. The span of the carrier comes back by value so
    /// that an inlined caller keeps it in registers.
    #[inline(always)]
    fn choose_aoff_span(&self, need: usize) -> Option<(usize, CarrierSpan)> {
        let carrier_node = self.aoff_search(self.aoff_carrier_root, need)?;
        let (span, root) = self.carrier_of_tree_node(carrier_node);
        self.tree_span.set(span);
        self.aoff_search(root, need).map(|block| (block, span))
    }

    /// `choose_free` with the span of the carrier holding the block, for `alloc`.
    #[inline(always)]
    fn choose_free_span(&self, need: usize) -> Result<Option<(usize, CarrierSpan)>, AllocError> {
        if is_aoff(self.strategy) {
            return Ok(self.choose_aoff_span(need));
        }
        match self.choose_free_in(need)? {
            Some((block, Some(span))) => Ok(Some((block, span))),
            Some((block, None)) => Ok(Some((
                block,
                self.span_of(block).ok_or(AllocError::Corrupt)?,
            ))),
            None => Ok(None),
        }
    }

    /// `choose_free` that also returns the span of the aoff carrier holding the block, which the
    /// search had to resolve anyway.
    #[inline]
    fn choose_free_in(
        &self,
        need: usize,
    ) -> Result<Option<(usize, Option<CarrierSpan>)>, AllocError> {
        // Port of aoff_get_free_block, erl_ao_firstfit_alloc.c:895, OTP-29.1.1;
        // goodfit_get_free_block, erl_goodfit_alloc.c:393, OTP-29.1.1; and
        // afit_get_free_block, erl_afit_alloc.c:123, OTP-29.1.1.
        if self.strategy == Strategy::Afit {
            let head = self.afit_head;
            if head == 0 || self.blk(head)?.size < need {
                return Ok(None);
            }
            return Ok(Some((head, None)));
        }
        if self.strategy == Strategy::GoodFit {
            let first_bucket = goodfit_bucket(need, self.goodfit_interval_d);
            let mut next_bucket = first_bucket;
            while let Some(bucket) = self.next_goodfit_bucket(next_bucket) {
                next_bucket = bucket + 1;
                let mut best = None;
                let mut node = self.goodfit_heads[bucket];
                let mut searched = 0;
                while node != 0 && searched < self.options.max_bucket_search.max(1) {
                    let size = self.blk(node)?.size;
                    if size >= need && best.is_none_or(|(_, best_size)| size < best_size) {
                        best = Some((node, size));
                        if size == need {
                            break;
                        }
                    }
                    searched += 1;
                    node = self.word_at(node, LIST_NEXT_WORD)?;
                }
                if let Some((node, _)) = best {
                    return Ok(Some((node, None)));
                }
            }
            return Ok(None);
        }
        if is_aoff(self.strategy) {
            return Ok(self
                .choose_aoff_span(need)
                .map(|(block, span)| (block, Some(span))));
        }
        let mut current = self.free_root;
        let mut best = 0;
        while current != 0 {
            let size = self.blk(current)?.size;
            if size < need {
                current = self.node_word(current, TREE_RIGHT_WORD)?;
            } else {
                best = current;
                current = self.node_word(current, TREE_LEFT_WORD)?;
            }
        }
        if best == 0 {
            return Ok(None);
        }
        if self.strategy == Strategy::BestFit {
            let next = self.node_word(best, BF_NEXT_WORD)?;
            if next != 0 {
                best = next;
            }
        }
        Ok(Some((best, None)))
    }

    /// Removes a free block from its intrusive tree node or BF size list.
    /// Port of `bf_unlink_free_block` and `tree_delete`, `erl_bestfit_alloc.c:399-433,780-806`, OTP-29.1.1.
    #[inline(always)]
    fn unlink_free_inner(&mut self, node: usize, size: usize) -> Result<(), AllocError> {
        let span = self.span_of(node).ok_or(AllocError::Corrupt)?;
        self.unlink_free_in(span, node, size)
    }

    #[inline(always)]
    fn unlink_free_in(
        &mut self,
        span: CarrierSpan,
        node: usize,
        size: usize,
    ) -> Result<(), AllocError> {
        if is_aoff(self.strategy) {
            self.tree_span.set(span);
            self.unlink_tree_node::<true>(span, node);
            return Ok(());
        }
        if self.strategy == Strategy::GoodFit {
            let index = goodfit_bucket(size, self.goodfit_interval_d);
            self.list_remove(FreeListId::Bucket(index), node)?;
            if self.goodfit_heads[index] == 0 {
                self.goodfit_mask[index / 64] &= !(1 << (index % 64));
            }
            return Ok(());
        }
        if self.strategy == Strategy::Afit {
            self.list_remove(FreeListId::Afit, node)?;
            return Ok(());
        }
        self.tree_span.set(span);
        self.unlink_tree_node::<false>(span, node);
        Ok(())
    }

    /// Port of aoff_unlink_free_block, erl_ao_firstfit_alloc.c, OTP-29.1.1, and of the tree part of
    /// bf_unlink_free_block, erl_bestfit_alloc.c, OTP-29.1.1.
    #[inline(always)]
    fn unlink_tree_node<const A: bool>(&mut self, span: CarrierSpan, node: usize) {
        let tree = TreeId::Blocks;
        let del = self.tn::<A>(node);
        if matches!(self.strategy, Strategy::BestFit | Strategy::AoffCbf) {
            if del.flags() & TREE_NODE == 0 {
                let prev = del.parent();
                let next = del.next();
                debug_assert_ne!(prev, 0, "list member {node:#x} without a head");
                self.tn::<A>(prev).set_next(next);
                if next != 0 {
                    self.tn::<A>(next).set_parent(prev);
                }
                return;
            }
            let next = del.next();
            if next != 0 {
                let new = self.tn::<A>(next);
                self.replace_tree_node(tree, del, new);
                return;
            }
        }
        self.delete_tree_node::<A>(tree, node);
        if A {
            self.aoff_lower_carrier_max(span);
        }
    }

    /// `red` for the validator, which follows links that may be corrupt: the node address is
    /// checked first.
    fn is_red(&self, node: usize) -> Result<bool, AllocError> {
        if node != 0 && !self.is_tree_node_address(node) {
            return Err(AllocError::Corrupt);
        }
        Ok(if is_aoff(self.strategy) {
            self.red::<true>(node)
        } else {
            self.red::<false>(node)
        })
    }

    /// Port of left_rotate, erl_ao_firstfit_alloc.c, OTP-29.1.1.
    #[inline(always)]
    fn rotate_left<const A: bool>(&mut self, tree: TreeId, x: TNode<A>) {
        let y_key = x.right();
        let y = self.tn::<A>(y_key);
        let beta = y.left();
        x.set_right(beta);
        if beta != 0 {
            self.tn::<A>(beta).set_parent(x.key());
        }
        let parent = x.parent();
        y.set_parent(parent);
        if parent == 0 {
            self.set_root_of::<A>(tree, y_key);
        } else {
            let p = self.tn::<A>(parent);
            if x.key() == p.left() {
                p.set_left(y_key);
            } else {
                p.set_right(y_key);
            }
        }
        y.set_left(x.key());
        x.set_parent(y_key);
        if A {
            y.set_max(x.max());
            let max = self.node_max_size(x);
            x.set_max(max);
        }
    }

    /// Port of right_rotate, erl_ao_firstfit_alloc.c, OTP-29.1.1.
    #[inline(always)]
    fn rotate_right<const A: bool>(&mut self, tree: TreeId, x: TNode<A>) {
        let y_key = x.left();
        let y = self.tn::<A>(y_key);
        let beta = y.right();
        x.set_left(beta);
        if beta != 0 {
            self.tn::<A>(beta).set_parent(x.key());
        }
        let parent = x.parent();
        y.set_parent(parent);
        if parent == 0 {
            self.set_root_of::<A>(tree, y_key);
        } else {
            let p = self.tn::<A>(parent);
            if x.key() == p.right() {
                p.set_right(y_key);
            } else {
                p.set_left(y_key);
            }
        }
        y.set_right(x.key());
        x.set_parent(y_key);
        if A {
            y.set_max(x.max());
            let max = self.node_max_size(x);
            x.set_max(max);
        }
    }

    #[inline(always)]
    fn node_max_size<const A: bool>(&self, x: TNode<A>) -> usize {
        let mut sz = x.size();
        let left = x.left();
        if left != 0 {
            sz = sz.max(self.tn::<A>(left).max());
        }
        let right = x.right();
        if right != 0 {
            sz = sz.max(self.tn::<A>(right).max());
        }
        sz
    }

    #[inline(never)]
    fn lower_max_size<const A: bool>(&self, node: TNode<A>, stop_at: usize) {
        let old_max = node.max();
        let new_max = self.node_max_size(node);
        if new_max < old_max {
            node.set_max(new_max);
            let mut x = node;
            loop {
                let parent = x.parent();
                if parent == stop_at {
                    break;
                }
                x = self.tn::<A>(parent);
                if x.max() != old_max {
                    break;
                }
                let max = self.node_max_size(x);
                x.set_max(max);
            }
        }
    }

    /// Port of tree_insert_fixup, erl_ao_firstfit_alloc.c, OTP-29.1.1.
    fn insert_fixup<const A: bool>(&mut self, tree: TreeId, blk: TNode<A>) {
        let mut x = blk;
        loop {
            let parent = self.tn::<A>(x.parent());
            let grand = self.tn::<A>(parent.parent());
            if parent.key() == grand.left() {
                let y_key = grand.right();
                if self.red::<A>(y_key) {
                    self.tn::<A>(y_key).set_black();
                    parent.set_black();
                    grand.set_red();
                    x = grand;
                } else {
                    if x.key() == parent.right() {
                        x = parent;
                        self.rotate_left(tree, x);
                    }
                    let parent = self.tn::<A>(x.parent());
                    let grand = self.tn::<A>(parent.parent());
                    parent.set_black();
                    grand.set_red();
                    self.rotate_right(tree, grand);
                    break;
                }
            } else {
                let y_key = grand.left();
                if self.red::<A>(y_key) {
                    self.tn::<A>(y_key).set_black();
                    parent.set_black();
                    grand.set_red();
                    x = grand;
                } else {
                    if x.key() == parent.left() {
                        x = parent;
                        self.rotate_right(tree, x);
                    }
                    let parent = self.tn::<A>(x.parent());
                    let grand = self.tn::<A>(parent.parent());
                    parent.set_black();
                    grand.set_red();
                    self.rotate_left(tree, grand);
                    break;
                }
            }
            if !self.red::<A>(x.parent()) {
                break;
            }
        }
        let root = self.root_of::<A>(tree);
        self.tn::<A>(root).set_black();
    }

    /// Port of replace, erl_ao_firstfit_alloc.c, OTP-29.1.1: `new` takes over every link, the color
    /// and the max of `old`. The block header of `new` is not changed.
    #[inline(always)]
    fn replace_tree_node<const A: bool>(&mut self, tree: TreeId, old: TNode<A>, new: TNode<A>) {
        let parent = old.parent();
        if parent == 0 {
            self.set_root_of::<A>(tree, new.key());
        } else {
            let p = self.tn::<A>(parent);
            if old.key() == p.left() {
                p.set_left(new.key());
            } else {
                p.set_right(new.key());
            }
        }
        let left = old.left();
        if left != 0 {
            self.tn::<A>(left).set_parent(new.key());
        }
        let right = old.right();
        if right != 0 {
            self.tn::<A>(right).set_parent(new.key());
        }
        new.set_flags(old.flags());
        new.set_parent(parent);
        new.set_right(right);
        new.set_left(left);
        if A {
            new.set_max(old.max());
        }
    }

    /// Port of rbt_delete, erl_ao_firstfit_alloc.c, OTP-29.1.1. The sentinel `null_x` of the C code
    /// is the pair (`x`, `x_parent`) here. The aoff `max_sz` is lowered right after the splice,
    /// where each walk stops as soon as an ancestor keeps its value.
    #[inline(never)]
    fn delete_tree_node<const A: bool>(&mut self, tree: TreeId, node: usize) {
        let z = self.tn::<A>(node);
        let z_right = z.right();
        let y = if z.left() == 0 || z_right == 0 {
            z
        } else {
            let mut y = self.tn::<A>(z_right);
            loop {
                let left = y.left();
                if left == 0 {
                    break y;
                }
                y = self.tn::<A>(left);
            }
        };
        let y_left = y.left();
        let x = if y_left != 0 { y_left } else { y.right() };
        let spliced_is_black = !y.is_red();
        let y_parent = y.parent();
        let mut x_parent = y_parent;
        if x != 0 {
            self.tn::<A>(x).set_parent(y_parent);
        }
        if y_parent == 0 {
            self.set_root_of::<A>(tree, x);
        } else {
            let p = self.tn::<A>(y_parent);
            if y.key() == p.left() {
                p.set_left(x);
            } else {
                p.set_right(x);
            }
            if A && y_parent != node {
                self.lower_max_size(p, if y.key() == node { 0 } else { node });
            }
        }
        if y.key() != node {
            self.replace_tree_node(tree, z, y);
            if A {
                self.lower_max_size(y, 0);
            }
            if x_parent == node {
                x_parent = y.key();
            }
        }
        if spliced_is_black {
            self.delete_fixup::<A>(tree, x, x_parent);
        }
    }

    /// The fixup loop of rbt_delete, erl_ao_firstfit_alloc.c, OTP-29.1.1.
    fn delete_fixup<const A: bool>(&mut self, tree: TreeId, mut x: usize, mut x_parent: usize) {
        while x_parent != 0 && !self.red::<A>(x) {
            let parent = self.tn::<A>(x_parent);
            if x == parent.left() {
                let mut y = self.tn::<A>(parent.right());
                if y.is_red() {
                    y.set_black();
                    parent.set_red();
                    self.rotate_left(tree, parent);
                    y = self.tn::<A>(parent.right());
                }
                let y_left = y.left();
                let y_right = y.right();
                if !self.red::<A>(y_left) && !self.red::<A>(y_right) {
                    y.set_red();
                    x = x_parent;
                    x_parent = parent.parent();
                } else {
                    if !self.red::<A>(y_right) {
                        self.tn::<A>(y_left).set_black();
                        y.set_red();
                        self.rotate_right(tree, y);
                        y = self.tn::<A>(parent.right());
                    }
                    if parent.is_red() {
                        parent.set_black();
                        y.set_red();
                    }
                    self.tn::<A>(y.right()).set_black();
                    self.rotate_left(tree, parent);
                    x = self.root_of::<A>(tree);
                    break;
                }
            } else {
                let mut y = self.tn::<A>(parent.left());
                if y.is_red() {
                    y.set_black();
                    parent.set_red();
                    self.rotate_right(tree, parent);
                    y = self.tn::<A>(parent.left());
                }
                let y_right = y.right();
                let y_left = y.left();
                if !self.red::<A>(y_right) && !self.red::<A>(y_left) {
                    y.set_red();
                    x = x_parent;
                    x_parent = parent.parent();
                } else {
                    if !self.red::<A>(y_left) {
                        self.tn::<A>(y_right).set_black();
                        y.set_red();
                        self.rotate_left(tree, y);
                        y = self.tn::<A>(parent.left());
                    }
                    if parent.is_red() {
                        parent.set_black();
                        y.set_red();
                    }
                    self.tn::<A>(y.left()).set_black();
                    self.rotate_right(tree, parent);
                    x = self.root_of::<A>(tree);
                    break;
                }
            }
        }
        if x != 0 {
            self.tn::<A>(x).set_black();
        }
    }

    fn tree_free_blocks(&self) -> Result<HashSet<usize>, AllocError> {
        fn walk(
            allocator: &AllocUtil,
            node: usize,
            parent: usize,
            lower: Option<(usize, usize)>,
            upper: Option<(usize, usize)>,
            seen: &mut HashSet<usize>,
        ) -> Result<usize, AllocError> {
            if node == 0 {
                return Ok(1);
            }
            if !seen.insert(node) {
                return Err(AllocError::Corrupt);
            }
            let block = allocator.blk(node)?;
            if block.allocated
                || allocator.node_word(node, TREE_PARENT_WORD)? != parent
                || allocator.node_word(node, TREE_FLAGS_WORD)? & TREE_NODE == 0
            {
                return Err(AllocError::Corrupt);
            }
            let key = match allocator.strategy {
                Strategy::Aoff => (0, node),
                Strategy::AoffCbf => (block.size, 0),
                _ => (block.size, node),
            };
            if lower.is_some_and(|bound| key <= bound) || upper.is_some_and(|bound| key >= bound) {
                return Err(AllocError::Corrupt);
            }
            let left = allocator.node_word(node, TREE_LEFT_WORD)?;
            let right = allocator.node_word(node, TREE_RIGHT_WORD)?;
            let red = allocator.is_red(node)?;
            if red && (allocator.is_red(left)? || allocator.is_red(right)?) {
                return Err(AllocError::Corrupt);
            }
            if matches!(allocator.strategy, Strategy::BestFit | Strategy::AoffCbf) {
                let mut list = allocator.node_word(node, BF_NEXT_WORD)?;
                let mut previous = node;
                while list != 0 {
                    if !seen.insert(list)
                        || allocator
                            .blk(list)
                            .map_or(true, |b| b.allocated || b.size != block.size)
                        || allocator.node_word(list, TREE_FLAGS_WORD)? & TREE_NODE != 0
                        || allocator.node_word(list, TREE_PARENT_WORD)? != previous
                    {
                        return Err(AllocError::Corrupt);
                    }
                    previous = list;
                    list = allocator.node_word(list, BF_NEXT_WORD)?;
                }
            }
            let left_height = walk(allocator, left, node, lower, Some(key), seen)?;
            let right_height = walk(allocator, right, node, Some(key), upper, seen)?;
            if left_height != right_height {
                return Err(AllocError::Corrupt);
            }
            Ok(left_height + usize::from(!red))
        }
        let mut seen = HashSet::default();
        match self.strategy {
            Strategy::GoodFit => {
                let mut nodes = HashSet::default();
                for bucket in 0..self.goodfit_heads.len() {
                    for node in self.list_nodes(FreeListId::Bucket(bucket))? {
                        if !nodes.insert(node) {
                            return Err(AllocError::Corrupt);
                        }
                    }
                }
                return Ok(nodes);
            }
            Strategy::Afit => {
                let nodes = self.list_nodes(FreeListId::Afit)?;
                let set = nodes.iter().copied().collect::<HashSet<_>>();
                if set.len() != nodes.len() {
                    return Err(AllocError::Corrupt);
                }
                return Ok(set);
            }
            _ => {}
        }
        let roots: Vec<usize> = if is_aoff(self.strategy) {
            let mut roots = Vec::new();
            for index in 0..self.carriers.len() {
                if let Some(entry) = self.carriers[index].as_ref()
                    && !entry.sbc
                {
                    roots.push(self.aoff_root(self.carrier_span(index)?));
                }
            }
            roots
        } else {
            vec![self.free_root]
        };
        for root in roots {
            if root != 0 && self.is_red(root)? {
                return Err(AllocError::Corrupt);
            }
            walk(self, root, 0, None, None, &mut seen)?;
        }
        Ok(seen)
    }
    #[inline(always)]
    fn previous_block(&self, offset: usize) -> Result<usize, AllocError> {
        let size = self.word_at(offset - WORD, 0)?;
        let previous = offset.checked_sub(size).ok_or(AllocError::Corrupt)?;
        let carrier = self
            .carrier_of(offset)
            .and_then(|index| self.carriers[index].as_ref())
            .ok_or(AllocError::Corrupt)?;
        if size == 0 || previous < carrier.start {
            return Err(AllocError::Corrupt);
        }
        Ok(previous)
    }

    /// Destroys a carrier whose only block was just freed and never linked into a free index.
    fn remove_carrier(&mut self, ci: usize) -> Result<(), AllocError> {
        if is_aoff(self.strategy) {
            self.aoff_remove_carrier_node(ci)?;
        }
        if let Some(c) = self.vacate_carrier(ci) {
            self.carrier_removed(c.sbc, c.mseg, c.size);
            self.stats.carriers -= 1;
            self.stats.carriers_size -= c.size;
            if c.mseg {
                self.stats.mseg_carriers -= 1;
                self.stats.mseg_carriers_size -= c.size;
                self.stats.mseg_dealloc_calls += 1;
                if let CarrierMemory::Segmented(segment) = c.memory {
                    self.mseg.dealloc(segment, MsegOptions::default());
                }
            } else {
                self.stats.sys_alloc_carriers -= 1;
                self.stats.sys_alloc_carriers_size -= c.size;
                self.stats.sys_free_calls += 1;
                if let CarrierMemory::Arena(region) = c.memory {
                    self.carrier_arena
                        .as_mut()
                        .ok_or(AllocError::Corrupt)?
                        .release(region);
                }
            }
        }
        Ok(())
    }
    fn update_carrier_peak(&mut self) {
        self.stats.max_carriers = self.stats.max_carriers.max(self.stats.carriers);
        self.stats.max_carriers_size = self.stats.max_carriers_size.max(self.stats.carriers_size);
        self.stats.max_mseg_carriers = self.stats.max_mseg_carriers.max(self.stats.mseg_carriers);
        self.stats.max_sys_alloc_carriers = self
            .stats
            .max_sys_alloc_carriers
            .max(self.stats.sys_alloc_carriers);
        self.stats.max_mseg_carriers_size = self
            .stats
            .max_mseg_carriers_size
            .max(self.stats.mseg_carriers_size);
        self.stats.max_sys_alloc_carriers_size = self
            .stats
            .max_sys_alloc_carriers_size
            .max(self.stats.sys_alloc_carriers_size);
        self.stats.max_ever_carriers = self.stats.max_ever_carriers.max(self.stats.max_carriers);
        self.stats.max_ever_carriers_size = self
            .stats
            .max_ever_carriers_size
            .max(self.stats.max_carriers_size);
        self.stats.max_ever_mseg_carriers = self
            .stats
            .max_ever_mseg_carriers
            .max(self.stats.mseg_carriers);
        self.stats.max_ever_sys_alloc_carriers = self
            .stats
            .max_ever_sys_alloc_carriers
            .max(self.stats.sys_alloc_carriers);
        self.stats.max_ever_mseg_carriers_size = self
            .stats
            .max_ever_mseg_carriers_size
            .max(self.stats.mseg_carriers_size);
        self.stats.max_ever_sys_alloc_carriers_size = self
            .stats
            .max_ever_sys_alloc_carriers_size
            .max(self.stats.sys_alloc_carriers_size);
    }
    #[inline]
    fn update_series(series: &mut ValueSeries) {
        if series.current > series.max {
            series.max = series.current;
            series.max_ever = series.max_ever.max(series.max);
        }
    }
    #[inline(always)]
    fn block_added(&mut self, sbc: bool, size: usize) {
        let class = &mut self.class_stats[usize::from(sbc)];
        class.blocks.current += 1;
        class.blocks_size.current += size;
        Self::update_series(&mut class.blocks);
        Self::update_series(&mut class.blocks_size);
    }
    #[inline(always)]
    fn block_removed(&mut self, sbc: bool, size: usize) {
        let class = &mut self.class_stats[usize::from(sbc)];
        class.blocks.current -= 1;
        class.blocks_size.current -= size;
    }
    fn block_resized(&mut self, sbc: bool, old_size: usize, new_size: usize) {
        let class = &mut self.class_stats[usize::from(sbc)];
        class.blocks_size.current = class.blocks_size.current - old_size + new_size;
        Self::update_series(&mut class.blocks_size);
    }
    fn carrier_added(&mut self, sbc: bool, mseg: bool, size: usize) {
        let class = &mut self.class_stats[usize::from(sbc)];
        class.carriers.current += 1;
        class.carriers_size.current += size;
        Self::update_series(&mut class.carriers);
        Self::update_series(&mut class.carriers_size);
        let (count, bytes) = if mseg {
            (&mut class.mseg_carriers, &mut class.mseg_carriers_size)
        } else {
            (&mut class.sys_carriers, &mut class.sys_carriers_size)
        };
        count.current += 1;
        bytes.current += size;
        Self::update_series(count);
        Self::update_series(bytes);
        if !sbc {
            self.set_new_allctr_abandon_limit();
        }
    }

    /// Port of set_new_allctr_abandon_limit, erl_alloc_util.c, OTP-29.1.1.
    #[inline(always)]
    fn set_new_allctr_abandon_limit(&mut self) {
        self.abandon_limit =
            percent_limit(self.class_stats[0].carriers_size.current, self.options.acul);
    }
    fn carrier_removed(&mut self, sbc: bool, mseg: bool, size: usize) {
        let class = &mut self.class_stats[usize::from(sbc)];
        class.carriers.current -= 1;
        class.carriers_size.current -= size;
        let (count, bytes) = if mseg {
            (&mut class.mseg_carriers, &mut class.mseg_carriers_size)
        } else {
            (&mut class.sys_carriers, &mut class.sys_carriers_size)
        };
        count.current -= 1;
        bytes.current -= size;
        if !sbc {
            self.set_new_allctr_abandon_limit();
        }
    }
    fn carrier_resized(&mut self, sbc: bool, mseg: bool, old_size: usize, new_size: usize) {
        let class = &mut self.class_stats[usize::from(sbc)];
        class.carriers_size.current = class.carriers_size.current - old_size + new_size;
        Self::update_series(&mut class.carriers_size);
        let bytes = if mseg {
            &mut class.mseg_carriers_size
        } else {
            &mut class.sys_carriers_size
        };
        bytes.current = bytes.current - old_size + new_size;
        Self::update_series(bytes);
    }
}

/// Allocation failure with no unsafe or unchecked pointer API.
#[derive(Debug)]
pub enum AllocError {
    Map(std::io::ErrorKind),
    NoSpace,
    InvalidAllocation,
    OutOfBounds,
    Corrupt,
    Overflow,
}
impl AllocError {
    /// Keeps the error `Copy`-like: a payload with drop glue (`io::Error`) makes every eagerly
    /// built `ok_or(AllocError::..)` on the hot success path call a destructor.
    fn mapped(error: MapError) -> Self {
        Self::Map(error.0.kind())
    }
}
impl std::fmt::Display for AllocError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for AllocError {}

/// Port of the `min_block_size` setup in erts_alcu_start, erl_alloc_util.c, OTP-29.1.1: the node
/// struct plus the free block footer, rounded to the unit. The aoff node carries the list word.
fn min_block_size(strategy: Strategy) -> usize {
    let node_size = if strategy == Strategy::BestFit || is_aoff(strategy) {
        BF_NODE_SIZE
    } else {
        RB_NODE_SIZE
    };
    align_const(node_size + FOOTER)
}

fn is_aoff(strategy: Strategy) -> bool {
    matches!(
        strategy,
        Strategy::Aoff | Strategy::AoffCbf | Strategy::AoffCaobf
    )
}

/// Returns OTP goodfit's four linear bucket regions' bucket index.
/// Port of BKT_IX_, erl_goodfit_alloc.c:101-115, OTP-29.1.1.
const GF_MIN_BLOCK: usize = 40;
const GF_QUARTER: usize = 64;
const GF_A: usize = 8;
const GF_B: usize = 128;
const GF_C: usize = 768;
const GF_MAX_A: usize = GF_MIN_BLOCK + GF_QUARTER * GF_A - 1;
const GF_MIN_B: usize = GF_MAX_A + 1;
const GF_MAX_B: usize = GF_MIN_B + GF_QUARTER * GF_B - 1;
const GF_MIN_C: usize = GF_MAX_B + 1;
const GF_MAX_C: usize = GF_MIN_C + GF_QUARTER * GF_C - 1;
const GF_MIN_D: usize = GF_MAX_C + 1;

/// Region D bucket interval for `sbct`, computed once per allocator like `bkt_intrvl_d`.
/// Port of erts_gfalc_start, erl_goodfit_alloc.c:236-247, OTP-29.1.1.
fn goodfit_interval_d(sbct: usize) -> usize {
    const QUARTER: usize = GF_QUARTER;
    const C: usize = GF_C;
    let min_d = GF_MIN_D;
    if sbct > min_d - 1 {
        let raw = 3usize
            .saturating_mul(sbct.saturating_sub(min_d + 1))
            .checked_div(QUARTER - 1)
            .unwrap_or(usize::MAX)
            .div_ceil(2);
        align_const(raw.max(C))
    } else {
        C
    }
}

#[inline(always)]
fn goodfit_bucket(size: usize, interval_d: usize) -> usize {
    let max_d = GF_MIN_D.saturating_add(GF_QUARTER.saturating_mul(interval_d) - 1);
    if size <= GF_MAX_A {
        (size.saturating_sub(GF_MIN_BLOCK)) / GF_A
    } else if size <= GF_MAX_B {
        GF_QUARTER + (size - GF_MIN_B) / GF_B
    } else if size <= GF_MAX_C {
        2 * GF_QUARTER + (size - GF_MIN_C) / GF_C
    } else if size <= max_d {
        3 * GF_QUARTER + (size - GF_MIN_D) / interval_d
    } else {
        255
    }
}

fn call_count(total: u64) -> CallCount {
    CallCount {
        giga: total / 1_000_000_000,
        count: (total % 1_000_000_000) as u32,
    }
}
fn align_up(n: usize) -> Result<usize, AllocError> {
    n.checked_add(ALIGN - 1)
        .map(|v| v & !(ALIGN - 1))
        .ok_or(AllocError::Overflow)
}
fn block_size(n: usize, strategy: Strategy) -> Result<usize, AllocError> {
    align_up(
        BLOCK_HEADER
            .checked_add(n)
            .ok_or(AllocError::Overflow)?
            .max(min_block_size(strategy)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::{prop_assert, prop_assert_eq, proptest, test_runner::Config as ProptestConfig};
    #[test]
    fn otp_header_layout_matches_arm64_abi() {
        assert_eq!(std::mem::size_of::<BlockLayout>(), 2 * WORD);
        assert_eq!(RB_NODE_SIZE, 6 * WORD);
        assert_eq!(BF_NODE_SIZE, 7 * WORD);
        assert_eq!(ALIGN, 8);
        assert_eq!(SBC_HEADER, 32);
        assert_eq!(MBC_HEADER, 352);
        assert_eq!(AOFF_MBC_HEADER, 424);
        assert_eq!(AOFF_ROOT_WORD * WORD, 408);
    }
    #[test]
    fn aoff_carrier_header_holds_block_root_and_order() {
        for (strategy, order) in [
            (Strategy::Aoff, 1),
            (Strategy::AoffCaobf, 2),
            (Strategy::AoffCbf, 3),
        ] {
            let mut a = AllocUtil::new(strategy, AllocUtilOptions::default());
            let first = a.alloc(64).unwrap();
            let second = a.alloc(64).unwrap();
            let carrier = a.carriers.iter().flatten().find(|c| !c.sbc).unwrap();
            let read = |word: usize| carrier.memory.read_word(word * WORD).unwrap();
            assert_eq!(read(AOFF_BLK_ORDER_WORD) & 0xffff_ffff, order);
            let index = a.carrier_of(carrier.key_base).unwrap();
            assert_eq!(read(AOFF_BLK_ORDER_WORD) >> AOFF_INDEX_SHIFT, index);
            assert_ne!(read(AOFF_ROOT_WORD), 0);
            a.free(first).unwrap();
            a.free(second).unwrap();
            a.validate().unwrap();
        }
    }
    #[test]
    fn bf_and_aobf_allocate_and_coalesce() {
        for s in [
            Strategy::BestFit,
            Strategy::AddressOrderBestFit,
            Strategy::Aoff,
            Strategy::AoffCbf,
            Strategy::AoffCaobf,
            Strategy::GoodFit,
            Strategy::Afit,
        ] {
            let mut a = AllocUtil::new(
                s,
                AllocUtilOptions {
                    sbct: 4096,
                    smbcs: 8192,
                    mmbcs: 8192,
                    lmbcs: 8192,
                    ..Default::default()
                },
            );
            let x = a.alloc(128).unwrap();
            let y = a.alloc(128).unwrap();
            a.free(x).unwrap();
            a.free(y).unwrap();
            a.validate().unwrap();
            assert_eq!(a.block_count(), 0);
        }
    }
    #[test]
    fn sbc_threshold_uses_runtime_option() {
        let o = AllocUtilOptions {
            sbct: 128,
            ..Default::default()
        };
        let mut a = AllocUtil::new(Strategy::BestFit, o);
        let x = a.alloc(128).unwrap();
        assert_eq!(a.stats().mseg_carriers + a.stats().sys_alloc_carriers, 1);
        a.validate().unwrap();
        a.free(x).unwrap();
        assert_eq!(a.stats().carriers, 0);

        let options = AllocUtilOptions {
            sbct: 128,
            mmsbc: 0,
            ..Default::default()
        };
        let mut fallback = AllocUtil::new(Strategy::BestFit, options);
        let block = fallback.alloc(128).unwrap();
        assert_eq!(fallback.stats().sys_alloc_carriers, 1);
        fallback.free(block).unwrap();
    }
    #[test]
    fn sbc_realloc_obeys_shrink_move_threshold_and_updates_calls() {
        let options = AllocUtilOptions {
            sbct: 512,
            rsbcmt: 100,
            mmsbc: 0,
            ..Default::default()
        };
        let mut allocator = AllocUtil::new(Strategy::BestFit, options);
        let block = allocator.alloc(600).unwrap();
        let resized = allocator.realloc(block, 300).unwrap();
        assert_eq!(allocator.stats().sys_realloc_calls, 1);
        assert_eq!(allocator.info().sbcs.blocks, 1);
        assert_eq!(allocator.info().mbcs.blocks, 0);
        allocator.validate().unwrap();
        allocator.free(resized).unwrap();
    }
    #[test]
    fn sbc_mseg_realloc_preserves_payload_and_accounts_resize() {
        let options = AllocUtilOptions {
            sbct: 512,
            mmsbc: 1,
            ..Default::default()
        };
        let mut allocator = AllocUtil::new(Strategy::BestFit, options);
        let block = allocator.alloc(600).unwrap();
        allocator.write(block, 0, &[0x5a, 0xa5]).unwrap();
        let resized = allocator.realloc(block, 5000).unwrap();
        let mut bytes = [0; 2];
        allocator.read(resized, 0, &mut bytes).unwrap();
        assert_eq!(bytes, [0x5a, 0xa5]);
        assert_eq!(allocator.stats().mseg_realloc_calls, 1);
        allocator.validate().unwrap();
        allocator.free(resized).unwrap();
    }
    #[test]
    fn rmbcmt_controls_mbc_shrink_moves() {
        let options = AllocUtilOptions {
            sbct: 4096,
            smbcs: 16 * 1024,
            mmbcs: 16 * 1024,
            lmbcs: 16 * 1024,
            rmbcmt: 0,
            ..Default::default()
        };
        let mut allocator = AllocUtil::new(Strategy::BestFit, options);
        let large = allocator.alloc(1000).unwrap();
        let hole = allocator.alloc(128).unwrap();
        let _guard = allocator.alloc(1000).unwrap();
        let old_offset = large.id;
        allocator.free(hole).unwrap();
        let smaller = allocator.realloc(large, 16).unwrap();
        assert_ne!(smaller.id, old_offset);
        assert_eq!(allocator.stats().alloc_calls, 3);
        assert_eq!(allocator.stats().free_calls, 1);
        allocator.validate().unwrap();
    }
    #[test]
    fn mbc_main_carrier_uses_sys_alloc_then_mseg_limit_applies() {
        let options = AllocUtilOptions {
            sbct: 64 * 1024,
            mmbcs: 8192,
            smbcs: 8192,
            lmbcs: 8192,
            mmmbc: 1,
            ..Default::default()
        };
        let mut allocator = AllocUtil::new(Strategy::BestFit, options);
        let first = allocator.alloc(13_000).unwrap();
        assert_eq!(allocator.stats().sys_alloc_carriers, 1);
        let second = allocator.alloc(13_000).unwrap();
        assert_eq!(allocator.stats().mseg_carriers, 1);
        let third = allocator.alloc(4000).unwrap();
        assert_eq!(allocator.stats().sys_alloc_carriers, 1);
        assert!(allocator.stats().mseg_alloc_calls >= 1);
        allocator.validate().unwrap();
        allocator.free(first).unwrap();
        allocator.free(second).unwrap();
        allocator.free(third).unwrap();

        let limited_options = AllocUtilOptions {
            mmmbc: 0,
            ..options
        };
        let mut limited = AllocUtil::new(Strategy::BestFit, limited_options);
        let first = limited.alloc(13_000).unwrap();
        let second = limited.alloc(13_000).unwrap();
        assert_eq!(limited.stats().mseg_carriers, 0);
        assert_eq!(limited.stats().sys_alloc_carriers, 2);
        limited.free(first).unwrap();
        limited.free(second).unwrap();
    }
    #[test]
    fn bestfit_uses_smallest_fit_and_aobf_breaks_ties_by_address() {
        let options = AllocUtilOptions {
            sbct: 4096,
            smbcs: 16 * 1024,
            mmbcs: 16 * 1024,
            lmbcs: 16 * 1024,
            ..Default::default()
        };
        let mut best = AllocUtil::new(Strategy::BestFit, options);
        let large = best.alloc(1000).unwrap();
        let spacer = best.alloc(16).unwrap();
        let small = best.alloc(500).unwrap();
        let _guard = best.alloc(1000).unwrap();
        let small_address = small.id;
        best.free(large).unwrap();
        best.free(small).unwrap();
        let chosen = best.alloc(400).unwrap();
        assert_eq!(chosen.id, small_address);
        best.free(spacer).unwrap();

        let mut address = AllocUtil::new(Strategy::AddressOrderBestFit, options);
        let lower = address.alloc(500).unwrap();
        let separator = address.alloc(16).unwrap();
        let higher = address.alloc(500).unwrap();
        let _guard = address.alloc(1000).unwrap();
        let lower_address = address.allocation_ptr(lower).unwrap() as usize;
        address.free(lower).unwrap();
        address.free(higher).unwrap();
        let chosen = address.alloc(500).unwrap();
        let chosen_address = address.allocation_ptr(chosen).unwrap() as usize;
        assert_eq!(chosen_address, lower_address);
        address.free(separator).unwrap();
        address.validate().unwrap();
    }

    #[test]
    fn literal_allocator_returns_empty_carriers_to_the_reserved_range() {
        let region = RawRegion::map(4 * 1024 * 1024).unwrap();
        let start = region.as_ptr() as usize;
        let end = start + region.len();
        let mut allocator = AllocUtil::new_literal_alloc(region);

        let first = allocator.alloc(600 * 1024).unwrap();
        let second = allocator.alloc(600 * 1024).unwrap();
        let second_ptr = allocator.allocation_ptr(second).unwrap() as usize;
        assert!(second_ptr >= start && second_ptr < end);
        similar_asserts::assert_eq!(allocator.stats().carriers, 2);

        allocator.free(second).unwrap();
        similar_asserts::assert_eq!(allocator.stats().carriers, 1);
        let reused = allocator.alloc(600 * 1024).unwrap();
        similar_asserts::assert_eq!(
            allocator.allocation_ptr(reused).unwrap() as usize,
            second_ptr
        );
        allocator.free(reused).unwrap();
        allocator.free(first).unwrap();
        allocator.validate().unwrap();
    }

    #[test]
    fn afit_selects_the_largest_block_at_the_free_list_head() {
        let options = AllocUtilOptions {
            sbct: 32 * 1024,
            smbcs: 16 * 1024,
            mmbcs: 16 * 1024,
            lmbcs: 16 * 1024,
            ..Default::default()
        };
        let mut allocator = AllocUtil::new(Strategy::Afit, options);
        let small = allocator.alloc(128).unwrap();
        let _separator = allocator.alloc(16).unwrap();
        let large = allocator.alloc(1024).unwrap();
        let _separator = allocator.alloc(16).unwrap();
        let _guard = allocator.alloc(14_400).unwrap();
        let large_offset = large.id as usize;
        allocator.free(small).unwrap();
        allocator.free(large).unwrap();
        assert_eq!(allocator.afit_head, large_offset);
        let reused = allocator.alloc(512).unwrap();
        assert_eq!(reused.id as usize, large_offset);
        assert_eq!(allocator.info().mbcs.carriers, 1);
        allocator.validate().unwrap();
    }

    #[test]
    fn goodfit_searches_the_requested_bucket_then_larger_buckets() {
        let options = AllocUtilOptions {
            sbct: 32 * 1024,
            smbcs: 64 * 1024,
            mmbcs: 64 * 1024,
            lmbcs: 64 * 1024,
            ..Default::default()
        };
        let mut allocator = AllocUtil::new(Strategy::GoodFit, options);
        let small = allocator.alloc(128).unwrap();
        let _separator = allocator.alloc(16).unwrap();
        let fitting = allocator.alloc(512).unwrap();
        let _separator = allocator.alloc(16).unwrap();
        let _guard = allocator.alloc(1024).unwrap();
        let fitting_offset = fitting.id as usize;
        allocator.free(small).unwrap();
        allocator.free(fitting).unwrap();
        assert_eq!(
            allocator
                .choose_free(block_size(400, Strategy::GoodFit).unwrap())
                .unwrap(),
            Some(fitting_offset)
        );
        allocator.validate().unwrap();
    }
    #[test]
    fn payload_bounds_and_realloc() {
        let mut a = AllocUtil::new(Strategy::AddressOrderBestFit, AllocUtilOptions::default());
        let x = a.alloc(32).unwrap();
        a.write(x, 0, &[1, 2, 3]).unwrap();
        let y = a.realloc(x, 800).unwrap();
        let mut b = [0; 3];
        a.read(y, 0, &mut b).unwrap();
        assert_eq!(b, [1, 2, 3]);
        a.validate().unwrap();
    }
    #[test]
    fn info_reports_mbc_sbc_and_per_instance_calls() {
        let options = AllocUtilOptions {
            sbct: 256,
            smbcs: 16 * 1024,
            mmbcs: 16 * 1024,
            lmbcs: 16 * 1024,
            ..Default::default()
        };
        let mut allocator = AllocUtil::new(Strategy::BestFit, options);
        let mbc_block = allocator.alloc(32).unwrap();
        let sbc_block = allocator.alloc(512).unwrap();
        let info = allocator.info();
        assert_eq!(info.mbcs.blocks, 1);
        assert_eq!(info.sbcs.blocks, 1);
        assert_eq!(info.mbcs.carriers, 1);
        assert_eq!(info.sbcs.carriers, 1);
        assert_eq!(info.calls.alloc_calls, 2);
        allocator.free(mbc_block).unwrap();
        allocator.free(sbc_block).unwrap();
        let info = allocator.info();
        // The main carrier survives being emptied (erl_alloc_util.c:2791).
        assert_eq!(info.mbcs.carriers, 1);
        assert_eq!(info.sbcs.carriers, 0);
        assert_eq!(info.calls.free_calls, 2);
        assert_eq!(info.mbcs.blocks_max, 1);
        assert_eq!(info.mbcs.blocks_max_ever, 1);
        assert_eq!(info.call_counts.free.count, 2);
    }

    #[test]
    fn call_counters_use_erts_giga_pairs() {
        assert_eq!(call_count(1_000_000_001), CallCount { giga: 1, count: 1 });
    }

    #[test]
    fn erl_eheap_defaults_match() {
        let d = AllocUtilOptions::default();
        assert_eq!(
            (
                d.sbct, d.asbcst, d.rsbcst, d.rsbcmt, d.rmbcmt, d.mmbcs, d.mmmbc, d.mmsbc, d.smbcs,
                d.lmbcs, d.mbcgs
            ),
            (
                524288,
                4145152,
                50,
                80,
                50,
                131072,
                usize::MAX,
                256,
                262144,
                5242880,
                10
            )
        );
        assert_eq!(
            (d.acful, d.acul, d.acnl, d.acfml, d.cpool),
            (0, 0, 0, 0, None)
        );
    }

    fn tree_writes_per_equal_size_pair(
        strategy: Strategy,
        free_blocks: usize,
        pairs: usize,
    ) -> f64 {
        let mut allocator = AllocUtil::new(
            strategy,
            AllocUtilOptions {
                sbct: 1 << 20,
                smbcs: 8 << 20,
                mmbcs: 8 << 20,
                lmbcs: 8 << 20,
                ..Default::default()
            },
        );
        let mut live = Vec::new();
        for index in 0..free_blocks * 2 {
            let size = 64 + (index % 7) * 16;
            live.push(allocator.alloc(size).unwrap());
        }
        for (index, allocation) in live.iter().enumerate() {
            if index % 2 == 1 {
                allocator.free(*allocation).unwrap();
            }
        }
        let size = 64 + 16;
        let warm = allocator.alloc(size).unwrap();
        allocator.free(warm).unwrap();
        allocator.validate().unwrap();
        let before = crate::raw::NODE_WRITES.with(|writes| writes.get());
        for _ in 0..pairs {
            let allocation = allocator.alloc(size).unwrap();
            allocator.free(allocation).unwrap();
        }
        let after = crate::raw::NODE_WRITES.with(|writes| writes.get());
        allocator.validate().unwrap();
        (after - before) as f64 / pairs as f64
    }

    fn tree_work_per_pair(strategy: Strategy, pairs: usize) -> (f64, f64, f64) {
        let mut allocator = AllocUtil::new(strategy, AllocUtilOptions::default());
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let background: Vec<Allocation> = (0..2000)
            .map(|_| allocator.alloc(16 + (next() % 20) as usize * 16).unwrap())
            .collect();
        for allocation in background.iter().step_by(2) {
            allocator.free(*allocation).unwrap();
        }
        let mut fragments = Vec::with_capacity(32);
        let counts = || {
            (
                crate::raw::NODE_READS.with(|c| c.get()),
                crate::raw::NODE_WRITES.with(|c| c.get()),
                crate::raw::NODE_CHECKS.with(|c| c.get()),
            )
        };
        let before = counts();
        for _ in 0..pairs / 26 {
            for _ in 0..26 {
                fragments.push(allocator.alloc(8 + (next() % 12) as usize * 8).unwrap());
            }
            for allocation in fragments.drain(..) {
                allocator.free(allocation).unwrap();
            }
        }
        let after = counts();
        let n = (pairs / 26 * 26) as f64;
        (
            (after.0 - before.0) as f64 / n,
            (after.1 - before.1) as f64 / n,
            (after.2 - before.2) as f64 / n,
        )
    }

    #[test]
    fn fragment_pairs_cost_bounded_node_work() {
        let (reads, writes, checks) = tree_work_per_pair(Strategy::AoffCbf, 26 * 400);
        assert!(reads <= 36.0, "node reads per pair {reads}");
        assert!(writes <= 16.0, "node writes per pair {writes}");
        assert!(checks <= 18.0, "node address checks per pair {checks}");
    }

    #[test]
    fn equal_size_pairs_cost_constant_tree_writes() {
        let small = tree_writes_per_equal_size_pair(Strategy::AoffCbf, 64, 1000);
        let large = tree_writes_per_equal_size_pair(Strategy::AoffCbf, 4096, 1000);
        assert!(small <= 24.0, "{small}");
        assert!(large <= small, "{small} vs {large}");
    }

    fn abandon_options() -> AllocUtilOptions {
        AllocUtilOptions {
            sbct: 1 << 20,
            mmbcs: 64 << 10,
            smbcs: 64 << 10,
            lmbcs: 64 << 10,
            mbcgs: 1,
            acul: 60,
            acful: 40,
            acnl: 1000,
            acfml: 64,
            cpool: Some('H'),
            ..AllocUtilOptions::default()
        }
    }

    fn drop_abandoned(
        allocator: &mut AllocUtil,
        live: &mut Vec<Allocation>,
        abandoned: &mut usize,
    ) {
        for transfer in allocator.take_pending_carriers() {
            *abandoned += 1;
            for (gone, _) in transfer.allocations() {
                live.retain(|allocation| allocation.id != gone.id);
            }
        }
    }

    #[test]
    fn abandon_limits_follow_erts_rounding() {
        assert_eq!(percent_limit(1000, 60), 600);
        assert_eq!(percent_limit(1000, 1), 10);
        assert_eq!(percent_limit(150, 1), 1);
        assert_eq!(percent_limit(0, 45), 0);
    }

    #[test]
    fn abandon_decision_from_counters_matches_carrier_walk_and_frees_do_not_walk() {
        let mut allocator = AllocUtil::new_for_instance(
            Strategy::AoffCbf,
            abandon_options(),
            "eheap_alloc",
            0,
            true,
        );
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut live: Vec<Allocation> = Vec::new();
        let (mut abandoned, mut plain_frees) = (0, 0);
        for step in 0..30_000_usize {
            let grow_bias = if (step / 1500) % 2 == 0 { 75 } else { 25 };
            let roll = next() % 100;
            if live.is_empty() || roll < grow_bias {
                let size = 16 + (next() % 3000) as usize;
                live.push(allocator.alloc(size).unwrap());
            } else if roll % 9 == 0 {
                let at = (next() as usize) % live.len();
                let size = 16 + (next() % 3000) as usize;
                if let Ok(moved) = allocator.realloc(live[at], size) {
                    live[at] = moved;
                }
            } else {
                let at = (next() as usize) % live.len();
                let victim = live.swap_remove(at);
                let walks = allocator.carrier_walks.get();
                let pending = allocator.pending_carriers.len();
                allocator.free(victim).unwrap();
                if allocator.pending_carriers.len() == pending {
                    assert_eq!(allocator.carrier_walks.get(), walks, "step {step}");
                    plain_frees += 1;
                }
            }
            drop_abandoned(&mut allocator, &mut live, &mut abandoned);
            if step % 97 == 0 {
                allocator.validate().unwrap();
            }
        }
        allocator.validate().unwrap();
        assert!(abandoned >= 3, "{abandoned}");
        assert!(plain_frees >= 3000, "{plain_frees}");
    }

    #[test]
    fn aoff_block_orders_follow_the_strategy() {
        for (strategy, best_fit_block) in [
            (Strategy::Aoff, false),
            (Strategy::AoffCbf, true),
            (Strategy::AoffCaobf, true),
        ] {
            let mut allocator = AllocUtil::new(strategy, AllocUtilOptions::default());
            let large = allocator.alloc(200).unwrap();
            let _fence_a = allocator.alloc(32).unwrap();
            let small = allocator.alloc(100).unwrap();
            let _fence_b = allocator.alloc(32).unwrap();
            allocator.free(large).unwrap();
            allocator.free(small).unwrap();
            let picked = allocator.alloc(90).unwrap();
            let expected = if best_fit_block { small } else { large };
            assert_eq!(picked.id, expected.id, "{strategy:?}");
            allocator.validate().unwrap();
        }
    }

    #[test]
    #[ignore = "timing: cargo test --release -p arinsal-alloc abandon_check_bench -- --ignored --nocapture"]
    fn abandon_check_bench() {
        let mut allocator = AllocUtil::new_for_instance(
            Strategy::AoffCbf,
            AllocUtilOptions {
                acul: 45,
                acful: 25,
                acnl: 1000,
                acfml: 0,
                mmmbc: 0,
                ..abandon_options()
            },
            "eheap_alloc",
            0,
            true,
        );
        allocator.verify_abandon_by_walk = false;
        let mut blocks = Vec::new();
        for _ in 0..2300 {
            blocks.push(allocator.alloc(100).unwrap());
        }
        for (index, allocation) in blocks.iter().enumerate() {
            let Ok(block) = allocator.live_block(allocation.id as usize) else {
                continue;
            };
            if index % 4 == 1 && !allocator.carriers[block.carrier].as_ref().unwrap().main {
                allocator.free(*allocation).unwrap();
            }
        }
        assert!(allocator.pending_carriers.is_empty());
        let cycles: usize = std::env::var("FRAG_CYCLES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(500_000);
        let started = std::time::Instant::now();
        for _ in 0..cycles {
            let allocation = allocator.alloc(100).unwrap();
            allocator.free(allocation).unwrap();
        }
        let nanos = started.elapsed().as_nanos() as f64;
        eprintln!(
            "abandon check: {:.1} ns per alloc+free pair, {} carriers, {} walks, {} pending",
            nanos / cycles as f64,
            allocator.mbc_count,
            allocator.carrier_walks.get(),
            allocator.pending_carriers.len()
        );
    }

    #[test]
    #[ignore = "timing: cargo test --release -p arinsal-alloc fragment_cycle_bench -- --ignored --nocapture"]
    fn fragment_cycle_bench() {
        for strategy in [Strategy::AoffCbf, Strategy::Aoff] {
            let mut allocator = AllocUtil::new(strategy, AllocUtilOptions::default());
            let mut state = 0x2545_f491_4f6c_dd1d_u64;
            let mut next = move || {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state
            };
            let background: Vec<Allocation> = (0..2000)
                .map(|_| allocator.alloc(16 + (next() % 20) as usize * 16).unwrap())
                .collect();
            for allocation in background.iter().step_by(2) {
                allocator.free(*allocation).unwrap();
            }
            let cycles: usize = std::env::var("FRAG_CYCLES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(20_000);
            let mut fragments = Vec::with_capacity(32);
            let started = std::time::Instant::now();
            for _ in 0..cycles {
                for _ in 0..26 {
                    fragments.push(allocator.alloc(8 + (next() % 12) as usize * 8).unwrap());
                }
                for allocation in fragments.drain(..) {
                    allocator.free(allocation).unwrap();
                }
            }
            let nanos = started.elapsed().as_nanos() as f64;
            eprintln!(
                "{strategy:?}: {:.1} ns per alloc+free pair",
                nanos / (cycles as f64 * 26.0)
            );
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]
        #[test]
        fn randomized_operations_preserve_allocator_invariants(ops in proptest::collection::vec((0u8..3, 1u16..2048), 1..120)) {
            for strategy in [
                Strategy::BestFit,
                Strategy::AddressOrderBestFit,
                Strategy::Aoff,
                Strategy::AoffCbf,
                Strategy::AoffCaobf,
                Strategy::GoodFit,
                Strategy::Afit,
            ] {
                let mut allocator = AllocUtil::new(
                    strategy,
                    AllocUtilOptions { sbct: 4096, smbcs: 16 * 1024, mmbcs: 16 * 1024, lmbcs: 64 * 1024, ..Default::default() },
                );
                let mut live: Vec<Option<Allocation>> = Vec::new();
                for (operation_index, (op, raw_size)) in ops.iter().enumerate() {
                    let size = usize::from(*raw_size);
                    match *op {
                        0 | 1 if live.iter().any(Option::is_none) || live.is_empty() => {
                            let allocation = allocator.alloc(size).unwrap();
                            if let Some(slot) = live.iter_mut().find(|slot| slot.is_none()) { *slot = Some(allocation); }
                            else { live.push(Some(allocation)); }
                        }
                        0 => {
                            let index = usize::from(*raw_size) % live.len();
                            if let Some(allocation) = live[index].take() { allocator.free(allocation).unwrap(); }
                        }
                        1 => {
                            let index = usize::from(*raw_size) % live.len();
                            if let Some(allocation) = live[index] {
                                let resized = allocator.realloc(allocation, size);
                                prop_assert!(
                                    resized.is_ok(),
                                    "realloc failed: strategy={strategy:?}, op_index={operation_index}, size={size}, allocation={allocation:?}, error={:?}",
                                    resized.as_ref().err(),
                                );
                                live[index] = Some(resized.unwrap());
                            }
                        }
                        _ => {
                            let allocation = allocator.alloc(size).unwrap();
                            live.push(Some(allocation));
                        }
                    }
                    prop_assert!(
                        allocator.validate().is_ok(),
                        "strategy={strategy:?}, op_index={operation_index}, op={op}, size={raw_size}, free_root={}, tree={:?}",
                        allocator.free_root,
                        allocator.tree_free_blocks(),
                    );
                    prop_assert_eq!(allocator.block_count(), live.iter().filter(|a| a.is_some()).count());
                }
            }
        }
    }

    /// Deep trees: thousands of live blocks force rotations and recolors in the aoff and
    /// bestfit trees, which the short proptest sequences rarely reach.
    #[test]
    fn many_blocks_keep_tree_invariants_for_tree_strategies() {
        for strategy in [
            Strategy::BestFit,
            Strategy::AddressOrderBestFit,
            Strategy::Aoff,
            Strategy::AoffCbf,
            Strategy::AoffCaobf,
        ] {
            let mut allocator = AllocUtil::new(
                strategy,
                AllocUtilOptions {
                    sbct: 64 * 1024,
                    smbcs: 256 * 1024,
                    mmbcs: 256 * 1024,
                    lmbcs: 1024 * 1024,
                    ..Default::default()
                },
            );
            let mut state = 0x9e37_79b9_7f4a_7c15_u64;
            let mut next = move || {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state
            };
            let mut live: Vec<Allocation> = Vec::new();
            for step in 0..3000 {
                let roll = next() % 100;
                if roll < 55 || live.is_empty() {
                    let size = 8 + (next() % 700) as usize;
                    live.push(allocator.alloc(size).unwrap());
                } else {
                    let index = (next() % live.len() as u64) as usize;
                    allocator.free(live.swap_remove(index)).unwrap();
                }
                if step % 25 == 0 {
                    assert!(
                        allocator.validate().is_ok(),
                        "{strategy:?} invalid after step {step}"
                    );
                }
            }
            for allocation in live {
                allocator.free(allocation).unwrap();
            }
            assert!(allocator.validate().is_ok(), "{strategy:?} invalid at end");
        }
    }

    #[test]
    fn otp_default_thresholds_are_read_from_erl() {
        let eval = "[{instance,0,Info}|_] = erlang:system_info({allocator,eheap_alloc}), O = proplists:get_value(options,Info), io:format(\"~p ~p ~p ~p ~p ~p ~p ~p ~p ~p ~p ~p ~p ~p ~p ~p\", [proplists:get_value(sbct,O),proplists:get_value(asbcst,O),proplists:get_value(rsbcst,O),proplists:get_value(rsbcmt,O),proplists:get_value(rmbcmt,O),proplists:get_value(mmbcs,O),proplists:get_value(mmmbc,O),proplists:get_value(mmsbc,O),proplists:get_value(smbcs,O),proplists:get_value(lmbcs,O),proplists:get_value(mbcgs,O),proplists:get_value(acful,O),proplists:get_value(acul,O),proplists:get_value(acnl,O),proplists:get_value(acfml,O),proplists:get_value(cp,O)]), halt().";
        let output = std::process::Command::new("erl")
            .args(["-noshell", "-eval", eval])
            .output();
        let Ok(output) = output else {
            eprintln!("skipping OTP allocator defaults check: erl is not installed");
            return;
        };
        assert!(
            output.status.success(),
            "erl failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            format!(
                "524288 4145152 50 80 50 131072 {} 256 262144 5242880 10 0 0 0 0 undefined",
                usize::MAX
            )
        );
    }
}
