//! Safe alloc_util core with OTP block headers and bestfit policies.

use crate::mseg::{CacheConfig, CallCount, MsegAllocator, MsegOptions, Segment, SegmentFlags};
use crate::raw::{MapError, RawRegion, WordView, page_size};
use std::collections::{HashMap as StdHashMap, HashSet as StdHashSet};
use std::hash::{BuildHasherDefault, Hasher};

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
}

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
pub struct AllocUtilOptions {
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
    /// Abandon carriers below this utilization, as a percent (`acul`).
    pub acul: usize,
    /// Discard free blocks below this utilization, as a percent (`acful`).
    pub acful: usize,
    /// Maximum carriers kept in the shared pool (`acnl`).
    pub acnl: usize,
    /// Minimum free block size retained in the pool (`acfml`).
    pub acfml: usize,
    /// Shared carrier pool group (`cp`).
    pub cpool: Option<char>,
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
}

/// Current and peak allocated block and carrier counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AllocStats {
    pub blocks: usize,
    pub blocks_size: usize,
    pub max_blocks: usize,
    pub max_blocks_size: usize,
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
    pub alloc_calls: u64,
    pub free_calls: u64,
    pub realloc_calls: u64,
    pub mseg_alloc_calls: u64,
    pub mseg_dealloc_calls: u64,
    pub sys_alloc_calls: u64,
    pub sys_free_calls: u64,
    pub mseg_realloc_calls: u64,
    pub sys_realloc_calls: u64,
    pub max_ever_blocks: usize,
    pub max_ever_blocks_size: usize,
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

/// One indexed carrier's address range: the cached answer to "which carrier holds this
/// address". Block keys are addresses, so a key's words are read straight from the range.
#[derive(Clone, Copy)]
struct CarrierSpan {
    start: usize,
    end: usize,
    index: usize,
    sbc: bool,
}

impl CarrierSpan {
    const EMPTY: Self = Self {
        start: 0,
        end: 0,
        index: usize::MAX,
        sbc: false,
    };

    /// The carrier's words. A span exists only while its carrier is indexed, and a carrier
    /// is unindexed (dropping the cached span) before its memory moves or is released.
    #[inline(always)]
    fn words(self) -> WordView {
        WordView::new(self.start as *mut u64, (self.end - self.start) / WORD)
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

/// One safe, single-threaded alloc_util instance.
///
/// Port of `erts/emulator/beam/erl_alloc_util.c` allocator state, OTP-29.1.1.
pub struct AllocUtil {
    strategy: Strategy,
    options: AllocUtilOptions,
    allocation_type: &'static str,
    instance_index: usize,
    pool_managed: bool,
    carriers: Vec<Option<Carrier>>,
    /// Vacated `carriers` slots, reused so churn does not grow the table.
    free_carrier_slots: Vec<usize>,
    /// Number of live multiblock carriers.
    mbc_count: usize,
    /// `(start, end, index)` of every live carrier sorted by address: block address to carrier,
    /// standing in for erts' carrier pointer arithmetic (erl_alloc_util.h:430 FBLK_TO_MBC/ABLK_TO_MBC).
    carrier_ranges: Vec<(usize, usize, usize)>,
    /// Last `carrier_ranges` hit; consecutive header accesses nearly always stay in one carrier.
    last_carrier: std::cell::Cell<CarrierSpan>,
    free_root: usize,
    aoff_roots: Vec<usize>,
    aoff_carrier_root: usize,
    /// Bucket list heads (`buckets` in erl_goodfit_alloc.c); 0 is an empty bucket.
    goodfit_heads: Vec<usize>,
    /// Bit per non-empty goodfit bucket, like `bucket_mask` in erl_goodfit_alloc.c.
    goodfit_mask: [u64; 4],
    /// `bkt_intrvl_d` of erl_goodfit_alloc.c, derived from `sbct`.
    goodfit_interval_d: usize,
    /// `free_list` head of erl_afit_alloc.c; 0 is empty.
    afit_head: usize,
    stats: AllocStats,
    class_stats: [ClassStats; 2],
    mseg: MsegAllocator,
    pending_carriers: Vec<CarrierTransfer>,
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
            carriers: Vec::new(),
            free_carrier_slots: Vec::new(),
            mbc_count: 0,
            carrier_ranges: Vec::new(),
            last_carrier: std::cell::Cell::new(CarrierSpan::EMPTY),
            free_root: 0,
            aoff_roots: Vec::new(),
            aoff_carrier_root: 0,
            goodfit_heads: vec![0; 256],
            goodfit_mask: [0; 4],
            goodfit_interval_d: goodfit_interval_d(options.sbct),
            afit_head: 0,
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

    /// Allocates a payload of `size` bytes.
    /// Port of `erts_alcu_alloc`, `erl_alloc_util.c:2377`, OTP-29.1.1.
    pub fn alloc(&mut self, size: usize) -> Result<Allocation, AllocError> {
        self.stats.alloc_calls += 1;
        let block_size = block_size(size, self.strategy)?;
        if block_size >= self.options.sbct {
            let start = self.add_sbc(block_size)?;
            self.stats.blocks += 1;
            self.stats.blocks_size += block_size;
            self.block_added(true, block_size);
            self.update_block_peak();
            return Ok(Allocation {
                id: start as u64,
                size,
            });
        }
        let offset = if let Some(block) = self.choose_free(block_size)? {
            block
        } else {
            let ci = self.add_mbc(block_size)?;
            self.carriers[ci].as_ref().ok_or(AllocError::Corrupt)?.start
        };
        // Port of mbc_alloc_finalize, erl_alloc_util.c:1913, OTP-29.1.1.
        let old = self.blk(offset)?;
        self.unlink_free_inner(offset, old.size)?;
        let actual = old.size;
        let split = actual.saturating_sub(block_size) >= min_block_size(self.strategy);
        let used = if split { block_size } else { actual };
        self.write_block(&Block {
            size: used,
            allocated: true,
            last: old.last && !split,
            ..old
        })?;
        if split {
            let tail = Block {
                carrier: old.carrier,
                offset: offset + block_size,
                size: actual - block_size,
                allocated: false,
                prev_free: false,
                last: old.last,
            };
            self.write_block(&tail)?;
            if !tail.last {
                self.set_next_prev_free(&tail, true)?;
            }
            self.link_free_inner(tail.offset, tail.size)?;
        } else {
            self.set_next_prev_free(&Block { size: used, ..old }, false)?;
        }
        self.stats.blocks += 1;
        self.stats.blocks_size += used;
        self.block_added(false, used);
        self.update_block_peak();
        Ok(Allocation {
            id: offset as u64,
            size,
        })
    }

    /// Frees a live allocation and merges adjacent free MBC blocks.
    /// Port of `erts_alcu_free`, `erl_alloc_util.c:2820`, OTP-29.1.1.
    pub fn free(&mut self, allocation: Allocation) -> Result<(), AllocError> {
        self.stats.free_calls += 1;
        let b = self.live_block(allocation.id as usize)?;
        let offset = b.offset;
        self.stats.blocks -= 1;
        self.stats.blocks_size -= b.size;
        let sbc = self.carriers[b.carrier]
            .as_ref()
            .ok_or(AllocError::Corrupt)?
            .sbc;
        self.block_removed(sbc, b.size);
        if sbc {
            self.remove_carrier(b.carrier)?;
            return Ok(());
        }
        // Port of mbc_free, erl_alloc_util.c:2045, OTP-29.1.1.
        let mut merged = Block {
            allocated: false,
            ..b
        };
        if b.prev_free {
            let prev = self.previous_block(offset)?;
            let p = self.blk_in(b.carrier, prev)?;
            if !p.allocated {
                self.unlink_free_inner(prev, p.size)?;
                merged = Block {
                    offset: prev,
                    size: p.size + b.size,
                    prev_free: p.prev_free,
                    ..merged
                };
            }
        }
        if !merged.last {
            let next = merged.offset + merged.size;
            let n = self.blk_in(merged.carrier, next)?;
            if !n.allocated {
                self.unlink_free_inner(next, n.size)?;
                merged.size += n.size;
                merged.last = n.last;
            }
        }
        self.write_block(&merged)?;
        if !merged.last {
            self.set_next_prev_free(&merged, true)?;
        }
        let c = self.carriers[merged.carrier]
            .as_ref()
            .ok_or(AllocError::Corrupt)?;
        // Port of erl_alloc_util.c:2791 (dealloc_block), OTP-29.1.1: the main carrier is never destroyed.
        if merged.offset == c.start && merged.last && !c.main {
            self.remove_carrier(merged.carrier)?;
        } else {
            self.link_free_inner(merged.offset, merged.size)?;
            self.check_abandon_carrier(merged.carrier)?;
        }
        Ok(())
    }

    /// Returns the stable payload address while `allocation` remains allocated.
    pub fn allocation_ptr(&self, allocation: Allocation) -> Result<*mut u64, AllocError> {
        self.live_block(allocation.id as usize)?;
        self.payload_ptr(allocation)
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

    /// Payload address of an allocation this instance just returned (no liveness check).
    #[inline]
    pub(crate) fn payload_ptr(&self, allocation: Allocation) -> Result<*mut u64, AllocError> {
        let key = allocation.id as usize;
        let carrier = self
            .carrier_of(key)
            .and_then(|index| self.carriers[index].as_ref())
            .ok_or(AllocError::Corrupt)?;
        let byte_offset = key - carrier.key_base + BLOCK_HEADER;
        Ok(carrier.memory.as_ptr().wrapping_add(byte_offset).cast())
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
        let index = self
            .carrier_ranges
            .partition_point(|&(start, _, _)| start <= key)
            .checked_sub(1)?;
        let (start, end, carrier) = self.carrier_ranges[index];
        if key >= start && key < end {
            let span = CarrierSpan {
                start,
                end,
                index: carrier,
                sbc: self.carriers[carrier].as_ref()?.sbc,
            };
            self.last_carrier.set(span);
            Some(span)
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
        let span = CarrierSpan {
            start: carrier.key_base,
            end: carrier.key_base + carrier.memory.len(),
            index,
            sbc: carrier.sbc,
        };
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

    #[inline(always)]
    fn check_abandon_carrier(&mut self, carrier_index: usize) -> Result<(), AllocError> {
        if self.options.acul == 0
            || self.options.acnl == 0
            || self.options.cpool.is_none()
            || !self.pool_managed
            || !is_aoff(self.strategy)
            || self.pending_carriers.len() >= self.options.acnl
        {
            return Ok(());
        }
        let Some(carrier) = self.carriers.get(carrier_index).and_then(Option::as_ref) else {
            return Ok(());
        };
        if carrier.sbc || carrier.main {
            return Ok(());
        }
        let carrier_size = carrier.size;
        let blocks = self.carrier_blocks(carrier_index)?;
        let allocated_size = blocks
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
        let total_carrier_size = self
            .carriers
            .iter()
            .flatten()
            .filter(|entry| !entry.sbc)
            .map(|entry| entry.size)
            .sum::<usize>();
        let below = |used: usize, total: usize| {
            (used as u128) * 100 <= (total as u128) * (self.options.acul as u128)
        };
        if !below(self.stats.blocks_size, total_carrier_size)
            || !below(allocated_size, carrier_size)
            || largest_free < self.options.acfml
        {
            return Ok(());
        }
        self.discard_free_blocks(carrier_index)?;
        self.detach_carrier(carrier_index)
    }

    fn discard_free_blocks(&mut self, carrier_index: usize) -> Result<(), AllocError> {
        if self.options.acful == 0 {
            return Ok(());
        }
        let blocks = self.carrier_blocks(carrier_index)?;
        let carrier = self.carriers[carrier_index]
            .as_ref()
            .ok_or(AllocError::Corrupt)?;
        let allocated_size = blocks
            .iter()
            .filter(|block| block.allocated)
            .map(|block| block.size)
            .sum::<usize>();
        if (allocated_size as u128) * 100 > (carrier.size as u128) * (self.options.acful as u128) {
            return Ok(());
        }
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
        for block in transfer_blocks.iter().filter(|block| block.allocated) {
            self.stats.blocks -= 1;
            self.stats.blocks_size -= block.size;
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
        self.aoff_roots[carrier_index] = 0;
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
        Ok((need < self.options.sbct).then_some(need))
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
        // Blocks keep their addresses with the carrier memory, so allocations keep their identity.
        let mut remapped = Vec::with_capacity(transfer.allocations.len());
        for (old, offset) in transfer.allocations {
            let size = self.blk(offset)?.size;
            self.stats.blocks += 1;
            self.stats.blocks_size += size;
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
        self.update_block_peak();
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
        if old_sbc && needed >= self.options.sbct {
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
        if old_sbc && needed < self.options.sbct {
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
            self.stats.blocks_size -= old.size - needed;
            self.block_resized(false, old.size, needed);
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
            self.stats.blocks_size = self.stats.blocks_size - old.size + grown.size;
            self.block_resized(false, old.size, grown.size);
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
                    self.stats.blocks_size = self.stats.blocks_size - old.size + used;
                    self.block_resized(false, old.size, used);
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
        for (index, carrier) in self.carriers.iter().enumerate() {
            let Some(carrier) = carrier else { continue };
            let class = if carrier.sbc { &mut sbcs } else { &mut mbcs };
            for block in self.carrier_blocks(index).unwrap_or_default() {
                if block.allocated {
                    class.blocks += 1;
                    class.blocks_size += block.size;
                }
            }
        }
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
            options: self.options,
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
        let mut count = 0;
        let mut bytes = 0;
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
                    if c.memory.read_word(rel + b.size - WORD) != Some(b.size) {
                        return Err(AllocError::Corrupt);
                    }
                } else {
                    count += 1;
                    bytes += b.size;
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
        }
        if free != self.tree_free_blocks()?
            || count != self.stats.blocks
            || bytes != self.stats.blocks_size
        {
            return Err(AllocError::Corrupt);
        }
        if is_aoff(self.strategy) {
            for (carrier, root) in self.aoff_roots.iter().copied().enumerate() {
                self.validate_aoff_tree(root, 0, None, None, false)?;
                if self.carriers[carrier].is_none() {
                    if root != 0 {
                        return Err(AllocError::Corrupt);
                    }
                    continue;
                }
                let carrier_node = self.carrier_tree_node(carrier)?;
                let largest = if root == 0 {
                    0
                } else {
                    self.node_word(root, TREE_FLAGS_WORD)? >> 32
                };
                let in_tree = self.carriers[carrier]
                    .as_ref()
                    .is_some_and(|entry| entry.in_aoff_tree);
                if (largest != 0) != in_tree
                    || (largest != 0 && self.tree_node_size(carrier_node)? != largest)
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
        let key = if (carrier_tree && self.strategy == Strategy::AoffCbf)
            || (!carrier_tree && self.strategy == Strategy::AoffCaobf)
        {
            (size, node)
        } else {
            (0, node)
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
        self.stats.blocks_size = self.stats.blocks_size - old.size + new_block_size;
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
        self.update_block_peak();
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
            self.aoff_roots[index] = 0;
            self.carriers[index] = Some(carrier);
            index
        } else {
            self.carriers.push(Some(carrier));
            self.aoff_roots.push(0);
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
        });
        self.write_carrier(ci)?;
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
        if !b.allocated && !c.memory.write_word(rel + b.size - WORD, b.size) {
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

    fn node_word(&self, node: usize, word: usize) -> Result<usize, AllocError> {
        self.word_at(node, self.tree_word(word))
    }

    fn set_node_word(&mut self, node: usize, word: usize, value: usize) -> Result<(), AllocError> {
        let word = self.tree_word(word);
        let value = if is_aoff(self.strategy) && word == AOFF_FLAGS_WORD {
            let old = self.word_at(node, word)?;
            (old & !u32::MAX as usize) | (value & u32::MAX as usize)
        } else {
            value
        };
        self.set_word_at(node, word, value)
    }

    /// Carrier whose free-block tree holds `node`, or `None` for an aoff carrier-tree node.
    fn node_carrier(&self, node: usize) -> Result<Option<usize>, AllocError> {
        let index = self.carrier_of(node).ok_or(AllocError::Corrupt)?;
        if self.aoff_carrier_index(node).is_some() {
            Ok(None)
        } else {
            Ok(Some(index))
        }
    }

    fn tree_root(&self, node: usize) -> Result<usize, AllocError> {
        match self.node_carrier(node)? {
            None => Ok(self.aoff_carrier_root),
            Some(carrier) => self.root_for_carrier(carrier),
        }
    }

    fn root_for_carrier(&self, carrier: usize) -> Result<usize, AllocError> {
        if is_aoff(self.strategy) {
            self.aoff_roots
                .get(carrier)
                .copied()
                .ok_or(AllocError::Corrupt)
        } else {
            Ok(self.free_root)
        }
    }

    fn set_tree_root(&mut self, node: usize, root: usize) -> Result<(), AllocError> {
        match self.node_carrier(node)? {
            None => self.aoff_carrier_root = root,
            Some(carrier) if is_aoff(self.strategy) => {
                *self
                    .aoff_roots
                    .get_mut(carrier)
                    .ok_or(AllocError::Corrupt)? = root;
            }
            Some(_) => self.free_root = root,
        }
        Ok(())
    }

    /// The carrier whose aoff carrier-tree node (`crr.cpool`-adjacent node) is `node`.
    #[inline]
    fn aoff_carrier_index(&self, node: usize) -> Option<usize> {
        if !is_aoff(self.strategy) {
            return None;
        }
        let index = self.carrier_of(node)?;
        let carrier = self.carriers[index].as_ref()?;
        (!carrier.sbc && node == carrier.key_base + MBC_HEADER).then_some(index)
    }

    fn tree_node_size(&self, node: usize) -> Result<usize, AllocError> {
        let word = self.word_at(node, 0)?;
        if self.aoff_carrier_index(node).is_some() {
            Ok(word)
        } else {
            Ok(word & !BLOCK_FLAGS)
        }
    }

    fn set_tree_node_max_size(&mut self, node: usize, max_size: usize) -> Result<(), AllocError> {
        let word = self.word_at(node, AOFF_FLAGS_WORD)?;
        let value = (word & u32::MAX as usize) | (((max_size as u32) as usize) << 32);
        self.set_word_at(node, AOFF_FLAGS_WORD, value)
    }

    fn recompute_tree_max(&mut self, node: usize) -> Result<usize, AllocError> {
        if node == 0 {
            return Ok(0);
        }
        let left = self.node_word(node, TREE_LEFT_WORD)?;
        let right = self.node_word(node, TREE_RIGHT_WORD)?;
        let largest = self
            .tree_node_size(node)?
            .max(self.recompute_tree_max(left)?)
            .max(self.recompute_tree_max(right)?);
        self.set_tree_node_max_size(node, largest)?;
        Ok(largest)
    }

    /// Port of rbt_search, erl_ao_firstfit_alloc.c:863-881, OTP-29.1.1.
    fn aoff_search(&self, mut root: usize, need: usize) -> Result<Option<usize>, AllocError> {
        while root != 0 {
            let left = self.node_word(root, TREE_LEFT_WORD)?;
            if left != 0 && self.node_word(left, TREE_FLAGS_WORD)? >> 32 >= need {
                root = left;
            } else if self.tree_node_size(root)? >= need {
                return Ok(Some(root));
            } else {
                root = self.node_word(root, TREE_RIGHT_WORD)?;
            }
        }
        Ok(None)
    }

    /// Port of aoff_link_free_block/aoff_add_mbc, erl_ao_firstfit_alloc.c:761-779,991-1017, OTP-29.1.1.
    fn update_aoff_carrier_node(&mut self, carrier_index: usize) -> Result<(), AllocError> {
        let node = {
            let carrier = self.carriers[carrier_index]
                .as_ref()
                .ok_or(AllocError::Corrupt)?;
            if carrier.sbc {
                return Ok(());
            }
            carrier.key_base + MBC_HEADER
        };
        if self.carriers[carrier_index]
            .as_ref()
            .is_some_and(|carrier| carrier.in_aoff_tree)
        {
            self.delete_tree_node(node)?;
            self.carriers[carrier_index]
                .as_mut()
                .ok_or(AllocError::Corrupt)?
                .in_aoff_tree = false;
        }
        let largest = self.aoff_roots[carrier_index];
        let largest_size = if largest == 0 {
            0
        } else {
            let mut max = 0;
            let mut stack = vec![largest];
            while let Some(block) = stack.pop() {
                max = max.max(self.tree_node_size(block)?);
                let left = self.node_word(block, TREE_LEFT_WORD)?;
                let right = self.node_word(block, TREE_RIGHT_WORD)?;
                if left != 0 {
                    stack.push(left);
                }
                if right != 0 {
                    stack.push(right);
                }
            }
            max
        };
        if largest_size == 0 {
            return Ok(());
        }
        let base = self.carriers[carrier_index]
            .as_ref()
            .ok_or(AllocError::Corrupt)?
            .key_base;
        if !self.carriers[carrier_index]
            .as_mut()
            .ok_or(AllocError::Corrupt)?
            .memory
            .write_word(node - base, largest_size)
        {
            return Err(AllocError::Corrupt);
        }
        self.insert_tree_node(node, largest_size)?;
        self.carriers[carrier_index]
            .as_mut()
            .ok_or(AllocError::Corrupt)?
            .in_aoff_tree = true;
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
        if self.strategy == Strategy::GoodFit {
            let bucket = goodfit_bucket(size, self.goodfit_interval_d);
            self.list_push_front(FreeListId::Bucket(bucket), node)?;
            self.goodfit_mask[bucket / 64] |= 1 << (bucket % 64);
        } else if self.strategy == Strategy::Afit {
            let head = self.afit_head;
            if head != 0 && self.blk(head)?.size > size {
                self.list_insert_after_head(FreeListId::Afit, node)?;
            } else {
                self.list_push_front(FreeListId::Afit, node)?;
            }
        }
        if matches!(self.strategy, Strategy::GoodFit | Strategy::Afit) {
            // erl_goodfit_alloc.c and erl_afit_alloc.c index free blocks by lists only, no tree.
            return Ok(());
        }
        self.insert_tree_node(node, size)?;
        if is_aoff(self.strategy) {
            let carrier = self.carrier_of(node).ok_or(AllocError::Corrupt)?;
            self.update_aoff_carrier_node(carrier)?;
        }
        Ok(())
    }

    /// Port of rbt_insert and tree_insert_fixup, erl_ao_firstfit_alloc.c:793-861, OTP-29.1.1.
    fn insert_tree_node(&mut self, node: usize, size: usize) -> Result<(), AllocError> {
        self.set_node_word(node, TREE_FLAGS_WORD, 0)?;
        self.set_node_word(node, TREE_PARENT_WORD, 0)?;
        self.set_node_word(node, TREE_LEFT_WORD, 0)?;
        self.set_node_word(node, TREE_RIGHT_WORD, 0)?;
        let block_node = self.aoff_carrier_index(node).is_none();
        if self.strategy == Strategy::BestFit && block_node {
            self.set_node_word(node, BF_NEXT_WORD, 0)?;
        }
        let mut parent = 0;
        let mut current = self.tree_root(node)?;
        while current != 0 {
            parent = current;
            let current_size = self.tree_node_size(current)?;
            if self.strategy == Strategy::BestFit && block_node && size == current_size {
                let head_next = self.node_word(current, BF_NEXT_WORD)?;
                self.set_node_word(node, TREE_PARENT_WORD, current)?;
                self.set_node_word(node, BF_NEXT_WORD, head_next)?;
                if head_next != 0 {
                    self.set_node_word(head_next, TREE_PARENT_WORD, node)?;
                }
                self.set_node_word(current, BF_NEXT_WORD, node)?;
                return Ok(());
            }
            let go_left = self.free_tree_goes_left(node, current, size, current_size);
            let child_word = if go_left {
                TREE_LEFT_WORD
            } else {
                TREE_RIGHT_WORD
            };
            current = self.node_word(current, child_word)?;
        }
        self.set_node_word(node, TREE_FLAGS_WORD, TREE_NODE | RED)?;
        self.set_node_word(node, TREE_PARENT_WORD, parent)?;
        if parent == 0 {
            self.set_tree_root(node, node)?;
            self.set_node_word(node, TREE_FLAGS_WORD, TREE_NODE)?;
            if is_aoff(self.strategy) {
                self.recompute_tree_max(node)?;
            }
            return Ok(());
        }
        let parent_size = self.tree_node_size(parent)?;
        let go_left = self.free_tree_goes_left(node, parent, size, parent_size);
        self.set_node_word(
            parent,
            if go_left {
                TREE_LEFT_WORD
            } else {
                TREE_RIGHT_WORD
            },
            node,
        )?;
        self.insert_fixup(node)?;
        if is_aoff(self.strategy) {
            let root = self.tree_root(node)?;
            self.recompute_tree_max(root)?;
        }
        Ok(())
    }

    fn free_tree_goes_left(
        &self,
        lhs: usize,
        rhs: usize,
        lhs_size: usize,
        rhs_size: usize,
    ) -> bool {
        if self.aoff_carrier_index(lhs).is_some() && self.aoff_carrier_index(rhs).is_some() {
            if self.strategy == Strategy::AoffCbf {
                (lhs_size, lhs) < (rhs_size, rhs)
            } else {
                lhs < rhs
            }
        } else if self.strategy == Strategy::AoffCaobf {
            (lhs_size, lhs) < (rhs_size, rhs)
        } else if is_aoff(self.strategy) {
            lhs < rhs
        } else {
            (lhs_size, lhs) < (rhs_size, rhs)
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
        // Port of aoff_get_free_block, erl_ao_firstfit_alloc.c:895, OTP-29.1.1;
        // goodfit_get_free_block, erl_goodfit_alloc.c:393, OTP-29.1.1; and
        // afit_get_free_block, erl_afit_alloc.c:123, OTP-29.1.1.
        if self.strategy == Strategy::Afit {
            let head = self.afit_head;
            if head == 0 || self.blk(head)?.size < need {
                return Ok(None);
            }
            return Ok(Some(head));
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
                    return Ok(Some(node));
                }
            }
            return Ok(None);
        }
        if is_aoff(self.strategy) {
            let Some(carrier_node) = self.aoff_search(self.aoff_carrier_root, need)? else {
                return Ok(None);
            };
            let carrier_index = self
                .aoff_carrier_index(carrier_node)
                .ok_or(AllocError::Corrupt)?;
            return self.aoff_search(self.aoff_roots[carrier_index], need);
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
        Ok(Some(best))
    }

    /// Removes a free block from its intrusive tree node or BF size list.
    /// Port of `bf_unlink_free_block` and `tree_delete`, `erl_bestfit_alloc.c:399-433,780-806`, OTP-29.1.1.
    #[inline(always)]
    fn unlink_free_inner(&mut self, node: usize, size: usize) -> Result<(), AllocError> {
        if self.strategy == Strategy::GoodFit {
            let index = goodfit_bucket(size, self.goodfit_interval_d);
            self.list_remove(FreeListId::Bucket(index), node)?;
            if self.goodfit_heads[index] == 0 {
                self.goodfit_mask[index / 64] &= !(1 << (index % 64));
            }
        } else if self.strategy == Strategy::Afit {
            self.list_remove(FreeListId::Afit, node)?;
        }
        if matches!(self.strategy, Strategy::GoodFit | Strategy::Afit) {
            return Ok(());
        }
        let flags = self.node_word(node, TREE_FLAGS_WORD)?;
        if self.strategy == Strategy::BestFit && flags & TREE_NODE == 0 {
            let prev = self.node_word(node, TREE_PARENT_WORD)?;
            let next = self.node_word(node, BF_NEXT_WORD)?;
            if prev == 0 {
                return Err(AllocError::Corrupt);
            }
            self.set_node_word(prev, BF_NEXT_WORD, next)?;
            if next != 0 {
                self.set_node_word(next, TREE_PARENT_WORD, prev)?;
            }
            return Ok(());
        }
        if self.strategy == Strategy::BestFit {
            let next = self.node_word(node, BF_NEXT_WORD)?;
            if next != 0 {
                self.replace_tree_node(node, next)?;
                return Ok(());
            }
        }
        self.delete_tree_node(node)?;
        if is_aoff(self.strategy)
            && let Some(carrier) = self.node_carrier(node)?
        {
            self.update_aoff_carrier_node(carrier)?;
        }
        Ok(())
    }

    fn is_red(&self, node: usize) -> Result<bool, AllocError> {
        Ok(node != 0 && self.node_word(node, TREE_FLAGS_WORD)? & RED != 0)
    }

    fn set_red(&mut self, node: usize, red: bool) -> Result<(), AllocError> {
        if node == 0 {
            return Ok(());
        }
        let flags = self.node_word(node, TREE_FLAGS_WORD)?;
        self.set_node_word(
            node,
            TREE_FLAGS_WORD,
            (flags | TREE_NODE) & !RED | if red { RED } else { 0 },
        )
    }

    fn rotate_left(&mut self, x: usize) -> Result<(), AllocError> {
        let y = self.node_word(x, TREE_RIGHT_WORD)?;
        if y == 0 {
            return Err(AllocError::Corrupt);
        }
        let beta = self.node_word(y, TREE_LEFT_WORD)?;
        let parent = self.node_word(x, TREE_PARENT_WORD)?;
        self.set_node_word(x, TREE_RIGHT_WORD, beta)?;
        if beta != 0 {
            self.set_node_word(beta, TREE_PARENT_WORD, x)?;
        }
        self.set_node_word(y, TREE_PARENT_WORD, parent)?;
        if parent == 0 {
            self.set_tree_root(x, y)?;
        } else if self.node_word(parent, TREE_LEFT_WORD)? == x {
            self.set_node_word(parent, TREE_LEFT_WORD, y)?;
        } else {
            self.set_node_word(parent, TREE_RIGHT_WORD, y)?;
        }
        self.set_node_word(y, TREE_LEFT_WORD, x)?;
        self.set_node_word(x, TREE_PARENT_WORD, y)
    }

    fn rotate_right(&mut self, x: usize) -> Result<(), AllocError> {
        let y = self.node_word(x, TREE_LEFT_WORD)?;
        if y == 0 {
            return Err(AllocError::Corrupt);
        }
        let beta = self.node_word(y, TREE_RIGHT_WORD)?;
        let parent = self.node_word(x, TREE_PARENT_WORD)?;
        self.set_node_word(x, TREE_LEFT_WORD, beta)?;
        if beta != 0 {
            self.set_node_word(beta, TREE_PARENT_WORD, x)?;
        }
        self.set_node_word(y, TREE_PARENT_WORD, parent)?;
        if parent == 0 {
            self.set_tree_root(x, y)?;
        } else if self.node_word(parent, TREE_RIGHT_WORD)? == x {
            self.set_node_word(parent, TREE_RIGHT_WORD, y)?;
        } else {
            self.set_node_word(parent, TREE_LEFT_WORD, y)?;
        }
        self.set_node_word(y, TREE_RIGHT_WORD, x)?;
        self.set_node_word(x, TREE_PARENT_WORD, y)
    }

    fn insert_fixup(&mut self, mut node: usize) -> Result<(), AllocError> {
        while self.is_red(self.node_word(node, TREE_PARENT_WORD)?)? {
            let parent = self.node_word(node, TREE_PARENT_WORD)?;
            let grand = self.node_word(parent, TREE_PARENT_WORD)?;
            if grand == 0 {
                return Err(AllocError::Corrupt);
            }
            if parent == self.node_word(grand, TREE_LEFT_WORD)? {
                let uncle = self.node_word(grand, TREE_RIGHT_WORD)?;
                if self.is_red(uncle)? {
                    self.set_red(parent, false)?;
                    self.set_red(uncle, false)?;
                    self.set_red(grand, true)?;
                    node = grand;
                } else {
                    if node == self.node_word(parent, TREE_RIGHT_WORD)? {
                        node = parent;
                        self.rotate_left(node)?;
                    }
                    let parent = self.node_word(node, TREE_PARENT_WORD)?;
                    let grand = self.node_word(parent, TREE_PARENT_WORD)?;
                    self.set_red(parent, false)?;
                    self.set_red(grand, true)?;
                    self.rotate_right(grand)?;
                }
            } else {
                let uncle = self.node_word(grand, TREE_LEFT_WORD)?;
                if self.is_red(uncle)? {
                    self.set_red(parent, false)?;
                    self.set_red(uncle, false)?;
                    self.set_red(grand, true)?;
                    node = grand;
                } else {
                    if node == self.node_word(parent, TREE_LEFT_WORD)? {
                        node = parent;
                        self.rotate_right(node)?;
                    }
                    let parent = self.node_word(node, TREE_PARENT_WORD)?;
                    let grand = self.node_word(parent, TREE_PARENT_WORD)?;
                    self.set_red(parent, false)?;
                    self.set_red(grand, true)?;
                    self.rotate_left(grand)?;
                }
            }
        }
        let root = self.tree_root(node)?;
        self.set_red(root, false)
    }

    fn replace_tree_node(&mut self, old: usize, new: usize) -> Result<(), AllocError> {
        let parent = self.node_word(old, TREE_PARENT_WORD)?;
        let left = self.node_word(old, TREE_LEFT_WORD)?;
        let right = self.node_word(old, TREE_RIGHT_WORD)?;
        let flags = self.node_word(old, TREE_FLAGS_WORD)?;
        if parent == 0 {
            self.set_tree_root(old, new)?;
        } else if self.node_word(parent, TREE_LEFT_WORD)? == old {
            self.set_node_word(parent, TREE_LEFT_WORD, new)?;
        } else {
            self.set_node_word(parent, TREE_RIGHT_WORD, new)?;
        }
        self.set_node_word(new, TREE_FLAGS_WORD, flags)?;
        self.set_node_word(new, TREE_PARENT_WORD, parent)?;
        self.set_node_word(new, TREE_LEFT_WORD, left)?;
        self.set_node_word(new, TREE_RIGHT_WORD, right)?;
        if left != 0 {
            self.set_node_word(left, TREE_PARENT_WORD, new)?;
        }
        if right != 0 {
            self.set_node_word(right, TREE_PARENT_WORD, new)?;
        }
        let next = self.node_word(new, BF_NEXT_WORD)?;
        if next != 0 {
            self.set_node_word(next, TREE_PARENT_WORD, new)?;
        }
        Ok(())
    }

    fn transplant(&mut self, old: usize, new: usize) -> Result<(), AllocError> {
        let parent = self.node_word(old, TREE_PARENT_WORD)?;
        if parent == 0 {
            self.set_tree_root(old, new)?;
        } else if self.node_word(parent, TREE_LEFT_WORD)? == old {
            self.set_node_word(parent, TREE_LEFT_WORD, new)?;
        } else {
            self.set_node_word(parent, TREE_RIGHT_WORD, new)?;
        }
        if new != 0 {
            self.set_node_word(new, TREE_PARENT_WORD, parent)?;
        }
        Ok(())
    }

    fn minimum_node(&self, mut node: usize) -> Result<usize, AllocError> {
        while self.node_word(node, TREE_LEFT_WORD)? != 0 {
            node = self.node_word(node, TREE_LEFT_WORD)?;
        }
        Ok(node)
    }

    fn delete_tree_node(&mut self, node: usize) -> Result<(), AllocError> {
        let block_carrier = self.node_carrier(node)?;
        let carrier_node = block_carrier.is_none();
        let carrier = block_carrier.unwrap_or(0);
        let mut replacement = node;
        let mut replacement_was_red = self.is_red(replacement)?;
        let left = self.node_word(node, TREE_LEFT_WORD)?;
        let right = self.node_word(node, TREE_RIGHT_WORD)?;
        let (child, child_parent);
        if left == 0 {
            child = right;
            child_parent = self.node_word(node, TREE_PARENT_WORD)?;
            self.transplant(node, right)?;
        } else if right == 0 {
            child = left;
            child_parent = self.node_word(node, TREE_PARENT_WORD)?;
            self.transplant(node, left)?;
        } else {
            replacement = self.minimum_node(right)?;
            replacement_was_red = self.is_red(replacement)?;
            let successor_right = self.node_word(replacement, TREE_RIGHT_WORD)?;
            let successor_parent = self.node_word(replacement, TREE_PARENT_WORD)?;
            if successor_parent == node {
                child = successor_right;
                child_parent = replacement;
                if child != 0 {
                    self.set_node_word(child, TREE_PARENT_WORD, replacement)?;
                }
            } else {
                child = successor_right;
                child_parent = successor_parent;
                self.transplant(replacement, successor_right)?;
                self.set_node_word(replacement, TREE_RIGHT_WORD, right)?;
                self.set_node_word(right, TREE_PARENT_WORD, replacement)?;
            }
            self.transplant(node, replacement)?;
            self.set_node_word(replacement, TREE_LEFT_WORD, left)?;
            self.set_node_word(left, TREE_PARENT_WORD, replacement)?;
            let flags = self.node_word(node, TREE_FLAGS_WORD)?;
            self.set_node_word(
                replacement,
                TREE_FLAGS_WORD,
                (flags | TREE_NODE) & !RED | if self.is_red(node)? { RED } else { 0 },
            )?;
        }
        if !replacement_was_red {
            self.delete_fixup(child, child_parent, carrier, carrier_node)?;
        }
        self.set_node_word(node, TREE_FLAGS_WORD, 0)?;
        self.set_node_word(node, TREE_PARENT_WORD, 0)?;
        self.set_node_word(node, TREE_LEFT_WORD, 0)?;
        self.set_node_word(node, TREE_RIGHT_WORD, 0)?;
        if is_aoff(self.strategy) {
            let root = self.tree_root(node)?;
            self.recompute_tree_max(root)?;
        }
        Ok(())
    }

    fn delete_fixup(
        &mut self,
        mut node: usize,
        mut parent: usize,
        carrier: usize,
        carrier_node: bool,
    ) -> Result<(), AllocError> {
        let root = |this: &Self| {
            if carrier_node {
                Ok(this.aoff_carrier_root)
            } else {
                this.root_for_carrier(carrier)
            }
        };
        while node != root(self)? && !self.is_red(node)? {
            if parent == 0 {
                break;
            }
            if node == self.node_word(parent, TREE_LEFT_WORD)? {
                let mut sibling = self.node_word(parent, TREE_RIGHT_WORD)?;
                if self.is_red(sibling)? {
                    self.set_red(sibling, false)?;
                    self.set_red(parent, true)?;
                    self.rotate_left(parent)?;
                    sibling = self.node_word(parent, TREE_RIGHT_WORD)?;
                }
                let sl = if sibling == 0 {
                    0
                } else {
                    self.node_word(sibling, TREE_LEFT_WORD)?
                };
                let sr = if sibling == 0 {
                    0
                } else {
                    self.node_word(sibling, TREE_RIGHT_WORD)?
                };
                if !self.is_red(sl)? && !self.is_red(sr)? {
                    self.set_red(sibling, true)?;
                    node = parent;
                    parent = self.node_word(node, TREE_PARENT_WORD)?;
                } else {
                    if !self.is_red(sr)? {
                        self.set_red(sl, false)?;
                        self.set_red(sibling, true)?;
                        self.rotate_right(sibling)?;
                        sibling = self.node_word(parent, TREE_RIGHT_WORD)?;
                    }
                    self.set_red(sibling, self.is_red(parent)?)?;
                    self.set_red(parent, false)?;
                    let sr = self.node_word(sibling, TREE_RIGHT_WORD)?;
                    self.set_red(sr, false)?;
                    self.rotate_left(parent)?;
                    node = root(self)?;
                    parent = 0;
                }
            } else {
                let mut sibling = self.node_word(parent, TREE_LEFT_WORD)?;
                if self.is_red(sibling)? {
                    self.set_red(sibling, false)?;
                    self.set_red(parent, true)?;
                    self.rotate_right(parent)?;
                    sibling = self.node_word(parent, TREE_LEFT_WORD)?;
                }
                let sr = if sibling == 0 {
                    0
                } else {
                    self.node_word(sibling, TREE_RIGHT_WORD)?
                };
                let sl = if sibling == 0 {
                    0
                } else {
                    self.node_word(sibling, TREE_LEFT_WORD)?
                };
                if !self.is_red(sr)? && !self.is_red(sl)? {
                    self.set_red(sibling, true)?;
                    node = parent;
                    parent = self.node_word(node, TREE_PARENT_WORD)?;
                } else {
                    if !self.is_red(sl)? {
                        self.set_red(sr, false)?;
                        self.set_red(sibling, true)?;
                        self.rotate_left(sibling)?;
                        sibling = self.node_word(parent, TREE_LEFT_WORD)?;
                    }
                    self.set_red(sibling, self.is_red(parent)?)?;
                    self.set_red(parent, false)?;
                    let sl = self.node_word(sibling, TREE_LEFT_WORD)?;
                    self.set_red(sl, false)?;
                    self.rotate_right(parent)?;
                    node = root(self)?;
                    parent = 0;
                }
            }
        }
        self.set_red(node, false)
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
            let key = if allocator.strategy == Strategy::AoffCaobf {
                (block.size, node)
            } else if is_aoff(allocator.strategy) {
                (0, node)
            } else {
                (block.size, node)
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
            if allocator.strategy == Strategy::BestFit {
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
            self.aoff_roots.clone()
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
    /// Start of the free block preceding `offset`, from its size footer.
    /// Port of PREV_BLK_SZ, erl_alloc_util.c:223, OTP-29.1.1.
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
    #[inline(always)]
    fn update_block_peak(&mut self) {
        // Maxima can only move when a current value passes them (erl_alloc_util.c:726 STAT_MBC_BLK_ALLOC).
        if self.stats.blocks <= self.stats.max_blocks
            && self.stats.blocks_size <= self.stats.max_blocks_size
        {
            return;
        }
        self.stats.max_blocks = self.stats.max_blocks.max(self.stats.blocks);
        self.stats.max_blocks_size = self.stats.max_blocks_size.max(self.stats.blocks_size);
        self.stats.max_ever_blocks = self.stats.max_ever_blocks.max(self.stats.max_blocks);
        self.stats.max_ever_blocks_size = self
            .stats
            .max_ever_blocks_size
            .max(self.stats.max_blocks_size);
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

fn min_block_size(strategy: Strategy) -> usize {
    let node_size = if strategy == Strategy::BestFit {
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
        assert_eq!(AOFF_MBC_HEADER, 408);
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
            assert_eq!(a.stats().blocks, 0);
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
                    prop_assert_eq!(allocator.stats().blocks, live.iter().filter(|a| a.is_some()).count());
                }
            }
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
