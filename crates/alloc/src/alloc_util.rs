//! Safe alloc_util core with OTP block headers and bestfit policies.

use crate::mseg::{CacheConfig, CallCount, MsegAllocator, MsegOptions, Segment, SegmentFlags};
use crate::raw::{MapError, RawRegion, page_size};
use std::collections::{HashMap, HashSet};

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
}

const MBC_HEADER: usize = std::mem::size_of::<CarrierLayout>();
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
        }
    }
}

/// Stable identifier for an allocated user block.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Allocation {
    id: u64,
    size: usize,
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Block {
    carrier: usize,
    offset: usize,
    size: usize,
    allocated: bool,
    prev_free: bool,
    last: bool,
}

struct Carrier {
    memory: CarrierMemory,
    sbc: bool,
    mseg: bool,
    key_base: usize,
    start: usize,
    size: usize,
    blocks: Vec<usize>,
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
    Segmented(Segment),
}

impl CarrierMemory {
    fn len(&self) -> usize {
        match self {
            Self::Mapped(region) => region.len(),
            Self::Segmented(segment) => segment.len(),
        }
    }
    fn as_ptr(&self) -> *mut u8 {
        match self {
            Self::Mapped(region) => region.as_ptr(),
            Self::Segmented(segment) => segment.as_ptr(),
        }
    }
    fn read_word(&self, offset: usize) -> Option<usize> {
        match self {
            Self::Mapped(region) => region.read_word(offset),
            Self::Segmented(segment) => segment.read_word(offset),
        }
    }
    fn write_word(&mut self, offset: usize, value: usize) -> bool {
        match self {
            Self::Mapped(region) => region.write_word(offset, value),
            Self::Segmented(segment) => segment.write_word(offset, value),
        }
    }
    fn read_byte(&self, offset: usize) -> Option<u8> {
        match self {
            Self::Mapped(region) => region.read_byte(offset),
            Self::Segmented(segment) => segment.read_byte(offset),
        }
    }
    fn write_byte(&mut self, offset: usize, value: u8) -> bool {
        match self {
            Self::Mapped(region) => region.write_byte(offset, value),
            Self::Segmented(segment) => segment.write_byte(offset, value),
        }
    }
}

/// One safe, single-threaded alloc_util instance.
///
/// Port of `erts/emulator/beam/erl_alloc_util.c` allocator state, OTP-29.1.1.
pub struct AllocUtil {
    strategy: Strategy,
    options: AllocUtilOptions,
    allocation_type: &'static str,
    carriers: Vec<Option<Carrier>>,
    blocks: HashMap<usize, Block>,
    free_root: usize,
    allocations: HashMap<u64, usize>,
    next_id: u64,
    stats: AllocStats,
    class_stats: [ClassStats; 2],
    mseg: MsegAllocator,
}

impl AllocUtil {
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
        Self {
            strategy,
            options,
            allocation_type,
            carriers: Vec::new(),
            blocks: HashMap::new(),
            free_root: 0,
            allocations: HashMap::new(),
            next_id: 1,
            stats: AllocStats::default(),
            class_stats: [ClassStats::default(); 2],
            mseg: MsegAllocator::new(0, CacheConfig::default()),
        }
    }

    /// Allocates a payload of `size` bytes.
    /// Port of `erts_alcu_alloc`, `erl_alloc_util.c:2377`, OTP-29.1.1.
    pub fn alloc(&mut self, size: usize) -> Result<Allocation, AllocError> {
        self.stats.alloc_calls += 1;
        let block_size = block_size(size, self.strategy)?;
        if block_size >= self.options.sbct {
            let id = self.add_sbc(block_size)?;
            let offset = self.allocations[&id];
            let actual = self.blocks[&offset].size;
            self.stats.blocks += 1;
            self.stats.blocks_size += actual;
            self.block_added(true, actual);
            self.update_block_peak();
            return Ok(Allocation { id, size });
        }
        let offset = if let Some(block) = self.choose_free(block_size)? {
            self.unlink_free(block)?;
            block
        } else {
            let ci = self.add_mbc(block_size)?;
            let block = self.carriers[ci].as_ref().unwrap().blocks[0];
            self.unlink_free(block)?;
            block
        };
        let old = self.blocks[&offset].clone();
        let actual = old.size;
        let carrier = old.carrier;
        let id = self.next_id;
        self.next_id += 1;
        self.allocations.insert(id, offset);
        let split = actual.saturating_sub(block_size) >= min_block_size(self.strategy);
        let used = if split { block_size } else { actual };
        self.blocks.get_mut(&offset).unwrap().allocated = true;
        self.blocks.get_mut(&offset).unwrap().size = used;
        self.write_block(offset)?;
        if split {
            let tail = offset + block_size;
            let tb = Block {
                carrier,
                offset: tail,
                size: actual - block_size,
                allocated: false,
                prev_free: false,
                last: old.last,
            };
            self.blocks.insert(tail, tb);
            let prev = self.blocks.get_mut(&offset).unwrap();
            prev.last = false;
            self.write_block(offset)?;
            let c = self.carriers[carrier].as_mut().unwrap();
            c.blocks.push(tail);
            c.blocks.sort_unstable();
            self.write_block(tail)?;
            if !old.last {
                self.set_next_prev_free(tail, true)?;
            }
            self.link_free(tail)?;
        } else {
            self.set_next_prev_free(offset, false)?;
        }
        self.stats.blocks += 1;
        self.stats.blocks_size += used;
        self.block_added(false, used);
        self.update_block_peak();
        Ok(Allocation { id, size })
    }

    /// Frees a live allocation and merges adjacent free MBC blocks.
    /// Port of `erts_alcu_free`, `erl_alloc_util.c:2820`, OTP-29.1.1.
    pub fn free(&mut self, allocation: Allocation) -> Result<(), AllocError> {
        self.stats.free_calls += 1;
        let offset = self
            .allocations
            .remove(&allocation.id)
            .ok_or(AllocError::InvalidAllocation)?;
        let b = self
            .blocks
            .get(&offset)
            .ok_or(AllocError::InvalidAllocation)?
            .clone();
        self.stats.blocks -= 1;
        self.stats.blocks_size -= b.size;
        let sbc = self.carriers[b.carrier].as_ref().unwrap().sbc;
        self.block_removed(sbc, b.size);
        if sbc {
            self.remove_carrier(b.carrier)?;
            return Ok(());
        }
        self.blocks.get_mut(&offset).unwrap().allocated = false;
        let mut merged = offset;
        if b.prev_free
            && let Some(prev) = self.previous_block(offset)
        {
            let p = self.blocks[&prev].clone();
            if !p.allocated {
                self.unlink_free(prev)?;
                merged = prev;
                self.blocks.get_mut(&prev).unwrap().size += b.size;
                self.blocks.get_mut(&prev).unwrap().last = b.last;
                self.blocks.remove(&offset);
                self.carriers[p.carrier]
                    .as_mut()
                    .unwrap()
                    .blocks
                    .retain(|block| *block != offset);
            }
        }
        let current = self.blocks[&merged].clone();
        if !current.last {
            let next = merged + current.size;
            if self.blocks.get(&next).is_some_and(|n| !n.allocated) {
                self.unlink_free(next)?;
                let n = self.blocks.remove(&next).unwrap();
                let c = self.carriers[current.carrier].as_mut().unwrap();
                c.blocks.retain(|o| *o != next);
                let m = self.blocks.get_mut(&merged).unwrap();
                m.size += n.size;
                m.last = n.last;
            }
        }
        let last = self.blocks[&merged].last;
        self.write_block(merged)?;
        if !last {
            self.set_next_prev_free(merged, true)?;
        }
        let c = self.carriers[current.carrier].as_ref().unwrap();
        if c.blocks.len() == 1 && self.blocks[&merged].size == c.size - (c.start - c.key_base) {
            self.remove_carrier(current.carrier)?;
        } else {
            self.link_free(merged)?;
        }
        Ok(())
    }

    /// Resizes an allocation, preserving its prefix and moving only when needed.
    /// Port of `erts_alcu_realloc`, `erl_alloc_util.c:2828`, OTP-29.1.1.
    pub fn realloc(
        &mut self,
        allocation: Allocation,
        size: usize,
    ) -> Result<Allocation, AllocError> {
        self.stats.realloc_calls += 1;
        let old_offset = *self
            .allocations
            .get(&allocation.id)
            .ok_or(AllocError::InvalidAllocation)?;
        let old = self.blocks[&old_offset].clone();
        let needed = block_size(size, self.strategy)?;
        let old_sbc = self.carriers[old.carrier].as_ref().unwrap().sbc;
        if old_sbc && needed >= self.options.sbct {
            match self.resize_sbc(allocation.id, old_offset, needed) {
                Ok(()) => {
                    return Ok(Allocation {
                        id: allocation.id,
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
                match self.resize_sbc(allocation.id, old_offset, needed) {
                    Ok(()) => {
                        return Ok(Allocation {
                            id: allocation.id,
                            size,
                        });
                    }
                    Err(AllocError::Map(_)) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        let tiny_shrink_can_merge = !old.last
            && self
                .blocks
                .get(&(old_offset + old.size))
                .is_some_and(|block| !block.allocated);
        if !old_sbc && needed == old.size
            || (!old_sbc
                && needed < old.size
                && old.size - needed < min_block_size(self.strategy)
                && !tiny_shrink_can_merge)
        {
            return Ok(Allocation {
                id: allocation.id,
                size,
            });
        }
        let large_shrink = !old_sbc
            && needed < old.size
            && ((old.size - needed) as u128) * 100
                > (self.options.rmbcmt as u128) * (old.size as u128);
        if !old_sbc && needed < old.size {
            let mut candidate_start = old_offset;
            let mut candidate_size = old.size;
            if old.prev_free {
                candidate_start = self.previous_block(old_offset).ok_or(AllocError::Corrupt)?;
                candidate_size += self.blocks[&candidate_start].size;
            }
            if !old.last {
                let next = old_offset + old.size;
                if self.blocks.get(&next).is_some_and(|block| !block.allocated) {
                    candidate_size += self.blocks[&next].size;
                }
            }
            let tree_better = self.choose_free(needed)?.is_some_and(|candidate| {
                let candidate_block_size = self.blocks[&candidate].size;
                candidate_block_size < candidate_size
                    || (self.strategy == Strategy::AddressOrderBestFit
                        && candidate_block_size == candidate_size
                        && candidate < candidate_start)
            });
            if large_shrink && tree_better {
                let replacement = self.alloc(size)?;
                let new_offset = self.allocations[&replacement.id];
                let copy = size.min(old.size.saturating_sub(BLOCK_HEADER));
                for index in 0..copy {
                    let byte = self
                        .read_payload_byte(old_offset, index)
                        .ok_or(AllocError::Corrupt)?;
                    self.write_payload_byte(new_offset, index, byte)?;
                }
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
            let tail_offset = old_offset + needed;
            let mut tail_size = old.size - needed;
            let mut tail_last = old.last;
            if !old.last {
                let next = old_offset + old.size;
                if self.blocks.get(&next).is_some_and(|block| !block.allocated) {
                    let next_block = self.blocks[&next].clone();
                    self.unlink_free(next)?;
                    self.blocks.remove(&next);
                    self.carriers[old.carrier]
                        .as_mut()
                        .unwrap()
                        .blocks
                        .retain(|offset| *offset != next);
                    tail_size += next_block.size;
                    tail_last = next_block.last;
                }
            }
            let block = self.blocks.get_mut(&old_offset).unwrap();
            block.size = needed;
            block.last = false;
            self.blocks.insert(
                tail_offset,
                Block {
                    carrier: old.carrier,
                    offset: tail_offset,
                    size: tail_size,
                    allocated: false,
                    prev_free: false,
                    last: tail_last,
                },
            );
            let carrier = self.carriers[old.carrier].as_mut().unwrap();
            carrier.blocks.push(tail_offset);
            carrier.blocks.sort_unstable();
            self.write_block(old_offset)?;
            self.write_block(tail_offset)?;
            if !tail_last {
                self.set_next_prev_free(tail_offset, true)?;
            }
            self.link_free(tail_offset)?;
            self.stats.blocks_size -= old.size - needed;
            self.block_resized(false, old.size, needed);
            return Ok(Allocation {
                id: allocation.id,
                size,
            });
        }
        if !old_sbc && needed > old.size && !old.last {
            let next = old_offset + old.size;
            if self.blocks.get(&next).is_some_and(|b| !b.allocated)
                && old.size + self.blocks[&next].size >= needed
            {
                self.unlink_free(next)?;
                let n = self.blocks[&next].clone();
                self.blocks.remove(&next);
                self.carriers[old.carrier]
                    .as_mut()
                    .unwrap()
                    .blocks
                    .retain(|o| *o != next);
                let total = old.size + n.size;
                if total - needed >= min_block_size(self.strategy) {
                    let tail = old_offset + needed;
                    self.blocks.get_mut(&old_offset).unwrap().size = needed;
                    self.blocks.get_mut(&old_offset).unwrap().last = false;
                    self.blocks.insert(
                        tail,
                        Block {
                            carrier: old.carrier,
                            offset: tail,
                            size: total - needed,
                            allocated: false,
                            prev_free: false,
                            last: n.last,
                        },
                    );
                    self.carriers[old.carrier]
                        .as_mut()
                        .unwrap()
                        .blocks
                        .push(tail);
                    self.carriers[old.carrier]
                        .as_mut()
                        .unwrap()
                        .blocks
                        .sort_unstable();
                    self.write_block(old_offset)?;
                    self.write_block(tail)?;
                    if !n.last {
                        self.set_next_prev_free(tail, true)?;
                    }
                    self.link_free(tail)?;
                } else {
                    let b = self.blocks.get_mut(&old_offset).unwrap();
                    b.size = total;
                    b.last = n.last;
                    self.write_block(old_offset)?;
                    if !n.last {
                        self.set_next_prev_free(old_offset, false)?;
                    }
                }
                self.stats.blocks_size =
                    self.stats.blocks_size - old.size + self.blocks[&old_offset].size;
                self.block_resized(false, old.size, self.blocks[&old_offset].size);
                return Ok(Allocation {
                    id: allocation.id,
                    size,
                });
            }
        }
        if !old_sbc && old.prev_free && (needed > old.size || large_shrink) {
            let previous = self.previous_block(old_offset).ok_or(AllocError::Corrupt)?;
            let prev = self.blocks[&previous].clone();
            let mut candidate_size = prev.size + old.size;
            let mut next_free = None;
            if !old.last {
                let next = old_offset + old.size;
                if self.blocks.get(&next).is_some_and(|block| !block.allocated) {
                    next_free = Some(next);
                    candidate_size += self.blocks[&next].size;
                }
            }
            if candidate_size >= needed {
                let best = self.choose_free(needed)?;
                let external_is_better = best.is_some_and(|block| {
                    let block_size = self.blocks[&block].size;
                    block_size < candidate_size
                        || (self.strategy == Strategy::AddressOrderBestFit
                            && block_size == candidate_size
                            && block < previous)
                });
                if !external_is_better {
                    let mut payload = Vec::with_capacity(size.min(old.size - BLOCK_HEADER));
                    for index in 0..size.min(old.size - BLOCK_HEADER) {
                        payload.push(
                            self.read_payload_byte(old_offset, index)
                                .ok_or(AllocError::Corrupt)?,
                        );
                    }
                    self.unlink_free(previous)?;
                    if let Some(next) = next_free {
                        self.unlink_free(next)?;
                    }
                    let carrier_index = old.carrier;
                    let last = next_free.map_or(old.last, |next| self.blocks[&next].last);
                    self.blocks.remove(&old_offset);
                    if let Some(next) = next_free {
                        self.blocks.remove(&next);
                        self.carriers[carrier_index]
                            .as_mut()
                            .unwrap()
                            .blocks
                            .retain(|offset| *offset != next);
                    }
                    let remainder = candidate_size - needed;
                    let split = remainder >= min_block_size(self.strategy);
                    let used = if split { needed } else { candidate_size };
                    let block = self.blocks.get_mut(&previous).ok_or(AllocError::Corrupt)?;
                    block.size = used;
                    block.allocated = true;
                    block.last = last && !split;
                    self.allocations.insert(allocation.id, previous);
                    self.carriers[carrier_index]
                        .as_mut()
                        .unwrap()
                        .blocks
                        .retain(|offset| *offset != old_offset);
                    for (index, byte) in payload.into_iter().enumerate() {
                        self.write_payload_byte(previous, index, byte)?;
                    }
                    self.write_block(previous)?;
                    if split {
                        let tail = previous + needed;
                        self.blocks.insert(
                            tail,
                            Block {
                                carrier: carrier_index,
                                offset: tail,
                                size: remainder,
                                allocated: false,
                                prev_free: false,
                                last,
                            },
                        );
                        let carrier = self.carriers[carrier_index].as_mut().unwrap();
                        carrier.blocks.push(tail);
                        carrier.blocks.sort_unstable();
                        self.write_block(tail)?;
                        if !last {
                            self.set_next_prev_free(tail, true)?;
                        }
                        self.link_free(tail)?;
                    } else if !last {
                        self.set_next_prev_free(previous, false)?;
                    }
                    self.stats.blocks_size = self.stats.blocks_size - old.size + used;
                    self.block_resized(false, old.size, used);
                    return Ok(Allocation {
                        id: allocation.id,
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
        let new_offset = self.allocations[&replacement.id];
        let copy = old.size.saturating_sub(BLOCK_HEADER).min(size);
        for i in 0..copy {
            let byte = self
                .read_payload_byte(old_offset, i)
                .ok_or(AllocError::Corrupt)?;
            self.write_payload_byte(new_offset, i, byte)?;
        }
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
        for block in self.blocks.values().filter(|block| block.allocated) {
            let class = if self.carriers[block.carrier].as_ref().unwrap().sbc {
                &mut sbcs
            } else {
                &mut mbcs
            };
            class.blocks += 1;
            class.blocks_size += block.size;
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
            instance: 0,
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
        }
    }

    /// Writes bytes into an allocation with checked bounds.
    pub fn write(
        &mut self,
        allocation: Allocation,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), AllocError> {
        let block = self
            .allocations
            .get(&allocation.id)
            .copied()
            .ok_or(AllocError::InvalidAllocation)?;
        if offset
            .checked_add(bytes.len())
            .is_none_or(|end| end > allocation.size)
        {
            return Err(AllocError::OutOfBounds);
        }
        for (i, byte) in bytes.iter().enumerate() {
            self.write_payload_byte(block, offset + i, *byte)?;
        }
        Ok(())
    }

    /// Reads bytes from an allocation with checked bounds.
    pub fn read(
        &self,
        allocation: Allocation,
        offset: usize,
        out: &mut [u8],
    ) -> Result<(), AllocError> {
        let block = self
            .allocations
            .get(&allocation.id)
            .copied()
            .ok_or(AllocError::InvalidAllocation)?;
        if offset
            .checked_add(out.len())
            .is_none_or(|end| end > allocation.size)
        {
            return Err(AllocError::OutOfBounds);
        }
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = self
                .read_payload_byte(block, offset + i)
                .ok_or(AllocError::Corrupt)?;
        }
        Ok(())
    }

    /// Checks block chains, footer/header agreement, allocation ownership, and free index.
    pub fn validate(&self) -> Result<(), AllocError> {
        let mut free = HashSet::new();
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
                || c.start - c.key_base != if c.sbc { SBC_HEADER } else { MBC_HEADER }
            {
                return Err(AllocError::Corrupt);
            }
            while pos < end {
                let b = self.blocks.get(&pos).ok_or(AllocError::Corrupt)?;
                if b.carrier != ci
                    || b.offset != pos
                    || b.size < min_block_size(self.strategy)
                    || pos + b.size > end
                {
                    return Err(AllocError::Corrupt);
                }
                let rel = pos - c.key_base;
                let h = c.memory.read_word(rel).ok_or(AllocError::Corrupt)?;
                if (h & !BLOCK_FLAGS) != b.size
                    || (!c.sbc && ((h & FREE) != 0) == b.allocated)
                    || (c.sbc && h & (FREE | PREV_FREE | LAST) != FREE | PREV_FREE | LAST)
                    || ((h & PREV_FREE) != 0) != b.prev_free
                    || ((h & LAST) != 0) != b.last
                {
                    return Err(AllocError::Corrupt);
                }
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
            || self.allocations.len() != count
        {
            return Err(AllocError::Corrupt);
        }
        Ok(())
    }

    fn resize_sbc(
        &mut self,
        id: u64,
        old_offset: usize,
        new_block_size: usize,
    ) -> Result<(), AllocError> {
        let old = self
            .blocks
            .get(&old_offset)
            .ok_or(AllocError::Corrupt)?
            .clone();
        let (old_carrier_size, is_mseg) = self.carriers[old.carrier]
            .as_ref()
            .map(|carrier| (carrier.size, carrier.mseg))
            .ok_or(AllocError::Corrupt)?;
        let requested_size = SBC_HEADER
            .checked_add(new_block_size)
            .ok_or(AllocError::Overflow)?;
        {
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
                    .map_err(AllocError::Map)?;
            } else {
                self.stats.sys_realloc_calls += 1;
                let CarrierMemory::Mapped(region) = &mut carrier.memory else {
                    return Err(AllocError::Corrupt);
                };
                region
                    .resize_preserving(requested_size, page_size())
                    .map_err(AllocError::Map)?;
            }
        }
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
            carrier.blocks = vec![new_offset];
        }
        self.blocks.remove(&old_offset);
        self.blocks.insert(
            new_offset,
            Block {
                carrier: old.carrier,
                offset: new_offset,
                size: new_block_size,
                allocated: true,
                prev_free: true,
                last: true,
            },
        );
        self.allocations.insert(id, new_offset);
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
        self.write_block(new_offset)?;
        self.update_block_peak();
        self.update_carrier_peak();
        Ok(())
    }

    fn add_sbc(&mut self, size: usize) -> Result<u64, AllocError> {
        let total = align_up(SBC_HEADER + size)?;
        let (memory, mseg) = self.allocate_carrier(
            total,
            self.stats.mseg_carriers < self.options.mmsbc,
            SegmentFlags::PageAligned,
        )?;
        let total = memory.len();
        let ci = self.carriers.len();
        let key_base = memory.as_ptr() as usize;
        let start = key_base + SBC_HEADER;
        self.carriers.push(Some(Carrier {
            memory,
            sbc: true,
            mseg,
            key_base,
            start,
            size: total,
            blocks: vec![start],
        }));
        self.write_carrier(ci)?;
        let b = Block {
            carrier: ci,
            offset: start,
            size,
            allocated: true,
            prev_free: true,
            last: true,
        };
        self.blocks.insert(start, b.clone());
        self.write_block(start)?;
        let id = self.next_id;
        self.next_id += 1;
        self.allocations.insert(id, start);
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
        Ok(id)
    }
    fn add_mbc(&mut self, needed: usize) -> Result<usize, AllocError> {
        let mbc_count = self
            .carriers
            .iter()
            .flatten()
            .filter(|carrier| !carrier.sbc)
            .count();
        let is_main = mbc_count == 0;
        let mut size = if is_main {
            self.options.mmbcs.max(MBC_HEADER + needed)
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
            .max(MBC_HEADER + needed)
        };
        size = size.max(MBC_HEADER + needed);
        size = align_up(size)?;
        let (memory, mseg) = self.allocate_carrier(
            size,
            !is_main && self.stats.mseg_carriers < self.options.mmmbc,
            SegmentFlags::PowerOfTwo,
        )?;
        let size = memory.len();
        let ci = self.carriers.len();
        let key_base = memory.as_ptr() as usize;
        let start = key_base + MBC_HEADER;
        self.carriers.push(Some(Carrier {
            memory,
            sbc: false,
            mseg,
            key_base,
            start,
            size,
            blocks: vec![start],
        }));
        self.write_carrier(ci)?;
        let b = Block {
            carrier: ci,
            offset: start,
            size: size - (start - key_base),
            allocated: false,
            prev_free: false,
            last: true,
        };
        self.blocks.insert(start, b);
        self.write_block(start)?;
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
        let c = self.carriers[ci].as_mut().unwrap();
        let flags = (if c.sbc { SBC } else { 0 }) | (if c.mseg { MSEG_CARRIER } else { 0 });
        let _ = c.memory.write_word(0, c.size | flags);
        let _ = c.memory.write_word(WORD, 0);
        let _ = c.memory.write_word(2 * WORD, 0);
        let _ = c.memory.write_word(3 * WORD, 0);
        if !c.sbc {
            for offset in (4 * WORD..MBC_HEADER).step_by(WORD) {
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
                    .map_err(|_| AllocError::Map(sys_error))
            }
            Err(error) => Err(AllocError::Map(error)),
        }
    }
    fn write_block(&mut self, offset: usize) -> Result<(), AllocError> {
        let b = self.blocks.get(&offset).ok_or(AllocError::Corrupt)?.clone();
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
        let rel = offset - c.key_base;
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
    fn set_next_prev_free(&mut self, offset: usize, value: bool) -> Result<(), AllocError> {
        let b = self.blocks.get(&offset).ok_or(AllocError::Corrupt)?;
        if b.last {
            return Ok(());
        }
        let next = offset + b.size;
        let n = self.blocks.get_mut(&next).ok_or(AllocError::Corrupt)?;
        n.prev_free = value;
        self.write_block(next)
    }
    fn node_word(&self, node: usize, word: usize) -> Result<usize, AllocError> {
        let block = self.blocks.get(&node).ok_or(AllocError::Corrupt)?;
        let carrier = self.carriers[block.carrier]
            .as_ref()
            .ok_or(AllocError::Corrupt)?;
        carrier
            .memory
            .read_word(node - carrier.key_base + word * WORD)
            .ok_or(AllocError::Corrupt)
    }

    fn set_node_word(&mut self, node: usize, word: usize, value: usize) -> Result<(), AllocError> {
        let block = self.blocks.get(&node).ok_or(AllocError::Corrupt)?;
        let carrier = self.carriers[block.carrier]
            .as_mut()
            .ok_or(AllocError::Corrupt)?;
        if carrier
            .memory
            .write_word(node - carrier.key_base + word * WORD, value)
        {
            Ok(())
        } else {
            Err(AllocError::Corrupt)
        }
    }

    /// Inserts the free block into the OTP intrusive bestfit tree/list.
    /// Port of `bf_link_free_block` and `aobf_link_free_block`, `erl_bestfit_alloc.c:592-818`, OTP-29.1.1.
    fn link_free(&mut self, node: usize) -> Result<(), AllocError> {
        let size = self.blocks.get(&node).ok_or(AllocError::Corrupt)?.size;
        self.set_node_word(node, TREE_FLAGS_WORD, 0)?;
        self.set_node_word(node, TREE_PARENT_WORD, 0)?;
        self.set_node_word(node, TREE_LEFT_WORD, 0)?;
        self.set_node_word(node, TREE_RIGHT_WORD, 0)?;
        if self.strategy == Strategy::BestFit {
            self.set_node_word(node, BF_NEXT_WORD, 0)?;
        }
        let mut parent = 0;
        let mut current = self.free_root;
        while current != 0 {
            parent = current;
            let current_size = self.blocks.get(&current).ok_or(AllocError::Corrupt)?.size;
            if self.strategy == Strategy::BestFit && size == current_size {
                let head_next = self.node_word(current, BF_NEXT_WORD)?;
                self.set_node_word(node, TREE_PARENT_WORD, current)?;
                self.set_node_word(node, BF_NEXT_WORD, head_next)?;
                if head_next != 0 {
                    self.set_node_word(head_next, TREE_PARENT_WORD, node)?;
                }
                self.set_node_word(current, BF_NEXT_WORD, node)?;
                return Ok(());
            }
            let go_left = if size != current_size {
                size < current_size
            } else {
                node < current
            };
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
            self.free_root = node;
            self.set_node_word(node, TREE_FLAGS_WORD, TREE_NODE)?;
            return Ok(());
        }
        let parent_size = self.blocks.get(&parent).ok_or(AllocError::Corrupt)?.size;
        let go_left = size < parent_size || (size == parent_size && node < parent);
        self.set_node_word(
            parent,
            if go_left {
                TREE_LEFT_WORD
            } else {
                TREE_RIGHT_WORD
            },
            node,
        )?;
        self.insert_fixup(node)
    }

    /// Finds the smallest fitting size-tree node, retaining OTP's BF list preference.
    /// Port of `bf_get_free_block` and `aobf_get_free_block`, `erl_bestfit_alloc.c:657-865`, OTP-29.1.1.
    fn choose_free(&self, need: usize) -> Result<Option<usize>, AllocError> {
        let mut current = self.free_root;
        let mut best = 0;
        while current != 0 {
            let size = self.blocks.get(&current).ok_or(AllocError::Corrupt)?.size;
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
    fn unlink_free(&mut self, node: usize) -> Result<(), AllocError> {
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
        self.delete_tree_node(node)
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
            self.free_root = y;
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
            self.free_root = y;
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
        self.set_red(self.free_root, false)
    }

    fn replace_tree_node(&mut self, old: usize, new: usize) -> Result<(), AllocError> {
        let parent = self.node_word(old, TREE_PARENT_WORD)?;
        let left = self.node_word(old, TREE_LEFT_WORD)?;
        let right = self.node_word(old, TREE_RIGHT_WORD)?;
        let flags = self.node_word(old, TREE_FLAGS_WORD)?;
        if parent == 0 {
            self.free_root = new;
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
            self.free_root = new;
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
            self.delete_fixup(child, child_parent)?;
        }
        self.set_node_word(node, TREE_FLAGS_WORD, 0)?;
        self.set_node_word(node, TREE_PARENT_WORD, 0)?;
        self.set_node_word(node, TREE_LEFT_WORD, 0)?;
        self.set_node_word(node, TREE_RIGHT_WORD, 0)?;
        Ok(())
    }

    fn delete_fixup(&mut self, mut node: usize, mut parent: usize) -> Result<(), AllocError> {
        while node != self.free_root && !self.is_red(node)? {
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
                    node = self.free_root;
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
                    node = self.free_root;
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
            let block = allocator.blocks.get(&node).ok_or(AllocError::Corrupt)?;
            if block.allocated
                || allocator.node_word(node, TREE_PARENT_WORD)? != parent
                || allocator.node_word(node, TREE_FLAGS_WORD)? & TREE_NODE == 0
            {
                return Err(AllocError::Corrupt);
            }
            let key = (block.size, node);
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
                            .blocks
                            .get(&list)
                            .is_none_or(|b| b.allocated || b.size != block.size)
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
        let mut seen = HashSet::new();
        if self.free_root != 0 && self.is_red(self.free_root)? {
            return Err(AllocError::Corrupt);
        }
        walk(self, self.free_root, 0, None, None, &mut seen)?;
        Ok(seen)
    }
    fn previous_block(&self, offset: usize) -> Option<usize> {
        let c = self.carriers[self.blocks[&offset].carrier].as_ref()?;
        c.blocks.iter().copied().take_while(|o| *o < offset).last()
    }
    fn remove_carrier(&mut self, ci: usize) -> Result<(), AllocError> {
        let indexed = self.tree_free_blocks()?;
        if let Some(c) = self.carriers[ci].as_ref() {
            let free_blocks = c
                .blocks
                .iter()
                .copied()
                .filter(|offset| indexed.contains(offset))
                .collect::<Vec<_>>();
            for offset in free_blocks {
                self.unlink_free(offset)?;
            }
        }
        if let Some(c) = self.carriers[ci].take() {
            self.carrier_removed(c.sbc, c.mseg, c.size);
            for o in &c.blocks {
                self.blocks.remove(o);
            }
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
                self.stats.sys_free_calls += 1
            }
        }
        Ok(())
    }
    fn read_payload_byte(&self, offset: usize, n: usize) -> Option<u8> {
        let b = &self.blocks[&offset];
        let c = self.carriers[b.carrier].as_ref()?;
        c.memory.read_byte(offset - c.key_base + BLOCK_HEADER + n)
    }
    fn write_payload_byte(&mut self, offset: usize, n: usize, v: u8) -> Result<(), AllocError> {
        let b = self.blocks.get(&offset).ok_or(AllocError::Corrupt)?;
        let c = self.carriers[b.carrier]
            .as_mut()
            .ok_or(AllocError::Corrupt)?;
        if c.memory
            .write_byte(offset - c.key_base + BLOCK_HEADER + n, v)
        {
            Ok(())
        } else {
            Err(AllocError::Corrupt)
        }
    }
    fn update_block_peak(&mut self) {
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
    fn update_series(series: &mut ValueSeries) {
        series.max = series.max.max(series.current);
        series.max_ever = series.max_ever.max(series.max);
    }
    fn block_added(&mut self, sbc: bool, size: usize) {
        let class = &mut self.class_stats[usize::from(sbc)];
        class.blocks.current += 1;
        class.blocks_size.current += size;
        Self::update_series(&mut class.blocks);
        Self::update_series(&mut class.blocks_size);
    }
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
    Map(MapError),
    NoSpace,
    InvalidAllocation,
    OutOfBounds,
    Corrupt,
    Overflow,
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
    }
    #[test]
    fn bf_and_aobf_allocate_and_coalesce() {
        for s in [Strategy::BestFit, Strategy::AddressOrderBestFit] {
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
        let old_offset = allocator.allocations[&large.id];
        allocator.free(hole).unwrap();
        let smaller = allocator.realloc(large, 16).unwrap();
        assert_ne!(allocator.allocations[&smaller.id], old_offset);
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
        let small_address = best.allocations[&small.id];
        best.free(large).unwrap();
        best.free(small).unwrap();
        let chosen = best.alloc(400).unwrap();
        assert_eq!(best.allocations[&chosen.id], small_address);
        best.free(spacer).unwrap();

        let mut address = AllocUtil::new(Strategy::AddressOrderBestFit, options);
        let lower = address.alloc(500).unwrap();
        let separator = address.alloc(16).unwrap();
        let higher = address.alloc(500).unwrap();
        let _guard = address.alloc(1000).unwrap();
        let lower_offset = address.allocations[&lower.id];
        let lower_carrier = &address.carriers[address.blocks[&lower_offset].carrier];
        let lower_address = lower_carrier.as_ref().unwrap().memory.as_ptr() as usize + lower_offset
            - lower_carrier.as_ref().unwrap().key_base;
        address.free(lower).unwrap();
        address.free(higher).unwrap();
        let chosen = address.alloc(500).unwrap();
        let chosen_offset = address.allocations[&chosen.id];
        let chosen_carrier = &address.carriers[address.blocks[&chosen_offset].carrier];
        let chosen_address = chosen_carrier.as_ref().unwrap().memory.as_ptr() as usize
            + chosen_offset
            - chosen_carrier.as_ref().unwrap().key_base;
        assert_eq!(chosen_address, lower_address);
        address.free(separator).unwrap();
        address.validate().unwrap();
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
        assert_eq!(info.mbcs.carriers, 0);
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
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]
        #[test]
        fn randomized_operations_preserve_allocator_invariants(ops in proptest::collection::vec((0u8..3, 1u16..2048), 1..120)) {
            for strategy in [Strategy::BestFit, Strategy::AddressOrderBestFit] {
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
                                    "realloc failed: strategy={strategy:?}, op_index={operation_index}, size={size}, allocation={allocation:?}, offset={:?}, error={:?}, blocks={:?}, allocations={:?}",
                                    allocator.allocations.get(&allocation.id),
                                    resized.as_ref().err(),
                                    allocator.blocks,
                                    allocator.allocations
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
                        "strategy={strategy:?}, op_index={operation_index}, op={op}, size={raw_size}, free_root={}, tree={:?}, blocks={:?}, allocations={:?}",
                        allocator.free_root,
                        allocator.tree_free_blocks(),
                        allocator.blocks,
                        allocator.allocations
                    );
                    prop_assert_eq!(allocator.stats().blocks, live.iter().filter(|a| a.is_some()).count());
                }
            }
        }
    }

    #[test]
    fn otp_default_thresholds_are_read_from_erl() {
        let eval = "[{instance,0,Info}|_] = erlang:system_info({allocator,eheap_alloc}), O = proplists:get_value(options,Info), io:format(\"~p ~p ~p ~p ~p ~p ~p ~p ~p ~p ~p\", [proplists:get_value(sbct,O),proplists:get_value(asbcst,O),proplists:get_value(rsbcst,O),proplists:get_value(rsbcmt,O),proplists:get_value(rmbcmt,O),proplists:get_value(mmbcs,O),proplists:get_value(mmmbc,O),proplists:get_value(mmsbc,O),proplists:get_value(smbcs,O),proplists:get_value(lmbcs,O),proplists:get_value(mbcgs,O)]), halt().";
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
                "524288 4145152 50 80 50 131072 {} 256 262144 5242880 10",
                usize::MAX
            )
        );
    }
}
