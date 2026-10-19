//! Process and port table identifier layout.
//!
//! erts stores a local pid/port as `pixdata`: the 60-bit identifier data with
//! its low table-index bits permuted so consecutive identifiers land in
//! different cache lines. Printing, ordering, hashing and the external format
//! use the unpermuted `data`; the tagged word (seen by the internal hash) uses
//! `pixdata`. The permutation depends on the table size, so the layout of the
//! one process table and the one port table of this OS process is global, as
//! `erts_proc` and `erts_port` are in erts.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

/// Bits of identifier data in a local pid or port word.
// Port of erts/emulator/beam/erl_ptab.h:171 (ERTS_PTAB_ID_DATA_SIZE), OTP-29.1.1.
pub const PTAB_ID_DATA_SIZE: u32 = 60;
/// Mask of identifier data.
pub const PTAB_ID_DATA_MASK: u64 = (1 << PTAB_ID_DATA_SIZE) - 1;
/// Data of the invalid element; never handed out.
pub const PTAB_INVALID_DATA: u64 = PTAB_ID_DATA_MASK;
/// Largest table size.
// Port of erts/emulator/beam/erl_ptab.h:174 (ERTS_PTAB_MAX_SIZE), OTP-29.1.1.
pub const PTAB_MAX_SIZE: u32 = 1 << 27;
/// Bits of a pid's number; the remaining 32 data bits are its serial.
// Port of erts/emulator/beam/erl_term.h:646 (_PID_NUM_SIZE), OTP-29.1.1.
pub const PID_NUM_SIZE: u32 = 28;
/// Largest local pid number.
pub const MAX_INTERNAL_PID_NUMBER: u32 = (1 << PID_NUM_SIZE) - 1;

/// Table entries per 64-byte cache line (`ERTS_CACHE_LINE_SIZE / sizeof(erts_atomic_t)`).
const IX_PER_CACHE_LINE: u32 = 8;
/// Smallest table whose erts index permutation is a bijection.
const MIN_BITS: u32 = 4;

/// Geometry of a process or port table (`ErtsPTab.r.o` index masks).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PtabLayout {
    bits: u32,
}

/// `erts_fit_in_bits_int32`: bits needed for `value`, at least 1.
fn fit_in_bits(value: u32) -> u32 {
    (32 - value.leading_zeros()).max(1)
}

impl PtabLayout {
    /// Layout of a table asked to hold `size` elements: rounded up to a power of
    /// two and capped at [`PTAB_MAX_SIZE`].
    ///
    /// Port of erts/emulator/beam/erl_ptab.c:383 (erts_ptab_init_table), OTP-29.1.1.
    /// erts never builds tables below `ERTS_MIN_PROCESSES` (1024); smaller requests
    /// are raised to 16 entries, the least size whose index permutation is a bijection.
    pub fn new(size: u32) -> Self {
        let mut bits = fit_in_bits(size.max(1) - 1);
        if (1_u64 << bits) > u64::from(PTAB_MAX_SIZE) {
            bits = fit_in_bits(PTAB_MAX_SIZE - 1);
        }
        Self {
            bits: bits.max(MIN_BITS),
        }
    }

    const fn from_bits(bits: u32) -> Self {
        Self { bits }
    }

    /// Number of index bits.
    pub const fn bits(self) -> u32 {
        self.bits
    }

    /// Table size (`r.o.max`).
    pub const fn max(self) -> u32 {
        1 << self.bits
    }

    const fn pix_mask(self) -> u64 {
        (1 << self.bits) - 1
    }

    /// `pix_cl_mask`: cache lines in the table minus one.
    const fn cl_mask(self) -> u64 {
        (1 << (self.bits - 3)) - 1
    }

    /// `pix_cli_shift`.
    const fn cli_shift(self) -> u32 {
        self.bits - 3
    }

    /// Table index of identifier data.
    ///
    /// Port of erts/emulator/beam/erl_ptab.h:301 (erts_ptab_data2pix), OTP-29.1.1.
    #[inline]
    pub const fn data2pix(self, data: u64) -> u32 {
        (((data & self.cl_mask()) << 3) + ((data >> self.cli_shift()) & 7)) as u32
    }

    /// Permuted data stored in the tagged word.
    ///
    /// Port of erts/emulator/beam/erl_ptab.h:311 (erts_ptab_data2pixdata), OTP-29.1.1.
    #[inline]
    pub const fn data2pixdata(self, data: u64) -> u64 {
        (data & !self.pix_mask()) | self.data2pix(data) as u64
    }

    /// Identifier data of a tagged word's payload.
    ///
    /// Port of erts/emulator/beam/erl_ptab.h:288 (erts_ptab_pixdata2data), OTP-29.1.1.
    #[inline]
    pub const fn pixdata2data(self, pixdata: u64) -> u64 {
        (pixdata & !self.pix_mask())
            | ((pixdata >> 3) & self.cl_mask())
            | ((pixdata & 7) << self.cli_shift())
    }

    /// Table index of a tagged word's payload.
    #[inline]
    pub const fn pixdata2pix(self, pixdata: u64) -> u32 {
        (pixdata & self.pix_mask()) as u32
    }

    /// Index into the free identifier ring for a ring position.
    ///
    /// Port of erts/emulator/beam/erl_ptab.c:338 (ix_to_free_id_data_ix), OTP-29.1.1.
    #[inline]
    pub const fn ix_to_free_id_data_ix(self, ix: u32) -> u32 {
        // The free-id ring has the same size and cache-line geometry as the table.
        self.data2pix(ix as u64)
    }

    /// Initial content of free identifier ring slot `dix`.
    ///
    /// Port of erts/emulator/beam/erl_ptab.c:446 (erts_ptab_init_table free_id_data), OTP-29.1.1.
    #[inline]
    pub const fn initial_free_id_data(self, dix: u32) -> u64 {
        let cl = dix / IX_PER_CACHE_LINE;
        let cli = dix % IX_PER_CACHE_LINE;
        cli as u64 * (self.cl_mask() + 1) + cl as u64
    }
}

impl Default for PtabLayout {
    /// Layout for `ERTS_DEFAULT_MAX_PROCESSES` (2^20).
    fn default() -> Self {
        Self::from_bits(20)
    }
}

static PROCESS_TABLE_BITS: AtomicU8 = AtomicU8::new(20);
/// Zero until the first use fixes the default size from the environment.
static PORT_TABLE_BITS: AtomicU8 = AtomicU8::new(0);

/// Size of the port table when neither `+Q` nor `ERL_MAX_PORTS` is given: the larger of
/// `ERTS_DEFAULT_MAX_PORTS` and the descriptor limit.
// Port of erts/emulator/beam/erl_init.c (erl_start) and io.c (erts_init_io), OTP-29.1.1.
fn default_port_table_size() -> u32 {
    const DEFAULT_MAX_PORTS: usize = 1 << 16;
    const MIN_PORTS: usize = 1024;
    const MAX_PORTS: usize = PTAB_MAX_SIZE as usize - 1;
    if let Some(size) = std::env::var("ERL_MAX_PORTS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
    {
        return size.clamp(MIN_PORTS, MAX_PORTS) as u32;
    }
    DEFAULT_MAX_PORTS
        .max(arinsal_alloc::cpuinfo::poll_max_fds())
        .clamp(MIN_PORTS, MAX_PORTS) as u32
}

#[cold]
fn init_port_table_bits() -> u8 {
    let bits = PtabLayout::new(default_port_table_size()).bits as u8;
    // A concurrent `set_port_table_layout` (+Q) wins.
    match PORT_TABLE_BITS.compare_exchange(0, bits, Ordering::Relaxed, Ordering::Relaxed) {
        Ok(_) => bits,
        Err(set) => set,
    }
}

/// Layout of this OS process's Erlang process table (`erts_proc`).
#[inline]
pub fn process_table_layout() -> PtabLayout {
    PtabLayout::from_bits(u32::from(PROCESS_TABLE_BITS.load(Ordering::Relaxed)))
}

/// Install the process table layout; done once when the emulator sizes its table.
pub fn set_process_table_layout(layout: PtabLayout) {
    PROCESS_TABLE_BITS.store(layout.bits as u8, Ordering::Relaxed);
}

/// Layout of this OS process's port table (`erts_port`).
#[inline]
pub fn port_table_layout() -> PtabLayout {
    let bits = match PORT_TABLE_BITS.load(Ordering::Relaxed) {
        0 => init_port_table_bits(),
        bits => bits,
    };
    PtabLayout::from_bits(u32::from(bits))
}

/// Install the port table layout; done once when the emulator sizes its table.
pub fn set_port_table_layout(layout: PtabLayout) {
    PORT_TABLE_BITS.store(layout.bits as u8, Ordering::Relaxed);
}

/// Entries per lazily materialized page of the free identifier ring.
const RING_PAGE: usize = 1024;

/// Identifier allocator of a process or port table: the element count and the
/// free identifier ring (`free_id_data`, `aid_ix`, `fid_ix`) of erts' non-legacy
/// `ErtsPTab`. Slot storage stays with the owner, which serializes
/// [`PtabIdRing::test_next_id`] against reservations and releases as erts' table
/// rwlock does. Pages of the ring are materialized on first use; an untouched page
/// holds its initial content.
pub struct PtabIdRing {
    layout: PtabLayout,
    limit: u32,
    count: AtomicU32,
    aid_ix: AtomicU32,
    fid_ix: AtomicU32,
    pages: Box<[OnceLock<Box<[AtomicU64]>>]>,
    invalid_pix: Option<u32>,
}

impl PtabIdRing {
    /// Allocator for a table asked to hold `capacity` elements. At most
    /// `capacity` elements are live at once even when the table rounds up.
    ///
    /// Port of erts/emulator/beam/erl_ptab.c:359 (erts_ptab_init_table), OTP-29.1.1.
    pub fn new(capacity: u32) -> Self {
        let layout = PtabLayout::new(capacity);
        // A full-size table parks the invalid element in its slot so only
        // ERTS_PTAB_MAX_SIZE-1 identifiers are ever handed out (erl_ptab.c:470).
        let invalid_pix =
            (layout.max() == PTAB_MAX_SIZE).then(|| layout.data2pix(PTAB_INVALID_DATA));
        Self {
            layout,
            limit: capacity.clamp(1, layout.max()),
            count: AtomicU32::new(u32::from(invalid_pix.is_some())),
            aid_ix: AtomicU32::new(u32::MAX),
            fid_ix: AtomicU32::new(u32::MAX),
            pages: (0..(layout.max() as usize).div_ceil(RING_PAGE))
                .map(|_| OnceLock::new())
                .collect(),
            invalid_pix,
        }
    }

    /// Number of live elements.
    ///
    /// Port of erts/emulator/beam/erl_ptab.h:273 (erts_ptab_count), OTP-29.1.1.
    pub fn count(&self) -> usize {
        let mut max = self.layout.max();
        let mut res = self.count.load(Ordering::Relaxed);
        if max == PTAB_MAX_SIZE {
            max -= 1;
            res = res.saturating_sub(1);
        }
        res.min(max) as usize
    }

    /// Table geometry.
    pub fn layout(&self) -> PtabLayout {
        self.layout
    }

    /// Slot permanently taken by the invalid element, if any.
    pub fn invalid_pix(&self) -> Option<u32> {
        self.invalid_pix
    }

    fn slot(&self, dix: u32) -> &AtomicU64 {
        let dix = dix as usize;
        let page = self.pages[dix / RING_PAGE].get_or_init(|| {
            let base = (dix / RING_PAGE * RING_PAGE) as u32;
            (0..RING_PAGE as u32)
                .map(|offset| AtomicU64::new(self.layout.initial_free_id_data(base + offset)))
                .collect()
        });
        &page[dix % RING_PAGE]
    }

    /// Reserve an element and take the next free identifier data; `None` when the
    /// table is full.
    ///
    /// Port of erts/emulator/beam/erl_ptab.c:500 (erts_ptab_new_element), OTP-29.1.1.
    pub fn reserve(&self) -> Option<u64> {
        let mut count = self.count.fetch_add(1, Ordering::Acquire) + 1;
        if count > self.limit {
            loop {
                match self.count.compare_exchange(
                    count,
                    count - 1,
                    Ordering::Release,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => return None,
                    Err(actual) => count = actual,
                }
                if count <= self.limit {
                    break;
                }
            }
        }
        loop {
            let ix = self.aid_ix.fetch_add(1, Ordering::Acquire).wrapping_add(1);
            let dix = self.layout.ix_to_free_id_data_ix(ix);
            let data = self.slot(dix).swap(PTAB_INVALID_DATA, Ordering::Relaxed);
            if data != PTAB_INVALID_DATA {
                return Some(data);
            }
        }
    }

    /// Release the element identified by `data` after its slot was cleared; the
    /// slot's next identifier is `data` plus the table size.
    ///
    /// Port of erts/emulator/beam/erl_ptab.c:675 (erts_ptab_delete_element), OTP-29.1.1.
    pub fn release(&self, data: u64) {
        let max = u64::from(self.layout.max());
        let mut data = (data + max) & PTAB_ID_DATA_MASK;
        if data == PTAB_INVALID_DATA {
            data = (data + max) & PTAB_ID_DATA_MASK;
        }
        loop {
            let ix = self.fid_ix.fetch_add(1, Ordering::Release).wrapping_add(1);
            let dix = self.layout.ix_to_free_id_data_ix(ix);
            if self
                .slot(dix)
                .compare_exchange(
                    PTAB_INVALID_DATA,
                    data,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                break;
            }
        }
        self.count.fetch_sub(1, Ordering::Release);
    }

    /// Inspect, or with `set` restart the free ring after `next`, returning the data
    /// the next reservation takes. `occupied(pix)` reports live table slots; the
    /// caller excludes concurrent reservations and releases.
    ///
    /// Port of erts/emulator/beam/erl_ptab.c:1356 (erts_ptab_test_next_id), OTP-29.1.1.
    pub fn test_next_id(&self, set: bool, next: u64, occupied: impl Fn(u32) -> bool) -> u64 {
        let max_ix = self.layout.max() - 1;
        if set {
            let max = u64::from(self.layout.max());
            let mut num = next;
            let mut id_ix = self.aid_ix.load(Ordering::Relaxed);
            for _ in 0..=max_ix {
                num = num.wrapping_add(1) & PTAB_ID_DATA_MASK;
                if num == PTAB_INVALID_DATA {
                    num = (num + max) & PTAB_ID_DATA_MASK;
                }
                let pix = self.layout.data2pix(num);
                if self.invalid_pix != Some(pix) && !occupied(pix) {
                    id_ix = id_ix.wrapping_add(1);
                    let dix = self.layout.ix_to_free_id_data_ix(id_ix);
                    self.slot(dix).store(num, Ordering::Relaxed);
                }
            }
            self.fid_ix.store(id_ix, Ordering::Relaxed);
            // Write invalid data in the rest of the ring.
            let stop_id_ix = self.aid_ix.load(Ordering::Relaxed).wrapping_add(1) & max_ix;
            loop {
                id_ix = id_ix.wrapping_add(1) & max_ix;
                if id_ix == stop_id_ix {
                    break;
                }
                let dix = self.layout.ix_to_free_id_data_ix(id_ix);
                self.slot(dix).store(PTAB_INVALID_DATA, Ordering::Relaxed);
            }
        }
        let id_ix = self.aid_ix.load(Ordering::Relaxed).wrapping_add(1);
        self.slot(self.layout.ix_to_free_id_data_ix(id_ix))
            .load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permutation_round_trips() {
        for size in [16, 1024, 1 << 20, PTAB_MAX_SIZE] {
            let layout = PtabLayout::new(size);
            for data in [
                0,
                1,
                7,
                8,
                131_071,
                131_072,
                1_048_585,
                PTAB_INVALID_DATA - 5,
            ] {
                let pixdata = layout.data2pixdata(data);
                assert_eq!(layout.pixdata2data(pixdata), data);
                assert_eq!(layout.pixdata2pix(pixdata), layout.data2pix(data));
            }
            let mut seen = vec![false; layout.max() as usize];
            for dix in 0..layout.max().min(1 << 16) {
                let data = layout.initial_free_id_data(dix);
                assert!(!std::mem::replace(
                    &mut seen[layout.data2pix(data) as usize],
                    true
                ));
            }
        }
    }

    #[test]
    fn ring_hands_out_sequential_then_recycled_data() {
        let ring = PtabIdRing::new(16);
        let first: Vec<u64> = (0..16).map(|_| ring.reserve().unwrap()).collect();
        assert_eq!(first, (0..16).collect::<Vec<_>>());
        assert_eq!(ring.reserve(), None);
        ring.release(5);
        assert_eq!(ring.reserve(), Some(21));
        assert_eq!(
            ring.test_next_id(true, 99, |pix| pix != ring.layout().data2pix(5)),
            101
        );
    }

    #[test]
    fn rounding_matches_erts() {
        assert_eq!(PtabLayout::new(1_048_576).max(), 1_048_576);
        assert_eq!(PtabLayout::new(1000).max(), 1024);
        assert_eq!(PtabLayout::new(1025).max(), 2048);
        assert_eq!(PtabLayout::new(u32::MAX).max(), PTAB_MAX_SIZE);
    }
}
