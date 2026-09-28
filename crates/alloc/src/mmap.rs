//! macOS OS mapping path from `erl_mmap.c`; this configuration does not reserve a supercarrier.

use crate::raw::{MapError, RawRegion};
use std::sync::{Arc, Mutex};

/// OS mmap counters, matching the non-supercarrier `erts_mmap_info` fields.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MmapStats {
    /// Current mapped bytes.
    pub used: usize,
    /// Largest observed mapped byte count.
    pub peak: usize,
    /// Number of successful mappings.
    pub maps: u64,
    /// Number of successful unmaps.
    pub unmaps: u64,
}

/// A mapper instance with the OS accounting exposed by ERTS.
#[derive(Debug, Default)]
pub struct MemMapper {
    stats: Arc<Mutex<MmapStats>>,
}

impl MemMapper {
    /// Maps page-aligned read/write memory.
    /// Port of erts/emulator/sys/common/erl_mmap.c:1617 (erts_mmap), OTP-29.1.1.
    pub fn map(&mut self, size: usize, superaligned: bool) -> Result<MappedRegion, MapError> {
        let region = if superaligned {
            RawRegion::map_aligned(size, 1 << 24)?
        } else {
            RawRegion::map(size)?
        };
        let mut stats = self.stats.lock().expect("mmap stats lock poisoned");
        stats.used += region.len();
        stats.peak = stats.peak.max(stats.used);
        stats.maps += 1;
        drop(stats);
        Ok(MappedRegion {
            region: Some(region),
            mapped_len: self.stats_len(size, superaligned),
            stats: Arc::clone(&self.stats),
        })
    }

    /// Returns a snapshot of OS mapping counters.
    pub fn stats(&self) -> MmapStats {
        *self.stats.lock().expect("mmap stats lock poisoned")
    }

    /// Accounts for a region released by `unmap`.
    pub fn unmap(&mut self, region: MappedRegion) {
        drop(region);
    }

    fn stats_len(&self, size: usize, _superaligned: bool) -> usize {
        let page = crate::raw::page_size();
        size.max(1).saturating_add(page - 1) & !(page - 1)
    }
}

/// An owned mapped region returned by [`MemMapper`].
pub struct MappedRegion {
    region: Option<RawRegion>,
    mapped_len: usize,
    stats: Arc<Mutex<MmapStats>>,
}

impl MappedRegion {
    /// Requested accessible byte length, page rounded.
    pub fn len(&self) -> usize {
        self.mapped_len
    }
    /// Whether the mapping has zero length.
    pub fn is_empty(&self) -> bool {
        self.mapped_len == 0
    }
    /// Base address.
    pub fn as_ptr(&self) -> *mut u8 {
        self.region
            .as_ref()
            .expect("mapping already unmapped")
            .as_ptr()
    }
    /// Borrows the checked raw region.
    pub fn region(&self) -> &RawRegion {
        self.region.as_ref().expect("mapping already unmapped")
    }
    /// Mutably borrows the checked raw region.
    pub fn region_mut(&mut self) -> &mut RawRegion {
        self.region.as_mut().expect("mapping already unmapped")
    }
}

impl Drop for MappedRegion {
    fn drop(&mut self) {
        // Region ownership remains with RawRegion; dropping it performs munmap.
        if let Some(region) = self.region.take() {
            let len = region.len();
            drop(region);
            let mut stats = self.stats.lock().expect("mmap stats lock poisoned");
            stats.used = stats.used.saturating_sub(len);
            stats.unmaps += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mapper_tracks_map_and_unmap() {
        let mut mapper = MemMapper::default();
        let region = mapper.map(3, false).unwrap();
        assert_eq!(mapper.stats().maps, 1);
        assert_eq!(mapper.stats().used, region.len());
        mapper.unmap(region);
        assert_eq!(mapper.stats().used, 0);
        assert_eq!(mapper.stats().unmaps, 1);
    }
}
