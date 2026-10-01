//! ERTS segment cache and per-instance accounting.

use crate::raw::{MapError, RawRegion, page_size};

/// Cache and realloc policy from `erts_mseg_default_opt`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MsegOptions {
    /// Keep deallocated segments in the cache.
    pub cache: bool,
    /// Preserve contents when a segment must be recreated.
    pub preserve: bool,
    /// Minimum shrink threshold in bytes.
    pub absolute_shrink_threshold: usize,
    /// Minimum shrink ratio in percent.
    pub relative_shrink_threshold: usize,
    /// Select the scheduler instance.
    pub scheduler_specific: bool,
}

impl Default for MsegOptions {
    fn default() -> Self {
        Self {
            cache: true,
            preserve: true,
            absolute_shrink_threshold: 0,
            relative_shrink_threshold: 0,
            scheduler_specific: false,
        }
    }
}

/// Cache limits configured from `ErtsMsegInit_t`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheConfig {
    pub absolute_bad_fit: usize,
    pub relative_bad_fit: usize,
    pub max_cache_size: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            absolute_bad_fit: 4 * 1024 * 1024,
            relative_bad_fit: 20,
            max_cache_size: 10,
        }
    }
}

/// Segment allocation mode; powered segments require superalignment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SegmentFlags {
    PageAligned,
    PowerOfTwo,
}

/// A mapped segment with its original allocation mode.
pub struct Segment {
    region: RawRegion,
    flags: SegmentFlags,
}

impl Segment {
    /// Segment base address.
    pub fn as_ptr(&self) -> *mut u8 {
        self.region.as_ptr()
    }
    /// Segment size.
    pub fn len(&self) -> usize {
        self.region.len()
    }
    /// Whether the segment has zero bytes.
    pub fn is_empty(&self) -> bool {
        self.region.is_empty()
    }

    /// The whole segment as bytes, or `None` when it is not readable.
    pub fn bytes(&self) -> Option<&[u8]> {
        self.region.bytes()
    }

    /// The whole segment as mutable bytes, or `None` when it is not writable.
    pub fn bytes_mut(&mut self) -> Option<&mut [u8]> {
        self.region.bytes_mut()
    }

    /// Reads a checked byte from the segment.
    pub fn read_byte(&self, offset: usize) -> Option<u8> {
        self.region.read_byte(offset)
    }

    /// Writes a checked byte to the segment.
    pub fn write_byte(&mut self, offset: usize, value: u8) -> bool {
        self.region.write_byte(offset, value)
    }

    /// Reads a checked native word from the segment.
    #[inline]
    pub fn read_word(&self, offset: usize) -> Option<usize> {
        self.region.read_word(offset)
    }

    /// Writes a checked native word to the segment.
    #[inline]
    pub fn write_word(&mut self, offset: usize, value: usize) -> bool {
        self.region.write_word(offset, value)
    }

    /// Advises the OS about a page-aligned range inside this segment.
    pub fn advise_range(&mut self, offset: usize, len: usize, advice: i32) -> Result<(), MapError> {
        self.region.advise_range(offset, len, advice)
    }

    /// Resizes this segment while keeping the original alive if mapping fails.
    pub fn resize_preserving(
        &mut self,
        new_size: usize,
        flags: SegmentFlags,
    ) -> Result<(), MapError> {
        let wanted = rounded_size(new_size, flags);
        let alignment = if flags == SegmentFlags::PowerOfTwo {
            1 << 24
        } else {
            page_size()
        };
        self.region.resize_preserving(wanted, alignment)?;
        self.flags = flags;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
/// ERTS's wrapping giga/no counter pair.
pub struct CallCount {
    pub giga: u64,
    pub count: u32,
}

impl CallCount {
    pub(crate) fn inc(&mut self) {
        if self.count == 999_999_999 {
            self.giga += 1;
            self.count = 0;
        } else {
            self.count += 1;
        }
    }
    fn dec(&mut self) {
        if self.count == 0 {
            self.giga = self.giga.saturating_sub(1);
            self.count = 999_999_999;
        } else {
            self.count -= 1;
        }
    }
}

/// All nine counters printed by mseg allocator info.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MsegCalls {
    pub alloc: CallCount,
    pub dealloc: CallCount,
    pub realloc: CallCount,
    pub create: CallCount,
    pub create_resize: CallCount,
    pub destroy: CallCount,
    pub recreate: CallCount,
    pub clear_cache: CallCount,
    pub check_cache: CallCount,
}

/// Segment status tuple fields reported by `system_info({allocator, mseg_alloc})`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SegmentStatus {
    pub cached_segments: usize,
    pub cache_hits: u64,
    pub segments_current: usize,
    pub segments_max: usize,
    pub segments_max_ever: usize,
    pub segments_watermark: usize,
    pub size_current: usize,
    pub size_max: usize,
    pub size_max_ever: usize,
}

/// Rust representation of one `{instance, Ix, [...]}` info entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstanceInfo {
    pub instance: usize,
    pub version: &'static str,
    pub config: CacheConfig,
    pub status: SegmentStatus,
    pub calls: MsegCalls,
}

/// A scheduler-local segment allocator and cache.
pub struct MsegAllocator {
    pub instance: usize,
    pub config: CacheConfig,
    status: SegmentStatus,
    calls: MsegCalls,
    powered: Vec<Segment>,
    unpowered: Vec<Segment>,
}

impl MsegAllocator {
    /// Creates one allocator instance. Instance zero is the global instance.
    pub fn new(instance: usize, config: CacheConfig) -> Self {
        Self {
            instance,
            config,
            status: SegmentStatus::default(),
            calls: MsegCalls::default(),
            powered: Vec::new(),
            unpowered: Vec::new(),
        }
    }

    /// Maps a segment, reusing a compatible cached mapping when possible.
    /// Port of erts/emulator/sys/common/erl_mseg.c:687 (mseg_alloc), OTP-29.1.1.
    pub fn alloc(&mut self, requested: usize, flags: SegmentFlags) -> Result<Segment, MapError> {
        self.calls.alloc.inc();
        let size = rounded_size(requested, flags);
        if flags == SegmentFlags::PowerOfTwo {
            if let Some(index) = self
                .powered
                .iter()
                .enumerate()
                .filter(|(_, s)| s.len() >= size)
                .min_by_key(|(_, s)| s.len())
                .map(|(index, _)| index)
            {
                let mut seg = self.powered.remove(index);
                self.status.cached_segments -= 1;
                self.status.cache_hits += 1;
                if seg.len() > size {
                    self.calls.destroy.inc();
                    let (head, _tail) = seg
                        .region
                        .split_at(size)
                        .expect("powered segment boundaries are aligned");
                    seg = Segment {
                        region: head,
                        flags,
                    };
                }
                self.account_alloc(seg.len());
                return Ok(seg);
            }
        } else if !self.unpowered.is_empty() {
            let best = self
                .unpowered
                .iter()
                .enumerate()
                .filter(|(_, s)| s.len() >= size)
                .min_by_key(|(_, s)| s.len() - size)
                .map(|(i, _)| i);
            if let Some(index) = best {
                let current = self.unpowered[index].len();
                let within_absolute = current - size < self.config.absolute_bad_fit;
                let within_relative = (current - size) as u128 * 100
                    < self.config.relative_bad_fit as u128 * size as u128;
                let (segment, actual) = if within_absolute && within_relative {
                    let segment = self.unpowered.remove(index);
                    self.status.cached_segments -= 1;
                    self.status.cache_hits += 1;
                    (segment, current)
                } else {
                    let cached = self.unpowered.remove(index);
                    let (head, tail) = cached
                        .region
                        .split_at(size)
                        .expect("page-aligned size splits cached segment");
                    self.unpowered.insert(
                        index,
                        Segment {
                            region: tail,
                            flags: SegmentFlags::PageAligned,
                        },
                    );
                    self.status.cache_hits += 1;
                    (
                        Segment {
                            region: head,
                            flags,
                        },
                        size,
                    )
                };
                self.account_alloc(actual);
                return Ok(segment);
            }
        }
        self.calls.create.inc();
        let region = if flags == SegmentFlags::PowerOfTwo {
            RawRegion::map_aligned(size, 1 << 24)?
        } else {
            RawRegion::map(size)?
        };
        let segment = Segment { region, flags };
        self.account_alloc(segment.len());
        Ok(segment)
    }

    /// Returns a segment to the cache or unmaps it according to mcs.
    /// Port of erts/emulator/sys/common/erl_mseg.c:602 (cache_bless_segment), OTP-29.1.1.
    pub fn dealloc(&mut self, segment: Segment, options: MsegOptions) {
        self.status.segments_current -= 1;
        self.status.size_current -= segment.len();
        self.calls.dealloc.inc();
        if options.cache && self.cache_segment(segment) {
            return;
        }
        self.calls.destroy.inc();
    }

    /// Accounts for a live segment transferred from another scheduler-local owner.
    pub(crate) fn adopt_existing(&mut self, size: usize) {
        self.account_alloc(size);
    }

    /// Removes a transferred segment from this instance without unmapping it.
    pub(crate) fn release_transferred(&mut self, size: usize) {
        self.status.segments_current -= 1;
        self.status.size_current -= size;
    }

    /// Resizes a segment while preserving the original prefix.
    /// Port of erts/emulator/sys/common/erl_mseg.c:757 (mseg_realloc), OTP-29.1.1.
    pub fn realloc(
        &mut self,
        segment: Option<Segment>,
        new_size: usize,
        flags: SegmentFlags,
        options: MsegOptions,
    ) -> Result<Option<Segment>, MapError> {
        let Some(segment) = segment else {
            let segment = self.alloc(new_size, flags)?;
            self.calls.alloc.dec();
            return Ok(Some(segment));
        };
        if new_size == 0 {
            self.dealloc(segment, options);
            self.calls.dealloc.dec();
            return Ok(None);
        }
        let old_size = segment.len();
        let wanted = rounded_size(new_size, flags);
        if wanted > old_size && !options.preserve {
            self.dealloc(segment, options);
            self.calls.dealloc.dec();
            let replacement = self.alloc(new_size, flags)?;
            self.calls.alloc.dec();
            self.calls.realloc.inc();
            return Ok(Some(replacement));
        }
        if wanted < old_size {
            let shrink = old_size - wanted;
            if shrink < options.absolute_shrink_threshold
                && (shrink as u128) * 100
                    < (options.relative_shrink_threshold as u128) * old_size as u128
            {
                self.calls.realloc.inc();
                return Ok(Some(segment));
            }
        }
        let (region, result_size) = if wanted == old_size {
            (segment.region, old_size)
        } else {
            self.calls.recreate.inc();
            let alignment = if flags == SegmentFlags::PowerOfTwo {
                1 << 24
            } else {
                page_size()
            };
            (segment.region.resize_aligned(wanted, alignment)?, wanted)
        };
        self.calls.realloc.inc();
        self.status.size_current = self.status.size_current - old_size + result_size;
        self.status.size_max = self.status.size_max.max(self.status.size_current);
        self.status.size_max_ever = self.status.size_max_ever.max(self.status.size_current);
        Ok(Some(Segment { region, flags }))
    }

    /// Resizes an owned segment without consuming it on mapping failure.
    pub fn resize_carrier(
        &mut self,
        segment: &mut Segment,
        new_size: usize,
        flags: SegmentFlags,
        options: MsegOptions,
    ) -> Result<(), MapError> {
        let old_size = segment.len();
        let wanted = rounded_size(new_size, flags);
        if wanted < old_size {
            let shrink = old_size - wanted;
            if shrink < options.absolute_shrink_threshold
                && (shrink as u128) * 100
                    < (options.relative_shrink_threshold as u128) * old_size as u128
            {
                self.calls.realloc.inc();
                return Ok(());
            }
        }
        if wanted != old_size {
            self.calls.recreate.inc();
            segment.resize_preserving(wanted, flags)?;
            let new_size = segment.len();
            self.status.size_current = self.status.size_current - old_size + new_size;
            self.status.size_max = self.status.size_max.max(self.status.size_current);
            self.status.size_max_ever = self.status.size_max_ever.max(self.status.size_current);
        }
        self.calls.realloc.inc();
        Ok(())
    }

    /// Destroys all cached mappings.
    /// Port of erts/emulator/sys/common/erl_mseg.c:681 (erts_mseg_clear_cache), OTP-29.1.1.
    pub fn clear_cache(&mut self) {
        self.calls.clear_cache.inc();
        let cached = self.powered.len() + self.unpowered.len();
        self.calls.destroy.count = self.calls.destroy.count.saturating_add(cached as u32);
        self.status.segments_watermark = self.status.segments_watermark.saturating_sub(cached);
        self.status.cached_segments = 0;
        self.powered.clear();
        self.unpowered.clear();
    }

    /// Drops one cached segment, as scheduler aux-work does.
    /// Port of erts/emulator/sys/common/erl_mseg.c:446 (mseg_check_cache), OTP-29.1.1.
    pub fn check_cache(&mut self) -> bool {
        self.calls.check_cache.inc();
        if !self.powered.is_empty() {
            self.powered.remove(0);
        } else if !self.unpowered.is_empty() {
            self.unpowered.remove(0);
        } else {
            return false;
        }
        self.status.cached_segments -= 1;
        self.status.segments_watermark = self.status.segments_watermark.saturating_sub(1);
        self.calls.destroy.inc();
        true
    }

    /// Returns the data fields in OTP's version 0.9 info shape.
    pub fn info(&self) -> InstanceInfo {
        InstanceInfo {
            instance: self.instance,
            version: "0.9",
            config: self.config,
            status: self.status,
            calls: self.calls,
        }
    }

    fn account_alloc(&mut self, size: usize) {
        self.status.segments_current += 1;
        self.status.segments_max = self.status.segments_max.max(self.status.segments_current);
        self.status.segments_max_ever = self
            .status
            .segments_max_ever
            .max(self.status.segments_current);
        self.status.segments_watermark = self
            .status
            .segments_watermark
            .max(self.status.segments_current + self.status.cached_segments);
        self.status.size_current += size;
        self.status.size_max = self.status.size_max.max(self.status.size_current);
        self.status.size_max_ever = self.status.size_max_ever.max(self.status.size_current);
    }

    fn cache_segment(&mut self, segment: Segment) -> bool {
        let count = self.powered.len() + self.unpowered.len();
        if count < self.config.max_cache_size {
            if segment.flags == SegmentFlags::PowerOfTwo {
                self.powered.insert(0, segment);
            } else {
                self.unpowered.insert(0, segment);
            }
            self.status.cached_segments += 1;
            return true;
        }
        if segment.flags == SegmentFlags::PageAligned {
            if !self.unpowered.is_empty() {
                self.unpowered.pop();
                self.calls.destroy.inc();
                self.unpowered.insert(0, segment);
                return true;
            }
            if let Some((index, _)) = self.powered.iter().enumerate().min_by_key(|(_, s)| s.len()) {
                self.powered.remove(index);
                self.calls.destroy.inc();
                self.unpowered.insert(0, segment);
                return true;
            }
        }
        false
    }
}

/// Builds a global instance and one independent instance per scheduler.
pub fn instances(schedulers: usize, config: CacheConfig) -> Vec<MsegAllocator> {
    (0..=schedulers)
        .map(|ix| MsegAllocator::new(ix, config))
        .collect()
}

fn rounded_size(size: usize, flags: SegmentFlags) -> usize {
    let page = page_size();
    let alignment = if flags == SegmentFlags::PowerOfTwo {
        1 << 24
    } else {
        page
    };
    let aligned = size.max(1).saturating_add(alignment - 1) & !(alignment - 1);
    if flags == SegmentFlags::PowerOfTwo {
        aligned.checked_next_power_of_two().unwrap_or(aligned)
    } else {
        aligned
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn defaults_match_header() {
        assert_eq!(
            CacheConfig::default(),
            CacheConfig {
                absolute_bad_fit: 4_194_304,
                relative_bad_fit: 20,
                max_cache_size: 10
            }
        );
    }
    #[test]
    fn runtime_defaults_match_erl() {
        let output = std::process::Command::new("erl")
            .args([
                "-noshell",
                "-eval",
                "io:format(\"~p\", [erlang:system_info({allocator,mseg_alloc})]), halt().",
            ])
            .output()
            .expect("erl must be installed per task environment");
        let output = String::from_utf8_lossy(&output.stdout);
        assert!(output.contains("{amcbf,4194304}"), "{output}");
        assert!(output.contains("{rmcbf,20}"), "{output}");
        assert!(output.contains("{mcs,10}"), "{output}");
    }
    #[test]
    fn mseg_cache_hit_counts() {
        let mut a = MsegAllocator::new(0, CacheConfig::default());
        let s = a.alloc(4096, SegmentFlags::PageAligned).unwrap();
        a.dealloc(s, MsegOptions::default());
        let s = a.alloc(4096, SegmentFlags::PageAligned).unwrap();
        assert_eq!(a.info().status.cache_hits, 1);
        a.dealloc(s, MsegOptions::default());
        a.clear_cache();
    }
    #[test]
    fn mseg_cache_capacity_obeys_mcs() {
        let mut a = MsegAllocator::new(
            0,
            CacheConfig {
                max_cache_size: 2,
                ..Default::default()
            },
        );
        let mut segments = Vec::new();
        for _ in 0..4 {
            segments.push(a.alloc(4096, SegmentFlags::PageAligned).unwrap());
        }
        for s in segments {
            a.dealloc(s, MsegOptions::default());
        }
        assert_eq!(a.info().status.cached_segments, 2);
        a.clear_cache();
    }
    #[test]
    fn mseg_check_cache_drops_one() {
        let mut a = MsegAllocator::new(0, CacheConfig::default());
        let s = a.alloc(4096, SegmentFlags::PageAligned).unwrap();
        a.dealloc(s, MsegOptions::default());
        assert!(a.check_cache());
        assert_eq!(a.info().status.cached_segments, 0);
    }
    #[test]
    fn mseg_instance_counters_are_separate() {
        let mut all = instances(2, CacheConfig::default());
        let _ = all[1].alloc(4096, SegmentFlags::PageAligned).unwrap();
        assert_eq!(all[0].info().calls.alloc.count, 0);
        assert_eq!(all[1].info().calls.alloc.count, 1);
    }
    #[test]
    fn mseg_sizes_track_realloc() {
        let mut a = MsegAllocator::new(0, CacheConfig::default());
        let s = a.alloc(4096, SegmentFlags::PageAligned).unwrap();
        let s = a
            .realloc(
                Some(s),
                8192,
                SegmentFlags::PageAligned,
                MsegOptions::default(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(a.info().status.size_current, s.len());
        a.dealloc(
            s,
            MsegOptions {
                cache: false,
                ..Default::default()
            },
        );
    }
    #[test]
    fn mseg_calls_and_watermark_report() {
        let mut a = MsegAllocator::new(0, CacheConfig::default());
        let s = a.alloc(1, SegmentFlags::PageAligned).unwrap();
        a.dealloc(s, MsegOptions::default());
        let i = a.info();
        assert_eq!(i.calls.alloc.count, 1);
        assert_eq!(i.calls.dealloc.count, 1);
        assert!(i.status.segments_watermark > 0);
        a.clear_cache();
    }
    #[test]
    fn mseg_zero_realloc_frees() {
        let mut a = MsegAllocator::new(0, CacheConfig::default());
        let s = a.alloc(4096, SegmentFlags::PageAligned).unwrap();
        assert!(
            a.realloc(
                Some(s),
                0,
                SegmentFlags::PageAligned,
                MsegOptions {
                    cache: false,
                    ..Default::default()
                }
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(a.info().status.segments_current, 0);
    }
    #[test]
    fn powered_cache_reuses_aligned_segment() {
        let mut a = MsegAllocator::new(0, CacheConfig::default());
        let s = a.alloc(1, SegmentFlags::PowerOfTwo).unwrap();
        assert_eq!((s.as_ptr() as usize) % (1 << 24), 0);
        a.dealloc(s, MsegOptions::default());
        let s = a.alloc(1, SegmentFlags::PowerOfTwo).unwrap();
        assert_eq!(a.info().status.cache_hits, 1);
        a.dealloc(
            s,
            MsegOptions {
                cache: false,
                ..Default::default()
            },
        );
    }
    #[test]
    fn realloc_respects_preserve_and_shrink_thresholds() {
        let mut a = MsegAllocator::new(0, CacheConfig::default());
        let page = page_size();
        let s = a.alloc(4 * page, SegmentFlags::PageAligned).unwrap();
        let s = a
            .realloc(
                Some(s),
                2 * page,
                SegmentFlags::PageAligned,
                MsegOptions {
                    absolute_shrink_threshold: 4 * page,
                    relative_shrink_threshold: 100,
                    ..Default::default()
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(s.len(), 4 * page);
        let s = a
            .realloc(
                Some(s),
                8 * page,
                SegmentFlags::PageAligned,
                MsegOptions {
                    preserve: false,
                    ..Default::default()
                },
            )
            .unwrap()
            .unwrap();
        assert_eq!(s.len(), 8 * page);
        let info = a.info();
        assert_eq!(info.calls.alloc.count, 1);
        assert_eq!(info.calls.dealloc.count, 0);
        assert_eq!(info.calls.realloc.count, 2);
        a.dealloc(
            s,
            MsegOptions {
                cache: false,
                ..Default::default()
            },
        );
    }
    proptest! {
        #[test] fn cache_policy_matches_fifo_model(sizes in prop::collection::vec(1u16..32, 1..80)) {
            let mut a = MsegAllocator::new(0, CacheConfig { max_cache_size: 4, ..Default::default() });
            let segments = sizes.iter().map(|size| a.alloc(*size as usize * page_size(), SegmentFlags::PageAligned).unwrap()).collect::<Vec<_>>();
            let mut model_count = 0usize;
            for segment in segments {
                a.dealloc(segment, MsegOptions::default());
                model_count = (model_count + 1).min(4);
                prop_assert_eq!(a.info().status.cached_segments, model_count);
            }
            a.clear_cache();
        }
    }
}
