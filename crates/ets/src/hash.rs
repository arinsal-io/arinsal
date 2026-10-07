//! ETS hash storage with OTP's segmented linear-hash directory.

use crate::{EtsError, StoredTerm, TableType, WriteConcurrency};
use arinsal_term::{HeapAlloc, Term, global_atoms, internal_hash};
use parking_lot::RwLock as FastRwLock;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

const FIRST_SEGMENT: usize = 256;
const EXT_SEGMENT: usize = 2048;

/// Port of erts/emulator/beam/erl_term_hashing.c:1770 (make_internal_hash), OTP-29.1.1.
/// The scalar path avoids constructing the term-walk stack for immediate integers.
#[inline]
pub(super) fn ets_hash(term: Term) -> u64 {
    if let Some(atom) = term.as_atom() {
        // Port of erl_db_hash.c:280 (MAKE_HASH atom fast path), OTP-29.1.1.
        return global_atoms().hash(atom).unwrap() as u64;
    }
    if term.as_small().is_some() {
        // Port of crates/term/src/internal_hash.rs:74-75 fast path, OTP-29.1.1.
        return mix64(term.tagged_word());
    }
    internal_hash(term)
}

#[inline]
fn mix64(mut hash: u64) -> u64 {
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xff51_afd7_ed55_8ccd);
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    hash ^ (hash >> 33)
}

/// Port of `HashDbTerm` in erl_db_hash.h:41-49, OTP-29.1.1.
pub(super) struct HashDbTerm {
    next: Option<Box<HashDbTerm>>,
    hvalue: u64,
    pseudo_deleted: bool,
    pub(super) object: StoredTerm,
}

impl Deref for HashDbTerm {
    type Target = StoredTerm;

    fn deref(&self) -> &Self::Target {
        &self.object
    }
}

/// Port of the bucket head in `struct segment` in erl_db_hash.c:605-609.
#[derive(Default)]
pub(super) struct HashBucket {
    head: Option<Box<HashDbTerm>>,
}

// The first OTP segment is intentionally smaller than every later segment.
#[expect(
    clippy::large_enum_variant,
    reason = "ports OTP's distinct segment bucket capacities"
)]
enum Segment {
    First([HashBucket; FIRST_SEGMENT]),
    Extended([HashBucket; EXT_SEGMENT]),
}

impl Segment {
    fn first() -> Self {
        Self::First(std::array::from_fn(|_| HashBucket::default()))
    }

    fn extended() -> Self {
        Self::Extended(std::array::from_fn(|_| HashBucket::default()))
    }

    fn get(&self, index: usize) -> &HashBucket {
        match self {
            Self::First(buckets) => &buckets[index],
            Self::Extended(buckets) => &buckets[index],
        }
    }

    fn get_mut(&mut self, index: usize) -> &mut HashBucket {
        match self {
            Self::First(buckets) => &mut buckets[index],
            Self::Extended(buckets) => &mut buckets[index],
        }
    }

    fn iter(&self) -> std::slice::Iter<'_, HashBucket> {
        match self {
            Self::First(buckets) => buckets.as_slice().iter(),
            Self::Extended(buckets) => buckets.as_slice().iter(),
        }
    }

    fn iter_mut(&mut self) -> std::slice::IterMut<'_, HashBucket> {
        match self {
            Self::First(buckets) => buckets.as_mut_slice().iter_mut(),
            Self::Extended(buckets) => buckets.as_mut_slice().iter_mut(),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct HashIter<'a> {
    next: Option<&'a HashDbTerm>,
}

impl<'a> HashIter<'a> {
    pub(super) fn iter(self) -> Self {
        self
    }
}

impl<'a> Iterator for HashIter<'a> {
    type Item = &'a HashDbTerm;
    fn next(&mut self) -> Option<Self::Item> {
        let node = self.next?;
        self.next = node.next.as_deref();
        (!node.pseudo_deleted).then_some(node)
    }
}

struct HashIterMut<'a> {
    next: Option<&'a mut HashDbTerm>,
}

impl<'a> Iterator for HashIterMut<'a> {
    type Item = &'a mut StoredTerm;

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.next.take()?;
        self.next = node.next.as_deref_mut();
        Some(&mut node.object)
    }
}

/// Port of erts/emulator/beam/erl_db_hash.c:164-170, OTP-29.1.1.
pub(super) struct HashStorage {
    // OTP stores segment pointers in the segment table, so segment allocation remains stable.
    segments: Vec<Box<Segment>>,
    pub(super) next_order: u64,
    pub(super) size: usize,
    pub(super) size_bias: isize,
    pub(super) nactive: usize,
    pub(super) deleted: Vec<StoredTerm>,
    szm: usize,
    pub(super) nslots: usize,
    lock_slots: RwLock<Vec<Arc<RwLock<()>>>>,
    auto_lock_count: AtomicUsize,
    auto_adapt: bool,
}

impl HashStorage {
    /// Port of erts/emulator/beam/erl_db_hash.c:1007-1018, OTP-29.1.1.
    pub(super) fn new(write_concurrency: WriteConcurrency) -> Self {
        let locks = match write_concurrency {
            WriteConcurrency::Disabled => 1,
            WriteConcurrency::Enabled => 64,
            WriteConcurrency::Auto => 64,
            WriteConcurrency::Fixed(count) => count,
        };
        Self {
            segments: vec![Box::new(Segment::first())],
            next_order: 0,
            size: 0,
            size_bias: 0,
            nactive: FIRST_SEGMENT,
            deleted: Vec::new(),
            szm: FIRST_SEGMENT - 1,
            nslots: FIRST_SEGMENT,
            lock_slots: RwLock::new((0..locks).map(|_| Arc::new(RwLock::new(()))).collect()),
            auto_lock_count: AtomicUsize::new(locks),
            auto_adapt: write_concurrency == WriteConcurrency::Auto,
        }
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:207-217, OTP-29.1.1.
    #[inline]
    pub(super) fn slot_index(&self, hval: u64) -> usize {
        let index = hval as usize & self.szm;
        if index >= self.nactive {
            index & (self.szm >> 1)
        } else {
            index
        }
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:280, OTP-29.1.1.
    #[inline]
    fn make_hash(term: Term) -> u64 {
        ets_hash(term) >> 1
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:280-281, OTP-29.1.1.
    #[inline]
    fn hash_to_lock(&self, hval: u64) -> usize {
        hval as usize & (self.auto_lock_count.load(Ordering::Relaxed) - 1)
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:1041-1067, OTP-29.1.1.
    pub(super) fn lock_count(&self) -> usize {
        self.auto_lock_count.load(Ordering::Relaxed)
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:1041-1067, OTP-29.1.1.
    pub(super) fn note_contention(&self, contended: bool) {
        if contended
            && self.auto_adapt
            && let Ok(old) =
                self.auto_lock_count
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                        (n < 8192).then_some(n * 2)
                    })
        {
            let mut slots = self.lock_slots.write().unwrap();
            let old_len = slots.len();
            slots.extend((old_len..old * 2).map(|_| Arc::new(RwLock::new(()))));
        }
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:1526-1528, OTP-29.1.1.
    pub(super) fn lock_for_hash(&self, hval: u64) -> Option<Arc<RwLock<()>>> {
        (self.lock_count() > 1)
            .then(|| Arc::clone(&self.lock_slots.read().unwrap()[self.hash_to_lock(hval)]))
    }

    #[inline]
    fn segment_bucket(&self, slot: usize) -> &HashBucket {
        if slot < FIRST_SEGMENT {
            self.segments[0].get(slot)
        } else {
            self.segments[1 + (slot - FIRST_SEGMENT) / EXT_SEGMENT]
                .get((slot - FIRST_SEGMENT) % EXT_SEGMENT)
        }
    }

    #[inline]
    fn segment_bucket_mut(&mut self, slot: usize) -> &mut HashBucket {
        if slot < FIRST_SEGMENT {
            self.segments[0].get_mut(slot)
        } else {
            self.segments[1 + (slot - FIRST_SEGMENT) / EXT_SEGMENT]
                .get_mut((slot - FIRST_SEGMENT) % EXT_SEGMENT)
        }
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:1107-1110,1155-1157, OTP-29.1.1.
    pub(super) fn objects(&self, key: Term) -> HashIter<'_> {
        self.objects_hash(ets_hash(key))
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:1155-1157, OTP-29.1.1.
    #[inline]
    pub(super) fn objects_hash(&self, hval: u64) -> HashIter<'_> {
        let bucket = self.segment_bucket(self.slot_index(hval >> 1));
        HashIter {
            next: bucket.head.as_deref(),
        }
    }

    /// The live object at `key` in a set table, for an update in place.
    ///
    /// Port of erts/emulator/beam/erl_db_hash.c:3872 (db_lookup_dbterm_hash), OTP-29.1.1.
    pub(super) fn find_mut(&mut self, key: Term, keypos: usize) -> Option<&mut StoredTerm> {
        let hval = ets_hash(key);
        let slot = self.slot_index(hval >> 1);
        let mut next = self.segment_bucket_mut(slot).head.as_deref_mut();
        while let Some(node) = next {
            if !node.pseudo_deleted
                && node.hvalue == hval >> 1
                && arinsal_term::exact_eq(node.object.key(keypos), key)
            {
                return Some(&mut node.object);
            }
            next = node.next.as_deref_mut();
        }
        None
    }

    /// Return the first live key in OTP's bucket order.
    ///
    /// Port of erts/emulator/beam/erl_db_hash.c:4173-4194, OTP-29.1.1.
    pub(super) fn raw_first(&self, keypos: usize) -> Option<Term> {
        (0..self.nactive).find_map(|slot| {
            HashIter {
                next: self.segment_bucket(slot).head.as_deref(),
            }
            .next()
            .map(|object| object.key(keypos))
        })
    }

    /// Return a key's raw successor, preserving the hash directory walk order.
    ///
    /// Port of erts/emulator/beam/erl_db_hash.c:4196-4231, OTP-29.1.1.
    pub(super) fn raw_next(&self, key: Term, keypos: usize) -> Result<Option<Term>, EtsError> {
        let hash = ets_hash(key) >> 1;
        let slot = self.slot_index(hash);
        let mut found = false;
        for node in (HashIter {
            next: self.segment_bucket(slot).head.as_deref(),
        }) {
            if !found {
                if node.hvalue == hash && exact_key(node.object.key(keypos), key) {
                    found = true;
                }
                continue;
            }
            if node.hvalue != hash || !exact_key(node.object.key(keypos), key) {
                return Ok(Some(node.object.key(keypos)));
            }
        }
        if !found {
            return Err(EtsError::BadArg);
        }
        for slot in slot + 1..self.nactive {
            if let Some(node) = (HashIter {
                next: self.segment_bucket(slot).head.as_deref(),
            })
            .next()
            {
                return Ok(Some(node.object.key(keypos)));
            }
        }
        Ok(None)
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:3883-3885, OTP-29.1.1.
    pub(super) fn find_object_mut_at(
        &mut self,
        slot: usize,
        predicate: &mut impl FnMut(&StoredTerm) -> bool,
    ) -> Option<&mut StoredTerm> {
        let mut node = self.segment_bucket_mut(slot).head.as_deref_mut();
        while let Some(current) = node {
            if predicate(&current.object) {
                return Some(&mut current.object);
            }
            node = current.next.as_deref_mut();
        }
        None
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:1363-1440, OTP-29.1.1.
    pub(super) fn push_at(&mut self, slot: usize, object: StoredTerm) {
        let hvalue = object.hvalue;
        let bucket = self.segment_bucket_mut(slot);
        let mut node = Box::new(HashDbTerm {
            next: bucket.head.take(),
            hvalue,
            pseudo_deleted: false,
            object,
        });
        node.object.hvalue = hvalue;
        bucket.head = Some(node);
    }

    pub(super) fn take_all_buckets(&mut self) -> Vec<StoredTerm> {
        let mut objects = Vec::with_capacity(self.size);
        for segment in &mut self.segments {
            for bucket in segment.iter_mut() {
                let mut node = bucket.head.take();
                while let Some(mut current) = node {
                    node = current.next.take();
                    objects.push(current.object);
                }
            }
        }
        objects
    }

    /// Free every object and return to the initial single-segment layout.
    // Port of erts/emulator/beam/erl_db_hash.c:4017 (db_delete_all_objects_hash:
    // db_free_table_continue_hash + db_create_hash), OTP-29.1.1.
    pub(super) fn clear_buckets(&mut self) {
        self.segments.clear();
        self.segments.push(Box::new(Segment::first()));
        self.nactive = FIRST_SEGMENT;
        self.szm = FIRST_SEGMENT - 1;
        self.nslots = FIRST_SEGMENT;
    }

    /// Detach all buckets (and, for a table being deleted, the pseudo-deleted list) so they can
    /// be released a few segments at a time, leaving the initial single-segment layout.
    // Port of erts/emulator/beam/erl_db_hash.c:3122 (db_free_table_continue_hash), OTP-29.1.1.
    pub(super) fn take_garbage(&mut self, with_deleted: bool) -> HashGarbage {
        let segments = std::mem::take(&mut self.segments);
        self.clear_buckets();
        HashGarbage {
            segments,
            deleted: if with_deleted {
                std::mem::take(&mut self.deleted)
            } else {
                Vec::new()
            },
        }
    }

    pub(super) fn values(&self) -> impl Iterator<Item = &StoredTerm> {
        self.segments
            .iter()
            .flat_map(|segment| segment.iter())
            .flat_map(|bucket| HashIter {
                next: bucket.head.as_deref(),
            })
            .map(|node| &node.object)
    }

    pub(super) fn key_count(&self, keypos: usize) -> usize {
        let mut count = 0;
        for slot in 0..self.nactive {
            let mut keys = Vec::new();
            let mut iter = HashIter {
                next: self.segment_bucket(slot).head.as_deref(),
            };
            for object in &mut iter {
                let key = object.key(keypos);
                if !keys.iter().any(|&old| arinsal_term::exact_eq(old, key)) {
                    keys.push(key);
                    count += 1;
                }
            }
        }
        count
    }

    /// Replace live objects in place, keeping their bucket position and insertion order.
    pub(super) fn replace_each(
        &mut self,
        mut replace: impl FnMut(&StoredTerm) -> Result<Option<StoredTerm>, EtsError>,
    ) -> Result<usize, EtsError> {
        let mut count = 0;
        for object in self.values_mut() {
            if let Some(mut replacement) = replace(object)? {
                replacement.order = object.order;
                replacement.group_order = object.group_order;
                replacement.hvalue = object.hvalue;
                *object = replacement;
                count += 1;
            }
        }
        Ok(count)
    }

    fn values_mut(&mut self) -> impl Iterator<Item = &mut StoredTerm> {
        self.segments
            .iter_mut()
            .flat_map(|segment| segment.iter_mut())
            .flat_map(|bucket| HashIterMut {
                next: bucket.head.as_deref_mut(),
            })
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:3973-3984, OTP-29.1.1.
    pub(super) fn detach_matching(
        &mut self,
        hval: u64,
        mut predicate: impl FnMut(&StoredTerm) -> bool,
    ) -> Vec<StoredTerm> {
        let slot = self.slot_index(hval);
        let mut link = &mut self.segment_bucket_mut(slot).head;
        let mut removed = Vec::new();
        while let Some(mut node) = link.take() {
            if predicate(&node.object) {
                *link = node.next.take();
                removed.push(node.object);
            } else {
                *link = Some(node);
                link = &mut link.as_mut().unwrap().next;
            }
        }
        removed
    }

    /// Unlink every live object for which `predicate` holds while walking the buckets once.
    ///
    /// Port of erts/emulator/beam/erl_db_hash.c:2723 (db_select_delete_hash), OTP-29.1.1:
    /// erts frees matching objects during the traversal and shrinks the table afterwards.
    pub(super) fn delete_where<E>(
        &mut self,
        mut predicate: impl FnMut(&StoredTerm) -> Result<bool, E>,
    ) -> Result<usize, E> {
        let mut removed = 0;
        let mut failure = None;
        'slots: for slot in 0..self.nactive {
            let mut link = &mut self.segment_bucket_mut(slot).head;
            while let Some(mut node) = link.take() {
                let selected = if node.pseudo_deleted {
                    Ok(false)
                } else {
                    predicate(&node.object)
                };
                match selected {
                    Ok(true) => {
                        *link = node.next.take();
                        removed += 1;
                    }
                    Ok(false) => {
                        *link = Some(node);
                        link = &mut link.as_mut().unwrap().next;
                    }
                    Err(error) => {
                        *link = Some(node);
                        failure = Some(error);
                        break 'slots;
                    }
                }
            }
        }
        self.size -= removed;
        match failure {
            Some(error) => Err(error),
            None => Ok(removed),
        }
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:3973-3984, OTP-29.1.1.
    pub(super) fn retain_fixed_delete(&mut self, object: StoredTerm) {
        self.deleted.push(object);
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:1745-1750, OTP-29.1.1.
    pub(super) fn active_slots(&self) -> usize {
        self.nactive
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:1624-1626, OTP-29.1.1.
    pub(super) fn is_valid_slot(&self, slot: usize) -> bool {
        slot <= self.nactive
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:3883-3885, OTP-29.1.1.
    pub(super) fn slot_for_key(&self, key: Term) -> usize {
        self.slot_index(Self::make_hash(key))
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:1990-2010, OTP-29.1.1.
    pub(super) fn ordered(&self, keypos: usize) -> Vec<&StoredTerm> {
        // Buckets already are in slot order, so only each short chain needs sorting.
        let _ = keypos;
        let mut objects: Vec<&StoredTerm> = Vec::new();
        for slot in 0..self.nactive {
            let start = objects.len();
            objects.extend(
                HashIter {
                    next: self.segment_bucket(slot).head.as_deref(),
                }
                .map(|node| &node.object),
            );
            if objects.len() - start > 1 {
                objects[start..]
                    .sort_unstable_by_key(|object| (object.group_order, u64::MAX - object.order));
            }
        }
        objects
    }

    /// Objects of one slot in traversal order, optionally with fixed-table pseudo-deleted ones.
    ///
    /// Port of erts/emulator/beam/erl_db_hash.c:4196-4231 (db_next_hash), OTP-29.1.1: a
    /// traversal step only walks the key's own bucket and the following buckets, never the
    /// whole table.
    pub(super) fn slot_ordered(&self, slot: usize, with_deleted: bool) -> Vec<&StoredTerm> {
        let mut objects: Vec<&StoredTerm> = HashIter {
            next: self.segment_bucket(slot).head.as_deref(),
        }
        .map(|node| &node.object)
        .collect();
        if with_deleted {
            objects.extend(
                self.deleted
                    .iter()
                    .filter(|object| self.slot_index(object.hvalue) == slot),
            );
        }
        objects.sort_unstable_by_key(|object| (object.group_order, u64::MAX - object.order));
        objects
    }

    /// First live object of the first non-empty slot at or after `slot`, in traversal order.
    pub(super) fn first_from_slot(&self, slot: usize) -> Option<&StoredTerm> {
        (slot..self.nactive).find_map(|slot| {
            HashIter {
                next: self.segment_bucket(slot).head.as_deref(),
            }
            .map(|node| &node.object)
            .min_by_key(|object| (object.group_order, u64::MAX - object.order))
        })
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:3411-3444, OTP-29.1.1.
    fn ensure_slot(&mut self) {
        if self.nactive == self.nslots {
            self.segments.push(Box::new(Segment::extended()));
            self.nslots += EXT_SEGMENT;
        }
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:3648-3731 (grow), OTP-29.1.1.
    #[inline]
    pub(super) fn maybe_grow(&mut self, fixed: bool, _keypos: usize) {
        if fixed || self.size <= self.nactive {
            return;
        }
        self.ensure_slot();
        let old_active = self.nactive;
        let old_mask = self.szm;
        let source = if old_active <= old_mask {
            old_active & (old_mask >> 1)
        } else {
            self.szm = (old_mask << 1) | 1;
            0
        };
        let new_slot = old_active;
        self.nactive += 1;
        let mask = self.szm;
        let mut current = self.segment_bucket_mut(source).head.take();
        if current.is_none() {
            return;
        }
        let mut keep_head = None;
        let mut moved_head = None;
        let mut keep_tail = &mut keep_head;
        let mut moved_tail = &mut moved_head;
        while let Some(mut node) = current {
            current = node.next.take();
            if node.hvalue as usize & mask == new_slot {
                *moved_tail = Some(node);
                moved_tail = &mut moved_tail.as_mut().unwrap().next;
            } else {
                *keep_tail = Some(node);
                keep_tail = &mut keep_tail.as_mut().unwrap().next;
            }
        }
        self.segment_bucket_mut(source).head = keep_head;
        self.segment_bucket_mut(new_slot).head = moved_head;
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:3350-3398, OTP-29.1.1.
    fn shrink_limit(&self) -> usize {
        if self.nslots < 4352 {
            0
        } else {
            (self.nslots - EXT_SEGMENT) / 2
        }
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:3743-3800 (shrink), OTP-29.1.1.
    fn shrink(&mut self) {
        if self.nactive <= FIRST_SEGMENT {
            return;
        }
        let source = self.nactive - 1;
        let mask = self.szm >> 1;
        let destination = source & mask;
        self.nactive = source;
        if destination == 0 {
            self.szm = mask;
        }
        let mut source_head = self.segment_bucket_mut(source).head.take();
        if let Some(mut head) = source_head.take() {
            let mut tail = &mut head;
            while tail.next.is_some() {
                tail = tail.next.as_mut().unwrap();
            }
            tail.next = self.segment_bucket_mut(destination).head.take();
            self.segment_bucket_mut(destination).head = Some(head);
        }
        if self.nslots - source >= EXT_SEGMENT {
            self.nslots -= EXT_SEGMENT;
            self.segments.pop();
        }
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:757-760, OTP-29.1.1.
    pub(super) fn shrink_after_delete(&mut self, _keypos: usize) {
        for _ in 0..5 {
            if self.size >= self.shrink_limit() || self.nactive <= FIRST_SEGMENT {
                break;
            }
            let source = self.nactive - 1;
            let destination = source & (self.szm >> 1);
            let mut ranks = HashMap::new();
            let mut rank = 0_u64;
            for slot in [source, destination] {
                let mut ordered = self
                    .values()
                    .filter(|object| self.slot_index(object.hvalue) == slot)
                    .collect::<Vec<_>>();
                ordered
                    .sort_unstable_by_key(|object| (object.group_order, u64::MAX - object.order));
                let mut last_group = None;
                for object in ordered {
                    if last_group != Some(object.group_order) {
                        rank += 1;
                        last_group = Some(object.group_order);
                    }
                    ranks.insert(object.order, rank);
                }
            }
            for object in self.values_mut() {
                if let Some(&rank) = ranks.get(&object.order) {
                    object.group_order = rank;
                }
            }
            self.shrink();
        }
    }
}

const LOCK_COUNT: usize = 64;
const AUTO_MIN_LOCK_COUNT: usize = 64;
const AUTO_MAX_LOCK_COUNT: usize = 8192;
const AUTO_GROW_STAT: isize = 1000;
const AUTO_SHRINK_STAT: isize = -10_000_000;

#[repr(align(64))]
struct ConcurrentLockSlot {
    buckets: FastRwLock<SlotBuckets>,
    nitems: AtomicUsize,
    lock_stat: AtomicIsize,
}

struct SlotBuckets {
    segments: Vec<Box<[HashBucket]>>,
    lock_count: usize,
}

enum ConcurrentLocks {
    Fixed(Box<[ConcurrentLockSlot]>),
    Adaptive(FastRwLock<Box<[ConcurrentLockSlot]>>),
}

enum ConcurrentLocksRead<'a> {
    Fixed(&'a [ConcurrentLockSlot]),
    Adaptive(parking_lot::RwLockReadGuard<'a, Box<[ConcurrentLockSlot]>>),
}

impl std::ops::Deref for ConcurrentLocksRead<'_> {
    type Target = [ConcurrentLockSlot];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Fixed(locks) => locks,
            Self::Adaptive(locks) => locks,
        }
    }
}

impl ConcurrentLocks {
    fn read(&self) -> ConcurrentLocksRead<'_> {
        match self {
            Self::Fixed(locks) => ConcurrentLocksRead::Fixed(locks),
            Self::Adaptive(locks) => ConcurrentLocksRead::Adaptive(locks.read()),
        }
    }

    fn adaptive(&self) -> Option<&FastRwLock<Box<[ConcurrentLockSlot]>>> {
        match self {
            Self::Fixed(_) => None,
            Self::Adaptive(locks) => Some(locks),
        }
    }
}

impl SlotBuckets {
    fn new(lock_count: usize) -> Self {
        Self {
            segments: vec![
                std::iter::repeat_with(HashBucket::default)
                    .take(FIRST_SEGMENT.div_ceil(lock_count))
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            ],
            lock_count,
        }
    }

    fn ensure_global_slot(&mut self, global_slot: usize) {
        if global_slot < FIRST_SEGMENT {
            return;
        }
        let segment_ix = 1 + (global_slot - FIRST_SEGMENT) / EXT_SEGMENT;
        while self.segments.len() <= segment_ix {
            self.segments.push(
                std::iter::repeat_with(HashBucket::default)
                    .take(EXT_SEGMENT.div_ceil(self.lock_count))
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            );
        }
    }

    fn bucket(&self, global_slot: usize) -> &HashBucket {
        if global_slot < FIRST_SEGMENT {
            &self.segments[0][global_slot / self.lock_count]
        } else {
            let offset = global_slot - FIRST_SEGMENT;
            &self.segments[1 + offset / EXT_SEGMENT][(offset % EXT_SEGMENT) / self.lock_count]
        }
    }

    fn bucket_mut(&mut self, global_slot: usize) -> &mut HashBucket {
        if global_slot < FIRST_SEGMENT {
            &mut self.segments[0][global_slot / self.lock_count]
        } else {
            let offset = global_slot - FIRST_SEGMENT;
            &mut self.segments[1 + offset / EXT_SEGMENT][(offset % EXT_SEGMENT) / self.lock_count]
        }
    }
}

/// Lock-owned bucket partitions for concurrent set, bag, and duplicate_bag tables.
pub(super) struct ConcurrentHashStorage {
    locks: ConcurrentLocks,
    resize: FastRwLock<()>,
    growth_active: AtomicBool,
    nactive: AtomicUsize,
    auto_adapt: bool,
    resize_state: AtomicUsize,
}

impl ConcurrentHashStorage {
    pub(super) fn new(write_concurrency: WriteConcurrency) -> Self {
        let lock_count = match write_concurrency {
            WriteConcurrency::Disabled => 1,
            WriteConcurrency::Enabled => LOCK_COUNT,
            WriteConcurrency::Auto => AUTO_MIN_LOCK_COUNT,
            WriteConcurrency::Fixed(count) => count,
        };
        Self {
            locks: if write_concurrency == WriteConcurrency::Auto {
                ConcurrentLocks::Adaptive(FastRwLock::new(Self::new_lock_array(lock_count)))
            } else {
                ConcurrentLocks::Fixed(Self::new_lock_array(lock_count))
            },
            resize: FastRwLock::new(()),
            growth_active: AtomicBool::new(false),
            nactive: AtomicUsize::new(FIRST_SEGMENT),
            auto_adapt: write_concurrency == WriteConcurrency::Auto,
            resize_state: AtomicUsize::new(0),
        }
    }

    fn new_lock_array(lock_count: usize) -> Box<[ConcurrentLockSlot]> {
        (0..lock_count)
            .map(|_| ConcurrentLockSlot {
                buckets: FastRwLock::new(SlotBuckets::new(lock_count)),
                nitems: AtomicUsize::new(0),
                lock_stat: AtomicIsize::new(0),
            })
            .collect()
    }

    #[inline]
    fn bucket_index(&self, hvalue: u64) -> usize {
        let active = self.nactive.load(Ordering::Acquire);
        let mask = active.next_power_of_two() - 1;
        let index = hvalue as usize & mask;
        if index >= active {
            index & (mask >> 1)
        } else {
            index
        }
    }

    #[inline]
    fn lock_index(index: usize, lock_count: usize) -> usize {
        index & (lock_count - 1)
    }

    pub(super) fn insert(
        &self,
        mut object: StoredTerm,
        hash: u64,
        table_type: TableType,
        keypos: usize,
    ) {
        self.adapt_lock_array();
        let _resize = self.auto_adapt.then(|| self.resize.read());
        let locks = self.locks.read();
        let lock_count = locks.len();
        let hvalue = hash >> 1;
        let (index, lock_ix, mut slot) = loop {
            let index = self.bucket_index(hvalue);
            let lock_ix = Self::lock_index(index, lock_count);
            let slot = match locks[lock_ix].buckets.try_write() {
                Some(slot) => {
                    self.note_uncontended(&locks, lock_ix, index);
                    slot
                }
                None => {
                    self.note_contended(&locks, lock_ix, index);
                    locks[lock_ix].buckets.write()
                }
            };
            if self.bucket_index(hvalue) == index {
                break (index, lock_ix, slot);
            }
            drop(slot);
        };
        let bucket = slot.bucket_mut(index);
        let key = object.key(keypos);
        object.hvalue = hvalue;
        let mut cursor = &mut bucket.head;
        while let Some(node) = cursor {
            if node.hvalue == hvalue && exact_key(node.object.key(keypos), key) {
                match table_type {
                    TableType::Set => {
                        object.order = node.object.order;
                        object.group_order = node.object.group_order;
                        node.object = object;
                        return;
                    }
                    TableType::Bag if node.object.exact_eq_stored(&object) => return,
                    TableType::Bag => {}
                    TableType::DuplicateBag => {}
                    TableType::OrderedSet => unreachable!(),
                }
            }
            cursor = &mut cursor.as_mut().unwrap().next;
        }
        let item = Box::new(HashDbTerm {
            next: bucket.head.take(),
            hvalue,
            pseudo_deleted: false,
            object,
        });
        bucket.head = Some(item);
        locks[lock_ix].nitems.fetch_add(1, Ordering::Relaxed);
        let local_items = locks[lock_ix].nitems.load(Ordering::Relaxed);
        drop(slot);
        drop(locks);
        drop(_resize);
        if local_items > self.nactive.load(Ordering::Acquire).div_ceil(lock_count) {
            self.grow_one(lock_ix, lock_count);
        }
    }

    fn adapt_lock_array(&self) {
        if !self.auto_adapt || self.resize_state.load(Ordering::Relaxed) == 0 {
            return;
        }
        let _resize = self.resize.write();
        let mut locks = self.locks.adaptive().unwrap().write();
        let old_count = locks.len();
        let state = self.resize_state.swap(0, Ordering::Relaxed);
        let active = self.nactive.load(Ordering::Acquire);
        let new_count = match state {
            1 if old_count < AUTO_MAX_LOCK_COUNT && active >= 2 * old_count => old_count * 2,
            2 if old_count > AUTO_MIN_LOCK_COUNT => old_count / 2,
            _ => {
                for slot in locks.iter() {
                    slot.lock_stat.store(0, Ordering::Relaxed);
                }
                return;
            }
        };
        let mut heads = Vec::with_capacity(self.nactive.load(Ordering::Acquire));
        for bucket_ix in 0..self.nactive.load(Ordering::Acquire) {
            let old_lock = Self::lock_index(bucket_ix, old_count);
            let head = locks[old_lock]
                .buckets
                .write()
                .bucket_mut(bucket_ix)
                .head
                .take();
            heads.push((bucket_ix, head));
        }
        let mut replacement = Self::new_lock_array(new_count);
        for (bucket_ix, mut head) in heads {
            let new_lock = Self::lock_index(bucket_ix, new_count);
            let mut count = 0;
            let mut node = head.as_deref();
            while let Some(current) = node {
                count += 1;
                node = current.next.as_deref();
            }
            replacement[new_lock]
                .buckets
                .get_mut()
                .bucket_mut(bucket_ix)
                .head = head.take();
            replacement[new_lock]
                .nitems
                .fetch_add(count, Ordering::Relaxed);
        }
        *locks = replacement;
    }

    fn note_contended(&self, locks: &[ConcurrentLockSlot], lock_ix: usize, bucket_ix: usize) {
        if !self.auto_adapt {
            return;
        }
        let stat = locks[lock_ix].lock_stat.fetch_add(100, Ordering::Relaxed) + 100;
        if stat > AUTO_GROW_STAT
            && locks.len() < AUTO_MAX_LOCK_COUNT
            && self.nactive.load(Ordering::Acquire) >= 2 * locks.len()
        {
            self.resize_state.store(1, Ordering::Relaxed);
        }
        let _ = bucket_ix;
    }

    fn note_uncontended(&self, locks: &[ConcurrentLockSlot], lock_ix: usize, _bucket_ix: usize) {
        if !self.auto_adapt {
            return;
        }
        let stat = locks[lock_ix].lock_stat.fetch_sub(1, Ordering::Relaxed) - 1;
        if stat < AUTO_SHRINK_STAT && locks.len() > AUTO_MIN_LOCK_COUNT {
            self.resize_state.store(2, Ordering::Relaxed);
        }
    }

    fn grow_one(&self, lock_ix: usize, lock_count: usize) {
        if self
            .growth_active
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let _resize = self.auto_adapt.then(|| self.resize.read());
        let old_active = self.nactive.load(Ordering::Acquire);
        let locks = self.locks.read();
        let local_items = locks[lock_ix].nitems.load(Ordering::Relaxed);
        if local_items <= old_active.div_ceil(lock_count) {
            self.growth_active.store(false, Ordering::Release);
            return;
        }
        let split_mask = if old_active.is_power_of_two() {
            (old_active << 1) - 1
        } else {
            old_active.next_power_of_two() - 1
        };
        let source = if old_active.is_power_of_two() {
            0
        } else {
            old_active & (split_mask >> 1)
        };
        let destination = old_active;
        let source_lock = Self::lock_index(source, lock_count);
        let destination_lock = Self::lock_index(destination, lock_count);
        if source_lock == destination_lock {
            let mut buckets = locks[source_lock].buckets.write();
            buckets.ensure_global_slot(destination);
            let mut current = buckets.bucket_mut(source).head.take();
            let (mut keep, mut moved) = (None, None);
            let (mut keep_tail, mut moved_tail) = (&mut keep, &mut moved);
            while let Some(mut node) = current {
                current = node.next.take();
                if node.hvalue as usize & split_mask == destination {
                    *moved_tail = Some(node);
                    moved_tail = &mut moved_tail.as_mut().unwrap().next;
                } else {
                    *keep_tail = Some(node);
                    keep_tail = &mut keep_tail.as_mut().unwrap().next;
                }
            }
            buckets.bucket_mut(source).head = keep;
            buckets.bucket_mut(destination).head = moved;
            self.nactive.store(old_active + 1, Ordering::Release);
        } else {
            // The low-bit lock mapping only diverges before the lock-count boundary.
            let mut source_guard = locks[source_lock].buckets.write();
            let mut destination_guard = locks[destination_lock].buckets.write();
            destination_guard.ensure_global_slot(destination);
            let mut current = source_guard.bucket_mut(source).head.take();
            while let Some(mut node) = current {
                current = node.next.take();
                if node.hvalue as usize & split_mask == destination {
                    let target = destination_guard.bucket_mut(destination);
                    node.next = target.head.take();
                    target.head = Some(node);
                } else {
                    let target = source_guard.bucket_mut(source);
                    node.next = target.head.take();
                    target.head = Some(node);
                }
            }
            self.nactive.store(old_active + 1, Ordering::Release);
        }
        drop(locks);
        self.growth_active.store(false, Ordering::Release);
    }

    pub(super) fn lookup<H: HeapAlloc>(
        &self,
        key: Term,
        hash: u64,
        keypos: usize,
        dst: &mut H,
    ) -> Result<Vec<Term>, EtsError> {
        let _resize = self.auto_adapt.then(|| self.resize.read());
        let locks = self.locks.read();
        let (index, guard) = loop {
            let index = self.bucket_index(hash >> 1);
            let guard = locks[Self::lock_index(index, locks.len())].buckets.read();
            if self.bucket_index(hash >> 1) == index {
                break (index, guard);
            }
            drop(guard);
        };
        let bucket = guard.bucket(index);
        let mut results = Vec::new();
        let mut node = bucket.head.as_deref();
        while let Some(current) = node {
            if current.hvalue == hash >> 1 && exact_key(current.object.key(keypos), key) {
                results.push(current.object.copy_out(dst)?);
            }
            node = current.next.as_deref();
        }
        results.reverse();
        Ok(results)
    }

    pub(super) fn member(&self, key: Term, hash: u64, keypos: usize) -> bool {
        let _resize = self.auto_adapt.then(|| self.resize.read());
        let locks = self.locks.read();
        let (index, guard) = loop {
            let index = self.bucket_index(hash >> 1);
            let guard = locks[Self::lock_index(index, locks.len())].buckets.read();
            if self.bucket_index(hash >> 1) == index {
                break (index, guard);
            }
            drop(guard);
        };
        let mut node = guard.bucket(index).head.as_deref();
        while let Some(current) = node {
            if current.hvalue == hash >> 1 && exact_key(current.object.key(keypos), key) {
                return true;
            }
            node = current.next.as_deref();
        }
        false
    }

    pub(super) fn delete(&self, key: Term, hash: u64, keypos: usize) {
        let _adapt_resize = self.auto_adapt.then(|| self.resize.read());
        let locks = self.locks.read();
        let (index, lock_ix, mut guard) = loop {
            let index = self.bucket_index(hash >> 1);
            let lock_ix = Self::lock_index(index, locks.len());
            let guard = locks[lock_ix].buckets.write();
            if self.bucket_index(hash >> 1) == index {
                break (index, lock_ix, guard);
            }
            drop(guard);
        };
        let mut link = &mut guard.bucket_mut(index).head;
        let mut removed = 0;
        while let Some(mut node) = link.take() {
            if node.hvalue == hash >> 1 && exact_key(node.object.key(keypos), key) {
                *link = node.next.take();
                removed += 1;
            } else {
                *link = Some(node);
                link = &mut link.as_mut().unwrap().next;
            }
        }
        locks[lock_ix].nitems.fetch_sub(removed, Ordering::Relaxed);
    }

    pub(super) fn len(&self) -> usize {
        self.locks
            .read()
            .iter()
            .map(|slot| slot.nitems.load(Ordering::Relaxed))
            .sum()
    }
}

#[inline]
fn exact_key(left: Term, right: Term) -> bool {
    arinsal_term::exact_eq(left, right)
}

/// Bucket storage detached from a table, released incrementally.
pub struct HashGarbage {
    segments: Vec<Box<Segment>>,
    deleted: Vec<StoredTerm>,
}

impl HashGarbage {
    /// Release up to `reds` reductions of work; `keep` receives live objects instead of freeing
    /// them (a fixed table keeps them as pseudo-deleted). Returns whether everything is done.
    ///
    /// Port of erts/emulator/beam/erl_db_hash.c:3122 (db_free_table_continue_hash), OTP-29.1.1.
    pub(super) fn step(
        &mut self,
        reds: &mut isize,
        mut keep: Option<&mut Vec<StoredTerm>>,
    ) -> bool {
        while let Some(object) = self.deleted.pop() {
            drop(object);
            *reds -= 1;
            if *reds < 0 {
                return false;
            }
        }
        while let Some(mut segment) = self.segments.pop() {
            let mut records = 0isize;
            for bucket in segment.iter_mut() {
                let mut node = bucket.head.take();
                while let Some(mut current) = node {
                    node = current.next.take();
                    records += 1;
                    if let Some(keep) = keep.as_deref_mut() {
                        keep.push(current.object);
                    }
                }
            }
            *reds -= (EXT_SEGMENT / 64) as isize + records;
            if *reds < 0 {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod concurrent_tests {
    use super::*;

    #[test]
    fn integer_hashes_cover_lock_slots() {
        let mut occupied = [false; LOCK_COUNT];
        for key in 0..4096_i64 {
            occupied[(ets_hash(Term::small(key).unwrap()) as usize >> 1) & (LOCK_COUNT - 1)] = true;
        }
        assert!(occupied.into_iter().filter(|&slot| slot).count() > 48);
    }
}
