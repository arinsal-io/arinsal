//! ETS hash storage with OTP's segmented linear-hash directory.

use crate::{EtsError, StoredTerm, TableType, WriteConcurrency};
use arinsal_term::{
    FrequentReadGuard, FrequentReadRwLock, FrequentWriteGuard, HeapAlloc, Term, global_atoms,
    internal_hash,
};
use parking_lot::RwLock as FastRwLock;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Mutex;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU64, AtomicUsize, Ordering};

const FIRST_SEGMENT: usize = 256;
const EXT_SEGMENT: usize = 2048;
const NLOCKS_WITH_ITEM_COUNTERS: usize = 64;

/// Port of erts/emulator/beam/erl_term_hashing.c:1770 (make_internal_hash), OTP-29.1.1.
/// The scalar path avoids constructing the term-walk stack for immediate integers.
#[inline]
pub(super) fn ets_hash(term: Term) -> u64 {
    if let Some(atom) = term.as_atom() {
        // Port of erl_db_hash.c:280 (MAKE_HASH atom fast path), OTP-29.1.1.
        return global_atoms().hvalue(atom).unwrap();
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

#[derive(Clone, Copy)]
pub(super) struct HashIter<'a> {
    next: Option<&'a HashDbTerm>,
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

pub(super) struct RemovedHashTerms {
    head: Option<Box<HashDbTerm>>,
}

impl RemovedHashTerms {
    pub(super) fn take_first(&mut self) -> Option<StoredTerm> {
        let mut first = self.head.take()?;
        self.head = first.next.take();
        Some(first.object)
    }
}

impl Drop for RemovedHashTerms {
    fn drop(&mut self) {
        while let Some(mut node) = self.head.take() {
            self.head = node.next.take();
        }
    }
}

struct Stripe {
    buckets: StripeBuckets,
    nitems: AtomicIsize,
}

enum StripeBuckets {
    Plain(Vec<HashBucket>),
    Normal(RwLock<Vec<HashBucket>>),
    FrequentRead(FrequentReadRwLock<Vec<HashBucket>>),
}

enum StripeReadGuard<'a> {
    Plain(&'a Vec<HashBucket>),
    Normal(std::sync::RwLockReadGuard<'a, Vec<HashBucket>>),
    FrequentRead(FrequentReadGuard<'a, Vec<HashBucket>>),
}

impl std::ops::Deref for StripeReadGuard<'_> {
    type Target = Vec<HashBucket>;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Plain(buckets) => buckets,
            Self::Normal(guard) => guard,
            Self::FrequentRead(guard) => guard,
        }
    }
}

enum StripeWriteGuard<'a> {
    Normal(std::sync::RwLockWriteGuard<'a, Vec<HashBucket>>),
    FrequentRead(FrequentWriteGuard<'a, Vec<HashBucket>>),
}

impl std::ops::Deref for StripeWriteGuard<'_> {
    type Target = Vec<HashBucket>;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Normal(guard) => guard,
            Self::FrequentRead(guard) => guard,
        }
    }
}

impl std::ops::DerefMut for StripeWriteGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Normal(guard) => guard,
            Self::FrequentRead(guard) => guard,
        }
    }
}

impl StripeBuckets {
    // Port of erl_db_hash.c:403-416 (RLOCK_HASH is NULL for non-fine tables) and
    // :1035-1041 (DB_FREQ_READ selects frequent-read stripe locks), OTP-29.1.1.
    fn new(bucket_count: usize, fine_grained: bool, frequent_read: bool) -> Self {
        let buckets = || {
            std::iter::repeat_with(HashBucket::default)
                .take(bucket_count)
                .collect()
        };
        if !fine_grained {
            Self::Plain(buckets())
        } else if frequent_read {
            Self::FrequentRead(FrequentReadRwLock::new(buckets()))
        } else {
            Self::Normal(RwLock::new(buckets()))
        }
    }

    fn read(&self) -> StripeReadGuard<'_> {
        match self {
            Self::Plain(buckets) => StripeReadGuard::Plain(buckets),
            Self::Normal(lock) => StripeReadGuard::Normal(lock.read().unwrap()),
            Self::FrequentRead(lock) => StripeReadGuard::FrequentRead(lock.read()),
        }
    }

    fn write(&self) -> StripeWriteGuard<'_> {
        match self {
            Self::Plain(_) => panic!("non-fine hash stripe cannot be write-locked"),
            Self::Normal(lock) => StripeWriteGuard::Normal(lock.write().unwrap()),
            Self::FrequentRead(lock) => StripeWriteGuard::FrequentRead(lock.write()),
        }
    }

    fn get_mut(&mut self) -> &mut Vec<HashBucket> {
        match self {
            Self::Plain(buckets) => buckets,
            Self::Normal(lock) => lock.get_mut().unwrap(),
            Self::FrequentRead(lock) => lock.get_mut(),
        }
    }
}

impl Stripe {
    fn new(bucket_count: usize, fine_grained: bool, frequent_read: bool) -> Self {
        Self {
            buckets: StripeBuckets::new(bucket_count, fine_grained, frequent_read),
            nitems: AtomicIsize::new(0),
        }
    }
}

fn stripe_bucket_count_before(end: usize, stripe: usize, nlocks: usize) -> usize {
    if end <= stripe {
        0
    } else {
        1 + (end - 1 - stripe) / nlocks
    }
}

fn stripe_bucket_count_in(start: usize, end: usize, stripe: usize, nlocks: usize) -> usize {
    stripe_bucket_count_before(end, stripe, nlocks)
        - stripe_bucket_count_before(start, stripe, nlocks)
}

fn split_bucket(
    source: &mut HashBucket,
    destination: &mut HashBucket,
    new_slot: usize,
    mask: usize,
) {
    let mut current = source.head.take();
    let (mut keep, mut moved) = (None, None);
    let (mut keep_tail, mut moved_tail) = (&mut keep, &mut moved);
    while let Some(mut node) = current {
        current = node.next.take();
        if node.pseudo_deleted {
            continue;
        }
        if node.hvalue as usize & mask == new_slot {
            *moved_tail = Some(node);
            moved_tail = &mut moved_tail.as_mut().unwrap().next;
        } else {
            *keep_tail = Some(node);
            keep_tail = &mut keep_tail.as_mut().unwrap().next;
        }
    }
    source.head = keep;
    destination.head = moved;
}

fn purge_pseudo_deleted(mut current: Option<Box<HashDbTerm>>) -> Option<Box<HashDbTerm>> {
    let mut live = None;
    let mut tail = &mut live;
    while let Some(mut node) = current {
        current = node.next.take();
        if !node.pseudo_deleted {
            *tail = Some(node);
            tail = &mut tail.as_mut().unwrap().next;
        }
    }
    live
}

/// Port of erts/emulator/beam/erl_db_hash.c:164-170, OTP-29.1.1.
pub(super) struct HashStorage {
    stripes: Box<[Stripe]>,
    nlocks: usize,
    pub(super) next_order: AtomicU64,
    pub(super) size: AtomicIsize,
    pub(super) size_bias: AtomicIsize,
    pub(super) nactive: AtomicUsize,
    pub(super) deleted: Mutex<Vec<StoredTerm>>,
    szm: AtomicUsize,
    pub(super) nslots: AtomicUsize,
    initial_slots: usize,
    auto_lock_count: AtomicUsize,
    decentralized_counters: bool,
    resize_lock: Mutex<()>,
}

impl HashStorage {
    /// Port of erts/emulator/beam/erl_db_hash.c:1017-1050, OTP-29.1.1.
    pub(super) fn new(
        write_concurrency: WriteConcurrency,
        decentralized_counters: bool,
        read_concurrency: bool,
    ) -> Self {
        let locks = match write_concurrency {
            WriteConcurrency::Disabled if decentralized_counters => NLOCKS_WITH_ITEM_COUNTERS,
            WriteConcurrency::Disabled => 1,
            WriteConcurrency::Enabled | WriteConcurrency::Auto => 64,
            WriteConcurrency::Fixed(count) => {
                let count = count.max(if decentralized_counters {
                    NLOCKS_WITH_ITEM_COUNTERS
                } else {
                    64
                });
                1 << (usize::BITS - count.leading_zeros() - 1)
            }
        };
        let mut initial_slots = FIRST_SEGMENT;
        while locks > initial_slots {
            initial_slots += EXT_SEGMENT;
        }
        Self {
            stripes: (0..locks)
                .map(|stripe| {
                    Stripe::new(
                        stripe_bucket_count_in(0, initial_slots, stripe, locks),
                        write_concurrency != WriteConcurrency::Disabled,
                        read_concurrency,
                    )
                })
                .collect(),
            nlocks: locks,
            next_order: AtomicU64::new(0),
            size: AtomicIsize::new(0),
            size_bias: AtomicIsize::new(0),
            nactive: AtomicUsize::new(FIRST_SEGMENT),
            deleted: Mutex::new(Vec::new()),
            szm: AtomicUsize::new(FIRST_SEGMENT - 1),
            nslots: AtomicUsize::new(initial_slots),
            initial_slots,
            auto_lock_count: AtomicUsize::new(locks),
            decentralized_counters,
            resize_lock: Mutex::new(()),
        }
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:207-217, OTP-29.1.1.
    #[inline]
    pub(super) fn slot_index(&self, hval: u64) -> usize {
        let nactive = self.nactive.load(Ordering::Acquire);
        let szm = self.szm.load(Ordering::Acquire);
        let index = hval as usize & szm;
        if index >= nactive {
            index & (szm >> 1)
        } else {
            index
        }
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:280, OTP-29.1.1.
    #[inline]
    fn make_hash(term: Term) -> u64 {
        ets_hash(term) >> 1
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:1041-1067, OTP-29.1.1.
    pub(super) fn lock_count(&self) -> usize {
        self.auto_lock_count.load(Ordering::Relaxed)
    }

    #[inline]
    pub(super) fn size(&self) -> usize {
        self.size.load(Ordering::Relaxed).max(0) as usize
    }

    #[inline]
    pub(super) fn add_items(&self, hval: u64, delta: isize) -> isize {
        if self.decentralized_counters {
            let counter = &self.stripes[hval as usize % NLOCKS_WITH_ITEM_COUNTERS].nitems;
            counter.fetch_add(delta, Ordering::Relaxed);
        }
        self.size.fetch_add(delta, Ordering::Relaxed) + delta
    }

    #[inline]
    fn estimated_items(&self, hval: u64) -> isize {
        if self.decentralized_counters {
            self.stripes[hval as usize % NLOCKS_WITH_ITEM_COUNTERS]
                .nitems
                .load(Ordering::Relaxed)
                * NLOCKS_WITH_ITEM_COUNTERS as isize
        } else {
            self.size.load(Ordering::Relaxed)
        }
    }

    #[inline]
    pub(super) fn nactive(&self) -> usize {
        self.nactive.load(Ordering::Acquire)
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:1526-1528, OTP-29.1.1.
    #[inline]
    fn stripe_index(&self, slot: usize) -> usize {
        slot % self.nlocks
    }

    #[inline]
    fn segment_bucket_mut(&mut self, slot: usize) -> &mut HashBucket {
        self.stripes[self.stripe_index(slot)]
            .buckets
            .get_mut()
            .get_mut(slot / self.nlocks)
            .unwrap()
    }

    /// Hold the bucket's hash stripe while its borrowed terms are consumed.
    // Port of erts/emulator/beam/erl_db_hash.c:404-419 (RLOCK_HASH), OTP-29.1.1.
    fn with_bucket<R>(&self, slot: usize, visit: impl FnOnce(&HashBucket) -> R) -> Option<R> {
        let stripe = &self.stripes[self.stripe_index(slot)];
        let buckets = stripe.buckets.read();
        (slot < self.nactive()).then(|| visit(&buckets[slot / self.nlocks]))
    }

    /// Keep the key's write stripe held through the complete bucket mutation.
    // Port of erts/emulator/beam/erl_db_hash.c:491-499 (WLOCK_HASH), OTP-29.1.1.
    fn with_hash_bucket_mut<R>(
        &self,
        hvalue: u64,
        visit: impl FnOnce(usize, &mut HashBucket) -> R,
    ) -> R {
        let mut visit = Some(visit);
        loop {
            let slot = self.slot_index(hvalue);
            let stripe = &self.stripes[self.stripe_index(slot)];
            let mut buckets = stripe.buckets.write();
            if self.slot_index(hvalue) == slot {
                return visit.take().unwrap()(slot, &mut buckets[slot / self.nlocks]);
            }
        }
    }

    /// Insert a prepared object under its hash stripe.
    // Port of erts/emulator/beam/erl_db_hash.c:1363-1460 (db_put_hash), OTP-29.1.1.
    pub(super) fn insert_shared(
        &self,
        mut object: StoredTerm,
        hash: u64,
        table_type: TableType,
        keypos: usize,
        fixed: bool,
        new_only: bool,
    ) -> bool {
        let hvalue = hash >> 1;
        object.hvalue = hvalue;
        let mut inserted = false;
        let mut accepted = true;
        self.with_hash_bucket_mut(hvalue, |_slot, bucket| {
            let key = object.key(keypos);
            let mut link = &mut bucket.head;
            while link.as_ref().is_some_and(|node| {
                node.hvalue != hvalue || !exact_key(node.object.key(keypos), key)
            }) {
                link = &mut link.as_mut().unwrap().next;
            }
            let group_order = link.as_ref().map(|node| node.object.group_order);
            if table_type == TableType::Set
                && let Some(node) = link.as_mut()
            {
                if new_only && !node.pseudo_deleted {
                    accepted = false;
                    return;
                }
                object.order = node.object.order;
                object.group_order = node.object.group_order;
                if node.pseudo_deleted {
                    node.pseudo_deleted = false;
                    inserted = true;
                    self.add_items(hash, 1);
                }
                node.object = object;
                return;
            }
            if new_only {
                let mut node = link.as_deref();
                while let Some(current) = node {
                    if current.hvalue != hvalue || !exact_key(current.object.key(keypos), key) {
                        break;
                    }
                    if !current.pseudo_deleted {
                        accepted = false;
                        return;
                    }
                    node = current.next.as_deref();
                }
            }
            if table_type == TableType::Bag {
                let revived = {
                    let mut cursor = &mut *link;
                    let mut at_group_head = true;
                    let mut revived = None;
                    while let Some(node) = cursor.as_deref_mut() {
                        if node.hvalue != hvalue || !exact_key(node.object.key(keypos), key) {
                            break;
                        }
                        if node.object.exact_eq_stored(&object) {
                            if !node.pseudo_deleted {
                                return;
                            }
                            node.pseudo_deleted = false;
                            inserted = true;
                            self.add_items(hash, 1);
                            if !at_group_head {
                                let mut node = cursor.take().unwrap();
                                *cursor = node.next.take();
                                revived = Some(node);
                            } else {
                                return;
                            }
                            break;
                        }
                        cursor = &mut cursor.as_mut().unwrap().next;
                        at_group_head = false;
                    }
                    revived
                };
                if let Some(mut node) = revived {
                    node.next = link.take();
                    *link = Some(node);
                    return;
                }
            }

            object.order = self.next_order.fetch_add(1, Ordering::Relaxed);
            object.group_order = group_order.unwrap_or(object.order);
            let new = Box::new(HashDbTerm {
                next: link.take(),
                hvalue,
                pseudo_deleted: false,
                object,
            });
            *link = Some(new);
            inserted = true;
            self.add_items(hash, 1);
        });
        if inserted && accepted {
            self.grow_after_insert(hash, fixed);
        }
        accepted
    }

    /// Delete all objects at a key while holding its write stripe.
    // Port of erts/emulator/beam/erl_db_hash.c:1613-1666 (db_erase_hash), OTP-29.1.1.
    pub(super) fn delete_key_shared(&self, key: Term, hash: u64, keypos: usize, fixed: bool) {
        self.delete_matching_shared(key, hash, keypos, fixed, |_| true);
    }

    // Port of erts/emulator/beam/erl_db.c:1494-1683 (do_update_counter), OTP-29.1.1.
    pub(super) fn update_counter_shared(
        &self,
        key: Term,
        hash: u64,
        keypos: usize,
        operations: &[crate::CounterOp],
    ) -> Option<smallvec::SmallVec<[Term; 4]>> {
        self.with_hash_bucket_mut(hash >> 1, |_slot, bucket| {
            let mut node = bucket.head.as_deref_mut();
            let object = loop {
                let current = node?;
                if !current.pseudo_deleted
                    && current.hvalue == hash >> 1
                    && exact_key(current.object.key(keypos), key)
                {
                    break &mut current.object;
                }
                node = current.next.as_deref_mut();
            };
            if !object.compressed_elements.is_empty() {
                return None;
            }
            let mut updated: smallvec::SmallVec<[(usize, i64); 4]> = smallvec::SmallVec::new();
            let mut results = smallvec::SmallVec::new();
            for operation in operations {
                if operation.position == keypos || operation.position == 0 {
                    return None;
                }
                let index = operation.position - 1;
                let old = match updated.iter().rev().find(|(at, _)| *at == index) {
                    Some(&(_, value)) => value,
                    None => object.tuple_element(index)?.as_small()?,
                };
                let mut next = old.checked_add(operation.increment)?;
                if let Some((threshold, reset)) = operation.threshold
                    && if operation.increment < 0 {
                        next < threshold
                    } else {
                        next > threshold
                    }
                {
                    next = reset;
                }
                results.push(Term::small(next)?);
                updated.push((index, next));
            }
            for (index, value) in updated {
                if !object.set_immediate_element(index, Term::small(value)?) {
                    return None;
                }
            }
            Some(results)
        })
    }

    // Port of erts/emulator/beam/erl_db.c:1371-1442 (do_update_element) and :1494-1683
    // (do_update_counter), OTP-29.1.1.
    pub(super) fn update_or_insert_shared<E>(
        &self,
        key: Term,
        hash: u64,
        keypos: usize,
        fixed: bool,
        update: impl FnOnce(Option<&StoredTerm>) -> Result<Option<StoredTerm>, E>,
    ) -> Result<bool, E> {
        let hvalue = hash >> 1;
        let mut update = Some(update);
        let (changed, inserted) = self.with_hash_bucket_mut(hvalue, |_slot, bucket| {
            let mut link = &mut bucket.head;
            while link.as_ref().is_some_and(|node| {
                node.hvalue != hvalue || !exact_key(node.object.key(keypos), key)
            }) {
                link = &mut link.as_mut().unwrap().next;
            }
            let found = link
                .as_ref()
                .filter(|node| !node.pseudo_deleted)
                .map(|node| &node.object);
            let Some(mut replacement) = update.take().unwrap()(found)? else {
                return Ok((false, false));
            };
            replacement.hvalue = hvalue;
            if let Some(node) = link.as_mut() {
                let revived = node.pseudo_deleted;
                replacement.order = node.object.order;
                replacement.group_order = node.object.group_order;
                node.object = replacement;
                if revived {
                    node.pseudo_deleted = false;
                    self.add_items(hash, 1);
                    return Ok((true, true));
                }
                return Ok((true, false));
            }
            replacement.order = self.next_order.fetch_add(1, Ordering::Relaxed);
            replacement.group_order = replacement.order;
            let new = Box::new(HashDbTerm {
                next: link.take(),
                hvalue,
                pseudo_deleted: false,
                object: replacement,
            });
            *link = Some(new);
            self.add_items(hash, 1);
            Ok((true, true))
        })?;
        if inserted {
            self.grow_after_insert(hash, fixed);
        }
        Ok(changed)
    }

    // Port of erts/emulator/beam/erl_db_hash.c:1613-1666 (db_erase_hash), OTP-29.1.1.
    pub(super) fn delete_object_shared(
        &self,
        key: Term,
        hash: u64,
        keypos: usize,
        object: Term,
        fixed: bool,
    ) {
        self.delete_matching_shared(key, hash, keypos, fixed, |stored| {
            stored.exact_eq_term(object)
        });
    }

    // Port of erts/emulator/beam/erl_db_hash.c:2949-3005 (db_take_hash), OTP-29.1.1.
    pub(super) fn take_shared<H: HeapAlloc>(
        &self,
        key: Term,
        hash: u64,
        keypos: usize,
        table_type: TableType,
        fixed: bool,
        dst: &mut H,
    ) -> Result<Vec<Term>, EtsError> {
        let mut removed_count = 0;
        let mut values = self.with_hash_bucket_mut(hash >> 1, |_slot, bucket| {
            let mut values = Vec::new();
            let mut current = bucket.head.as_deref();
            let mut found = false;
            while let Some(node) = current {
                if !node.pseudo_deleted
                    && node.hvalue == hash >> 1
                    && exact_key(node.object.key(keypos), key)
                {
                    found = true;
                    values.push(node.object.copy_out(dst)?);
                    if !matches!(table_type, TableType::Bag | TableType::DuplicateBag) {
                        break;
                    }
                } else if found {
                    break;
                }
                current = node.next.as_deref();
            }
            let mut link = &mut bucket.head;
            let mut first = true;
            while let Some(mut node) = link.take() {
                if !node.pseudo_deleted
                    && node.hvalue == hash >> 1
                    && exact_key(node.object.key(keypos), key)
                {
                    removed_count += 1;
                    if fixed && first {
                        node.pseudo_deleted = true;
                        *link = Some(node);
                        link = &mut link.as_mut().unwrap().next;
                        first = false;
                    } else {
                        *link = node.next.take();
                    }
                    if !matches!(table_type, TableType::Bag | TableType::DuplicateBag) {
                        break;
                    }
                } else {
                    *link = Some(node);
                    link = &mut link.as_mut().unwrap().next;
                }
            }
            if removed_count != 0 {
                self.add_items(hash, -(removed_count as isize));
            }
            Ok::<_, EtsError>(values)
        })?;
        if matches!(table_type, TableType::Bag | TableType::DuplicateBag) {
            values.reverse();
        }
        if removed_count != 0 && !fixed {
            self.shrink_after_delete_shared(self.estimated_items(hash));
        }
        Ok(values)
    }

    // Port of erts/emulator/beam/erl_db_hash.c:2870-2905 (db_select_replace_hash), OTP-29.1.1.
    pub(super) fn replace_key_shared<E>(
        &self,
        key: Term,
        hash: u64,
        keypos: usize,
        mut replace: impl FnMut(&StoredTerm) -> Result<Option<StoredTerm>, E>,
    ) -> Result<usize, E> {
        self.with_hash_bucket_mut(hash >> 1, |_slot, bucket| {
            let mut count = 0;
            let mut node = bucket.head.as_deref_mut();
            while let Some(current) = node {
                if !current.pseudo_deleted
                    && current.hvalue == hash >> 1
                    && exact_key(current.object.key(keypos), key)
                    && let Some(mut replacement) = replace(&current.object)?
                {
                    replacement.order = current.object.order;
                    replacement.group_order = current.object.group_order;
                    replacement.hvalue = current.hvalue;
                    current.object = replacement;
                    count += 1;
                }
                node = current.next.as_deref_mut();
            }
            Ok(count)
        })
    }

    fn delete_matching_shared(
        &self,
        key: Term,
        hash: u64,
        keypos: usize,
        fixed: bool,
        mut matches: impl FnMut(&StoredTerm) -> bool,
    ) {
        let (mut removed, count) = self.with_hash_bucket_mut(hash >> 1, |_slot, bucket| {
            let mut link = &mut bucket.head;
            let mut removed = RemovedHashTerms { head: None };
            let mut tail = &mut removed.head;
            let mut count = 0;
            while let Some(mut node) = link.take() {
                if !node.pseudo_deleted
                    && node.hvalue == hash >> 1
                    && exact_key(node.object.key(keypos), key)
                    && matches(&node.object)
                {
                    *link = node.next.take();
                    *tail = Some(node);
                    tail = &mut tail.as_mut().unwrap().next;
                    count += 1;
                } else {
                    *link = Some(node);
                    link = &mut link.as_mut().unwrap().next;
                }
            }
            if count != 0 {
                self.add_items(hash, -(count as isize));
            }
            (removed, count)
        });
        if fixed && let Some(object) = removed.take_first() {
            self.deleted.lock().unwrap().push(object);
        }
        if count != 0 && !fixed {
            let nitems = self.estimated_items(hash);
            self.shrink_after_delete_shared(nitems);
        }
    }

    fn shrink_after_delete_shared(&self, nitems: isize) {
        // Port of erts/emulator/beam/erl_db_hash.c:757-761 (try_shrink), OTP-29.1.1.
        if nitems >= self.shrink_limit() as isize {
            return;
        }
        let _resize = self.resize_lock.lock().unwrap();
        for _ in 0..5 {
            let nslots = self.nslots.load(Ordering::Relaxed);
            if nitems >= ((nslots.saturating_sub(EXT_SEGMENT)) / 2) as isize {
                break;
            }
            let old_active = self.nactive();
            if old_active <= FIRST_SEGMENT {
                break;
            }
            let source = old_active - 1;
            let low_mask = self.szm.load(Ordering::Relaxed) >> 1;
            let destination = source & low_mask;
            let stripe_index = self.stripe_index(source);
            debug_assert_eq!(stripe_index, self.stripe_index(destination));
            let mut buckets = self.stripes[stripe_index].buckets.write();
            if self.nactive() != old_active {
                drop(buckets);
                break;
            }
            self.nactive.store(source, Ordering::Release);
            if destination == 0 {
                self.szm.store(low_mask, Ordering::Release);
            }
            let source_index = source / self.nlocks;
            let destination_index = destination / self.nlocks;
            let mut source_head = buckets[source_index].head.take();
            if let Some(mut head) = source_head.take() {
                let mut tail = &mut head;
                while tail.next.is_some() {
                    tail = tail.next.as_mut().unwrap();
                }
                tail.next = buckets[destination_index].head.take();
                buckets[destination_index].head = purge_pseudo_deleted(Some(head));
            }
            drop(buckets);
            if nslots - source >= EXT_SEGMENT {
                let new_slots = self.nslots.fetch_sub(EXT_SEGMENT, Ordering::Relaxed) - EXT_SEGMENT;
                for (index, stripe) in self.stripes.iter().enumerate() {
                    stripe.buckets.write().truncate(stripe_bucket_count_before(
                        new_slots,
                        index,
                        self.nlocks,
                    ));
                }
            }
        }
    }

    // Port of erts/emulator/beam/erl_db_hash.c:3648-3731 (grow), OTP-29.1.1.
    fn grow_after_insert(&self, hash: u64, fixed: bool) {
        if fixed {
            return;
        }
        // Port of erts/emulator/beam/erl_db_hash.c:3993-4001 (db_finalize_dbterm_hash),
        // OTP-29.1.1.
        if self.estimated_items(hash) <= self.nactive() as isize {
            return;
        }
        let _resize = self.resize_lock.lock().unwrap();
        let nitems = self.estimated_items(hash);
        let old_active = self.nactive();
        if nitems <= old_active as isize {
            return;
        }
        let old_slots = self.nslots.load(Ordering::Relaxed);
        if old_active == old_slots {
            let end = old_slots + EXT_SEGMENT;
            for (index, stripe) in self.stripes.iter().enumerate() {
                stripe.buckets.write().extend(
                    std::iter::repeat_with(HashBucket::default).take(stripe_bucket_count_in(
                        old_slots,
                        end,
                        index,
                        self.nlocks,
                    )),
                );
            }
            self.nslots.store(end, Ordering::Relaxed);
        }
        let old_mask = self.szm.load(Ordering::Relaxed);
        let (source, new_mask) = if old_active <= old_mask {
            (old_active & (old_mask >> 1), old_mask)
        } else {
            (0, (old_mask << 1) | 1)
        };
        let destination = old_active;
        let source_lock = self.stripe_index(source);
        let destination_lock = self.stripe_index(destination);
        if source_lock == destination_lock {
            let mut buckets = self.stripes[source_lock].buckets.write();
            let source_index = source / self.nlocks;
            let destination_index = destination / self.nlocks;
            if source_index < destination_index {
                let (left, right) = buckets.split_at_mut(destination_index);
                split_bucket(
                    &mut left[source_index],
                    &mut right[0],
                    destination,
                    new_mask,
                );
            } else {
                let (left, right) = buckets.split_at_mut(source_index);
                split_bucket(
                    &mut right[0],
                    &mut left[destination_index],
                    destination,
                    new_mask,
                );
            }
        } else if source_lock < destination_lock {
            let mut source_buckets = self.stripes[source_lock].buckets.write();
            let mut destination_buckets = self.stripes[destination_lock].buckets.write();
            split_bucket(
                &mut source_buckets[source / self.nlocks],
                &mut destination_buckets[destination / self.nlocks],
                destination,
                new_mask,
            );
        } else {
            let mut destination_buckets = self.stripes[destination_lock].buckets.write();
            let mut source_buckets = self.stripes[source_lock].buckets.write();
            split_bucket(
                &mut source_buckets[source / self.nlocks],
                &mut destination_buckets[destination / self.nlocks],
                destination,
                new_mask,
            );
        }
        self.szm.store(new_mask, Ordering::Relaxed);
        self.nactive.store(old_active + 1, Ordering::Release);
    }

    pub(super) fn with_objects_hash<R>(
        &self,
        hval: u64,
        visit: impl FnOnce(HashIter<'_>) -> R,
    ) -> R {
        let hvalue = hval >> 1;
        loop {
            let slot = self.slot_index(hvalue);
            let stripe = &self.stripes[self.stripe_index(slot)];
            let buckets = stripe.buckets.read();
            if self.slot_index(hvalue) == slot {
                return visit(HashIter {
                    next: buckets[slot / self.nlocks].head.as_deref(),
                });
            }
        }
    }

    pub(super) fn try_for_each_value<E>(
        &self,
        mut visit: impl FnMut(&StoredTerm) -> Result<(), E>,
    ) -> Result<(), E> {
        self.try_for_each_value_while(|object| {
            visit(object)?;
            Ok(true)
        })
    }

    pub(super) fn for_each_value(&self, mut visit: impl FnMut(&StoredTerm)) {
        for slot in 0..self.nactive() {
            let _ = self.with_bucket(slot, |bucket| {
                for node in (HashIter {
                    next: bucket.head.as_deref(),
                }) {
                    visit(&node.object);
                }
            });
        }
    }

    pub(super) fn try_for_each_value_while<E>(
        &self,
        mut visit: impl FnMut(&StoredTerm) -> Result<bool, E>,
    ) -> Result<(), E> {
        for slot in 0..self.nactive() {
            let Some(keep_going) = self.with_bucket(slot, |bucket| {
                for node in (HashIter {
                    next: bucket.head.as_deref(),
                }) {
                    if !visit(&node.object)? {
                        return Ok::<_, E>(false);
                    }
                }
                Ok(true)
            }) else {
                continue;
            };
            let keep_going = keep_going?;
            if !keep_going {
                break;
            }
        }
        Ok(())
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
        for slot in 0..self.nactive() {
            if let Some(Some(key)) = self.with_bucket(slot, |bucket| {
                HashIter {
                    next: bucket.head.as_deref(),
                }
                .next()
                .map(|object| object.key(keypos))
            }) {
                return Some(key);
            }
        }
        None
    }

    /// Return a key's raw successor, preserving the hash directory walk order.
    ///
    /// Port of erts/emulator/beam/erl_db_hash.c:4196-4231, OTP-29.1.1.
    pub(super) fn raw_next(&self, key: Term, keypos: usize) -> Result<Option<Term>, EtsError> {
        let hash = ets_hash(key) >> 1;
        loop {
            let slot = self.slot_index(hash);
            let mut found = false;
            let Some(in_slot) = self.with_bucket(slot, |bucket| {
                let mut successor = None;
                for node in (HashIter {
                    next: bucket.head.as_deref(),
                }) {
                    if !found {
                        if node.hvalue == hash && exact_key(node.object.key(keypos), key) {
                            found = true;
                        }
                        continue;
                    }
                    if node.hvalue != hash || !exact_key(node.object.key(keypos), key) {
                        successor = Some(node.object.key(keypos));
                        break;
                    }
                }
                successor
            }) else {
                continue;
            };
            if in_slot.is_some() {
                return Ok(in_slot);
            }
            if !found {
                return Err(EtsError::BadArg);
            }
            for slot in slot + 1..self.nactive() {
                if let Some(Some(key)) = self.with_bucket(slot, |bucket| {
                    HashIter {
                        next: bucket.head.as_deref(),
                    }
                    .next()
                    .map(|node| node.object.key(keypos))
                }) {
                    return Ok(Some(key));
                }
            }
            return Ok(None);
        }
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

    /// Port of erts/emulator/beam/erl_db_hash.c:1363-1450 (db_put_hash), OTP-29.1.1.
    pub(super) fn push_at_key(&mut self, slot: usize, object: StoredTerm, keypos: usize) {
        let hvalue = object.hvalue;
        let key = object.key(keypos);
        let bucket = self.segment_bucket_mut(slot);
        let mut link = &mut bucket.head;
        while link
            .as_ref()
            .is_some_and(|node| node.hvalue != hvalue || !exact_key(node.object.key(keypos), key))
        {
            link = &mut link.as_mut().unwrap().next;
        }
        let node = Box::new(HashDbTerm {
            next: link.take(),
            hvalue,
            pseudo_deleted: false,
            object,
        });
        *link = Some(node);
    }

    /// Restore an object at its former place after a fixed-table deletion.
    pub(super) fn push_at_order(&mut self, slot: usize, object: StoredTerm) {
        let hvalue = object.hvalue;
        let order = (object.group_order, u64::MAX - object.order);
        let bucket = self.segment_bucket_mut(slot);
        let mut link = &mut bucket.head;
        while link
            .as_ref()
            .is_some_and(|node| (node.object.group_order, u64::MAX - node.object.order) < order)
        {
            link = &mut link.as_mut().unwrap().next;
        }
        let node = Box::new(HashDbTerm {
            next: link.take(),
            hvalue,
            pseudo_deleted: false,
            object,
        });
        *link = Some(node);
    }

    pub(super) fn take_all_buckets(&mut self) -> Vec<StoredTerm> {
        let mut objects = Vec::with_capacity(self.size());
        for slot in 0..self.nactive() {
            let mut node = self.segment_bucket_mut(slot).head.take();
            while let Some(mut current) = node {
                node = current.next.take();
                objects.push(current.object);
            }
        }
        for stripe in self.stripes.iter() {
            stripe.nitems.store(0, Ordering::Relaxed);
        }
        objects
    }

    /// Free every object and return to the initial single-segment layout.
    // Port of erts/emulator/beam/erl_db_hash.c:4017 (db_delete_all_objects_hash:
    // db_free_table_continue_hash + db_create_hash), OTP-29.1.1.
    pub(super) fn clear_buckets(&mut self) {
        for (index, stripe) in self.stripes.iter_mut().enumerate() {
            let buckets = stripe.buckets.get_mut();
            buckets.clear();
            buckets.extend(std::iter::repeat_with(HashBucket::default).take(
                stripe_bucket_count_in(0, self.initial_slots, index, self.nlocks),
            ));
            stripe.nitems.store(0, Ordering::Relaxed);
        }
        self.nactive.store(FIRST_SEGMENT, Ordering::Release);
        self.szm.store(FIRST_SEGMENT - 1, Ordering::Release);
        self.nslots.store(self.initial_slots, Ordering::Release);
    }

    /// Detach all buckets (and, for a table being deleted, the pseudo-deleted list) so they can
    /// be released a few segments at a time, leaving the initial single-segment layout.
    // Port of erts/emulator/beam/erl_db_hash.c:3122 (db_free_table_continue_hash), OTP-29.1.1.
    pub(super) fn take_garbage(&mut self, with_deleted: bool) -> HashGarbage {
        let nslots = self.nslots.load(Ordering::Relaxed);
        let mut segments = Vec::new();
        let mut start = 0;
        let mut end = FIRST_SEGMENT;
        while start < nslots {
            let mut segment = Vec::with_capacity(end - start);
            for slot in start..end.min(nslots) {
                let stripe = &mut self.stripes[slot % self.nlocks];
                segment.push(std::mem::take(
                    &mut stripe.buckets.get_mut()[slot / self.nlocks],
                ));
            }
            segments.push(segment);
            start = end;
            end += EXT_SEGMENT;
        }
        self.clear_buckets();
        HashGarbage {
            segments,
            deleted: if with_deleted {
                std::mem::take(self.deleted.get_mut().unwrap())
            } else {
                Vec::new()
            },
        }
    }

    pub(super) fn key_count(&self, keypos: usize) -> usize {
        let mut count = 0;
        for slot in 0..self.nactive() {
            let _ = self.with_bucket(slot, |bucket| {
                let mut keys = Vec::new();
                for object in (HashIter {
                    next: bucket.head.as_deref(),
                }) {
                    let key = object.key(keypos);
                    if !keys.iter().any(|&old| arinsal_term::exact_eq(old, key)) {
                        keys.push(key);
                        count += 1;
                    }
                }
            });
        }
        count
    }

    /// Replace live objects in place, keeping their bucket position and insertion order.
    pub(super) fn replace_each(
        &mut self,
        mut replace: impl FnMut(&StoredTerm) -> Result<Option<StoredTerm>, EtsError>,
    ) -> Result<usize, EtsError> {
        let mut count = 0;
        for slot in 0..self.nactive() {
            let mut node = self.segment_bucket_mut(slot).head.as_deref_mut();
            while let Some(current) = node {
                if !current.pseudo_deleted
                    && let Some(mut replacement) = replace(&current.object)?
                {
                    replacement.order = current.object.order;
                    replacement.group_order = current.object.group_order;
                    replacement.hvalue = current.object.hvalue;
                    current.object = replacement;
                    count += 1;
                }
                node = current.next.as_deref_mut();
            }
        }
        Ok(count)
    }

    /// Unlink live terms into the same intrusive free list used by `db_erase_hash`.
    // Port of erts/emulator/beam/erl_db_hash.c:1620-1690 (db_erase_hash), OTP-29.1.1.
    pub(super) fn detach_live_matching(
        &mut self,
        hval: u64,
        mut predicate: impl FnMut(&StoredTerm) -> bool,
    ) -> (RemovedHashTerms, usize) {
        let slot = self.slot_index(hval);
        let mut link = &mut self.segment_bucket_mut(slot).head;
        let mut removed = RemovedHashTerms { head: None };
        let mut tail = &mut removed.head;
        let mut count = 0;
        while let Some(mut node) = link.take() {
            if !node.pseudo_deleted && predicate(&node.object) {
                *link = node.next.take();
                *tail = Some(node);
                tail = &mut tail.as_mut().unwrap().next;
                count += 1;
            } else {
                *link = Some(node);
                link = &mut link.as_mut().unwrap().next;
            }
        }
        (removed, count)
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
        let mut per_lock = [0isize; NLOCKS_WITH_ITEM_COUNTERS];
        let mut failure = None;
        'slots: for slot in 0..self.nactive() {
            let mut link = &mut self.segment_bucket_mut(slot).head;
            while let Some(mut node) = link.take() {
                let selected = if node.pseudo_deleted {
                    Ok(false)
                } else {
                    predicate(&node.object)
                };
                match selected {
                    Ok(true) => {
                        let counter = node.hvalue as usize % NLOCKS_WITH_ITEM_COUNTERS;
                        *link = node.next.take();
                        removed += 1;
                        per_lock[counter] += 1;
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
        self.size.fetch_sub(removed as isize, Ordering::Relaxed);
        if self.decentralized_counters {
            for (index, count) in per_lock.into_iter().enumerate() {
                self.stripes[index]
                    .nitems
                    .fetch_sub(count, Ordering::Relaxed);
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(removed),
        }
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:3973-3984, OTP-29.1.1.
    pub(super) fn retain_fixed_delete(&mut self, object: StoredTerm) {
        self.deleted.get_mut().unwrap().push(object);
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:1745-1750, OTP-29.1.1.
    pub(super) fn active_slots(&self) -> usize {
        self.nactive()
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:1624-1626, OTP-29.1.1.
    pub(super) fn is_valid_slot(&self, slot: usize) -> bool {
        slot <= self.nactive()
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:3883-3885, OTP-29.1.1.
    pub(super) fn slot_for_key(&self, key: Term) -> usize {
        self.slot_index(Self::make_hash(key))
    }

    /// Objects of one slot in traversal order, optionally with fixed-table pseudo-deleted ones.
    ///
    /// Port of erts/emulator/beam/erl_db_hash.c:4196-4231 (db_next_hash), OTP-29.1.1: a
    /// traversal step only walks the key's own bucket and the following buckets, never the
    /// whole table.
    pub(super) fn try_with_slot_ordered<E>(
        &self,
        slot: usize,
        with_deleted: bool,
        mut visit: impl FnMut(&StoredTerm, bool) -> Result<(), E>,
    ) -> Result<(), E> {
        if let Some(result) = self.with_bucket(slot, |bucket| {
            let mut objects: Vec<(&StoredTerm, bool)> = HashIter {
                next: bucket.head.as_deref(),
            }
            .map(|node| (&node.object, false))
            .collect();
            let deleted = with_deleted.then(|| self.deleted.lock().unwrap());
            if let Some(deleted) = deleted.as_ref() {
                objects.extend(
                    deleted
                        .iter()
                        .filter(|object| self.slot_index(object.hvalue) == slot)
                        .map(|object| (object, true)),
                );
                objects.sort_unstable_by_key(|(object, _)| {
                    (object.group_order, u64::MAX - object.order)
                });
            }
            for (object, deleted) in objects {
                visit(object, deleted)?;
            }
            Ok(())
        }) {
            result
        } else {
            Ok(())
        }
    }

    /// First live object of the first non-empty slot at or after `slot`, in traversal order.
    pub(super) fn with_first_from_slot<R>(
        &self,
        slot: usize,
        mut visit: impl FnMut(&StoredTerm) -> R,
    ) -> Option<R> {
        for slot in slot..self.nactive() {
            if let Some(Some(result)) = self.with_bucket(slot, |bucket| {
                HashIter {
                    next: bucket.head.as_deref(),
                }
                .next()
                .map(|node| visit(&node.object))
            }) {
                return Some(result);
            }
        }
        None
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:3411-3444, OTP-29.1.1.
    fn ensure_slot(&mut self) {
        let nactive = self.nactive();
        let nslots = self.nslots.load(Ordering::Relaxed);
        if nactive == nslots {
            let start = nslots;
            let end = start + EXT_SEGMENT;
            for (index, stripe) in self.stripes.iter_mut().enumerate() {
                stripe.buckets.get_mut().extend(
                    std::iter::repeat_with(HashBucket::default).take(stripe_bucket_count_in(
                        start,
                        end,
                        index,
                        self.nlocks,
                    )),
                );
            }
            self.nslots.fetch_add(EXT_SEGMENT, Ordering::Relaxed);
        }
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:3648-3731 (grow), OTP-29.1.1.
    #[inline]
    pub(super) fn maybe_grow(&mut self, fixed: bool, _keypos: usize) {
        if fixed || self.size() <= self.nactive() {
            return;
        }
        self.ensure_slot();
        let old_active = self.nactive();
        let old_mask = self.szm.load(Ordering::Relaxed);
        let source = if old_active <= old_mask {
            old_active & (old_mask >> 1)
        } else {
            self.szm.store((old_mask << 1) | 1, Ordering::Relaxed);
            0
        };
        let new_slot = old_active;
        self.nactive.store(old_active + 1, Ordering::Release);
        let mask = self.szm.load(Ordering::Relaxed);
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
        let nslots = self.nslots.load(Ordering::Relaxed);
        if nslots < 4352 {
            0
        } else {
            (nslots - EXT_SEGMENT) / 2
        }
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:3743-3800 (shrink), OTP-29.1.1.
    fn shrink(&mut self) {
        let nactive = self.nactive();
        if nactive <= FIRST_SEGMENT {
            return;
        }
        let source = nactive - 1;
        let mask = self.szm.load(Ordering::Relaxed) >> 1;
        let destination = source & mask;
        self.nactive.store(source, Ordering::Release);
        if destination == 0 {
            self.szm.store(mask, Ordering::Relaxed);
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
        let nslots = self.nslots.load(Ordering::Relaxed);
        if nslots - source >= EXT_SEGMENT {
            let nslots = self.nslots.fetch_sub(EXT_SEGMENT, Ordering::Relaxed) - EXT_SEGMENT;
            for (index, stripe) in self.stripes.iter_mut().enumerate() {
                stripe
                    .buckets
                    .get_mut()
                    .truncate(stripe_bucket_count_before(nslots, index, self.nlocks));
            }
        }
    }

    /// Port of erts/emulator/beam/erl_db_hash.c:757-760, OTP-29.1.1.
    pub(super) fn shrink_after_delete(&mut self, _keypos: usize) {
        for _ in 0..5 {
            if self.size() >= self.shrink_limit() || self.nactive() <= FIRST_SEGMENT {
                break;
            }
            let source = self.nactive() - 1;
            let destination = source & (self.szm.load(Ordering::Relaxed) >> 1);
            let mut ranks = HashMap::new();
            let mut rank = 0_u64;
            for slot in [source, destination] {
                let ordered = HashIter {
                    next: self.segment_bucket_mut(slot).head.as_deref(),
                };
                let mut last_group = None;
                for object in ordered {
                    let object = &object.object;
                    if last_group != Some(object.group_order) {
                        rank += 1;
                        last_group = Some(object.group_order);
                    }
                    ranks.insert(object.order, rank);
                }
            }
            for slot in [source, destination] {
                let mut objects = HashIterMut {
                    next: self.segment_bucket_mut(slot).head.as_deref_mut(),
                };
                for object in &mut objects {
                    if let Some(&rank) = ranks.get(&object.order) {
                        object.group_order = rank;
                    }
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
    segments: Vec<Vec<HashBucket>>,
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
