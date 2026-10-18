//! Immutable, chunk-backed terms for message publication.
//!
//! Constructors write into a private builder. Sealing publishes its pages and
//! freezes every word; the ordinary term tags and readers then need no adapter.

use crate::{
    ExportEntry, ExternalBinary, FunEntry, HeapAlloc, MagicRef, Node, RefcBinary, Term,
    TermBuilder, TermError, copy_term,
};
use arinsal_etf::OwnedTerm;
use std::alloc::{Layout, alloc, dealloc};
use std::collections::{HashMap, HashSet};
use std::ptr::NonNull;
#[cfg(not(miri))]
use std::sync::mpsc;
use std::sync::{Arc, OnceLock, RwLock, Weak};

const PAGE_BYTES: usize = 64 * 1024;
const PAGE_WORDS: usize = PAGE_BYTES / 8;
/// Maximum number of words copied from a private graph at send time.
pub const SEND_COPY_LIMIT_WORDS: usize = 4096;

struct Chunk {
    ptr: NonNull<u8>,
    bytes: usize,
    used_words: usize,
}

impl Chunk {
    fn new(words: usize) -> Option<Self> {
        let bytes = words
            .checked_mul(8)?
            .max(PAGE_BYTES)
            .next_multiple_of(PAGE_BYTES);
        let layout = Layout::from_size_align(bytes, PAGE_BYTES).ok()?;
        // SAFETY: layout has nonzero size and valid power-of-two alignment.
        let ptr = NonNull::new(unsafe { alloc(layout) })?;
        Some(Self {
            ptr,
            bytes,
            used_words: 0,
        })
    }

    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        if words > self.bytes / 8 - self.used_words {
            return None;
        }
        // SAFETY: used_words is within this allocation and the checked span fits.
        let ptr = unsafe { self.ptr.as_ptr().cast::<u64>().add(self.used_words) };
        self.used_words += words;
        Some(ptr)
    }
}

// SAFETY: a chunk is builder-private until publication; afterward its cells are immutable.
unsafe impl Send for Chunk {}
// SAFETY: published chunks are never mutated and their allocation stays pinned.
unsafe impl Sync for Chunk {}

impl Drop for Chunk {
    fn drop(&mut self) {
        // SAFETY: ptr was allocated with this exact layout in Chunk::new.
        unsafe {
            dealloc(
                self.ptr.as_ptr(),
                Layout::from_size_align_unchecked(self.bytes, PAGE_BYTES),
            )
        };
    }
}

struct Storage {
    chunks: Vec<Chunk>,
    words: usize,
    off_heap_first: usize,
    wrt_bins: usize,
    overhead: u64,
    funs: Vec<Arc<FunEntry>>,
    exports: Vec<Arc<ExportEntry>>,
    dependencies: HashMap<usize, Arc<Region>>,
}

impl Drop for Storage {
    fn drop(&mut self) {
        // Port of erts/emulator/beam/copy.c:2049 (fragment ownership release), OTP-29.1.1.
        crate::gc::release_off_heap_chain(self.off_heap_first);
        crate::gc::release_off_heap_chain(self.wrt_bins);
    }
}

impl Storage {
    fn new() -> Self {
        Self {
            chunks: Vec::new(),
            words: 0,
            off_heap_first: 0,
            wrt_bins: 0,
            overhead: 0,
            funs: Vec::new(),
            exports: Vec::new(),
            dependencies: HashMap::new(),
        }
    }
}

impl HeapAlloc for Storage {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        if words == 0 {
            return None;
        }
        if self
            .chunks
            .last()
            .is_none_or(|c| words > c.bytes / 8 - c.used_words)
        {
            self.chunks.push(Chunk::new(words.max(PAGE_WORDS))?);
        }
        let ptr = self.chunks.last_mut()?.alloc(words)?;
        self.words = self.words.checked_add(words)?;
        Some(ptr)
    }
    fn retain_binary(&mut self, binary: Arc<RefcBinary>) {
        drop(binary);
    }
    fn link_bin_ref(
        &mut self,
        bin_ref: *mut u64,
        writable: bool,
        overhead_words: u64,
        owner: Option<arinsal_alloc::raw::OwnedBinaryRef>,
    ) -> Result<(), TermError> {
        let head = if writable {
            &mut self.wrt_bins
        } else {
            &mut self.off_heap_first
        };
        crate::heap::store(bin_ref.wrapping_add(2), *head as u64);
        *head = bin_ref as usize;
        if let Some(owner) = owner {
            owner.transfer_to_bin_ref(bin_ref);
        }
        self.overhead = self.overhead.saturating_add(overhead_words);
        Ok(())
    }
    fn link_external_binary(
        &mut self,
        bin_ref: *mut u64,
        binary: Arc<ExternalBinary>,
    ) -> Result<(), TermError> {
        crate::heap::link_external_bin_ref(&mut self.off_heap_first, bin_ref, binary);
        Ok(())
    }
    fn supports_external_binary(&self) -> bool {
        true
    }
    fn link_node(&mut self, thing: *mut u64, node: Arc<Node>) {
        crate::heap::link_node_thing(&mut self.off_heap_first, thing, node);
    }
    fn retain_fun(&mut self, entry: Arc<FunEntry>) {
        self.funs.push(entry);
    }
    fn retain_export(&mut self, entry: Arc<ExportEntry>) {
        self.exports.push(entry);
    }
    fn link_magic_ref(&mut self, thing: *mut u64, owner: Arc<MagicRef>) -> Result<(), TermError> {
        crate::heap::link_magic_thing(&mut self.off_heap_first, &mut self.overhead, thing, owner);
        Ok(())
    }
    fn supports_magic(&self) -> bool {
        true
    }
}

fn pages() -> &'static RwLock<HashMap<usize, Weak<Region>>> {
    static PAGES: OnceLock<RwLock<HashMap<usize, Weak<Region>>>> = OnceLock::new();
    PAGES.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Find the immutable region owning any tagged interior pointer in expected O(1).
///
/// The caller must keep the term's original allocation live during this call.
pub fn region_owner(term: Term) -> Option<SharedRoot> {
    if !term.is_pointer() {
        return None;
    }
    let page = (term.0 as usize & !7) & !(PAGE_BYTES - 1);
    let region = pages().read().unwrap().get(&page)?.upgrade()?;
    Some(SharedRoot {
        region: Some(region),
        term,
    })
}

/// Whether a tagged pointer belongs to a sealed region, for a process GC hook.
pub fn is_region_term(term: Term) -> bool {
    region_owner(term).is_some()
}

struct Region {
    storage: Storage,
    retained_bytes: usize,
}

impl Drop for Region {
    fn drop(&mut self) {
        let mut table = pages().write().unwrap();
        for chunk in &self.storage.chunks {
            let base = chunk.ptr.as_ptr() as usize;
            for offset in (0..chunk.bytes).step_by(PAGE_BYTES) {
                table.remove(&(base + offset));
            }
        }
    }
}

/// Builder-private region. Child terms must be immediate, local, or sealed.
pub struct RegionBuilder {
    storage: Storage,
}

impl RegionBuilder {
    /// Start an empty shareable allocation region.
    pub fn new() -> Self {
        Self {
            storage: Storage::new(),
        }
    }

    /// Number of initialized words in this builder.
    pub fn used_words(&self) -> usize {
        self.storage.words
    }

    fn allow(&mut self, term: Term) -> Result<(), TermError> {
        if !term.is_pointer() || term.0 == ((&crate::EMPTY_TUPLE as *const u64 as u64) | 2) {
            return Ok(());
        }
        let address = (term.0 & !7) as usize;
        if self.storage.chunks.iter().any(|c| {
            let start = c.ptr.as_ptr() as usize;
            address >= start && address < start + c.used_words * 8
        }) {
            return Ok(());
        }
        let owner = region_owner(term).ok_or(TermError::BadArg)?;
        let region = owner.region.as_ref().unwrap();
        self.storage
            .dependencies
            .entry(Arc::as_ptr(region) as usize)
            .or_insert_with(|| region.clone());
        Ok(())
    }

    /// Allocate a cons directly in this region after checking both edges.
    pub fn cons(&mut self, head: Term, tail: Term) -> Result<Term, TermError> {
        self.allow(head)?;
        self.allow(tail)?;
        TermBuilder::new(&mut self.storage).cons(head, tail)
    }

    /// Allocate a tuple directly in this region after checking its elements.
    pub fn tuple(&mut self, values: &[Term]) -> Result<Term, TermError> {
        for &value in values {
            self.allow(value)?;
        }
        TermBuilder::new(&mut self.storage).tuple(values)
    }

    /// Build a list from any iterator of checked terms.
    pub fn list_from_iter(
        &mut self,
        values: impl IntoIterator<Item = Term>,
    ) -> Result<Term, TermError> {
        let values: Vec<_> = values.into_iter().collect();
        let mut tail = Term::NIL;
        for value in values.into_iter().rev() {
            tail = self.cons(value, tail)?;
        }
        Ok(tail)
    }

    /// Build an arbitrary owned ETF value directly into this region.
    pub fn from_owned(&mut self, value: &OwnedTerm) -> Result<Term, TermError> {
        crate::from_owned(value, &mut self.storage)
    }

    /// Allocate binary data directly into this region.
    pub fn binary(&mut self, bytes: &[u8]) -> Result<Term, TermError> {
        TermBuilder::new(&mut self.storage).binary(bytes)
    }

    /// Allocate a map whose keys and values obey the region closure rule.
    pub fn flatmap_from_pairs(&mut self, pairs: &[(Term, Term)]) -> Result<Term, TermError> {
        for &(key, value) in pairs {
            self.allow(key)?;
            self.allow(value)?;
        }
        TermBuilder::new(&mut self.storage).flatmap_from_pairs(pairs)
    }

    /// Publish all chunks and return a rooted view. The builder cannot be used again.
    pub fn seal(self, root: Term) -> Result<SharedRoot, TermError> {
        let address = (root.0 & !7) as usize;
        if !root.is_pointer()
            || !self.storage.chunks.iter().any(|c| {
                let start = c.ptr.as_ptr() as usize;
                address >= start && address < start + c.used_words * 8
            })
        {
            return Err(TermError::BadArg);
        }
        let mut retained_bytes = self.storage.words * 8;
        if !self.storage.dependencies.is_empty() {
            let mut seen = HashSet::new();
            let mut stack: Vec<_> = self.storage.dependencies.values().cloned().collect();
            while let Some(child) = stack.pop() {
                let key = Arc::as_ptr(&child) as usize;
                if seen.insert(key) {
                    retained_bytes = retained_bytes.saturating_add(child.storage.words * 8);
                    stack.extend(child.storage.dependencies.values().cloned());
                }
            }
        }
        let region = Arc::new(Region {
            storage: self.storage,
            retained_bytes,
        });
        {
            let mut table = pages().write().unwrap();
            let weak = Arc::downgrade(&region);
            for chunk in &region.storage.chunks {
                let base = chunk.ptr.as_ptr() as usize;
                for offset in (0..chunk.bytes).step_by(PAGE_BYTES) {
                    table.insert(base + offset, weak.clone());
                }
            }
        }
        Ok(SharedRoot {
            region: Some(region),
            term: root,
        })
    }
}

impl Default for RegionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Default size for routing a growing cons spine to shareable storage.
pub const DEFAULT_REGION_LIST_CONS: usize = 256;

/// Result of an allocation-time list placement decision.
pub enum BuiltList {
    /// Short or non-closed list allocated in the caller's private heap.
    Private(Term),
    /// Large closed list allocated in immutable shareable storage.
    Shared(SharedRoot),
}

/// Generic prepend constructor that switches to region chunks as the spine grows.
///
/// Heads that point into private heaps keep the list on the private path. The
/// caller must keep all submitted heads live until `finish` returns.
pub struct GrowingList {
    threshold_cons: usize,
    buffered: Vec<Term>,
    shared: Option<(RegionBuilder, Term)>,
    private_only: bool,
}

impl GrowingList {
    /// Start a list with the default size threshold.
    pub fn new() -> Self {
        Self::with_threshold_cons(DEFAULT_REGION_LIST_CONS)
    }

    /// Set the number of cons cells that remain on the private path.
    pub fn with_threshold_cons(threshold_cons: usize) -> Self {
        Self {
            threshold_cons,
            buffered: Vec::new(),
            shared: None,
            private_only: false,
        }
    }

    /// Prepend one head, possibly switching to region allocation.
    pub fn prepend(&mut self, head: Term) -> Result<(), TermError> {
        if let Some((builder, root)) = &mut self.shared {
            *root = builder.cons(head, *root)?;
            return Ok(());
        }
        self.buffered.push(head);
        if self.private_only || self.buffered.len() <= self.threshold_cons {
            return Ok(());
        }
        let mut builder = RegionBuilder::new();
        let mut root = Term::NIL;
        for &value in &self.buffered {
            match builder.cons(value, root) {
                Ok(next) => root = next,
                Err(TermError::BadArg) => {
                    self.private_only = true;
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
        }
        self.buffered.clear();
        self.shared = Some((builder, root));
        Ok(())
    }

    /// Complete the list, using the private heap only for the small path.
    pub fn finish<H: HeapAlloc>(self, private_heap: &mut H) -> Result<BuiltList, TermError> {
        if let Some((builder, root)) = self.shared {
            return builder.seal(root).map(BuiltList::Shared);
        }
        let mut builder = TermBuilder::new(private_heap);
        let mut root = Term::NIL;
        for head in self.buffered {
            root = builder.cons(head, root)?;
        }
        Ok(BuiltList::Private(root))
    }
}

impl Default for GrowingList {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(miri))]
enum ReaperJob {
    Release(Arc<Region>),
    #[cfg(test)]
    Barrier(mpsc::Sender<()>),
}

#[cfg(not(miri))]
fn release_queue() -> Option<&'static mpsc::Sender<ReaperJob>> {
    static QUEUE: OnceLock<Option<mpsc::Sender<ReaperJob>>> = OnceLock::new();
    QUEUE
        .get_or_init(|| {
            let (sender, receiver) = mpsc::channel::<ReaperJob>();
            std::thread::Builder::new()
                .name("arinsal-region-reaper".into())
                .spawn(move || {
                    for job in receiver {
                        match job {
                            ReaperJob::Release(region) => drop(region),
                            #[cfg(test)]
                            ReaperJob::Barrier(done) => {
                                let _ = done.send(());
                            }
                        }
                    }
                })
                .ok()
                .map(|_| sender)
        })
        .as_ref()
}

/// One mailbox or process reference to a sealed immutable graph.
pub struct SharedRoot {
    region: Option<Arc<Region>>,
    term: Term,
}

impl Clone for SharedRoot {
    fn clone(&self) -> Self {
        Self {
            region: self.region.clone(),
            term: self.term,
        }
    }
}

impl Drop for SharedRoot {
    fn drop(&mut self) {
        if let Some(region) = self.region.take()
            && Arc::strong_count(&region) == 1
        {
            #[cfg(not(miri))]
            if let Some(queue) = release_queue() {
                if let Err(error) = queue.send(ReaperJob::Release(region)) {
                    drop(error.0);
                }
            } else {
                drop(region);
            }
            #[cfg(miri)]
            drop(region);
        }
    }
}

impl SharedRoot {
    /// Tagged term, valid while this handle or another region owner stays live.
    pub fn term(&self) -> Term {
        self.term
    }
    /// Initialized bytes in this root's own region.
    pub fn region_bytes(&self) -> usize {
        self.region.as_ref().map_or(0, |r| r.storage.words * 8)
    }

    /// Bytes retained by this region and each distinct sealed dependency.
    pub fn retained_bytes(&self) -> usize {
        self.region.as_ref().map_or(0, |r| r.retained_bytes)
    }
}

/// Return an O(1) handle for a region term or copy at most 4096 private words.
///
/// The caller must keep a private source graph live throughout the fallback copy.
/// Graphs over the limit return `SystemLimit` so the VM can use its ordinary
/// receiver-owned copy path. Mutable binary builders are rejected by copy_term.
pub fn seal_for_send(term: Term) -> Result<SharedRoot, TermError> {
    if let Some(owner) = region_owner(term) {
        return Ok(owner);
    }
    if !term.is_pointer() {
        return Err(TermError::BadArg);
    }
    let mut stack = vec![term];
    let mut words = 0usize;
    while let Some(value) = stack.pop() {
        if !value.is_pointer() {
            continue;
        }
        let object_words = if value.0 & 3 == 1 {
            2
        } else {
            // SAFETY: the caller keeps each source object live during fallback closure.
            unsafe {
                crate::boxed_object_words(value.header().ok_or(TermError::BadArg)?, value.raw_ptr())
            }
        };
        words = words
            .checked_add(object_words)
            .ok_or(TermError::SystemLimit)?;
        if words > SEND_COPY_LIMIT_WORDS {
            return Err(TermError::SystemLimit);
        }
        stack.extend(crate::ops::children(value));
    }
    let mut builder = RegionBuilder::new();
    let copied = copy_term(term, &mut builder.storage)?;
    builder.seal(copied)
}

/// Process-side region roots and incremental virtual-byte charge.
///
/// On GC, call `begin_gc`, `mark` for each live tagged root or copied slot,
/// then `finish_gc`. The collector must treat `is_region_term` pointers as
/// external so it never moves their cells. Mailboxes own `SharedRoot` until
/// adoption; process exit drops this table. Integration belongs to wave 1.
pub struct RegionRoots {
    first: Option<SharedRoot>,
    roots: HashMap<usize, SharedRoot>,
    charges: HashMap<usize, usize>,
    marked: HashSet<usize>,
    virtual_bytes: usize,
}

impl RegionRoots {
    /// Create empty process-side accounting.
    pub fn new() -> Self {
        Self {
            first: None,
            roots: HashMap::new(),
            charges: HashMap::new(),
            marked: HashSet::new(),
            virtual_bytes: 0,
        }
    }

    fn charge(&mut self, region: &Arc<Region>) {
        let mut stack = vec![region.clone()];
        while let Some(region) = stack.pop() {
            let id = Arc::as_ptr(&region) as usize;
            let charge = self.charges.entry(id).or_insert(0);
            if *charge == 0 {
                self.virtual_bytes += region.storage.words * 8;
            }
            *charge += 1;
            stack.extend(region.storage.dependencies.values().cloned());
        }
    }

    /// Transfer a mailbox handle into a process, retaining a single handle per region.
    pub fn adopt(&mut self, root: SharedRoot) -> Term {
        let term = root.term;
        let region = root.region.as_ref().expect("sealed root");
        let key = Arc::as_ptr(region) as usize;
        if self.first.is_none() {
            self.virtual_bytes = region.retained_bytes;
            self.first = Some(root);
            return term;
        }
        let first = self.first.as_ref().unwrap().region.as_ref().unwrap();
        if key == Arc::as_ptr(first) as usize || self.roots.contains_key(&key) {
            return term;
        }
        if self.charges.is_empty() {
            let first = first.clone();
            self.virtual_bytes = 0;
            self.charge(&first);
        }
        self.charge(region);
        self.roots.insert(key, root);
        term
    }

    /// Register a region pointer discovered in a process root or GC slot.
    pub fn register(&mut self, term: Term) -> bool {
        if let Some(root) = region_owner(term) {
            self.adopt(root);
            true
        } else {
            false
        }
    }

    /// Current virtual bytes across distinct retained regions and dependencies.
    pub fn virtual_bytes(&self) -> usize {
        self.virtual_bytes
    }

    /// Whether an incoming region charge crosses a process GC budget.
    pub fn collection_due(&self, incoming_bytes: usize, limit_bytes: usize) -> bool {
        incoming_bytes > limit_bytes
            || self.virtual_bytes.saturating_add(incoming_bytes) > limit_bytes
    }

    /// Clear the previous collection's live marks.
    pub fn begin_gc(&mut self) {
        self.marked.clear();
    }

    /// Record a live region term without following immutable region cells.
    pub fn mark(&mut self, term: Term) -> bool {
        if let Some(root) = region_owner(term) {
            let key = Arc::as_ptr(root.region.as_ref().unwrap()) as usize;
            self.marked.insert(key);
            self.adopt(root);
            true
        } else {
            false
        }
    }

    /// Release process handles no longer referenced after a collection.
    pub fn finish_gc(&mut self) {
        if self.first.as_ref().is_some_and(|root| {
            let key = Arc::as_ptr(root.region.as_ref().unwrap()) as usize;
            !self.marked.contains(&key)
        }) {
            self.first = None;
        }
        self.roots.retain(|key, _| self.marked.contains(key));
        if self.first.is_none()
            && let Some((&key, _)) = self.roots.iter().next()
        {
            self.first = self.roots.remove(&key);
        }
        self.charges.clear();
        self.virtual_bytes = 0;
        if let Some(root) = &self.first {
            let region = root.region.as_ref().unwrap().clone();
            if self.roots.is_empty() {
                self.virtual_bytes = region.retained_bytes;
                return;
            }
            self.charge(&region);
        }
        let regions: Vec<_> = self
            .roots
            .values()
            .map(|root| root.region.as_ref().unwrap().clone())
            .collect();
        for region in regions {
            self.charge(&region);
        }
    }
}

impl Default for RegionRoots {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_dependency_chain_releases_without_cycles() {
        let mut builder = RegionBuilder::new();
        let root = builder.cons(Term::small(1).unwrap(), Term::NIL).unwrap();
        let mut current = builder.seal(root).unwrap();
        let mut weak = Vec::new();
        weak.push(Arc::downgrade(current.region.as_ref().unwrap()));
        for _ in 0..128 {
            let mut builder = RegionBuilder::new();
            let next = builder.tuple(&[current.term()]).unwrap();
            let next = builder.seal(next).unwrap();
            weak.push(Arc::downgrade(next.region.as_ref().unwrap()));
            current = next;
        }
        drop(current);
        #[cfg(not(miri))]
        if let Some(queue) = release_queue() {
            let (sender, receiver) = mpsc::channel();
            queue.send(ReaperJob::Barrier(sender)).unwrap();
            receiver.recv().unwrap();
        }
        assert!(weak.iter().all(|region| region.upgrade().is_none()));
    }
}
