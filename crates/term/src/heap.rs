//! Stable word allocations. Every pointer remains valid until its heap is dropped.
use crate::bits::{ExternalBinary, WritableBinary, binary_data, owner_adjustment};
use crate::identity::check_external_ref;
use crate::record::RecordSnapshot;
use crate::{
    ARITY, Atom, BIN_REF, EMPTY_TUPLE, EXTERNAL_PID, EXTERNAL_PORT, EXTERNAL_REF, ExportEntry,
    FLOAT, FunEntry, HEAP_BITS, MAP, MAX_SMALL, MIN_SMALL, NEG_BIG, Node, POS_BIG, RECORD, REF,
    SUB_BITS, Term, TermError, TermKind, cmp, exact_eq,
};
use arinsal_alloc::typed::{AllocBlock, ErtsAlcType};
use num_bigint::{BigInt, Sign};
use num_traits::ToPrimitive;
use std::cell::UnsafeCell;
use std::cmp::Ordering;
use std::ops::Index;
use std::sync::Arc;

pub(crate) struct WordBlock {
    memory: Box<AllocBlock>,
}

const LITERAL_HEAP_BIT: usize = MAPPED_WORDS;
const MAPPED_WORDS: usize = 1 << (usize::BITS - 1);

// SAFETY: A process owns its word block exclusively; moving it changes no pointers within it.
unsafe impl Send for WordBlock {}

/// A heap fragment: a BIF-allocated side buffer or an adopted message heap.
pub(crate) enum Fragment {
    Block(WordBlock),
}

impl Fragment {
    pub(crate) fn as_ptr(&self) -> *const u64 {
        self.as_block().as_ptr().cast()
    }
    pub(crate) fn as_mut_ptr(&mut self) -> *mut u64 {
        self.as_block_mut().as_mut_ptr().cast()
    }
    pub(crate) fn len(&self) -> usize {
        self.as_block().len()
    }

    fn as_block(&self) -> &WordBlock {
        let Self::Block(block) = self;
        block
    }

    fn as_block_mut(&mut self) -> &mut WordBlock {
        let Self::Block(block) = self;
        block
    }
}

impl WordBlock {
    fn new(words: usize, allocation_type: ErtsAlcType) -> Self {
        let mut memory =
            AllocBlock::new(allocation_type, words).expect("ERTS heap block allocation failed");
        memory.as_mut_slice().fill(0);
        Self {
            memory: Box::new(memory),
        }
    }

    fn empty(allocation_type: ErtsAlcType) -> Self {
        Self::new(0, allocation_type)
    }

    pub(crate) fn as_ptr(&self) -> *const UnsafeCell<u64> {
        self.memory.as_ptr().cast()
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut UnsafeCell<u64> {
        self.memory.as_mut_ptr().cast()
    }

    pub(crate) fn len(&self) -> usize {
        self.memory.len()
    }

    pub(crate) fn contains_initialized(&self, address: usize, words: usize) -> bool {
        let start = self.as_ptr() as usize;
        address >= start && address < start.saturating_add(words.saturating_mul(8))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(crate) fn get(&self, index: usize) -> Option<&UnsafeCell<u64>> {
        if index >= self.len() {
            return None;
        }
        let word = self.memory.as_slice().get(index)?;
        // SAFETY: The allocator supplies aligned word storage; UnsafeCell has u64's layout.
        Some(unsafe { &*std::ptr::from_ref(word).cast::<UnsafeCell<u64>>() })
    }
}

impl Default for WordBlock {
    fn default() -> Self {
        Self::empty(ErtsAlcType::OLD_HEAP)
    }
}

impl Index<usize> for WordBlock {
    type Output = UnsafeCell<u64>;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).expect("word index out of bounds")
    }
}

/// Order of flatmap keys (`erts_cmp_flatmap_keys`), also the order of record fields.
pub fn flat_key_cmp(a: Term, b: Term) -> Ordering {
    exact_flat_key_cmp(a, b, true)
}

pub(crate) fn exact_flat_key_cmp(a: Term, b: Term, flat_atom: bool) -> Ordering {
    if let (Some(a), Some(b)) = (a.as_atom(), b.as_atom())
        && flat_atom
    {
        return a.0.cmp(&b.0);
    }
    if a.classify() == TermKind::Number && b.classify() == TermKind::Number {
        let af = a.header().is_some_and(|h| h & 63 == FLOAT);
        let bf = b.header().is_some_and(|h| h & 63 == FLOAT);
        return match (af, bf) {
            (false, true) => Ordering::Less,
            (true, false) => Ordering::Greater,
            (true, true) => {
                // SAFETY: both headers identify live float terms.
                unsafe {
                    a.float_ref()
                        .unwrap()
                        .get()
                        .total_cmp(&b.float_ref().unwrap().get())
                }
            }
            (false, false) => cmp(a, b),
        };
    }
    match (a.classify(), b.classify()) {
        (TermKind::Tuple, TermKind::Tuple) => {
            // SAFETY: the tuple terms remain live during sorting.
            let (a, b) = unsafe { (a.tuple_ref().unwrap(), b.tuple_ref().unwrap()) };
            let order = a.len().cmp(&b.len());
            if order != Ordering::Equal {
                return order;
            }
            for i in 0..a.len() {
                let order = exact_flat_key_cmp(a.get(i).unwrap(), b.get(i).unwrap(), false);
                if order != Ordering::Equal {
                    return order;
                }
            }
            Ordering::Equal
        }
        (TermKind::List, TermKind::List) => {
            // SAFETY: the list cells remain live during sorting.
            let ((ah, at), (bh, bt)) = unsafe { (a.cons_ref().unwrap(), b.cons_ref().unwrap()) };
            exact_flat_key_cmp(ah, bh, false).then_with(|| exact_flat_key_cmp(at, bt, false))
        }
        (TermKind::Map, TermKind::Map) => {
            let (mut av, mut bv) = (crate::hamt::pairs(a), crate::hamt::pairs(b));
            let order = av.len().cmp(&bv.len());
            if order != Ordering::Equal {
                return order;
            }
            av.sort_by(|x, y| exact_flat_key_cmp(x.0, y.0, false));
            bv.sort_by(|x, y| exact_flat_key_cmp(x.0, y.0, false));
            for i in 0..av.len() {
                let order = exact_flat_key_cmp(av[i].0, bv[i].0, false);
                if order != Ordering::Equal {
                    return order;
                }
            }
            for i in 0..av.len() {
                let order = exact_flat_key_cmp(av[i].1, bv[i].1, false);
                if order != Ordering::Equal {
                    return order;
                }
            }
            Ordering::Equal
        }
        _ => cmp(a, b),
    }
}

/// Allocator for word-aligned, stable term objects.
pub trait HeapAlloc {
    /// Reserve contiguous words, or return `None` so the caller can collect.
    fn alloc(&mut self, words: usize) -> Option<*mut u64>;
    /// Keep an off-heap binary alive until GC examines this heap's owners.
    fn retain_binary(&mut self, binary: Arc<Vec<u8>>);
    /// Retain a growable off-heap binary until collection examines its BinRef.
    fn retain_writable_binary(&mut self, _binary: Arc<WritableBinary>) -> Result<(), TermError> {
        Err(TermError::Unsupported("writable binary heap owner"))
    }
    /// Whether this heap can retain a writable owner without losing it at GC.
    fn supports_writable_binary(&self) -> bool {
        false
    }
    /// Retain a resource-backed binary until GC examines its BinRef.
    fn retain_external_binary(&mut self, _binary: Arc<ExternalBinary>) -> Result<(), TermError> {
        Err(TermError::Unsupported("external binary heap owner"))
    }
    /// Whether the heap retains external binary owners across collection.
    fn supports_external_binary(&self) -> bool {
        false
    }
    /// Keep a node-table entry alive for external identities.
    fn retain_node(&mut self, node: Arc<Node>);
    /// Retain a local fun entry.
    fn retain_fun(&mut self, entry: Arc<FunEntry>);
    /// Retain an export entry.
    fn retain_export(&mut self, entry: Arc<ExportEntry>);
    /// Keep a magic reference alive until GC examines this heap's owners.
    fn retain_magic(&mut self, _owner: Arc<crate::MagicRef>) {
        unreachable!("supports_magic must be checked before retention")
    }
    /// Whether the allocator keeps magic owners across its heap lifetime.
    fn supports_magic(&self) -> bool {
        false
    }
}

/// A process heap with an upward bump pointer and a downward stack pointer.
pub struct ProcessHeap {
    pub(crate) words: WordBlock,
    pub(crate) htop: usize,
    pub(crate) stop: usize,
    pub(crate) frame_pointer: usize,
    pub(crate) old_words: WordBlock,
    pub(crate) old_htop: usize,
    pub(crate) high_water: usize,
    pub(crate) min_heap_size: u32,
    pub(crate) fullsweep_after: u16,
    pub(crate) minor_since_major: u16,
    pub(crate) off_heap_binary_bytes: u64,
    pub(crate) bin_vheap: u64,
    pub(crate) bin_vheap_size: u64,
    pub(crate) heap_grow: bool,
    pub(crate) native_allocation: bool,
    pub(crate) fragments: Vec<Fragment>,
    /// Total word capacity in process heap fragments (`mbuf_sz` in erts).
    /// Words in heap fragments (u32 keeps the hot heap struct within 128 bytes).
    pub(crate) fragment_words: u32,
    pub(crate) owners: LazyOwners,
}

/// Word kinds found while walking the live Erlang stack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StackWord {
    /// A tagged Erlang term.
    Term(Term),
    /// A return address into registered native code.
    ReturnAddr(usize),
    /// A frame pointer into the live Erlang stack.
    FramePtr(usize),
}

/// The native FP_RA frame layout: `[frame pointer, return address]`.
pub struct FrameLayout;

impl FrameLayout {
    /// Word offset of the saved frame pointer.
    pub const FRAME_POINTER_WORD: usize = 0;
    /// Word offset of the saved return address.
    pub const RETURN_ADDRESS_WORD: usize = 1;
    /// Number of words in a frame header.
    pub const WORDS: usize = 2;
}

/// Number of words reserved for a default BeamAsm continuation pointer.
pub const CP_WORDS: usize = 1;
/// Stack redzone that runtime heap allocators must leave for native calls.
// Port of erts/emulator/beam/erl_vm.h:108-110, OTP-29.1.1, BEAMAsm AArch64.
pub const S_REDZONE: usize = CP_WORDS * 3;
/// Minimum free gap kept between the young heap and Erlang stack.
// Port of erts/emulator/beam/erl_vm.h:120, OTP-29.1.1.
pub const S_RESERVED: usize = CP_WORDS + S_REDZONE;
/// Stack words BeamAsm code may borrow below E to address X registers past the register
/// cache as stack slots. Native heap checks and native-mode runtime allocation keep them free.
pub const NATIVE_SPILL_WORDS: usize = 72;
/// Rarely touched virtual binary heap state, kept out of the hot `ProcessHeap`.
pub(crate) struct VheapCold {
    pub(crate) old: u64,
    pub(crate) old_size: u64,
    pub(crate) min: u64,
}

impl Default for VheapCold {
    fn default() -> Self {
        Self {
            old: 0,
            old_size: 46_422,
            min: 46_422,
        }
    }
}

#[derive(Default)]
pub(crate) struct HeapOwners {
    pub(crate) vheap: VheapCold,
    pub(crate) off_heap: Vec<Arc<Vec<u8>>>,
    pub(crate) writable: Vec<Arc<WritableBinary>>,
    pub(crate) external: Vec<Arc<ExternalBinary>>,
    pub(crate) nodes: Vec<Arc<Node>>,
    pub(crate) funs: Vec<Arc<FunEntry>>,
    pub(crate) exports: Vec<Arc<ExportEntry>>,
    pub(crate) magic: Vec<Arc<crate::MagicRef>>,
    pub(crate) old_off_heap: Vec<Arc<Vec<u8>>>,
    pub(crate) old_writable: Vec<Arc<WritableBinary>>,
    pub(crate) old_external: Vec<Arc<ExternalBinary>>,
    pub(crate) old_nodes: Vec<Arc<Node>>,
    pub(crate) old_funs: Vec<Arc<FunEntry>>,
    pub(crate) old_exports: Vec<Arc<ExportEntry>>,
    pub(crate) old_magic: Vec<Arc<crate::MagicRef>>,
    pub(crate) old_writable_refs: Vec<Term>,
}

#[derive(Default)]
pub(crate) struct LazyOwners(Option<Box<HeapOwners>>);

impl std::ops::Deref for LazyOwners {
    type Target = HeapOwners;
    fn deref(&self) -> &Self::Target {
        static EMPTY: std::sync::OnceLock<HeapOwners> = std::sync::OnceLock::new();
        self.0
            .as_deref()
            .unwrap_or_else(|| EMPTY.get_or_init(HeapOwners::default))
    }
}
impl std::ops::DerefMut for LazyOwners {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
            .get_or_insert_with(|| Box::new(HeapOwners::default()))
    }
}

/// A heap with stack or old-generation words cannot be adopted as a message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdoptError {
    /// The source is not a standalone message fragment.
    NotStandalone,
}

impl ProcessHeap {
    /// Create a heap with 64 words, including stack space.
    pub fn new() -> Self {
        Self::with_words(64)
    }
    /// Create a heap of the specified word capacity.
    pub fn with_words(words: usize) -> Self {
        Self::with_words_for_type(words, ErtsAlcType::HEAP)
    }

    /// Create a heap fragment block with the requested typed allocator.
    pub fn with_words_for_type(words: usize, allocation_type: ErtsAlcType) -> Self {
        Self {
            words: WordBlock::new(words, allocation_type),
            htop: 0,
            stop: words,
            frame_pointer: 0,
            old_words: WordBlock::default(),
            old_htop: 0,
            high_water: 0,
            min_heap_size: 233,
            fullsweep_after: u16::MAX,
            minor_since_major: 0,
            off_heap_binary_bytes: 0,
            bin_vheap: 0,
            bin_vheap_size: 46_422,
            heap_grow: false,
            native_allocation: false,
            fragments: Vec::new(),
            fragment_words: 0,
            owners: LazyOwners::default(),
        }
    }

    /// Reserve contiguous words for a process object.
    pub fn alloc(&mut self, words: usize) -> Option<*mut Term> {
        <Self as HeapAlloc>::alloc(self, words).map(|ptr| ptr.cast::<Term>())
    }
    /// Number of words consumed by heap objects.
    pub fn used_words(&self) -> usize {
        self.htop
    }
    /// Write one allocated raw word for the `erts_debug:inconsistent_heap` test hook.
    ///
    /// This debug-only API deliberately permits invalid term headers and sentinels.
    pub fn debug_write_heap_word(&mut self, index: usize, word: u64) -> bool {
        let Some(cell) = self.words.get(index).filter(|_| index < self.htop) else {
            return false;
        };
        // SAFETY: The index is within the allocated young heap, owned exclusively here.
        unsafe { cell.get().write(word) };
        true
    }
    /// Number of words between the heap and stack pointers.
    pub fn free_words(&self) -> usize {
        self.stop - self.htop
    }
    /// Young heap allocation boundary, leaving the native stack redzone unused.
    // Port of erts/emulator/beam/erl_process.h:990-998, OTP-29.1.1.
    pub fn heap_limit_words(&self) -> usize {
        self.htop.max(
            self.stop
                .saturating_sub(crate::S_REDZONE + NATIVE_SPILL_WORDS),
        )
    }
    /// Whether generated code is running on this heap (set by the native bridge).
    pub fn native_active(&self) -> bool {
        self.native_allocation
    }
    /// Words an allocation must leave free below the stack: the native redzone and spill
    /// area while generated code is active, none otherwise.
    pub fn allocation_reserve(&self) -> usize {
        if self.native_allocation {
            crate::S_REDZONE + NATIVE_SPILL_WORDS
        } else {
            0
        }
    }
    /// Select the runtime heap limit while generated Erlang code is active.
    pub fn set_native_allocation(&mut self, active: bool) {
        self.native_allocation = active;
    }
    /// Return the current heap top and stack boundary for a VM-local bump cursor.
    /// The pointers remain valid until this heap collects or grows.
    pub fn heap_cursor(&self) -> (*mut u64, *mut u64) {
        // SAFETY: Both indices are within or one past the fixed allocation.
        unsafe {
            let base = self.words.as_ptr().cast::<u64>().cast_mut();
            (base.add(self.htop), base.add(self.stop))
        }
    }
    /// Publish the active native frame pointer before a moving collection.
    pub fn set_frame_pointer(&mut self, frame_pointer: usize) {
        let base = self.words.as_ptr() as usize;
        let start = base + self.stop * 8;
        let end = base + self.words.len() * 8;
        self.frame_pointer = if frame_pointer >= start && frame_pointer < end {
            frame_pointer
        } else {
            0
        };
    }
    /// Return the active native frame pointer after collection.
    pub fn frame_pointer(&self) -> usize {
        self.frame_pointer
    }
    /// Return the start and end of the young heap allocation.
    pub fn heap_bounds(&self) -> (*mut u64, *mut u64) {
        // SAFETY: The fixed word block owns this entire allocation.
        unsafe {
            let base = self.words.as_ptr().cast::<u64>().cast_mut();
            (base, base.add(self.words.len()))
        }
    }
    /// Return the address of the young-heap high-water boundary.
    pub fn high_water_ptr(&self) -> *mut u64 {
        let (heap, _) = self.heap_bounds();
        heap.wrapping_add(self.high_water)
    }
    /// Commit a VM-local cursor before collection or another heap allocator runs.
    pub fn set_heap_top(&mut self, top: *mut u64) {
        let base = self.words.as_ptr() as usize;
        let address = top as usize;
        assert!(
            address >= base && address <= base + self.stop * 8,
            "heap top={address:#x} base={base:#x} stop={:#x} end={:#x}",
            base + self.stop * 8,
            base + self.words.len() * 8,
        );
        assert_eq!((address - base) % 8, 0);
        self.htop = (address - base) / 8;
    }
    /// Commit the native Erlang stack pointer before collection or interpretation.
    pub fn set_stack_pointer(&mut self, stop: *mut u64) {
        let base = self.words.as_ptr() as usize;
        let address = stop as usize;
        assert!(address >= base && address <= base + self.words.len() * 8);
        assert_eq!((address - base) % 8, 0);
        let index = (address - base) / 8;
        assert!(index >= self.htop);
        self.stop = index;
    }
    /// Reserve stack words from the high end.
    pub fn reserve_stack(&mut self, words: usize) -> bool {
        if words > self.free_words() {
            return false;
        }
        self.stop -= words;
        true
    }
    /// Allocate a side fragment when a BIF cannot collect at this point.
    pub fn heap_fragment(&mut self, words: usize) -> *mut u64 {
        self.fragment_words = self
            .fragment_words
            .saturating_add(u32::try_from(words).unwrap_or(u32::MAX));
        self.fragments.push(Fragment::Block(WordBlock::new(
            words,
            ErtsAlcType::HEAP_FRAG,
        )));
        self.fragments
            .last_mut()
            .expect("fragment inserted")
            .as_mut_ptr()
    }
    /// Move a standalone message heap into this process without copying its terms.
    ///
    /// The source must have no live stack or old generation. Terms allocated in
    /// it remain valid until this process next collects its fragments.
    pub fn adopt_message_fragment(&mut self, mut source: ProcessHeap) -> Result<(), AdoptError> {
        if source.stop != source.words.len()
            || source.old_htop != 0
            || !source.old_words.is_empty()
            || !source.owners.old_writable_refs.is_empty()
        {
            return Err(AdoptError::NotStandalone);
        }
        // The block moves with its terms; no word is copied.
        let adopted_words = source
            .words
            .len()
            .saturating_add(source.fragment_words as usize);
        self.fragment_words = self
            .fragment_words
            .saturating_add(u32::try_from(adopted_words).unwrap_or(u32::MAX));
        self.fragments
            .push(Fragment::Block(std::mem::take(&mut source.words)));
        self.fragments.append(&mut source.fragments);
        if let Some(mut owners) = source.owners.0.take() {
            let source_old_vheap = owners.vheap.old;
            self.off_heap_binary_bytes = self
                .off_heap_binary_bytes
                .saturating_add(source.off_heap_binary_bytes);
            self.bin_vheap = self.bin_vheap.saturating_add(source.bin_vheap);
            self.owners.vheap.old = self.owners.vheap.old.saturating_add(source_old_vheap);
            if let Some(target) = self.owners.0.as_mut() {
                target.off_heap.append(&mut owners.off_heap);
                target.writable.append(&mut owners.writable);
                target.external.append(&mut owners.external);
                target.nodes.append(&mut owners.nodes);
                target.funs.append(&mut owners.funs);
                target.exports.append(&mut owners.exports);
                target.magic.append(&mut owners.magic);
                target.old_off_heap.append(&mut owners.old_off_heap);
                target.old_writable.append(&mut owners.old_writable);
                target.old_external.append(&mut owners.old_external);
                target.old_nodes.append(&mut owners.old_nodes);
                target.old_funs.append(&mut owners.old_funs);
                target.old_exports.append(&mut owners.old_exports);
                target.old_magic.append(&mut owners.old_magic);
            } else {
                self.owners.0 = Some(owners);
            }
        }
        Ok(())
    }
    /// Number of off-heap binary owners retained by this process.
    pub fn off_heap_count(&self) -> usize {
        self.owners.off_heap.len()
            + self.owners.writable.len()
            + self.owners.external.len()
            + self.owners.old_off_heap.len()
            + self.owners.old_writable.len()
            + self.owners.old_external.len()
    }

    /// Number of bytes in live off-heap binaries after the last collection.
    pub fn off_heap_binary_bytes(&self) -> u64 {
        self.off_heap_binary_bytes
    }

    /// Return one `(identity, byte length, refcount)` per retained refc binary reference.
    ///
    /// Port of erts/emulator/beam/erl_bif_info.c:179 (erts_bld_bin_list), OTP-29.1.1: every
    /// reference in the off-heap list is reported separately, newest first.
    pub fn off_heap_binary_info(&self) -> Vec<(usize, usize, usize)> {
        let o = &self.owners;
        let mut out = Vec::new();
        for binary in o.off_heap.iter().chain(&o.old_off_heap) {
            out.push((
                Arc::as_ptr(binary) as usize,
                binary.len(),
                Arc::strong_count(binary),
            ));
        }
        for binary in o.writable.iter().chain(&o.old_writable) {
            out.push((
                Arc::as_ptr(binary) as usize,
                binary.len(),
                Arc::strong_count(binary),
            ));
        }
        for binary in o.external.iter().chain(&o.old_external) {
            out.push((
                Arc::as_ptr(binary) as usize,
                binary.len(),
                Arc::strong_count(binary),
            ));
        }
        out.reverse();
        out
    }

    /// Minimum virtual binary heap capacity, in machine words.
    pub fn min_bin_vheap_size(&self) -> u64 {
        self.owners.vheap.min
    }

    /// Current young virtual binary heap usage, in machine words.
    pub fn bin_vheap_used(&self) -> u64 {
        self.bin_vheap
    }

    /// Current old virtual binary heap usage, in machine words.
    pub fn bin_old_vheap_used(&self) -> u64 {
        self.owners.vheap.old
    }

    /// Current young virtual binary heap block size, in machine words.
    pub fn bin_vheap_block_size(&self) -> u64 {
        self.bin_vheap_size
    }

    /// Current old virtual binary heap block size, in machine words.
    pub fn bin_old_vheap_block_size(&self) -> u64 {
        self.owners.vheap.old_size
    }

    /// Set the process minimum used by virtual binary heap growth.
    pub fn set_min_bin_vheap_size(&mut self, words: u64) {
        self.owners.vheap.min = words.max(46_422);
        self.bin_vheap_size = self.bin_vheap_size.max(self.owners.vheap.min);
        self.owners.vheap.old_size = self.owners.vheap.old_size.max(self.owners.vheap.min);
    }

    /// Account `words` of virtual binary heap to the young or old counter.
    pub(crate) fn add_vheap(&mut self, promote: bool, words: u64) {
        if promote {
            self.owners.vheap.old = self.owners.vheap.old.saturating_add(words);
        } else {
            self.bin_vheap = self.bin_vheap.saturating_add(words);
        }
    }

    /// Whether off-heap binary overhead has reached the young virtual heap limit.
    pub fn bin_vheap_gc_due(&self) -> bool {
        self.bin_vheap > self.bin_vheap_size
    }
}
impl Default for ProcessHeap {
    fn default() -> Self {
        Self::new()
    }
}
impl HeapAlloc for ProcessHeap {
    #[inline]
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        let limit = if self.native_allocation {
            self.heap_limit_words()
        } else {
            self.stop
        };
        let available = limit.saturating_sub(self.htop);
        if words > available {
            return None;
        }
        // SAFETY: htop is within the fixed boxed slice and capacity is checked.
        let ptr = unsafe { self.words.as_ptr().add(self.htop).cast::<u64>().cast_mut() };
        self.htop += words;
        Some(ptr)
    }
    fn retain_binary(&mut self, binary: Arc<Vec<u8>>) {
        // Port of erts/emulator/beam/erl_message.h:85 (OH_OVERHEAD), OTP-29.1.1.
        self.bin_vheap = self.bin_vheap.saturating_add((binary.len() / 8) as u64);
        self.off_heap_binary_bytes = self
            .off_heap_binary_bytes
            .saturating_add(binary.len() as u64);
        self.owners.off_heap.push(binary);
    }
    fn retain_writable_binary(&mut self, binary: Arc<WritableBinary>) -> Result<(), TermError> {
        self.bin_vheap = self
            .bin_vheap
            .saturating_add((binary.capacity() / 8) as u64);
        self.owners.writable.push(binary);
        Ok(())
    }
    fn supports_writable_binary(&self) -> bool {
        true
    }
    fn retain_external_binary(&mut self, binary: Arc<ExternalBinary>) -> Result<(), TermError> {
        self.owners.external.push(binary);
        Ok(())
    }
    fn supports_external_binary(&self) -> bool {
        true
    }
    fn retain_node(&mut self, node: Arc<Node>) {
        self.owners.nodes.push(node);
    }
    fn retain_fun(&mut self, entry: Arc<FunEntry>) {
        self.owners.funs.push(entry);
    }
    fn retain_export(&mut self, entry: Arc<ExportEntry>) {
        self.owners.exports.push(entry);
    }
    fn retain_magic(&mut self, owner: Arc<crate::MagicRef>) {
        self.owners.magic.push(owner);
    }
    fn supports_magic(&self) -> bool {
        true
    }
}

/// Growable heap whose separately allocated chunks never move.
pub struct VecHeap {
    chunks: Vec<Box<[UnsafeCell<u64>]>>,
    off_heap: Vec<Arc<Vec<u8>>>,
    writable: Vec<Arc<WritableBinary>>,
    external: Vec<Arc<ExternalBinary>>,
    nodes: Vec<Arc<Node>>,
    funs: Vec<Arc<FunEntry>>,
    exports: Vec<Arc<ExportEntry>>,
    magic: Vec<Arc<crate::MagicRef>>,
    used: usize,
    total_used: usize,
    chunk_words: usize,
}

// SAFETY: Reading an allocated literal through a shared heap is safe. Every
// operation that can write or grow VecHeap requires exclusive `&mut self`.
unsafe impl Sync for VecHeap {}
impl VecHeap {
    /// Create a standalone heap.
    pub fn new() -> Self {
        Self {
            chunks: Vec::new(),
            off_heap: Vec::new(),
            writable: Vec::new(),
            external: Vec::new(),
            nodes: Vec::new(),
            funs: Vec::new(),
            exports: Vec::new(),
            magic: Vec::new(),
            used: 0,
            total_used: 0,
            chunk_words: 1024,
        }
    }
    /// Create a stable heap for module literal terms.
    pub fn new_literal() -> Self {
        let mut heap = Self::new();
        heap.chunk_words |= LITERAL_HEAP_BIT;
        heap
    }
    fn with_literal_chunk_words(words: usize) -> Self {
        let mut heap = Self::new();
        heap.chunk_words = words.max(1) | LITERAL_HEAP_BIT;
        heap
    }
    fn is_literal_area(&self) -> bool {
        self.chunk_words & LITERAL_HEAP_BIT != 0
    }
    fn next_chunk_words(&self) -> usize {
        self.chunk_words & !LITERAL_HEAP_BIT
    }
    /// Number of allocated words.
    pub fn used_words(&self) -> usize {
        self.total_used
    }
    /// Whether a pointer belongs to any allocation in this area.
    pub fn contains(&self, ptr: *const u64) -> bool {
        let address = ptr as usize;
        self.chunks.iter().any(|c| {
            address >= c.as_ptr() as usize && address < (c.as_ptr() as usize + c.len() * 8)
        })
    }
    /// Address ranges occupied by initialized or reserved heap chunks.
    pub fn pointer_ranges(&self) -> Vec<(usize, usize)> {
        self.chunks
            .iter()
            .map(|chunk| {
                let start = chunk.as_ptr() as usize;
                (start, start.saturating_add(chunk.len() * 8))
            })
            .collect()
    }
}
impl Default for VecHeap {
    fn default() -> Self {
        Self::new()
    }
}
impl Drop for VecHeap {
    fn drop(&mut self) {
        for chunk in &self.chunks {
            if self.is_literal_area() {
                let start = chunk.as_ptr() as usize;
                crate::literal::unregister(start, start + chunk.len() * 8);
            }
            #[cfg(any(feature = "validate-terms", debug_assertions, test))]
            crate::validate::forget_stable_range(chunk.as_ptr() as usize);
        }
    }
}
impl HeapAlloc for VecHeap {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        if self.chunks.is_empty() || self.used.checked_add(words)? > self.chunks.last()?.len() {
            let size = self.next_chunk_words().max(words);
            self.chunks
                .push((0..size).map(|_| UnsafeCell::new(0)).collect());
            self.used = 0;
            let literal_bit = self.chunk_words & LITERAL_HEAP_BIT;
            self.chunk_words = self.next_chunk_words().saturating_mul(2) | literal_bit;
            if self.is_literal_area()
                && let Some(chunk) = self.chunks.last()
            {
                let start = chunk.as_ptr() as usize;
                crate::literal::register(start, start + chunk.len() * 8);
            }
            // g_asan: literal areas and other VecHeaps stay address-stable.
            #[cfg(any(feature = "validate-terms", debug_assertions, test))]
            if let Some(chunk) = self.chunks.last() {
                crate::validate::note_stable_range(chunk.as_ptr() as usize, chunk.len() * 8);
            }
        }
        let chunk = self.chunks.last()?;
        // SAFETY: checked against chunk length above.
        let ptr = unsafe { chunk.as_ptr().add(self.used).cast::<u64>().cast_mut() };
        self.used += words;
        self.total_used += words;
        Some(ptr)
    }
    fn retain_binary(&mut self, binary: Arc<Vec<u8>>) {
        self.off_heap.push(binary);
    }
    fn retain_writable_binary(&mut self, binary: Arc<WritableBinary>) -> Result<(), TermError> {
        self.writable.push(binary);
        Ok(())
    }
    fn supports_writable_binary(&self) -> bool {
        true
    }
    fn retain_external_binary(&mut self, binary: Arc<ExternalBinary>) -> Result<(), TermError> {
        self.external.push(binary);
        Ok(())
    }
    fn supports_external_binary(&self) -> bool {
        true
    }
    fn retain_node(&mut self, node: Arc<Node>) {
        self.nodes.push(node);
    }
    fn retain_fun(&mut self, entry: Arc<FunEntry>) {
        self.funs.push(entry);
    }
    fn retain_export(&mut self, entry: Arc<ExportEntry>) {
        self.exports.push(entry);
    }
    fn retain_magic(&mut self, owner: Arc<crate::MagicRef>) {
        self.magic.push(owner);
    }
    fn supports_magic(&self) -> bool {
        true
    }
}

/// Immutable module literals. Address-range checks avoid consuming a pointer tag bit.
pub struct LiteralArea {
    heap: VecHeap,
}
impl LiteralArea {
    /// Create an empty literal area.
    pub fn new() -> Self {
        Self {
            heap: VecHeap::new_literal(),
        }
    }
    /// Reserve a first chunk sized for a known literal graph.
    pub fn with_capacity_words(words: usize) -> Self {
        Self {
            heap: VecHeap::with_literal_chunk_words(words),
        }
    }
    /// Build literals before publishing the area to readers.
    pub fn builder(&mut self) -> TermBuilder<'_, VecHeap> {
        TermBuilder::new(&mut self.heap)
    }
    /// Copy a term and all of its children into this unpublished area.
    pub fn copy_from(&mut self, term: Term) -> Result<Term, TermError> {
        crate::copy_term_preserving_sharing(term, &mut self.heap)
    }
    /// Number of initialized words in this area.
    pub fn used_words(&self) -> usize {
        self.heap.used_words()
    }
    /// Check whether a tagged pointer lies in this area's allocations.
    pub fn is_literal(&self, term: Term) -> bool {
        term.is_pointer() && self.heap.contains((term.bits() & !7) as *const u64)
    }
    /// Address ranges used by the literal-reference collector's pointer checks.
    pub fn pointer_ranges(&self) -> Vec<(usize, usize)> {
        self.heap.pointer_ranges()
    }
}
impl Default for LiteralArea {
    fn default() -> Self {
        Self::new()
    }
}

/// Build terms in any stable heap. Methods report exhaustion without moving objects.
pub struct TermBuilder<'a, H: HeapAlloc + ?Sized> {
    pub(crate) heap: &'a mut H,
}
impl<'a, H: HeapAlloc + ?Sized> TermBuilder<'a, H> {
    /// Attach a builder to a heap.
    pub fn new(heap: &'a mut H) -> Self {
        Self { heap }
    }
    pub(crate) fn words(&mut self, words: usize) -> Result<*mut u64, TermError> {
        self.heap.alloc(words).ok_or(TermError::HeapFull)
    }
    /// Build a tuple with OTP's arity header.
    pub fn tuple(&mut self, values: &[Term]) -> Result<Term, TermError> {
        self.tuple_iter(values.len(), values.iter().copied())
    }

    /// Build a tuple from an exact-length iterator without staging its elements.
    pub fn tuple_iter(
        &mut self,
        len: usize,
        mut values: impl ExactSizeIterator<Item = Term>,
    ) -> Result<Term, TermError> {
        if values.len() != len {
            return Err(TermError::BadArg);
        }
        self.tuple_from_fn(len, |_, _| {
            values.next().expect("tuple iterator length was checked")
        })
    }

    /// Build a tuple while reading each element from the heap that will own it.
    pub fn tuple_from_fn(
        &mut self,
        len: usize,
        mut value_at: impl FnMut(usize, &mut H) -> Term,
    ) -> Result<Term, TermError> {
        if len > (1 << 24) - 1 {
            return Err(TermError::SystemLimit);
        }
        if len == 0 {
            return Ok(Term::from_ptr((&EMPTY_TUPLE as *const u64).cast_mut(), 2));
        }
        let p = self.words(len + 1)?;
        // SAFETY: words() reserved exactly the header and elements.
        unsafe {
            *p = (len as u64) << 6 | ARITY;
            for i in 0..len {
                *p.add(i + 1) = value_at(i, self.heap).bits();
            }
        }
        Ok(Term::from_ptr(p, 2))
    }
    /// Build a two-word cons cell.
    pub fn cons(&mut self, head: Term, tail: Term) -> Result<Term, TermError> {
        let p = self.words(2)?;
        // SAFETY: two words were reserved.
        unsafe {
            *p = head.bits();
            *p.add(1) = tail.bits();
        }
        Ok(Term::from_ptr(p, 1))
    }
    /// Build a list in iteration order.
    pub fn list_from_iter(
        &mut self,
        values: impl IntoIterator<Item = Term>,
    ) -> Result<Term, TermError> {
        let values: Vec<Term> = values.into_iter().collect();
        let mut tail = Term::NIL;
        for value in values.into_iter().rev() {
            tail = self.cons(value, tail)?;
        }
        Ok(tail)
    }
    /// Build a list from a slice without staging the elements.
    pub fn list_from_slice(&mut self, values: &[Term]) -> Result<Term, TermError> {
        let mut tail = Term::NIL;
        for value in values.iter().rev() {
            tail = self.cons(*value, tail)?;
        }
        Ok(tail)
    }
    /// Build a list of Unicode scalar values.
    pub fn string_to_list(&mut self, text: &str) -> Result<Term, TermError> {
        self.list_from_iter(text.chars().map(|c| Term::small(c as i64).unwrap()))
    }
    /// Box a 64-bit float, retaining its exact bit pattern.
    pub fn float(&mut self, value: f64) -> Result<Term, TermError> {
        let p = self.words(2)?;
        // SAFETY: two words were reserved.
        unsafe {
            *p = (1 << 6) | FLOAT;
            *p.add(1) = value.to_bits();
        }
        Ok(Term::from_ptr(p, 2))
    }
    /// Select immediate or bignum storage for an `i64`.
    pub fn int_from_i64(&mut self, value: i64) -> Result<Term, TermError> {
        self.int_from_bigint(&BigInt::from(value))
    }
    /// Select immediate or bignum storage for an `i128`.
    pub fn int_from_i128(&mut self, value: i128) -> Result<Term, TermError> {
        self.int_from_bigint(&BigInt::from(value))
    }
    /// Box little-endian 64-bit magnitude digits when outside the small range.
    pub fn int_from_bigint(&mut self, value: &BigInt) -> Result<Term, TermError> {
        if let Some(n) = value.to_i64()
            && (MIN_SMALL..=MAX_SMALL).contains(&n)
        {
            return Ok(Term::small(n).unwrap());
        }
        let (sign, bytes) = value.to_bytes_le();
        let digits = bytes.len().div_ceil(8);
        if digits > 65_535 {
            return Err(TermError::SystemLimit);
        }
        let p = self.words(1 + digits)?;
        // SAFETY: header and digit words were reserved.
        unsafe {
            *p = ((digits as u64) << 6)
                | if sign == Sign::Minus {
                    NEG_BIG
                } else {
                    POS_BIG
                };
            for (i, part) in bytes.chunks(8).enumerate() {
                let mut digit = [0; 8];
                digit[..part.len()].copy_from_slice(part);
                *p.add(i + 1) = u64::from_le_bytes(digit);
            }
        }
        Ok(Term::from_ptr(p, 2))
    }
    /// Build a byte-aligned binary.
    pub fn binary(&mut self, bytes: &[u8]) -> Result<Term, TermError> {
        self.bitstring(bytes, bytes.len() * 8)
    }
    /// Build a bitstring with high bits significant in its final byte.
    pub fn bitstring(&mut self, bytes: &[u8], bit_len: usize) -> Result<Term, TermError> {
        if bit_len > bytes.len().saturating_mul(8) {
            return Err(TermError::BadArg);
        }
        let count = bit_len.div_ceil(8);
        if count <= 64 {
            let words = 2 + count.div_ceil(8);
            let p = self.words(words)?;
            // SAFETY: allocation includes count rounded to whole words.
            unsafe {
                *p = (((words - 1) as u64) << 6) | HEAP_BITS;
                *p.add(1) = bit_len as u64;
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), p.add(2).cast::<u8>(), count);
                if !bit_len.is_multiple_of(8) && count > 0 {
                    let last = p.add(2).cast::<u8>().add(count - 1);
                    *last &= 0xff << (8 - (bit_len % 8));
                }
            }
            return Ok(Term::from_ptr(p, 2));
        }
        let mut data = bytes[..count].to_vec();
        if !bit_len.is_multiple_of(8)
            && let Some(last) = data.last_mut()
        {
            *last &= 0xff << (8 - bit_len % 8);
        }
        let binary = Arc::new(data);
        let adjustment = binary.as_ptr() as usize & 3;
        let ref_ptr = self.words(8)?;
        // SAFETY: the same allocation reserves three BinRef and five SubBits words.
        let sub_ptr = unsafe { ref_ptr.add(3) };
        // SAFETY: both word ranges are reserved; Arc owns stable vector data.
        unsafe {
            *ref_ptr = (2 << 6) | BIN_REF;
            *ref_ptr.add(1) = Arc::as_ptr(&binary) as u64;
            *ref_ptr.add(2) = (adjustment as u64) << 1;
            *sub_ptr = (4 << 6) | SUB_BITS;
            *sub_ptr.add(1) = binary.as_ptr() as u64 & !3;
            *sub_ptr.add(2) = (adjustment * 8) as u64;
            *sub_ptr.add(3) = (bit_len + adjustment * 8) as u64;
            *sub_ptr.add(4) = Term::from_ptr(ref_ptr, 2).bits();
        }
        self.heap.retain_binary(binary);
        Ok(Term::from_ptr(sub_ptr, 2))
    }
    /// Create a slice of a bitstring, retaining the original owner.
    pub fn sub_binary(
        &mut self,
        original: Term,
        start: usize,
        bit_len: usize,
    ) -> Result<Term, TermError> {
        crate::bits::writable_finalize(original);
        // SAFETY: The original binary and heap remain live during construction.
        let view = unsafe { original.binary_ref() }.ok_or(TermError::BadArg)?;
        if start
            .checked_add(bit_len)
            .is_none_or(|end| end > view.bit_len())
        {
            return Err(TermError::BadArg);
        }
        let mut owner = original;
        while owner.header().is_some_and(|h| h & 63 == SUB_BITS) {
            // SAFETY: a live SubBits has its original term in word four.
            owner = Term(unsafe { *owner.raw_ptr().add(4) });
        }
        if owner.header().is_some_and(|h| h & 63 == HEAP_BITS) {
            let mut bytes = vec![0; bit_len.div_ceil(8)];
            for i in 0..bit_len {
                let src = view.start_bit() + start + i;
                bytes[i / 8] |= ((view.bytes()[src / 8] >> (7 - src % 8)) & 1) << (7 - i % 8);
            }
            return self.bitstring(&bytes, bit_len);
        }
        if owner.header().is_none_or(|h| h & 63 != BIN_REF) {
            return Err(TermError::BadArg);
        }
        if !self.heap.supports_writable_binary() && crate::bits::binary_owner_is_writable(owner) {
            return Err(TermError::Unsupported("writable binary heap owner"));
        }
        let p = self.words(8)?;
        // SAFETY: the BinRef pointer is held by the original heap.
        let (binary, flags) = unsafe { crate::bits::clone_binary_owner(owner) };
        // SAFETY: eight reserved words hold a BinRef followed by a SubBits.
        let sub = unsafe { p.add(3) };
        let absolute = view.start_bit() + start;
        let adjustment = owner_adjustment(owner);
        // SAFETY: the new BinRef owns the Arc data and both objects are initialized.
        unsafe {
            *p = (2 << 6) | BIN_REF;
            *p.add(1) = binary;
            *p.add(2) = flags;
            *sub = (4 << 6) | SUB_BITS;
            *sub.add(1) = binary_data(p) as u64 & !3;
            *sub.add(2) = (absolute + adjustment * 8) as u64;
            *sub.add(3) = (absolute + bit_len + adjustment * 8) as u64;
            *sub.add(4) = Term::from_ptr(p, 2).bits();
        }
        // SAFETY: clone_binary_owner returned an owned Arc raw pointer.
        unsafe { crate::bits::retain_cloned_binary_owner(self.heap, binary, flags)? };
        Ok(Term::from_ptr(sub, 2))
    }
    /// Construct a sorted flatmap; last duplicate key wins.
    pub fn flatmap_from_pairs(&mut self, pairs: &[(Term, Term)]) -> Result<Term, TermError> {
        // Port of erts/emulator/beam/erl_utils.h:267 (erts_cmp_flatmap_keys), OTP-29.1.1.
        let mut sorted: Vec<_> = pairs.iter().copied().enumerate().collect();
        sorted.sort_by(|a, b| flat_key_cmp(a.1.0, b.1.0).then(a.0.cmp(&b.0)));
        let mut unique: Vec<(Term, Term)> = Vec::with_capacity(sorted.len());
        for (_, pair) in sorted {
            if unique.last().is_some_and(|prior| exact_eq(prior.0, pair.0)) {
                *unique.last_mut().unwrap() = pair;
            } else {
                unique.push(pair);
            }
        }
        if unique.len() > 32 {
            return crate::hamt::build_hamt_from_unique(&unique, self.heap);
        }
        let keys = self.tuple(&unique.iter().map(|p| p.0).collect::<Vec<_>>())?;
        let values: Vec<Term> = unique.iter().map(|p| p.1).collect();
        self.flatmap_with_key_tuple(keys, &values)
    }
    /// Construct a flatmap that shares a sorted key tuple, allocating its header and values.
    ///
    /// Port of erts/emulator/beam/beam_common.c:2203-2283 (`erts_gc_update_map_exact`), OTP-29.1.1.
    pub fn flatmap_with_key_tuple(
        &mut self,
        keys: Term,
        values: &[Term],
    ) -> Result<Term, TermError> {
        // `keys` must be the sorted key tuple of a flatmap with exactly `values.len()` keys (the caller's map).
        if keys.classify() != crate::TermKind::Tuple
            || keys
                .header()
                .is_none_or(|header| (header >> 6) as usize != values.len())
            || values.len() > 32
        {
            return Err(TermError::BadArg);
        }
        let p = self.words(3 + values.len())?;
        // SAFETY: header, size, keys, values are reserved.
        unsafe {
            *p = MAP;
            *p.add(1) = values.len() as u64;
            *p.add(2) = keys.bits();
            for (i, value) in values.iter().enumerate() {
                *p.add(3 + i) = value.bits();
            }
        }
        Ok(Term::from_ptr(p, 2))
    }
    /// Port of erts/emulator/beam/erl_record.c:701-779, OTP-29.1.1.
    /// Construct a native record and its tuple-tagged definition.
    /// Fields are supplied in definition order and stored in atom-index order.
    pub fn native_record(
        &mut self,
        module: Atom,
        name: Atom,
        exported: bool,
        fields: &[(Atom, Term)],
    ) -> Result<Term, TermError> {
        if fields.len() > (1 << 24) - 2 {
            return Err(TermError::SystemLimit);
        }
        let mut sorted: Vec<(usize, Atom, Term)> = fields
            .iter()
            .enumerate()
            .map(|(i, (k, v))| (i, *k, *v))
            .collect();
        sorted.sort_by_key(|(_, key, _)| key.0);
        if sorted.windows(2).any(|pair| pair[0].1 == pair[1].1) {
            return Err(TermError::BadArg);
        }
        let bool_term = Term::atom(if exported {
            crate::atoms::TRUE
        } else {
            crate::atoms::FALSE
        });
        let mut temp = vec![0_u64; 4 + fields.len()];
        temp[0] = ((3 + fields.len()) as u64) << 6;
        temp[1] = Term::atom(module).bits();
        temp[2] = Term::atom(name).bits();
        temp[3] = bool_term.bits();
        for (i, (key, _)) in fields.iter().enumerate() {
            temp[4 + i] = Term::atom(*key).bits();
        }
        let hash = crate::make_hash2(Term::from_ptr(temp.as_mut_ptr(), 2));
        let mut order = vec![Term::NIL; fields.len()];
        for (sorted_index, (original_index, _, _)) in sorted.iter().enumerate() {
            // Port of erts/emulator/beam/erl_record.c:761, OTP-29.1.1.
            order[*original_index] = Term::small(sorted_index as i64).unwrap();
        }
        let order = self.tuple(&order)?;
        let def = self.words(6 + fields.len())?;
        // SAFETY: definition tuple has header and 5 fields plus field keys.
        unsafe {
            *def = ((5 + fields.len()) as u64) << 6 | ARITY;
            *def.add(1) = order.bits();
            *def.add(2) = Term::small(hash as i64).unwrap().bits();
            *def.add(3) = Term::atom(module).bits();
            *def.add(4) = Term::atom(name).bits();
            *def.add(5) = bool_term.bits();
            for (i, (_, key, _)) in sorted.iter().enumerate() {
                *def.add(6 + i) = Term::atom(*key).bits();
            }
        }
        let values: Vec<_> = sorted.iter().map(|(_, _, value)| *value).collect();
        self.native_record_instance(Term::from_ptr(def, 2), &values)
    }
    /// Copy a native record with selected field replacements.
    pub fn update_native_record(
        &mut self,
        snapshot: &RecordSnapshot,
        changes: &[(Atom, Term)],
    ) -> Result<Term, TermError> {
        if changes.is_empty() {
            return Ok(snapshot.instance);
        }
        let mut values = snapshot.values.clone();
        for (key, value) in changes {
            let Some(original_index) = snapshot.fields.iter().position(|field| field == key) else {
                return Err(TermError::BadArg);
            };
            let sorted_index = snapshot.fields[..original_index]
                .iter()
                .filter(|field| field.0 < key.0)
                .count()
                + snapshot.fields[original_index + 1..]
                    .iter()
                    .filter(|field| field.0 < key.0)
                    .count();
            let slot = values.get_mut(sorted_index).ok_or(TermError::BadArg)?;
            *slot = *value;
        }
        self.native_record_instance(snapshot.definition, &values)
    }
    fn native_record_instance(
        &mut self,
        definition: Term,
        values: &[Term],
    ) -> Result<Term, TermError> {
        let instance = self.words(2 + values.len())?;
        // SAFETY: instance has header, definition pointer, and all field values.
        unsafe {
            *instance = ((1 + values.len()) as u64) << 6 | RECORD;
            *instance.add(1) = definition.bits();
            for (i, value) in values.iter().enumerate() {
                *instance.add(2 + i) = value.bits();
            }
        }
        Ok(Term::from_ptr(instance, 2))
    }
    /// Construct a local fun, with a two-word head and captured environment.
    pub fn local_fun(&mut self, entry: Arc<FunEntry>, free: &[Term]) -> Result<Term, TermError> {
        let header =
            crate::fun::local_header(entry.arity, free.len()).ok_or(TermError::SystemLimit)?;
        let p = self.words(2 + free.len())?;
        // SAFETY: header, entry pointer, and environment words were reserved.
        unsafe {
            *p = header;
            *p.add(1) = Arc::as_ptr(&entry) as u64;
            for (i, value) in free.iter().enumerate() {
                *p.add(2 + i) = value.bits();
            }
        }
        self.heap.retain_fun(entry);
        Ok(Term::from_ptr(p, 2))
    }
    /// Construct an export fun with no environment.
    pub fn export_fun(&mut self, entry: Arc<ExportEntry>) -> Result<Term, TermError> {
        let p = self.words(2)?;
        // SAFETY: the two-word fun head was reserved.
        unsafe {
            *p = crate::fun::export_header(entry.arity);
            *p.add(1) = Arc::as_ptr(&entry) as u64;
        }
        self.heap.retain_export(entry);
        Ok(Term::from_ptr(p, 2))
    }
    /// Construct an external pid with the OTP four-word ExternalThing head.
    pub fn external_pid(
        &mut self,
        node: Arc<Node>,
        index: u32,
        serial: u32,
    ) -> Result<Term, TermError> {
        let p = self.words(4)?;
        // SAFETY: four words are reserved and the retained Arc keeps the node pointer live.
        unsafe {
            *p = (3 << 6) | EXTERNAL_PID;
            *p.add(1) = Arc::as_ptr(&node) as u64;
            *p.add(2) = 0;
            *p.add(3) = (index as u64) | ((serial as u64) << 32);
        }
        self.heap.retain_node(node);
        Ok(Term::from_ptr(p, 2))
    }
    /// Construct an external port.
    pub fn external_port(&mut self, node: Arc<Node>, id: u64) -> Result<Term, TermError> {
        let p = self.words(4)?;
        // SAFETY: four words are reserved and the retained Arc keeps the node pointer live.
        unsafe {
            *p = (3 << 6) | EXTERNAL_PORT;
            *p.add(1) = Arc::as_ptr(&node) as u64;
            *p.add(2) = 0;
            *p.add(3) = id;
        }
        self.heap.retain_node(node);
        Ok(Term::from_ptr(p, 2))
    }
    /// Construct an external ordinary or pid reference.
    // Port of erts/emulator/beam/erl_term.h:1142-1161 (ExternalThing layout), OTP-29.1.1.
    pub fn external_ref(&mut self, node: Arc<Node>, ids: &[u32]) -> Result<Term, TermError> {
        check_external_ref(ids)?;
        let words = 3 + (ids.len() + 1).div_ceil(2);
        let p = self.words(words)?;
        // SAFETY: words includes the external head and packed 32-bit count and ids.
        unsafe {
            *p = (((words - 1) as u64) << 6) | EXTERNAL_REF;
            *p.add(1) = Arc::as_ptr(&node) as u64;
            *p.add(2) = 0;
            *p.add(3) = ids.len() as u64;
            for (i, id) in ids.iter().enumerate() {
                let index = i + 1;
                let slot = p.add(3 + index / 2);
                if index % 2 == 0 {
                    *slot |= *id as u64;
                } else {
                    *slot |= (*id as u64) << 32;
                }
            }
        }
        self.heap.retain_node(node);
        Ok(Term::from_ptr(p, 2))
    }
    /// Construct an ordinary local reference (three 32-bit components).
    #[inline]
    pub fn local_ref(&mut self, ids: [u32; 3]) -> Result<Term, TermError> {
        Term::local_ref(self.heap, ids)
    }
}

impl Term {
    /// Construct an ordinary local reference (three 32-bit components) directly on any heap.
    #[inline]
    pub fn local_ref(
        heap: &mut (impl HeapAlloc + ?Sized),
        ids: [u32; 3],
    ) -> Result<Self, TermError> {
        let p = heap.alloc(3).ok_or(TermError::HeapFull)?;
        // SAFETY: three words reserved, matching ErtsORefThing on little endian.
        unsafe {
            *p = (2 << 6) | REF;
            *p.add(1) = ((ids[0] as u64) << 32) | 0xffff_ffff;
            *p.add(2) = ((ids[2] as u64) << 32) | ids[1] as u64;
        }
        Ok(Term::from_ptr(p, 2))
    }
}

impl<'a, H: HeapAlloc + ?Sized> TermBuilder<'a, H> {
    /// Box a reference to an opaque owner for NIF resources and future native handles.
    pub fn magic_ref(&mut self, owner: Arc<crate::MagicRef>) -> Result<Term, TermError> {
        if !self.heap.supports_magic() {
            return Err(TermError::Unsupported("magic reference heap owner"));
        }
        let p = self.words(3)?;
        // SAFETY: three reserved words hold the header, retained owner, and identity.
        unsafe {
            *p = (2 << 6) | crate::MAGIC_REF;
            *p.add(1) = Arc::as_ptr(&owner) as u64;
            *p.add(2) = owner.id();
        }
        self.heap.retain_magic(owner);
        Ok(Term::from_ptr(p, 2))
    }
}

/// Borrowed bitstring view. An unaligned slice includes the surrounding bytes;
/// `start_bit` and `bit_len` identify the significant bit interval.
pub struct BinaryRef<'a> {
    bytes: &'a [u8],
    start: usize,
    bits: usize,
}
impl BinaryRef<'_> {
    /// Whole backing bytes; unused bits may be present at the ends.
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }
    /// Number of significant bits.
    pub fn bit_len(&self) -> usize {
        self.bits
    }
    /// Starting bit within the backing data.
    pub fn start_bit(&self) -> usize {
        self.start
    }
}
impl Term {
    /// Borrow a binary's underlying bytes.
    ///
    /// # Safety
    /// The owning heap and any off-heap binary owner must remain live. No
    /// writable append may run while a view of its owner is retained.
    pub unsafe fn binary_ref<'a>(self) -> Option<BinaryRef<'a>> {
        let header = self.header()?;
        // SAFETY: The header determines the initialized object layout.
        let p = unsafe { self.raw_ptr() };
        if header & 63 == HEAP_BITS {
            // SAFETY: HeapBits has size in word 1 and data starting in word 2.
            let bits = unsafe { *p.add(1) } as usize;
            // SAFETY: HeapBits data begins at word two.
            let base = unsafe { p.add(2).cast::<u8>() };
            // SAFETY: The builder allocated ceil(bits / 8) data bytes.
            let bytes = unsafe { std::slice::from_raw_parts(base, bits.div_ceil(8)) };
            Some(BinaryRef {
                bytes,
                start: 0,
                bits,
            })
        } else if header & 63 == SUB_BITS {
            // SAFETY: SUB_BITS stores start/end and a live original in word four.
            let (start, end, original) =
                unsafe { (*p.add(2) as usize, *p.add(3) as usize, Term(*p.add(4))) };
            let adjustment = owner_adjustment(original) * 8;
            let base = if original.header().is_some_and(|h| h & 63 == BIN_REF) {
                // SAFETY: original is a retained BinRef and the caller prevents mutation.
                unsafe { binary_data(original.raw_ptr()) }
            } else {
                // SAFETY: a match context may refer directly to live HeapBits data.
                unsafe { original.raw_ptr().add(2).cast::<u8>() }
            };
            // SAFETY: The original allocation keeps this bit interval live.
            let bytes = unsafe { std::slice::from_raw_parts(base, (end - adjustment).div_ceil(8)) };
            Some(BinaryRef {
                bytes,
                start: start - adjustment,
                bits: end - start,
            })
        } else {
            None
        }
    }
}
