//! Raw heap layout operations ported from `erts/emulator/beam/erl_map.c`.

use crate::{MAP_HEADER_FLATMAP, bits, boxed, key_cmp, term};
use arinsal_term::{HeapAlloc, Term, TermError};
use std::cmp::Ordering;

/// Cursor over HAMT child words, matching the advancing `Eterm*` cursors in
/// `hashmap_merge`.
// Port of erts/emulator/beam/erl_map.c:1615-1804 (hashmap_merge), OTP-29.1.1.
#[derive(Clone, Copy)]
pub(crate) struct HamtCursor {
    at: *const u64,
}

// SAFETY: cursors point only into process-owned, non-moving HAMT nodes. A trapped merge disables
// GC until it resumes or is destroyed, and the owning trap context serializes scheduler access.
unsafe impl Send for HamtCursor {}
// SAFETY: shared cursors only read immutable map words; cursor advancement requires `&mut self`.
unsafe impl Sync for HamtCursor {}

impl HamtCursor {
    /// Cursor used only until `open_node` replaces it with a live node cursor.
    pub(crate) const fn empty() -> Self {
        Self {
            at: std::ptr::NonNull::<u64>::dangling().as_ptr(),
        }
    }

    /// Start at the first child word in a live, non-moving map node.
    #[inline(always)]
    pub(crate) fn from_words(words: &'static [u64]) -> Self {
        Self { at: words.as_ptr() }
    }

    /// Read the current child without a per-step slice bounds check.
    #[inline(always)]
    pub(crate) fn current(self) -> Term {
        // SAFETY: `open_node` initializes this cursor into a live HAMT node, and the process
        // heap does not move that node while the merge runs or while its trap state is saved.
        term(unsafe { self.at.read() })
    }

    /// Read and advance one child, as `*srcA++` / `*srcB++` do in erts.
    #[inline(always)]
    pub(crate) fn next(&mut self) -> Term {
        let value = self.current();
        self.at = self.at.wrapping_add(1);
        value
    }

    /// Advance over the paired child after a recursive merge.
    #[inline(always)]
    pub(crate) fn advance(&mut self) {
        self.at = self.at.wrapping_add(1);
    }

    /// Read a collision-node child at an offset from this cursor.
    #[inline(always)]
    pub(crate) fn get_at(self, offset: usize) -> Term {
        // SAFETY: collision-node sizes and the paired source ranges are established by
        // `hashmap_merge` before `merge_collision_node` reads these offsets.
        term(unsafe { self.at.wrapping_add(offset).read() })
    }
}

/// The fixed sixteen-child output array in one `hashmap_merge` frame.
// Port of erts/emulator/beam/erl_map.c:1467-1476 (HashmapMergePStackType), OTP-29.1.1.
#[derive(Clone, Copy)]
pub(crate) struct HamtChildren([u64; 16]);

impl HamtChildren {
    pub(crate) const fn new() -> Self {
        Self([0; 16])
    }

    /// Store one child selected by the frame's pending bitmap.
    #[inline(always)]
    pub(crate) fn write(&mut self, index: usize, value: u64) {
        debug_assert!(index < self.0.len());
        // SAFETY: `hashmap_merge` consumes at most the sixteen bits in a HAMT bitmap, so
        // every output index is within this frame's fixed child array.
        unsafe { self.0.as_mut_ptr().add(index).write(value) };
    }

    /// Borrow the initialized prefix copied into a newly allocated HAMT node.
    #[inline(always)]
    pub(crate) fn prefix(&self, len: usize) -> &[u64] {
        debug_assert!(len <= self.0.len());
        // SAFETY: the merge loop writes every slot in the prefix before node allocation,
        // and the bitmap bounds `len` to the sixteen-element array.
        unsafe { std::slice::from_raw_parts(self.0.as_ptr(), len) }
    }
}

// Port of erts/emulator/beam/erl_map.c:367-472 (flatmap_from_validated_list), OTP-29.1.1.
pub(crate) fn flatmap_from_validated_list<H: HeapAlloc + ?Sized>(
    allocated: usize,
    pairs: impl Iterator<Item = (Term, Term)>,
    heap: &mut H,
) -> Result<Term, TermError> {
    if allocated == 0 {
        return crate::empty_flatmap(heap);
    }

    let words = 3 + 1 + 2 * allocated;
    let (_block, ptr) = arinsal_term::alloc_terms(heap, words)?;
    // SAFETY: alloc_terms reserved the complete flatmap block, and the iterator and comparator
    // do not allocate or move this heap block until construction completes.
    unsafe {
        let tuple_arity = ptr;
        let ks = ptr.add(1);
        let mp = ks.add(allocated);
        let vs = mp.add(3);
        tuple_arity.write(bits(term((allocated as u64) << 6)));
        mp.write(bits(term(MAP_HEADER_FLATMAP)));
        mp.add(1).write(bits(term(allocated as u64)));
        mp.add(2).write(bits(term(ptr as u64 | 2)));

        let mut pairs = pairs;
        let (key, value) = pairs
            .next()
            .expect("validated list length matches the iterator");
        ks.write(bits(key));
        vs.write(bits(value));
        let mut size = 1usize;
        let mut unused_size = 0usize;

        for (key, value) in pairs {
            let mut idx = size;
            let mut ordering = Ordering::Less;
            while idx > 0 {
                ordering = key_cmp(key, term(*ks.add(idx - 1)));
                if ordering != Ordering::Less {
                    break;
                }
                idx -= 1;
            }
            if ordering == Ordering::Equal {
                ks.add(idx - 1).write(bits(key));
                vs.add(idx - 1).write(bits(value));
                unused_size += 1;
            } else {
                let mut i = size;
                while i > idx {
                    ks.add(i).write(*ks.add(i - 1));
                    vs.add(i).write(*vs.add(i - 1));
                    i -= 1;
                }
                ks.add(idx).write(bits(key));
                vs.add(idx).write(bits(value));
                size += 1;
            }
        }

        if unused_size > 0 {
            ks.add(size)
                .write(bits(term(((unused_size as u64 - 1) << 6) | 0x08)));
            heap.release(vs.add(size + unused_size), vs.add(size));
        }
        tuple_arity.write(bits(term((size as u64) << 6)));
        mp.add(1).write(bits(term(size as u64)));
        Ok(boxed(mp))
    }
}
