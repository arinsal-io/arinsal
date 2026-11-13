//! Raw heap layout operations ported from `erts/emulator/beam/erl_map.c`.

use crate::{MAP_HEADER_FLATMAP, bits, boxed, key_cmp, term};
use arinsal_term::{HeapAlloc, Term, TermError};
use std::cmp::Ordering;

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
